import { Hono } from 'hono';
import { cors } from 'hono/cors';
import {
  verifyPassword, signSession, buildSessionCookie, buildClearCookie, readCookie,
  verifySession, checkLockout, recordLoginFailure, clearLoginFailures, requireAdmin, SESSION_COOKIE,
} from './auth.js';

const app = new Hono();

// BUG FIX: origin:'*' cannot be paired with credentialed (cookie-based) requests
// per the CORS spec — browsers reject it. The admin panel needs cookies sent
// cross-origin (Pages domain -> Workers domain), so ALLOWED_ORIGIN must be an
// exact origin, and credentials must be enabled.
app.use('*', async (c, next) => {
  const mw = cors({
    origin: c.env.ALLOWED_ORIGIN || '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'X-Admin-Request'],
    credentials: true,
  });
  return mw(c, next);
});

// Baseline security headers on every response.
app.use('*', async (c, next) => {
  await next();
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('X-Frame-Options', 'DENY');
  c.res.headers.set('Referrer-Policy', 'no-referrer');
  c.res.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
});

const clientIp = (c) => c.req.header('CF-Connecting-IP') || 'unknown';

/* ================= SUPER ADMIN AUTH ================= */
app.post('/api/admin/login', async (c) => {
  const ip = clientIp(c);
  const { locked, until } = await checkLockout(c.env.DB, ip);
  if (locked) return c.json({ error: 'Too many failed attempts. Try again later.', lockedUntil: until }, 429);

  let body;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid request' }, 400); }
  const password = typeof body.password === 'string' ? body.password : '';
  if (!password) return c.json({ error: 'Password required' }, 400);

  const ok = await verifyPassword(password, c.env.ADMIN_PASSWORD_HASH);
  if (!ok) {
    await recordLoginFailure(c.env.DB, ip);
    // Generic message — do not reveal whether an account/password format is wrong.
    return c.json({ error: 'Invalid credentials' }, 401);
  }
  await clearLoginFailures(c.env.DB, ip);
  const token = await signSession({ role: 'admin' }, c.env.JWT_SECRET);
  c.header('Set-Cookie', buildSessionCookie(token));
  return c.json({ ok: true });
});

app.post('/api/admin/logout', async (c) => {
  c.header('Set-Cookie', buildClearCookie());
  return c.json({ ok: true });
});

app.get('/api/admin/session', async (c) => {
  const cookie = readCookie(c.req.header('Cookie'), SESSION_COOKIE);
  const session = await verifySession(cookie, c.env.JWT_SECRET);
  return c.json({ authenticated: !!session });
});

/* ---------- row <-> JSON field mapping (keeps frontend field names unchanged) ---------- */
const memberOut = (r) => ({
  id: r.id, name: r.name, phone: r.phone, address: r.address, joinDate: r.join_date,
  nominee: r.nominee, regFee: r.reg_fee, exited: !!r.exited, exitDate: r.exit_date, exitAmount: r.exit_amount,
});
const subOut = (r) => ({ id: r.id, memberId: r.member_id, month: r.month, amount: r.amount, date: r.date });
const loanOut = (r) => ({
  id: r.id, memberId: r.member_id, amount: r.amount, rate: r.rate, installments: r.installments,
  issueDate: r.issue_date, deductInterest: !!r.deduct_interest, deductionRate: r.deduction_rate,
});
const paymentOut = (r) => ({ id: r.id, loanId: r.loan_id, no: r.no, amount: r.amount, date: r.date, interestWaived: !!r.interest_waived });
const txnOut = (r) => ({
  id: r.id, type: r.type, amount: r.amount, category: r.category, date: r.date, note: r.note,
  auto: !!r.auto, sourceType: r.source_type, loanId: r.loan_id, memberId: r.member_id,
});
const cycleOut = (r) => ({
  number: r.number, resetDate: r.reset_date, interestDistributed: r.interest_distributed,
  perMemberShare: r.per_member_share, memberCount: r.member_count,
});
const settingsOut = (r) => ({
  orgName: r.org_name, startMonth: r.start_month, startMonthAuto: !!r.start_month_auto, subAmount: r.sub_amount,
});

const bad = (c, msg, status = 400) => c.json({ error: msg }, status);

// Everything under /api/* requires an admin session EXCEPT:
// - /api/admin/login|logout|session (the login flow itself)
// - /api/state (the public, unauthenticated ledger app's read/save endpoint)
// This is what makes the granular CRUD surface the "Super Admin, super
// controls everything" panel while the ledger app keeps working unauthenticated.
const PUBLIC_PATHS = new Set(['/api/state', '/api/admin/login', '/api/admin/logout', '/api/admin/session']);
app.use('/api/*', async (c, next) => {
  if (PUBLIC_PATHS.has(c.req.path)) return next();
  return requireAdmin()(c, next);
});

/* ================= MEMBERS ================= */
app.get('/api/members', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM members ORDER BY created_at').all();
  return c.json(results.map(memberOut));
});
app.post('/api/members', async (c) => {
  const b = await c.req.json();
  if (!b.id || !b.name) return bad(c, 'id and name required');
  await c.env.DB.prepare(
    `INSERT INTO members (id,name,phone,address,join_date,nominee,reg_fee,exited,exit_date,exit_amount)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(b.id, b.name, b.phone || null, b.address || null, b.joinDate || null, b.nominee || null,
    b.regFee || 0, b.exited ? 1 : 0, b.exitDate || null, b.exitAmount ?? null).run();
  return c.json({ ok: true }, 201);
});
app.put('/api/members/:id', async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  await c.env.DB.prepare(
    `UPDATE members SET name=?, phone=?, address=?, join_date=?, nominee=?, reg_fee=?, exited=?, exit_date=?, exit_amount=? WHERE id=?`
  ).bind(b.name, b.phone || null, b.address || null, b.joinDate || null, b.nominee || null,
    b.regFee || 0, b.exited ? 1 : 0, b.exitDate || null, b.exitAmount ?? null, id).run();
  return c.json({ ok: true });
});
app.delete('/api/members/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM members WHERE id=?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

/* ================= SUBSCRIPTIONS ================= */
app.get('/api/subs', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM subscriptions ORDER BY date').all();
  return c.json(results.map(subOut));
});
app.post('/api/subs', async (c) => {
  const b = await c.req.json();
  if (!b.id || !b.memberId || !b.month || b.amount == null) return bad(c, 'id, memberId, month, amount required');
  await c.env.DB.prepare('INSERT INTO subscriptions (id,member_id,month,amount,date) VALUES (?,?,?,?,?)')
    .bind(b.id, b.memberId, b.month, b.amount, b.date || null).run();
  return c.json({ ok: true }, 201);
});
app.delete('/api/subs/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM subscriptions WHERE id=?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

/* ================= LOANS ================= */
app.get('/api/loans', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM loans ORDER BY issue_date').all();
  return c.json(results.map(loanOut));
});
app.post('/api/loans', async (c) => {
  const b = await c.req.json();
  if (!b.id || !b.memberId || b.amount == null || !b.installments) return bad(c, 'id, memberId, amount, installments required');
  await c.env.DB.prepare(
    `INSERT INTO loans (id,member_id,amount,rate,installments,issue_date,deduct_interest,deduction_rate)
     VALUES (?,?,?,?,?,?,?,?)`
  ).bind(b.id, b.memberId, b.amount, b.rate || 0, b.installments, b.issueDate || null,
    b.deductInterest ? 1 : 0, b.deductionRate ?? null).run();
  return c.json({ ok: true }, 201);
});
app.put('/api/loans/:id', async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  await c.env.DB.prepare(
    `UPDATE loans SET amount=?, rate=?, installments=?, issue_date=?, deduct_interest=?, deduction_rate=? WHERE id=?`
  ).bind(b.amount, b.rate || 0, b.installments, b.issueDate || null, b.deductInterest ? 1 : 0, b.deductionRate ?? null, id).run();
  return c.json({ ok: true });
});
app.delete('/api/loans/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM loans WHERE id=?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

/* ================= LOAN PAYMENTS ================= */
app.get('/api/loans/:id/payments', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM loan_payments WHERE loan_id=? ORDER BY no')
    .bind(c.req.param('id')).all();
  return c.json(results.map(paymentOut));
});
app.post('/api/loans/:id/payments', async (c) => {
  const loanId = c.req.param('id');
  const b = await c.req.json();
  if (!b.id || b.no == null || b.amount == null) return bad(c, 'id, no, amount required');
  await c.env.DB.prepare('INSERT INTO loan_payments (id,loan_id,no,amount,date,interest_waived) VALUES (?,?,?,?,?,?)')
    .bind(b.id, loanId, b.no, b.amount, b.date || null, b.interestWaived ? 1 : 0).run();
  return c.json({ ok: true }, 201);
});
app.delete('/api/loan-payments/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM loan_payments WHERE id=?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

/* ================= TRANSACTIONS ================= */
app.get('/api/transactions', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM transactions ORDER BY date').all();
  return c.json(results.map(txnOut));
});
app.post('/api/transactions', async (c) => {
  const b = await c.req.json();
  if (!b.id || !b.type || b.amount == null) return bad(c, 'id, type, amount required');
  await c.env.DB.prepare(
    `INSERT INTO transactions (id,type,amount,category,date,note,auto,source_type,loan_id,member_id)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(b.id, b.type, b.amount, b.category || null, b.date || null, b.note || null,
    b.auto ? 1 : 0, b.sourceType || null, b.loanId || null, b.memberId || null).run();
  return c.json({ ok: true }, 201);
});
app.put('/api/transactions/:id', async (c) => {
  const id = c.req.param('id');
  const b = await c.req.json();
  await c.env.DB.prepare(
    `UPDATE transactions SET type=?, amount=?, category=?, date=?, note=?, auto=?, source_type=?, loan_id=?, member_id=? WHERE id=?`
  ).bind(b.type, b.amount, b.category || null, b.date || null, b.note || null,
    b.auto ? 1 : 0, b.sourceType || null, b.loanId || null, b.memberId || null, id).run();
  return c.json({ ok: true });
});
app.delete('/api/transactions/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM transactions WHERE id=?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

/* ================= CYCLES ================= */
app.get('/api/cycles', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM cycles ORDER BY number').all();
  return c.json(results.map(cycleOut));
});
app.post('/api/cycles', async (c) => {
  const b = await c.req.json();
  await c.env.DB.prepare(
    `INSERT INTO cycles (number, reset_date, interest_distributed, per_member_share, member_count) VALUES (?,?,?,?,?)`
  ).bind(b.number, b.resetDate, b.interestDistributed, b.perMemberShare, b.memberCount).run();
  return c.json({ ok: true }, 201);
});

/* ================= SETTINGS ================= */
app.get('/api/settings', async (c) => {
  const row = await c.env.DB.prepare('SELECT * FROM settings WHERE id=1').first();
  return c.json(settingsOut(row || {}));
});
app.put('/api/settings', async (c) => {
  const b = await c.req.json();
  await c.env.DB.prepare(
    `UPDATE settings SET org_name=?, start_month=?, start_month_auto=?, sub_amount=? WHERE id=1`
  ).bind(b.orgName || '', b.startMonth || null, b.startMonthAuto === false ? 0 : 1, b.subAmount || 500).run();
  return c.json({ ok: true });
});

/* ================= FULL-STATE (bootstrap read + atomic sync used by the app on every save) ================= */
app.get('/api/state', async (c) => {
  const db = c.env.DB;
  const [members, subs, loans, payments, txns, cycles, settings] = await Promise.all([
    db.prepare('SELECT * FROM members').all(),
    db.prepare('SELECT * FROM subscriptions').all(),
    db.prepare('SELECT * FROM loans').all(),
    db.prepare('SELECT * FROM loan_payments').all(),
    db.prepare('SELECT * FROM transactions').all(),
    db.prepare('SELECT * FROM cycles ORDER BY number').all(),
    db.prepare('SELECT * FROM settings WHERE id=1').first(),
  ]);
  return c.json({
    members: members.results.map(memberOut),
    subs: subs.results.map(subOut),
    loans: loans.results.map(loanOut),
    loanPayments: payments.results.map(paymentOut),
    transactions: txns.results.map(txnOut),
    cycles: cycles.results.map(cycleOut),
    settings: settingsOut(settings || {}),
  });
});

// Atomic full replace: deletes all rows and re-inserts the payload in one D1 batch.
// Used by the frontend's saveState() so every mutation (including multi-table workflows
// like exit settlement, final closure, and cycle reset) is written consistently.
app.put('/api/state', async (c) => {
  const db = c.env.DB;
  const s = await c.req.json();
  const members = s.members || [];
  const subs = s.subs || [];
  const loans = s.loans || [];
  const payments = s.loanPayments || [];
  const txns = s.transactions || [];
  const cycles = s.cycles || [];
  const settings = s.settings || {};

  const stmts = [
    db.prepare('DELETE FROM loan_payments'),
    db.prepare('DELETE FROM transactions'),
    db.prepare('DELETE FROM subscriptions'),
    db.prepare('DELETE FROM loans'),
    db.prepare('DELETE FROM cycles'),
    db.prepare('DELETE FROM members'),
  ];

  for (const m of members) {
    stmts.push(db.prepare(
      `INSERT INTO members (id,name,phone,address,join_date,nominee,reg_fee,exited,exit_date,exit_amount)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).bind(m.id, m.name, m.phone || null, m.address || null, m.joinDate || null, m.nominee || null,
      m.regFee || 0, m.exited ? 1 : 0, m.exitDate || null, m.exitAmount ?? null));
  }
  for (const l of loans) {
    stmts.push(db.prepare(
      `INSERT INTO loans (id,member_id,amount,rate,installments,issue_date,deduct_interest,deduction_rate)
       VALUES (?,?,?,?,?,?,?,?)`
    ).bind(l.id, l.memberId, l.amount, l.rate || 0, l.installments, l.issueDate || null,
      l.deductInterest ? 1 : 0, l.deductionRate ?? null));
  }
  for (const s2 of subs) {
    stmts.push(db.prepare('INSERT INTO subscriptions (id,member_id,month,amount,date) VALUES (?,?,?,?,?)')
      .bind(s2.id, s2.memberId, s2.month, s2.amount, s2.date || null));
  }
  for (const p of payments) {
    stmts.push(db.prepare('INSERT INTO loan_payments (id,loan_id,no,amount,date,interest_waived) VALUES (?,?,?,?,?,?)')
      .bind(p.id, p.loanId, p.no, p.amount, p.date || null, p.interestWaived ? 1 : 0));
  }
  for (const x of txns) {
    stmts.push(db.prepare(
      `INSERT INTO transactions (id,type,amount,category,date,note,auto,source_type,loan_id,member_id)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).bind(x.id, x.type, x.amount, x.category || null, x.date || null, x.note || null,
      x.auto ? 1 : 0, x.sourceType || null, x.loanId || null, x.memberId || null));
  }
  for (const cy of cycles) {
    stmts.push(db.prepare(
      `INSERT INTO cycles (number, reset_date, interest_distributed, per_member_share, member_count) VALUES (?,?,?,?,?)`
    ).bind(cy.number, cy.resetDate, cy.interestDistributed, cy.perMemberShare, cy.memberCount));
  }
  stmts.push(db.prepare(
    `UPDATE settings SET org_name=?, start_month=?, start_month_auto=?, sub_amount=? WHERE id=1`
  ).bind(settings.orgName || '', settings.startMonth || null, settings.startMonthAuto === false ? 0 : 1, settings.subAmount || 500));

  await db.batch(stmts);
  return c.json({ ok: true });
});

app.get('/', (c) => c.text('Nidhi Ledger API is running.'));

export default app;
