// Adversarial test suite. These tests try to BREAK the API: forge sessions,
// bypass auth, inject SQL, skip CSRF checks, and feed the endpoints garbage.
// A failure here is a real finding, not a flaky test.
import { describe, it, expect, beforeAll } from 'vitest';
import { SELF, env } from 'cloudflare:test';
import schemaSql from '../schema.sql?raw';

const TEST_PASSWORD = 'testpassword123';   // must match vitest.config.js
const TEST_JWT_SECRET = 'test-only-jwt-secret';

beforeAll(async () => {
  const statements = schemaSql
    .split('\n').filter(l => !l.trim().startsWith('--')).join('\n')
    .split(';').map(s => s.trim()).filter(Boolean);
  for (const stmt of statements) await env.DB.prepare(stmt).run();
});

async function login() {
  const res = await SELF.fetch('https://test/api/admin/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: TEST_PASSWORD }),
  });
  return (res.headers.get('set-cookie') || '').split(';')[0];
}
const authHeaders = (cookie) => ({ Cookie: cookie, 'Content-Type': 'application/json', 'X-Admin-Request': '1' });

/* ---------- helpers to hand-craft JWTs ---------- */
const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const enc = (obj) => b64url(new TextEncoder().encode(JSON.stringify(obj)));
async function hmac(data, secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))));
}
async function forgeToken(payload, secret = TEST_JWT_SECRET, header = { alg: 'HS256', typ: 'JWT' }) {
  const h = enc(header), b = enc(payload);
  return `${h}.${b}.${await hmac(`${h}.${b}`, secret)}`;
}
const now = () => Math.floor(Date.now() / 1000);

/* ================= SESSION FORGERY ================= */
describe('session token cannot be forged', () => {
  const probe = (cookie) => SELF.fetch('https://test/api/members', { headers: { Cookie: `nidhi_admin_session=${cookie}` } });

  it('rejects a token signed with the wrong secret', async () => {
    const token = await forgeToken({ role: 'admin', exp: now() + 3600 }, 'attacker-guessed-secret');
    expect((await probe(token)).status).toBe(401);
  });

  it('rejects the "alg: none" unsigned-token attack', async () => {
    const h = enc({ alg: 'none', typ: 'JWT' });
    const b = enc({ role: 'admin', exp: now() + 3600 });
    expect((await probe(`${h}.${b}.`)).status).toBe(401);
  });

  it('rejects a token whose payload was tampered with after signing', async () => {
    const valid = await forgeToken({ role: 'viewer', exp: now() + 3600 });
    const [h, , sig] = valid.split('.');
    const tampered = `${h}.${enc({ role: 'admin', exp: now() + 3600 })}.${sig}`;
    expect((await probe(tampered)).status).toBe(401);
  });

  it('rejects an expired token even though the signature is valid', async () => {
    const token = await forgeToken({ role: 'admin', exp: now() - 60 });
    expect((await probe(token)).status).toBe(401);
  });

  it('rejects a correctly-signed token that is not the admin role', async () => {
    const token = await forgeToken({ role: 'viewer', exp: now() + 3600 });
    expect((await probe(token)).status).toBe(401);
  });

  it('rejects garbage and empty cookies without crashing', async () => {
    for (const junk of ['', 'abc', 'a.b.c', '...', 'null', '{}']) {
      const res = await probe(junk);
      expect(res.status).toBe(401);
    }
  });
});

/* ================= AUTH COVERAGE ================= */
// Guards against a future endpoint being added without protection.
describe('every write endpoint refuses unauthenticated callers', () => {
  const writes = [
    ['POST', '/api/members', { id: 'x', name: 'x' }],
    ['PUT', '/api/members/x', { name: 'x' }],
    ['DELETE', '/api/members/x', null],
    ['POST', '/api/subs', { id: 'x', memberId: 'x', month: '2025-01', amount: 1 }],
    ['DELETE', '/api/subs/x', null],
    ['POST', '/api/loans', { id: 'x', memberId: 'x', amount: 1, installments: 1 }],
    ['PUT', '/api/loans/x', { amount: 1, installments: 1 }],
    ['DELETE', '/api/loans/x', null],
    ['POST', '/api/loans/x/payments', { id: 'x', no: 1, amount: 1 }],
    ['DELETE', '/api/loan-payments/x', null],
    ['POST', '/api/transactions', { id: 'x', type: 'income', amount: 1 }],
    ['PUT', '/api/transactions/x', { type: 'income', amount: 1 }],
    ['DELETE', '/api/transactions/x', null],
    ['POST', '/api/cycles', { number: 1, resetDate: '2025-01-01', interestDistributed: 0, perMemberShare: 0, memberCount: 0 }],
    ['PUT', '/api/settings', { orgName: 'x' }],
    ['PUT', '/api/state', { members: [], subs: [], loans: [], loanPayments: [], transactions: [], cycles: [], settings: {} }],
  ];

  it.each(writes)('%s %s requires a session', async (method, path, body) => {
    const res = await SELF.fetch('https://test' + path, {
      method,
      headers: { 'Content-Type': 'application/json', 'X-Admin-Request': '1' },
      body: body ? JSON.stringify(body) : undefined,
    });
    expect(res.status).toBe(401);
  });

  const reads = ['/api/members', '/api/subs', '/api/loans', '/api/transactions', '/api/cycles', '/api/settings'];
  it.each(reads)('GET %s requires a session', async (path) => {
    expect((await SELF.fetch('https://test' + path)).status).toBe(401);
  });
});

/* ================= CSRF ================= */
describe('CSRF protection', () => {
  it('blocks state-changing requests that lack the custom header', async () => {
    const cookie = await login();
    for (const [method, path, body] of [
      ['POST', '/api/members', { id: 'csrf1', name: 'x' }],
      ['DELETE', '/api/members/csrf1', null],
      ['PUT', '/api/settings', { orgName: 'pwned' }],
      ['PUT', '/api/state', { members: [], subs: [], loans: [], loanPayments: [], transactions: [], cycles: [], settings: {} }],
    ]) {
      const res = await SELF.fetch('https://test' + path, {
        method,
        headers: { Cookie: cookie, 'Content-Type': 'application/json' }, // no X-Admin-Request
        body: body ? JSON.stringify(body) : undefined,
      });
      expect(res.status).toBe(403);
    }
  });
});

/* ================= SQL INJECTION ================= */
describe('SQL injection is not possible', () => {
  const payloads = [
    "'; DROP TABLE members; --",
    "' OR '1'='1",
    "1'; DELETE FROM members WHERE '1'='1",
    "\\'; DROP TABLE members; --",
    "' UNION SELECT name FROM sqlite_master --",
  ];

  it.each(payloads)('treats %s as literal data in a field value', async (payload) => {
    const cookie = await login();
    const id = 'inj-' + Math.random().toString(36).slice(2, 8);
    const create = await SELF.fetch('https://test/api/members', {
      method: 'POST', headers: authHeaders(cookie),
      body: JSON.stringify({ id, name: payload, phone: payload }),
    });
    expect(create.status).toBe(201);

    // tables still exist and the payload was stored verbatim, not executed
    const list = await SELF.fetch('https://test/api/members', { headers: { Cookie: cookie } });
    expect(list.status).toBe(200);
    const stored = (await list.json()).find(m => m.id === id);
    expect(stored.name).toBe(payload);
  });

  it.each(payloads)('treats %s as literal data in a URL path parameter', async (payload) => {
    const cookie = await login();
    const res = await SELF.fetch('https://test/api/members/' + encodeURIComponent(payload), {
      method: 'DELETE', headers: authHeaders(cookie),
    });
    expect([200, 404]).toContain(res.status);
    // the members table must still be queryable
    expect((await SELF.fetch('https://test/api/members', { headers: { Cookie: cookie } })).status).toBe(200);
  });
});

/* ================= INPUT VALIDATION / ROBUSTNESS ================= */
describe('malformed input is rejected cleanly (never a 500)', () => {
  it('rejects a malformed JSON body on login', async () => {
    const res = await SELF.fetch('https://test/api/admin/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json',
    });
    expect(res.status).toBe(400);
  });

  it('rejects a login with a non-string password', async () => {
    for (const password of [null, 123, {}, [], true]) {
      const res = await SELF.fetch('https://test/api/admin/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }),
      });
      expect(res.status).toBe(400);
    }
  });

  it('rejects creating a member with no name', async () => {
    const cookie = await login();
    const res = await SELF.fetch('https://test/api/members', {
      method: 'POST', headers: authHeaders(cookie), body: JSON.stringify({ id: 'noname' }),
    });
    expect(res.status).toBe(400);
  });

  it('rejects a transaction with an invalid type instead of crashing', async () => {
    const cookie = await login();
    const res = await SELF.fetch('https://test/api/transactions', {
      method: 'POST', headers: authHeaders(cookie),
      body: JSON.stringify({ id: 'badtype', type: 'not-a-type', amount: 1, date: '2025-01-01' }),
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  it('rejects a duplicate primary key instead of returning 500', async () => {
    const cookie = await login();
    const body = JSON.stringify({ id: 'dup-1', name: 'First' });
    const first = await SELF.fetch('https://test/api/members', { method: 'POST', headers: authHeaders(cookie), body });
    expect(first.status).toBe(201);
    const second = await SELF.fetch('https://test/api/members', { method: 'POST', headers: authHeaders(cookie), body });
    expect(second.status).toBeGreaterThanOrEqual(400);
    expect(second.status).toBeLessThan(500);
  });

  it('rejects a full-state payload containing duplicate ids instead of 500', async () => {
    const cookie = await login();
    const res = await SELF.fetch('https://test/api/state', {
      method: 'PUT', headers: authHeaders(cookie),
      body: JSON.stringify({
        members: [{ id: 'same', name: 'A' }, { id: 'same', name: 'B' }],
        subs: [], loans: [], loanPayments: [], transactions: [], cycles: [], settings: {},
      }),
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  it('rejects a state payload whose fields are the wrong shape', async () => {
    const cookie = await login();
    const res = await SELF.fetch('https://test/api/state', {
      method: 'PUT', headers: authHeaders(cookie),
      body: JSON.stringify({ members: 'not-an-array', subs: {}, loans: null, settings: 'x' }),
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  it('rejects a loan referencing a member that does not exist', async () => {
    const cookie = await login();
    const res = await SELF.fetch('https://test/api/loans', {
      method: 'POST', headers: authHeaders(cookie),
      body: JSON.stringify({ id: 'orphan', memberId: 'ghost-member', amount: 100, rate: 2, installments: 5, issueDate: '2025-01-01' }),
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });
});

/* ================= ERROR DISCLOSURE ================= */
describe('errors do not leak internals', () => {
  it('never returns a stack trace or SQL text in an error body', async () => {
    const cookie = await login();
    const res = await SELF.fetch('https://test/api/members', {
      method: 'POST', headers: authHeaders(cookie), body: JSON.stringify({ id: null, name: null }),
    });
    const text = await res.text();
    expect(text).not.toMatch(/at \w+ \(/);       // stack frames
    expect(text).not.toMatch(/INSERT INTO|SELECT .* FROM/i); // raw SQL
    expect(text).not.toMatch(/D1_ERROR|SQLITE_/);
  });

  it('does not reveal whether the password format was close', async () => {
    const wrong = await SELF.fetch('https://test/api/admin/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'definitely-wrong' }),
    });
    expect(await wrong.json()).toEqual({ error: 'Invalid credentials' });
  });
});

/* ================= TRANSPORT / HEADERS ================= */
describe('response hardening', () => {
  it('sets the expected security headers', async () => {
    const res = await SELF.fetch('https://test/api/state');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');
  });

  it('does not hand a credentialed CORS grant to an arbitrary origin', async () => {
    const res = await SELF.fetch('https://test/api/state', { headers: { Origin: 'https://evil.example.com' } });
    const allowed = res.headers.get('Access-Control-Allow-Origin');
    const credentials = res.headers.get('Access-Control-Allow-Credentials');
    // Either no grant at all, or a grant that is not both wildcard AND credentialed.
    if (credentials === 'true') expect(allowed).not.toBe('*');
    expect(allowed).not.toBe('https://evil.example.com');
  });

  it('sets the session cookie HttpOnly, Secure and SameSite=Strict', async () => {
    const res = await SELF.fetch('https://test/api/admin/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: TEST_PASSWORD }),
    });
    const cookie = res.headers.get('set-cookie') || '';
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Strict');
  });
});

/* ================= DATA INTEGRITY ================= */
describe('data integrity rules hold', () => {
  it('cascades installment deletes when a loan is removed', async () => {
    const cookie = await login();
    await SELF.fetch('https://test/api/members', { method: 'POST', headers: authHeaders(cookie), body: JSON.stringify({ id: 'im1', name: 'M' }) });
    await SELF.fetch('https://test/api/loans', { method: 'POST', headers: authHeaders(cookie), body: JSON.stringify({ id: 'il1', memberId: 'im1', amount: 1000, rate: 2, installments: 5, issueDate: '2025-01-01' }) });
    await SELF.fetch('https://test/api/loans/il1/payments', { method: 'POST', headers: authHeaders(cookie), body: JSON.stringify({ id: 'ip1', no: 1, amount: 100, date: '2025-02-01' }) });

    await SELF.fetch('https://test/api/loans/il1', { method: 'DELETE', headers: authHeaders(cookie) });
    const left = await (await SELF.fetch('https://test/api/loans/il1/payments', { headers: { Cookie: cookie } })).json();
    expect(left.length).toBe(0);
  });

  it('refuses two payments for the same installment of one loan', async () => {
    const cookie = await login();
    await SELF.fetch('https://test/api/members', { method: 'POST', headers: authHeaders(cookie), body: JSON.stringify({ id: 'im2', name: 'M2' }) });
    await SELF.fetch('https://test/api/loans', { method: 'POST', headers: authHeaders(cookie), body: JSON.stringify({ id: 'il2', memberId: 'im2', amount: 1000, rate: 2, installments: 5, issueDate: '2025-01-01' }) });
    const p = (id) => SELF.fetch('https://test/api/loans/il2/payments', { method: 'POST', headers: authHeaders(cookie), body: JSON.stringify({ id, no: 1, amount: 100, date: '2025-02-01' }) });
    expect((await p('pay-a')).status).toBe(201);
    const dupe = await p('pay-b');
    expect(dupe.status).toBeGreaterThanOrEqual(400);
    expect(dupe.status).toBeLessThan(500);
  });
});
