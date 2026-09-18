// Auth primitives for the Super Admin surface.
// Password itself never lives in code or the database — only a PBKDF2
// hash does, supplied via the ADMIN_PASSWORD_HASH env var (see README:
// "Generating the admin password hash"). JWT_SECRET is a separate env
// secret used only to sign session tokens.

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32; // bytes
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours
const MAX_LOGIN_FAILURES = 5;
const LOCKOUT_MINUTES = 15;

function b64urlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function b64Encode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64Decode(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/* ---------------- password hashing (PBKDF2-HMAC-SHA256) ---------------- */
// ADMIN_PASSWORD_HASH env format: "<base64 salt>:<base64 derived key>"
// Generate it with worker/scripts/hash-password.js — never hand-write it.
export async function verifyPassword(plainPassword, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [saltB64, hashB64] = storedHash.split(':');
  const salt = b64Decode(saltB64);
  const expected = b64Decode(hashB64);
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(plainPassword), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, PBKDF2_KEYLEN * 8
  );
  const derivedBytes = new Uint8Array(derived);
  if (derivedBytes.length !== expected.length) return false;
  // constant-time compare
  let diff = 0;
  for (let i = 0; i < derivedBytes.length; i++) diff |= derivedBytes[i] ^ expected[i];
  return diff === 0;
}

/* ---------------- JWT (HMAC-SHA256, no external deps) ---------------- */
async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return b64urlEncode(new Uint8Array(sig));
}

export async function signSession(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = { ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS };
  const headerB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const bodyB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(body)));
  const signature = await hmacSign(`${headerB64}.${bodyB64}`, secret);
  return `${headerB64}.${bodyB64}.${signature}`;
}

export async function verifySession(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, bodyB64, signature] = parts;
  const expected = await hmacSign(`${headerB64}.${bodyB64}`, secret);
  if (expected !== signature) return null;
  let body;
  try { body = JSON.parse(new TextDecoder().decode(b64urlDecode(bodyB64))); }
  catch { return null; }
  if (!body.exp || body.exp < Math.floor(Date.now() / 1000)) return null;
  return body;
}

/* ---------------- cookie helpers ---------------- */
export const SESSION_COOKIE = 'nidhi_admin_session';

export function buildSessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_SECONDS}`;
}
export function buildClearCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}
export function readCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const match = cookieHeader.split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return match ? match.slice(name.length + 1) : null;
}

/* ---------------- login rate limiting (D1-backed, per client IP) ---------------- */
export async function checkLockout(db, ip) {
  const row = await db.prepare('SELECT * FROM admin_login_attempts WHERE ip=?').bind(ip).first();
  if (!row) return { locked: false };
  if (row.locked_until && new Date(row.locked_until) > new Date()) {
    return { locked: true, until: row.locked_until };
  }
  return { locked: false };
}
export async function recordLoginFailure(db, ip) {
  const row = await db.prepare('SELECT * FROM admin_login_attempts WHERE ip=?').bind(ip).first();
  const failCount = (row ? row.fail_count : 0) + 1;
  const lockedUntil = failCount >= MAX_LOGIN_FAILURES
    ? new Date(Date.now() + LOCKOUT_MINUTES * 60000).toISOString()
    : null;
  await db.prepare(
    `INSERT INTO admin_login_attempts (ip, fail_count, locked_until) VALUES (?,?,?)
     ON CONFLICT(ip) DO UPDATE SET fail_count=excluded.fail_count, locked_until=excluded.locked_until`
  ).bind(ip, failCount, lockedUntil).run();
}
export async function clearLoginFailures(db, ip) {
  await db.prepare('DELETE FROM admin_login_attempts WHERE ip=?').bind(ip).run();
}

/* ---------------- Hono middleware ---------------- */
export function requireAdmin() {
  return async (c, next) => {
    const cookie = readCookie(c.req.header('Cookie'), SESSION_COOKIE);
    const session = await verifySession(cookie, c.env.JWT_SECRET);
    if (!session || session.role !== 'admin') {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    // CSRF defense-in-depth: state-changing requests must also carry this
    // custom header. Cross-site HTML forms/img/script tags cannot set
    // custom headers, so this blocks classic CSRF even though the cookie
    // is SameSite=Strict (which alone already blocks most cross-site cases).
    if (['POST', 'PUT', 'DELETE'].includes(c.req.method)) {
      if (c.req.header('X-Admin-Request') !== '1') {
        return c.json({ error: 'Missing CSRF header' }, 403);
      }
    }
    await next();
  };
}
