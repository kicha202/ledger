#!/usr/bin/env node
// Generates the ADMIN_PASSWORD_HASH value for wrangler.toml / `wrangler secret put`.
// Usage: node scripts/hash-password.js "YourStrongPassword"
// Uses PBKDF2-HMAC-SHA256, matching worker/src/auth.js exactly (same iterations/keylen).

import crypto from 'node:crypto';

const ITERATIONS = 100000;
const KEYLEN = 32;

const password = process.argv[2];
if (!password) {
  console.error('Usage: node scripts/hash-password.js "YourStrongPassword"');
  process.exit(1);
}

const salt = crypto.randomBytes(16);
const derived = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEYLEN, 'sha256');
const value = `${salt.toString('base64')}:${derived.toString('base64')}`;

console.log('\nADMIN_PASSWORD_HASH value (store as a Worker secret, never commit it):\n');
console.log(value);
console.log('\nSet it with:\n  npx wrangler secret put ADMIN_PASSWORD_HASH\n(paste the value above when prompted)\n');
