import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';
import crypto from 'node:crypto';

// Must match TEST_PASSWORD in test/api.test.js — this is a throwaway
// test-only credential, never used outside the test runner.
const TEST_PASSWORD = 'testpassword123';
const salt = crypto.randomBytes(16);
const derived = crypto.pbkdf2Sync(TEST_PASSWORD, salt, 100000, 32, 'sha256');
const ADMIN_PASSWORD_HASH = `${salt.toString('base64')}:${derived.toString('base64')}`;

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          bindings: {
            ADMIN_PASSWORD_HASH,
            JWT_SECRET: 'test-only-jwt-secret',
            ALLOWED_ORIGIN: '*',
          },
        },
      },
    },
  },
});
