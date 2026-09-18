# Nidhi Ledger — Cloudflare-backed CRUD app

Converts the original single-file, localStorage-only `nidhi-ledger-app-3.html`
into a real client/server app: static frontend (Cloudflare Pages) + REST API
(Cloudflare Worker, Hono) + Cloudflare D1 (SQLite) database. UI, styling, and
all business logic (loan schedules, interest calc, cycle reset, exit
settlement, exports) are unchanged — only the persistence layer moved from
`localStorage`/`window.storage` to the database.

## Structure

```
nidhi-app/
  frontend/index.html   # original UI, storage calls now hit the API
  worker/
    src/index.js         # Hono API (all routes, prepared statements)
    schema.sql            # D1 schema (tables, indexes, relationships)
    wrangler.toml          # Worker + D1 binding config
    package.json
  README.md               # this file
```

## Data model

| Table | Purpose | Key relationships |
|---|---|---|
| `members` | Member registration | — |
| `subscriptions` | Monthly subscription payments | `member_id → members.id` |
| `loans` | Issued loans | `member_id → members.id` |
| `loan_payments` | Installment payments against a loan | `loan_id → loans.id` |
| `transactions` | Income/expense ledger (manual + auto-generated) | `loan_id`, `member_id` (nullable) |
| `cycles` | Interest-distribution cycle-close history | — |
| `settings` | Single-row config: org name, start month, standard sub amount | — |

Full DDL with indexes and foreign keys: `worker/schema.sql`.

## How persistence works

The original app kept one in-memory `state` object (`{members, subs, loans,
loanPayments, transactions, cycles, settings}`) and wrote it whole to
`localStorage` on every change via `saveState()`.

That's preserved architecturally, but now:
- `loadState()` calls `GET /api/state` to hydrate `state` from D1 on page load.
- `saveState()` calls `PUT /api/state`, which the Worker applies as **one
  atomic D1 batch** (prepared statements only — delete all rows, re-insert
  the current payload for every table, transactionally). This keeps
  multi-table workflows (member exit settlement, final closure, cycle reset,
  bulk monthly entry, backup restore) consistent without touching the 40+
  existing mutator functions individually.

In addition, the Worker exposes full granular REST CRUD per resource
(`/api/members`, `/api/subs`, `/api/loans`, etc.) for direct integrations,
scripting, or future incremental-save work — see API reference below.

## Database setup

1. Install Wrangler and log in:
   ```
   cd worker
   npm install
   npx wrangler login
   ```
2. Create the D1 database:
   ```
   npx wrangler d1 create nidhi_ledger
   ```
   Copy the returned `database_id` into `wrangler.toml` (`REPLACE_WITH_YOUR_D1_DATABASE_ID`).
3. Apply the schema:
   ```
   npm run db:init:remote      # production D1
   npm run db:init:local       # local D1 (for `wrangler dev`)
   ```

## Super Admin panel (`frontend/admin.html`)

A separate, protected control panel with full CRUD over every table
(members, subscriptions, loans, installments, transactions, cycles,
settings). The main ledger app (`index.html`) stays open/unauthenticated as
requested; the admin surface is what's locked down.

**Security measures implemented:**
- **Password never stored in code or DB** — only a PBKDF2-SHA256 hash
  (100,000 iterations, random salt) lives in the `ADMIN_PASSWORD_HASH`
  Worker secret. Change the password by regenerating the hash and updating
  that one env secret — nothing else changes.
- **Sessions**: signed JWT (HMAC-SHA256, `JWT_SECRET` env secret) in an
  `HttpOnly`, `Secure`, `SameSite=Strict` cookie — not readable by JS, so an
  XSS bug can't steal the session token.
- **Protected routes**: every granular `/api/*` CRUD endpoint (members,
  subs, loans, loan-payments, transactions, cycles, settings) requires a
  valid session; `/api/state` stays public (that's what the open ledger app
  uses). Enforced by one middleware (`requireAdmin` in `worker/src/auth.js`),
  not per-route checks that could be forgotten.
  Requesting a protected route with no/invalid session → `401`.
- **CSRF defense-in-depth**: mutating requests (POST/PUT/DELETE) must carry
  a custom `X-Admin-Request: 1` header in addition to the SameSite cookie —
  cross-site forms/images can't set custom headers, so classic CSRF is
  blocked even if a browser's SameSite handling is misconfigured.
- **Brute-force lockout**: 5 failed logins from one IP locks that IP out for
  15 minutes (`admin_login_attempts` table in D1, survives Worker restarts).
- **Generic error messages**: wrong password just says "Invalid
  credentials" — no hints about account existence.
- **Constant-time password comparison** to avoid timing side-channels.
- **Security headers** on every API response: `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Strict-Transport-Security`.
- **Prepared statements only** — every query anywhere in the Worker uses
  `.bind()`, never string-concatenated SQL.

### Generating the admin password hash

```
cd worker
node scripts/hash-password.js "YourStrongPassword"
```
Copy the printed value and store it as a secret (never commit it):
```
npx wrangler secret put ADMIN_PASSWORD_HASH
npx wrangler secret put JWT_SECRET      # any long random string, e.g. `openssl rand -hex 32`
```
To change the password later: regenerate the hash and re-run
`wrangler secret put ADMIN_PASSWORD_HASH` — that's the only place it's
configurable, as required.

### Deploying the admin page

Same Pages deploy as the main frontend — `admin.html` sits next to
`index.html`. Set `window.NIDHI_API_BASE` in `admin.html` the same way as in
`index.html`. Visit `https://your-pages-site/admin.html` to log in.

## Environment variables / config

Worker (`wrangler.toml` `[vars]` for non-secret, `wrangler secret put` for secrets):
- `ALLOWED_ORIGIN` — CORS origin allowed to call the API (your Pages URL, e.g.
  `https://nidhi-ledger.pages.dev`). **Must be an exact origin, not `*`,
  once the admin panel is in use** — browsers reject wildcard origins on
  credentialed (cookie-bearing) requests, so the admin login won't work
  until this is a real URL.
- `ADMIN_PASSWORD_HASH` (secret) — PBKDF2 hash of the admin password. See
  "Generating the admin password hash" above. Never set as a plain `[vars]`
  value — always `wrangler secret put`.
- `JWT_SECRET` (secret) — random signing key for session tokens, e.g.
  `openssl rand -hex 32`. Also via `wrangler secret put`.

Frontend (`frontend/index.html`):
- `API_BASE` (top of the `<script>` block) — reads `window.NIDHI_API_BASE`.
  Set it by adding, right before the main `<script>` tag, e.g.:
  ```html
  <script>window.NIDHI_API_BASE = 'https://nidhi-ledger-api.YOUR-SUBDOMAIN.workers.dev';</script>
  ```
  Leave unset only if Pages and the Worker are proxied under the same origin.

## Cloudflare deployment

**Worker (API):**
```
cd worker
npx wrangler deploy
```
Note the deployed URL (`https://nidhi-ledger-api.<subdomain>.workers.dev`).

**Pages (frontend):**
- Dashboard: Pages → Create project → Direct upload → upload `frontend/` folder.
- Or CLI:
  ```
  npx wrangler pages deploy frontend --project-name=nidhi-ledger
  ```
- Set `window.NIDHI_API_BASE` in `frontend/index.html` to the Worker URL from
  the previous step, then redeploy Pages.
- Set `ALLOWED_ORIGIN` in the Worker to the resulting Pages URL, then
  redeploy the Worker.

The main ledger (`index.html`) has no login (open by design, per
requirements). The Super Admin panel (`admin.html`) is fully protected —
see the section above.

## API reference

Base path: `/api`. All bodies/responses are JSON. All queries use D1 prepared
statements (`.bind()`) — no string-concatenated SQL anywhere.

🔓 = public (no session needed). 🔒 = requires a valid admin session cookie
(and, for POST/PUT/DELETE, the `X-Admin-Request: 1` header).

### Bootstrap / full sync (used by the open ledger app) 🔓
| Method | Path | Description |
|---|---|---|
| GET | `/api/state` | Returns `{members, subs, loans, loanPayments, transactions, cycles, settings}` |
| PUT | `/api/state` | Atomically replaces all table contents with the given payload |

### Super Admin auth
| Method | Path | Auth | Body / Notes |
|---|---|---|---|
| POST | `/api/admin/login` | 🔓 | `{password}` → sets session cookie. 401 on bad password, 429 after 5 failures/15 min |
| POST | `/api/admin/logout` | 🔓 | Clears the session cookie |
| GET | `/api/admin/session` | 🔓 | `{authenticated: bool}` — used by `admin.html` on load |

### Members 🔒
| Method | Path | Body |
|---|---|---|
| GET | `/api/members` | — |
| POST | `/api/members` | `{id, name, phone?, address?, joinDate?, nominee?, regFee?, exited?, exitDate?, exitAmount?}` |
| PUT | `/api/members/:id` | same fields (minus id) |
| DELETE | `/api/members/:id` | — |

### Subscriptions 🔒
| Method | Path | Body |
|---|---|---|
| GET | `/api/subs` | — |
| POST | `/api/subs` | `{id, memberId, month, amount, date}` |
| DELETE | `/api/subs/:id` | — |

### Loans 🔒
| Method | Path | Body |
|---|---|---|
| GET | `/api/loans` | — |
| POST | `/api/loans` | `{id, memberId, amount, rate, installments, issueDate, deductInterest?, deductionRate?}` |
| PUT | `/api/loans/:id` | same fields (minus id/memberId) |
| DELETE | `/api/loans/:id` | cascades to its loan_payments |

### Loan payments 🔒
| Method | Path | Body |
|---|---|---|
| GET | `/api/loans/:id/payments` | — |
| POST | `/api/loans/:id/payments` | `{id, no, amount, date, interestWaived?}` |
| DELETE | `/api/loan-payments/:id` | — |

### Transactions (ledger) 🔒
| Method | Path | Body |
|---|---|---|
| GET | `/api/transactions` | — |
| POST | `/api/transactions` | `{id, type, amount, category?, date, note?, auto?, sourceType?, loanId?, memberId?}` |
| PUT | `/api/transactions/:id` | same fields |
| DELETE | `/api/transactions/:id` | — |

### Cycles 🔒
| Method | Path | Body |
|---|---|---|
| GET | `/api/cycles` | — |
| POST | `/api/cycles` | `{number, resetDate, interestDistributed, perMemberShare, memberCount}` |

### Settings (single row) 🔒
| Method | Path | Body |
|---|---|---|
| GET | `/api/settings` | — |
| PUT | `/api/settings` | `{orgName, startMonth, startMonthAuto, subAmount}` |

Errors return `{error: "message"}` with a 4xx status.

## Local development

```
cd worker
npm install
npm run db:init:local
npx wrangler dev
```
Then open `frontend/index.html` via a local static server (e.g. `npx serve frontend`),
with `window.NIDHI_API_BASE` pointed at the `wrangler dev` URL (default `http://localhost:8787`).

## Automated tests

```
cd worker
npm install
npm test
```

Integration tests (`worker/test/api.test.js`, via `@cloudflare/vitest-pool-workers`
— runs the real Worker against an in-memory D1, no mocking) cover:
- `/api/state` stays public with no session (ledger app keeps working).
- Admin login: empty password rejected, wrong password rejected with a
  generic error, 5 failed attempts locks the IP out (429).
- Protected routes reject requests with no session cookie (401).
- A valid session is required **and** the `X-Admin-Request` CSRF header is
  required for mutations — missing either is rejected.
- Full member CRUD (create → list → update → delete) through the
  authenticated admin API.
- Nested resource: creating a loan, recording an installment payment, and
  confirming `ON DELETE CASCADE` removes its payments when the loan is deleted.
- Logout actually invalidates the session.

Bugs this test pass caught and fixed while building the admin layer:
1. **CORS `origin: '*'` + cookies** — browsers refuse wildcard CORS on
   credentialed requests, which would have silently broken every admin
   login. Fixed: `ALLOWED_ORIGIN` must be an exact origin, `credentials: true`
   set in the CORS middleware.
2. **Missing `nodejs_compat` flag** — required for the Worker's
   `crypto`/`atob`/`btoa` usage in `auth.js`; without it the Worker fails
   to even start.
3. **Semicolon inside a SQL comment in `schema.sql`** (`-- ISO timestamp;
   NULL = not locked`) broke naive statement-splitting (used by the test
   setup, and would break any simple SQL migration runner). Fixed by
   rewording the comment.
