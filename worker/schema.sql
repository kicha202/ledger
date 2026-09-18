-- Nidhi Ledger — D1 (SQLite) schema
-- Run: wrangler d1 execute nidhi_ledger --file=./schema.sql (add --remote for production)

PRAGMA foreign_keys = ON;

-- Single-row settings table (org name, sub amount, cycle start month)
CREATE TABLE IF NOT EXISTS settings (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  org_name          TEXT DEFAULT '',
  start_month       TEXT,                 -- 'YYYY-MM'
  start_month_auto  INTEGER DEFAULT 1,    -- 1 = auto-detected, 0 = user-fixed
  sub_amount        REAL DEFAULT 500
);
INSERT OR IGNORE INTO settings (id, org_name, start_month, start_month_auto, sub_amount)
VALUES (1, '', NULL, 1, 500);

CREATE TABLE IF NOT EXISTS members (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  phone       TEXT,
  address     TEXT,
  join_date   TEXT,                 -- 'YYYY-MM-DD'
  nominee     TEXT,
  reg_fee     REAL DEFAULT 0,
  exited      INTEGER DEFAULT 0,    -- 0/1
  exit_date   TEXT,
  exit_amount REAL,
  created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id         TEXT PRIMARY KEY,
  member_id  TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  month      TEXT NOT NULL,          -- 'YYYY-MM'
  amount     REAL NOT NULL,
  date       TEXT NOT NULL           -- 'YYYY-MM-DD'
);
CREATE INDEX IF NOT EXISTS idx_subs_member ON subscriptions(member_id);
CREATE INDEX IF NOT EXISTS idx_subs_month  ON subscriptions(month);

CREATE TABLE IF NOT EXISTS loans (
  id               TEXT PRIMARY KEY,
  member_id        TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  amount           REAL NOT NULL,
  rate             REAL NOT NULL,     -- monthly interest %
  installments     INTEGER NOT NULL,
  issue_date       TEXT NOT NULL,
  deduct_interest  INTEGER DEFAULT 0,
  deduction_rate   REAL
);
CREATE INDEX IF NOT EXISTS idx_loans_member ON loans(member_id);

CREATE TABLE IF NOT EXISTS loan_payments (
  id               TEXT PRIMARY KEY,
  loan_id          TEXT NOT NULL REFERENCES loans(id) ON DELETE CASCADE,
  no               INTEGER NOT NULL,   -- installment number
  amount           REAL NOT NULL,
  date             TEXT NOT NULL,
  interest_waived  INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_payments_loan ON loan_payments(loan_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_payments_loan_no ON loan_payments(loan_id, no);

CREATE TABLE IF NOT EXISTS transactions (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL CHECK (type IN ('income','expense')),
  amount      REAL NOT NULL,
  category    TEXT,
  date        TEXT NOT NULL,
  note        TEXT,
  auto        INTEGER DEFAULT 0,     -- 1 = system-generated (loan/exit/etc.)
  source_type TEXT,                 -- 'loan' | 'loan_payment' | 'member_fee' | 'interest_buyin' | 'member_exit' | NULL
  loan_id     TEXT REFERENCES loans(id) ON DELETE SET NULL,
  member_id   TEXT REFERENCES members(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_txn_date   ON transactions(date);
CREATE INDEX IF NOT EXISTS idx_txn_source ON transactions(source_type);

CREATE TABLE IF NOT EXISTS cycles (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  number                INTEGER NOT NULL,
  reset_date            TEXT NOT NULL,
  interest_distributed  REAL NOT NULL,
  per_member_share      REAL NOT NULL,
  member_count          INTEGER NOT NULL
);

-- Login attempt tracking for the Super Admin login (brute-force lockout).
-- One row per client IP; reset on successful login.
CREATE TABLE IF NOT EXISTS admin_login_attempts (
  ip            TEXT PRIMARY KEY,
  fail_count    INTEGER NOT NULL DEFAULT 0,
  locked_until  TEXT             -- ISO timestamp, NULL means not locked
);

-- Sample data (safe to delete): one member, one sub payment
-- INSERT INTO members (id,name,phone,address,join_date,nominee,reg_fee,exited)
--   VALUES ('m_sample1','Sample Member','9999999999','','2025-01-01','','100',0);
-- INSERT INTO subscriptions (id,member_id,month,amount,date)
--   VALUES ('s_sample1','m_sample1','2025-01','500','2025-01-05');
