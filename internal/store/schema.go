package store

import (
	"database/sql"
	"fmt"
	"strings"
)

func (d *DB) migrate() error {
	if _, err := d.SQL.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA journal_size_limit=67108864;`); err != nil {
		return err
	}
	exists, err := d.tableExists("accounts")
	if err != nil {
		return err
	}
	if !exists {
		if err := d.create(); err != nil {
			return err
		}
		return nil
	}
	if d.hasColumn("accounts", "workspace_id") {
		return fmt.Errorf("this ghook version needs a fresh database (multi-tenant SaaS); back up and replace the old file")
	}
	if !d.hasColumn("accounts", "user_id") {
		return fmt.Errorf("unrecognized ghook database schema")
	}
	return d.ensure()
}

func (d *DB) tableExists(name string) (bool, error) {
	var n int
	err := d.SQL.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	return n > 0, err
}

func (d *DB) hasColumn(table, col string) bool {
	rows, err := d.SQL.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk) == nil && name == col {
			return true
		}
	}
	return false
}

func (d *DB) create() error {
	_, err := d.SQL.Exec(schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  subject TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_login INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
  user_id INTEGER NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (user_id, key)
);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  email TEXT NOT NULL UNIQUE,
  refresh_token TEXT NOT NULL DEFAULT '',
  access_token TEXT NOT NULL DEFAULT '',
  access_expiry INTEGER NOT NULL DEFAULT 0,
  scopes TEXT NOT NULL DEFAULT '',
  history_id TEXT NOT NULL DEFAULT '',
  watch_expiry INTEGER NOT NULL DEFAULT 0,
  watch_error TEXT NOT NULL DEFAULT '',
  last_notify INTEGER NOT NULL DEFAULT 0,
  last_notify_history TEXT NOT NULL DEFAULT '',
  last_sync INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL DEFAULT '',
  auth_mode TEXT NOT NULL DEFAULT 'bearer',
  auth_header TEXT NOT NULL DEFAULT '',
  payload_template TEXT NOT NULL DEFAULT '',
  include_body INTEGER NOT NULL DEFAULT 0,
  paused INTEGER NOT NULL DEFAULT 0,
  quiet_start TEXT NOT NULL DEFAULT '',
  quiet_end TEXT NOT NULL DEFAULT '',
  digest_at TEXT NOT NULL DEFAULT '',
  rate_per_minute INTEGER NOT NULL DEFAULT 0,
  last_digest INTEGER NOT NULL DEFAULT 0,
  payload_pubkey TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(user_id, name)
);
CREATE TABLE IF NOT EXISTS routes (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  position INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  fallback INTEGER NOT NULL DEFAULT 0,
  cont INTEGER NOT NULL DEFAULT 0,
  target_id INTEGER NOT NULL,
  match_json TEXT NOT NULL,
  apply_label INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  account_id INTEGER NOT NULL,
  gmail_id TEXT NOT NULL,
  thread_id TEXT NOT NULL DEFAULT '',
  history_id TEXT NOT NULL DEFAULT '',
  from_addr TEXT NOT NULL DEFAULT '',
  to_addr TEXT NOT NULL DEFAULT '',
  cc_addr TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  snippet TEXT NOT NULL DEFAULT '',
  date_ms INTEGER NOT NULL DEFAULT 0,
  labels TEXT NOT NULL DEFAULT '[]',
  category TEXT NOT NULL DEFAULT '',
  has_attachment INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, account_id, gmail_id)
);
CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  delivery_key TEXT NOT NULL UNIQUE,
  account_id INTEGER NOT NULL DEFAULT 0,
  account_email TEXT NOT NULL DEFAULT '',
  gmail_id TEXT NOT NULL,
  thread_id TEXT NOT NULL DEFAULT '',
  route_key TEXT NOT NULL,
  route_name TEXT NOT NULL,
  target_id INTEGER NOT NULL,
  target_name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'mail',
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt INTEGER NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  request_log TEXT NOT NULL DEFAULT '',
  response_status INTEGER NOT NULL DEFAULT 0,
  response_body TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  sent_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(user_id, account_id, gmail_id, route_key)
);
CREATE INDEX IF NOT EXISTS idx_del_due ON deliveries(user_id, status, next_attempt);
CREATE TABLE IF NOT EXISTS user_keys (
  user_id INTEGER PRIMARY KEY,
  wrapped_dek TEXT NOT NULL,
  kek_id TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  rotated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL
);
`

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	if len(s) > 80 {
		return s[:80]
	}
	return s
}
