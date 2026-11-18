package store

import (
	"database/sql"
	"fmt"
	"strings"
)

func (d *DB) migrate() error {
	if _, err := d.SQL.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`); err != nil {
		return err
	}
	exists, err := d.tableExists("accounts")
	if err != nil {
		return err
	}
	if !exists {
		if err := d.createV2(); err != nil {
			return err
		}
	} else if !d.hasColumn("accounts", "workspace_id") {
		if err := d.upgradeV1(); err != nil {
			return err
		}
	}
	return d.ensureDefault()
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

func (d *DB) createV2() error {
	_, err := d.SQL.Exec(schemaV2)
	return err
}

const schemaV2 = `
CREATE TABLE IF NOT EXISTS workspaces (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  subject TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  instance_admin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  user_id INTEGER NOT NULL,
  workspace_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (user_id, workspace_id)
);
CREATE TABLE IF NOT EXISTS invites (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(workspace_id, email)
);
CREATE TABLE IF NOT EXISTS settings (
  workspace_id INTEGER NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (workspace_id, key)
);
CREATE TABLE IF NOT EXISTS pubsubs (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  project TEXT NOT NULL DEFAULT '',
  topic TEXT NOT NULL DEFAULT '',
  subscription TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT 'pull',
  push_audience TEXT NOT NULL DEFAULT '',
  push_email TEXT NOT NULL DEFAULT '',
  use_oauth INTEGER NOT NULL DEFAULT 0,
  sa_json TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(workspace_id, name)
);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL,
  pubsub_id INTEGER NOT NULL DEFAULT 0,
  email TEXT NOT NULL,
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
  updated_at INTEGER NOT NULL,
  UNIQUE(workspace_id, email)
);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL,
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
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(workspace_id, name)
);
CREATE TABLE IF NOT EXISTS routes (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL,
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
  workspace_id INTEGER NOT NULL,
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
  UNIQUE(workspace_id, account_id, gmail_id)
);
CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL,
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
  UNIQUE(workspace_id, account_id, gmail_id, route_key)
);
CREATE INDEX IF NOT EXISTS idx_del_due ON deliveries(workspace_id, status, next_attempt);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL
);
`

func (d *DB) upgradeV1() error {
	tx, err := d.SQL.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS workspaces (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
INSERT INTO workspaces(id, name, created_at) SELECT 1, 'Default', strftime('%s','now') WHERE NOT EXISTS (SELECT 1 FROM workspaces);
`); err != nil {
		return err
	}
	// Settings gain a workspace id. Instance secrets stay on workspace 0.
	// Do not query the pool here: this transaction holds the only connection.
	if _, err := tx.Exec(`
ALTER TABLE settings RENAME TO settings_v1;
CREATE TABLE settings (workspace_id INTEGER NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (workspace_id, key));
INSERT INTO settings(workspace_id, key, value)
  SELECT CASE WHEN key IN ('session_secret','google_client_json') THEN 0 ELSE 1 END, key, value FROM settings_v1;
DROP TABLE settings_v1;
`); err != nil {
		return err
	}
	steps := []string{
		`CREATE TABLE accounts_v2 AS SELECT id, 1 AS workspace_id, 0 AS pubsub_id, email, refresh_token, access_token, access_expiry, scopes, history_id, watch_expiry, watch_error, last_notify, last_notify_history, last_sync, disabled, created_at, updated_at FROM accounts`,
		`DROP TABLE accounts`,
		`CREATE TABLE accounts (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, pubsub_id INTEGER NOT NULL DEFAULT 0,
  email TEXT NOT NULL, refresh_token TEXT NOT NULL DEFAULT '', access_token TEXT NOT NULL DEFAULT '',
  access_expiry INTEGER NOT NULL DEFAULT 0, scopes TEXT NOT NULL DEFAULT '', history_id TEXT NOT NULL DEFAULT '',
  watch_expiry INTEGER NOT NULL DEFAULT 0, watch_error TEXT NOT NULL DEFAULT '', last_notify INTEGER NOT NULL DEFAULT 0,
  last_notify_history TEXT NOT NULL DEFAULT '', last_sync INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(workspace_id, email))`,
		`INSERT INTO accounts SELECT * FROM accounts_v2`,
		`DROP TABLE accounts_v2`,
		`CREATE TABLE targets_v2 AS SELECT id, 1 AS workspace_id, name, url, secret, auth_mode, auth_header, payload_template, include_body, paused, quiet_start, quiet_end, digest_at, rate_per_minute, last_digest, created_at, updated_at FROM targets`,
		`DROP TABLE targets`,
		`CREATE TABLE targets (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, name TEXT NOT NULL, url TEXT NOT NULL,
  secret TEXT NOT NULL DEFAULT '', auth_mode TEXT NOT NULL DEFAULT 'bearer', auth_header TEXT NOT NULL DEFAULT '',
  payload_template TEXT NOT NULL DEFAULT '', include_body INTEGER NOT NULL DEFAULT 0, paused INTEGER NOT NULL DEFAULT 0,
  quiet_start TEXT NOT NULL DEFAULT '', quiet_end TEXT NOT NULL DEFAULT '', digest_at TEXT NOT NULL DEFAULT '',
  rate_per_minute INTEGER NOT NULL DEFAULT 0, last_digest INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL, UNIQUE(workspace_id, name))`,
		`INSERT INTO targets SELECT * FROM targets_v2`,
		`DROP TABLE targets_v2`,
		`CREATE TABLE routes_v2 AS SELECT id, 1 AS workspace_id, name, position, enabled, fallback, cont, target_id, match_json, apply_label, created_at, updated_at FROM routes`,
		`DROP TABLE routes`,
		`CREATE TABLE routes (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, name TEXT NOT NULL, position INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1, fallback INTEGER NOT NULL DEFAULT 0, cont INTEGER NOT NULL DEFAULT 0,
  target_id INTEGER NOT NULL, match_json TEXT NOT NULL, apply_label INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
		`INSERT INTO routes SELECT * FROM routes_v2`,
		`DROP TABLE routes_v2`,
		`CREATE TABLE messages_v2 AS SELECT id, 1 AS workspace_id, account_id, gmail_id, thread_id, history_id, from_addr, to_addr, cc_addr, subject, snippet, date_ms, labels, category, has_attachment, created_at FROM messages`,
		`DROP TABLE messages`,
		`CREATE TABLE messages (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, account_id INTEGER NOT NULL, gmail_id TEXT NOT NULL,
  thread_id TEXT NOT NULL DEFAULT '', history_id TEXT NOT NULL DEFAULT '', from_addr TEXT NOT NULL DEFAULT '',
  to_addr TEXT NOT NULL DEFAULT '', cc_addr TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
  snippet TEXT NOT NULL DEFAULT '', date_ms INTEGER NOT NULL DEFAULT 0, labels TEXT NOT NULL DEFAULT '[]',
  category TEXT NOT NULL DEFAULT '', has_attachment INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
  UNIQUE(workspace_id, account_id, gmail_id))`,
		`INSERT INTO messages SELECT * FROM messages_v2`,
		`DROP TABLE messages_v2`,
		`CREATE TABLE deliveries_v2 AS SELECT id, 1 AS workspace_id, delivery_key, account_id, account_email, gmail_id, thread_id, route_key, route_name, target_id, target_name, kind, status, attempts, next_attempt, last_error, request_log, response_status, response_body, payload_json, created_at, updated_at, sent_at FROM deliveries`,
		`DROP TABLE deliveries`,
		`CREATE TABLE deliveries (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, delivery_key TEXT NOT NULL UNIQUE,
  account_id INTEGER NOT NULL DEFAULT 0, account_email TEXT NOT NULL DEFAULT '', gmail_id TEXT NOT NULL,
  thread_id TEXT NOT NULL DEFAULT '', route_key TEXT NOT NULL, route_name TEXT NOT NULL,
  target_id INTEGER NOT NULL, target_name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'mail',
  status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
  last_error TEXT NOT NULL DEFAULT '', request_log TEXT NOT NULL DEFAULT '', response_status INTEGER NOT NULL DEFAULT 0,
  response_body TEXT NOT NULL DEFAULT '', payload_json TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL, sent_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(workspace_id, account_id, gmail_id, route_key))`,
		`INSERT INTO deliveries SELECT * FROM deliveries_v2`,
		`DROP TABLE deliveries_v2`,
		`CREATE TABLE audit_v2 AS SELECT id, 1 AS workspace_id, at, actor, action, detail FROM audit`,
		`DROP TABLE audit`,
		`CREATE TABLE audit (id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)`,
		`INSERT INTO audit SELECT * FROM audit_v2`,
		`DROP TABLE audit_v2`,
	}
	for _, s := range steps {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("upgrade: %w (%s)", err, firstLine(s))
		}
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS pubsubs (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, name TEXT NOT NULL,
  project TEXT NOT NULL DEFAULT '', topic TEXT NOT NULL DEFAULT '', subscription TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT 'pull', push_audience TEXT NOT NULL DEFAULT '', push_email TEXT NOT NULL DEFAULT '',
  use_oauth INTEGER NOT NULL DEFAULT 0, sa_json TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(workspace_id, name))`); err != nil {
		return err
	}
	// Move the old singleton Pub/Sub settings into one connection.
	if _, err := tx.Exec(`INSERT INTO pubsubs(workspace_id, name, project, topic, subscription, mode, push_audience, push_email, use_oauth, sa_json, created_at, updated_at)
SELECT 1, 'main',
  COALESCE((SELECT value FROM settings WHERE workspace_id=1 AND key='ps_project'), ''),
  COALESCE((SELECT value FROM settings WHERE workspace_id=1 AND key='ps_topic'), ''),
  COALESCE((SELECT value FROM settings WHERE workspace_id=1 AND key='ps_subscription'), ''),
  COALESCE((SELECT value FROM settings WHERE workspace_id=1 AND key='ps_mode'), 'pull'),
  COALESCE((SELECT value FROM settings WHERE workspace_id=1 AND key='ps_push_audience'), ''),
  COALESCE((SELECT value FROM settings WHERE workspace_id=1 AND key='ps_push_email'), ''),
  CASE WHEN COALESCE((SELECT value FROM settings WHERE workspace_id=1 AND key='ps_use_oauth'), '0') IN ('1','true') THEN 1 ELSE 0 END,
  COALESCE((SELECT value FROM settings WHERE key='ps_sa_json'), ''),
  strftime('%s','now'), strftime('%s','now')
WHERE EXISTS (SELECT 1 FROM settings WHERE key IN ('ps_project','ps_topic','ps_subscription','ps_sa_json'))
  AND NOT EXISTS (SELECT 1 FROM pubsubs)`); err != nil {
		return err
	}
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, subject TEXT NOT NULL UNIQUE, email TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '', instance_admin INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS memberships (
  user_id INTEGER NOT NULL, workspace_id INTEGER NOT NULL, role TEXT NOT NULL, PRIMARY KEY (user_id, workspace_id));
CREATE TABLE IF NOT EXISTS invites (
  id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL,
  created_at INTEGER NOT NULL, UNIQUE(workspace_id, email));`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

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

func (d *DB) ensureDefault() error {
	var n int
	if err := d.SQL.QueryRow(`SELECT count(*) FROM workspaces`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := d.SQL.Exec(`INSERT INTO workspaces(name, created_at) VALUES('Default', strftime('%s','now'))`); err != nil {
			return err
		}
	}
	return nil
}
