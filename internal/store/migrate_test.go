package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestUpgradeMovesRowsIntoDefaultWorkspace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO settings(key, value) VALUES('label_prefix', 'Ghook');
CREATE TABLE accounts (
  id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, refresh_token TEXT NOT NULL DEFAULT '',
  access_token TEXT NOT NULL DEFAULT '', access_expiry INTEGER NOT NULL DEFAULT 0, scopes TEXT NOT NULL DEFAULT '',
  history_id TEXT NOT NULL DEFAULT '', watch_expiry INTEGER NOT NULL DEFAULT 0, watch_error TEXT NOT NULL DEFAULT '',
  last_notify INTEGER NOT NULL DEFAULT 0, last_notify_history TEXT NOT NULL DEFAULT '', last_sync INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
INSERT INTO accounts(email, created_at, updated_at) VALUES('ada@example.com', 1, 1);
CREATE TABLE targets (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL, secret TEXT NOT NULL DEFAULT '',
  auth_mode TEXT NOT NULL DEFAULT 'bearer', auth_header TEXT NOT NULL DEFAULT '', payload_template TEXT NOT NULL DEFAULT '',
  include_body INTEGER NOT NULL DEFAULT 0, paused INTEGER NOT NULL DEFAULT 0, quiet_start TEXT NOT NULL DEFAULT '',
  quiet_end TEXT NOT NULL DEFAULT '', digest_at TEXT NOT NULL DEFAULT '', rate_per_minute INTEGER NOT NULL DEFAULT 0,
  last_digest INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
INSERT INTO targets(name, url, created_at, updated_at) VALUES('ceo', 'https://bot.example.com/hook', 1, 1);
CREATE TABLE routes (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, position INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  fallback INTEGER NOT NULL DEFAULT 0, cont INTEGER NOT NULL DEFAULT 0, target_id INTEGER NOT NULL,
  match_json TEXT NOT NULL, apply_label INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE messages (
  id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL, gmail_id TEXT NOT NULL, thread_id TEXT NOT NULL DEFAULT '',
  history_id TEXT NOT NULL DEFAULT '', from_addr TEXT NOT NULL DEFAULT '', to_addr TEXT NOT NULL DEFAULT '',
  cc_addr TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '', snippet TEXT NOT NULL DEFAULT '',
  date_ms INTEGER NOT NULL DEFAULT 0, labels TEXT NOT NULL DEFAULT '[]', category TEXT NOT NULL DEFAULT '',
  has_attachment INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, UNIQUE(account_id, gmail_id));
CREATE TABLE deliveries (
  id INTEGER PRIMARY KEY, delivery_key TEXT NOT NULL UNIQUE, account_id INTEGER NOT NULL DEFAULT 0,
  account_email TEXT NOT NULL DEFAULT '', gmail_id TEXT NOT NULL, thread_id TEXT NOT NULL DEFAULT '',
  route_key TEXT NOT NULL, route_name TEXT NOT NULL, target_id INTEGER NOT NULL, target_name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'mail', status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt INTEGER NOT NULL, last_error TEXT NOT NULL DEFAULT '', request_log TEXT NOT NULL DEFAULT '',
  response_status INTEGER NOT NULL DEFAULT 0, response_body TEXT NOT NULL DEFAULT '', payload_json TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, sent_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(account_id, gmail_id, route_key));
CREATE TABLE audit (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
`)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	db, err := Open(path, "", filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ws, err := db.Workspaces()
	if err != nil || len(ws) != 1 || ws[0].Name != "Default" {
		t.Fatalf("workspaces %+v %v", ws, err)
	}
	accs, err := db.Accounts()
	if err != nil || len(accs) != 1 || accs[0].Email != "ada@example.com" || accs[0].WorkspaceID != ws[0].ID {
		t.Fatalf("accounts %+v %v", accs, err)
	}
	targets, err := db.Targets()
	if err != nil || len(targets) != 1 || targets[0].Name != "ceo" {
		t.Fatalf("targets %+v %v", targets, err)
	}
	if db.Setting("label_prefix", "") != "Ghook" {
		t.Fatal("setting was not moved")
	}
	other, err := db.CreateWorkspace("Other", 0)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := db.Use(other.ID).Accounts(); len(n) != 0 {
		t.Fatal("other workspace saw the migrated mailbox")
	}
}
