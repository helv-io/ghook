package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenRejectsWorkspaceEraDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ghook.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE accounts (
		id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL DEFAULT 1, email TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	_, err = Open(path, "test-secret", "")
	if err == nil || !strings.Contains(err.Error(), "fresh database") {
		t.Fatalf("want a fresh-database error, got %v", err)
	}
}

func TestOpenFreshDatabase(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "ghook.db"), "test-secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, u, err := db.EnsureAndUse("sub-ada", "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "ada@example.com" {
		t.Fatalf("user %+v", u)
	}
	if _, err := Open(filepath.Join("no-such-dir", "ghook.db"), "x", ""); err == nil {
		t.Fatal("expected missing path to fail")
	}
	_ = os.ErrNotExist
}
