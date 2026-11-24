package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "ghook.db"), "test-secret", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNewFileIsIncremental(t *testing.T) {
	db := openTest(t)
	var mode int
	if err := db.SQL.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil || mode != 2 {
		t.Fatalf("auto_vacuum = %d, %v; want 2 (incremental)", mode, err)
	}
}

func TestCompactShrinksFile(t *testing.T) {
	db := openTest(t)
	// Start from a file without incremental vacuum, like one made by an older release.
	if _, err := db.SQL.Exec(`PRAGMA auto_vacuum=NONE; VACUUM`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL.Exec(`CREATE TABLE junk(b BLOB)`); err != nil {
		t.Fatal(err)
	}
	blob := strings.Repeat("x", 64<<10)
	for i := 0; i < 200; i++ {
		if _, err := db.SQL.Exec(`INSERT INTO junk VALUES (?)`, blob); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.SQL.Exec(`DELETE FROM junk`); err != nil {
		t.Fatal(err)
	}
	res, err := db.Compact()
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "vacuum" {
		t.Fatalf("first run mode %q, want vacuum", res.Mode)
	}
	if res.Before.FreeBytes() < 8<<20 || !res.Before.NeedsCompact() {
		t.Fatalf("before: %+v", res.Before)
	}
	if res.After.FreePages != 0 || res.After.WAL != 0 || res.After.Bytes()*10 > res.Before.Bytes() {
		t.Fatalf("after: %+v (before %+v)", res.After, res.Before)
	}
	if res.After.NeedsCompact() {
		t.Fatal("still wants compaction")
	}
	if db.CompactLast().IsZero() {
		t.Fatal("last run not recorded")
	}

	// Now incremental: freed pages go back without a full rewrite.
	for i := 0; i < 50; i++ {
		_, _ = db.SQL.Exec(`INSERT INTO junk VALUES (?)`, blob)
	}
	_, _ = db.SQL.Exec(`DELETE FROM junk`)
	res, err = db.Compact()
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "incremental" || res.After.FreePages != 0 {
		t.Fatalf("second run: %q %+v", res.Mode, res.After)
	}
}

func TestCompactSkipsWhileRunning(t *testing.T) {
	db := openTest(t)
	db.maint.Lock()
	defer db.maint.Unlock()
	if _, err := db.Use(1).Compact(); err != ErrCompactBusy {
		t.Fatalf("err = %v, want ErrCompactBusy", err)
	}
}

func TestTokensSealedOnce(t *testing.T) {
	db := openTest(t)
	u, _, err := db.EnsureAndUse("sub-a", "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := u.SaveAccount("ada@example.com", "refresh-1", "access-1", 100, "gmail.readonly", "1")
	if err != nil {
		t.Fatal(err)
	}
	rawLen := func() int {
		var r string
		if err := db.SQL.QueryRow(`SELECT refresh_token FROM accounts WHERE id=?`, acc.ID).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return len(r)
	}
	first := rawLen()
	// A caller that hands back the stored (sealed) value must not nest it.
	var sealed string
	_ = db.SQL.QueryRow(`SELECT refresh_token FROM accounts WHERE id=?`, acc.ID).Scan(&sealed)
	for i := 0; i < 5; i++ {
		if err := u.UpdateTokens(acc.ID, sealed, "access-2", 200); err != nil {
			t.Fatal(err)
		}
	}
	if got := rawLen(); got != first {
		t.Fatalf("refresh grew from %d to %d bytes", first, got)
	}
	// An empty refresh keeps the stored one.
	if err := u.UpdateTokens(acc.ID, "", "access-3", 300); err != nil {
		t.Fatal(err)
	}
	got, ok, err := u.AccountByID(acc.ID)
	if err != nil || !ok || got.RefreshToken() != "refresh-1" {
		t.Fatalf("refresh %q ok %v err %v", got.RefreshToken(), ok, err)
	}
	if a, _ := got.AccessToken(); a != "access-3" {
		t.Fatalf("access %q", a)
	}
}

func TestNestedTokenOpensToPlain(t *testing.T) {
	db := openTest(t)
	u, _, err := db.EnsureAndUse("sub-a", "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := u.SaveAccount("ada@example.com", "refresh-1", "", 0, "gmail.readonly", "1")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a value an older release sealed several times over.
	v := "refresh-1"
	for i := 0; i < 6; i++ {
		v = u.Box.Seal(v)
	}
	if _, err := db.SQL.Exec(`UPDATE accounts SET refresh_token=? WHERE id=?`, v, acc.ID); err != nil {
		t.Fatal(err)
	}
	got, ok, err := u.AccountByID(acc.ID)
	if err != nil || !ok || got.RefreshToken() != "refresh-1" {
		t.Fatalf("refresh %q ok %v err %v", got.RefreshToken(), ok, err)
	}
}
