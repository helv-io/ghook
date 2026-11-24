package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/secrets"
)

func TestEnvelopeRoundTripRotateShred(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ghook.db")
	keyFile := filepath.Join(dir, "secrets.key")
	db, err := Open(dbPath, "", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scoped, u, err := db.EnsureAndUse("sub-ada", "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if !db.HasDEK(u.ID) {
		t.Fatal("expected a wrapped DEK after first Use")
	}

	const token = "refresh-token-value-XYZ"
	const hookSecret = "supersecret-hook-XYZ"
	const fromAddr = "billing-xyz@example.com"
	if _, err := scoped.SaveAccount("ada@example.com", token, "access-xyz", 0, "gmail.readonly", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.SaveTarget(Target{Name: "Chief of Staff", URL: "https://bot.example.com/hook"}, hookSecret, false); err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.SaveRoute(Route{Name: "invoices", TargetID: 1, Enabled: true, Spec: match.Spec{From: []string{fromAddr}}}); err != nil {
		t.Fatal(err)
	}

	assertAbsent(t, dbPath, token, hookSecret, fromAddr)

	acc, ok, err := scoped.AccountByEmail("ada@example.com")
	if err != nil || !ok {
		t.Fatalf("load account %v %v", ok, err)
	}
	if acc.RefreshToken() != token {
		t.Fatalf("refresh token %q", acc.RefreshToken())
	}
	tg, ok, err := scoped.TargetByName("Chief of Staff", true)
	if err != nil || !ok || tg.Secret() != hookSecret {
		t.Fatalf("target secret ok=%v err=%v", ok, err)
	}
	rts, err := scoped.Routes()
	if err != nil || len(rts) != 1 || len(rts[0].Spec.From) == 0 || rts[0].Spec.From[0] != fromAddr {
		t.Fatalf("route %+v %v", rts, err)
	}

	if err := db.RotateDEK(u.ID); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, dbPath, token, hookSecret, fromAddr)
	scoped = db.Use(u.ID)
	acc, ok, _ = scoped.AccountByEmail("ada@example.com")
	if !ok || acc.RefreshToken() != token {
		t.Fatal("token unreadable after rotation")
	}

	if err := db.Unscoped().DeleteUserData(u.ID); err != nil {
		t.Fatal(err)
	}
	if db.HasDEK(u.ID) {
		t.Fatal("DEK survived crypto-shred")
	}
	if _, ok, _ := db.Unscoped().UserByID(u.ID); ok {
		t.Fatal("user row survived")
	}
}

func TestMigrateV1SecretsToDEK(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ghook.db")
	keyFile := filepath.Join(dir, "secrets.key")
	db, err := Open(dbPath, "", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scoped, u, err := db.EnsureAndUse("sub-bea", "bea@example.com", "Bea")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.SaveAccount("bea@example.com", "placeholder-token", "", 0, "", "1"); err != nil {
		t.Fatal(err)
	}
	// Overwrite the stored refresh token with a v0.1.3 derived (enc:v1) value.
	legacy := db.root.Derive(u.ID)
	v1 := legacy.Seal("legacy-refresh-token")
	if !secrets.IsV1(v1) {
		t.Fatalf("expected v1, got %s", v1[:8])
	}
	if _, err := db.SQL.Exec(`UPDATE accounts SET refresh_token=? WHERE user_id=?`, v1, u.ID); err != nil {
		t.Fatal(err)
	}
	// Force remigration by deleting the DEK and calling Use again.
	if _, err := db.SQL.Exec(`DELETE FROM user_keys WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	scoped = db.Use(u.ID)
	acc, ok, err := scoped.AccountByEmail("bea@example.com")
	if err != nil || !ok {
		t.Fatalf("load %v %v", ok, err)
	}
	if acc.RefreshToken() != "legacy-refresh-token" {
		t.Fatalf("migrated token %q", acc.RefreshToken())
	}
	assertAbsent(t, dbPath, "legacy-refresh-token")
}

func assertAbsent(t *testing.T, dbPath string, needles ...string) {
	t.Helper()
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range needles {
		if n != "" && strings.Contains(string(raw), n) {
			t.Fatalf("sqlite file still contains plaintext %q", n)
		}
	}
}
