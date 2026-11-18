package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	b, err := FromString("not-32-bytes-this-is-a-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	sealed := b.Seal("super-secret")
	if !IsSealed(sealed) || sealed == "super-secret" {
		t.Fatalf("not sealed: %s", sealed)
	}
	got, err := b.Open(sealed)
	if err != nil || got != "super-secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	if b.Seal("") != "" {
		t.Fatal("empty must stay empty")
	}
	plain, err := b.Open("left-alone")
	if err != nil || plain != "left-alone" {
		t.Fatal(plain, err)
	}
	other, _ := FromString("a-different-passphrase")
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("wrong key opened the value")
	}
}

func TestKeyFileCreatedOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.key")
	b1, src, err := LoadOrCreate("", path)
	if err != nil || src != path+" (created)" {
		t.Fatal(src, err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", st.Mode().Perm(), err)
	}
	b2, src2, err := LoadOrCreate("", path)
	if err != nil || src2 != path {
		t.Fatal(src2, err)
	}
	s := b1.Seal("token")
	got, err := b2.Open(s)
	if err != nil || got != "token" {
		t.Fatal(got, err)
	}
}

func TestEnvKeyWins(t *testing.T) {
	b, src, err := LoadOrCreate("exactly-thirty-two-bytes-of-key!!", "")
	if err != nil || src != "SECRETS_KEY" || b == nil {
		t.Fatal(src, err)
	}
}
