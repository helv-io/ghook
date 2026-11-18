package secrets

import "testing"

func TestDeriveIsolatesWorkspaces(t *testing.T) {
	root, err := FromString("instance-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	a := root.Derive(1)
	b := root.Derive(2)
	sealed := a.Seal("mailbox-token")
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("workspace B opened workspace A's secret")
	}
	got, err := a.Open(sealed)
	if err != nil || got != "mailbox-token" {
		t.Fatal(got, err)
	}
	again, err := root.Derive(1).Open(sealed)
	if err != nil || again != "mailbox-token" {
		t.Fatal("derive is not stable", again, err)
	}
}
