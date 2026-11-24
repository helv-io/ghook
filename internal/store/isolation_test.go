package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/helv-io/ghook/internal/mail"
)

func TestUserIsolation(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "ghook.db"), "test-secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a, ua, err := db.EnsureAndUse("sub-a", "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	b, ub, err := db.EnsureAndUse("sub-b", "bea@example.com", "Bea")
	if err != nil {
		t.Fatal(err)
	}
	if ua.ID == ub.ID {
		t.Fatal("users share an id")
	}

	tgA, err := a.SaveTarget(Target{Name: "ops", URL: "https://a.example.com/hook"}, "secret-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SaveRoute(Route{Name: "primary", Enabled: true, TargetID: tgA.ID}); err != nil {
		t.Fatal(err)
	}
	accA, err := a.SaveAccount("ada-mail@example.com", "refresh-a", "", 0, "gmail.readonly", "1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.QueueAndAdvance(accA.ID, accA.Email, mail.Message{
		ID: "m1", From: "bank@example.com", Subject: "Ada invoice", Date: time.Now().UTC(),
	}, []MatchPlan{{RouteKey: "primary", RouteName: "primary", TargetID: tgA.ID, TargetName: "ops"}}, ""); err != nil {
		t.Fatal(err)
	}
	a.Audit("Ada", "route.save", "primary")

	tgB, err := b.SaveTarget(Target{Name: "ops", URL: "https://b.example.com/hook"}, "secret-b", false)
	if err != nil {
		t.Fatal(err)
	}

	gotA, _ := a.Targets()
	gotB, _ := b.Targets()
	if len(gotA) != 1 || len(gotB) != 1 || gotA[0].URL == gotB[0].URL {
		t.Fatalf("lists leaked: %+v %+v", gotA, gotB)
	}
	if _, ok, _ := b.TargetByID(tgA.ID, true); ok {
		t.Fatal("user B opened user A's target by id")
	}
	openB, ok, err := b.TargetByName("ops", true)
	if err != nil || !ok || openB.Secret() != "secret-b" {
		t.Fatalf("secret %q ok %v err %v", openB.Secret(), ok, err)
	}
	if openB.Secret() == "secret-a" {
		t.Fatal("derived key did not isolate the secret")
	}
	if err := b.DeleteTarget(tgA.ID); err == nil {
		if still, ok, _ := a.TargetByID(tgA.ID, false); !ok {
			t.Fatal("user B deleted user A's target")
		} else {
			_ = still
		}
	}
	routesB, _ := b.Routes()
	if len(routesB) != 0 {
		t.Fatalf("user B saw routes: %+v", routesB)
	}
	dels, _ := b.Deliveries("", "", "", 50)
	if len(dels) != 0 {
		t.Fatalf("user B saw deliveries: %+v", dels)
	}
	accs, _ := b.Accounts()
	if len(accs) != 0 {
		t.Fatalf("user B saw accounts: %+v", accs)
	}
	audits, _ := b.Audits(50)
	for _, ev := range audits {
		if ev.Detail == "primary" || ev.Actor == "Ada" {
			t.Fatalf("user B saw A's audit: %+v", ev)
		}
	}

	// Pub/Sub routing by emailAddress must land on the owning user only.
	found, err := db.AccountsByEmail("ada-mail@example.com")
	if err != nil || len(found) != 1 || found[0].UserID != ua.ID {
		t.Fatalf("AccountsByEmail: %+v err %v", found, err)
	}

	if err := db.Unscoped().DeleteUserData(ua.ID); err != nil {
		t.Fatal(err)
	}
	if still, _ := a.Targets(); len(still) != 0 {
		t.Fatalf("targets survived delete: %+v", still)
	}
	if _, ok, _ := db.UserByID(ua.ID); ok {
		t.Fatal("user survived delete")
	}
	if left, _ := b.Targets(); len(left) != 1 || left[0].ID != tgB.ID {
		t.Fatalf("delete touched user B: %+v", left)
	}
}

func TestQuotaCounters(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "ghook.db"), "test-secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a, _, err := db.EnsureAndUse("sub-a", "ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if a.TargetCount() != 0 || a.RouteCount() != 0 {
		t.Fatalf("fresh counts %d %d", a.TargetCount(), a.RouteCount())
	}
	tg, err := a.SaveTarget(Target{Name: "ops", URL: "https://a.example.com/hook"}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SaveRoute(Route{Name: "primary", Enabled: true, TargetID: tg.ID}); err != nil {
		t.Fatal(err)
	}
	if a.TargetCount() != 1 || a.RouteCount() != 1 {
		t.Fatalf("counts %d %d", a.TargetCount(), a.RouteCount())
	}
}
