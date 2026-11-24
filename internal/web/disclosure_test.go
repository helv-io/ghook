package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/store"
)

func TestTestingModeHidesSimulatorAndReplay(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	tg, err := scoped.SaveTarget(store.Target{Name: "ops", URL: "https://hooks.example.com/ops"}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.SaveRoute(store.Route{Name: "all", Enabled: true, TargetID: tg.ID}); err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{
		"/admin/routes":     "Simulator",
		"/admin/routes/new": "Simulate this draft",
		"/admin/deliveries": "Replay a window",
	}
	for path, word := range pages {
		if body := read(t, get(srv, path, ck)); strings.Contains(body, word) {
			t.Fatalf("%s shows %q with testing mode off", path, word)
		}
	}
	if err := scoped.SetSetting("testing_mode", "1"); err != nil {
		t.Fatal(err)
	}
	for path, word := range pages {
		if body := read(t, get(srv, path, ck)); !strings.Contains(body, word) {
			t.Fatalf("%s hides %q with testing mode on", path, word)
		}
	}
}

func TestMoreOptionsOpensOnlyWhenUsed(t *testing.T) {
	if routeAdvanced(store.Route{Enabled: true, Spec: match.Spec{From: []string{"example.com"}}}, false) {
		t.Fatal("a sender-only route should stay collapsed")
	}
	if !routeAdvanced(store.Route{Enabled: true, Spec: match.Spec{Subject: "(?i)invoice"}}, false) {
		t.Fatal("a subject filter should open More options")
	}
	if !routeAdvanced(store.Route{Enabled: false}, false) {
		t.Fatal("a route that is off should open More options")
	}
	if targetAdvanced(store.Target{Name: "a", URL: "https://hooks.example.com/a", AuthMode: "bearer"}) {
		t.Fatal("a plain bearer target should stay collapsed")
	}
	if !targetAdvanced(store.Target{QuietStart: "22:00"}) {
		t.Fatal("quiet hours should open More options")
	}
}

func TestTargetWebhookPaste(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	csrf, _ := srv.Session(reqWith(ck))
	form := url.Values{"csrf": {csrf}, "name": {"ops"}, "webhook": {"  https://hooks.example.com/ops  key-123 "}}
	if res := postJSON(t, srv, "/admin/targets/save", form, ck); res.Code != 200 {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
	got, ok, _ := scoped.TargetByName("ops", true)
	if !ok || got.URL != "https://hooks.example.com/ops" || got.Secret() != "key-123" {
		t.Fatalf("url %q ok %v secret set %v", got.URL, ok, got.Secret() == "key-123")
	}
	// A URL alone keeps the saved key.
	form.Set("id", itoa(got.ID))
	form.Set("webhook", "https://hooks.example.com/ops2")
	if res := postJSON(t, srv, "/admin/targets/save", form, ck); res.Code != 200 {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
	got, _, _ = scoped.TargetByName("ops", true)
	if got.URL != "https://hooks.example.com/ops2" || got.Secret() != "key-123" {
		t.Fatalf("url %q, key kept %v", got.URL, got.Secret() == "key-123")
	}
	form.Set("webhook", "not-a-url")
	res := postJSON(t, srv, "/admin/targets/save", form, ck)
	if res.Code != 400 || !strings.Contains(res.Body.String(), `"field":"webhook"`) {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
}

func TestSettingsRendersToTheEnd(t *testing.T) {
	srv, db := testServer(t)
	ck, _, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	if _, err := db.Compact(); err != nil {
		t.Fatal(err)
	}
	body := read(t, get(srv, "/admin/settings", ck))
	for _, want := range []string{"Compacted daily", "Export and import", "Download YAML"} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings missing %q", want)
		}
	}
}

func TestRouteFormHasSubjectExamples(t *testing.T) {
	srv, db := testServer(t)
	ck, _, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	body := read(t, get(srv, "/admin/routes/new", ck))
	for _, ex := range match.SubjectExamples {
		if !strings.Contains(body, ex.Label) || !strings.Contains(body, `data-insert="subject"`) {
			t.Fatalf("route form is missing the %q example", ex.Label)
		}
	}
}
