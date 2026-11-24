package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/store"
)

func TestTargetDest(t *testing.T) {
	cases := []struct{ url, label, id string }{
		{"https://api2.cursor.sh/automations/webhook/0f3c9a52-1b2d-4e5f-8a9b-0c1d2e3f4a5b", "Grok Bot routine", "0f3c9a52…"},
		{"https://hooks.slack.com/services/T000/B000/XXXX", "Slack webhook", "XXXX"},
		{"https://discord.com/api/webhooks/123/abc", "Discord webhook", "abc"},
		{"https://www.Example.com/hook", "example.com", "hook"},
		{"https://bot.example.com/", "bot.example.com", ""},
		{"http://10.0.0.5:8080/in", "10.0.0.5", "in"},
		{"https://cursor.sh.example.com/automations/webhook/x", "cursor.sh.example.com", "x"},
	}
	for _, c := range cases {
		d := targetDest(c.url)
		if d.Label != c.label || d.ID != c.id {
			t.Errorf("%s: got %q %q, want %q %q", c.url, d.Label, d.ID, c.label, c.id)
		}
	}
}

func TestShortAndFullTime(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tzdata")
	}
	ts := time.Date(2026, 11, 24, 18, 41, 5, 0, time.UTC).Unix()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	if got := shortTime(ts, ny, now); got != "Nov 24, 1:41 PM" {
		t.Fatalf("short %q", got)
	}
	if got := shortTime(ts, ny, time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)); got != "Nov 24, 2026, 1:41 PM" {
		t.Fatalf("short other year %q", got)
	}
	if got := fullTime(ts, ny); got != "Tue, Nov 24, 2026, 1:41:05 PM EST" {
		t.Fatalf("full %q", got)
	}
	if shortTime(0, ny, now) != "—" || fullTime(0, ny) != "" {
		t.Fatal("zero time")
	}
}

func TestSender(t *testing.T) {
	cases := []struct{ in, name, addr string }{
		{`Premier Association Management LLC <support@example.com>`, "Premier Association Management LLC", "support@example.com"},
		{`"Ada, L." <ada@example.com>`, "Ada, L.", "ada@example.com"},
		{`ada@example.com`, "ada@example.com", ""},
		{`Broken <not an address>`, "Broken", "not an address"},
		{``, "", ""},
	}
	for _, c := range cases {
		n, a := sender(c.in)
		if n != c.name || a != c.addr {
			t.Errorf("%q: got %q %q", c.in, n, a)
		}
	}
}

func seedRoute(t *testing.T, db *store.DB, from ...string) store.Route {
	t.Helper()
	tg, err := db.SaveTarget(store.Target{Name: "CFO", URL: "https://bot.example.com/hook/cfo", AuthMode: "bearer"}, "s3cret-value", false)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := db.SaveRoute(store.Route{Name: "bills", TargetID: tg.ID, Enabled: true, Spec: match.Spec{From: from, Subject: "(?i)bill"}})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestRouteFieldSortsAndSaves(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	rt := seedRoute(t, scoped, "b.com")
	csrf, _ := srv.Session(reqWith(ck))

	res := postJSON(t, srv, "/admin/routes/field", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(rt.ID, 10)}, "field": {"from"},
		"value": {"zed@x.com\nb.com\n*.bank.com\na.com\nB.COM"}}, ck)
	if res.Code != 200 {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
	var out fieldResponse
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil || !out.OK {
		t.Fatalf("body %s", res.Body.String())
	}
	if strings.Join(out.Values, ",") != "a.com,b.com,*.bank.com,zed@x.com" {
		t.Fatalf("values %v", out.Values)
	}
	got, _, _ := scoped.RouteByID(rt.ID)
	if strings.Join(got.Spec.From, ",") != "a.com,b.com,*.bank.com,zed@x.com" || got.Spec.Subject != "(?i)bill" {
		t.Fatalf("stored %+v", got.Spec)
	}

	res = postJSON(t, srv, "/admin/routes/field", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(rt.ID, 10)}, "field": {"subject"}, "value": {"(["}}, ck)
	if res.Code != 400 || !strings.Contains(res.Body.String(), "regex") {
		t.Fatalf("bad regex %d %s", res.Code, res.Body.String())
	}
	res = postJSON(t, srv, "/admin/routes/field", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(rt.ID, 10)}, "field": {"category"}, "value": {"primary"}}, ck)
	if res.Code != 400 {
		t.Fatalf("category in place %d", res.Code)
	}
	res = postJSON(t, srv, "/admin/routes/field", url.Values{"csrf": {"nope"}, "id": {strconv.FormatInt(rt.ID, 10)}, "field": {"from"}, "value": {"x.com"}}, ck)
	if res.Code != 400 {
		t.Fatalf("csrf %d", res.Code)
	}
}

func TestRouteFieldIsScopedToUser(t *testing.T) {
	srv, db := testServer(t)
	_, scopedA, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	rt := seedRoute(t, scopedA, "a.com")
	ckB, _, _ := loginAs(t, srv, db, "sub-b", "bob@example.com", "Bob")
	csrf, _ := srv.Session(reqWith(ckB))
	res := postJSON(t, srv, "/admin/routes/field", url.Values{"csrf": {csrf}, "id": {strconv.FormatInt(rt.ID, 10)}, "field": {"from"}, "value": {"evil.com"}}, ckB)
	if res.Code != 404 {
		t.Fatalf("user B edited A's route: %d %s", res.Code, res.Body.String())
	}
	got, _, _ := scopedA.RouteByID(rt.ID)
	if strings.Join(got.Spec.From, ",") != "a.com" {
		t.Fatalf("A's route changed: %v", got.Spec.From)
	}
}

func TestListPagesRender(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	_ = scoped.SetSetting("timezone", "America/New_York")
	seedRoute(t, scoped, "z@x.com", "b.com", "*.bank.com", "a.com", "c.com")
	get := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(ck)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		b, _ := io.ReadAll(rec.Result().Body)
		return string(b)
	}
	routes := get("/admin/routes")
	for _, want := range []string{`data-field="from"`, `any of 5`, `>AND<`, `data-twistie`, `class="extra"`, `data-handle`} {
		if !strings.Contains(routes, want) {
			t.Errorf("routes page lacks %s", want)
		}
	}
	if strings.Index(routes, ">a.com<") > strings.Index(routes, ">*.bank.com<") || strings.Index(routes, ">*.bank.com<") > strings.Index(routes, ">z@x.com<") {
		t.Error("senders are not in saved order")
	}
	if strings.Count(routes, `class="handle"`) != 1 {
		t.Error("one handle per row")
	}
	targets := get("/admin/targets")
	for _, want := range []string{"bot.example.com", ">bills<", "Bearer", ">never<", "Copy URL"} {
		if !strings.Contains(targets, want) {
			t.Errorf("targets page lacks %s", want)
		}
	}
	if strings.Contains(targets, "s3cret-value") {
		t.Fatal("target secret rendered")
	}
	get("/admin/deliveries")
}
