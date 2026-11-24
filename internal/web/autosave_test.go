package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/helv-io/ghook/internal/store"
)

func TestSettingsAutosaveJSON(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	csrf, _ := srv.Session(reqWith(ck))
	form := url.Values{"csrf": {csrf}, "label_prefix": {"ada-prefix"}, "label_convention": {"1"},
		"catchup_minutes": {"30"}, "resync_days": {"2"}, "retry_max_attempts": {"8"},
		"retry_max_hours": {"24"}, "retry_base_seconds": {"30"}, "retention_days": {"30"},
		"timezone": {"America/New_York"}, "notify_dead": {"1"}, "notify_watch": {"1"}}
	res := postJSON(t, srv, "/admin/settings", form, ck)
	if res.Code != 200 {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
	var out saveResponse
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil || !out.OK {
		t.Fatalf("body %s err %v", res.Body.String(), err)
	}
	if got := scoped.Setting("label_prefix", ""); got != "ada-prefix" {
		t.Fatalf("prefix %q", got)
	}

	form.Set("timezone", "Not/AZone")
	res = postJSON(t, srv, "/admin/settings", form, ck)
	if res.Code != 400 {
		t.Fatalf("bad tz status %d %s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil || out.OK || out.Field != "timezone" {
		t.Fatalf("bad tz body %s", res.Body.String())
	}
	if got := scoped.Setting("timezone", ""); got != "America/New_York" {
		t.Fatalf("timezone reverted? %q", got)
	}
}

func TestSettingsAutosaveNeedsCSRF(t *testing.T) {
	srv, db := testServer(t)
	ck, _, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	form := url.Values{"csrf": {"nope"}, "timezone": {"UTC"}, "label_prefix": {"x"},
		"catchup_minutes": {"30"}, "resync_days": {"2"}, "retry_max_attempts": {"8"},
		"retry_max_hours": {"24"}, "retry_base_seconds": {"30"}, "retention_days": {"30"}}
	res := postJSON(t, srv, "/admin/settings", form, ck)
	if res.Code != 400 {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "csrf") {
		t.Fatalf("body %s", res.Body.String())
	}
}

func TestEditPagesHaveNoSaveButton(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	if _, err := scoped.SaveTarget(store.Target{Name: "Chief of Staff", URL: "https://bot.example.com/hook"}, "s", false); err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.SaveRoute(store.Route{Name: "invoices", TargetID: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rts, _ := scoped.Routes()
	tgs, _ := scoped.Targets()

	settings := read(t, get(srv, "/admin/settings", ck))
	if strings.Contains(settings, "Save settings") {
		t.Fatal("settings still has a Save button")
	}
	if !strings.Contains(settings, `data-autosave="/admin/settings"`) {
		t.Fatal("settings missing data-autosave")
	}

	body := read(t, get(srv, "/admin/targets/new", ck))
	if !strings.Contains(body, ">Create</button>") || strings.Contains(body, ">Save</button>") {
		t.Fatalf("new target buttons: %s", clip(body))
	}
	body = read(t, get(srv, "/admin/targets/"+itoa(tgs[0].ID), ck))
	if strings.Contains(body, ">Save</button>") || !strings.Contains(body, `data-autosave="/admin/targets/save"`) {
		t.Fatalf("edit target: %s", clip(body))
	}

	body = read(t, get(srv, "/admin/routes/new", ck))
	if !strings.Contains(body, ">Create</button>") || strings.Contains(body, ">Save</button>") {
		t.Fatalf("new route buttons: %s", clip(body))
	}
	body = read(t, get(srv, "/admin/routes/"+itoa(rts[0].ID), ck))
	if strings.Contains(body, ">Save</button>") || !strings.Contains(body, `data-autosave="/admin/routes/save"`) {
		t.Fatalf("edit route: %s", clip(body))
	}

	accounts := read(t, get(srv, "/admin/accounts", ck))
	if strings.Contains(accounts, "Update scopes") {
		t.Fatal("accounts still has Update scopes")
	}
	if !strings.Contains(accounts, "data-google-consent") {
		t.Fatal("accounts missing google consent form")
	}
	css, err := assets.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".gh-word{") || !strings.Contains(string(css), "white-space:nowrap") {
		t.Fatal("gh-word is missing nowrap")
	}
}

func TestTargetAutosaveJSON(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	saved, err := scoped.SaveTarget(store.Target{Name: "Chief of Staff", URL: "https://bot.example.com/hook"}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := srv.Session(reqWith(ck))
	form := url.Values{"csrf": {csrf}, "id": {itoa(saved.ID)}, "name": {"Chief of Staff"}, "url": {"not-a-url"}}
	res := postJSON(t, srv, "/admin/targets/save", form, ck)
	if res.Code != 400 {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
	var out saveResponse
	_ = json.Unmarshal(res.Body.Bytes(), &out)
	if out.OK || out.Field != "url" {
		t.Fatalf("body %s", res.Body.String())
	}
	form.Set("url", "https://bot.example.com/hook2")
	res = postJSON(t, srv, "/admin/targets/save", form, ck)
	if res.Code != 200 {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
	got, ok, _ := scoped.TargetByID(saved.ID, false)
	if !ok || got.URL != "https://bot.example.com/hook2" {
		t.Fatalf("url %q", got.URL)
	}
}

func postJSON(t *testing.T, srv *Server, path string, form url.Values, ck *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "fetch")
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}
