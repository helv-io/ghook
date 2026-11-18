package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helv-io/ghook/internal/auth"
	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/mail"
	"github.com/helv-io/ghook/internal/runtime"
	"github.com/helv-io/ghook/internal/store"
)

func testServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ghook.db"), "", filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{
		PublicURL: "https://ghook.example.com", Listen: ":8080", DBPath: filepath.Join(dir, "ghook.db"),
		MaxTargets: 25, MaxRoutes: 50, MaxDeliveries: 1000, MetricsToken: "metrics-secret",
		GoogleClient: `{"web":{"client_id":"test.apps.googleusercontent.com","client_secret":"s"}}`,
	}
	rt := runtime.New(cfg, db)
	srv, err := New(rt)
	if err != nil {
		t.Fatal(err)
	}
	return srv, db
}

func loginAs(t *testing.T, srv *Server, db *store.DB, subject, email, name string) (*http.Cookie, *store.DB, store.User) {
	t.Helper()
	scoped, u, err := db.EnsureAndUse(subject, email, name)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.setSession(rec, auth.Identity{Subject: subject, Email: email, Name: name, Username: name})
	cks := rec.Result().Cookies()
	if len(cks) == 0 {
		t.Fatal("no session cookie")
	}
	return cks[0], scoped, u
}

func TestLegalPagesArePublic(t *testing.T) {
	srv, _ := testServer(t)
	for _, path := range []string{"/privacy", "/terms", "/login"} {
		res := get(srv, path, nil)
		body := read(t, res)
		if res.StatusCode != 200 || !strings.Contains(strings.ToLower(body), "ghook") {
			t.Fatalf("%s status %d\n%s", path, res.StatusCode, clip(body))
		}
	}
	res := get(srv, "/healthz", nil)
	body := read(t, res)
	if res.StatusCode != 200 || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("/healthz status %d\n%s", res.StatusCode, clip(body))
	}
}

func TestLoginRequired(t *testing.T) {
	srv, _ := testServer(t)
	for _, path := range []string{"/", "/admin", "/admin/routes", "/admin/targets", "/admin/account"} {
		res := get(srv, path, nil)
		if res.StatusCode != http.StatusFound {
			t.Fatalf("%s status %d", path, res.StatusCode)
		}
		loc := res.Header.Get("Location")
		if loc != "/login" && loc != "/auth/google" && !strings.HasPrefix(loc, "/login") {
			t.Fatalf("%s redirected to %q", path, loc)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/targets/save", strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST: %d", rec.Code)
	}
}

func TestSessionCSRFAndPagesHideSecrets(t *testing.T) {
	srv, db := testServer(t)
	const secret = "super-secret-value"
	ck, scoped, _ := loginAs(t, srv, db, "u-1", "ada@example.com", "Ada")
	tg, err := scoped.SaveTarget(store.Target{Name: "ceo", URL: "https://bot.example.com/hook", AuthMode: "bearer"}, secret, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.SaveRoute(store.Route{Name: "primary", Enabled: true, Fallback: true, TargetID: tg.ID}); err != nil {
		t.Fatal(err)
	}
	acc, err := scoped.SaveAccount("ada@example.com", "refresh-token-value", "", 0, "gmail.readonly", "10")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = scoped.QueueAndAdvance(acc.ID, acc.Email, mail.Message{
		ID: "m1", From: "Ada <ada@example.com>", Subject: "Hello", Snippet: "hi",
		Date: time.Now().UTC(), Labels: []string{"INBOX", "CATEGORY_PERSONAL"}, Category: "primary",
	}, nil, "")

	bad := *ck
	bad.Value = ck.Value[:len(ck.Value)-1] + "x"
	res := get(srv, "/admin", &bad)
	if res.StatusCode != http.StatusFound || !strings.Contains(res.Header.Get("Location"), "/login") {
		t.Fatalf("tampered cookie was accepted: %d %s", res.StatusCode, res.Header.Get("Location"))
	}

	form := url.Values{"name": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/targets/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("csrf: %d", rec.Code)
	}

	pages := map[string]string{
		"/admin":                        "Queue",
		"/admin/accounts":               "Sign in with Google",
		"/admin/routes":                 "Simulator",
		"/admin/routes/new":             "Simulate this draft",
		"/admin/targets":                "Add target",
		"/admin/targets/new":            "Grok bot",
		"/admin/targets/" + itoa(tg.ID): "bearer",
		"/admin/deliveries":             "Replay a window",
		"/admin/settings":               "Label prefix",
		"/admin/audit":                  "Audit",
		"/admin/account":                "Delete my account",
		"/healthz":                      `"status":"ok"`,
		"/privacy":                      "self-hosted",
		"/terms":                        "sign in with Google",
	}
	for path, want := range pages {
		res := get(srv, path, ck)
		body := read(t, res)
		if res.StatusCode != 200 || !strings.Contains(body, want) {
			t.Fatalf("%s status %d missing %q\n%s", path, res.StatusCode, want, clip(body))
		}
		if strings.Contains(body, secret) || strings.Contains(body, "refresh-token-value") {
			t.Fatalf("%s leaked a secret", path)
		}
	}

	csrf, _ := srv.Session(reqWith(ck))
	post := url.Values{"csrf": {csrf}, "n": {"5"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/routes/simulate", strings.NewReader(post.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "Hello") || !strings.Contains(body, "primary") {
		t.Fatalf("simulator: %d %s", rec.Code, clip(body))
	}
}

func TestMetricsRequiresTokenAndHidesEmails(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "u-1", "ada@example.com", "Ada")
	if _, err := scoped.SaveAccount("ada@example.com", "refresh-token-value", "", 0, "gmail.readonly", "10"); err != nil {
		t.Fatal(err)
	}

	res := get(srv, "/metrics", ck)
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusNotFound {
		t.Fatalf("session must not unlock metrics: %d %s", res.StatusCode, read(t, res))
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer metrics-secret")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "ghook_up") || !strings.Contains(body, "ghook_users") {
		t.Fatalf("metrics: %d %s", rec.Code, body)
	}
	if strings.Contains(body, "ada@example.com") || strings.Contains(body, "refresh-token") {
		t.Fatalf("metrics leaked an email or token: %s", body)
	}

	srv.RT.Cfg.MetricsToken = ""
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unset token: %d", rec.Code)
	}
}

func TestPushRejectsBadToken(t *testing.T) {
	srv, _ := testServer(t)
	srv.Verify = func(*http.Request, string, string) (string, error) {
		return "", errString("no")
	}
	req := httptest.NewRequest(http.MethodPost, "/hooks/pubsub", strings.NewReader(`{"message":{"data":"eyJlbWFpbEFkZHJlc3MiOiJhZGFAZXhhbXBsZS5jb20iLCJoaXN0b3J5SWQiOjF9"}}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestUserIsolationHTTP(t *testing.T) {
	srv, db := testServer(t)
	aCK, aDB, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	bCK, bDB, _ := loginAs(t, srv, db, "sub-b", "bea@example.com", "Bea")

	tg, err := aDB.SaveTarget(store.Target{Name: "ada-hook", URL: "https://a.example.com/hook"}, "secret-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aDB.SaveRoute(store.Route{Name: "ada-route", Enabled: true, TargetID: tg.ID}); err != nil {
		t.Fatal(err)
	}
	acc, err := aDB.SaveAccount("ada-mail@example.com", "refresh-a", "", 0, "gmail.readonly", "10")
	if err != nil {
		t.Fatal(err)
	}
	aDB.Audit("Ada", "route.save", "ada-route")
	_, _ = aDB.QueueAndAdvance(acc.ID, acc.Email, mail.Message{
		ID: "m-ada", From: "bank@example.com", Subject: "Ada secret invoice", Snippet: "paid",
		Date: time.Now().UTC(), Category: "primary",
	}, []store.MatchPlan{{RouteKey: "ada-route", RouteName: "ada-route", TargetID: tg.ID, TargetName: "ada-hook"}}, "")

	if _, err := bDB.SaveTarget(store.Target{Name: "bea-hook", URL: "https://b.example.com/hook"}, "secret-b", false); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/admin/routes", "/admin/targets", "/admin/deliveries", "/admin/accounts", "/admin/audit"} {
		body := read(t, get(srv, path, bCK))
		for _, leak := range []string{"ada-hook", "ada-route", "ada-mail@example.com", "Ada secret invoice", "secret-a", "refresh-a"} {
			if strings.Contains(body, leak) {
				t.Fatalf("user B saw %q on %s:\n%s", leak, path, clip(body))
			}
		}
		if path == "/admin/targets" && !strings.Contains(body, "bea-hook") {
			t.Fatalf("user B missing own target on %s:\n%s", path, clip(body))
		}
	}

	// B must not open or delete A's target by id.
	res := get(srv, "/admin/targets/"+itoa(tg.ID), bCK)
	body := read(t, res)
	if res.StatusCode == 200 && strings.Contains(body, "ada-hook") {
		t.Fatal("user B opened user A's target")
	}
	csrf, _ := srv.Session(reqWith(bCK))
	form := url.Values{"csrf": {csrf}, "id": {itoa(tg.ID)}}
	req := httptest.NewRequest(http.MethodPost, "/admin/targets/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(bCK)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if still, ok, _ := aDB.TargetByID(tg.ID, false); !ok || still.Name != "ada-hook" {
		t.Fatalf("user B deleted user A's target: ok=%v %+v", ok, still)
	}

	// A still sees own data.
	body = read(t, get(srv, "/admin/routes", aCK))
	if !strings.Contains(body, "ada-route") {
		t.Fatalf("user A lost their route: %s", clip(body))
	}
}

func TestQuotaOnNewTarget(t *testing.T) {
	srv, db := testServer(t)
	srv.RT.Cfg.MaxTargets = 1
	ck, scoped, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	if _, err := scoped.SaveTarget(store.Target{Name: "one", URL: "https://a.example.com/hook"}, "", false); err != nil {
		t.Fatal(err)
	}
	csrf, _ := srv.Session(reqWith(ck))
	form := url.Values{"csrf": {csrf}, "name": {"two"}, "url": {"https://b.example.com/hook"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/targets/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "limit") {
		t.Fatalf("quota: %d %s", rec.Code, clip(rec.Body.String()))
	}
	got, _ := scoped.Targets()
	if len(got) != 1 {
		t.Fatalf("targets after quota: %d", len(got))
	}
}

func TestDeleteAccountRemovesDataAndSession(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, u := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	if _, err := scoped.SaveTarget(store.Target{Name: "ada-hook", URL: "https://a.example.com/hook"}, "secret-a", false); err != nil {
		t.Fatal(err)
	}
	csrf, _ := srv.Session(reqWith(ck))
	form := url.Values{"csrf": {csrf}, "confirm": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/account/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok, _ := db.UserByID(u.ID); ok {
		t.Fatal("user row still present")
	}
	res := get(srv, "/admin", ck)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("session survived delete: %d", res.StatusCode)
	}
}

func TestSettingsAndExportStayPerUser(t *testing.T) {
	srv, db := testServer(t)
	aCK, aDB, _ := loginAs(t, srv, db, "sub-a", "ada@example.com", "Ada")
	bCK, bDB, _ := loginAs(t, srv, db, "sub-b", "bea@example.com", "Bea")
	if _, err := aDB.SaveTarget(store.Target{Name: "ada-hook", URL: "https://a.example.com/hook"}, "", false); err != nil {
		t.Fatal(err)
	}

	csrf, _ := srv.Session(reqWith(aCK))
	form := url.Values{"csrf": {csrf}, "label_prefix": {"ada-prefix"}, "label_convention": {"1"},
		"catchup_minutes": {"30"}, "resync_days": {"2"}, "retry_max_attempts": {"8"},
		"retry_max_hours": {"24"}, "retry_base_seconds": {"30"}, "retention_days": {"30"},
		"timezone": {"America/New_York"}, "notify_dead": {"1"}, "notify_watch": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(aCK)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if got := aDB.Setting("label_prefix", ""); got != "ada-prefix" {
		t.Fatalf("A prefix %q", got)
	}
	if got := bDB.Setting("label_prefix", "ghook"); got != "ghook" {
		t.Fatalf("B inherited A's prefix: %q", got)
	}

	body := read(t, get(srv, "/admin/settings", aCK))
	if !strings.Contains(body, "ada-prefix") || !strings.Contains(body, "1 target") {
		t.Fatalf("A settings page: %s", clip(body))
	}
	body = read(t, get(srv, "/admin/settings", bCK))
	if strings.Contains(body, "ada-prefix") || strings.Contains(body, "ada-hook") {
		t.Fatalf("B saw A's settings or export data: %s", clip(body))
	}

	csrf, _ = srv.Session(reqWith(aCK))
	req = httptest.NewRequest(http.MethodPost, "/admin/export", strings.NewReader("csrf="+csrf))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(aCK)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	out := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(out, "ada-hook") {
		t.Fatalf("export A: %d %s", rec.Code, clip(out))
	}

	csrf, _ = srv.Session(reqWith(bCK))
	req = httptest.NewRequest(http.MethodPost, "/admin/export", strings.NewReader("csrf="+csrf))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(bCK)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	out = rec.Body.String()
	if strings.Contains(out, "ada-hook") {
		t.Fatalf("B exported A's target: %s", clip(out))
	}
}

func get(srv *Server, path string, ck *http.Cookie) *http.Response {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ck != nil {
		req.AddCookie(ck)
	}
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	return res.Result()
}

func reqWith(ck *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.AddCookie(ck)
	return r
}

func read(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func clip(s string) string {
	if len(s) > 800 {
		return s[:800]
	}
	return s
}

func itoa(n int64) string {
	return strconvFormat(n)
}

func strconvFormat(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

type errString string

func (e errString) Error() string { return string(e) }
