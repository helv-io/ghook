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

	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/mail"
	"github.com/helv-io/ghook/internal/oidcauth"
	"github.com/helv-io/ghook/internal/runtime"
	"github.com/helv-io/ghook/internal/store"
)

func testServer(t *testing.T, oidc bool) (*Server, *store.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ghook.db"), "", filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{PublicURL: "https://ghook.example.com", Listen: ":8080", DBPath: filepath.Join(dir, "ghook.db")}
	if oidc {
		cfg.OIDCIssuer = "https://auth.example.com"
		cfg.OIDCClientID = "ghook"
		cfg.OIDCClientSecret = "s3cret"
	}
	rt := runtime.New(cfg, db)
	srv, err := New(rt)
	if err != nil {
		t.Fatal(err)
	}
	return srv, db
}

func TestLegalPagesArePublic(t *testing.T) {
	srv, _ := testServer(t, true)
	for _, path := range []string{"/privacy", "/terms"} {
		res := get(srv, path, nil)
		body := read(t, res)
		if res.StatusCode != 200 || strings.Contains(body, "Signed out") || !strings.Contains(body, "ghook") {
			t.Fatalf("%s status %d\n%s", path, res.StatusCode, clip(body))
		}
	}
}

func TestNoAuthIsImplicitAdmin(t *testing.T) {
	srv, _ := testServer(t, false)
	res := get(srv, "/admin", nil)
	body := read(t, res)
	if res.StatusCode != 200 || !strings.Contains(body, "Sign-in is off") {
		t.Fatalf("status %d body %s", res.StatusCode, clip(body))
	}
}

func TestSessionCSRFAndPagesHideSecrets(t *testing.T) {
	srv, db := testServer(t, true)
	const secret = "super-secret-value"
	tg, err := db.SaveTarget(store.Target{Name: "ceo", URL: "https://bot.example.com/hook", AuthMode: "bearer"}, secret, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveRoute(store.Route{Name: "primary", Enabled: true, Fallback: true, TargetID: tg.ID}); err != nil {
		t.Fatal(err)
	}
	acc, err := db.SaveAccount("ada@example.com", "refresh-token-value", "", 0, "gmail.readonly", "10")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.QueueAndAdvance(acc.ID, acc.Email, mail.Message{
		ID: "m1", From: "Ada <ada@example.com>", Subject: "Hello", Snippet: "hi",
		Date: time.Now().UTC(), Labels: []string{"INBOX", "CATEGORY_PERSONAL"}, Category: "primary",
	}, nil, "")

	rec := httptest.NewRecorder()
	srv.setSession(rec, oidcauth.Identity{Subject: "u-1", Email: "admin@example.com", Username: "admin"})
	ck := rec.Result().Cookies()[0]

	// tamper
	bad := *ck
	bad.Value = ck.Value[:len(ck.Value)-1] + "x"
	if res := get(srv, "/admin", &bad); !strings.Contains(read(t, res), "Signed out") {
		t.Fatal("tampered cookie was accepted")
	}
	expired := *ck
	// csrf without a matching token
	form := url.Values{"name": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/targets/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("csrf: %d", res.Code)
	}
	_ = expired

	pages := map[string]string{
		"/admin":                        "Queue",
		"/admin/accounts":               "Connect Google",
		"/admin/routes":                 "Simulator",
		"/admin/routes/new":             "Simulate this draft",
		"/admin/targets":                "Add target",
		"/admin/targets/new":            "Grok bot",
		"/admin/targets/" + itoa(tg.ID): "bearer",
		"/admin/deliveries":             "Replay a window",
		"/admin/settings":               "Label prefix",
		"/admin/audit":                  "Audit",
		"/healthz":                      `"status":"ok"`,
		"/privacy":                      "self-hosted",
		"/terms":                        "without warranty",
		"/metrics":                      "ghook_up",
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

	// simulator against the stored message
	csrf, _ := srv.Session(reqWith(ck))
	post := url.Values{"csrf": {csrf}, "n": {"5"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/routes/simulate", strings.NewReader(post.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	body := res.Body.String()
	if res.Code != 200 || !strings.Contains(body, "Hello") || !strings.Contains(body, "primary") {
		t.Fatalf("simulator: %d %s", res.Code, clip(body))
	}
}

func TestPushRejectsBadToken(t *testing.T) {
	srv, _ := testServer(t, true)
	srv.Verify = func(*http.Request, string, string) (string, error) {
		return "", errString("no")
	}
	req := httptest.NewRequest(http.MethodPost, "/hooks/pubsub", strings.NewReader(`{"message":{"data":"eyJlbWFpbEFkZHJlc3MiOiJhZGFAZXhhbXBsZS5jb20iLCJoaXN0b3J5SWQiOjF9"}}`))
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", res.Code)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

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
	var b [20]byte
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
