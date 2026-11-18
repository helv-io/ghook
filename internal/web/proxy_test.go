package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/runtime"
	"github.com/helv-io/ghook/internal/store"
)

func TestProxyHeaderTrustAndFallback(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ghook.db"), "", filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{
		PublicURL: "http://ghook.example.com", Listen: ":8080", AuthMode: config.AuthProxy,
		ProxyUser: "Remote-User", ProxyEmail: "Remote-Email", ProxyName: "Remote-Name", ProxyGroups: "Remote-Groups",
		Trust: trustNets(),
	}
	rt := runtime.New(cfg, db)
	srv, err := New(rt)
	if err != nil {
		t.Fatal(err)
	}

	// A public peer cannot supply the header.
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "8.8.8.8:443"
	req.Header.Set("Remote-User", "admin")
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if !strings.Contains(res.Body.String(), "trusted proxy") {
		t.Fatalf("public peer was trusted: %s", res.Body.String())
	}

	// Trusted peer, no header, no fallback: a clear page, not the app.
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "10.1.0.5:1234"
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != 200 || !strings.Contains(res.Body.String(), "No identity header") || strings.Contains(res.Body.String(), "Queue") {
		t.Fatalf("missing header: %d %s", res.Code, res.Body.String())
	}

	// Fallback identity when the LAN proxy strips the header.
	cfg.ProxyFallback = "admin"
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "10.1.0.5:1234"
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if !strings.Contains(res.Body.String(), "Queue") {
		t.Fatalf("fallback did not sign in: %s", res.Body.String())
	}
	fallback, ok, err := db.UserBySubject("admin")
	if err != nil || !ok {
		t.Fatal(err, ok)
	}

	// The same name in Remote-User is that account, not a second one.
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "192.168.1.9:1234"
	req.Header.Set("Remote-User", "admin")
	req.Header.Set("Remote-Email", "admin@example.com")
	res = httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if !strings.Contains(res.Body.String(), "admin@example.com") && !strings.Contains(res.Body.String(), "Queue") {
		t.Fatalf("header user: %s", res.Body.String())
	}
	again, ok, err := db.UserBySubject("admin")
	if err != nil || !ok || again.ID != fallback.ID {
		t.Fatalf("fallback and header diverged: %+v %+v %v", fallback, again, err)
	}
	if db.UserCount() != 1 {
		t.Fatalf("users: %d", db.UserCount())
	}
}

func TestWorkspaceIsolation(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ghook.db"), "", filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	other, err := db.CreateWorkspace("Other", 0)
	if err != nil {
		t.Fatal(err)
	}
	a := db
	b := db.Use(other.ID)
	if _, err := a.SaveTarget(store.Target{Name: "ceo", URL: "https://a.example.com/hook"}, "secret-a", false); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SaveTarget(store.Target{Name: "ceo", URL: "https://b.example.com/hook"}, "secret-b", false); err != nil {
		t.Fatal(err)
	}
	gotA, _ := a.Targets()
	gotB, _ := b.Targets()
	if len(gotA) != 1 || len(gotB) != 1 || gotA[0].URL == gotB[0].URL {
		t.Fatalf("lists leaked: %+v %+v", gotA, gotB)
	}
	if _, ok, _ := b.TargetByID(gotA[0].ID, true); ok {
		t.Fatal("workspace B opened workspace A's target by id")
	}
	openB, ok, err := b.TargetByName("ceo", true)
	if err != nil || !ok || openB.Secret() != "secret-b" {
		t.Fatalf("secret %q ok %v err %v", openB.Secret(), ok, err)
	}
	if openB.Secret() == "secret-a" {
		t.Fatal("workspace key did not isolate the secret")
	}
}

func trustNets() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8"} {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}
