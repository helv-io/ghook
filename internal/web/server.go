// Package web is the ghook admin UI and the public health, metrics and push endpoints.
package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/engine"
	"github.com/helv-io/ghook/internal/feed"
	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/oidcauth"
	"github.com/helv-io/ghook/internal/runtime"
	"github.com/helv-io/ghook/internal/store"
)

//go:embed templates static
var assets embed.FS

const (
	cookieName = "ghook_session"
	flashName  = "ghook_flash"
	stateName  = "ghook_google"
	sessionTTL = 12 * time.Hour
)

// PushVerifier checks a Pub/Sub push bearer token. Tests replace it.
type PushVerifier func(ctx *http.Request, raw, audience string) (email string, err error)

// Server is the HTTP front of one runtime.
type Server struct {
	RT     *runtime.App
	OIDC   *oidcauth.Client
	Verify func(r *http.Request, raw, audience string) (email string, err error)

	tpl       map[string]*template.Template
	sessions  sessionStore
	secretMu  sync.Mutex
	secretKey []byte
}

type sessionStore struct {
	mu      sync.Mutex
	info    map[string]sessionInfo
	revoked map[string]time.Time
}

type sessionInfo struct {
	who, idToken string
	exp          time.Time
}

type sessionClaims struct {
	Sub   string `json:"s"`
	Email string `json:"e,omitempty"`
	Label string `json:"l,omitempty"`
}

func (c sessionClaims) label() string {
	switch {
	case c.Label != "":
		return c.Label
	case c.Email != "":
		return c.Email
	}
	return c.Sub
}

type toast struct {
	Kind string
	Msg  string
}

type health struct {
	Label, Value, Class string
}

// page is the view model for every template. Unused fields stay zero.
type page struct {
	Title, Nav, CSRF, User, Version, Public string
	Solo                                    bool
	Toasts                                  []toast
	Err                                     string
	OIDCRedirect, GoogleRedirect, PushURL   string

	Accounts      []store.Account
	HasClient     bool
	ClientID      string
	Modify        bool
	SettingsScope bool
	PubSubScope   bool
	Pub           store.PubSub
	LabelPrefix   string
	Labels        []labelView
	LabelAccount  int64

	Routes     []store.Route
	Route      store.Route
	Targets    []store.Target
	Target     store.Target
	IsNew      bool
	Previews   []engine.Preview
	PreviewN   int
	Categories []string

	Deliveries                              []store.Delivery
	Delivery                                store.Delivery
	FilterStatus, FilterRoute, FilterTarget string
	Statuses                                []string

	Checks      []health
	Setup       []string
	RouteStats  []store.Stat
	TargetStats []store.Stat
	Events      []feed.Event

	Audits []store.AuditRow

	LabelConvention                                                      bool
	Catchup, ResyncDays, RetryAttempts, RetryHours, RetryBase, Retention int
	Timezone                                                             string
	NotifyTarget                                                         int64
	NotifyDead, NotifyWatch, RetainBodies, InstanceAdmin, AutoProvision  bool
	FallbackUser, WorkspaceName                                          string

	ShowTeam               bool
	Banner, Role, AuthMode string
	WorkspaceID            int64
	Workspaces             []store.Workspace
	Members                []store.Membership
}

type labelView struct {
	ID, Name string
}

// New parses templates and prepares OIDC when it is configured.
func New(rt *runtime.App) (*Server, error) {
	s := &Server{RT: rt, tpl: map[string]*template.Template{}}
	if rt.Cfg.AuthMode == config.AuthOIDC && rt.Cfg.OIDCEnabled() {
		s.OIDC = oidcauth.New(oidcauth.Config{
			Issuer: rt.Cfg.OIDCIssuer, ClientID: rt.Cfg.OIDCClientID, ClientSecret: rt.Cfg.OIDCClientSecret,
			Scopes: rt.Cfg.OIDCScopes, AllowedEmails: rt.Cfg.OIDCEmails, AllowedGroups: rt.Cfg.OIDCGroups,
		}, s.secret, rt.Cfg.OIDCRedirect, s.secure)
	}
	names := []string{"dashboard", "accounts", "routes", "route_edit", "targets", "target_edit", "deliveries", "delivery", "settings", "audit", "signedout", "notconfigured", "autherror", "noidentity", "noworkspace", "members", "privacy", "terms"}
	for _, name := range names {
		t, err := template.New(name).Funcs(s.funcs()).ParseFS(assets, "templates/layout.html", "templates/components.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		s.tpl[name] = t
	}
	return s, nil
}

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"wordmark": wordmark,
		"when":     func(u int64) string { return s.format(u, false) },
		"until":    func(u int64) string { return s.until(u) },
		"rel":      func(u int64) string { return s.rel(u) },
		"lines":    func(v []string) string { return strings.Join(v, "\n") },
		"summary":  func(sp match.Spec) string { return sp.Summary() },
		"has": func(list []string, x string) bool {
			for _, v := range list {
				if strings.EqualFold(v, x) {
					return true
				}
			}
			return false
		},
		"clock": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.In(s.loc()).Format("15:04:05")
		},
	}
}

func (s *Server) loc() *time.Location {
	name := "UTC"
	if s.RT != nil && s.RT.DB != nil {
		name = s.RT.DB.Setting("timezone", "UTC")
	}
	l, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	return l
}

func (s *Server) format(unix int64, dateOnly bool) string {
	if unix == 0 {
		return "—"
	}
	return time.Unix(unix, 0).In(s.loc()).Format("2006-01-02 15:04")
}

func (s *Server) rel(unix int64) string {
	if unix == 0 {
		return "never"
	}
	d := time.Since(time.Unix(unix, 0))
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + "d ago"
	}
}

func (s *Server) until(unix int64) string {
	if unix == 0 {
		return "not started"
	}
	d := time.Until(time.Unix(unix, 0))
	if d < 0 {
		return "expired"
	}
	switch {
	case d < time.Hour:
		return "in " + strconv.Itoa(int(d.Minutes())) + "m"
	case d < 48*time.Hour:
		return "in " + strconv.Itoa(int(d.Hours())) + "h"
	default:
		return "in " + strconv.Itoa(int(d.Hours()/24)) + "d"
	}
}

// Handler is the public HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /admin/static/", http.StripPrefix("/admin/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		b, _ := assets.ReadFile("static/favicon.svg")
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /privacy", s.legal("privacy", "Privacy"))
	mux.HandleFunc("GET /terms", s.legal("terms", "Terms"))
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("POST /hooks/pubsub", s.push)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	mux.HandleFunc("GET /admin/oidc/login", s.oidcLogin)
	mux.HandleFunc("GET /admin/oidc/callback", s.oidcCallback)
	mux.HandleFunc("POST /admin/logout", s.guard(s.logout))

	mux.HandleFunc("GET /admin", s.guard(s.dashboard))
	mux.HandleFunc("GET /admin/events", s.guard(s.events))
	mux.HandleFunc("GET /admin/accounts", s.guard(s.accounts))
	mux.HandleFunc("POST /admin/accounts/client", s.guard(s.saveClient))
	mux.HandleFunc("POST /admin/accounts/connect", s.guard(s.connect))
	mux.HandleFunc("GET /admin/google/callback", s.guard(s.googleCallback))
	mux.HandleFunc("POST /admin/accounts/watch", s.guard(s.renewOne))
	mux.HandleFunc("POST /admin/accounts/pause", s.guard(s.pauseAccount))
	mux.HandleFunc("POST /admin/accounts/disconnect", s.guard(s.disconnect))
	mux.HandleFunc("POST /admin/accounts/pubsub", s.guard(s.savePubSub))
	mux.HandleFunc("POST /admin/accounts/pubsub/verify", s.guard(s.verifyPubSub))
	mux.HandleFunc("POST /admin/accounts/pubsub/create", s.guard(s.createPubSub))
	mux.HandleFunc("POST /admin/accounts/pubsub/grant", s.guard(s.grantPubSub))
	mux.HandleFunc("POST /admin/accounts/labels", s.guard(s.createLabel))
	mux.HandleFunc("POST /admin/accounts/filters", s.guard(s.createFilter))

	mux.HandleFunc("GET /admin/routes", s.guard(s.routes))
	mux.HandleFunc("GET /admin/routes/new", s.guard(s.routeEdit))
	mux.HandleFunc("GET /admin/routes/{id}", s.guard(s.routeEdit))
	mux.HandleFunc("POST /admin/routes/save", s.guard(s.routeSave))
	mux.HandleFunc("POST /admin/routes/preview", s.guard(s.routePreview))
	mux.HandleFunc("POST /admin/routes/delete", s.guard(s.routeDelete))
	mux.HandleFunc("POST /admin/routes/reorder", s.guard(s.routeReorder))
	mux.HandleFunc("POST /admin/routes/move", s.guard(s.routeMove))
	mux.HandleFunc("POST /admin/routes/simulate", s.guard(s.routeSimulate))

	mux.HandleFunc("GET /admin/targets", s.guard(s.targets))
	mux.HandleFunc("GET /admin/targets/new", s.guard(s.targetEdit))
	mux.HandleFunc("GET /admin/targets/{id}", s.guard(s.targetEdit))
	mux.HandleFunc("POST /admin/targets/save", s.guard(s.targetSave))
	mux.HandleFunc("POST /admin/targets/delete", s.guard(s.targetDelete))
	mux.HandleFunc("POST /admin/targets/pause", s.guard(s.targetPause))
	mux.HandleFunc("POST /admin/targets/test", s.guard(s.targetTest))

	mux.HandleFunc("GET /admin/deliveries", s.guard(s.deliveries))
	mux.HandleFunc("GET /admin/deliveries/{id}", s.guard(s.delivery))
	mux.HandleFunc("POST /admin/deliveries/retry", s.guard(s.deliveryRetry))
	mux.HandleFunc("POST /admin/deliveries/replay", s.guard(s.deliveryReplay))
	mux.HandleFunc("POST /admin/deliveries/window", s.guard(s.deliveryWindow))

	mux.HandleFunc("GET /admin/settings", s.guard(s.settings))
	mux.HandleFunc("POST /admin/settings", s.guard(s.settingsSave))
	mux.HandleFunc("POST /admin/export", s.guard(s.exportYAML))
	mux.HandleFunc("POST /admin/import", s.guard(s.importYAML))
	mux.HandleFunc("GET /admin/audit", s.guard(s.auditPage))
	mux.HandleFunc("GET /admin/members", s.guard(s.members))
	mux.HandleFunc("POST /admin/members", s.guard(s.membersSave))
	mux.HandleFunc("POST /admin/workspace", s.guard(s.switchWorkspace))
	mux.HandleFunc("POST /admin/workspaces", s.guard(s.createWorkspace))
	return secureHeaders(mux)
}

func (s *Server) legal(name, title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.render(w, name, page{Title: title, Solo: true})
	}
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) render(w http.ResponseWriter, name string, p page) {
	p.Version = config.Version
	if s.RT != nil && s.RT.Cfg != nil {
		p.Public = s.RT.Cfg.PublicURL
		if p.GoogleRedirect == "" {
			p.GoogleRedirect = s.RT.Cfg.GoogleRedirect()
		}
		if p.PushURL == "" {
			p.PushURL = s.RT.Cfg.PushEndpoint()
		}
		if p.OIDCRedirect == "" {
			p.OIDCRedirect = s.RT.Cfg.OIDCRedirect()
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl[name].ExecuteTemplate(w, "layout", p); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func (s *Server) guard(fn func(http.ResponseWriter, *http.Request, page)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.RT == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		mode := s.RT.Cfg.Mode()
		switch mode {
		case config.AuthNone:
			if !s.sessionOrMint(w, r, "ghook:implicit", "", "Admin") {
				return
			}
		case config.AuthProxy:
			if !s.proxyAuth(w, r) {
				return
			}
		default:
			if !s.RT.Cfg.OIDCEnabled() {
				if r.Method != http.MethodGet {
					http.Error(w, "OIDC is not configured", http.StatusForbidden)
					return
				}
				s.render(w, "notconfigured", page{Title: "Sign in", Solo: true})
				return
			}
			if _, ok := s.Session(r); !ok {
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					http.Error(w, "sign in required", http.StatusUnauthorized)
					return
				}
				s.render(w, "signedout", page{Title: "Sign in", Solo: true})
				return
			}
		}
		csrf, ok := s.Session(r)
		if !ok {
			http.Error(w, "sign in required", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
				_ = r.ParseMultipartForm(2 << 20)
			} else {
				_ = r.ParseForm()
			}
			if !csrfOK(r, csrf) {
				http.Error(w, "csrf check failed", http.StatusBadRequest)
				return
			}
		}
		p, ok := s.pageFor(w, r, csrf)
		if !ok {
			s.render(w, "noworkspace", page{Title: "No workspace", Solo: true, User: s.Label(r)})
			return
		}
		if r.Method == http.MethodPost && !s.allowPost(r, p.Role) {
			http.Error(w, "this role cannot change that", http.StatusForbidden)
			return
		}
		fn(w, r, p)
	}
}

func (s *Server) allowPost(r *http.Request, role string) bool {
	if role == "owner" || role == "" {
		return role == "owner"
	}
	path := r.URL.Path
	if role == "viewer" {
		return strings.HasSuffix(path, "/simulate") || strings.HasSuffix(path, "/preview") || path == "/admin/workspace"
	}
	// editor
	switch {
	case strings.HasPrefix(path, "/admin/settings"), strings.HasPrefix(path, "/admin/members"),
		strings.HasPrefix(path, "/admin/accounts/client"), strings.HasPrefix(path, "/admin/accounts/pubsub"),
		path == "/admin/workspaces":
		return false
	}
	return true
}

func csrfOK(r *http.Request, want string) bool {
	got := r.FormValue("csrf")
	if got == "" {
		got = r.Header.Get("X-CSRF")
	}
	if len(got) != len(want) || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) flash(w http.ResponseWriter, kind, msg string) {
	raw, _ := json.Marshal(toast{Kind: kind, Msg: msg})
	http.SetCookie(w, &http.Cookie{
		Name: flashName, Value: base64.RawURLEncoding.EncodeToString(raw), Path: "/", MaxAge: 30,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secure(),
	})
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) []toast {
	c, err := r.Cookie(flashName)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flashName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure()})
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	var t toast
	if json.Unmarshal(raw, &t) != nil || t.Msg == "" {
		return nil
	}
	return []toast{t}
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, path, kind, msg string) {
	s.flash(w, kind, msg)
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (s *Server) audit(actor, action, detail string) {
	if s.RT == nil {
		return
	}
	_ = s.RT.DB.Audit(actor, action, detail)
}

func (s *Server) secure() bool {
	return s.RT != nil && strings.HasPrefix(s.RT.Cfg.PublicURL, "https://")
}

func (s *Server) secret() []byte {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	if s.secretKey != nil {
		return s.secretKey
	}
	plain, ok, err := s.RT.DB.Instance().OpenSecret("session_secret")
	if err == nil && ok {
		if b, err := base64.RawStdEncoding.DecodeString(plain); err == nil && len(b) >= 32 {
			s.secretKey = b
			return b
		}
	}
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return b
	}
	if s.RT.DB.Instance().SetSecret("session_secret", base64.RawStdEncoding.EncodeToString(b)) == nil {
		s.secretKey = b
	}
	return b
}

func (s *Server) mac(msg string) string {
	m := hmac.New(sha256.New, s.secret())
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) setSession(w http.ResponseWriter, id oidcauth.Identity) {
	nonce := randToken(16)
	exp := time.Now().Add(sessionTTL)
	raw, _ := json.Marshal(sessionClaims{Sub: id.Subject, Email: id.Email, Label: id.Display()})
	payload := strconv.FormatInt(exp.Unix(), 10) + "." + nonce + "." + base64.RawURLEncoding.EncodeToString(raw)
	s.sessions.put(nonce, sessionInfo{who: id.Display(), idToken: id.IDToken, exp: exp})
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: payload + "." + s.mac(payload), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secure(), Expires: exp,
	})
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secure()})
}

func (s *Server) parseSession(r *http.Request) (nonce string, payload string, cl sessionClaims, ok bool) {
	if s.RT == nil {
		return "", "", cl, false
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", "", cl, false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 4 {
		return "", "", cl, false
	}
	payload = strings.Join(parts[:3], ".")
	sig := s.mac(payload)
	if len(sig) != len(parts[3]) || subtle.ConstantTimeCompare([]byte(sig), []byte(parts[3])) != 1 {
		return "", "", cl, false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", "", cl, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || json.Unmarshal(raw, &cl) != nil || cl.Sub == "" {
		return "", "", cl, false
	}
	if s.sessions.isRevoked(parts[1]) {
		return "", "", cl, false
	}
	return parts[1], payload, cl, true
}

// Session returns the CSRF token for a signed-in admin.
func (s *Server) Session(r *http.Request) (string, bool) {
	_, payload, _, ok := s.parseSession(r)
	if !ok {
		return "", false
	}
	return s.mac("csrf:" + payload), true
}

// Label is the header name of the signed-in admin.
func (s *Server) Label(r *http.Request) string {
	_, _, cl, ok := s.parseSession(r)
	if !ok {
		return ""
	}
	return cl.label()
}

func (ss *sessionStore) put(nonce string, si sessionInfo) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.info == nil {
		ss.info = map[string]sessionInfo{}
	}
	ss.info[nonce] = si
}

func (ss *sessionStore) get(nonce string) (sessionInfo, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	si, ok := ss.info[nonce]
	return si, ok && time.Now().Before(si.exp)
}

func (ss *sessionStore) revoke(nonce string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.revoked == nil {
		ss.revoked = map[string]time.Time{}
	}
	ss.revoked[nonce] = time.Now().Add(sessionTTL)
	delete(ss.info, nonce)
}

func (ss *sessionStore) isRevoked(nonce string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	_, ok := ss.revoked[nonce]
	return ok
}
