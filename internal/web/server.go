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

	"github.com/helv-io/ghook/internal/auth"
	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/engine"
	"github.com/helv-io/ghook/internal/feed"
	"github.com/helv-io/ghook/internal/match"
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
	who string
	exp time.Time
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
	Title, Nav, CSRF, User, UserEmail, Version, Public string
	Solo, Ready                                        bool
	// Testing shows the simulator and replay controls (Settings > Testing mode).
	Testing bool
	// More opens the "More options" section of an edit form.
	More bool
	// DBSize and CompactLast describe the instance database on Settings.
	DBSize                  string
	CompactLast             time.Time
	CompactAt               string
	Banner                  string
	Toasts                  []toast
	Err                     string
	GoogleRedirect, PushURL string

	Accounts      []store.Account
	HasClient     bool
	ClientID      string
	Modify        bool
	SettingsScope bool
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

	// Loc is the signed-in user's display timezone. Every time on a page is shown in it.
	Loc                     *time.Location
	TargetRows              []targetRow
	RouteNames, TargetNames []string

	LabelConvention                                                      bool
	Catchup, ResyncDays, RetryAttempts, RetryHours, RetryBase, Retention int
	Timezone                                                             string
	NotifyTarget                                                         int64
	NotifyDead, NotifyWatch, RetainBodies                                bool
	MaxTargets, MaxRoutes, MaxDeliveries                                 int
	TargetCount, RouteCount, TodayCount                                  int
}

type labelView struct {
	ID, Name string
}

// New parses templates and returns a server.
func New(rt *runtime.App) (*Server, error) {
	s := &Server{RT: rt, tpl: map[string]*template.Template{}}
	names := []string{"dashboard", "accounts", "routes", "route_edit", "targets", "target_edit", "deliveries", "delivery", "settings", "audit", "signedout", "notconfigured", "autherror", "login", "account", "privacy", "terms"}
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
		"wordmark":        wordmark,
		"subjectExamples": func() []match.Example { return match.SubjectExamples },
		"pathcode":        pathcode,
		"scopes": func(raw string) []string {
			var out []string
			for _, p := range strings.Fields(raw) {
				p = strings.TrimSuffix(p, "/")
				if i := strings.LastIndex(p, "/"); i >= 0 {
					p = p[i+1:]
				}
				if p != "" {
					out = append(out, p)
				}
			}
			return out
		},
		"when":  func(u int64) string { return s.format(u, false) },
		"short": func(u int64) string { return shortTime(u, time.UTC, time.Now()) },
		"full":  func(u int64) string { return fullTime(u, time.UTC) },
		"iso": func(u int64) string {
			if u == 0 {
				return ""
			}
			return time.Unix(u, 0).UTC().Format(time.RFC3339)
		},
		"view":        func(sp match.Spec) match.View { return sp.View() },
		"dest":        targetDest,
		"authLabel":   authLabel,
		"statusClass": statusClass,
		"senderName":  func(f string) string { n, _ := sender(f); return n },
		"senderAddr":  func(f string) string { _, a := sender(f); return a },
		"add":         func(a, b int) int { return a + b },
		"until":       func(u int64) string { return s.until(u) },
		"rel":         func(u int64) string { return s.rel(u) },
		"lines":       func(v []string) string { return strings.Join(v, "\n") },
		"summary":     func(sp match.Spec) string { return sp.Summary() },
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

func (s *Server) loc() *time.Location { return s.locOf(nil) }

// timeFuncs are the template time helpers bound to one display timezone.
func (s *Server) timeFuncs(loc *time.Location) template.FuncMap {
	return template.FuncMap{
		"when": func(u int64) string {
			if u == 0 {
				return "—"
			}
			return time.Unix(u, 0).In(loc).Format("2006-01-02 15:04")
		},
		"short": func(u int64) string { return shortTime(u, loc, time.Now()) },
		"full":  func(u int64) string { return fullTime(u, loc) },
		"clock": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.In(loc).Format("15:04:05")
		},
	}
}

func (s *Server) locOf(r *http.Request) *time.Location {
	name := "UTC"
	if r != nil {
		if db := s.db(r); db != nil && db.UserID() != 0 {
			name = db.Setting("timezone", "UTC")
		}
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
	mux.HandleFunc("GET /{$}", s.root)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /auth/google", s.googleStart)
	mux.HandleFunc("GET /admin/google/callback", s.googleCallback)
	mux.HandleFunc("POST /admin/logout", s.guard(s.logout))

	mux.HandleFunc("GET /admin", s.guard(s.dashboard))
	mux.HandleFunc("GET /admin/events", s.guard(s.events))
	mux.HandleFunc("GET /admin/accounts", s.guard(s.accounts))
	mux.HandleFunc("POST /admin/accounts/scopes", s.guard(s.saveScopes))
	mux.HandleFunc("POST /admin/accounts/watch", s.guard(s.renewOne))
	mux.HandleFunc("POST /admin/accounts/pause", s.guard(s.pauseAccount))
	mux.HandleFunc("POST /admin/accounts/disconnect", s.guard(s.disconnect))
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
	mux.HandleFunc("POST /admin/routes/field", s.guard(s.routeField))
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
	mux.HandleFunc("GET /admin/account", s.guard(s.accountPage))
	mux.HandleFunc("POST /admin/account/delete", s.guard(s.deleteAccount))
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
		p.Ready = s.RT.Cfg.Ready()
		p.MaxTargets, p.MaxRoutes, p.MaxDeliveries = s.RT.Cfg.MaxTargets, s.RT.Cfg.MaxRoutes, s.RT.Cfg.MaxDeliveries
	}
	// The parsed set is never executed itself: html/template cannot clone a set after it runs.
	// Each render runs a clone with the time helpers bound to the user's timezone.
	loc := p.Loc
	if loc == nil {
		loc = time.UTC
	}
	t, err := s.tpl[name].Clone()
	if err != nil {
		log.Printf("template %s: %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	t = t.Funcs(s.timeFuncs(loc))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", p); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func (s *Server) guard(fn func(http.ResponseWriter, *http.Request, page)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.RT == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		if _, ok := s.Session(r); !ok {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.Error(w, "sign in required", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		csrf, ok := s.Session(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
				_ = r.ParseMultipartForm(2 << 20)
			} else {
				_ = r.ParseForm()
			}
			if !csrfOK(r, csrf) {
				if wantsJSON(r) {
					writeSaveErr(w, "csrf check failed", "")
					return
				}
				http.Error(w, "csrf check failed", http.StatusBadRequest)
				return
			}
		}
		p, ok := s.pageFor(w, r, csrf)
		if !ok {
			s.clearSession(w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		fn(w, r, p)
	}
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

// IssueSession writes a session cookie for the given Google identity.
// Tests and local screenshot tools use this; it is not an HTTP route.
func (s *Server) IssueSession(w http.ResponseWriter, subject, email, name string) {
	s.setSession(w, auth.Identity{Subject: subject, Email: email, Name: name, Username: name})
}

func (s *Server) setSession(w http.ResponseWriter, id auth.Identity) {
	nonce := randToken(16)
	exp := time.Now().Add(sessionTTL)
	raw, _ := json.Marshal(sessionClaims{Sub: id.Subject, Email: id.Email, Label: id.Display()})
	payload := strconv.FormatInt(exp.Unix(), 10) + "." + nonce + "." + base64.RawURLEncoding.EncodeToString(raw)
	s.sessions.put(nonce, sessionInfo{who: id.Display(), exp: exp})
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
