package web

// The JSON API under /api/v1. Auth is a per-user API key sent as
// "Authorization: Bearer ghk_...". A key acts only as its own user, exactly
// like that user's session. Cookies and query strings are never accepted as
// credentials, so there is no CSRF surface.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/helv-io/ghook/internal/bundle"
	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/engine"
	"github.com/helv-io/ghook/internal/gmailx"
	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/store"
	"gopkg.in/yaml.v3"
)

const (
	// apiPerMinute is the request budget of one key.
	apiPerMinute = 300
	// apiFailPerMinute is how many failed authentications one client may make.
	apiFailPerMinute = 30
	apiBodyLimit     = 1 << 20
)

// apiCall is what an API handler gets: the caller's scoped database and an audit actor.
type apiCall struct {
	db    *store.DB
	key   store.APIKey
	user  store.User
	actor string
}

type apiFunc func(w http.ResponseWriter, r *http.Request, c apiCall)

type apiResponse struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
	Field string `json:"field,omitempty"`
}

func apiWrite(w http.ResponseWriter, status int, resp apiResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func apiOK(w http.ResponseWriter, data any) {
	apiWrite(w, http.StatusOK, apiResponse{OK: true, Data: data})
}

func apiCreated(w http.ResponseWriter, data any) {
	apiWrite(w, http.StatusCreated, apiResponse{OK: true, Data: data})
}

func apiFail(w http.ResponseWriter, err error) {
	status, msg, field := explain(err)
	apiWrite(w, status, apiResponse{Error: msg, Field: field})
}

func apiError(w http.ResponseWriter, status int, msg string) {
	apiWrite(w, status, apiResponse{Error: msg})
}

// limiter is a fixed one-minute window per key.
type limiter struct {
	mu    sync.Mutex
	win   int64
	count map[string]int
}

func (l *limiter) allow(key string, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := time.Now().Unix() / 60
	if w != l.win || l.count == nil {
		l.win, l.count = w, map[string]int{}
	}
	l.count[key]++
	return l.count[key] <= max
}

func clientIP(r *http.Request) string {
	// The last X-Forwarded-For entry is the one the proxy in front added.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// bearer reads the API key from the Authorization header only.
func bearer(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// keyInQuery reports a credential sent in the URL, which is refused.
func keyInQuery(r *http.Request) bool {
	for name, vals := range r.URL.Query() {
		switch strings.ToLower(name) {
		case "access_token", "api_key", "apikey", "token", "key", "bearer":
			return true
		}
		for _, v := range vals {
			if strings.HasPrefix(v, store.KeyPrefix) {
				return true
			}
		}
	}
	return false
}

func (s *Server) api(fn apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.RT == nil {
			apiError(w, http.StatusServiceUnavailable, "Not ready.")
			return
		}
		if keyInQuery(r) {
			apiError(w, http.StatusBadRequest, "Send the key in the Authorization header.")
			return
		}
		// Failed attempts are throttled per client. A valid key is never held
		// back by someone else's failures, so a spoofed address cannot lock it out.
		ip := clientIP(r)
		deny := func() {
			if !s.apiFails.allow(ip, apiFailPerMinute) {
				w.Header().Set("Retry-After", "60")
				apiError(w, http.StatusTooManyRequests, "Too many failed attempts. Try again in a minute.")
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="ghook"`)
			apiError(w, http.StatusUnauthorized, "A valid API key is required.")
		}
		token := bearer(r)
		if token == "" {
			deny()
			return
		}
		key, err := s.RT.DB.LookupAPIKey(token)
		if err != nil {
			deny()
			return
		}
		user, ok, err := s.RT.DB.UserByID(key.UserID)
		if err != nil || !ok {
			deny()
			return
		}
		if !s.apiRate.allow(key.KeyID, apiPerMinute) {
			w.Header().Set("Retry-After", "60")
			apiError(w, http.StatusTooManyRequests, "Rate limit reached. Try again in a minute.")
			return
		}
		write := r.Method != http.MethodGet && r.Method != http.MethodHead
		if write && !key.CanWrite() {
			apiError(w, http.StatusForbidden, "This key is read only.")
			return
		}
		db := s.RT.DB.Use(user.ID)
		*r = *r.WithContext(context.WithValue(r.Context(), userKey, db))
		label := user.Name
		if label == "" {
			label = user.Email
		}
		c := apiCall{db: db, key: key, user: user, actor: label + " via " + key.Display()}
		if write {
			_ = db.Audit(c.actor, "apikey.use", r.Method+" "+r.URL.Path)
		}
		r.Body = http.MaxBytesReader(w, r.Body, apiBodyLimit)
		fn(w, r, c)
	}
}

func decode(r *http.Request, v any) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return errBad("The request body is too large.", "")
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return errBad("The request body is not valid JSON: "+safeErr(err), "")
	}
	return nil
}

func pathID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		return 0, errNotFound("Not found.")
	}
	return id, nil
}

func iso(u int64) string {
	if u == 0 {
		return ""
	}
	return time.Unix(u, 0).UTC().Format(time.RFC3339)
}

// ---- views ----

type accountView struct {
	ID          int64    `json:"id"`
	Email       string   `json:"email"`
	Scopes      []string `json:"scopes"`
	Connected   bool     `json:"connected"`
	Paused      bool     `json:"paused"`
	WatchExpiry string   `json:"watch_expiry,omitempty"`
	WatchError  string   `json:"watch_error,omitempty"`
	LastNotify  string   `json:"last_notification,omitempty"`
	LastSync    string   `json:"last_sync,omitempty"`
	HistoryID   string   `json:"history_id,omitempty"`
}

func viewAccount(a store.Account) accountView {
	return accountView{
		ID: a.ID, Email: a.Email, Scopes: strings.Fields(a.Scopes), Connected: a.HasToken, Paused: a.Disabled,
		WatchExpiry: iso(a.WatchExpiry), WatchError: a.WatchError, LastNotify: iso(a.LastNotify), LastSync: iso(a.LastSync),
		HistoryID: a.HistoryID,
	}
}

type routeView struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Position   int        `json:"position"`
	Enabled    bool       `json:"enabled"`
	Fallback   bool       `json:"fallback"`
	Continue   bool       `json:"continue"`
	ApplyLabel bool       `json:"apply_label"`
	TargetID   int64      `json:"target_id"`
	Target     string     `json:"target"`
	Match      match.Spec `json:"match"`
	Summary    string     `json:"summary"`
}

func viewRoute(rt store.Route) routeView {
	return routeView{
		ID: rt.ID, Name: rt.Name, Position: rt.Position, Enabled: rt.Enabled, Fallback: rt.Fallback, Continue: rt.Continue,
		ApplyLabel: rt.ApplyLabel, TargetID: rt.TargetID, Target: rt.TargetName, Match: rt.Spec, Summary: rt.Spec.Summary(),
	}
}

// routeInput is a create or a partial update. Absent fields keep their value.
type routeInput struct {
	Name       *string     `json:"name"`
	TargetID   *int64      `json:"target_id"`
	Target     *string     `json:"target"`
	Enabled    *bool       `json:"enabled"`
	Fallback   *bool       `json:"fallback"`
	Continue   *bool       `json:"continue"`
	ApplyLabel *bool       `json:"apply_label"`
	Match      *match.Spec `json:"match"`
	N          int         `json:"n"`
}

func (in routeInput) apply(db *store.DB, rt store.Route) (store.Route, error) {
	if in.Name != nil {
		rt.Name = *in.Name
	}
	if in.TargetID != nil {
		rt.TargetID = *in.TargetID
	}
	if in.Target != nil && in.TargetID == nil {
		tg, ok, err := db.TargetByName(strings.TrimSpace(*in.Target), false)
		if err != nil {
			return rt, err
		}
		if !ok {
			return rt, errBad("No target by that name.", "target")
		}
		rt.TargetID = tg.ID
	}
	if in.Enabled != nil {
		rt.Enabled = *in.Enabled
	}
	if in.Fallback != nil {
		rt.Fallback = *in.Fallback
	}
	if in.Continue != nil {
		rt.Continue = *in.Continue
	}
	if in.ApplyLabel != nil {
		rt.ApplyLabel = *in.ApplyLabel
	}
	if in.Match != nil {
		rt.Spec = in.Match.Normalize()
	}
	return rt, nil
}

type targetView struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	AuthMode      string `json:"auth_mode"`
	AuthHeader    string `json:"auth_header,omitempty"`
	HasSecret     bool   `json:"has_secret"`
	Template      string `json:"payload_template,omitempty"`
	IncludeBody   bool   `json:"include_body"`
	Paused        bool   `json:"paused"`
	QuietStart    string `json:"quiet_start,omitempty"`
	QuietEnd      string `json:"quiet_end,omitempty"`
	DigestAt      string `json:"digest_at,omitempty"`
	RatePerMin    int    `json:"rate_per_minute"`
	PayloadPubKey string `json:"payload_pubkey,omitempty"`
}

func viewTarget(t store.Target) targetView {
	return targetView{
		ID: t.ID, Name: t.Name, URL: t.URL, AuthMode: t.AuthMode, AuthHeader: t.AuthHeader, HasSecret: t.HasSecret,
		Template: t.Template, IncludeBody: t.IncludeBody, Paused: t.Paused, QuietStart: t.QuietStart, QuietEnd: t.QuietEnd,
		DigestAt: t.DigestAt, RatePerMin: t.RatePerMin, PayloadPubKey: t.PayloadPubKey,
	}
}

// targetInput is a create or a partial update. Secret is write only.
type targetInput struct {
	Name          *string `json:"name"`
	URL           *string `json:"url"`
	Secret        *string `json:"secret"`
	ClearSecret   bool    `json:"clear_secret"`
	AuthMode      *string `json:"auth_mode"`
	AuthHeader    *string `json:"auth_header"`
	Template      *string `json:"payload_template"`
	IncludeBody   *bool   `json:"include_body"`
	Paused        *bool   `json:"paused"`
	QuietStart    *string `json:"quiet_start"`
	QuietEnd      *string `json:"quiet_end"`
	DigestAt      *string `json:"digest_at"`
	RatePerMin    *int    `json:"rate_per_minute"`
	PayloadPubKey *string `json:"payload_pubkey"`
}

func (in targetInput) apply(t store.Target) store.Target {
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	set(&t.Name, in.Name)
	set(&t.URL, in.URL)
	set(&t.AuthMode, in.AuthMode)
	set(&t.AuthHeader, in.AuthHeader)
	set(&t.Template, in.Template)
	set(&t.QuietStart, in.QuietStart)
	set(&t.QuietEnd, in.QuietEnd)
	set(&t.DigestAt, in.DigestAt)
	set(&t.PayloadPubKey, in.PayloadPubKey)
	if in.IncludeBody != nil {
		t.IncludeBody = *in.IncludeBody
	}
	if in.Paused != nil {
		t.Paused = *in.Paused
	}
	if in.RatePerMin != nil {
		t.RatePerMin = *in.RatePerMin
	}
	return t
}

type deliveryView struct {
	ID             int64  `json:"id"`
	DeliveryID     string `json:"delivery_id"`
	Status         string `json:"status"`
	Kind           string `json:"kind"`
	Route          string `json:"route"`
	TargetID       int64  `json:"target_id"`
	Target         string `json:"target"`
	Account        string `json:"account"`
	GmailID        string `json:"gmail_id"`
	ThreadID       string `json:"thread_id,omitempty"`
	From           string `json:"from,omitempty"`
	Subject        string `json:"subject,omitempty"`
	Attempts       int    `json:"attempts"`
	NextAttempt    string `json:"next_attempt,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	ResponseStatus int    `json:"response_status,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
	SentAt         string `json:"sent_at,omitempty"`
	Request        string `json:"request,omitempty"`
	Response       string `json:"response,omitempty"`
}

func viewDelivery(d store.Delivery, full bool) deliveryView {
	v := deliveryView{
		ID: d.ID, DeliveryID: d.Key, Status: d.Status, Kind: d.Kind, Route: d.RouteName, TargetID: d.TargetID, Target: d.TargetName,
		Account: d.AccountEmail, GmailID: d.GmailID, ThreadID: d.ThreadID, From: d.From, Subject: d.Subject,
		Attempts: d.Attempts, NextAttempt: iso(d.NextAttempt), LastError: d.LastError, ResponseStatus: d.ResponseStatus,
		CreatedAt: iso(d.CreatedAt), UpdatedAt: iso(d.UpdatedAt), SentAt: iso(d.SentAt),
	}
	if full {
		v.Request, v.Response = d.RequestLog, d.ResponseBody
	}
	return v
}

type previewView struct {
	From    string `json:"from"`
	Subject string `json:"subject"`
	Account string `json:"account"`
	Route   string `json:"route"`
	GmailID string `json:"gmail_id"`
}

func viewPreviews(in []engine.Preview) []previewView {
	out := []previewView{}
	for _, p := range in {
		out = append(out, previewView{From: p.From, Subject: p.Subject, Account: p.Account, Route: p.Route, GmailID: p.GmailID})
	}
	return out
}

type keyView struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Prefix    string `json:"prefix"`
	CreatedAt string `json:"created_at"`
	LastUsed  string `json:"last_used,omitempty"`
	Token     string `json:"token,omitempty"`
}

func viewKey(k store.APIKey) keyView {
	scope := "read-only"
	if k.CanWrite() {
		scope = "read-write"
	}
	return keyView{ID: k.ID, Name: k.Name, Scope: scope, Prefix: k.Display(), CreatedAt: iso(k.CreatedAt), LastUsed: iso(k.LastUsed)}
}

// ---- routes table ----

type apiRoute struct {
	Method, Path, Does string
	fn                 apiFunc
}

func (s *Server) apiRoutes() []apiRoute {
	return []apiRoute{
		{"GET", "/api/v1", "This list.", s.apiIndex},
		{"GET", "/api/v1/status", "Health and counts.", s.apiStatus},

		{"GET", "/api/v1/accounts", "Connected mailboxes.", s.apiAccounts},
		{"GET", "/api/v1/accounts/scopes", "Optional Gmail scopes.", s.apiScopes},
		{"PUT", "/api/v1/accounts/scopes", "Set optional Gmail scopes. Answers the Google consent URL.", s.apiSetScopes},
		{"GET", "/api/v1/accounts/{id}", "One mailbox.", s.apiAccount},
		{"POST", "/api/v1/accounts/{id}/watch", "Renew the Gmail watch.", s.apiAccountWatch},
		{"POST", "/api/v1/accounts/{id}/pause", `Pause or resume: {"paused":true}.`, s.apiAccountPause},
		{"DELETE", "/api/v1/accounts/{id}", "Disconnect a mailbox.", s.apiAccountDisconnect},
		{"GET", "/api/v1/accounts/{id}/labels", "Gmail labels.", s.apiLabels},
		{"POST", "/api/v1/accounts/{id}/labels", `Create a label: {"name":"..."}.`, s.apiCreateLabel},
		{"GET", "/api/v1/accounts/{id}/filters", "Gmail filters.", s.apiFilters},
		{"POST", "/api/v1/accounts/{id}/filters", `Create a filter: {"from","subject","label"}.`, s.apiCreateFilter},
		{"DELETE", "/api/v1/accounts/{id}/filters/{filter}", "Delete a Gmail filter.", s.apiDeleteFilter},

		{"GET", "/api/v1/routes", "Routes in order.", s.apiRouteList},
		{"POST", "/api/v1/routes", "Create a route.", s.apiRouteCreate},
		{"GET", "/api/v1/routes/simulate", "Run every route over recent mail: ?n=20.", s.apiRouteSimulate},
		{"POST", "/api/v1/routes/preview", "Preview an unsaved route over recent mail.", s.apiRoutePreview},
		{"PUT", "/api/v1/routes/order", `Set the order: {"ids":[3,1,2]}.`, s.apiRouteOrder},
		{"GET", "/api/v1/routes/{id}", "One route.", s.apiRouteGet},
		{"PATCH", "/api/v1/routes/{id}", "Update a route. Absent fields keep their value.", s.apiRouteUpdate},
		{"PUT", "/api/v1/routes/{id}", "Same as PATCH.", s.apiRouteUpdate},
		{"DELETE", "/api/v1/routes/{id}", "Delete a route.", s.apiRouteDelete},
		{"POST", "/api/v1/routes/{id}/move", `Move one step: {"dir":"up"} or "down".`, s.apiRouteMove},
		{"PUT", "/api/v1/routes/{id}/fields/{field}", `Set one filter field: {"values":[...]}.`, s.apiRouteField},

		{"GET", "/api/v1/targets", "Targets.", s.apiTargetList},
		{"POST", "/api/v1/targets", "Create a target.", s.apiTargetCreate},
		{"GET", "/api/v1/targets/{id}", "One target.", s.apiTargetGet},
		{"PATCH", "/api/v1/targets/{id}", "Update a target. Absent fields keep their value.", s.apiTargetUpdate},
		{"PUT", "/api/v1/targets/{id}", "Same as PATCH.", s.apiTargetUpdate},
		{"DELETE", "/api/v1/targets/{id}", "Delete a target no route uses.", s.apiTargetDelete},
		{"POST", "/api/v1/targets/{id}/pause", `Pause or resume: {"paused":true}.`, s.apiTargetPause},
		{"POST", "/api/v1/targets/{id}/test", "Send a test delivery now.", s.apiTargetTest},

		{"GET", "/api/v1/deliveries", "Deliveries: ?status=&route=&target=&limit=.", s.apiDeliveryList},
		{"POST", "/api/v1/deliveries/replay", `Replay a window: {"route","target","since","until"}.`, s.apiDeliveryWindow},
		{"GET", "/api/v1/deliveries/{id}", "One delivery with its request and response.", s.apiDeliveryGet},
		{"POST", "/api/v1/deliveries/{id}/retry", "Retry with the same delivery id.", s.apiDeliveryRetry},
		{"POST", "/api/v1/deliveries/{id}/replay", "Replay with a new delivery id.", s.apiDeliveryReplay},

		{"GET", "/api/v1/events", "Recent activity.", s.apiEvents},
		{"GET", "/api/v1/settings", "Settings.", s.apiSettings},
		{"PATCH", "/api/v1/settings", "Update settings. Absent keys keep their value.", s.apiSettingsSave},
		{"PUT", "/api/v1/settings", "Same as PATCH.", s.apiSettingsSave},
		{"GET", "/api/v1/export", "Routes and targets: ?format=yaml or json. Secrets left out.", s.apiExport},
		{"POST", "/api/v1/export", "Export with secrets sealed by the X-Ghook-Passphrase header.", s.apiExport},
		{"POST", "/api/v1/import", "Import a YAML or JSON bundle. Sealed secrets need X-Ghook-Passphrase.", s.apiImport},
		{"GET", "/api/v1/audit", "Audit log: ?limit=200.", s.apiAudit},

		{"GET", "/api/v1/account", "You.", s.apiMe},
		{"DELETE", "/api/v1/account", `Delete your account and data: {"confirm":true}.`, s.apiMeDelete},
		{"GET", "/api/v1/account/keys", "API keys.", s.apiKeyList},
		{"POST", "/api/v1/account/keys", `Create a key: {"name","scope":"read-only"|"read-write"}. The token is shown once.`, s.apiKeyCreate},
		{"DELETE", "/api/v1/account/keys/{id}", "Revoke a key.", s.apiKeyRevoke},
	}
}

func (s *Server) mountAPI(mux *http.ServeMux) {
	for _, rt := range s.apiRoutes() {
		mux.HandleFunc(rt.Method+" "+rt.Path, s.api(rt.fn))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "No such endpoint. GET /api/v1 lists them.")
	})
}

// ---- handlers ----

func (s *Server) apiIndex(w http.ResponseWriter, r *http.Request, c apiCall) {
	type ep struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Does   string `json:"does"`
	}
	out := []ep{}
	for _, rt := range s.apiRoutes() {
		out = append(out, ep{rt.Method, rt.Path, rt.Does})
	}
	apiOK(w, map[string]any{"version": config.Version, "endpoints": out})
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request, c apiCall) {
	accs, _ := c.db.Accounts()
	routes, _ := c.db.Routes()
	targets, _ := c.db.Targets()
	counts, _ := c.db.DeliveryCounts()
	var connected, paused, watching, enabled, filters, pausedTargets int
	var soonest, last int64
	for _, a := range accs {
		if a.HasToken && !a.Disabled {
			connected++
		}
		if a.Disabled {
			paused++
		}
		if a.WatchExpiry > time.Now().Unix() && a.WatchError == "" {
			watching++
		}
		if a.WatchExpiry != 0 && (soonest == 0 || a.WatchExpiry < soonest) {
			soonest = a.WatchExpiry
		}
		if a.LastNotify > last {
			last = a.LastNotify
		}
	}
	for _, rt := range routes {
		if rt.Enabled {
			enabled++
		}
		for _, f := range []string{"from", "to", "cc", "subject", "contains", "labels"} {
			filters += len(rt.Spec.Field(f))
		}
		filters += len(rt.Spec.Categories)
		if rt.Spec.Attachment != "" {
			filters++
		}
	}
	for _, t := range targets {
		if t.Paused {
			pausedTargets++
		}
	}
	day := time.Now().UTC().Truncate(24 * time.Hour).Unix()
	apiOK(w, map[string]any{
		"version": config.Version,
		"user":    c.user.Email,
		"accounts": map[string]any{
			"total": len(accs), "connected": connected, "paused": paused, "watching": watching,
			"watch_expires": iso(soonest), "last_notification": iso(last),
		},
		"routes":  map[string]int{"total": len(routes), "enabled": enabled, "filters": filters},
		"targets": map[string]int{"total": len(targets), "paused": pausedTargets},
		"deliveries": map[string]int{
			"queued": counts.Queued, "retry": counts.Retry, "dead": counts.Dead, "sent": counts.Sent,
			"today": c.db.DeliveriesSince(day),
		},
		"limits": map[string]int{"targets": s.RT.Cfg.MaxTargets, "routes": s.RT.Cfg.MaxRoutes, "deliveries_per_day": s.RT.Cfg.MaxDeliveries},
	})
}

// accounts

func (s *Server) apiAccounts(w http.ResponseWriter, r *http.Request, c apiCall) {
	accs, err := c.db.Accounts()
	if err != nil {
		apiFail(w, err)
		return
	}
	out := []accountView{}
	for _, a := range accs {
		out = append(out, viewAccount(a))
	}
	apiOK(w, out)
}

func (s *Server) apiAccount(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		var a store.Account
		if a, err = s.opAccount(c.db, id); err == nil {
			apiOK(w, viewAccount(a))
			return
		}
	}
	apiFail(w, err)
}

type scopesView struct {
	Modify     bool   `json:"modify"`
	Settings   bool   `json:"settings"`
	ConsentURL string `json:"consent_url,omitempty"`
}

func (s *Server) apiScopes(w http.ResponseWriter, r *http.Request, c apiCall) {
	apiOK(w, scopesView{Modify: c.db.BoolSetting("gmail_modify", false), Settings: c.db.BoolSetting("gmail_settings", false)})
}

func (s *Server) apiSetScopes(w http.ResponseWriter, r *http.Request, c apiCall) {
	in := scopesView{Modify: c.db.BoolSetting("gmail_modify", false), Settings: c.db.BoolSetting("gmail_settings", false)}
	if err := decode(r, &in); err != nil {
		apiFail(w, err)
		return
	}
	path := s.opSetScopes(c.db, c.actor, in.Modify, in.Settings)
	in.ConsentURL = strings.TrimRight(s.RT.Cfg.PublicURL, "/") + path
	apiOK(w, in)
}

func (s *Server) apiAccountWatch(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		var a store.Account
		if a, err = s.opRenewWatch(r.Context(), c.db, c.actor, id); err == nil {
			apiOK(w, viewAccount(a))
			return
		}
	}
	apiFail(w, err)
}

type pauseInput struct {
	Paused *bool `json:"paused"`
}

func (in pauseInput) value() bool { return in.Paused == nil || *in.Paused }

func (s *Server) apiAccountPause(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in pauseInput
	id, err := pathID(r, "id")
	if err == nil {
		err = decode(r, &in)
	}
	if err == nil {
		err = s.opPauseAccount(c.db, c.actor, id, in.value())
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	a, _ := s.opAccount(c.db, id)
	apiOK(w, viewAccount(a))
}

func (s *Server) apiAccountDisconnect(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		err = s.opDisconnect(r.Context(), c.db, c.actor, id)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, map[string]any{"deleted": id})
}

type labelJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Server) apiLabels(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		var ls []labelView
		if ls, err = s.opLabels(r.Context(), c.db, id); err == nil {
			out := []labelJSON{}
			for _, l := range ls {
				out = append(out, labelJSON(l))
			}
			apiOK(w, out)
			return
		}
	}
	apiFail(w, err)
}

func (s *Server) apiCreateLabel(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in struct {
		Name string `json:"name"`
	}
	id, err := pathID(r, "id")
	if err == nil {
		err = decode(r, &in)
	}
	if err == nil {
		var l labelView
		if l, err = s.opCreateLabel(r.Context(), c.db, c.actor, id, in.Name); err == nil {
			apiCreated(w, labelJSON(l))
			return
		}
	}
	apiFail(w, err)
}

type filterJSON struct {
	ID      string `json:"id"`
	From    string `json:"from,omitempty"`
	Subject string `json:"subject,omitempty"`
	Query   string `json:"query,omitempty"`
	Label   string `json:"label,omitempty"`
}

func (s *Server) apiFilters(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		var fs []gmailx.Filter
		if fs, err = s.opFilters(r.Context(), c.db, id); err == nil {
			out := []filterJSON{}
			for _, f := range fs {
				out = append(out, filterJSON{ID: f.ID, From: f.From, Subject: f.Subject, Query: f.Query, Label: f.AddLabel})
			}
			apiOK(w, out)
			return
		}
	}
	apiFail(w, err)
}

func (s *Server) apiCreateFilter(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in filterJSON
	id, err := pathID(r, "id")
	if err == nil {
		err = decode(r, &in)
	}
	if err == nil {
		err = s.opCreateFilter(r.Context(), c.db, c.actor, id, in.From, in.Subject, in.Label)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiCreated(w, in)
}

func (s *Server) apiDeleteFilter(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		err = s.opDeleteFilter(r.Context(), c.db, c.actor, id, r.PathValue("filter"))
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, map[string]any{"deleted": r.PathValue("filter")})
}

// routes

func (s *Server) apiRouteList(w http.ResponseWriter, r *http.Request, c apiCall) {
	routes, err := c.db.Routes()
	if err != nil {
		apiFail(w, err)
		return
	}
	out := []routeView{}
	for _, rt := range routes {
		out = append(out, viewRoute(rt))
	}
	apiOK(w, out)
}

func (s *Server) apiRouteGet(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		var rt store.Route
		if rt, err = s.opRoute(c.db, id); err == nil {
			apiOK(w, viewRoute(rt))
			return
		}
	}
	apiFail(w, err)
}

func (s *Server) apiRouteCreate(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in routeInput
	if err := decode(r, &in); err != nil {
		apiFail(w, err)
		return
	}
	rt, err := in.apply(c.db, store.Route{Enabled: true})
	if err == nil {
		rt, err = s.opSaveRoute(c.db, c.actor, rt)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiCreated(w, viewRoute(rt))
}

func (s *Server) apiRouteUpdate(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in routeInput
	var rt store.Route
	id, err := pathID(r, "id")
	if err == nil {
		err = decode(r, &in)
	}
	if err == nil {
		rt, err = s.opRoute(c.db, id)
	}
	if err == nil {
		rt, err = in.apply(c.db, rt)
	}
	if err == nil {
		rt, err = s.opSaveRoute(c.db, c.actor, rt)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, viewRoute(rt))
}

func (s *Server) apiRouteDelete(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		err = s.opDeleteRoute(c.db, c.actor, id)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, map[string]any{"deleted": id})
}

func (s *Server) apiRouteOrder(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in struct {
		IDs []int64 `json:"ids"`
	}
	err := decode(r, &in)
	if err == nil {
		err = s.opReorderRoutes(c.db, c.actor, in.IDs)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	s.apiRouteList(w, r, c)
}

func (s *Server) apiRouteMove(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in struct {
		Dir string `json:"dir"`
	}
	id, err := pathID(r, "id")
	if err == nil {
		err = decode(r, &in)
	}
	if err == nil && in.Dir != "up" && in.Dir != "down" {
		err = errBad(`dir is "up" or "down".`, "dir")
	}
	if err == nil {
		err = s.opMoveRoute(c.db, c.actor, id, in.Dir)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	s.apiRouteList(w, r, c)
}

func (s *Server) apiRouteField(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in struct {
		Values []string `json:"values"`
		Value  *string  `json:"value"`
	}
	id, err := pathID(r, "id")
	if err == nil {
		err = decode(r, &in)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	value := strings.Join(in.Values, "\n")
	if in.Value != nil {
		value = *in.Value
	}
	field := r.PathValue("field")
	values, err := s.opRouteField(c.db, c.actor, id, field, value)
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, map[string]any{"field": field, "values": values})
}

func (s *Server) apiRoutePreview(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in routeInput
	var in2 struct {
		ID int64 `json:"id"`
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		apiFail(w, errBad("The request body is too large.", ""))
		return
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			apiFail(w, errBad("The request body is not valid JSON.", ""))
			return
		}
		_ = json.Unmarshal(raw, &in2)
	}
	base := store.Route{Enabled: true}
	if in2.ID != 0 {
		if base, err = s.opRoute(c.db, in2.ID); err != nil {
			apiFail(w, err)
			return
		}
	}
	rt, err := in.apply(c.db, base)
	if err == nil {
		rt, err = checkRoute(c.db, rt)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	prev, err := s.opPreview(r.Context(), c.db, rt, in.N)
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, viewPreviews(prev))
}

func (s *Server) apiRouteSimulate(w http.ResponseWriter, r *http.Request, c apiCall) {
	prev, err := s.opSimulate(r.Context(), c.db, atoi(r.URL.Query().Get("n")))
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, viewPreviews(prev))
}

// targets

func (s *Server) apiTargetList(w http.ResponseWriter, r *http.Request, c apiCall) {
	ts, err := c.db.Targets()
	if err != nil {
		apiFail(w, err)
		return
	}
	out := []targetView{}
	for _, t := range ts {
		out = append(out, viewTarget(t))
	}
	apiOK(w, out)
}

func (s *Server) apiTargetGet(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		var t store.Target
		if t, err = s.opTarget(c.db, id); err == nil {
			apiOK(w, viewTarget(t))
			return
		}
	}
	apiFail(w, err)
}

func (s *Server) apiTargetCreate(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in targetInput
	if err := decode(r, &in); err != nil {
		apiFail(w, err)
		return
	}
	secret := ""
	if in.Secret != nil {
		secret = *in.Secret
	}
	t, err := s.opSaveTarget(c.db, c.actor, in.apply(store.Target{AuthMode: "bearer"}), secret, false)
	if err != nil {
		apiFail(w, err)
		return
	}
	apiCreated(w, viewTarget(t))
}

func (s *Server) apiTargetUpdate(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in targetInput
	var t store.Target
	id, err := pathID(r, "id")
	if err == nil {
		err = decode(r, &in)
	}
	if err == nil {
		t, err = s.opTarget(c.db, id)
	}
	if err == nil {
		secret := ""
		if in.Secret != nil {
			secret = *in.Secret
		}
		t, err = s.opSaveTarget(c.db, c.actor, in.apply(t), secret, in.ClearSecret)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, viewTarget(t))
}

func (s *Server) apiTargetDelete(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		err = s.opDeleteTarget(c.db, c.actor, id)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, map[string]any{"deleted": id})
}

func (s *Server) apiTargetPause(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in pauseInput
	id, err := pathID(r, "id")
	if err == nil {
		err = decode(r, &in)
	}
	if err == nil {
		err = s.opPauseTarget(c.db, c.actor, id, in.value())
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	t, _ := s.opTarget(c.db, id)
	apiOK(w, viewTarget(t))
}

func (s *Server) apiTargetTest(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		var d store.Delivery
		if d, err = s.opTestTarget(r.Context(), c.db, c.actor, id); err == nil {
			apiOK(w, viewDelivery(d, true))
			return
		}
	}
	apiFail(w, err)
}

// deliveries

func (s *Server) apiDeliveryList(w http.ResponseWriter, r *http.Request, c apiCall) {
	q := r.URL.Query()
	dels, err := c.db.Deliveries(q.Get("status"), q.Get("route"), q.Get("target"), atoi(q.Get("limit")))
	if err != nil {
		apiFail(w, err)
		return
	}
	out := []deliveryView{}
	for _, d := range dels {
		out = append(out, viewDelivery(d, false))
	}
	apiOK(w, out)
}

func (s *Server) apiDeliveryGet(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		var d store.Delivery
		if d, err = s.opDelivery(c.db, id); err == nil {
			apiOK(w, viewDelivery(d, true))
			return
		}
	}
	apiFail(w, err)
}

func (s *Server) apiRequeue(replay bool) apiFunc {
	return func(w http.ResponseWriter, r *http.Request, c apiCall) {
		id, err := pathID(r, "id")
		if err == nil {
			err = s.opRequeue(c.db, c.actor, id, replay)
		}
		if err != nil {
			apiFail(w, err)
			return
		}
		d, _ := s.opDelivery(c.db, id)
		apiOK(w, viewDelivery(d, false))
	}
}

func (s *Server) apiDeliveryRetry(w http.ResponseWriter, r *http.Request, c apiCall) {
	s.apiRequeue(false)(w, r, c)
}

func (s *Server) apiDeliveryReplay(w http.ResponseWriter, r *http.Request, c apiCall) {
	s.apiRequeue(true)(w, r, c)
}

func (s *Server) apiDeliveryWindow(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in struct {
		Route  string `json:"route"`
		Target string `json:"target"`
		Since  string `json:"since"`
		Until  string `json:"until"`
	}
	if err := decode(r, &in); err != nil {
		apiFail(w, err)
		return
	}
	loc := s.locOf(r)
	n, err := s.opReplayWindow(c.db, c.actor, in.Route, in.Target, parseTime(in.Since, loc), parseTime(in.Until, loc))
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, map[string]int{"requeued": n})
}

// events, settings, export, import, audit

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request, c apiCall) {
	type ev struct {
		Time string `json:"time"`
		Kind string `json:"kind"`
		Text string `json:"text"`
	}
	out := []ev{}
	for _, e := range s.RT.Feed.BacklogFor(c.db.UserID()) {
		out = append(out, ev{Time: e.Time.UTC().Format(time.RFC3339), Kind: e.Kind, Text: e.Text})
	}
	apiOK(w, out)
}

// settingsJSON gives booleans and numbers their JSON types.
func settingsJSON(kv map[string]string) map[string]any {
	out := map[string]any{}
	for _, k := range settingKeys {
		v := kv[k.Key]
		switch {
		case k.Bool:
			out[k.Key] = v == "1"
		case k.Key == "timezone" || k.Key == "label_prefix":
			out[k.Key] = v
		default:
			n, _ := strconv.Atoi(v)
			out[k.Key] = n
		}
	}
	return out
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request, c apiCall) {
	apiOK(w, settingsJSON(s.opSettings(c.db)))
}

func (s *Server) apiSettingsSave(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in map[string]any
	if err := decode(r, &in); err != nil {
		apiFail(w, err)
		return
	}
	kv := map[string]string{}
	for k, v := range in {
		known, isBool := settingKnown(k)
		if !known {
			apiFail(w, errBad("Unknown setting "+k+".", k))
			return
		}
		switch x := v.(type) {
		case bool:
			kv[k] = boolFlag(x)
		case float64:
			if isBool {
				kv[k] = boolFlag(x != 0)
			} else {
				kv[k] = strconv.FormatInt(int64(x), 10)
			}
		case string:
			if isBool {
				kv[k] = boolFlag(x == "1" || strings.EqualFold(x, "true") || strings.EqualFold(x, "on"))
			} else {
				kv[k] = x
			}
		default:
			apiFail(w, errBad("Bad value for "+k+".", k))
			return
		}
	}
	if err := s.opSaveSettings(c.db, c.actor, kv); err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, settingsJSON(s.opSettings(c.db)))
}

func (s *Server) apiExport(w http.ResponseWriter, r *http.Request, c apiCall) {
	raw, err := bundle.Export(c.db, r.Header.Get("X-Ghook-Passphrase"))
	if err != nil {
		apiFail(w, errBad("Could not export.", ""))
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			apiFail(w, err)
			return
		}
		apiOK(w, doc)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="ghook.yaml"`)
	_, _ = w.Write(raw)
}

func (s *Server) apiImport(w http.ResponseWriter, r *http.Request, c apiCall) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		apiFail(w, errBad("The bundle is too large.", ""))
		return
	}
	if strings.TrimSpace(string(raw)) == "" {
		apiFail(w, errBad("Send a YAML or JSON bundle as the body.", ""))
		return
	}
	msg, err := bundle.Import(c.db, raw, r.Header.Get("X-Ghook-Passphrase"))
	if err != nil {
		apiFail(w, errBad(safeErr(err), ""))
		return
	}
	_ = c.db.Audit(c.actor, "import", msg)
	apiOK(w, map[string]string{"result": msg})
}

func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request, c apiCall) {
	rows, err := c.db.Audits(atoi(r.URL.Query().Get("limit")))
	if err != nil {
		apiFail(w, err)
		return
	}
	type row struct {
		ID     int64  `json:"id"`
		At     string `json:"at"`
		Actor  string `json:"actor"`
		Action string `json:"action"`
		Detail string `json:"detail"`
	}
	out := []row{}
	for _, a := range rows {
		out = append(out, row{a.ID, iso(a.At), a.Actor, a.Action, a.Detail})
	}
	apiOK(w, out)
}

// account

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request, c apiCall) {
	scope := "read-only"
	if c.key.CanWrite() {
		scope = "read-write"
	}
	apiOK(w, map[string]any{
		"email": c.user.Email, "name": c.user.Name, "created_at": iso(c.user.CreatedAt), "last_login": iso(c.user.LastLogin),
		"timezone": c.db.Setting("timezone", "UTC"), "key": map[string]string{"name": c.key.Name, "prefix": c.key.Display(), "scope": scope},
	})
}

func (s *Server) apiMeDelete(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if err := decode(r, &in); err != nil {
		apiFail(w, err)
		return
	}
	if !in.Confirm {
		apiFail(w, errBad(`Send {"confirm":true} to delete the account and all its data.`, "confirm"))
		return
	}
	if err := s.opDeleteUser(r.Context(), c.db); err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, map[string]bool{"deleted": true})
}

func (s *Server) apiKeyList(w http.ResponseWriter, r *http.Request, c apiCall) {
	keys, err := c.db.APIKeys()
	if err != nil {
		apiFail(w, err)
		return
	}
	out := []keyView{}
	for _, k := range keys {
		out = append(out, viewKey(k))
	}
	apiOK(w, out)
}

func (s *Server) apiKeyCreate(w http.ResponseWriter, r *http.Request, c apiCall) {
	var in struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
	}
	if err := decode(r, &in); err != nil {
		apiFail(w, err)
		return
	}
	k, token, err := s.opCreateKey(c.db, c.actor, in.Name, in.Scope)
	if err != nil {
		apiFail(w, err)
		return
	}
	v := viewKey(k)
	v.Token = token
	apiCreated(w, v)
}

func (s *Server) apiKeyRevoke(w http.ResponseWriter, r *http.Request, c apiCall) {
	id, err := pathID(r, "id")
	if err == nil {
		err = s.opRevokeKey(c.db, c.actor, id)
	}
	if err != nil {
		apiFail(w, err)
		return
	}
	apiOK(w, map[string]any{"revoked": id})
}
