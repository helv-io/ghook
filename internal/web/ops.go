package web

// Shared operations. The admin UI handlers and the JSON API both call these,
// so a change in behavior lands in one place.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/engine"
	"github.com/helv-io/ghook/internal/gmailx"
	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/pubsubx"
	"github.com/helv-io/ghook/internal/store"
)

// opError is a failure the caller can show: an HTTP status, a message and the form field it belongs to.
type opError struct {
	Status int
	Msg    string
	Field  string
}

func (e *opError) Error() string { return e.Msg }

func errBad(msg, field string) error {
	return &opError{Status: http.StatusBadRequest, Msg: msg, Field: field}
}
func errNotFound(msg string) error { return &opError{Status: http.StatusNotFound, Msg: msg} }
func errConflict(msg string) error { return &opError{Status: http.StatusConflict, Msg: msg} }
func errUpstream(msg string) error { return &opError{Status: http.StatusBadGateway, Msg: msg} }

// explain turns any error into a status, a message and a field.
func explain(err error) (int, string, string) {
	var oe *opError
	if errors.As(err, &oe) {
		return oe.Status, oe.Msg, oe.Field
	}
	var q store.ErrQuota
	if errors.As(err, &q) {
		return http.StatusConflict, q.Error(), ""
	}
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound, "Not found.", ""
	}
	msg := safeErr(err)
	return http.StatusInternalServerError, msg, fieldFor(msg)
}

func msgOf(err error) string { _, m, _ := explain(err); return m }

// ---- accounts ----

func (s *Server) opAccount(db *store.DB, id int64) (store.Account, error) {
	acc, ok, err := db.AccountByID(id)
	if err != nil {
		return acc, err
	}
	if !ok {
		return acc, errNotFound("Mailbox not found.")
	}
	return acc, nil
}

func (s *Server) opMailbox(ctx context.Context, db *store.DB, id int64) (store.Account, gmailx.Client, error) {
	acc, err := s.opAccount(db, id)
	if err != nil {
		return acc, nil, err
	}
	c, err := s.RT.Client(ctx, acc.Email)
	if err != nil {
		return acc, nil, errUpstream(safeErr(err))
	}
	return acc, c, nil
}

func (s *Server) opRenewWatch(ctx context.Context, db *store.DB, actor string, id int64) (store.Account, error) {
	acc, err := s.opAccount(db, id)
	if err != nil {
		return acc, err
	}
	if s.RT == nil || !s.RT.Cfg.PubSubReady() {
		return acc, errConflict("Pub/Sub is not configured on this instance.")
	}
	c, err := s.RT.Client(ctx, acc.Email)
	if err != nil {
		return acc, errUpstream(safeErr(err))
	}
	hist, exp, err := c.Watch(ctx, pubsubx.TopicPath(s.RT.Cfg.PubSubProject, s.RT.Cfg.PubSubTopic))
	if err != nil {
		_ = db.SetWatch(acc.ID, acc.WatchExpiry, "", safeErr(err))
		s.RT.Feed.AddFor(acc.UserID, "error", "Watch renewal failed")
		return acc, errUpstream("Watch renewal failed.")
	}
	_ = db.SetWatch(acc.ID, exp.Unix(), hist, "")
	_ = db.Audit(actor, "watch.renew", acc.Email)
	s.RT.Feed.AddFor(acc.UserID, "watch", "Watch renewed")
	acc, _, _ = db.AccountByID(acc.ID)
	return acc, nil
}

func (s *Server) opPauseAccount(db *store.DB, actor string, id int64, disabled bool) error {
	if _, err := s.opAccount(db, id); err != nil {
		return err
	}
	if err := db.SetAccountDisabled(id, disabled); err != nil {
		return err
	}
	_ = db.Audit(actor, "account.pause", fmt.Sprintf("id %d paused=%v", id, disabled))
	return nil
}

func (s *Server) opDisconnect(ctx context.Context, db *store.DB, actor string, id int64) error {
	acc, err := s.opAccount(db, id)
	if err != nil {
		return err
	}
	if c, err := s.RT.Client(ctx, acc.Email); err == nil {
		_ = c.Stop(ctx)
	}
	if tok := acc.RefreshToken(); tok != "" {
		revokeGoogleToken(tok)
	}
	if err := db.DeleteAccount(id); err != nil {
		return err
	}
	_ = db.Audit(actor, "google.disconnect", acc.Email)
	return nil
}

// opSetScopes stores the optional Gmail scopes and returns the Google consent path that grants them.
func (s *Server) opSetScopes(db *store.DB, actor string, modify, settings bool) string {
	_ = db.SetSetting("gmail_modify", boolFlag(modify))
	_ = db.SetSetting("gmail_settings", boolFlag(settings))
	_ = db.Audit(actor, "google.scopes", "updated Gmail scopes")
	var q []string
	if modify {
		q = append(q, "modify=1")
	}
	if settings {
		q = append(q, "settings=1")
	}
	if len(q) == 0 {
		return "/auth/google"
	}
	return "/auth/google?" + strings.Join(q, "&")
}

func (s *Server) opLabels(ctx context.Context, db *store.DB, accountID int64) ([]labelView, error) {
	_, c, err := s.opMailbox(ctx, db, accountID)
	if err != nil {
		return nil, err
	}
	ls, err := c.Labels(ctx)
	if err != nil {
		return nil, errUpstream(safeErr(err))
	}
	out := []labelView{}
	for _, l := range ls {
		out = append(out, labelView{ID: l.ID, Name: l.Name})
	}
	return out, nil
}

func (s *Server) opCreateLabel(ctx context.Context, db *store.DB, actor string, accountID int64, name string) (labelView, error) {
	acc, c, err := s.opMailbox(ctx, db, accountID)
	if err != nil {
		return labelView{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return labelView{}, errBad("Enter a label name.", "name")
	}
	l, err := c.CreateLabel(ctx, name)
	if err != nil {
		return labelView{}, errUpstream("Could not create the label. gmail.modify has to be granted.")
	}
	_ = db.Audit(actor, "label.create", acc.Email+" "+name)
	return labelView{ID: l.ID, Name: l.Name}, nil
}

func (s *Server) opCreateFilter(ctx context.Context, db *store.DB, actor string, accountID int64, from, subject, label string) error {
	acc, c, err := s.opMailbox(ctx, db, accountID)
	if err != nil {
		return err
	}
	label = strings.TrimSpace(label)
	labels, err := c.Labels(ctx)
	if err != nil {
		return errUpstream("Could not list labels.")
	}
	var id string
	for _, l := range labels {
		if strings.EqualFold(l.Name, label) {
			id = l.ID
		}
	}
	if id == "" {
		return errBad("That label does not exist yet.", "label")
	}
	if err := c.CreateFilter(ctx, gmailx.Filter{From: from, Subject: subject, AddLabel: id}); err != nil {
		return errUpstream("Could not create the filter. gmail.settings.basic has to be granted.")
	}
	_ = db.Audit(actor, "filter.create", acc.Email+" "+label)
	return nil
}

func (s *Server) opFilters(ctx context.Context, db *store.DB, accountID int64) ([]gmailx.Filter, error) {
	_, c, err := s.opMailbox(ctx, db, accountID)
	if err != nil {
		return nil, err
	}
	fs, err := c.Filters(ctx)
	if err != nil {
		return nil, errUpstream("Could not list filters. gmail.settings.basic has to be granted.")
	}
	return fs, nil
}

func (s *Server) opDeleteFilter(ctx context.Context, db *store.DB, actor string, accountID int64, id string) error {
	acc, c, err := s.opMailbox(ctx, db, accountID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return errBad("Missing filter id.", "id")
	}
	if err := c.DeleteFilter(ctx, id); err != nil {
		return errUpstream("Could not delete the filter.")
	}
	_ = db.Audit(actor, "filter.delete", acc.Email+" "+id)
	return nil
}

// ---- routes ----

// checkRoute validates a route and confirms its target belongs to this user.
func checkRoute(db *store.DB, rt store.Route) (store.Route, error) {
	rt.Name = strings.TrimSpace(rt.Name)
	rt.Spec = rt.Spec.Normalize()
	if rt.Name == "" {
		return rt, errBad("A route needs a name.", "name")
	}
	if rt.TargetID == 0 {
		return rt, errBad("Pick a target.", "target_id")
	}
	if err := rt.Spec.Validate(); err != nil {
		return rt, errBad("Subject regex: "+safeErr(err), "subject")
	}
	if db != nil {
		tg, ok, err := db.TargetByID(rt.TargetID, false)
		if err != nil {
			return rt, err
		}
		if !ok {
			return rt, errBad("Pick a target.", "target_id")
		}
		rt.TargetName = tg.Name
	}
	return rt, nil
}

func (s *Server) opSaveRoute(db *store.DB, actor string, rt store.Route) (store.Route, error) {
	rt, err := checkRoute(db, rt)
	if err != nil {
		return rt, err
	}
	if rt.ID != 0 {
		if _, ok, err := db.RouteByID(rt.ID); err != nil {
			return rt, err
		} else if !ok {
			return rt, errNotFound("Route not found.")
		}
	} else if db.RouteCount() >= s.RT.Cfg.MaxRoutes {
		return rt, store.ErrQuota{Kind: "routes", Max: s.RT.Cfg.MaxRoutes}
	}
	saved, err := db.SaveRoute(rt)
	if err != nil {
		return rt, errBad(safeErr(err), fieldFor(safeErr(err)))
	}
	_ = db.Audit(actor, "route.save", saved.Name)
	return saved, nil
}

func (s *Server) opRoute(db *store.DB, id int64) (store.Route, error) {
	rt, ok, err := db.RouteByID(id)
	if err != nil {
		return rt, err
	}
	if !ok {
		return rt, errNotFound("Route not found.")
	}
	return rt, nil
}

func (s *Server) opDeleteRoute(db *store.DB, actor string, id int64) error {
	rt, err := s.opRoute(db, id)
	if err != nil {
		return err
	}
	if err := db.DeleteRoute(id); err != nil {
		return err
	}
	_ = db.Audit(actor, "route.delete", rt.Name)
	return nil
}

func (s *Server) opReorderRoutes(db *store.DB, actor string, ids []int64) error {
	if len(ids) == 0 {
		return errBad("Nothing to reorder.", "id")
	}
	if err := db.ReorderRoutes(ids); err != nil {
		return err
	}
	_ = db.Audit(actor, "route.reorder", fmt.Sprintf("%d routes", len(ids)))
	return nil
}

// opMoveRoute swaps a route with its neighbor. dir is "up" or "down". Moving past an end is a no-op.
func (s *Server) opMoveRoute(db *store.DB, actor string, id int64, dir string) error {
	routes, err := db.Routes()
	if err != nil {
		return err
	}
	idx := -1
	for i, rt := range routes {
		if rt.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return errNotFound("Route not found.")
	}
	swap := idx - 1
	if dir == "down" {
		swap = idx + 1
	}
	if swap < 0 || swap >= len(routes) {
		return nil
	}
	routes[idx], routes[swap] = routes[swap], routes[idx]
	ids := make([]int64, 0, len(routes))
	for _, rt := range routes {
		ids = append(ids, rt.ID)
	}
	if err := db.ReorderRoutes(ids); err != nil {
		return err
	}
	_ = db.Audit(actor, "route.reorder", "moved one route")
	return nil
}

// opRouteField saves one filter field and returns its stored values (sorted, deduped).
func (s *Server) opRouteField(db *store.DB, actor string, id int64, field, value string) ([]string, error) {
	rt, err := s.opRoute(db, id)
	if err != nil {
		return nil, err
	}
	spec, ok := rt.Spec.WithField(field, value)
	if !ok {
		return nil, errBad("That field is edited on the route page.", field)
	}
	if err := spec.Validate(); err != nil {
		return nil, errBad("Subject regex: "+safeErr(err), field)
	}
	rt.Spec = spec
	saved, err := db.SaveRoute(rt)
	if err != nil {
		return nil, errBad(safeErr(err), field)
	}
	_ = db.Audit(actor, "route.save", saved.Name)
	return saved.Spec.Field(field), nil
}

func (s *Server) engineFor(db *store.DB) engine.Engine {
	eng := *s.RT.Engine
	eng.DB = db
	return eng
}

// opPreview runs the saved rules with rt in place (or appended) over recent mail.
func (s *Server) opPreview(ctx context.Context, db *store.DB, rt store.Route, n int) ([]engine.Preview, error) {
	if tg, ok, _ := db.TargetByID(rt.TargetID, false); ok {
		rt.TargetName = tg.Name
	}
	saved, _ := db.Routes()
	var rules []match.Route
	replaced := false
	for _, existing := range saved {
		if rt.ID != 0 && existing.ID == rt.ID {
			rules = append(rules, rt.AsMatch())
			replaced = true
			continue
		}
		rules = append(rules, existing.AsMatch())
	}
	if !replaced {
		rules = append(rules, rt.AsMatch())
	}
	if n <= 0 {
		n = 20
	}
	eng := s.engineFor(db)
	return eng.Preview(ctx, rules, n)
}

// opSimulate runs the saved rules over the last n messages.
func (s *Server) opSimulate(ctx context.Context, db *store.DB, n int) ([]engine.Preview, error) {
	routes, _ := db.Routes()
	var rules []match.Route
	for _, rt := range routes {
		rules = append(rules, rt.AsMatch())
	}
	if n <= 0 {
		n = 20
	}
	eng := s.engineFor(db)
	return eng.Preview(ctx, rules, n)
}

// ---- targets ----

func (s *Server) opTarget(db *store.DB, id int64) (store.Target, error) {
	t, ok, err := db.TargetByID(id, false)
	if err != nil {
		return t, err
	}
	if !ok {
		return t, errNotFound("Target not found.")
	}
	return t, nil
}

func (s *Server) opSaveTarget(db *store.DB, actor string, t store.Target, secret string, clearSecret bool) (store.Target, error) {
	t.Name, t.URL = strings.TrimSpace(t.Name), strings.TrimSpace(t.URL)
	t.PayloadPubKey = strings.TrimSpace(t.PayloadPubKey)
	if t.Name == "" || t.URL == "" {
		field := "name"
		if t.Name != "" {
			field = "url"
		}
		return t, errBad("A target needs a name and a webhook URL.", field)
	}
	if !strings.HasPrefix(t.URL, "https://") && !strings.HasPrefix(t.URL, "http://") {
		return t, errBad("The URL must be http or https.", "url")
	}
	if t.ID != 0 {
		if _, err := s.opTarget(db, t.ID); err != nil {
			return t, err
		}
	} else if db.TargetCount() >= s.RT.Cfg.MaxTargets {
		return t, store.ErrQuota{Kind: "targets", Max: s.RT.Cfg.MaxTargets}
	}
	saved, err := db.SaveTarget(t, secret, clearSecret)
	if err != nil {
		return t, errBad(safeErr(err), fieldFor(safeErr(err)))
	}
	_ = db.Audit(actor, "target.save", saved.Name)
	return saved, nil
}

func (s *Server) opDeleteTarget(db *store.DB, actor string, id int64) error {
	t, err := s.opTarget(db, id)
	if err != nil {
		return err
	}
	if err := db.DeleteTarget(id); err != nil {
		return errConflict(safeErr(err))
	}
	_ = db.Audit(actor, "target.delete", t.Name)
	return nil
}

func (s *Server) opPauseTarget(db *store.DB, actor string, id int64, paused bool) error {
	if _, err := s.opTarget(db, id); err != nil {
		return err
	}
	if err := db.SetTargetPaused(id, paused); err != nil {
		return err
	}
	_ = db.Audit(actor, "target.pause", fmt.Sprintf("id %d paused=%v", id, paused))
	return nil
}

func (s *Server) opTestTarget(ctx context.Context, db *store.DB, actor string, id int64) (store.Delivery, error) {
	if _, err := s.opTarget(db, id); err != nil {
		return store.Delivery{}, err
	}
	d, err := s.RT.Worker.SendTest(ctx, db, id)
	if err != nil {
		return d, errUpstream(safeErr(err))
	}
	_ = db.Audit(actor, "target.test", d.TargetName)
	return d, nil
}

// ---- deliveries ----

func (s *Server) opDelivery(db *store.DB, id int64) (store.Delivery, error) {
	d, ok, err := db.DeliveryByID(id)
	if err != nil {
		return d, err
	}
	if !ok {
		return d, errNotFound("Delivery not found.")
	}
	return d, nil
}

// opRequeue retries (same delivery id) or replays (new delivery id) one delivery.
func (s *Server) opRequeue(db *store.DB, actor string, id int64, replay bool) error {
	if _, err := s.opDelivery(db, id); err != nil {
		return err
	}
	if err := db.Replay(id, replay); err != nil {
		return err
	}
	action := "delivery.retry"
	if replay {
		action = "delivery.replay"
	}
	_ = db.Audit(actor, action, strconv.FormatInt(id, 10))
	return nil
}

func (s *Server) opReplayWindow(db *store.DB, actor, route, target string, since, until int64) (int, error) {
	n, err := db.ReplayWindow(strings.TrimSpace(route), strings.TrimSpace(target), since, until)
	if err != nil {
		return 0, err
	}
	_ = db.Audit(actor, "delivery.replay.window", fmt.Sprintf("%d", n))
	return n, nil
}

// ---- settings ----

// settingKeys are the user settings, in form order, with their defaults.
var settingKeys = []struct {
	Key, Def string
	Bool     bool
}{
	{"timezone", "UTC", false},
	{"notify_target", "0", false},
	{"notify_dead", "1", true},
	{"notify_watch", "1", true},
	{"testing_mode", "0", true},
	{"retention_days", "30", false},
	{"retain_bodies", "0", true},
	{"retry_max_attempts", "8", false},
	{"retry_max_hours", "24", false},
	{"retry_base_seconds", "30", false},
	{"label_convention", "1", true},
	{"label_prefix", match.DefaultPrefix, false},
	{"catchup_minutes", "30", false},
	{"resync_days", "2", false},
}

func settingKnown(key string) (bool, bool) {
	for _, k := range settingKeys {
		if k.Key == key {
			return true, k.Bool
		}
	}
	return false, false
}

// opSettings returns every user setting as a string.
func (s *Server) opSettings(db *store.DB) map[string]string {
	out := map[string]string{}
	for _, k := range settingKeys {
		out[k.Key] = db.Setting(k.Key, k.Def)
	}
	return out
}

// opSaveSettings validates and stores the given settings. Keys not given keep their value.
func (s *Server) opSaveSettings(db *store.DB, actor string, kv map[string]string) error {
	for key := range kv {
		if ok, _ := settingKnown(key); !ok {
			return errBad("Unknown setting "+key+".", key)
		}
	}
	if tz, ok := kv["timezone"]; ok {
		tz = strings.TrimSpace(tz)
		if tz == "" {
			tz = "UTC"
		}
		if _, err := time.LoadLocation(tz); err != nil {
			return errBad("Unknown timezone.", "timezone")
		}
		kv["timezone"] = tz
	}
	if p, ok := kv["label_prefix"]; ok {
		p = strings.TrimSpace(p)
		if strings.EqualFold(p, match.DefaultPrefix) {
			p = match.DefaultPrefix
		}
		kv["label_prefix"] = p
	}
	if v, ok := kv["notify_target"]; ok && v != "" && v != "0" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return errBad("Pick a target.", "notify_target")
		}
		if _, err := s.opTarget(db, id); err != nil {
			return errBad("Pick a target.", "notify_target")
		}
	}
	for _, k := range settingKeys {
		v, ok := kv[k.Key]
		if !ok {
			continue
		}
		if !k.Bool && k.Key != "timezone" && k.Key != "label_prefix" && v != "" {
			if _, err := strconv.Atoi(strings.TrimSpace(v)); err != nil {
				return errBad("Enter a number.", k.Key)
			}
		}
		if err := db.SetSetting(k.Key, v); err != nil {
			return &opError{Status: http.StatusInternalServerError, Msg: "Could not save settings.", Field: k.Key}
		}
	}
	_ = db.Audit(actor, "settings.save", "updated settings")
	return nil
}

// ---- account ----

// opDeleteUser stops every watch, revokes Google tokens and crypto-shreds the user's data.
func (s *Server) opDeleteUser(ctx context.Context, db *store.DB) error {
	uid := db.UserID()
	accs, _ := db.Accounts()
	for _, a := range accs {
		if c, err := s.RT.Client(ctx, a.Email); err == nil {
			_ = c.Stop(ctx)
		}
		if tok := a.RefreshToken(); tok != "" {
			revokeGoogleToken(tok)
		}
	}
	if err := s.RT.DB.Unscoped().DeleteUserData(uid); err != nil {
		return &opError{Status: http.StatusInternalServerError, Msg: "Could not delete the account."}
	}
	return nil
}

func (s *Server) opCreateKey(db *store.DB, actor, name, scope string) (store.APIKey, string, error) {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "", "read", "read-only", "readonly", "ro":
		scope = store.ScopeRead
	case "write", "read-write", "readwrite", "rw":
		scope = store.ScopeWrite
	default:
		return store.APIKey{}, "", errBad("Scope is read or write.", "scope")
	}
	if strings.TrimSpace(name) == "" {
		return store.APIKey{}, "", errBad("Name the key.", "name")
	}
	k, token, err := db.CreateAPIKey(name, scope)
	if err != nil {
		return k, "", err
	}
	_ = db.Audit(actor, "apikey.create", k.Display()+" "+k.Name+" "+k.Scope)
	return k, token, nil
}

func (s *Server) opRevokeKey(db *store.DB, actor string, id int64) error {
	k, err := db.RevokeAPIKey(id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("Key not found.")
	}
	if err != nil {
		return err
	}
	_ = db.Audit(actor, "apikey.revoke", k.Display()+" "+k.Name)
	return nil
}

func boolFlag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
