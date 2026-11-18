package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/bundle"
	"github.com/helv-io/ghook/internal/engine"
	"github.com/helv-io/ghook/internal/gmailx"
	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/pubsubx"
	"github.com/helv-io/ghook/internal/store"
	"google.golang.org/api/idtoken"
)

func (s *Server) verifyPubSub(w http.ResponseWriter, r *http.Request, _ page) {
	api, ps, err := s.pubsubAPI(r)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", safeErr(err))
		return
	}
	topic := pubsubx.TopicPath(ps.Project, ps.Topic)
	sub := pubsubx.SubPath(ps.Project, ps.Subscription)
	tOK, tErr := api.Exists(r.Context(), topic)
	sOK, sErr := api.Exists(r.Context(), sub)
	msg := fmt.Sprintf("topic %s, subscription %s", yesno(tOK, tErr), yesno(sOK, sErr))
	kind := "ok"
	if tErr != nil || sErr != nil || !tOK || !sOK {
		kind = "warn"
	}
	s.redirect(w, r, "/admin/accounts", kind, msg)
}

func yesno(ok bool, err error) string {
	if err != nil {
		return "error"
	}
	if ok {
		return "exists"
	}
	return "missing"
}

func (s *Server) createPubSub(w http.ResponseWriter, r *http.Request, p page) {
	api, ps, err := s.pubsubAPI(r)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", safeErr(err))
		return
	}
	topic := pubsubx.TopicPath(ps.Project, ps.Topic)
	sub := pubsubx.SubPath(ps.Project, ps.Subscription)
	if err := api.CreateTopic(r.Context(), topic); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not create the topic.")
		return
	}
	if err := api.CreateSubscription(r.Context(), sub, topic); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not create the subscription.")
		return
	}
	s.db(r).Audit(p.User, "pubsub.create", topic)
	s.redirect(w, r, "/admin/accounts", "ok", "Topic and pull subscription are ready.")
}

func (s *Server) grantPubSub(w http.ResponseWriter, r *http.Request, p page) {
	api, ps, err := s.pubsubAPI(r)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", safeErr(err))
		return
	}
	topic := pubsubx.TopicPath(ps.Project, ps.Topic)
	if err := api.GrantGmailPublish(r.Context(), topic); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not grant publish. The credentials need Pub/Sub admin on the topic.")
		return
	}
	s.db(r).Audit(p.User, "pubsub.grant", topic)
	s.redirect(w, r, "/admin/accounts", "ok", "Gmail can publish to the topic.")
}

func (s *Server) mailbox(w http.ResponseWriter, r *http.Request) (store.Account, gmailx.Client, bool) {
	id, _ := strconv.ParseInt(r.FormValue("account"), 10, 64)
	acc, ok, _ := s.db(r).AccountByID(id)
	if !ok {
		s.redirect(w, r, "/admin/accounts", "bad", "Pick a mailbox.")
		return store.Account{}, nil, false
	}
	c, err := s.RT.Client(r.Context(), acc.Email)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", safeErr(err))
		return store.Account{}, nil, false
	}
	return acc, c, true
}

func (s *Server) createLabel(w http.ResponseWriter, r *http.Request, p page) {
	acc, c, ok := s.mailbox(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.redirect(w, r, "/admin/accounts", "bad", "Enter a label name.")
		return
	}
	if _, err := c.CreateLabel(r.Context(), name); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not create the label. gmail.modify has to be granted.")
		return
	}
	s.db(r).Audit(p.User, "label.create", acc.Email+" "+name)
	s.redirect(w, r, "/admin/accounts?labels="+strconv.FormatInt(acc.ID, 10), "ok", "Label created.")
}

func (s *Server) createFilter(w http.ResponseWriter, r *http.Request, p page) {
	acc, c, ok := s.mailbox(w, r)
	if !ok {
		return
	}
	labelName := strings.TrimSpace(r.FormValue("label"))
	labels, err := c.Labels(r.Context())
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not list labels.")
		return
	}
	var id string
	for _, l := range labels {
		if strings.EqualFold(l.Name, labelName) {
			id = l.ID
		}
	}
	if id == "" {
		s.redirect(w, r, "/admin/accounts", "bad", "That label does not exist yet.")
		return
	}
	if err := c.CreateFilter(r.Context(), gmailx.Filter{From: r.FormValue("from"), Subject: r.FormValue("subject"), AddLabel: id}); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not create the filter. gmail.settings.basic has to be granted.")
		return
	}
	s.db(r).Audit(p.User, "filter.create", acc.Email+" "+labelName)
	s.redirect(w, r, "/admin/accounts", "ok", "Filter created.")
}

func (s *Server) routes(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "routes", "routes"
	p.Routes, _ = s.db(r).Routes()
	s.render(w, "routes", p)
}

func (s *Server) routeEdit(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "route", "routes"
	p.Targets, _ = s.db(r).Targets()
	p.Categories = []string{"primary", "social", "promotions", "updates", "forums"}
	p.LabelPrefix = s.db(r).Setting("label_prefix", "Ghook")
	p.IsNew = strings.HasSuffix(r.URL.Path, "/new")
	if !p.IsNew {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		rt, ok, _ := s.db(r).RouteByID(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		p.Route = rt
		p.Title = rt.Name
	} else {
		p.Route.Enabled = true
	}
	s.render(w, "route_edit", p)
}

func routeFrom(r *http.Request) (store.Route, error) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	tid, _ := strconv.ParseInt(r.FormValue("target_id"), 10, 64)
	rt := store.Route{
		ID: id, Name: strings.TrimSpace(r.FormValue("name")), TargetID: tid,
		Enabled: r.FormValue("enabled") == "1", Fallback: r.FormValue("fallback") == "1",
		Continue: r.FormValue("continue") == "1", ApplyLabel: r.FormValue("apply_label") == "1",
		Spec: match.Spec{
			Op: r.FormValue("op"), From: []string{r.FormValue("from")}, To: []string{r.FormValue("to")},
			Cc: []string{r.FormValue("cc")}, Subject: r.FormValue("subject"), Contains: r.FormValue("contains"),
			Labels: []string{r.FormValue("labels")}, Categories: r.Form["category"], Attachment: r.FormValue("attachment"),
		}.Normalize(),
	}
	if rt.Name == "" {
		return rt, fmt.Errorf("a route needs a name")
	}
	if rt.TargetID == 0 {
		return rt, fmt.Errorf("pick a target")
	}
	if err := rt.Spec.Validate(); err != nil {
		return rt, fmt.Errorf("subject regex: %s", safeErr(err))
	}
	return rt, nil
}

func (s *Server) routeSave(w http.ResponseWriter, r *http.Request, p page) {
	rt, err := routeFrom(r)
	if err != nil {
		s.routeForm(w, r, p, rt, err.Error(), nil)
		return
	}
	saved, err := s.db(r).SaveRoute(rt)
	if err != nil {
		s.routeForm(w, r, p, rt, safeErr(err), nil)
		return
	}
	s.db(r).Audit(p.User, "route.save", saved.Name)
	s.redirect(w, r, "/admin/routes", "ok", "Route saved.")
}

func (s *Server) routeForm(w http.ResponseWriter, r *http.Request, p page, rt store.Route, err string, prev []engine.Preview) {
	p.Title, p.Nav = "route", "routes"
	p.Targets, _ = s.db(r).Targets()
	p.Categories = []string{"primary", "social", "promotions", "updates", "forums"}
	p.LabelPrefix = s.db(r).Setting("label_prefix", "Ghook")
	p.Route = rt
	p.IsNew = rt.ID == 0
	p.Err = err
	p.Previews = prev
	s.render(w, "route_edit", p)
}

func (s *Server) routePreview(w http.ResponseWriter, r *http.Request, p page) {
	rt, err := routeFrom(r)
	if err != nil {
		s.routeForm(w, r, p, rt, err.Error(), nil)
		return
	}
	if tg, ok, _ := s.db(r).TargetByID(rt.TargetID, false); ok {
		rt.TargetName = tg.Name
	}
	saved, _ := s.db(r).Routes()
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
	n := atoi(r.FormValue("n"))
	if n <= 0 {
		n = 20
	}
	eng := *s.RT.Engine
	eng.DB = s.db(r)
	prev, err := eng.Preview(r.Context(), rules, n)
	msg := ""
	if err != nil {
		msg = safeErr(err)
	}
	s.routeForm(w, r, p, rt, msg, prev)
}

func (s *Server) routeDelete(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	rt, _, _ := s.db(r).RouteByID(id)
	if err := s.db(r).DeleteRoute(id); err != nil {
		s.redirect(w, r, "/admin/routes", "bad", "Could not delete the route.")
		return
	}
	s.db(r).Audit(p.User, "route.delete", rt.Name)
	s.redirect(w, r, "/admin/routes", "ok", "Route deleted.")
}

func (s *Server) routeReorder(w http.ResponseWriter, r *http.Request, p page) {
	var ids []int64
	for _, raw := range r.Form["id"] {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		http.Error(w, "nothing to reorder", http.StatusBadRequest)
		return
	}
	if err := s.db(r).ReorderRoutes(ids); err != nil {
		http.Error(w, "could not save the order", http.StatusInternalServerError)
		return
	}
	s.db(r).Audit(p.User, "route.reorder", fmt.Sprintf("%d routes", len(ids)))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) routeMove(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	routes, _ := s.db(r).Routes()
	idx := -1
	for i, rt := range routes {
		if rt.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		s.redirect(w, r, "/admin/routes", "bad", "Route not found.")
		return
	}
	swap := idx - 1
	if r.FormValue("dir") == "down" {
		swap = idx + 1
	}
	if swap < 0 || swap >= len(routes) {
		http.Redirect(w, r, "/admin/routes", http.StatusSeeOther)
		return
	}
	routes[idx], routes[swap] = routes[swap], routes[idx]
	var ids []int64
	for _, rt := range routes {
		ids = append(ids, rt.ID)
	}
	_ = s.db(r).ReorderRoutes(ids)
	s.db(r).Audit(p.User, "route.reorder", "moved one route")
	http.Redirect(w, r, "/admin/routes", http.StatusSeeOther)
}

func (s *Server) routeSimulate(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "routes", "routes"
	p.Routes, _ = s.db(r).Routes()
	var rules []match.Route
	for _, rt := range p.Routes {
		rules = append(rules, rt.AsMatch())
	}
	n := atoi(r.FormValue("n"))
	if n <= 0 {
		n = 20
	}
	p.PreviewN = n
	eng := *s.RT.Engine
	eng.DB = s.db(r)
	prev, err := eng.Preview(r.Context(), rules, n)
	if err != nil {
		p.Err = safeErr(err)
	}
	p.Previews = prev
	s.render(w, "routes", p)
}

func (s *Server) targets(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "targets", "targets"
	p.Targets, _ = s.db(r).Targets()
	s.render(w, "targets", p)
}

func (s *Server) targetEdit(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "target", "targets"
	p.IsNew = strings.HasSuffix(r.URL.Path, "/new")
	if !p.IsNew {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		t, ok, err := s.db(r).TargetByID(id, false)
		if err != nil || !ok {
			http.NotFound(w, r)
			return
		}
		p.Target = t
		p.Title = t.Name
	}
	s.render(w, "target_edit", p)
}

func (s *Server) targetSave(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	t := store.Target{
		ID: id, Name: r.FormValue("name"), URL: r.FormValue("url"), AuthMode: r.FormValue("auth_mode"),
		AuthHeader: r.FormValue("auth_header"), Template: r.FormValue("template"),
		IncludeBody: r.FormValue("include_body") == "1", Paused: r.FormValue("paused") == "1",
		QuietStart: r.FormValue("quiet_start"), QuietEnd: r.FormValue("quiet_end"),
		DigestAt: r.FormValue("digest_at"), RatePerMin: atoi(r.FormValue("rate_per_minute")),
	}
	if strings.TrimSpace(t.Name) == "" || strings.TrimSpace(t.URL) == "" {
		p.Err = "A target needs a name and a URL."
		p.Target = t
		p.IsNew = id == 0
		p.Title, p.Nav = "target", "targets"
		s.render(w, "target_edit", p)
		return
	}
	if !strings.HasPrefix(t.URL, "https://") && !strings.HasPrefix(t.URL, "http://") {
		p.Err = "The URL must be http or https."
		p.Target = t
		p.Title, p.Nav = "target", "targets"
		s.render(w, "target_edit", p)
		return
	}
	saved, err := s.db(r).SaveTarget(t, r.FormValue("secret"), r.FormValue("clear_secret") == "1")
	if err != nil {
		p.Err = safeErr(err)
		p.Target = t
		p.Title, p.Nav = "target", "targets"
		s.render(w, "target_edit", p)
		return
	}
	s.db(r).Audit(p.User, "target.save", saved.Name)
	s.redirect(w, r, "/admin/targets", "ok", "Target saved.")
}

func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	t, _, _ := s.db(r).TargetByID(id, false)
	if err := s.db(r).DeleteTarget(id); err != nil {
		s.redirect(w, r, "/admin/targets/"+strconv.FormatInt(id, 10), "bad", safeErr(err))
		return
	}
	s.db(r).Audit(p.User, "target.delete", t.Name)
	s.redirect(w, r, "/admin/targets", "ok", "Target deleted.")
}

func (s *Server) targetPause(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	paused := r.FormValue("paused") == "1"
	if err := s.db(r).SetTargetPaused(id, paused); err != nil {
		s.redirect(w, r, "/admin/targets", "bad", "Could not update the target.")
		return
	}
	s.db(r).Audit(p.User, "target.pause", fmt.Sprintf("id %d paused=%v", id, paused))
	s.redirect(w, r, "/admin/targets", "ok", "Target updated.")
}

func (s *Server) targetTest(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	d, err := s.RT.Worker.SendTest(r.Context(), s.db(r), id)
	if err != nil {
		s.redirect(w, r, "/admin/targets", "bad", safeErr(err))
		return
	}
	s.db(r).Audit(p.User, "target.test", d.TargetName)
	http.Redirect(w, r, "/admin/deliveries/"+strconv.FormatInt(d.ID, 10), http.StatusSeeOther)
}

func (s *Server) deliveries(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "deliveries", "deliveries"
	p.FilterStatus = r.URL.Query().Get("status")
	p.FilterRoute = r.URL.Query().Get("route")
	p.FilterTarget = r.URL.Query().Get("target")
	p.Statuses = []string{"queued", "retry", "inflight", "sent", "dead"}
	p.Deliveries, _ = s.db(r).Deliveries(p.FilterStatus, p.FilterRoute, p.FilterTarget, 200)
	s.render(w, "deliveries", p)
}

func (s *Server) delivery(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, ok, _ := s.db(r).DeliveryByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	p.Title, p.Nav = "delivery", "deliveries"
	p.Delivery = d
	s.render(w, "delivery", p)
}

func (s *Server) deliveryRetry(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err := s.db(r).Replay(id, false); err != nil {
		s.redirect(w, r, "/admin/deliveries", "bad", "Could not retry.")
		return
	}
	s.db(r).Audit(p.User, "delivery.retry", strconv.FormatInt(id, 10))
	s.redirect(w, r, "/admin/deliveries/"+strconv.FormatInt(id, 10), "ok", "Queued again with the same delivery id.")
}

func (s *Server) deliveryReplay(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err := s.db(r).Replay(id, true); err != nil {
		s.redirect(w, r, "/admin/deliveries", "bad", "Could not replay.")
		return
	}
	s.db(r).Audit(p.User, "delivery.replay", strconv.FormatInt(id, 10))
	s.redirect(w, r, "/admin/deliveries/"+strconv.FormatInt(id, 10), "ok", "Queued again with a new delivery id.")
}

func (s *Server) deliveryWindow(w http.ResponseWriter, r *http.Request, p page) {
	n, err := s.db(r).ReplayWindow(strings.TrimSpace(r.FormValue("route")), strings.TrimSpace(r.FormValue("target")), parseTime(r.FormValue("since")), parseTime(r.FormValue("until")))
	if err != nil {
		s.redirect(w, r, "/admin/deliveries", "bad", "Could not replay that window.")
		return
	}
	s.db(r).Audit(p.User, "delivery.replay.window", fmt.Sprintf("%d", n))
	s.redirect(w, r, "/admin/deliveries", "ok", fmt.Sprintf("Re-queued %d deliveries.", n))
}

func (s *Server) members(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "members", "members"
	p.Members, _ = s.RT.DB.Members(p.WorkspaceID)
	_, _, cl, _ := s.parseSession(r)
	if u, ok, _ := s.RT.DB.UserBySubject(cl.Sub); ok {
		p.InstanceAdmin = u.InstanceAdmin
	}
	p.AutoProvision = s.RT.DB.Instance().BoolSetting("proxy_auto_provision", true)
	p.FallbackUser = s.fallbackUser()
	s.render(w, "members", p)
}

func (s *Server) membersSave(w http.ResponseWriter, r *http.Request, p page) {
	if r.FormValue("kind") == "provision" {
		v := "0"
		if r.FormValue("auto") == "1" {
			v = "1"
		}
		_ = s.RT.DB.Instance().SetSetting("proxy_auto_provision", v)
		_ = s.RT.DB.Instance().SetSetting("proxy_fallback_user", strings.TrimSpace(r.FormValue("fallback")))
		s.redirect(w, r, "/admin/members", "ok", "Proxy options saved.")
		return
	}
	if err := s.RT.DB.Invite(p.WorkspaceID, r.FormValue("email"), r.FormValue("role")); err != nil {
		s.redirect(w, r, "/admin/members", "bad", safeErr(err))
		return
	}
	s.db(r).Audit(p.User, "member.invite", r.FormValue("email"))
	s.redirect(w, r, "/admin/members", "ok", "Member updated.")
}

func (s *Server) switchWorkspace(w http.ResponseWriter, r *http.Request, _ page) {
	http.SetCookie(w, &http.Cookie{Name: "ghook_ws", Value: r.FormValue("workspace"), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secure()})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) createWorkspace(w http.ResponseWriter, r *http.Request, p page) {
	_, _, cl, _ := s.parseSession(r)
	u, ok, _ := s.RT.DB.UserBySubject(cl.Sub)
	if !ok || !u.InstanceAdmin {
		http.Error(w, "only an instance admin can create a workspace", http.StatusForbidden)
		return
	}
	ws, err := s.RT.DB.CreateWorkspace(r.FormValue("name"), u.ID)
	if err != nil {
		s.redirect(w, r, "/admin/members", "bad", safeErr(err))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "ghook_ws", Value: strconv.FormatInt(ws.ID, 10), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secure()})
	s.redirect(w, r, "/admin", "ok", "Workspace created.")
}

func parseTime(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Unix()
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Unix()
	}
	return 0
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "settings", "settings"
	s.fillSettings(&p)
	s.render(w, "settings", p)
}

func (s *Server) fillSettings(p *page) {
	db := s.RT.DB
	p.LabelPrefix = db.Setting("label_prefix", "Ghook")
	p.LabelConvention = db.BoolSetting("label_convention", true)
	p.Catchup = db.IntSetting("catchup_minutes", 30)
	p.ResyncDays = db.IntSetting("resync_days", 2)
	p.RetryAttempts = db.IntSetting("retry_max_attempts", 8)
	p.RetryHours = db.IntSetting("retry_max_hours", 24)
	p.RetryBase = db.IntSetting("retry_base_seconds", 30)
	p.Retention = db.IntSetting("retention_days", 30)
	p.RetainBodies = db.BoolSetting("retain_bodies", false)
	p.Timezone = db.Setting("timezone", "UTC")
	p.NotifyTarget = int64(db.IntSetting("notify_target", 0))
	p.NotifyDead = db.BoolSetting("notify_dead", true)
	p.NotifyWatch = db.BoolSetting("notify_watch", true)
	p.Targets, _ = db.Targets()
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request, p page) {
	db := s.RT.DB
	pairs := [][2]string{
		{"label_prefix", strings.TrimSpace(r.FormValue("label_prefix"))},
		{"label_convention", on(r, "label_convention")},
		{"catchup_minutes", r.FormValue("catchup_minutes")},
		{"resync_days", r.FormValue("resync_days")},
		{"retry_max_attempts", r.FormValue("retry_max_attempts")},
		{"retry_max_hours", r.FormValue("retry_max_hours")},
		{"retry_base_seconds", r.FormValue("retry_base_seconds")},
		{"retention_days", r.FormValue("retention_days")},
		{"retain_bodies", on(r, "retain_bodies")},
		{"timezone", strings.TrimSpace(r.FormValue("timezone"))},
		{"notify_target", r.FormValue("notify_target")},
		{"notify_dead", on(r, "notify_dead")},
		{"notify_watch", on(r, "notify_watch")},
	}
	if pairs[9][1] == "" {
		pairs[9][1] = "UTC"
	}
	if _, err := time.LoadLocation(pairs[9][1]); err != nil {
		s.redirect(w, r, "/admin/settings", "bad", "Unknown timezone.")
		return
	}
	for _, kv := range pairs {
		if err := db.SetSetting(kv[0], kv[1]); err != nil {
			s.redirect(w, r, "/admin/settings", "bad", "Could not save settings.")
			return
		}
	}
	s.db(r).Audit(p.User, "settings.save", "updated settings")
	s.redirect(w, r, "/admin/settings", "ok", "Settings saved.")
}

func (s *Server) exportYAML(w http.ResponseWriter, r *http.Request, _ page) {
	raw, err := bundle.Export(s.RT.DB, r.FormValue("passphrase"))
	if err != nil {
		s.redirect(w, r, "/admin/settings", "bad", "Could not export.")
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="ghook.yaml"`)
	_, _ = w.Write(raw)
}

func (s *Server) importYAML(w http.ResponseWriter, r *http.Request, p page) {
	raw := fileOrField(r, "yaml", "file")
	if strings.TrimSpace(raw) == "" {
		if f, _, err := r.FormFile("file"); err == nil {
			b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
			f.Close()
			raw = string(b)
		}
	}
	msg, err := bundle.Import(s.RT.DB, []byte(raw), r.FormValue("passphrase"))
	if err != nil {
		s.redirect(w, r, "/admin/settings", "bad", safeErr(err))
		return
	}
	s.db(r).Audit(p.User, "import", msg)
	s.redirect(w, r, "/admin/settings", "ok", msg)
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "audit", "audit"
	p.Audits, _ = s.db(r).Audits(200)
	s.render(w, "audit", p)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.db(r).SQL.PingContext(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"db"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	counts, _ := s.db(r).DeliveryCounts()
	fmt.Fprintf(w, "ghook_up 1\n")
	fmt.Fprintf(w, "ghook_deliveries{status=\"queued\"} %d\n", counts.Queued)
	fmt.Fprintf(w, "ghook_deliveries{status=\"retry\"} %d\n", counts.Retry)
	fmt.Fprintf(w, "ghook_deliveries{status=\"dead\"} %d\n", counts.Dead)
	fmt.Fprintf(w, "ghook_deliveries{status=\"sent\"} %d\n", counts.Sent)
	accs, _ := s.db(r).Accounts()
	for _, a := range accs {
		fmt.Fprintf(w, "ghook_watch_expiry_unixtime{account=%q} %d\n", prom(a.Email), a.WatchExpiry)
		if a.LastNotify > 0 {
			fmt.Fprintf(w, "ghook_last_notification_unixtime{account=%q} %d\n", prom(a.Email), a.LastNotify)
		}
	}
}

func prom(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", "").Replace(s)
}

func (s *Server) push(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var env struct {
		Message struct {
			Data string `json:"data"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.Message.Data == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ps := s.db(r).LoadPubSub()
	aud := ps.PushAudience
	if aud == "" {
		aud = s.RT.Cfg.PushEndpoint()
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	email, err := s.checkPush(r, strings.TrimSpace(token), aud)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if ps.PushEmail != "" && !strings.EqualFold(email, ps.PushEmail) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	data, err := base64.StdEncoding.DecodeString(env.Message.Data)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(env.Message.Data)
	}
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.RT.Engine.HandleNotification(r.Context(), data); err != nil {
		http.Error(w, "retry", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) checkPush(r *http.Request, raw, aud string) (string, error) {
	if s.Verify != nil {
		return s.Verify(r, raw, aud)
	}
	payload, err := idtoken.Validate(r.Context(), raw, aud)
	if err != nil {
		return "", err
	}
	email, _ := payload.Claims["email"].(string)
	return email, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
