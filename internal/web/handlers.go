package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/feed"
	"github.com/helv-io/ghook/internal/gmailx"
	"github.com/helv-io/ghook/internal/oidcauth"
	"github.com/helv-io/ghook/internal/pubsubx"
	"github.com/helv-io/ghook/internal/store"
	"golang.org/x/oauth2"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		s.render(w, "notconfigured", page{Title: "Sign in", Solo: true})
		return
	}
	if err := s.OIDC.Begin(w, r, "/admin"); err != nil {
		s.render(w, "autherror", page{Title: "Sign in", Solo: true, Err: err.Error()})
	}
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		s.render(w, "notconfigured", page{Title: "Sign in", Solo: true})
		return
	}
	id, next, err := s.OIDC.Finish(w, r)
	if err != nil {
		msg := err.Error()
		if errors.Is(err, oidcauth.ErrForbidden) {
			msg = "This account is not allowed to administer ghook."
		}
		s.render(w, "autherror", page{Title: "Sign in", Solo: true, Err: msg})
		return
	}
	s.setSession(w, id)
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/admin"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ page) {
	nonce, _, _, ok := s.parseSession(r)
	var end string
	if ok {
		if si, found := s.sessions.get(nonce); found && s.OIDC != nil {
			end = s.OIDC.EndSessionURL(r.Context(), si.idToken, s.RT.Cfg.PublicURL+"/admin")
		}
		s.sessions.revoke(nonce)
	}
	s.clearSession(w)
	if end != "" {
		http.Redirect(w, r, end, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "status", "status"
	accs, _ := s.db(r).Accounts()
	p.Accounts = accs
	counts, _ := s.db(r).DeliveryCounts()
	p.RouteStats, _ = s.db(r).RouteStats()
	p.TargetStats, _ = s.db(r).TargetStats()
	p.Events = s.RT.Feed.Backlog()
	connected := false
	var soon int64
	var last int64
	lag := "—"
	watchBad := false
	for _, a := range accs {
		if a.HasToken && !a.Disabled {
			connected = true
		}
		if a.WatchError != "" {
			watchBad = true
		}
		if a.WatchExpiry != 0 && (soon == 0 || a.WatchExpiry < soon) {
			soon = a.WatchExpiry
		}
		if a.LastNotify > last {
			last = a.LastNotify
		}
		if d := historyLag(a); d != "" {
			lag = d
		}
	}
	gClass, gVal := "bad", "not connected"
	if connected {
		gClass, gVal = "ok", "connected"
	}
	wClass, wVal := "warn", s.until(soon)
	if watchBad || wVal == "expired" {
		wClass = "bad"
	} else if soon > 0 && time.Until(time.Unix(soon, 0)) > 48*time.Hour {
		wClass = "ok"
	}
	dClass := ""
	if counts.Dead > 0 {
		dClass = "bad"
	}
	p.Checks = []health{
		{Label: "Google", Value: gVal, Class: gClass},
		{Label: "Watch", Value: wVal, Class: wClass},
		{Label: "History lag", Value: lag},
		{Label: "Last notification", Value: s.rel(last)},
		{Label: "Queue", Value: strconv.Itoa(counts.Queued + counts.Retry)},
		{Label: "Dead letters", Value: strconv.Itoa(counts.Dead), Class: dClass},
	}
	if _, ok, _ := s.db(r).GoogleClientJSON(); !ok {
		p.Setup = append(p.Setup, "Paste the Google OAuth client.")
	}
	if !connected {
		p.Setup = append(p.Setup, "Connect a Gmail account.")
	}
	ps := s.db(r).LoadPubSub()
	if ps.Topic == "" || ps.Subscription == "" {
		p.Setup = append(p.Setup, "Set the Pub/Sub topic and subscription.")
	}
	if connected && soon == 0 {
		p.Setup = append(p.Setup, "Start the Gmail watch.")
	}
	s.render(w, "dashboard", p)
}

func historyLag(a store.Account) string {
	if a.HistoryID == "" || a.LastNotifyHistory == "" {
		return ""
	}
	cur, ok1 := parseU(a.HistoryID)
	note, ok2 := parseU(a.LastNotifyHistory)
	if !ok1 || !ok2 || note < cur {
		return "0"
	}
	return strconv.FormatUint(note-cur, 10)
}

func parseU(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, true
}

func (s *Server) events(w http.ResponseWriter, r *http.Request, _ page) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch, cancel := s.RT.Feed.Subscribe()
	defer cancel()
	loc := s.loc()
	send := func(ev feed.Event) {
		raw, _ := json.Marshal(map[string]string{"time": ev.Time.In(loc).Format("15:04:05"), "text": ev.Text, "kind": ev.Kind})
		fmt.Fprintf(w, "data: %s\n\n", raw)
		fl.Flush()
	}
	for _, ev := range s.RT.Feed.Backlog() {
		send(ev)
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			send(ev)
		}
	}
}

func (s *Server) accounts(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "accounts", "accounts"
	s.fillAccounts(&p, r)
	s.render(w, "accounts", p)
}

func (s *Server) fillAccounts(p *page, r *http.Request) {
	p.Accounts, _ = s.db(r).Accounts()
	raw, ok, _ := s.db(r).GoogleClientJSON()
	p.HasClient = ok && raw != ""
	if p.HasClient {
		p.ClientID, _ = gmailx.ClientID(raw)
	}
	p.Modify = s.db(r).BoolSetting("gmail_modify", false)
	p.SettingsScope = s.db(r).BoolSetting("gmail_settings", false)
	p.PubSubScope = s.db(r).BoolSetting("gmail_pubsub", false)
	p.Pub = s.db(r).LoadPubSub()
	p.LabelPrefix = s.db(r).Setting("label_prefix", "Ghook")
	if len(p.Accounts) > 0 {
		p.LabelAccount = p.Accounts[0].ID
	}
	if id := r.URL.Query().Get("labels"); id != "" {
		n, _ := strconv.ParseInt(id, 10, 64)
		p.LabelAccount = n
		if acc, ok, _ := s.db(r).AccountByID(n); ok {
			if c, err := s.RT.Client(r.Context(), acc.Email); err == nil {
				if ls, err := c.Labels(r.Context()); err == nil {
					for _, l := range ls {
						p.Labels = append(p.Labels, labelView{ID: l.ID, Name: l.Name})
					}
				} else {
					p.Err = safeErr(err)
				}
			} else if p.Err == "" {
				p.Err = safeErr(err)
			}
		}
	}
}

func (s *Server) saveClient(w http.ResponseWriter, r *http.Request, p page) {
	raw := strings.TrimSpace(fileOrField(r, "client_json", "client_file"))
	if raw == "" {
		s.redirect(w, r, "/admin/accounts", "bad", "Paste or upload the OAuth client JSON.")
		return
	}
	if _, err := gmailx.ClientID(raw); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "That file is not a Google OAuth client.")
		return
	}
	var err error
	if r.FormValue("workspace_only") == "1" {
		err = s.db(r).SetGoogleClientJSON(raw)
	} else {
		err = s.RT.DB.Instance().SetGoogleClientJSON(raw)
	}
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not store the client.")
		return
	}
	s.db(r).Audit(p.User, "google.client", "saved the OAuth client")
	s.redirect(w, r, "/admin/accounts", "ok", "OAuth client saved.")
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request, p page) {
	_ = s.db(r).SetSetting("gmail_modify", on(r, "gmail_modify"))
	_ = s.db(r).SetSetting("gmail_settings", on(r, "gmail_settings"))
	_ = s.db(r).SetSetting("gmail_pubsub", on(r, "gmail_pubsub"))
	raw, ok, err := s.db(r).GoogleClientJSON()
	if err != nil || !ok {
		s.redirect(w, r, "/admin/accounts", "bad", "Save the OAuth client first.")
		return
	}
	scopes := gmailx.ScopeList(r.FormValue("gmail_modify") == "1", r.FormValue("gmail_settings") == "1", r.FormValue("gmail_pubsub") == "1")
	cfg, err := gmailx.Config(raw, s.RT.Cfg.GoogleRedirect(), scopes)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "The OAuth client could not be read.")
		return
	}
	state := randToken(24)
	s.setState(w, state)
	u := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account consent"), oauth2.SetAuthURLParam("include_granted_scopes", "true"))
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) setState(w http.ResponseWriter, state string) {
	payload := state + "." + strconv.FormatInt(time.Now().Add(15*time.Minute).Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name: stateName, Value: payload + "." + s.mac("google:"+payload), Path: "/admin/google",
		MaxAge: 900, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secure(),
	})
}

func (s *Server) takeState(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := r.Cookie(stateName)
	http.SetCookie(w, &http.Cookie{Name: stateName, Value: "", Path: "/admin/google", MaxAge: -1, HttpOnly: true, Secure: s.secure()})
	if err != nil {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload := parts[0] + "." + parts[1]
	sig := s.mac("google:" + payload)
	if len(sig) != len(parts[2]) || subtleCompare(sig, parts[2]) != 1 {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp || parts[0] == "" {
		return "", false
	}
	return parts[0], true
}

func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	n := 0
	for i := 0; i < len(a); i++ {
		n |= int(a[i] ^ b[i])
	}
	if n == 0 {
		return 1
	}
	return 0
}

func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request, p page) {
	state, ok := s.takeState(w, r)
	if !ok || r.URL.Query().Get("state") != state {
		s.redirect(w, r, "/admin/accounts", "bad", "The Google sign-in expired. Start it again.")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.redirect(w, r, "/admin/accounts", "bad", "Google returned an error.")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.redirect(w, r, "/admin/accounts", "bad", "Google did not return a code.")
		return
	}
	raw, _, err := s.db(r).GoogleClientJSON()
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "The OAuth client could not be read.")
		return
	}
	scopes := gmailx.ScopeList(s.db(r).BoolSetting("gmail_modify", false), s.db(r).BoolSetting("gmail_settings", false), s.db(r).BoolSetting("gmail_pubsub", false))
	cfg, err := gmailx.Config(raw, s.RT.Cfg.GoogleRedirect(), scopes)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "The OAuth client could not be read.")
		return
	}
	tok, err := cfg.Exchange(r.Context(), code)
	if err != nil || tok.RefreshToken == "" {
		s.redirect(w, r, "/admin/accounts", "bad", "Google did not return a refresh token. Remove ghook's access in the Google account and connect again.")
		return
	}
	live, err := gmailx.Dial(r.Context(), raw, tok.RefreshToken, tok.AccessToken, tok.Expiry, scopes, nil)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not open Gmail.")
		return
	}
	email, hist, err := live.Profile(r.Context())
	if err != nil || email == "" {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not read the Gmail profile.")
		return
	}
	acc, err := s.db(r).SaveAccount(email, tok.RefreshToken, tok.AccessToken, tok.Expiry.Unix(), strings.Join(scopes, " "), hist)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not save the mailbox.")
		return
	}
	s.db(r).Audit(p.User, "google.connect", "connected "+email)
	ps := s.db(r).LoadPubSub()
	if ps.Project != "" && ps.Topic != "" {
		topic := pubsubx.TopicPath(ps.Project, ps.Topic)
		wh, exp, werr := live.Watch(r.Context(), topic)
		if werr != nil {
			_ = s.db(r).SetWatch(acc.ID, 0, wh, safeErr(werr))
			s.RT.Feed.Add("error", "Watch failed for "+email)
			s.redirect(w, r, "/admin/accounts", "warn", "Connected "+email+", but the watch failed. Check the topic and the Gmail publish permission.")
			return
		}
		_ = s.db(r).SetWatch(acc.ID, exp.Unix(), wh, "")
		s.RT.Feed.Add("watch", email+" watch started")
	}
	s.redirect(w, r, "/admin/accounts", "ok", "Connected "+email+".")
}

func (s *Server) renewOne(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	acc, ok, _ := s.db(r).AccountByID(id)
	if !ok {
		s.redirect(w, r, "/admin/accounts", "bad", "Mailbox not found.")
		return
	}
	ps := s.db(r).LoadPubSub()
	if ps.Topic == "" {
		s.redirect(w, r, "/admin/accounts", "bad", "Set the Pub/Sub topic first.")
		return
	}
	c, err := s.RT.Client(r.Context(), acc.Email)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", safeErr(err))
		return
	}
	hist, exp, err := c.Watch(r.Context(), pubsubx.TopicPath(ps.Project, ps.Topic))
	if err != nil {
		_ = s.db(r).SetWatch(acc.ID, acc.WatchExpiry, "", safeErr(err))
		s.RT.Feed.Add("error", "Watch renewal failed for "+acc.Email)
		s.redirect(w, r, "/admin/accounts", "bad", "Watch renewal failed.")
		return
	}
	_ = s.db(r).SetWatch(acc.ID, exp.Unix(), hist, "")
	s.db(r).Audit(p.User, "watch.renew", acc.Email)
	s.RT.Feed.Add("watch", acc.Email+" watch renewed")
	s.redirect(w, r, "/admin/accounts", "ok", "Watch renewed for "+acc.Email+".")
}

func (s *Server) pauseAccount(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	dis := r.FormValue("disabled") == "1"
	if err := s.db(r).SetAccountDisabled(id, dis); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not update the mailbox.")
		return
	}
	s.db(r).Audit(p.User, "account.pause", fmt.Sprintf("id %d paused=%v", id, dis))
	s.redirect(w, r, "/admin/accounts", "ok", "Mailbox updated.")
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	acc, ok, _ := s.db(r).AccountByID(id)
	if ok {
		if c, err := s.RT.Client(r.Context(), acc.Email); err == nil {
			_ = c.Stop(r.Context())
		}
	}
	if err := s.db(r).DeleteAccount(id); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not disconnect.")
		return
	}
	s.db(r).Audit(p.User, "google.disconnect", acc.Email)
	s.redirect(w, r, "/admin/accounts", "ok", "Disconnected.")
}

func (s *Server) savePubSub(w http.ResponseWriter, r *http.Request, p page) {
	ps := store.PubSub{
		Project: r.FormValue("project"), Topic: r.FormValue("topic"), Subscription: r.FormValue("subscription"),
		Mode: r.FormValue("mode"), PushAudience: r.FormValue("push_audience"), PushEmail: r.FormValue("push_email"),
		UseOAuth: r.FormValue("use_oauth") == "1",
	}
	sa := strings.TrimSpace(fileOrField(r, "sa_json", "sa_file"))
	if sa != "" {
		if err := validSA(sa); err != nil {
			s.redirect(w, r, "/admin/accounts", "bad", "That file is not a service account key.")
			return
		}
	}
	if err := s.db(r).SavePubSub(ps, sa, r.FormValue("clear_sa") == "1"); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not save Pub/Sub settings.")
		return
	}
	s.db(r).Audit(p.User, "pubsub.save", ps.Project+"/"+ps.Topic)
	s.redirect(w, r, "/admin/accounts", "ok", "Pub/Sub settings saved.")
}

func validSA(s string) error {
	var v struct {
		Type  string `json:"type"`
		Email string `json:"client_email"`
	}
	if json.Unmarshal([]byte(s), &v) != nil || v.Type != "service_account" || v.Email == "" {
		return errors.New("not a service account")
	}
	return nil
}

func (s *Server) pubsubAPI(r *http.Request) (*pubsubx.API, store.PubSub, error) {
	ps := s.db(r).LoadPubSub()
	if ps.Project == "" {
		return nil, ps, errors.New("set the project id first")
	}
	api := &pubsubx.API{Token: s.RT.AccessToken}
	if _, err := api.Token(r.Context()); err != nil {
		return nil, ps, err
	}
	return api, ps, nil
}

func on(r *http.Request, name string) string {
	if r.FormValue(name) == "1" {
		return "1"
	}
	return "0"
}

func fileOrField(r *http.Request, field, file string) string {
	if f, _, err := r.FormFile(file); err == nil {
		defer f.Close()
		b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
		if strings.TrimSpace(string(b)) != "" {
			return string(b)
		}
	}
	return r.FormValue(field)
}

func safeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
