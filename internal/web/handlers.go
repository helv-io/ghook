package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/feed"
	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/store"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "status", "status"
	accs, _ := s.db(r).Accounts()
	p.Accounts = accs
	counts, _ := s.db(r).DeliveryCounts()
	p.RouteStats, _ = s.db(r).RouteStats()
	p.TargetStats, _ = s.db(r).TargetStats()
	p.Events = s.RT.Feed.BacklogFor(s.db(r).UserID())
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
	if s.RT == nil || !s.RT.Cfg.Ready() {
		p.Setup = append(p.Setup, "The operator has not finished configuring Google sign-in.")
	}
	if !connected {
		p.Setup = append(p.Setup, "Connect a Gmail mailbox from the accounts page.")
	}
	if connected && soon == 0 {
		p.Setup = append(p.Setup, "Start the Gmail watch from the accounts page.")
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
	uid := s.db(r).UserID()
	loc := s.locOf(r)
	send := func(ev feed.Event) {
		if ev.UserID != uid {
			return
		}
		raw, _ := json.Marshal(map[string]string{"time": ev.Time.In(loc).Format("15:04:05"), "text": ev.Text, "kind": ev.Kind})
		fmt.Fprintf(w, "data: %s\n\n", raw)
		fl.Flush()
	}
	for _, ev := range s.RT.Feed.BacklogFor(uid) {
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
	p.HasClient = s.RT.Cfg.Ready()
	p.Modify = s.db(r).BoolSetting("gmail_modify", false)
	p.SettingsScope = s.db(r).BoolSetting("gmail_settings", false)
	p.LabelPrefix = s.db(r).Setting("label_prefix", match.DefaultPrefix)
	if len(p.Accounts) > 0 {
		p.LabelAccount = p.Accounts[0].ID
	}
	if id := r.URL.Query().Get("labels"); id != "" {
		n, _ := strconv.ParseInt(id, 10, 64)
		p.LabelAccount = n
		if _, ok, _ := s.db(r).AccountByID(n); ok {
			ls, err := s.opLabels(r.Context(), s.db(r), n)
			if err != nil {
				p.Err = msgOf(err)
			}
			p.Labels = ls
		}
	}
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

func (s *Server) renewOne(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	acc, err := s.opRenewWatch(r.Context(), s.db(r), p.User, id)
	if err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", msgOf(err))
		return
	}
	s.redirect(w, r, "/admin/accounts", "ok", "Watch renewed for "+acc.Email+".")
}

func (s *Server) pauseAccount(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err := s.opPauseAccount(s.db(r), p.User, id, r.FormValue("disabled") == "1"); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not update the mailbox.")
		return
	}
	s.redirect(w, r, "/admin/accounts", "ok", "Mailbox updated.")
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err := s.opDisconnect(r.Context(), s.db(r), p.User, id); err != nil {
		s.redirect(w, r, "/admin/accounts", "bad", "Could not disconnect.")
		return
	}
	s.redirect(w, r, "/admin/accounts", "ok", "Disconnected.")
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
