package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/helv-io/ghook/internal/gmailx"
	"github.com/helv-io/ghook/internal/pubsubx"
	"golang.org/x/oauth2"
)

func loginScopes(modify, settings bool) []string {
	out := []string{
		"openid",
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	}
	return append(out, gmailx.ScopeList(modify, settings, false)...)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.Session(r); ok {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.Session(r); ok {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	p := page{Title: "Sign in", Solo: true}
	if e := r.URL.Query().Get("error"); e == "denied" {
		p.Err = "Google sign-in was cancelled."
	} else if e == "token" {
		p.Err = "Google did not return a usable token. Try again."
	} else if e == "mailbox" {
		p.Err = "That Gmail address is already connected to a different account."
	} else if e == "config" {
		p.Err = "This instance is not ready for sign-in."
	}
	s.render(w, "login", p)
}

func (s *Server) googleStart(w http.ResponseWriter, r *http.Request) {
	if s.RT == nil || !s.RT.Cfg.Ready() {
		s.render(w, "login", page{Title: "Sign in", Solo: true, Err: "This instance is not ready for sign-in. The operator needs to set the Google OAuth client."})
		return
	}
	modify, settings := false, false
	if _, ok := s.Session(r); ok {
		if p, ok := s.pageFor(w, r, ""); ok {
			_ = p
			db := s.db(r)
			if db != nil {
				modify = db.BoolSetting("gmail_modify", false) || r.URL.Query().Get("modify") == "1"
				settings = db.BoolSetting("gmail_settings", false) || r.URL.Query().Get("settings") == "1"
			}
		}
	} else if r.URL.Query().Get("modify") == "1" {
		modify = true
	}
	cfg, err := gmailx.Config(s.RT.Cfg.GoogleClient, s.RT.Cfg.GoogleRedirect(), loginScopes(modify, settings))
	if err != nil {
		s.render(w, "login", page{Title: "Sign in", Solo: true, Err: "The Google OAuth client could not be read."})
		return
	}
	state := randToken(24)
	s.setState(w, state)
	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
		oauth2.SetAuthURLParam("prompt", "select_account consent"),
	}
	http.Redirect(w, r, cfg.AuthCodeURL(state, opts...), http.StatusFound)
}

func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	if s.RT == nil || !s.RT.Cfg.Ready() {
		http.Redirect(w, r, "/login?error=config", http.StatusSeeOther)
		return
	}
	state, ok := s.takeState(w, r)
	if !ok || r.URL.Query().Get("state") != state {
		http.Redirect(w, r, "/login?error=denied", http.StatusSeeOther)
		return
	}
	if r.URL.Query().Get("error") != "" {
		http.Redirect(w, r, "/login?error=denied", http.StatusSeeOther)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/login?error=token", http.StatusSeeOther)
		return
	}
	scopes := loginScopes(false, false)
	cfg, err := gmailx.Config(s.RT.Cfg.GoogleClient, s.RT.Cfg.GoogleRedirect(), scopes)
	if err != nil {
		http.Redirect(w, r, "/login?error=config", http.StatusSeeOther)
		return
	}
	tok, err := cfg.Exchange(r.Context(), code)
	if err != nil {
		http.Redirect(w, r, "/login?error=token", http.StatusSeeOther)
		return
	}
	info, err := googleUser(r.Context(), tok)
	if err != nil || info.Subject == "" {
		http.Redirect(w, r, "/login?error=token", http.StatusSeeOther)
		return
	}
	email := info.Email
	if email == "" {
		email = info.EmailFallback
	}
	// Open Gmail with the same token so this consent also connects the mailbox.
	live, err := gmailx.Dial(r.Context(), s.RT.Cfg.GoogleClient, tok.RefreshToken, tok.AccessToken, tok.Expiry, scopes, nil)
	hist := ""
	if err == nil {
		if em, h, perr := live.Profile(r.Context()); perr == nil && em != "" {
			email = em
			hist = h
		}
	}
	if email == "" {
		http.Redirect(w, r, "/login?error=token", http.StatusSeeOther)
		return
	}
	// Unique mailbox: the address may already belong to another user.
	if accs, _ := s.RT.DB.Unscoped().AccountsByEmail(email); len(accs) > 0 {
		if existing, ok, _ := s.RT.DB.UserBySubject(info.Subject); !ok || existing.ID != accs[0].UserID {
			if !ok || existing.ID != accs[0].UserID {
				http.Redirect(w, r, "/login?error=mailbox", http.StatusSeeOther)
				return
			}
		}
	}
	db, user, ok := s.sessionOrMint(w, r, info.Subject, email, info.Name)
	if !ok {
		return
	}
	refresh := tok.RefreshToken
	if refresh == "" {
		if acc, found, _ := db.AccountByEmail(email); found {
			refresh = acc.RefreshToken()
		}
	}
	if refresh == "" {
		http.Redirect(w, r, "/login?error=token", http.StatusSeeOther)
		return
	}
	granted := strings.Join(scopes, " ")
	if tok.Extra("scope") != nil {
		if sc, _ := tok.Extra("scope").(string); sc != "" {
			granted = sc
		}
	}
	acc, err := db.SaveAccount(email, refresh, tok.AccessToken, tok.Expiry.Unix(), granted, hist)
	if err != nil {
		http.Redirect(w, r, "/login?error=mailbox", http.StatusSeeOther)
		return
	}
	db.Audit(user.Email, "google.connect", "connected "+email)
	if s.RT.Cfg.PubSubReady() && live != nil {
		topic := pubsubx.TopicPath(s.RT.Cfg.PubSubProject, s.RT.Cfg.PubSubTopic)
		if h, until, werr := live.Watch(r.Context(), topic); werr != nil {
			_ = db.SetWatch(acc.ID, 0, hist, werr.Error())
		} else {
			_ = db.SetWatch(acc.ID, until.Unix(), h, "")
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

type googleIdentity struct {
	Subject       string
	Email         string
	EmailFallback string
	Name          string
}

func googleUser(ctx interface { /* placeholder */
}, tok *oauth2.Token) (googleIdentity, error) {
	return fetchGoogleUser(tok)
}

func fetchGoogleUser(tok *oauth2.Token) (googleIdentity, error) {
	req, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return googleIdentity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return googleIdentity{}, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode >= 300 {
		return googleIdentity{}, googleErr("userinfo failed")
	}
	var doc struct {
		ID    string `json:"id"`
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return googleIdentity{}, err
	}
	sub := doc.Sub
	if sub == "" {
		sub = doc.ID
	}
	return googleIdentity{Subject: sub, Email: doc.Email, Name: doc.Name}, nil
}

type googleErr string

func (e googleErr) Error() string { return string(e) }

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ page) {
	nonce, _, _, ok := s.parseSession(r)
	if ok {
		s.sessions.revoke(nonce)
	}
	s.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, p page) {
	p.Title, p.Nav = "account", "account"
	s.fillKeys(w, r, &p)
	s.render(w, "account", p)
}

func (s *Server) saveScopes(w http.ResponseWriter, r *http.Request, p page) {
	q := s.opSetScopes(s.db(r), p.User, r.FormValue("gmail_modify") == "1", r.FormValue("gmail_settings") == "1")
	http.Redirect(w, r, q, http.StatusSeeOther)
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request, p page) {
	if r.FormValue("confirm") != "1" {
		s.redirect(w, r, "/admin/account", "bad", "Tick the box to confirm deletion.")
		return
	}
	if err := s.opDeleteUser(r.Context(), s.db(r)); err != nil {
		s.redirect(w, r, "/admin/account", "bad", msgOf(err))
		return
	}
	nonce, _, _, ok := s.parseSession(r)
	if ok {
		s.sessions.revoke(nonce)
	}
	s.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func revokeGoogleToken(token string) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err == nil {
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
}
