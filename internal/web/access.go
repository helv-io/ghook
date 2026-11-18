package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/oidcauth"
	"github.com/helv-io/ghook/internal/store"
)

type ctxKey int

const wsKey ctxKey = 1

func (s *Server) db(r *http.Request) *store.DB {
	if r != nil {
		if v := r.Context().Value(wsKey); v != nil {
			if db, ok := v.(*store.DB); ok && db != nil {
				return db
			}
		}
	}
	if s.RT != nil {
		return s.RT.DB
	}
	return nil
}

func (s *Server) sessionOrMint(w http.ResponseWriter, r *http.Request, subject, email, name string) bool {
	if _, ok := s.Session(r); ok {
		_, _, cl, good := s.parseSession(r)
		if good && cl.Sub == subject {
			return true
		}
	}
	if _, err := s.RT.DB.EnsureUser(subject, email, name, true); err != nil {
		http.Error(w, "could not open a session", http.StatusInternalServerError)
		return false
	}
	s.setSession(w, oidcauth.Identity{Subject: subject, Email: email, Name: name, Username: name})
	// The cookie is on the response, not the request. Copy it onto r so this
	// same request can read the session it just created.
	for _, c := range (&http.Response{Header: w.Header()}).Cookies() {
		if c.Name == cookieName {
			r.AddCookie(c)
		}
	}
	return true
}

func (s *Server) fallbackUser() string {
	if s.RT == nil {
		return ""
	}
	if v := strings.TrimSpace(s.RT.DB.Instance().Setting("proxy_fallback_user", "")); v != "" {
		return v
	}
	return strings.TrimSpace(s.RT.Cfg.ProxyFallback)
}

func (s *Server) proxyAuth(w http.ResponseWriter, r *http.Request) bool {
	if !s.RT.Cfg.TrustedProxy(r.RemoteAddr) {
		s.render(w, "noidentity", page{Title: "Not signed in", Solo: true, Err: "This request did not come from a trusted proxy, so the identity headers were ignored."})
		return false
	}
	user := strings.TrimSpace(r.Header.Get(s.RT.Cfg.ProxyUser))
	email := strings.TrimSpace(r.Header.Get(s.RT.Cfg.ProxyEmail))
	name := strings.TrimSpace(r.Header.Get(s.RT.Cfg.ProxyName))
	if user == "" {
		user = s.fallbackUser()
		if name == "" {
			name = user
		}
	}
	if user == "" {
		if r.URL.Path == "/admin/google/callback" {
			if _, ok := s.Session(r); ok {
				return true
			}
		}
		s.render(w, "noidentity", page{Title: "No identity header", Solo: true,
			Err: "The proxy did not send " + s.RT.Cfg.ProxyUser + ". On a LAN where forward auth is bypassed, set PROXY_FALLBACK_USER to the account that should be used."})
		return false
	}
	// The header user and the fallback name are the same account when the strings match.
	auto := s.RT.DB.Instance().BoolSetting("proxy_auto_provision", true)
	if _, err := s.RT.DB.EnsureUser(user, email, name, auto); err != nil {
		s.render(w, "noidentity", page{Title: "Not a member", Solo: true, Err: "This identity is not a member of a workspace yet."})
		return false
	}
	return s.sessionOrMint(w, r, user, email, name)
}

func (s *Server) pageFor(w http.ResponseWriter, r *http.Request, csrf string) (page, bool) {
	_, _, cl, ok := s.parseSession(r)
	if !ok {
		return page{}, false
	}
	user, found, err := s.RT.DB.UserBySubject(cl.Sub)
	if err != nil {
		return page{}, false
	}
	if !found {
		user, err = s.RT.DB.EnsureUser(cl.Sub, cl.Email, cl.Label, true)
		if err != nil {
			return page{}, false
		}
	}
	wss, err := s.RT.DB.MemberWorkspaces(user.ID)
	if err != nil || len(wss) == 0 {
		return page{}, false
	}
	chosen := wss[0].ID
	if c, err := r.Cookie("ghook_ws"); err == nil {
		if id, err := strconv.ParseInt(c.Value, 10, 64); err == nil {
			for _, w := range wss {
				if w.ID == id {
					chosen = id
				}
			}
		}
	}
	role, _ := s.RT.DB.Role(user.ID, chosen)
	ws := s.RT.DB.Use(chosen)
	*r = *r.WithContext(context.WithValue(r.Context(), wsKey, ws))
	label := user.Name
	if label == "" {
		label = user.Email
	}
	if label == "" {
		label = user.Subject
	}
	p := page{
		CSRF: csrf, User: label, Toasts: s.takeFlash(w, r),
		Role: role, WorkspaceID: chosen, Workspaces: wss,
		ShowTeam: !s.RT.DB.SingleTenant(), AuthMode: s.RT.Cfg.AuthMode,
	}
	if s.RT.Cfg.Mode() == config.AuthNone {
		p.Banner = "Sign-in is off. Anyone who can open this URL is the admin. Set AUTH_MODE=oidc or AUTH_MODE=proxy before you expose it."
	}
	return p, true
}
