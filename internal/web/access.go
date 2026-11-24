package web

import (
	"context"
	"net/http"

	"github.com/helv-io/ghook/internal/auth"
	"github.com/helv-io/ghook/internal/store"
)

type ctxKey int

const userKey ctxKey = 1

func (s *Server) db(r *http.Request) *store.DB {
	if r != nil {
		if v := r.Context().Value(userKey); v != nil {
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

func (s *Server) sessionOrMint(w http.ResponseWriter, r *http.Request, subject, email, name string) (*store.DB, store.User, bool) {
	db, u, err := s.RT.DB.EnsureAndUse(subject, email, name)
	if err != nil {
		http.Error(w, "could not open a session", http.StatusInternalServerError)
		return nil, store.User{}, false
	}
	s.setSession(w, auth.Identity{Subject: subject, Email: email, Name: name, Username: name})
	for _, c := range (&http.Response{Header: w.Header()}).Cookies() {
		if c.Name == cookieName {
			r.AddCookie(c)
		}
	}
	*r = *r.WithContext(context.WithValue(r.Context(), userKey, db))
	return db, u, true
}

func (s *Server) pageFor(w http.ResponseWriter, r *http.Request, csrf string) (page, bool) {
	_, _, cl, ok := s.parseSession(r)
	if !ok {
		return page{}, false
	}
	user, found, err := s.RT.DB.UserBySubject(cl.Sub)
	if err != nil || !found {
		return page{}, false
	}
	db := s.RT.DB.Use(user.ID)
	*r = *r.WithContext(context.WithValue(r.Context(), userKey, db))
	label := user.Name
	if label == "" {
		label = user.Email
	}
	if label == "" {
		label = user.Subject
	}
	p := page{
		CSRF: csrf, User: label, UserEmail: user.Email, Toasts: s.takeFlash(w, r),
		Public: s.RT.Cfg.PublicURL,
		Loc:    s.locOf(r),
	}
	p.Testing = db.BoolSetting("testing_mode", false)
	return p, true
}
