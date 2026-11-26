package web

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/helv-io/ghook/internal/store"
)

// revealStore holds a just-created API key for one session until the account
// page shows it once. The token never goes into a URL or a cookie.
type revealStore struct {
	mu   sync.Mutex
	keys map[string]revealed
}

type revealed struct {
	name, token string
	exp         time.Time
}

func (rs *revealStore) put(session string, v revealed) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.keys == nil {
		rs.keys = map[string]revealed{}
	}
	now := time.Now()
	for k, x := range rs.keys {
		if now.After(x.exp) {
			delete(rs.keys, k)
		}
	}
	rs.keys[session] = v
}

func (rs *revealStore) take(session string) (revealed, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	v, ok := rs.keys[session]
	delete(rs.keys, session)
	return v, ok && time.Now().Before(v.exp)
}

func (s *Server) fillKeys(w http.ResponseWriter, r *http.Request, p *page) {
	p.APIKeys, _ = s.db(r).APIKeys()
	if nonce, _, _, ok := s.parseSession(r); ok {
		if v, ok := s.reveal.take(nonce); ok {
			p.NewKey, p.NewKeyName = v.token, v.name
		}
	}
	w.Header().Set("Cache-Control", "no-store")
}

func (s *Server) keyCreate(w http.ResponseWriter, r *http.Request, p page) {
	k, token, err := s.opCreateKey(s.db(r), p.User, r.FormValue("name"), r.FormValue("scope"))
	if err != nil {
		s.redirect(w, r, "/admin/account#api-keys", "bad", msgOf(err))
		return
	}
	if nonce, _, _, ok := s.parseSession(r); ok {
		s.reveal.put(nonce, revealed{name: k.Name, token: token, exp: time.Now().Add(10 * time.Minute)})
	}
	http.Redirect(w, r, "/admin/account#api-keys", http.StatusSeeOther)
}

func (s *Server) keyRevoke(w http.ResponseWriter, r *http.Request, p page) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err := s.opRevokeKey(s.db(r), p.User, id); err != nil {
		s.redirect(w, r, "/admin/account#api-keys", "bad", msgOf(err))
		return
	}
	s.redirect(w, r, "/admin/account#api-keys", "ok", "Key revoked.")
}

func keyScope(k store.APIKey) string {
	if k.CanWrite() {
		return "read and write"
	}
	return "read only"
}
