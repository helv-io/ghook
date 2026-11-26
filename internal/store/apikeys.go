package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const apiKeysSchema = `
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  key_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  scope TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
`

// API key scopes.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

// KeyPrefix starts every API key.
const KeyPrefix = "ghk_"

// ErrNotFound means the row does not exist for this user.
var ErrNotFound = errors.New("not found")

// ErrBadKey means a bearer token is malformed, unknown, or revoked.
var ErrBadKey = errors.New("invalid API key")

// APIKey is one stored key. The token itself is never stored, only its SHA-256.
type APIKey struct {
	ID        int64  `json:"id"`
	KeyID     string `json:"key_id"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used"`
	UserID    int64  `json:"-"`
}

// Display is the visible part of a key, safe to show anywhere.
func (k APIKey) Display() string { return KeyPrefix + k.KeyID + "_…" }

// CanWrite reports whether the key may change data.
func (k APIKey) CanWrite() bool { return k.Scope == ScopeWrite }

func hashKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ParseKeyID returns the visible id of a well-formed token.
func ParseKeyID(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, KeyPrefix)
	if !ok || len(rest) < 10 || rest[8] != '_' {
		return "", false
	}
	id := rest[:8]
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	if len(rest[9:]) < 32 {
		return "", false
	}
	return id, true
}

// CreateAPIKey mints a key for this user. The token is returned once and never stored.
func (d *DB) CreateAPIKey(name, scope string) (APIKey, string, error) {
	if d.uid <= 0 {
		return APIKey{}, "", errors.New("user is required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return APIKey{}, "", errors.New("a key needs a name")
	}
	if len(name) > 64 {
		name = name[:64]
	}
	if scope != ScopeRead && scope != ScopeWrite {
		return APIKey{}, "", errors.New("scope must be read or write")
	}
	idb := make([]byte, 4)
	sec := make([]byte, 32)
	if _, err := rand.Read(idb); err != nil {
		return APIKey{}, "", err
	}
	if _, err := rand.Read(sec); err != nil {
		return APIKey{}, "", err
	}
	k := APIKey{KeyID: hex.EncodeToString(idb), Name: name, Scope: scope, CreatedAt: now(), UserID: d.uid}
	token := KeyPrefix + k.KeyID + "_" + base64.RawURLEncoding.EncodeToString(sec)
	res, err := d.SQL.Exec(`INSERT INTO api_keys(user_id, key_id, name, scope, hash, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		d.uid, k.KeyID, k.Name, k.Scope, hashKey(token), k.CreatedAt)
	if err != nil {
		return APIKey{}, "", err
	}
	k.ID, _ = res.LastInsertId()
	return k, token, nil
}

// APIKeys lists this user's active keys, newest first.
func (d *DB) APIKeys() ([]APIKey, error) {
	rows, err := d.SQL.Query(`SELECT id, key_id, name, scope, created_at, last_used, user_id FROM api_keys
		WHERE user_id=? AND revoked_at=0 ORDER BY id DESC`, d.uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.KeyID, &k.Name, &k.Scope, &k.CreatedAt, &k.LastUsed, &k.UserID); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey disables one of this user's keys. It returns the key that was revoked.
func (d *DB) RevokeAPIKey(id int64) (APIKey, error) {
	var k APIKey
	err := d.SQL.QueryRow(`SELECT id, key_id, name, scope, created_at, last_used, user_id FROM api_keys
		WHERE id=? AND user_id=? AND revoked_at=0`, id, d.uid).Scan(&k.ID, &k.KeyID, &k.Name, &k.Scope, &k.CreatedAt, &k.LastUsed, &k.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return k, ErrNotFound
	}
	if err != nil {
		return k, err
	}
	_, err = d.SQL.Exec(`UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=?`, now(), id, d.uid)
	return k, err
}

// LookupAPIKey finds the active key for a bearer token across users and marks it used.
func (d *DB) LookupAPIKey(token string) (APIKey, error) {
	keyID, ok := ParseKeyID(token)
	if !ok {
		return APIKey{}, ErrBadKey
	}
	var k APIKey
	var hash string
	var revoked int64
	err := d.SQL.QueryRow(`SELECT id, key_id, name, scope, created_at, last_used, user_id, hash, revoked_at FROM api_keys WHERE key_id=?`, keyID).
		Scan(&k.ID, &k.KeyID, &k.Name, &k.Scope, &k.CreatedAt, &k.LastUsed, &k.UserID, &hash, &revoked)
	want := hashKey(token)
	if err != nil {
		// Spend the same compare on a miss.
		subtle.ConstantTimeCompare([]byte(want), []byte(want))
		return APIKey{}, ErrBadKey
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(want)) != 1 || revoked != 0 || k.UserID <= 0 {
		return APIKey{}, ErrBadKey
	}
	t := now()
	if t-k.LastUsed >= 60 {
		_, _ = d.SQL.Exec(`UPDATE api_keys SET last_used=? WHERE id=?`, t, k.ID)
		k.LastUsed = t
	}
	return k, nil
}
