package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/helv-io/ghook/internal/secrets"
)

const userKeysSchema = `
CREATE TABLE IF NOT EXISTS user_keys (
  user_id INTEGER PRIMARY KEY,
  wrapped_dek TEXT NOT NULL,
  kek_id TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  rotated_at INTEGER NOT NULL DEFAULT 0
);
`

func (d *DB) ensure() error {
	if _, err := d.SQL.Exec(userKeysSchema); err != nil {
		return err
	}
	if !d.hasColumn("targets", "payload_pubkey") {
		if _, err := d.SQL.Exec(`ALTER TABLE targets ADD COLUMN payload_pubkey TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) kek() (secrets.KEK, error) {
	if d == nil || d.root == nil {
		return nil, errors.New("secrets: no KEK")
	}
	id := d.Source
	if id == "" {
		id = "local"
	}
	return secrets.NewLocalKEK(d.root.Key(), id)
}

func (d *DB) ensureUserBox(userID int64) (*secrets.Box, error) {
	if userID <= 0 {
		return nil, errors.New("user is required")
	}
	var wrapped, kekID string
	err := d.SQL.QueryRow(`SELECT wrapped_dek, kek_id FROM user_keys WHERE user_id=?`, userID).Scan(&wrapped, &kekID)
	kek, kerr := d.kek()
	if kerr != nil {
		return nil, kerr
	}
	if err == nil && wrapped != "" {
		dek, uerr := kek.Unwrap(wrapped)
		if uerr != nil {
			return nil, uerr
		}
		return secrets.BoxFromDEK(dek)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	box, dek, err := secrets.NewDEK()
	if err != nil {
		return nil, err
	}
	blob, err := kek.Wrap(dek)
	if err != nil {
		return nil, err
	}
	_, err = d.SQL.Exec(`INSERT INTO user_keys(user_id, wrapped_dek, kek_id, created_at) VALUES(?, ?, ?, ?)`,
		userID, blob, kek.ID(), now())
	if err != nil {
		return nil, err
	}
	if err := d.migrateUserSecrets(userID, box); err != nil {
		return nil, err
	}
	return box, nil
}

// openSealed opens enc:v2 with the user's DEK, enc:v1 with the derived key,
// and returns plaintext unchanged. This is how v0.1.3 rows keep working
// until they are re-sealed.
func (d *DB) openSealed(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if secrets.IsV2(s) {
		if d.Box == nil {
			return "", errors.New("secrets: no DEK")
		}
		return d.Box.Open(s)
	}
	if secrets.IsV1(s) && d.root != nil && d.uid != 0 {
		return d.root.Derive(d.uid).Open(s)
	}
	if d.Box != nil && secrets.IsSealed(s) {
		return d.Box.Open(s)
	}
	return s, nil
}

func (d *DB) migrateUserSecrets(userID int64, dek *secrets.Box) error {
	legacy := d.root.Derive(userID)
	open := func(s string) (string, error) {
		if secrets.IsV2(s) {
			return dek.Open(s)
		}
		if secrets.IsV1(s) {
			return legacy.Open(s)
		}
		return s, nil
	}
	reseal := func(table, col string) error {
		rows, err := d.SQL.Query(`SELECT id, `+col+` FROM `+table+` WHERE user_id=? AND `+col+`!=''`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		type row struct {
			id int64
			v  string
		}
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.v); err != nil {
				return err
			}
			list = append(list, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range list {
			plain, err := open(r.v)
			if err != nil {
				return fmt.Errorf("migrate %s.%s id %d: %w", table, col, r.id, err)
			}
			if secrets.IsV2(r.v) {
				continue
			}
			if _, err := d.SQL.Exec(`UPDATE `+table+` SET `+col+`=? WHERE id=? AND user_id=?`, dek.Seal(plain), r.id, userID); err != nil {
				return err
			}
		}
		return nil
	}
	if err := reseal("accounts", "refresh_token"); err != nil {
		return err
	}
	if err := reseal("accounts", "access_token"); err != nil {
		return err
	}
	if err := reseal("targets", "secret"); err != nil {
		return err
	}
	// Seal previously plain match_json (and re-seal v1 if any).
	rows, err := d.SQL.Query(`SELECT id, match_json FROM routes WHERE user_id=?`, userID)
	if err != nil {
		return err
	}
	type rj struct {
		id  int64
		raw string
	}
	var routes []rj
	for rows.Next() {
		var r rj
		if err := rows.Scan(&r.id, &r.raw); err != nil {
			rows.Close()
			return err
		}
		routes = append(routes, r)
	}
	rows.Close()
	for _, r := range routes {
		plain, err := open(r.raw)
		if err != nil {
			return err
		}
		if secrets.IsV2(r.raw) {
			continue
		}
		if _, err := d.SQL.Exec(`UPDATE routes SET match_json=? WHERE id=? AND user_id=?`, dek.Seal(plain), r.id, userID); err != nil {
			return err
		}
	}
	// Drop leftover bodies/snippets that are not supposed to persist.
	_, _ = d.SQL.Exec(`UPDATE messages SET snippet='' WHERE user_id=?`, userID)
	_, _ = d.SQL.Exec(`UPDATE deliveries SET payload_json='', request_log=CASE WHEN request_log LIKE 'enc:%' THEN '' ELSE request_log END, response_body='' WHERE user_id=?`, userID)
	return nil
}

// RotateDEK mints a new per-user DEK, re-seals ciphertext, and wraps the new
// key with the current KEK. The previous DEK is discarded (crypto-shredded).
func (d *DB) RotateDEK(userID int64) error {
	if userID <= 0 {
		return errors.New("user is required")
	}
	old, err := d.ensureUserBox(userID)
	if err != nil {
		return err
	}
	fresh, dek, err := secrets.NewDEK()
	if err != nil {
		return err
	}
	kek, err := d.kek()
	if err != nil {
		return err
	}
	blob, err := kek.Wrap(dek)
	if err != nil {
		return err
	}
	// Re-seal using old as the opener and fresh as the sealer.
	scoped := d.Use(userID)
	scoped.Box = old
	if err := scoped.resealAll(fresh); err != nil {
		return err
	}
	_, err = d.SQL.Exec(`UPDATE user_keys SET wrapped_dek=?, kek_id=?, rotated_at=? WHERE user_id=?`,
		blob, kek.ID(), now(), userID)
	return err
}

func (d *DB) resealAll(next *secrets.Box) error {
	uid := d.uid
	type col struct{ table, col string }
	for _, c := range []col{
		{"accounts", "refresh_token"},
		{"accounts", "access_token"},
		{"targets", "secret"},
		{"routes", "match_json"},
		{"deliveries", "payload_json"},
	} {
		rows, err := d.SQL.Query(`SELECT id, `+c.col+` FROM `+c.table+` WHERE user_id=? AND `+c.col+`!=''`, uid)
		if err != nil {
			return err
		}
		var ids []int64
		var vals []string
		for rows.Next() {
			var id int64
			var v string
			if err := rows.Scan(&id, &v); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
			vals = append(vals, v)
		}
		rows.Close()
		for i, v := range vals {
			plain, err := d.openSealed(v)
			if err != nil {
				return err
			}
			sealed := next.Seal(plain)
			if _, err := d.SQL.Exec(`UPDATE `+c.table+` SET `+c.col+`=? WHERE id=? AND user_id=?`, sealed, ids[i], uid); err != nil {
				return err
			}
		}
	}
	return nil
}

// RotateKEK re-wraps every stored DEK with next and records the new kek id.
func (d *DB) RotateKEK(next secrets.KEK) error {
	if next == nil {
		return errors.New("secrets: no KEK")
	}
	old, err := d.kek()
	if err != nil {
		return err
	}
	rows, err := d.SQL.Query(`SELECT user_id, wrapped_dek FROM user_keys`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id   int64
		blob string
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.blob); err != nil {
			return err
		}
		list = append(list, r)
	}
	for _, r := range list {
		dek, err := old.Unwrap(r.blob)
		if err != nil {
			return fmt.Errorf("user %d: %w", r.id, err)
		}
		blob, err := next.Wrap(dek)
		if err != nil {
			return err
		}
		if _, err := d.SQL.Exec(`UPDATE user_keys SET wrapped_dek=?, kek_id=?, rotated_at=? WHERE user_id=?`,
			blob, next.ID(), now(), r.id); err != nil {
			return err
		}
	}
	return nil
}

// ShredDEK deletes the wrapped DEK for a user. Ciphertext that remains
// cannot be opened. Called as part of account deletion.
func (d *DB) ShredDEK(userID int64) error {
	_, err := d.SQL.Exec(`DELETE FROM user_keys WHERE user_id=?`, userID)
	return err
}

// HasDEK reports whether a wrapped DEK is stored for the user.
func (d *DB) HasDEK(userID int64) bool {
	var n int
	_ = d.SQL.QueryRow(`SELECT count(*) FROM user_keys WHERE user_id=?`, userID).Scan(&n)
	return n > 0
}
