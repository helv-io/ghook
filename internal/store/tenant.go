package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrNotAllowed means the caller may not see or change that row.
var ErrNotAllowed = errors.New("not allowed")

// User is a signed-in Google identity. Each user owns their own data.
type User struct {
	ID        int64
	Subject   string
	Email     string
	Name      string
	CreatedAt int64
	LastLogin int64
}

// UpsertUser records a Google identity. A new subject becomes a new user.
func (d *DB) UpsertUser(subject, email, name string) (User, error) {
	subject = strings.TrimSpace(subject)
	email = strings.TrimSpace(email)
	name = strings.TrimSpace(name)
	if subject == "" {
		return User{}, errors.New("missing subject")
	}
	now := time.Now().Unix()
	if cur, ok, err := d.UserBySubject(subject); err != nil {
		return User{}, err
	} else if ok {
		_, err := d.SQL.Exec(`UPDATE users SET email=CASE WHEN ?!='' THEN ? ELSE email END, name=CASE WHEN ?!='' THEN ? ELSE name END, last_login=? WHERE id=?`,
			email, email, name, name, now, cur.ID)
		if err != nil {
			return User{}, err
		}
		cur, _, err = d.UserBySubject(subject)
		return cur, err
	}
	res, err := d.SQL.Exec(`INSERT INTO users(subject, email, name, created_at, last_login) VALUES(?, ?, ?, ?, ?)`,
		subject, email, name, now, now)
	if err != nil {
		return User{}, err
	}
	_, _ = res.LastInsertId()
	u, _, err := d.UserBySubject(subject)
	return u, err
}

// UserBySubject finds an identity by Google subject.
func (d *DB) UserBySubject(subject string) (User, bool, error) {
	return d.scanUser(d.SQL.QueryRow(`SELECT id, subject, email, name, created_at, last_login FROM users WHERE subject=?`, subject))
}

// UserByEmail finds an identity by email, case insensitive.
func (d *DB) UserByEmail(email string) (User, bool, error) {
	return d.scanUser(d.SQL.QueryRow(`SELECT id, subject, email, name, created_at, last_login FROM users WHERE lower(email)=lower(?) AND email!=''`, strings.TrimSpace(email)))
}

// UserByRef finds a user by numeric id or email.
func (d *DB) UserByRef(ref string) (User, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return User{}, errors.New("user is required")
	}
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil && id > 0 {
		u, ok, err := d.UserByID(id)
		if err != nil {
			return User{}, err
		}
		if !ok {
			return User{}, fmt.Errorf("user %d not found", id)
		}
		return u, nil
	}
	u, ok, err := d.UserByEmail(ref)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, fmt.Errorf("user %q not found", ref)
	}
	return u, nil
}

// UserByID loads a user.
func (d *DB) UserByID(id int64) (User, bool, error) {
	return d.scanUser(d.SQL.QueryRow(`SELECT id, subject, email, name, created_at, last_login FROM users WHERE id=?`, id))
}

func (d *DB) scanUser(row *sql.Row) (User, bool, error) {
	var u User
	err := row.Scan(&u.ID, &u.Subject, &u.Email, &u.Name, &u.CreatedAt, &u.LastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// Users lists every user. Background jobs only.
func (d *DB) Users() ([]User, error) {
	rows, err := d.SQL.Query(`SELECT id, subject, email, name, created_at, last_login FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Subject, &u.Email, &u.Name, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserCount is the number of users.
func (d *DB) UserCount() int {
	var n int
	_ = d.SQL.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n
}

// EnsureAndUse upserts the user and returns a handle scoped to them.
func (d *DB) EnsureAndUse(subject, email, name string) (*DB, User, error) {
	u, err := d.UpsertUser(subject, email, name)
	if err != nil {
		return nil, User{}, err
	}
	return d.Use(u.ID), u, nil
}

// TargetCount is the number of targets in this scope.
func (d *DB) TargetCount() int {
	var n int
	q, args := d.withUser(`SELECT count(*) FROM targets`, "", nil)
	_ = d.SQL.QueryRow(q, args...).Scan(&n)
	return n
}

// RouteCount is the number of routes in this scope.
func (d *DB) RouteCount() int {
	var n int
	q, args := d.withUser(`SELECT count(*) FROM routes`, "", nil)
	_ = d.SQL.QueryRow(q, args...).Scan(&n)
	return n
}

// DeliveriesSince counts deliveries created at or after unix in this scope.
func (d *DB) DeliveriesSince(unix int64) int {
	var n int
	if d.all {
		_ = d.SQL.QueryRow(`SELECT count(*) FROM deliveries WHERE created_at>=?`, unix).Scan(&n)
		return n
	}
	_ = d.SQL.QueryRow(`SELECT count(*) FROM deliveries WHERE user_id=? AND created_at>=?`, d.uid, unix).Scan(&n)
	return n
}

// ErrQuota is returned when a per-user limit would be exceeded.
type ErrQuota struct {
	Kind string
	Max  int
}

func (e ErrQuota) Error() string {
	return fmt.Sprintf("%s limit reached (%d)", e.Kind, e.Max)
}

// DeleteUserData removes the user and every row they own. The caller should
// stop the Gmail watch and revoke the Google token first.
func (d *DB) DeleteUserData(userID int64) error {
	if userID <= 0 {
		return errors.New("user is required")
	}
	tx, err := d.SQL.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Destroy the DEK first so leftover ciphertext is unreadable if the
	// rest of the transaction is interrupted after a later statement.
	if _, err := tx.Exec(`DELETE FROM user_keys WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM deliveries WHERE user_id=?`,
		`DELETE FROM messages WHERE user_id=?`,
		`DELETE FROM routes WHERE user_id=?`,
		`DELETE FROM targets WHERE user_id=?`,
		`DELETE FROM accounts WHERE user_id=?`,
		`DELETE FROM settings WHERE user_id=?`,
		`DELETE FROM audit WHERE user_id=?`,
		`DELETE FROM users WHERE id=?`,
	} {
		if _, err := tx.Exec(q, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AccountsByEmail finds mailboxes across users. The pull loop uses this to
// route a Pub/Sub notification by emailAddress.
func (d *DB) AccountsByEmail(email string) ([]Account, error) {
	rows, err := d.SQL.Query(`SELECT `+accountCols+` FROM accounts WHERE lower(email)=lower(?)`, strings.TrimSpace(email))
	if err != nil {
		return nil, err
	}
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	// Use queries user_keys; the DB has MaxOpenConns(1), so the
	// account rows must be closed first or this deadlocks.
	for i := range out {
		out[i] = d.Use(out[i].UserID).openAccount(out[i])
	}
	return out, nil
}
