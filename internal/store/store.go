// Package store is the SQLite state of ghook. Secrets are sealed before they
// are written. Rows returned to the UI never include an opened secret.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/mail"
	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/secrets"

	_ "modernc.org/sqlite"
)

// DB is one open database. wid is the workspace every tenant query is scoped to.
// all is set only for the background worker, which drains every workspace and
// then opens each row with Use.
type DB struct {
	SQL    *sql.DB
	Box    *secrets.Box
	root   *secrets.Box
	Source string
	wid    int64
	all    bool
}

// Open opens (and creates) the database at path and applies the schema.
func Open(path, secretsKey, keyFile string) (*DB, error) {
	box, src, err := secrets.LoadOrCreate(secretsKey, keyFile)
	if err != nil {
		return nil, err
	}
	s, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s.SetMaxOpenConns(1)
	d := &DB{SQL: s, Box: box, root: box, Source: src}
	if err := d.migrate(); err != nil {
		_ = s.Close()
		return nil, err
	}
	id, err := d.DefaultWorkspaceID()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return d.Use(id), nil
}

// Use returns a handle scoped to one workspace. Secrets are sealed with the
// key derived for that workspace.
func (d *DB) Use(id int64) *DB {
	cp := *d
	cp.wid = id
	cp.all = false
	if d.root != nil && id != 0 {
		cp.Box = d.root.Derive(id)
	}
	return &cp
}

// Unscoped is the background worker's view: lists span workspaces. Do not use
// it from a request.
func (d *DB) Unscoped() *DB {
	cp := *d
	cp.all = true
	cp.wid = 0
	if d.root != nil {
		cp.Box = d.root
	}
	return &cp
}

// WorkspaceID is the scope of this handle.
func (d *DB) WorkspaceID() int64 { return d.wid }

func (d *DB) filter(where string) (string, []any) {
	if d.all {
		return where, nil
	}
	if where == "" {
		return " WHERE workspace_id=?", []any{d.wid}
	}
	return where + " AND workspace_id=?", []any{d.wid}
}

// withWS adds the workspace predicate before tail. args are the tail's placeholders.
func (d *DB) withWS(from, tail string, args []any) (string, []any) {
	if d.all {
		if tail == "" {
			return from, args
		}
		return from + " " + tail, args
	}
	q := from + " WHERE workspace_id=?"
	out := append([]any{d.wid}, args...)
	if tail != "" {
		q += " " + tail
	}
	return q, out
}

// Close closes the database.
func (d *DB) Close() error { return d.SQL.Close() }

func now() int64 { return time.Now().Unix() }

// Setting reads a setting or returns def.
func (d *DB) Setting(key, def string) string {
	var v string
	err := d.SQL.QueryRow(`SELECT value FROM settings WHERE workspace_id=? AND key=?`, d.wid, key).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

// SetSetting writes a setting.
func (d *DB) SetSetting(key, value string) error {
	_, err := d.SQL.Exec(`INSERT INTO settings(workspace_id, key, value) VALUES(?, ?, ?)
		ON CONFLICT(workspace_id, key) DO UPDATE SET value=excluded.value`, d.wid, key, value)
	return err
}

// IntSetting reads an integer setting.
func (d *DB) IntSetting(key string, def int) int {
	v := strings.TrimSpace(d.Setting(key, ""))
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscan(v, &n); err != nil {
		return def
	}
	return n
}

// BoolSetting reads a boolean setting. The default is used when unset.
func (d *DB) BoolSetting(key string, def bool) bool {
	v := strings.TrimSpace(d.Setting(key, ""))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// SetSecret stores a sealed value. An empty plain clears it.
func (d *DB) SetSecret(key, plain string) error {
	if plain == "" {
		_, err := d.SQL.Exec(`DELETE FROM settings WHERE workspace_id=? AND key=?`, d.wid, key)
		return err
	}
	return d.SetSetting(key, d.Box.Seal(plain))
}

// OpenSecret opens a sealed setting. Missing is ("", false, nil).
func (d *DB) OpenSecret(key string) (string, bool, error) {
	var raw string
	err := d.SQL.QueryRow(`SELECT value FROM settings WHERE workspace_id=? AND key=?`, d.wid, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := d.Box.Open(raw)
	if err != nil {
		return "", true, err
	}
	return plain, true, nil
}

// Audit appends a configuration-change record. Detail must not contain a secret.
func (d *DB) Audit(actor, action, detail string) error {
	_, err := d.SQL.Exec(`INSERT INTO audit(workspace_id, at, actor, action, detail) VALUES(?, ?, ?, ?, ?)`,
		d.wid, now(), actor, action, detail)
	return err
}

// AuditRow is one audit entry.
type AuditRow struct {
	ID     int64
	At     int64
	Actor  string
	Action string
	Detail string
}

// Audits returns the newest entries.
func (d *DB) Audits(limit int) ([]AuditRow, error) {
	if limit <= 0 {
		limit = 200
	}
	q, args := d.withWS(`SELECT id, at, actor, action, detail FROM audit`, "ORDER BY id DESC LIMIT ?", []any{limit})
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.At, &r.Actor, &r.Action, &r.Detail); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GoogleClientJSON returns the workspace override, or the instance client.
func (d *DB) GoogleClientJSON() (string, bool, error) {
	if d.wid != 0 {
		s, ok, err := d.OpenSecret("google_client_json")
		if err != nil || (ok && s != "") {
			return s, ok && s != "", err
		}
	}
	return d.Instance().OpenSecret("google_client_json")
}

// SetGoogleClientJSON stores the client for this workspace. Use Instance to store the shared one.
func (d *DB) SetGoogleClientJSON(raw string) error { return d.SetSecret("google_client_json", raw) }

// Instance is workspace 0: the session secret and the shared Google client.
func (d *DB) Instance() *DB {
	cp := *d
	cp.wid = 0
	cp.all = false
	if d.root != nil {
		cp.Box = d.root
	}
	return &cp
}

// PubSub is one topic and subscription. The service account JSON is not on this struct.
type PubSub struct {
	ID           int64
	WorkspaceID  int64
	Name         string
	Project      string
	Topic        string
	Subscription string
	Mode         string
	PushAudience string
	PushEmail    string
	UseOAuth     bool
	HasSA        bool
}

// LoadPubSub reads the first connection in this workspace.
func (d *DB) LoadPubSub() PubSub {
	all, err := d.PubSubs()
	if err == nil && len(all) > 0 {
		return all[0]
	}
	p := PubSub{
		Name:         "main",
		Project:      d.Setting("ps_project", ""),
		Topic:        d.Setting("ps_topic", ""),
		Subscription: d.Setting("ps_subscription", ""),
		Mode:         d.Setting("ps_mode", "pull"),
		PushAudience: d.Setting("ps_push_audience", ""),
		PushEmail:    d.Setting("ps_push_email", ""),
		UseOAuth:     d.BoolSetting("ps_use_oauth", false),
	}
	if p.Mode != "push" {
		p.Mode = "pull"
	}
	if _, ok, _ := d.OpenSecret("ps_sa_json"); ok {
		p.HasSA = true
	}
	return p
}

// SavePubSub writes one named connection. An empty name is "main".
func (d *DB) SavePubSub(p PubSub, saJSON string, clearSA bool) error {
	if p.Mode != "push" {
		p.Mode = "pull"
	}
	if strings.TrimSpace(p.Name) == "" {
		p.Name = "main"
	}
	var existing string
	_ = d.SQL.QueryRow(`SELECT sa_json FROM pubsubs WHERE workspace_id=? AND name=?`, d.wid, p.Name).Scan(&existing)
	stored := existing
	switch {
	case clearSA:
		stored = ""
	case strings.TrimSpace(saJSON) != "":
		stored = d.Box.Seal(saJSON)
	}
	oauth := 0
	if p.UseOAuth {
		oauth = 1
	}
	ts := now()
	_, err := d.SQL.Exec(`INSERT INTO pubsubs(workspace_id, name, project, topic, subscription, mode, push_audience, push_email, use_oauth, sa_json, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, name) DO UPDATE SET
		project=excluded.project, topic=excluded.topic, subscription=excluded.subscription, mode=excluded.mode,
		push_audience=excluded.push_audience, push_email=excluded.push_email, use_oauth=excluded.use_oauth,
		sa_json=excluded.sa_json, updated_at=excluded.updated_at`,
		d.wid, strings.TrimSpace(p.Name), strings.TrimSpace(p.Project), strings.TrimSpace(p.Topic), strings.TrimSpace(p.Subscription),
		p.Mode, strings.TrimSpace(p.PushAudience), strings.TrimSpace(p.PushEmail), oauth, stored, ts, ts)
	return err
}

// ServiceAccountJSON opens the service account for this workspace's first connection.
func (d *DB) ServiceAccountJSON() (string, error) {
	var raw string
	err := d.SQL.QueryRow(`SELECT sa_json FROM pubsubs WHERE workspace_id=? AND sa_json!='' ORDER BY id LIMIT 1`, d.wid).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || raw == "" {
		s, ok, oerr := d.OpenSecret("ps_sa_json")
		if !ok {
			return "", oerr
		}
		return s, oerr
	}
	if err != nil {
		return "", err
	}
	return d.Box.Open(raw)
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Account is one connected mailbox. Token fields stay unexported.
type Account struct {
	ID                int64
	Email             string
	Scopes            string
	HistoryID         string
	WatchExpiry       int64
	WatchError        string
	LastNotify        int64
	LastNotifyHistory string
	LastSync          int64
	Disabled          bool
	HasToken          bool
	WorkspaceID       int64
	PubSubID          int64
	refresh           string
	access            string
	accessExp         int64
}

// RefreshToken opens the refresh token.
func (a Account) RefreshToken() string { return a.refresh }

// AccessToken returns the cached access token and its expiry.
func (a Account) AccessToken() (string, int64) { return a.access, a.accessExp }

func scanAccount(sc interface{ Scan(...any) error }) (Account, error) {
	var a Account
	var dis int
	var refresh, access string
	err := sc.Scan(&a.ID, &a.Email, &refresh, &access, &a.accessExp, &a.Scopes, &a.HistoryID,
		&a.WatchExpiry, &a.WatchError, &a.LastNotify, &a.LastNotifyHistory, &a.LastSync, &dis, &a.WorkspaceID, &a.PubSubID)
	if err != nil {
		return a, err
	}
	a.Disabled = dis == 1
	a.refresh = refresh
	a.access = access
	a.HasToken = refresh != ""
	return a, nil
}

const accountCols = `id, email, refresh_token, access_token, access_expiry, scopes, history_id,
	watch_expiry, watch_error, last_notify, last_notify_history, last_sync, disabled, workspace_id, pubsub_id`

// Accounts lists every mailbox.
func (d *DB) Accounts() ([]Account, error) {
	q, args := d.withWS(`SELECT `+accountCols+` FROM accounts`, "ORDER BY email", nil)
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d.openAccount(a))
	}
	return out, rows.Err()
}

// AccountByEmail finds a mailbox.
func (d *DB) AccountByEmail(email string) (Account, bool, error) {
	row := d.SQL.QueryRow(`SELECT `+accountCols+` FROM accounts WHERE lower(email)=lower(?) AND workspace_id=?`, strings.TrimSpace(email), d.wid)
	a, err := scanAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, err
	}
	return d.openAccount(a), true, nil
}

// AccountByID finds a mailbox.
func (d *DB) AccountByID(id int64) (Account, bool, error) {
	q := `SELECT ` + accountCols + ` FROM accounts WHERE id=?`
	args := []any{id}
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	row := d.SQL.QueryRow(q, args...)
	a, err := scanAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, err
	}
	return d.openAccount(a), true, nil
}

func (d *DB) openAccount(a Account) Account {
	if a.refresh != "" {
		if p, err := d.Box.Open(a.refresh); err == nil {
			a.refresh = p
		} else {
			a.refresh = ""
			a.WatchError = "cannot decrypt the refresh token"
		}
	}
	if a.access != "" {
		if p, err := d.Box.Open(a.access); err == nil {
			a.access = p
		} else {
			a.access = ""
		}
	}
	a.HasToken = a.refresh != ""
	return a
}

// SaveAccount inserts or updates a mailbox and its tokens.
func (d *DB) SaveAccount(email, refresh, access string, accessExp int64, scopes, historyID string) (Account, error) {
	email = strings.TrimSpace(email)
	cur, ok, err := d.AccountByEmail(email)
	if err != nil {
		return Account{}, err
	}
	t := now()
	if historyID == "" && ok {
		historyID = cur.HistoryID
	}
	if !ok {
		_, err = d.SQL.Exec(`INSERT INTO accounts(workspace_id, email, refresh_token, access_token, access_expiry, scopes, history_id, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			d.wid, email, d.Box.Seal(refresh), d.Box.Seal(access), accessExp, scopes, historyID, t, t)
	} else {
		if refresh == "" {
			refresh = cur.refresh
		}
		_, err = d.SQL.Exec(`UPDATE accounts SET refresh_token=?, access_token=?, access_expiry=?, scopes=?,
			history_id=CASE WHEN ?!='' THEN ? ELSE history_id END, updated_at=? WHERE id=? AND workspace_id=?`,
			d.Box.Seal(refresh), d.Box.Seal(access), accessExp, scopes, historyID, historyID, t, cur.ID, d.wid)
	}
	if err != nil {
		return Account{}, err
	}
	a, _, err := d.AccountByEmail(email)
	return a, err
}

// UpdateTokens caches a refreshed access token.
func (d *DB) UpdateTokens(id int64, refresh, access string, exp int64) error {
	_, err := d.SQL.Exec(`UPDATE accounts SET refresh_token=?, access_token=?, access_expiry=?, updated_at=? WHERE id=? AND workspace_id=?`,
		d.Box.Seal(refresh), d.Box.Seal(access), exp, now(), id, d.wid)
	return err
}

// SetWatch records a watch result.
func (d *DB) SetWatch(id int64, expiry int64, historyID, errText string) error {
	_, err := d.SQL.Exec(`UPDATE accounts SET watch_expiry=?, watch_error=?,
		history_id=CASE WHEN history_id='' AND ?!='' THEN ? ELSE history_id END, updated_at=? WHERE id=? AND workspace_id=?`,
		expiry, errText, historyID, historyID, now(), id, d.wid)
	return err
}

// SetAccountDisabled pauses or resumes a mailbox.
func (d *DB) SetAccountDisabled(id int64, disabled bool) error {
	v := 0
	if disabled {
		v = 1
	}
	_, err := d.SQL.Exec(`UPDATE accounts SET disabled=?, updated_at=? WHERE id=? AND workspace_id=?`, v, now(), id, d.wid)
	return err
}

// DeleteAccount removes a mailbox. Deliveries are kept.
func (d *DB) DeleteAccount(id int64) error {
	_, err := d.SQL.Exec(`DELETE FROM accounts WHERE id=? AND workspace_id=?`, id, d.wid)
	return err
}

// TouchNotify records that a notification arrived.
func (d *DB) TouchNotify(id int64, history string) error {
	_, err := d.SQL.Exec(`UPDATE accounts SET last_notify=?, last_notify_history=?, updated_at=? WHERE id=? AND workspace_id=?`,
		now(), history, now(), id, d.wid)
	return err
}

// Target is a webhook endpoint. Secret is never populated for the UI; HasSecret says if one is stored.
type Target struct {
	ID          int64
	Name        string
	URL         string
	AuthMode    string
	AuthHeader  string
	Template    string
	IncludeBody bool
	Paused      bool
	QuietStart  string
	QuietEnd    string
	DigestAt    string
	RatePerMin  int
	LastDigest  int64
	HasSecret   bool
	WorkspaceID int64
	secret      string
}

// Secret opens the webhook secret.
func (t Target) Secret() string { return t.secret }

func scanTarget(sc interface{ Scan(...any) error }, box *secrets.Box, open bool) (Target, error) {
	var t Target
	var body, paused int
	var secret string
	err := sc.Scan(&t.ID, &t.Name, &t.URL, &secret, &t.AuthMode, &t.AuthHeader, &t.Template,
		&body, &paused, &t.QuietStart, &t.QuietEnd, &t.DigestAt, &t.RatePerMin, &t.LastDigest, &t.WorkspaceID)
	if err != nil {
		return t, err
	}
	t.IncludeBody = body == 1
	t.Paused = paused == 1
	t.HasSecret = secret != ""
	if open && secret != "" && box != nil {
		p, err := box.Open(secret)
		if err != nil {
			return t, err
		}
		t.secret = p
	}
	if t.AuthMode == "" {
		t.AuthMode = "bearer"
	}
	return t, nil
}

const targetCols = `id, name, url, secret, auth_mode, auth_header, payload_template, include_body, paused,
	quiet_start, quiet_end, digest_at, rate_per_minute, last_digest, workspace_id`

// Targets lists endpoints. Secrets stay sealed.
func (d *DB) Targets() ([]Target, error) {
	q, args := d.withWS(`SELECT `+targetCols+` FROM targets`, "ORDER BY name", nil)
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows, nil, false)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TargetByID loads one endpoint. openSecret opens the secret for delivery.
func (d *DB) TargetByID(id int64, openSecret bool) (Target, bool, error) {
	q := `SELECT ` + targetCols + ` FROM targets WHERE id=?`
	args := []any{id}
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	row := d.SQL.QueryRow(q, args...)
	t, err := scanTarget(row, d.Box, openSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, false, nil
	}
	if err != nil {
		return Target{}, false, err
	}
	return t, true, nil
}

// TargetByName loads one endpoint by its unique name.
func (d *DB) TargetByName(name string, openSecret bool) (Target, bool, error) {
	row := d.SQL.QueryRow(`SELECT `+targetCols+` FROM targets WHERE lower(name)=lower(?) AND workspace_id=?`, strings.TrimSpace(name), d.wid)
	t, err := scanTarget(row, d.Box, openSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, false, nil
	}
	if err != nil {
		return Target{}, false, err
	}
	return t, true, nil
}

// SaveTarget inserts or updates a target. An empty secret keeps the stored one
// unless clearSecret is set.
func (d *DB) SaveTarget(t Target, secret string, clearSecret bool) (Target, error) {
	t.Name = strings.TrimSpace(t.Name)
	t.URL = strings.TrimSpace(t.URL)
	if t.AuthMode != "header" && t.AuthMode != "hmac" {
		t.AuthMode = "bearer"
	}
	cur, ok, err := d.TargetByName(t.Name, true)
	if err != nil {
		return Target{}, err
	}
	if t.ID != 0 && ok && cur.ID != t.ID {
		return Target{}, fmt.Errorf("a target named %s already exists", t.Name)
	}
	if t.ID != 0 && !ok {
		cur, ok, err = d.TargetByID(t.ID, true)
		if err != nil {
			return Target{}, err
		}
	}
	stored := ""
	switch {
	case clearSecret:
		stored = ""
	case secret != "":
		stored = d.Box.Seal(secret)
	case ok:
		stored = d.Box.Seal(cur.secret)
	}
	ts := now()
	body, paused := 0, 0
	if t.IncludeBody {
		body = 1
	}
	if t.Paused {
		paused = 1
	}
	if !ok || (t.ID == 0 && !ok) {
		res, err := d.SQL.Exec(`INSERT INTO targets(workspace_id, name, url, secret, auth_mode, auth_header, payload_template,
			include_body, paused, quiet_start, quiet_end, digest_at, rate_per_minute, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			d.wid, t.Name, t.URL, stored, t.AuthMode, strings.TrimSpace(t.AuthHeader), t.Template,
			body, paused, t.QuietStart, t.QuietEnd, t.DigestAt, t.RatePerMin, ts, ts)
		if err != nil {
			return Target{}, err
		}
		id, _ := res.LastInsertId()
		out, _, err := d.TargetByID(id, false)
		return out, err
	}
	id := t.ID
	if id == 0 {
		id = cur.ID
	}
	_, err = d.SQL.Exec(`UPDATE targets SET name=?, url=?, secret=?, auth_mode=?, auth_header=?, payload_template=?,
		include_body=?, paused=?, quiet_start=?, quiet_end=?, digest_at=?, rate_per_minute=?, updated_at=? WHERE id=? AND workspace_id=?`,
		t.Name, t.URL, stored, t.AuthMode, strings.TrimSpace(t.AuthHeader), t.Template,
		body, paused, t.QuietStart, t.QuietEnd, t.DigestAt, t.RatePerMin, ts, id, d.wid)
	if err != nil {
		return Target{}, err
	}
	out, _, err := d.TargetByID(id, false)
	return out, err
}

// SetTargetPaused flips the pause flag.
func (d *DB) SetTargetPaused(id int64, paused bool) error {
	v := 0
	if paused {
		v = 1
	}
	_, err := d.SQL.Exec(`UPDATE targets SET paused=?, updated_at=? WHERE id=? AND workspace_id=?`, v, now(), id, d.wid)
	return err
}

// SetLastDigest records the last digest send.
func (d *DB) SetLastDigest(id, unix int64) error {
	_, err := d.SQL.Exec(`UPDATE targets SET last_digest=? WHERE id=? AND workspace_id=?`, unix, id, d.wid)
	return err
}

// DeleteTarget removes a target that no route still uses.
func (d *DB) DeleteTarget(id int64) error {
	var n int
	if err := d.SQL.QueryRow(`SELECT count(*) FROM routes WHERE target_id=? AND workspace_id=?`, id, d.wid).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("this target is used by %d route(s)", n)
	}
	_, err := d.SQL.Exec(`DELETE FROM targets WHERE id=? AND workspace_id=?`, id, d.wid)
	return err
}

// Route is a stored rule.
type Route struct {
	ID         int64
	Name       string
	Position   int
	Enabled    bool
	Fallback   bool
	Continue   bool
	TargetID   int64
	TargetName string
	ApplyLabel bool
	Spec       match.Spec
	MatchJSON  string
}

func (r Route) AsMatch() match.Route {
	return match.Route{
		ID: r.ID, Name: r.Name, TargetName: r.TargetName, TargetID: r.TargetID,
		Enabled: r.Enabled, Fallback: r.Fallback, Continue: r.Continue, ApplyLabel: r.ApplyLabel,
		Spec: r.Spec,
	}
}

// Routes returns rules in position order.
func (d *DB) Routes() ([]Route, error) {
	q := `SELECT r.id, r.name, r.position, r.enabled, r.fallback, r.cont, r.target_id,
		COALESCE(t.name, ''), r.apply_label, r.match_json
		FROM routes r LEFT JOIN targets t ON t.id=r.target_id`
	args := []any{}
	if !d.all {
		q += ` WHERE r.workspace_id=?`
		args = append(args, d.wid)
	}
	q += ` ORDER BY r.position, r.id`
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		rt, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}

func scanRoute(sc interface{ Scan(...any) error }) (Route, error) {
	var r Route
	var en, fb, cont, apply int
	if err := sc.Scan(&r.ID, &r.Name, &r.Position, &en, &fb, &cont, &r.TargetID, &r.TargetName, &apply, &r.MatchJSON); err != nil {
		return r, err
	}
	r.Enabled, r.Fallback, r.Continue, r.ApplyLabel = en == 1, fb == 1, cont == 1, apply == 1
	_ = json.Unmarshal([]byte(r.MatchJSON), &r.Spec)
	r.Spec = r.Spec.Normalize()
	return r, nil
}

// RouteByID loads one rule.
func (d *DB) RouteByID(id int64) (Route, bool, error) {
	q := `SELECT r.id, r.name, r.position, r.enabled, r.fallback, r.cont, r.target_id,
		COALESCE(t.name, ''), r.apply_label, r.match_json
		FROM routes r LEFT JOIN targets t ON t.id=r.target_id WHERE r.id=?`
	args := []any{id}
	if !d.all {
		q += ` AND r.workspace_id=?`
		args = append(args, d.wid)
	}
	row := d.SQL.QueryRow(q, args...)
	r, err := scanRoute(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Route{}, false, nil
	}
	if err != nil {
		return Route{}, false, err
	}
	return r, true, nil
}

// SaveRoute inserts or updates a rule.
func (d *DB) SaveRoute(r Route) (Route, error) {
	if err := r.Spec.Validate(); err != nil {
		return Route{}, fmt.Errorf("subject regex: %w", err)
	}
	r.Spec = r.Spec.Normalize()
	raw, err := json.Marshal(r.Spec)
	if err != nil {
		return Route{}, err
	}
	ts := now()
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	if r.ID == 0 {
		var pos int
		_ = d.SQL.QueryRow(`SELECT COALESCE(MAX(position), 0) FROM routes WHERE workspace_id=?`, d.wid).Scan(&pos)
		if r.Position == 0 {
			r.Position = pos + 1
		}
		res, err := d.SQL.Exec(`INSERT INTO routes(workspace_id, name, position, enabled, fallback, cont, target_id, match_json, apply_label, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			d.wid, strings.TrimSpace(r.Name), r.Position, b(r.Enabled), b(r.Fallback), b(r.Continue), r.TargetID, string(raw), b(r.ApplyLabel), ts, ts)
		if err != nil {
			return Route{}, err
		}
		id, _ := res.LastInsertId()
		out, _, err := d.RouteByID(id)
		return out, err
	}
	_, err = d.SQL.Exec(`UPDATE routes SET name=?, enabled=?, fallback=?, cont=?, target_id=?, match_json=?, apply_label=?, updated_at=? WHERE id=? AND workspace_id=?`,
		strings.TrimSpace(r.Name), b(r.Enabled), b(r.Fallback), b(r.Continue), r.TargetID, string(raw), b(r.ApplyLabel), ts, r.ID, d.wid)
	if err != nil {
		return Route{}, err
	}
	out, _, err := d.RouteByID(r.ID)
	return out, err
}

// DeleteRoute removes a rule.
func (d *DB) DeleteRoute(id int64) error {
	_, err := d.SQL.Exec(`DELETE FROM routes WHERE id=? AND workspace_id=?`, id, d.wid)
	return err
}

// ReorderRoutes sets positions from the given id order.
func (d *DB) ReorderRoutes(ids []int64) error {
	tx, err := d.SQL.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for i, id := range ids {
		if _, err := tx.Exec(`UPDATE routes SET position=? WHERE id=? AND workspace_id=?`, i+1, id, d.wid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// StoredMessage is metadata kept for the simulator and the delivery log.
type StoredMessage struct {
	ID            int64
	AccountID     int64
	AccountEmail  string
	GmailID       string
	ThreadID      string
	HistoryID     string
	From          string
	To            string
	Cc            string
	Subject       string
	Snippet       string
	DateMS        int64
	Labels        []string
	Category      string
	HasAttachment bool
}

// AsMail converts stored metadata into a matchable message. Plain is empty.
func (m StoredMessage) AsMail() mail.Message {
	return mail.Message{
		ID: m.GmailID, ThreadID: m.ThreadID, HistoryID: m.HistoryID,
		From: m.From, To: m.To, Cc: m.Cc, Subject: m.Subject, Snippet: m.Snippet,
		Date: time.UnixMilli(m.DateMS).UTC(), Labels: m.Labels, Category: m.Category,
		HasAttachment: m.HasAttachment,
	}
}

// RecentMessages returns the newest stored metadata.
func (d *DB) RecentMessages(n int) ([]StoredMessage, error) {
	if n <= 0 {
		n = 20
	}
	q := `SELECT m.id, m.account_id, COALESCE(a.email, ''), m.gmail_id, m.thread_id, m.history_id,
		m.from_addr, m.to_addr, m.cc_addr, m.subject, m.snippet, m.date_ms, m.labels, m.category, m.has_attachment
		FROM messages m LEFT JOIN accounts a ON a.id=m.account_id`
	args := []any{}
	if !d.all {
		q += ` WHERE m.workspace_id=?`
		args = append(args, d.wid)
	}
	q += ` ORDER BY m.date_ms DESC, m.id DESC LIMIT ?`
	args = append(args, n)
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredMessage
	for rows.Next() {
		m, err := scanMsg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func scanMsg(sc interface{ Scan(...any) error }) (StoredMessage, error) {
	var m StoredMessage
	var labels string
	var att int
	if err := sc.Scan(&m.ID, &m.AccountID, &m.AccountEmail, &m.GmailID, &m.ThreadID, &m.HistoryID,
		&m.From, &m.To, &m.Cc, &m.Subject, &m.Snippet, &m.DateMS, &labels, &m.Category, &att); err != nil {
		return m, err
	}
	m.HasAttachment = att == 1
	_ = json.Unmarshal([]byte(labels), &m.Labels)
	return m, nil
}

// MatchPlan is one delivery to insert for a message.
type MatchPlan struct {
	RouteKey   string
	RouteName  string
	TargetID   int64
	TargetName string
	ApplyLabel bool
}

// QueueAndAdvance stores the message metadata, inserts deliveries that are not
// already queued for that (message, route), and moves the mailbox history id
// forward. It is one transaction: a failure leaves the history id where it was.
func (d *DB) QueueAndAdvance(accountID int64, accountEmail string, msg mail.Message, plans []MatchPlan, newHistory string) (int, error) {
	tx, err := d.SQL.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	labels, _ := json.Marshal(msg.Labels)
	ts := now()
	dateMS := msg.Date.UnixMilli()
	att := 0
	if msg.HasAttachment {
		att = 1
	}
	_, err = tx.Exec(`INSERT INTO messages(workspace_id, account_id, gmail_id, thread_id, history_id, from_addr, to_addr, cc_addr,
		subject, snippet, date_ms, labels, category, has_attachment, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, account_id, gmail_id) DO UPDATE SET
		thread_id=excluded.thread_id, history_id=excluded.history_id, from_addr=excluded.from_addr,
		to_addr=excluded.to_addr, cc_addr=excluded.cc_addr, subject=excluded.subject, snippet=excluded.snippet,
		date_ms=excluded.date_ms, labels=excluded.labels, category=excluded.category, has_attachment=excluded.has_attachment`,
		d.wid, accountID, msg.ID, msg.ThreadID, msg.HistoryID, msg.From, msg.To, msg.Cc, msg.Subject, msg.Snippet,
		dateMS, string(labels), msg.Category, att, ts)
	if err != nil {
		return 0, err
	}
	inserted := 0
	for _, p := range plans {
		key := newID()
		res, err := tx.Exec(`INSERT INTO deliveries(workspace_id, delivery_key, account_id, account_email, gmail_id, thread_id,
			route_key, route_name, target_id, target_name, kind, status, attempts, next_attempt, payload_json, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'mail', 'queued', 0, ?, '', ?, ?)
			ON CONFLICT(workspace_id, account_id, gmail_id, route_key) DO NOTHING`,
			d.wid, key, accountID, accountEmail, msg.ID, msg.ThreadID, p.RouteKey, p.RouteName, p.TargetID, p.TargetName, ts, ts, ts)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		inserted += int(n)
	}
	if newHistory != "" {
		var cur string
		_ = tx.QueryRow(`SELECT history_id FROM accounts WHERE id=? AND workspace_id=?`, accountID, d.wid).Scan(&cur)
		if historyNewer(newHistory, cur) {
			if _, err := tx.Exec(`UPDATE accounts SET history_id=?, last_sync=?, updated_at=? WHERE id=? AND workspace_id=?`,
				newHistory, ts, ts, accountID, d.wid); err != nil {
				return 0, err
			}
		} else if _, err := tx.Exec(`UPDATE accounts SET last_sync=?, updated_at=? WHERE id=? AND workspace_id=?`, ts, ts, accountID, d.wid); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

func historyNewer(next, cur string) bool {
	if cur == "" {
		return next != ""
	}
	if next == "" {
		return false
	}
	// Numeric comparison when both are integers; otherwise a longer id wins only if the prefix matches.
	ai, aok := parseU(cur)
	bi, bok := parseU(next)
	if aok && bok {
		return bi > ai
	}
	return next != cur
}

func parseU(s string) (uint64, bool) {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, s != ""
}

func (d *DB) idClause(id int64) (string, []any) {
	if d.all {
		return "id=?", []any{id}
	}
	return "id=? AND workspace_id=?", []any{id, d.wid}
}

func newID() string { return newKey() }

// Delivery is one outbox row.
type Delivery struct {
	ID             int64
	Key            string
	AccountID      int64
	AccountEmail   string
	GmailID        string
	ThreadID       string
	RouteKey       string
	RouteName      string
	TargetID       int64
	TargetName     string
	Kind           string
	Status         string
	Attempts       int
	NextAttempt    int64
	LastError      string
	RequestLog     string
	ResponseStatus int
	ResponseBody   string
	PayloadJSON    string
	WorkspaceID    int64
	CreatedAt      int64
	UpdatedAt      int64
	SentAt         int64
}

func scanDel(sc interface{ Scan(...any) error }) (Delivery, error) {
	var d Delivery
	err := sc.Scan(&d.ID, &d.Key, &d.AccountID, &d.AccountEmail, &d.GmailID, &d.ThreadID, &d.RouteKey,
		&d.RouteName, &d.TargetID, &d.TargetName, &d.Kind, &d.Status, &d.Attempts, &d.NextAttempt,
		&d.LastError, &d.RequestLog, &d.ResponseStatus, &d.ResponseBody, &d.PayloadJSON, &d.CreatedAt, &d.UpdatedAt, &d.SentAt, &d.WorkspaceID)
	return d, err
}

const delCols = `id, delivery_key, account_id, account_email, gmail_id, thread_id, route_key, route_name,
	target_id, target_name, kind, status, attempts, next_attempt, last_error, request_log, response_status,
	response_body, payload_json, created_at, updated_at, sent_at, workspace_id`

// DueDeliveries returns mail rows ready to send, skipping paused targets,
// digest targets and disabled mailboxes.
func (d *DB) DueDeliveries(nowUnix int64, limit int) ([]Delivery, error) {
	if limit <= 0 {
		limit = 20
	}
	q := `SELECT ` + delCols + ` FROM deliveries
		WHERE status IN ('queued','retry') AND next_attempt<=?
		AND target_id IN (SELECT id FROM targets WHERE paused=0 AND digest_at='' AND workspace_id=deliveries.workspace_id)
		AND (kind!='mail' OR account_id NOT IN (SELECT id FROM accounts WHERE disabled=1 AND workspace_id=deliveries.workspace_id))`
	args := []any{nowUnix}
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	q += ` ORDER BY id LIMIT ?`
	args = append(args, limit)
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDel(rows)
}

// DigestCandidates returns queued rows for one target.
func (d *DB) DigestCandidates(targetID int64, limit int) ([]Delivery, error) {
	q := `SELECT ` + delCols + ` FROM deliveries
		WHERE target_id=? AND status IN ('queued','retry') AND kind='mail'
		AND (account_id NOT IN (SELECT id FROM accounts WHERE disabled=1 AND workspace_id=deliveries.workspace_id))`
	args := []any{targetID}
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	q += ` ORDER BY id LIMIT ?`
	args = append(args, limit)
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDel(rows)
}

func collectDel(rows *sql.Rows) ([]Delivery, error) {
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		d, err := scanDel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeliveryByID loads one row.
func (d *DB) DeliveryByID(id int64) (Delivery, bool, error) {
	q := `SELECT ` + delCols + ` FROM deliveries WHERE id=?`
	args := []any{id}
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	row := d.SQL.QueryRow(q, args...)
	del, err := scanDel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, false, nil
	}
	if err != nil {
		return Delivery{}, false, err
	}
	return del, true, nil
}

// Deliveries lists the log, newest first, with optional filters.
func (d *DB) Deliveries(status, route, target string, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `SELECT ` + delCols + ` FROM deliveries WHERE 1=1`
	var args []any
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	if status != "" {
		q += ` AND status=?`
		args = append(args, status)
	}
	if route != "" {
		q += ` AND route_name=?`
		args = append(args, route)
	}
	if target != "" {
		q += ` AND target_name=?`
		args = append(args, target)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	return collectDel(rows)
}

// Claim moves a row to inflight if it is still queued. ok is false when another worker took it.
func (d *DB) Claim(id, nowUnix int64) (bool, error) {
	clause, args := d.idClause(id)
	res, err := d.SQL.Exec(`UPDATE deliveries SET status='inflight', updated_at=? WHERE `+clause+` AND status IN ('queued','retry')`, append([]any{nowUnix}, args...)...)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Postpone puts a claimed or queued row back until unix.
func (d *DB) Postpone(id, until int64) error {
	clause, args := d.idClause(id)
	_, err := d.SQL.Exec(`UPDATE deliveries SET status='queued', next_attempt=?, updated_at=? WHERE `+clause+` AND status IN ('queued','retry','inflight')`,
		append([]any{until, now()}, args...)...)
	return err
}

// Finish records the outcome of a send.
func (d *DB) Finish(id int64, status string, attempts int, next int64, lastErr, reqLog string, respStatus int, respBody string) error {
	sent := int64(0)
	if status == "sent" {
		sent = now()
	}
	clause, args := d.idClause(id)
	_, err := d.SQL.Exec(`UPDATE deliveries SET status=?, attempts=?, next_attempt=?, last_error=?, request_log=?,
		response_status=?, response_body=?, updated_at=?, sent_at=CASE WHEN ?>0 THEN ? ELSE sent_at END WHERE `+clause,
		append([]any{status, attempts, next, lastErr, reqLog, respStatus, respBody, now(), sent, sent}, args...)...)
	return err
}

// InsertDelivery inserts a row that is not a matched Gmail route (a test or a notification).
func (d *DB) InsertDelivery(del Delivery) (int64, error) {
	if del.Key == "" {
		del.Key = newKey()
	}
	if del.Status == "" {
		del.Status = "queued"
	}
	if del.Kind == "" {
		del.Kind = "mail"
	}
	ts := now()
	if del.NextAttempt == 0 {
		del.NextAttempt = ts
	}
	res, err := d.SQL.Exec(`INSERT INTO deliveries(workspace_id, delivery_key, account_id, account_email, gmail_id, thread_id,
		route_key, route_name, target_id, target_name, kind, status, attempts, next_attempt, last_error,
		request_log, response_status, response_body, payload_json, created_at, updated_at, sent_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.wid, del.Key, del.AccountID, del.AccountEmail, del.GmailID, del.ThreadID, del.RouteKey, del.RouteName,
		del.TargetID, del.TargetName, del.Kind, del.Status, del.Attempts, del.NextAttempt, del.LastError,
		del.RequestLog, del.ResponseStatus, del.ResponseBody, del.PayloadJSON, ts, ts, del.SentAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Replay re-queues a delivery. newKey mints a fresh idempotency id.
func (d *DB) Replay(id int64, newKey bool) error {
	keySQL := ""
	if newKey {
		keySQL = `, delivery_key=?`
	}
	clause, args := d.idClause(id)
	q := `UPDATE deliveries SET status='queued', attempts=0, next_attempt=?, last_error='', updated_at=?` + keySQL + ` WHERE ` + clause
	ts := now()
	if newKey {
		_, err := d.SQL.Exec(q, append([]any{ts, ts, freshKey()}, args...)...)
		return err
	}
	_, err := d.SQL.Exec(q, append([]any{ts, ts}, args...)...)
	return err
}

// ReplayWindow re-queues sent or dead deliveries matching the filter.
func (d *DB) ReplayWindow(route, target string, since, until int64) (int, error) {
	q := `UPDATE deliveries SET status='queued', attempts=0, next_attempt=?, last_error='', delivery_key=delivery_key||'-r'||?, updated_at=?
		WHERE status IN ('sent','dead','retry')`
	ts := now()
	args := []any{ts, ts, ts}
	if route != "" {
		q += ` AND route_name=?`
		args = append(args, route)
	}
	if target != "" {
		q += ` AND target_name=?`
		args = append(args, target)
	}
	if since > 0 {
		q += ` AND created_at>=?`
		args = append(args, since)
	}
	if until > 0 {
		q += ` AND created_at<=?`
		args = append(args, until)
	}
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	res, err := d.SQL.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// HasNotify reports whether a notification row with this route key already exists.
func (d *DB) HasNotify(routeKey string) bool {
	var n int
	q := `SELECT count(*) FROM deliveries WHERE route_key=? AND kind='notify'`
	args := []any{routeKey}
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	_ = d.SQL.QueryRow(q, args...).Scan(&n)
	return n > 0
}

// Counts is the dashboard summary.
type Counts struct {
	Queued int
	Retry  int
	Dead   int
	Sent   int
}

// DeliveryCounts groups the outbox by status.
func (d *DB) DeliveryCounts() (Counts, error) {
	var c Counts
	q := `SELECT status, count(*) FROM deliveries`
	args := []any{}
	if !d.all {
		q += ` WHERE workspace_id=?`
		args = append(args, d.wid)
	}
	q += ` GROUP BY status`
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return c, err
		}
		switch st {
		case "queued", "inflight":
			c.Queued += n
		case "retry":
			c.Retry += n
		case "dead":
			c.Dead += n
		case "sent":
			c.Sent += n
		}
	}
	return c, rows.Err()
}

// Stat is a name and a count.
type Stat struct {
	Name  string
	Count int
}

// RouteStats counts deliveries per route.
func (d *DB) RouteStats() ([]Stat, error) { return d.groupStats("route_name") }

// TargetStats counts deliveries per target.
func (d *DB) TargetStats() ([]Stat, error) { return d.groupStats("target_name") }

func (d *DB) groupStats(col string) ([]Stat, error) {
	q := `SELECT ` + col + `, count(*) FROM deliveries`
	var args []any
	if !d.all {
		q += ` WHERE workspace_id=?`
		args = append(args, d.wid)
	}
	q += ` GROUP BY ` + col + ` ORDER BY count(*) DESC`
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stat
	for rows.Next() {
		var s Stat
		if err := rows.Scan(&s.Name, &s.Count); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ResetInflight returns rows left inflight by a crash to the queue.
func (d *DB) ResetInflight() error {
	q := `UPDATE deliveries SET status='queued' WHERE status='inflight'`
	args := []any{}
	if !d.all {
		q += ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	_, err := d.SQL.Exec(q, args...)
	return err
}

// Purge deletes metadata older than the retention window.
func (d *DB) Purge(before int64) (int, error) {
	where := ""
	args := []any{before}
	if !d.all {
		where = ` AND workspace_id=?`
		args = append(args, d.wid)
	}
	res, err := d.SQL.Exec(`DELETE FROM deliveries WHERE created_at<? AND status IN ('sent','dead')`+where, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	msgWhere := ""
	msgArgs := []any{before}
	if !d.all {
		msgWhere = ` AND workspace_id=?`
		msgArgs = append(msgArgs, d.wid)
	}
	res, err = d.SQL.Exec(`DELETE FROM messages WHERE created_at<? AND gmail_id NOT IN (SELECT gmail_id FROM deliveries)`+msgWhere, msgArgs...)
	if err != nil {
		return int(n), err
	}
	m, _ := res.RowsAffected()
	aud := `DELETE FROM audit WHERE at<?`
	audArgs := []any{before}
	if !d.all {
		aud += ` AND workspace_id=?`
		audArgs = append(audArgs, d.wid)
	}
	_, _ = d.SQL.Exec(aud, audArgs...)
	return int(n + m), nil
}

// MessageForDelivery loads stored metadata for a gmail id.
func (d *DB) MessageForDelivery(accountID int64, gmailID string) (StoredMessage, bool, error) {
	q := `SELECT m.id, m.account_id, COALESCE(a.email, ''), m.gmail_id, m.thread_id, m.history_id,
		m.from_addr, m.to_addr, m.cc_addr, m.subject, m.snippet, m.date_ms, m.labels, m.category, m.has_attachment
		FROM messages m LEFT JOIN accounts a ON a.id=m.account_id
		WHERE m.account_id=? AND m.gmail_id=?`
	args := []any{accountID, gmailID}
	if !d.all {
		q += ` AND m.workspace_id=?`
		args = append(args, d.wid)
	}
	row := d.SQL.QueryRow(q, args...)
	m, err := scanMsg(row)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredMessage{}, false, nil
	}
	if err != nil {
		return StoredMessage{}, false, err
	}
	return m, true, nil
}

func freshKey() string { return newKey() }

func newKey() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return "gh_" + base64.RawURLEncoding.EncodeToString(b)
}
