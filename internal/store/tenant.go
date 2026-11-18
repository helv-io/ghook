package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrNotAllowed means this identity is not a member and was not provisioned.
var ErrNotAllowed = errors.New("not a member of any workspace")

// Workspace is one tenant.
type Workspace struct {
	ID        int64
	Name      string
	CreatedAt int64
}

// User is an identity from OIDC, a proxy header, or the implicit admin.
type User struct {
	ID            int64
	Subject       string
	Email         string
	Name          string
	InstanceAdmin bool
}

// Membership is a user's role in one workspace.
type Membership struct {
	UserID      int64
	WorkspaceID int64
	Role        string
	Email       string
	Name        string
	Subject     string
}

// DefaultWorkspaceID is the "Default" workspace created for a single-tenant database.
func (d *DB) DefaultWorkspaceID() (int64, error) {
	var id int64
	err := d.SQL.QueryRow(`SELECT id FROM workspaces WHERE name='Default' ORDER BY id LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = d.SQL.QueryRow(`SELECT id FROM workspaces ORDER BY id LIMIT 1`).Scan(&id)
	}
	return id, err
}

// Workspaces lists every workspace.
func (d *DB) Workspaces() ([]Workspace, error) {
	rows, err := d.SQL.Query(`SELECT id, name, created_at FROM workspaces ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Workspace
	for rows.Next() {
		var w Workspace
		if err := rows.Scan(&w.ID, &w.Name, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// CreateWorkspace adds a workspace and makes the user its owner.
func (d *DB) CreateWorkspace(name string, ownerID int64) (Workspace, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Workspace{}, errors.New("a workspace needs a name")
	}
	res, err := d.SQL.Exec(`INSERT INTO workspaces(name, created_at) VALUES(?, ?)`, name, time.Now().Unix())
	if err != nil {
		return Workspace{}, err
	}
	id, _ := res.LastInsertId()
	if ownerID != 0 {
		if err := d.SetMember(id, ownerID, "owner"); err != nil {
			return Workspace{}, err
		}
	}
	return Workspace{ID: id, Name: name}, nil
}

// WorkspaceByRef finds a workspace by numeric id or by name (case-insensitive).
func (d *DB) WorkspaceByRef(ref string) (Workspace, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Workspace{}, errors.New("workspace is required")
	}
	var w Workspace
	var err error
	if id, perr := strconv.ParseInt(ref, 10, 64); perr == nil && id > 0 {
		err = d.SQL.QueryRow(`SELECT id, name, created_at FROM workspaces WHERE id=?`, id).Scan(&w.ID, &w.Name, &w.CreatedAt)
	} else {
		err = d.SQL.QueryRow(`SELECT id, name, created_at FROM workspaces WHERE lower(name)=lower(?)`, ref).Scan(&w.ID, &w.Name, &w.CreatedAt)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Workspace{}, fmt.Errorf("workspace %q not found", ref)
	}
	return w, err
}

// UserCount is the number of identities.
func (d *DB) UserCount() int {
	var n int
	_ = d.SQL.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n
}

// WorkspaceCount is the number of workspaces.
func (d *DB) WorkspaceCount() int {
	var n int
	_ = d.SQL.QueryRow(`SELECT count(*) FROM workspaces`).Scan(&n)
	return n
}

// SingleTenant is true when the UI should hide the switcher and membership screens.
func (d *DB) SingleTenant() bool {
	return d.UserCount() <= 1 && d.WorkspaceCount() <= 1
}

// UserBySubject finds an identity.
func (d *DB) UserBySubject(subject string) (User, bool, error) {
	row := d.SQL.QueryRow(`SELECT id, subject, email, name, instance_admin FROM users WHERE subject=?`, subject)
	var u User
	var admin int
	err := row.Scan(&u.ID, &u.Subject, &u.Email, &u.Name, &admin)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	u.InstanceAdmin = admin == 1
	return u, true, nil
}

// UserByEmail finds an identity by email, case insensitive.
func (d *DB) UserByEmail(email string) (User, bool, error) {
	row := d.SQL.QueryRow(`SELECT id, subject, email, name, instance_admin FROM users WHERE lower(email)=lower(?) AND email!=''`, strings.TrimSpace(email))
	var u User
	var admin int
	err := row.Scan(&u.ID, &u.Subject, &u.Email, &u.Name, &admin)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	u.InstanceAdmin = admin == 1
	return u, true, nil
}

// EnsureUser records an identity. The first user becomes the instance admin and
// owner of every existing workspace. auto creates a later user; otherwise only
// an invite (matched by email) or an existing row is accepted.
func (d *DB) EnsureUser(subject, email, name string, auto bool) (User, error) {
	subject = strings.TrimSpace(subject)
	email = strings.TrimSpace(email)
	name = strings.TrimSpace(name)
	if subject == "" {
		return User{}, errors.New("missing subject")
	}
	if cur, ok, err := d.UserBySubject(subject); err != nil || ok {
		if err != nil {
			return User{}, err
		}
		_, _ = d.SQL.Exec(`UPDATE users SET email=CASE WHEN ?!='' THEN ? ELSE email END, name=CASE WHEN ?!='' THEN ? ELSE name END WHERE id=?`,
			email, email, name, name, cur.ID)
		if email != "" {
			_ = d.applyInvites(cur.ID, email)
		}
		cur, _, _ = d.UserBySubject(subject)
		return cur, nil
	}
	// Same person arriving once via the LAN fallback and once via the header.
	if email == "" {
		if byName, ok, _ := d.UserBySubject(subject); ok {
			return byName, nil
		}
	}
	first := d.UserCount() == 0
	if !first && !auto {
		if email == "" {
			return User{}, ErrNotAllowed
		}
		var n int
		_ = d.SQL.QueryRow(`SELECT count(*) FROM invites WHERE lower(email)=lower(?)`, email).Scan(&n)
		if n == 0 {
			if _, ok, _ := d.UserByEmail(email); !ok {
				return User{}, ErrNotAllowed
			}
		}
	}
	res, err := d.SQL.Exec(`INSERT INTO users(subject, email, name, instance_admin, created_at) VALUES(?, ?, ?, ?, ?)`,
		subject, email, name, boolInt(first), time.Now().Unix())
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	if first {
		ws, _ := d.Workspaces()
		for _, w := range ws {
			_ = d.SetMember(w.ID, id, "owner")
		}
	} else if email != "" {
		_ = d.applyInvites(id, email)
	}
	u, _, err := d.UserBySubject(subject)
	return u, err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (d *DB) applyInvites(userID int64, email string) error {
	rows, err := d.SQL.Query(`SELECT id, workspace_id, role FROM invites WHERE lower(email)=lower(?)`, email)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id, ws int64
		var role string
		if err := rows.Scan(&id, &ws, &role); err != nil {
			return err
		}
		if err := d.SetMember(ws, userID, role); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	for _, id := range ids {
		_, _ = d.SQL.Exec(`DELETE FROM invites WHERE id=?`, id)
	}
	return rows.Err()
}

// SetMember writes a role. Empty role removes the membership.
func (d *DB) SetMember(workspaceID, userID int64, role string) error {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" || role == "remove" {
		_, err := d.SQL.Exec(`DELETE FROM memberships WHERE workspace_id=? AND user_id=?`, workspaceID, userID)
		return err
	}
	if role != "owner" && role != "editor" && role != "viewer" {
		return errors.New("role must be owner, editor, or viewer")
	}
	_, err := d.SQL.Exec(`INSERT INTO memberships(workspace_id, user_id, role) VALUES(?, ?, ?)
		ON CONFLICT(user_id, workspace_id) DO UPDATE SET role=excluded.role`, workspaceID, userID, role)
	return err
}

// Invite records an email that should join a workspace on first sign-in.
func (d *DB) Invite(workspaceID int64, email, role string) error {
	email = strings.TrimSpace(email)
	role = strings.ToLower(strings.TrimSpace(role))
	if email == "" {
		return errors.New("an invite needs an email")
	}
	if role != "owner" && role != "editor" && role != "viewer" {
		role = "viewer"
	}
	if u, ok, _ := d.UserByEmail(email); ok {
		return d.SetMember(workspaceID, u.ID, role)
	}
	_, err := d.SQL.Exec(`INSERT INTO invites(workspace_id, email, role, created_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(workspace_id, email) DO UPDATE SET role=excluded.role`, workspaceID, email, role, time.Now().Unix())
	return err
}

// Role is the user's role in a workspace. Instance admins are owners everywhere.
func (d *DB) Role(userID, workspaceID int64) (string, bool) {
	var admin int
	_ = d.SQL.QueryRow(`SELECT instance_admin FROM users WHERE id=?`, userID).Scan(&admin)
	if admin == 1 {
		return "owner", true
	}
	var role string
	err := d.SQL.QueryRow(`SELECT role FROM memberships WHERE user_id=? AND workspace_id=?`, userID, workspaceID).Scan(&role)
	if err != nil || role == "" {
		return "", false
	}
	return role, true
}

// MemberWorkspaces lists workspaces a user can open.
func (d *DB) MemberWorkspaces(userID int64) ([]Workspace, error) {
	var admin int
	_ = d.SQL.QueryRow(`SELECT instance_admin FROM users WHERE id=?`, userID).Scan(&admin)
	if admin == 1 {
		return d.Workspaces()
	}
	rows, err := d.SQL.Query(`SELECT w.id, w.name, w.created_at FROM workspaces w
		JOIN memberships m ON m.workspace_id=w.id WHERE m.user_id=? ORDER BY w.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Workspace
	for rows.Next() {
		var w Workspace
		if err := rows.Scan(&w.ID, &w.Name, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Members lists a workspace.
func (d *DB) Members(workspaceID int64) ([]Membership, error) {
	rows, err := d.SQL.Query(`SELECT m.user_id, m.workspace_id, m.role, u.email, u.name, u.subject
		FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=? ORDER BY u.email, u.subject`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.UserID, &m.WorkspaceID, &m.Role, &m.Email, &m.Name, &m.Subject); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AccountsByEmail finds every mailbox with this address, across workspaces.
func (d *DB) AccountsByEmail(email string) ([]Account, error) {
	rows, err := d.SQL.Query(`SELECT `+accountCols+` FROM accounts WHERE lower(email)=lower(?)`, strings.TrimSpace(email))
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
		out = append(out, d.Use(a.WorkspaceID).openAccount(a))
	}
	return out, rows.Err()
}

// PubSubs lists the workspace's subscriptions. An unscoped handle lists all of them.
func (d *DB) PubSubs() ([]PubSub, error) {
	q := `SELECT id, workspace_id, name, project, topic, subscription, mode, push_audience, push_email, use_oauth, sa_json FROM pubsubs`
	var args []any
	if !d.all {
		q += ` WHERE workspace_id=?`
		args = append(args, d.wid)
	}
	q += ` ORDER BY id`
	rows, err := d.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PubSub
	for rows.Next() {
		var p PubSub
		var oauth int
		var sa string
		if err := rows.Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Project, &p.Topic, &p.Subscription, &p.Mode, &p.PushAudience, &p.PushEmail, &oauth, &sa); err != nil {
			return nil, err
		}
		p.UseOAuth = oauth == 1
		p.HasSA = sa != ""
		if p.Mode != "push" {
			p.Mode = "pull"
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PubSubByID loads one connection in this workspace.
func (d *DB) PubSubByID(id int64) (PubSub, bool, error) {
	all, err := d.PubSubs()
	if err != nil {
		return PubSub{}, false, err
	}
	for _, p := range all {
		if p.ID == id {
			return p, true, nil
		}
	}
	return PubSub{}, false, nil
}
