// Package bundle imports and exports routes and targets as YAML.
// Secrets are omitted unless a passphrase is supplied, in which case they are
// sealed with that passphrase and not with the server key.
package bundle

import (
	"fmt"
	"strings"

	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/secrets"
	"github.com/helv-io/ghook/internal/store"
	"gopkg.in/yaml.v3"
)

// File is the on-disk document.
type File struct {
	Version int      `yaml:"version"`
	Targets []Target `yaml:"targets"`
	Routes  []Route  `yaml:"routes"`
}

// Target is a webhook without an opened secret unless it was sealed for export.
type Target struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	AuthMode    string `yaml:"auth_mode,omitempty"`
	AuthHeader  string `yaml:"auth_header,omitempty"`
	Secret      string `yaml:"secret,omitempty"`
	IncludeBody bool   `yaml:"include_body,omitempty"`
	Paused      bool   `yaml:"paused,omitempty"`
	QuietStart  string `yaml:"quiet_start,omitempty"`
	QuietEnd    string `yaml:"quiet_end,omitempty"`
	DigestAt    string `yaml:"digest_at,omitempty"`
	RatePerMin  int    `yaml:"rate_per_minute,omitempty"`
	Template    string `yaml:"payload_template,omitempty"`
}

// Route is a rule. Target is the target's name.
type Route struct {
	Name       string     `yaml:"name"`
	Target     string     `yaml:"target"`
	Enabled    bool       `yaml:"enabled"`
	Fallback   bool       `yaml:"fallback,omitempty"`
	Continue   bool       `yaml:"continue,omitempty"`
	ApplyLabel bool       `yaml:"apply_label,omitempty"`
	Match      match.Spec `yaml:"match,omitempty"`
}

// Export writes routes and targets. A passphrase seals secrets into the file.
// Without one, secrets are left out.
func Export(db *store.DB, passphrase string) ([]byte, error) {
	var box *secrets.Box
	if strings.TrimSpace(passphrase) != "" {
		b, err := secrets.FromString(passphrase)
		if err != nil {
			return nil, err
		}
		box = b
	}
	targets, err := db.Targets()
	if err != nil {
		return nil, err
	}
	f := File{Version: 1}
	for _, t := range targets {
		item := Target{
			Name: t.Name, URL: t.URL, AuthMode: t.AuthMode, AuthHeader: t.AuthHeader,
			IncludeBody: t.IncludeBody, Paused: t.Paused, QuietStart: t.QuietStart,
			QuietEnd: t.QuietEnd, DigestAt: t.DigestAt, RatePerMin: t.RatePerMin, Template: t.Template,
		}
		if box != nil && t.HasSecret {
			full, _, err := db.TargetByID(t.ID, true)
			if err != nil {
				return nil, err
			}
			item.Secret = box.Seal(full.Secret())
		}
		f.Targets = append(f.Targets, item)
	}
	routes, err := db.Routes()
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		f.Routes = append(f.Routes, Route{
			Name: r.Name, Target: r.TargetName, Enabled: r.Enabled, Fallback: r.Fallback,
			Continue: r.Continue, ApplyLabel: r.ApplyLabel, Match: r.Spec,
		})
	}
	return yaml.Marshal(f)
}

// Import creates or updates targets and routes by name. An empty secret does
// not clear a stored one. Sealed secrets need the passphrase.
func Import(db *store.DB, raw []byte, passphrase string) (string, error) {
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return "", err
	}
	var box *secrets.Box
	if strings.TrimSpace(passphrase) != "" {
		b, err := secrets.FromString(passphrase)
		if err != nil {
			return "", err
		}
		box = b
	}
	nT, nR := 0, 0
	for _, t := range f.Targets {
		if strings.TrimSpace(t.Name) == "" || strings.TrimSpace(t.URL) == "" {
			return "", fmt.Errorf("every target needs a name and a url")
		}
		secret := ""
		if t.Secret != "" {
			if secrets.IsSealed(t.Secret) {
				if box == nil {
					return "", fmt.Errorf("target %s has an encrypted secret; enter the passphrase", t.Name)
				}
				plain, err := box.Open(t.Secret)
				if err != nil {
					return "", fmt.Errorf("target %s: %w", t.Name, err)
				}
				secret = plain
			} else {
				secret = t.Secret
			}
		}
		cur, ok, err := db.TargetByName(t.Name, false)
		if err != nil {
			return "", err
		}
		in := store.Target{
			Name: t.Name, URL: t.URL, AuthMode: t.AuthMode, AuthHeader: t.AuthHeader,
			Template: t.Template, IncludeBody: t.IncludeBody, Paused: t.Paused,
			QuietStart: t.QuietStart, QuietEnd: t.QuietEnd, DigestAt: t.DigestAt, RatePerMin: t.RatePerMin,
		}
		if ok {
			in.ID = cur.ID
		}
		if _, err := db.SaveTarget(in, secret, false); err != nil {
			return "", err
		}
		nT++
	}
	for i, r := range f.Routes {
		if strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.Target) == "" {
			return "", fmt.Errorf("every route needs a name and a target")
		}
		tg, ok, err := db.TargetByName(r.Target, false)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("route %s points at unknown target %s", r.Name, r.Target)
		}
		rt := store.Route{
			Name: r.Name, Position: i + 1, Enabled: r.Enabled, Fallback: r.Fallback,
			Continue: r.Continue, ApplyLabel: r.ApplyLabel, TargetID: tg.ID, Spec: r.Match,
		}
		routes, _ := db.Routes()
		for _, existing := range routes {
			if strings.EqualFold(existing.Name, r.Name) {
				rt.ID = existing.ID
				rt.Position = existing.Position
			}
		}
		if _, err := db.SaveRoute(rt); err != nil {
			return "", err
		}
		nR++
	}
	return fmt.Sprintf("imported %d target(s) and %d route(s)", nT, nR), nil
}
