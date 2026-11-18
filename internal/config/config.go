// Package config loads the few settings that have to exist before the database
// is open. Everything else is a WebUI setting stored in SQLite.
package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Version is the release stamped into the UI and the User-Agent.
const Version = "0.1.2"

// Config holds boot configuration.
type Config struct {
	PublicURL        string
	Listen           string
	DBPath           string
	SecretsKey       string
	KeyFile          string
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCScopes       string
	OIDCRedirectURL  string
	OIDCEmails       []string
	OIDCGroups       []string
	LogLevel         string
	PUID             int
	PGID             int
	AuthMode         string
	ProxyUser        string
	ProxyEmail       string
	ProxyName        string
	ProxyGroups      string
	ProxyFallback    string
	Trust            []*net.IPNet
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intEnv(k string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k)))
	if err != nil || n < 0 || n > 65535 {
		return def
	}
	return n
}

// OIDCEnabled reports whether admin sign-in is configured.
func (c *Config) OIDCEnabled() bool {
	return c.OIDCIssuer != "" && c.OIDCClientID != "" && c.OIDCClientSecret != ""
}

// OIDCRedirect is the callback registered at the identity provider.
func (c *Config) OIDCRedirect() string {
	if c.OIDCRedirectURL != "" {
		return c.OIDCRedirectURL
	}
	return strings.TrimRight(c.PublicURL, "/") + "/admin/oidc/callback"
}

// GoogleRedirect is the OAuth callback registered on the Google client.
func (c *Config) GoogleRedirect() string {
	return strings.TrimRight(c.PublicURL, "/") + "/admin/google/callback"
}

// PushEndpoint is the public URL of the optional Pub/Sub push receiver.
func (c *Config) PushEndpoint() string {
	return strings.TrimRight(c.PublicURL, "/") + "/hooks/pubsub"
}

// Load reads the environment.
func Load() *Config {
	c := &Config{
		PublicURL:        strings.TrimRight(env("PUBLIC_URL", "http://localhost:8080"), "/"),
		Listen:           env("LISTEN_ADDR", ":8080"),
		DBPath:           env("DB_PATH", "/data/ghook.db"),
		SecretsKey:       strings.TrimSpace(os.Getenv("SECRETS_KEY")),
		OIDCIssuer:       strings.TrimRight(strings.TrimSpace(os.Getenv("OIDC_ISSUER")), "/"),
		OIDCClientID:     strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		OIDCClientSecret: strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET")),
		OIDCScopes:       env("OIDC_SCOPES", "openid profile email groups"),
		OIDCRedirectURL:  strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL")),
		OIDCEmails:       splitList(os.Getenv("OIDC_ALLOWED_EMAILS")),
		OIDCGroups:       splitList(os.Getenv("OIDC_ALLOWED_GROUPS")),
		LogLevel:         strings.ToLower(env("LOG_LEVEL", "info")),
		PUID:             intEnv("PUID", 1000),
		PGID:             intEnv("PGID", 1000),
	}
	if c.PUID == 0 {
		c.PUID = 1000
	}
	if c.PGID == 0 {
		c.PGID = 1000
	}
	c.KeyFile = filepath.Join(filepath.Dir(c.DBPath), "secrets.key")
	c.applyAuth()
	return c
}
