// Package config loads the few settings that have to exist before the database
// is open. Everything else is a WebUI setting stored in SQLite, per user.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Version is the release stamped into the UI and the User-Agent.
const Version = "0.2.1"

// Config holds boot configuration.
type Config struct {
	PublicURL     string
	Listen        string
	DBPath        string
	SecretsKey    string
	KeyFile       string
	GoogleClient  string
	PubSubProject string
	PubSubTopic   string
	PubSubSub     string
	PubSubSA      string
	MetricsToken  string
	MaxTargets    int
	MaxRoutes     int
	MaxDeliveries int
	LogLevel      string
	// CompactAt is the local time of the daily compaction, "HH:MM" or "off".
	CompactAt string
	PUID      int
	PGID      int
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func intEnv(k string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k)))
	if err != nil || n < 0 {
		return def
	}
	return n
}

func fileOrEnv(fileKey, rawKey string) string {
	if p := strings.TrimSpace(os.Getenv(fileKey)); p != "" {
		b, err := os.ReadFile(p)
		if err == nil {
			return string(b)
		}
	}
	return strings.TrimSpace(os.Getenv(rawKey))
}

// GoogleRedirect is the OAuth callback registered on the Google client.
func (c *Config) GoogleRedirect() string {
	return strings.TrimRight(c.PublicURL, "/") + "/admin/google/callback"
}

// PushEndpoint is the public URL of the optional Pub/Sub push receiver.
func (c *Config) PushEndpoint() string {
	return strings.TrimRight(c.PublicURL, "/") + "/hooks/pubsub"
}

// Ready reports whether Google sign-in can start.
func (c *Config) Ready() bool {
	return strings.TrimSpace(c.GoogleClient) != "" && strings.TrimSpace(c.PublicURL) != ""
}

// PubSubReady reports whether the shared pull subscription is configured.
func (c *Config) PubSubReady() bool {
	return c.PubSubProject != "" && c.PubSubTopic != "" && c.PubSubSub != "" && c.PubSubSA != ""
}

// Load reads the environment.
func Load() *Config {
	c := &Config{
		PublicURL:     strings.TrimRight(env("PUBLIC_URL", "http://localhost:8080"), "/"),
		Listen:        env("LISTEN_ADDR", ":8080"),
		DBPath:        env("DB_PATH", "/data/ghook.db"),
		SecretsKey:    strings.TrimSpace(os.Getenv("SECRETS_KEY")),
		GoogleClient:  fileOrEnv("GOOGLE_CLIENT_FILE", "GOOGLE_CLIENT_JSON"),
		PubSubProject: strings.TrimSpace(os.Getenv("PUBSUB_PROJECT")),
		PubSubTopic:   env("PUBSUB_TOPIC", "gmail-inbox"),
		PubSubSub:     env("PUBSUB_SUBSCRIPTION", "ghook-pull"),
		PubSubSA:      fileOrEnv("PUBSUB_SA_FILE", "PUBSUB_SA_JSON"),
		MetricsToken:  strings.TrimSpace(os.Getenv("METRICS_TOKEN")),
		MaxTargets:    intEnv("MAX_TARGETS", 25),
		MaxRoutes:     intEnv("MAX_ROUTES", 50),
		MaxDeliveries: intEnv("MAX_DELIVERIES_PER_DAY", 1000),
		LogLevel:      strings.ToLower(env("LOG_LEVEL", "info")),
		CompactAt:     env("COMPACT_AT", "03:15"),
		PUID:          intEnv("PUID", 1000),
		PGID:          intEnv("PGID", 1000),
	}
	if c.PUID == 0 {
		c.PUID = 1000
	}
	if c.PGID == 0 {
		c.PGID = 1000
	}
	if c.MaxTargets < 1 {
		c.MaxTargets = 25
	}
	if c.MaxRoutes < 1 {
		c.MaxRoutes = 50
	}
	if c.MaxDeliveries < 1 {
		c.MaxDeliveries = 1000
	}
	c.KeyFile = filepath.Join(filepath.Dir(c.DBPath), "secrets.key")
	if c.PubSubProject == "" {
		c.PubSubProject = projectFromSA(c.PubSubSA)
	}
	return c
}

func projectFromSA(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var doc struct {
		ProjectID string `json:"project_id"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return ""
	}
	return strings.TrimSpace(doc.ProjectID)
}
