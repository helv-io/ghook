package web

import (
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/store"
)

// destination is a target URL as the target list shows it.
type destination struct {
	// Label names the receiving service, or is the host when the service is not known.
	Label string
	Host  string
	// ID is the last path segment, shortened, so two targets on one service tell apart.
	ID string
}

// knownHooks names services by host and path prefix. First match wins.
var knownHooks = []struct{ host, path, label string }{
	{"cursor.sh", "/automations/webhook", "Grok Bot routine"},
	{"hooks.slack.com", "/", "Slack webhook"},
	{"discord.com", "/api/webhooks", "Discord webhook"},
	{"discordapp.com", "/api/webhooks", "Discord webhook"},
	{"hooks.zapier.com", "/", "Zapier hook"},
	{"maker.ifttt.com", "/", "IFTTT applet"},
	{"ntfy.sh", "/", "ntfy topic"},
}

func targetDest(raw string) destination {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return destination{Label: raw}
	}
	host := strings.ToLower(u.Hostname())
	d := destination{Host: strings.TrimPrefix(host, "www."), Label: strings.TrimPrefix(host, "www.")}
	for _, k := range knownHooks {
		if (host == k.host || strings.HasSuffix(host, "."+k.host)) && strings.HasPrefix(u.Path, k.path) {
			d.Label = k.label
			break
		}
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if last := segs[len(segs)-1]; last != "" {
		if r := []rune(last); len(r) > 12 {
			last = string(r[:8]) + "…"
		}
		d.ID = last
	}
	return d
}

// targetRow is one line of the target list.
type targetRow struct {
	store.Target
	Dest    destination
	Routes  []store.Route
	Last    store.Delivery
	HasLast bool
}

func authLabel(mode string) string {
	switch strings.ToLower(mode) {
	case "bearer":
		return "Bearer"
	case "hmac":
		return "HMAC"
	case "header":
		return "Header"
	case "", "none":
		return "None"
	}
	return mode
}

// sender splits a From header into a display name and an address.
func sender(from string) (name, addr string) {
	from = strings.TrimSpace(from)
	if from == "" {
		return "", ""
	}
	if a, err := mail.ParseAddress(from); err == nil {
		if a.Name == "" {
			return a.Address, ""
		}
		return a.Name, a.Address
	}
	if i := strings.LastIndex(from, "<"); i > 0 && strings.HasSuffix(from, ">") {
		return strings.Trim(strings.TrimSpace(from[:i]), `"`), from[i+1 : len(from)-1]
	}
	return from, ""
}

// shortTime is a compact timestamp for a list: "Nov 24, 1:41 PM" this year,
// "Nov 24, 2025, 1:41 PM" before that. Times are in loc.
func shortTime(unix int64, loc *time.Location, now time.Time) string {
	if unix == 0 {
		return "—"
	}
	t := time.Unix(unix, 0).In(loc)
	now = now.In(loc)
	if t.Year() != now.Year() {
		return t.Format("Jan 2, 2006, 3:04 PM")
	}
	return t.Format("Jan 2, 3:04 PM")
}

// fullTime is the tooltip form: the whole date, seconds and the zone.
func fullTime(unix int64, loc *time.Location) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).In(loc).Format("Mon, Jan 2, 2006, 3:04:05 PM MST")
}

func statusClass(status string) string {
	switch status {
	case "sent":
		return "ok"
	case "dead":
		return "bad"
	case "retry":
		return "warn"
	}
	return "off"
}

// routeAdvanced reports whether a route uses anything past the essentials
// (name, senders, target), so its "More options" section opens by itself.
func routeAdvanced(r store.Route, isNew bool) bool {
	s := r.Spec.Normalize()
	return len(s.To) > 0 || len(s.Cc) > 0 || s.Subject != "" || s.Contains != "" ||
		len(s.Labels) > 0 || len(s.Categories) > 0 || s.Attachment != "" || s.Op == "or" ||
		r.Fallback || r.Continue || r.ApplyLabel || (!isNew && !r.Enabled)
}

// targetAdvanced reports whether a target uses anything past a name, a URL and a bearer key.
func targetAdvanced(t store.Target) bool {
	return (t.AuthMode != "" && t.AuthMode != "bearer") || t.AuthHeader != "" || t.PayloadPubKey != "" ||
		t.IncludeBody || t.Paused || t.QuietStart != "" || t.QuietEnd != "" || t.DigestAt != "" ||
		t.RatePerMin > 0 || strings.TrimSpace(t.Template) != ""
}

// settingsAdvanced reports whether any setting behind "More options" differs from its default.
func settingsAdvanced(p page) bool {
	return p.LabelPrefix != match.DefaultPrefix || !p.LabelConvention || p.Catchup != 30 || p.ResyncDays != 2 ||
		p.RetryAttempts != 8 || p.RetryHours != 24 || p.RetryBase != 30 || p.Retention != 30 || p.RetainBodies
}

// splitWebhook reads "URL KEY" (or just a URL) as pasted from a bot's setup screen.
func splitWebhook(raw string) (u, key string) {
	f := strings.Fields(raw)
	if len(f) == 0 {
		return "", ""
	}
	return f[0], strings.Join(f[1:], " ")
}
