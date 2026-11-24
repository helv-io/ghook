package web

import (
	"net/mail"
	"net/url"
	"strings"
	"time"

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
