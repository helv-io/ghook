// Package deliver posts queued webhooks with retries, quiet hours, digests and
// per-target rate limits. Request logs are stored with secrets and message
// bodies removed.
package deliver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/helv-io/ghook/internal/feed"
	"github.com/helv-io/ghook/internal/store"
)

// Doer sends one HTTP request.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// BodyFunc loads the plain text of a message when a target opted in. The text
// is not stored.
type BodyFunc func(ctx context.Context, accountEmail, gmailID string) (string, error)

// Payload is the default JSON body.
type Payload struct {
	Source     string   `json:"source"`
	Route      string   `json:"route"`
	Account    string   `json:"account"`
	MessageID  string   `json:"message_id"`
	ThreadID   string   `json:"thread_id"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	Cc         string   `json:"cc,omitempty"`
	Subject    string   `json:"subject"`
	Date       string   `json:"date"`
	Labels     []string `json:"labels"`
	Category   string   `json:"category"`
	Snippet    string   `json:"snippet"`
	GmailURL   string   `json:"gmail_url"`
	DeliveryID string   `json:"delivery_id"`
	Body       string   `json:"body,omitempty"`
	BodyText   string   `json:"body_text,omitempty"`
}

// Worker drains the outbox.
type Worker struct {
	DB      *store.DB
	HTTP    Doer
	Bodies  BodyFunc
	Feed    *feed.Feed
	Now     func() time.Time
	Locate  func() *time.Location
	limiter limiter
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Worker) loc() *time.Location {
	if w.Locate != nil {
		if l := w.Locate(); l != nil {
			return l
		}
	}
	name := "UTC"
	if w.DB != nil {
		name = w.DB.Setting("timezone", "UTC")
	}
	l, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	return l
}

// Run calls Step until the context ends.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Step(ctx)
		}
	}
}

// Step sends a batch of due deliveries and any digest that is due.
func (w *Worker) Step(ctx context.Context) {
	if w.DB == nil {
		return
	}
	now := w.now()
	saved := w.DB
	if users, err := saved.Unscoped().Users(); err == nil && len(users) > 0 {
		for _, u := range users {
			w.DB = saved.Use(u.ID)
			w.digests(ctx, now)
		}
	} else {
		w.digests(ctx, now)
	}
	due, err := saved.Unscoped().DueDeliveries(now.Unix(), 20)
	w.DB = saved
	if err != nil {
		return
	}
	for _, d := range due {
		if d.UserID != 0 {
			w.DB = saved.Use(d.UserID)
		} else {
			w.DB = saved
		}
		w.one(ctx, d, now)
		w.DB = saved
	}
}

func (w *Worker) one(ctx context.Context, d store.Delivery, now time.Time) {
	t, ok, err := w.DB.TargetByID(d.TargetID, true)
	if err != nil || !ok {
		_ = w.DB.Finish(d.ID, "dead", d.Attempts+1, now.Unix(), "target is gone", "", 0, "")
		return
	}
	if t.Paused {
		return
	}
	if in, until := quiet(now, w.loc(), t.QuietStart, t.QuietEnd); in && d.Kind != "notify" {
		_ = w.DB.Postpone(d.ID, until.Unix())
		return
	}
	if ok, at := w.limiter.allow(t.ID, t.RatePerMin, now); !ok {
		_ = w.DB.Postpone(d.ID, at.Unix())
		return
	}
	claimed, err := w.DB.Claim(d.ID, now.Unix())
	if err != nil || !claimed {
		return
	}
	maxAttempts := w.DB.IntSetting("retry_max_attempts", 8)
	maxHours := w.DB.IntSetting("retry_max_hours", 24)
	if maxAttempts < 1 {
		maxAttempts = 8
	}
	age := now.Sub(time.Unix(d.CreatedAt, 0))
	if d.Attempts >= maxAttempts || (maxHours > 0 && age > time.Duration(maxHours)*time.Hour && d.Attempts > 0) {
		_ = w.DB.Finish(d.ID, "dead", d.Attempts, now.Unix(), "gave up after retries", d.RequestLog, d.ResponseStatus, d.ResponseBody)
		w.notifyDead(d, t, "gave up after retries")
		return
	}
	body, plain, err := w.build(ctx, d, t)
	if err != nil {
		w.fail(d, t, now, err.Error(), "", 0, "")
		return
	}
	status, resp, reqLog, err := w.post(ctx, t, d.Key, body, plain)
	if err != nil || status < 200 || status >= 300 {
		msg := fmt.Sprintf("HTTP %d", status)
		if err != nil {
			msg = err.Error()
		}
		w.fail(d, t, now, msg, reqLog, status, resp)
		return
	}
	_ = w.DB.Finish(d.ID, "sent", d.Attempts+1, now.Unix(), "", reqLog, status, resp)
	if w.Feed != nil {
		w.Feed.Add("delivery", fmt.Sprintf("%s → %s sent", d.RouteName, t.Name))
	}
}

func (w *Worker) fail(d store.Delivery, t store.Target, now time.Time, msg, reqLog string, status int, resp string) {
	attempts := d.Attempts + 1
	maxAttempts := 8
	maxHours := 24
	base := 30
	capSec := 3600
	if w.DB != nil {
		maxAttempts = w.DB.IntSetting("retry_max_attempts", 8)
		maxHours = w.DB.IntSetting("retry_max_hours", 24)
		base = w.DB.IntSetting("retry_base_seconds", 30)
		capSec = w.DB.IntSetting("retry_cap_seconds", 3600)
	}
	if d.Kind == "notify" && maxAttempts > 3 {
		maxAttempts = 3
	}
	age := now.Sub(time.Unix(d.CreatedAt, 0))
	if attempts >= maxAttempts || (maxHours > 0 && age > time.Duration(maxHours)*time.Hour) {
		_ = w.DB.Finish(d.ID, "dead", attempts, now.Unix(), msg, reqLog, status, clip(resp))
		if d.Kind != "notify" {
			w.notifyDead(d, t, msg)
		}
		return
	}
	wait := Backoff(attempts, time.Duration(base)*time.Second, time.Duration(capSec)*time.Second)
	_ = w.DB.Finish(d.ID, "retry", attempts, now.Add(wait).Unix(), msg, reqLog, status, clip(resp))
}

func (w *Worker) notifyDead(d store.Delivery, t store.Target, msg string) {
	if w.Feed != nil {
		w.Feed.Add("error", fmt.Sprintf("%s → %s dead: %s", d.RouteName, t.Name, msg))
	}
	if d.Kind == "notify" || !w.DB.BoolSetting("notify_dead", true) {
		return
	}
	nid := w.DB.IntSetting("notify_target", 0)
	if nid == 0 || int64(nid) == t.ID {
		return
	}
	nt, ok, err := w.DB.TargetByID(int64(nid), false)
	if err != nil || !ok {
		return
	}
	key := fmt.Sprintf("notify:dead:%d", d.ID)
	if w.DB.HasNotify(key) {
		return
	}
	raw, _ := json.Marshal(map[string]any{
		"source": "ghook", "kind": "dead_letter", "delivery_id": d.Key, "target": t.Name,
		"route": d.RouteName, "account": d.AccountEmail, "error": msg, "attempts": d.Attempts + 1,
	})
	_, _ = w.DB.InsertDelivery(store.Delivery{
		AccountID: d.AccountID, AccountEmail: d.AccountEmail, GmailID: "dead-" + fmt.Sprint(d.ID),
		RouteKey: key, RouteName: "dead-letter", TargetID: nt.ID, TargetName: nt.Name,
		Kind: "notify", Status: "queued", PayloadJSON: string(raw),
	})
}

func (w *Worker) build(ctx context.Context, d store.Delivery, t store.Target) (body []byte, plain string, err error) {
	if d.Kind == "notify" && d.PayloadJSON != "" {
		return []byte(d.PayloadJSON), "", nil
	}
	p := Payload{Source: "ghook", Route: d.RouteName, Account: d.AccountEmail, MessageID: d.GmailID,
		ThreadID: d.ThreadID, DeliveryID: d.Key, Labels: []string{}}
	if m, ok, err := w.DB.MessageForDelivery(d.AccountID, d.GmailID); err == nil && ok {
		p.From, p.To, p.Cc = m.From, m.To, m.Cc
		p.Subject, p.Snippet, p.Category = m.Subject, m.Snippet, m.Category
		p.Labels = m.Labels
		if p.ThreadID == "" {
			p.ThreadID = m.ThreadID
		}
		if m.DateMS > 0 {
			p.Date = time.UnixMilli(m.DateMS).UTC().Format(time.RFC3339)
		}
	}
	if p.Labels == nil {
		p.Labels = []string{}
	}
	if p.Date == "" {
		p.Date = time.Unix(d.CreatedAt, 0).UTC().Format(time.RFC3339)
	}
	p.GmailURL = "https://mail.google.com/mail/u/0/#all/" + d.GmailID
	if t.IncludeBody && w.Bodies != nil && d.Kind == "mail" {
		plain, err = w.Bodies(ctx, d.AccountEmail, d.GmailID)
		if err != nil {
			return nil, "", err
		}
		p.Body, p.BodyText = plain, plain
	}
	if strings.TrimSpace(t.Template) != "" {
		tpl, err := template.New("payload").Option("missingkey=error").Parse(t.Template)
		if err != nil {
			return nil, plain, fmt.Errorf("payload template: %w", err)
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, p); err != nil {
			return nil, plain, fmt.Errorf("payload template: %w", err)
		}
		return buf.Bytes(), plain, nil
	}
	raw, err := encodeJSON(p)
	return raw, plain, err
}

func (w *Worker) post(ctx context.Context, t store.Target, deliveryID string, body []byte, plain string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ghook")
	req.Header.Set("X-Ghook-Delivery", deliveryID)
	switch t.AuthMode {
	case "hmac":
		mac := hmac.New(sha256.New, []byte(t.Secret()))
		mac.Write(body)
		req.Header.Set("X-Ghook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	case "header":
		name := t.AuthHeader
		if name == "" {
			name = "X-Api-Key"
		}
		if t.Secret() != "" {
			req.Header.Set(name, t.Secret())
		}
	default:
		if t.Secret() != "" {
			req.Header.Set("Authorization", "Bearer "+t.Secret())
		}
	}
	client := w.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	res, err := client.Do(req)
	reqLog := logRequest(req, body, t.Secret(), plain, w.retain())
	if err != nil {
		return 0, "", reqLog, err
	}
	defer res.Body.Close()
	slurp, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	return res.StatusCode, string(slurp), reqLog, nil
}

func (w *Worker) retain() bool {
	return w.DB != nil && w.DB.BoolSetting("retain_bodies", false)
}

func logRequest(req *http.Request, body []byte, secret, plain string, retain bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", req.Method, req.URL.String())
	for k, vs := range req.Header {
		val := strings.Join(vs, ", ")
		lk := strings.ToLower(k)
		if lk == "authorization" || strings.Contains(lk, "secret") || lk == "x-api-key" || (secret != "" && strings.Contains(val, secret)) {
			val = "••••"
		}
		fmt.Fprintf(&b, "%s: %s\n", k, val)
	}
	b.WriteByte('\n')
	logged := string(body)
	if secret != "" {
		logged = strings.ReplaceAll(logged, secret, "••••")
	}
	if !retain && plain != "" {
		logged = strings.ReplaceAll(logged, plain, "[not stored]")
	}
	b.WriteString(logged)
	return b.String()
}

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func clip(s string) string {
	if len(s) > 4000 {
		return s[:4000]
	}
	return s
}

// Backoff is base * 2^(attempt-1), capped.
func Backoff(attempt int, base, cap time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if base <= 0 {
		base = 30 * time.Second
	}
	d := base
	for i := 1; i < attempt; i++ {
		if d > cap/2 {
			return cap
		}
		d *= 2
	}
	if d > cap {
		return cap
	}
	return d
}

// quiet reports whether now is inside the window. An empty window is never quiet.
// A window that crosses midnight (22:00-07:00) is supported. until is the next open instant.
func quiet(now time.Time, loc *time.Location, start, end string) (bool, time.Time) {
	sh, sm, ok1 := clock(start)
	eh, em, ok2 := clock(end)
	if !ok1 || !ok2 || (sh == eh && sm == em) {
		return false, time.Time{}
	}
	local := now.In(loc)
	cur := local.Hour()*60 + local.Minute()
	a := sh*60 + sm
	b := eh*60 + em
	in := false
	if a < b {
		in = cur >= a && cur < b
	} else {
		in = cur >= a || cur < b
	}
	if !in {
		return false, time.Time{}
	}
	until := time.Date(local.Year(), local.Month(), local.Day(), eh, em, 0, 0, loc)
	if !until.After(local) {
		until = until.Add(24 * time.Hour)
	}
	return true, until
}

func clock(s string) (h, m int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// DigestDue reports whether the daily batch should go out now.
func DigestDue(now time.Time, loc *time.Location, at string, lastUnix int64) bool {
	h, m, ok := clock(at)
	if !ok {
		return false
	}
	local := now.In(loc)
	moment := time.Date(local.Year(), local.Month(), local.Day(), h, m, 0, 0, loc)
	if local.Before(moment) {
		return false
	}
	if lastUnix == 0 {
		// A brand-new target must not backfill today's already-passed slot.
		return false
	}
	last := time.Unix(lastUnix, 0).In(loc)
	return last.Before(moment)
}

func (w *Worker) digests(ctx context.Context, now time.Time) {
	targets, err := w.DB.Targets()
	if err != nil {
		return
	}
	loc := w.loc()
	for _, t := range targets {
		if t.Paused || t.DigestAt == "" || !DigestDue(now, loc, t.DigestAt, t.LastDigest) {
			continue
		}
		if in, until := quiet(now, loc, t.QuietStart, t.QuietEnd); in {
			_ = until
			continue
		}
		full, ok, err := w.DB.TargetByID(t.ID, true)
		if err != nil || !ok {
			continue
		}
		rows, err := w.DB.DigestCandidates(t.ID, 100)
		if err != nil || len(rows) == 0 {
			_ = w.DB.SetLastDigest(t.ID, now.Unix())
			continue
		}
		var items []Payload
		var ids []int64
		for _, d := range rows {
			claimed, err := w.DB.Claim(d.ID, now.Unix())
			if err != nil || !claimed {
				continue
			}
			raw, _, err := w.build(ctx, d, store.Target{})
			if err != nil {
				w.fail(d, full, now, err.Error(), "", 0, "")
				continue
			}
			var p Payload
			if json.Unmarshal(raw, &p) == nil {
				items = append(items, p)
				ids = append(ids, d.ID)
			}
		}
		if len(items) == 0 {
			continue
		}
		env := map[string]any{"source": "ghook", "digest": true, "target": full.Name, "count": len(items), "items": items}
		body, _ := encodeJSON(env)
		key := fmt.Sprintf("digest-%d-%d", full.ID, now.Unix())
		status, resp, reqLog, err := w.post(ctx, full, key, body, "")
		st := "sent"
		if err != nil || status < 200 || status >= 300 {
			st = "retry"
			msg := fmt.Sprintf("digest HTTP %d", status)
			if err != nil {
				msg = err.Error()
			}
			for _, id := range ids {
				_ = w.DB.Finish(id, "retry", 1, now.Add(time.Minute).Unix(), msg, reqLog, status, clip(resp))
			}
			continue
		}
		for _, id := range ids {
			_ = w.DB.Finish(id, st, 1, now.Unix(), "", reqLog, status, clip(resp))
		}
		_ = w.DB.SetLastDigest(full.ID, now.Unix())
		if w.Feed != nil {
			w.Feed.Add("delivery", fmt.Sprintf("digest → %s (%d)", full.Name, len(items)))
		}
	}
}

// SendTest posts a sample payload immediately and records the row.
func (w *Worker) SendTest(ctx context.Context, db *store.DB, targetID int64) (store.Delivery, error) {
	if db == nil {
		db = w.DB
	}
	t, ok, err := db.TargetByID(targetID, true)
	if err != nil || !ok {
		return store.Delivery{}, fmt.Errorf("target not found")
	}
	now := w.now()
	p := Payload{
		Source: "ghook", Route: "test", Account: "test@example.com", MessageID: "test",
		ThreadID: "test", From: "ghook@example.com", To: "you@example.com", Subject: "ghook test",
		Date: now.UTC().Format(time.RFC3339), Labels: []string{"INBOX"}, Category: "primary",
		Snippet: "This is a test delivery from ghook.", GmailURL: "https://mail.google.com/mail/",
		DeliveryID: "pending",
	}
	id, err := db.InsertDelivery(store.Delivery{
		GmailID: "test-" + fmt.Sprint(now.UnixNano()), RouteKey: "test", RouteName: "test",
		TargetID: t.ID, TargetName: t.Name, Kind: "test", Status: "inflight", AccountEmail: "test@example.com",
	})
	if err != nil {
		return store.Delivery{}, err
	}
	d, _, _ := db.DeliveryByID(id)
	p.DeliveryID = d.Key
	body, _ := encodeJSON(p)
	status, resp, reqLog, err := w.post(ctx, t, d.Key, body, "")
	st := "sent"
	msg := ""
	if err != nil || status < 200 || status >= 300 {
		st = "dead"
		msg = fmt.Sprintf("HTTP %d", status)
		if err != nil {
			msg = err.Error()
		}
	}
	_ = db.Finish(id, st, 1, now.Unix(), msg, reqLog, status, clip(resp))
	out, _, err := db.DeliveryByID(id)
	return out, err
}

type limiter struct {
	mu   sync.Mutex
	next map[int64]time.Time
}

func (l *limiter) allow(id int64, perMin int, now time.Time) (bool, time.Time) {
	if perMin <= 0 {
		return true, time.Time{}
	}
	if perMin > 6000 {
		perMin = 6000
	}
	gap := time.Minute / time.Duration(perMin)
	if gap <= 0 {
		gap = time.Millisecond
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next == nil {
		l.next = map[int64]time.Time{}
	}
	if at, ok := l.next[id]; ok && now.Before(at) {
		return false, at
	}
	l.next[id] = now.Add(gap)
	return true, time.Time{}
}
