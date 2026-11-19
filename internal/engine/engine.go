// Package engine turns a Gmail history id into durable outbox rows.
// The history id moves forward in the same transaction as the inserts, and the
// Pub/Sub message is acked only after that transaction commits.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/feed"
	"github.com/helv-io/ghook/internal/gmailx"
	"github.com/helv-io/ghook/internal/mail"
	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/secrets"
	"github.com/helv-io/ghook/internal/store"
)

// ErrUnknownAccount means the notification named a mailbox that is not connected.
// The caller acks it: retrying would never succeed.
var ErrUnknownAccount = errors.New("no connected account for that address")

// Clients opens a Gmail client for one mailbox.
type Clients func(ctx context.Context, email string) (gmailx.Client, error)

// Engine syncs mailboxes and queues deliveries.
type Engine struct {
	MaxDeliveries int
	DB            *store.DB
	Clients       Clients
	Feed          *feed.Feed
	Now           func() time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Note is the JSON inside a Gmail Pub/Sub notification.
type Note struct {
	Email   string
	History string
}

// ParseNote accepts the Gmail notification JSON. historyId arrives as a number.
func ParseNote(raw []byte) (Note, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Note{}, err
	}
	var n Note
	if v, ok := probe["emailAddress"]; ok {
		if err := json.Unmarshal(v, &n.Email); err != nil {
			return Note{}, err
		}
	}
	if v, ok := probe["historyId"]; ok {
		var s string
		if json.Unmarshal(v, &s) == nil {
			n.History = s
		} else {
			var num json.Number
			dec := json.NewDecoder(strings.NewReader(string(v)))
			dec.UseNumber()
			if err := dec.Decode(&num); err != nil {
				return Note{}, err
			}
			n.History = num.String()
		}
	}
	n.Email = strings.TrimSpace(n.Email)
	n.History = strings.TrimSpace(n.History)
	if n.Email == "" || n.History == "" {
		return Note{}, errors.New("notification is missing emailAddress or historyId")
	}
	return n, nil
}

// HandleNotification processes one Pub/Sub payload. A nil error means the
// message may be acked. ErrUnknownAccount is also safe to ack; the caller
// treats it as nil after logging.
func (e *Engine) HandleNotification(ctx context.Context, raw []byte) error {
	n, err := ParseNote(raw)
	if err != nil {
		// A payload we cannot read will never succeed. Ack it.
		log.Printf("ghook: dropping unreadable notification: %v", err)
		e.Feed.Add("error", "Dropped a notification that was not a Gmail message")
		return nil
	}
	err = e.Sync(ctx, n.Email, n.History)
	if errors.Is(err, ErrUnknownAccount) {
		log.Printf("ghook: notification for %s ignored: mailbox is not connected", redact(n.Email))
		e.Feed.Add("sync", "Notification ignored: mailbox is not connected")
		return nil
	}
	return err
}

// Sync catches a mailbox up. notifyHistory is the id from a push notification,
// or empty for the periodic catch-up.
func (e *Engine) Sync(ctx context.Context, email, notifyHistory string) error {
	acc, ok, err := e.DB.AccountByEmail(email)
	if err != nil {
		return err
	}
	if !ok {
		accs, err := e.DB.Unscoped().AccountsByEmail(email)
		if err != nil {
			return err
		}
		if len(accs) == 0 {
			return ErrUnknownAccount
		}
		var first error
		for _, a := range accs {
			eng := *e
			eng.DB = e.DB.Use(a.UserID)
			if err := eng.Sync(ctx, email, notifyHistory); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	if notifyHistory != "" {
		_ = e.DB.TouchNotify(acc.ID, notifyHistory)
	}
	if acc.Disabled {
		return nil
	}
	if notifyHistory != "" && acc.HistoryID != "" && !historyLess(acc.HistoryID, notifyHistory) {
		return nil
	}
	if e.Clients == nil {
		return errors.New("gmail client is not configured")
	}
	client, err := e.Clients(ctx, email)
	if err != nil {
		return err
	}
	days := e.DB.IntSetting("resync_days", 2)
	if days < 1 {
		days = 2
	}
	var (
		msgs     []mail.Message
		latest   string
		fallback bool
	)
	switch {
	case acc.HistoryID == "":
		fallback = true
		latest = notifyHistory
		since := e.now().AddDate(0, 0, -days)
		msgs, err = client.ListSince(ctx, since, 200)
	default:
		msgs, latest, err = client.History(ctx, acc.HistoryID)
		if errors.Is(err, gmailx.ErrHistoryGone) {
			fallback = true
			latest = notifyHistory
			if latest == "" {
				latest = acc.HistoryID
			}
			since := e.now().AddDate(0, 0, -days)
			msgs, err = client.ListSince(ctx, since, 200)
			e.Feed.AddFor(acc.UserID, "sync", "History id was too old, listed the last "+strconv.Itoa(days)+" days")
		}
	}
	if err != nil {
		return err
	}
	if historyLess(latest, notifyHistory) {
		latest = notifyHistory
	}
	names := map[string]string{}
	if labels, lerr := client.Labels(ctx); lerr == nil {
		for _, l := range labels {
			names[l.ID] = l.Name
		}
	}
	routes, err := e.DB.Routes()
	if err != nil {
		return err
	}
	var rules []match.Route
	for _, r := range routes {
		rules = append(rules, r.AsMatch())
	}
	prefix := match.Prefix(e.DB.Setting("label_prefix", match.DefaultPrefix))
	convention := e.DB.BoolSetting("label_convention", true)
	targets, err := e.DB.Targets()
	if err != nil {
		return err
	}
	byName := map[string]store.Target{}
	for _, t := range targets {
		byName[strings.ToLower(t.Name)] = t
	}
	inserted := 0
	for i := range msgs {
		resolveLabels(&msgs[i], names)
		plans := plansFor(msgs[i], rules, byName, prefix, convention)
		plans = e.limitPlans(plans)
		n, err := e.DB.QueueAndAdvance(acc.ID, acc.Email, msgs[i], plans, "")
		if err != nil {
			return err
		}
		inserted += n
		if n > 0 {
			e.applyLabels(ctx, client, prefix, msgs[i], plans)
		}
	}
	// History moves only after every match is committed. A failure above leaves
	// the old id in place so the notification is nacked and tried again.
	if latest != "" {
		if err := e.advance(acc.ID, latest); err != nil {
			return err
		}
		// Catch-up syncs also record last notification / history lag.
		if notifyHistory == "" {
			_ = e.DB.TouchNotify(acc.ID, latest)
		}
	}
	if fallback {
		e.Feed.AddFor(acc.UserID, "sync", fmt.Sprintf("Resynced %d message(s), %d new", len(msgs), inserted))
	} else if inserted > 0 {
		e.Feed.AddFor(acc.UserID, "sync", fmt.Sprintf("%d new message(s) queued", inserted))
	}
	return nil
}

func (e *Engine) advance(accountID int64, history string) error {
	var cur string
	if err := e.DB.SQL.QueryRow(`SELECT history_id FROM accounts WHERE id=? AND user_id=?`, accountID, e.DB.UserID()).Scan(&cur); err != nil {
		return err
	}
	ts := e.now().Unix()
	if !historyLess(cur, history) && cur != "" {
		_, err := e.DB.SQL.Exec(`UPDATE accounts SET last_sync=? WHERE id=? AND user_id=?`, ts, accountID, e.DB.UserID())
		return err
	}
	_, err := e.DB.SQL.Exec(`UPDATE accounts SET history_id=?, last_sync=?, updated_at=? WHERE id=? AND user_id=?`, history, ts, ts, accountID, e.DB.UserID())
	return err
}

func resolveLabels(m *mail.Message, names map[string]string) {
	if m.Category == "" {
		m.Category = mail.CategoryFromLabels(m.Labels)
	}
	if len(names) == 0 {
		return
	}
	var out []string
	seen := map[string]bool{}
	for _, id := range m.Labels {
		name := id
		if n, ok := names[id]; ok && n != "" {
			name = n
		}
		if !seen[strings.ToLower(name)] {
			seen[strings.ToLower(name)] = true
			out = append(out, name)
		}
		if name != id && !seen[strings.ToLower(id)] {
			seen[strings.ToLower(id)] = true
			out = append(out, id)
		}
	}
	m.Labels = out
	if m.Category == "" {
		m.Category = mail.CategoryFromLabels(m.Labels)
	}
}

func plansFor(m mail.Message, rules []match.Route, targets map[string]store.Target, prefix string, convention bool) []store.MatchPlan {
	var plans []store.MatchPlan
	seenTarget := map[int64]bool{}
	if convention {
		for _, name := range match.LabelTargets(prefix, m.Labels) {
			t, ok := targets[strings.ToLower(name)]
			if !ok || seenTarget[t.ID] {
				continue
			}
			seenTarget[t.ID] = true
			plans = append(plans, store.MatchPlan{
				RouteKey: "label:" + strings.ToLower(t.Name), RouteName: "label:" + t.Name,
				TargetID: t.ID, TargetName: t.Name,
			})
		}
	}
	claimed := len(plans) > 0
	for _, hit := range match.DecideClaimed(rules, m, claimed) {
		if hit.TargetID == 0 || seenTarget[hit.TargetID] {
			continue
		}
		seenTarget[hit.TargetID] = true
		plans = append(plans, store.MatchPlan{
			RouteKey: fmt.Sprintf("route:%d", hit.ID), RouteName: hit.Name,
			TargetID: hit.TargetID, TargetName: hit.TargetName, ApplyLabel: hit.ApplyLabel,
		})
	}
	return plans
}

func (e *Engine) applyLabels(ctx context.Context, client gmailx.Client, prefix string, m mail.Message, plans []store.MatchPlan) {
	if !e.DB.BoolSetting("gmail_modify", false) {
		return
	}
	var ids []string
	labels, err := client.Labels(ctx)
	if err != nil {
		return
	}
	byName := map[string]string{}
	for _, l := range labels {
		byName[strings.ToLower(l.Name)] = l.ID
	}
	for _, p := range plans {
		if !p.ApplyLabel {
			continue
		}
		name := match.RoutedLabel(prefix, p.TargetName)
		id, ok := byName[strings.ToLower(name)]
		if !ok {
			created, err := client.CreateLabel(ctx, name)
			if err != nil {
				e.Feed.AddFor(e.uid(), "error", "Could not create label "+name)
				continue
			}
			id = created.ID
			byName[strings.ToLower(name)] = id
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return
	}
	if err := client.AddLabels(ctx, m.ID, ids); err != nil {
		e.Feed.AddFor(e.uid(), "error", "Could not label a message")
	}
}

// RenewWatches renews watches that are missing or expire within two days.
func (e *Engine) RenewWatches(ctx context.Context, topic string) {
	if topic == "" || e.Clients == nil {
		return
	}
	accs, err := e.DB.Accounts()
	if err != nil {
		log.Printf("ghook: accounts: %v", err)
		return
	}
	for _, a := range accs {
		if a.Disabled || !a.HasToken {
			continue
		}
		exp := time.Unix(a.WatchExpiry, 0)
		if a.WatchExpiry != 0 && time.Until(exp) > 48*time.Hour {
			continue
		}
		client, err := e.Clients(ctx, a.Email)
		if err != nil {
			e.failWatch(a, err)
			continue
		}
		hist, until, err := client.Watch(ctx, topic)
		if err != nil {
			e.failWatch(a, err)
			continue
		}
		if err := e.DB.SetWatch(a.ID, until.Unix(), hist, ""); err != nil {
			log.Printf("ghook: save watch: %v", err)
			continue
		}
		e.Feed.AddFor(a.UserID, "watch", "Watch renewed until "+until.UTC().Format(time.RFC3339))
	}
}

func (e *Engine) failWatch(a store.Account, err error) {
	msg := err.Error()
	_ = e.DB.SetWatch(a.ID, a.WatchExpiry, "", msg)
	e.Feed.AddFor(a.UserID, "error", "Watch renewal failed")
	log.Printf("ghook: watch renewal failed for %s: %v", redact(a.Email), err)
	e.notifyWatch(a.Email, msg)
}

func (e *Engine) notifyWatch(email, msg string) {
	if !e.DB.BoolSetting("notify_watch", true) {
		return
	}
	id := e.DB.IntSetting("notify_target", 0)
	if id == 0 {
		return
	}
	t, ok, err := e.DB.TargetByID(int64(id), false)
	if err != nil || !ok {
		return
	}
	hour := e.now().UTC().Format("2006010215")
	key := "notify:watch:" + strings.ToLower(email) + ":" + hour
	if e.DB.HasNotify(key) {
		return
	}
	body, _ := json.Marshal(map[string]string{
		"source": "ghook", "kind": "watch_renewal", "account": email, "error": msg,
	})
	_, _ = e.DB.InsertDelivery(store.Delivery{
		Key: newNotifyKey(key), AccountEmail: email, GmailID: "watch-" + hour, RouteKey: key,
		RouteName: "watch", TargetID: t.ID, TargetName: t.Name, Kind: "notify", Status: "queued",
		PayloadJSON: string(body),
	})
}

func newNotifyKey(s string) string { return "ntf_" + strings.ReplaceAll(s, ":", "_") }

// CatchUp runs a history sync for every enabled mailbox.
func (e *Engine) CatchUp(ctx context.Context) {
	accs, err := e.DB.Accounts()
	if err != nil {
		return
	}
	interval := time.Duration(e.DB.IntSetting("catchup_minutes", 30)) * time.Minute
	if interval < time.Minute {
		interval = 30 * time.Minute
	}
	for _, a := range accs {
		if a.Disabled || !a.HasToken || a.HistoryID == "" {
			continue
		}
		if a.LastSync != 0 && e.now().Sub(time.Unix(a.LastSync, 0)) < interval {
			continue
		}
		if err := e.Sync(ctx, a.Email, ""); err != nil {
			log.Printf("ghook: catch-up %s: %v", redact(a.Email), err)
			e.Feed.AddFor(a.UserID, "error", "Catch-up failed")
		}
	}
}

// Preview runs rules against the newest stored messages. When a client is
// available the body is read for the match and then discarded.
func (e *Engine) Preview(ctx context.Context, rules []match.Route, n int) ([]Preview, error) {
	if n <= 0 {
		n = 20
	}
	stored, err := e.DB.RecentMessages(n)
	if err != nil {
		return nil, err
	}
	prefix := match.Prefix(e.DB.Setting("label_prefix", match.DefaultPrefix))
	convention := e.DB.BoolSetting("label_convention", true)
	targets, err := e.DB.Targets()
	if err != nil {
		return nil, err
	}
	byName := map[string]store.Target{}
	for _, t := range targets {
		byName[strings.ToLower(t.Name)] = t
	}
	var out []Preview
	for _, s := range stored {
		m := s.AsMail()
		if e.Clients != nil && s.AccountEmail != "" {
			if c, err := e.Clients(ctx, s.AccountEmail); err == nil {
				if full, err := c.Get(ctx, s.GmailID); err == nil {
					if full.Plain != "" {
						m.Plain = full.Plain
					}
					if full.Snippet != "" {
						m.Snippet = full.Snippet
					}
					m.HasAttachment = full.HasAttachment || m.HasAttachment
					if len(full.Labels) > 0 {
						m.Labels = full.Labels
					}
					if full.Category != "" {
						m.Category = full.Category
					}
				}
			}
		}
		plans := plansFor(m, rules, byName, prefix, convention)
		var names []string
		for _, h := range plans {
			names = append(names, h.RouteName)
		}
		route := ""
		if len(names) > 0 {
			route = strings.Join(names, " → ")
		}
		out = append(out, Preview{From: m.From, Subject: m.Subject, Account: s.AccountEmail, Route: route, GmailID: m.ID})
	}
	return out, nil
}

// Preview is one simulator row.
type Preview struct {
	From    string
	Subject string
	Account string
	Route   string
	GmailID string
}

func historyLess(cur, next string) bool {
	if cur == next || next == "" {
		return false
	}
	if cur == "" {
		return true
	}
	ai, aok := atoi(cur)
	bi, bok := atoi(next)
	if aok && bok {
		return ai < bi
	}
	return cur < next
}

func atoi(s string) (uint64, bool) {
	var n uint64
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, true
}

func (e *Engine) limitPlans(plans []store.MatchPlan) []store.MatchPlan {
	if e == nil || e.MaxDeliveries <= 0 || len(plans) == 0 {
		return plans
	}
	day := time.Now().UTC().Truncate(24 * time.Hour).Unix()
	left := e.MaxDeliveries - e.DB.DeliveriesSince(day)
	if left <= 0 {
		return nil
	}
	if left >= len(plans) {
		return plans
	}
	return plans[:left]
}

func redact(email string) string { return secrets.RedactEmail(email) }

func (e *Engine) uid() int64 {
	if e == nil || e.DB == nil {
		return 0
	}
	return e.DB.UserID()
}
