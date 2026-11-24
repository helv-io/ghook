package deliver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helv-io/ghook/internal/mail"
	"github.com/helv-io/ghook/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ghook.db"), "", filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_ = db.SetSetting("retry_base_seconds", "10")
	_ = db.SetSetting("retry_max_attempts", "3")
	_ = db.SetSetting("retry_max_hours", "24")
	_ = db.SetSetting("retry_cap_seconds", "60")
	return db
}

type script struct {
	mu     sync.Mutex
	codes  []int
	seen   []string
	auth   []string
	sig    []string
	bodies []string
}

func (s *script) Do(req *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(req.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, req.Header.Get("X-Ghook-Delivery"))
	s.auth = append(s.auth, req.Header.Get("Authorization"))
	s.sig = append(s.sig, req.Header.Get("X-Ghook-Signature"))
	s.bodies = append(s.bodies, string(raw))
	code := 200
	if len(s.codes) > 0 {
		code = s.codes[0]
		s.codes = s.codes[1:]
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
}

func due(t *testing.T, db *store.DB, at time.Time) {
	t.Helper()
	if _, err := db.SQL.Exec(`UPDATE deliveries SET next_attempt=?, created_at=? WHERE status IN ('queued','retry')`, at.Unix(), at.Unix()); err != nil {
		t.Fatal(err)
	}
}

func queue(t *testing.T, db *store.DB, target store.Target, gmailID string) store.Delivery {
	t.Helper()
	acc, err := db.SaveAccount("ada@example.com", "r", "", 0, "", "1")
	if err != nil {
		t.Fatal(err)
	}
	msg := mail.Message{ID: gmailID, ThreadID: "th", From: "ada@example.com", To: "ceo@example.com",
		Subject: "Hello", Snippet: "snippet", Date: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		Labels: []string{"INBOX"}, Category: "primary"}
	if _, err := db.QueueAndAdvance(acc.ID, acc.Email, msg, []store.MatchPlan{{
		RouteKey: "route:1", RouteName: "inbox", TargetID: target.ID, TargetName: target.Name,
	}}, ""); err != nil {
		t.Fatal(err)
	}
	dels, err := db.Deliveries("", "", "", 5)
	if err != nil || len(dels) == 0 {
		t.Fatal(err, len(dels))
	}
	return dels[0]
}

func TestRetryThenSuccessMasksSecret(t *testing.T) {
	db := openDB(t)
	tg, err := db.SaveTarget(store.Target{Name: "bot", URL: "https://bot.example.com/hook", AuthMode: "bearer"}, "super-secret-key", false)
	if err != nil {
		t.Fatal(err)
	}
	d := queue(t, db, tg, "m1")
	s := &script{codes: []int{500, 500, 200}}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	due(t, db, now)
	w := &Worker{DB: db, HTTP: s, Now: func() time.Time { return now }}
	w.Step(context.Background())
	got, _, _ := db.DeliveryByID(d.ID)
	if got.Status != "retry" || got.Attempts != 1 {
		t.Fatalf("after first: %+v", got)
	}
	if strings.Contains(got.RequestLog, "super-secret-key") || !strings.Contains(got.RequestLog, "••••") {
		t.Fatalf("secret leaked or not masked: %s", got.RequestLog)
	}
	if !strings.Contains(got.RequestLog, "X-Ghook-Delivery") && !strings.Contains(s.seen[0], got.Key) {
		t.Fatal("missing idempotency header")
	}
	now = time.Unix(got.NextAttempt, 0)
	w.Now = func() time.Time { return now }
	w.Step(context.Background())
	got, _, _ = db.DeliveryByID(d.ID)
	if got.Status != "retry" || got.Attempts != 2 {
		t.Fatalf("after second: %+v", got)
	}
	now = time.Unix(got.NextAttempt, 0)
	w.Now = func() time.Time { return now }
	w.Step(context.Background())
	got, _, _ = db.DeliveryByID(d.ID)
	if got.Status != "sent" || got.Attempts != 3 {
		t.Fatalf("after third: %+v", got)
	}
	if !strings.Contains(s.auth[0], "Bearer super-secret-key") {
		t.Fatalf("auth header: %s", s.auth[0])
	}
	if strings.Contains(s.bodies[0], `"body"`) {
		t.Fatalf("default payload included a body: %s", s.bodies[0])
	}
	for _, key := range []string{"message_id", "subject", "gmail_url", "delivery_id", "snippet"} {
		if !strings.Contains(s.bodies[0], key) {
			t.Fatalf("payload missing %s: %s", key, s.bodies[0])
		}
	}
}

func TestDeadLetterAfterMaxAttempts(t *testing.T) {
	db := openDB(t)
	_ = db.SetSetting("notify_dead", "1")
	note, err := db.SaveTarget(store.Target{Name: "ops", URL: "https://ops.example.com/hook"}, "n", false)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.SetSetting("notify_target", fmt.Sprint(note.ID))
	tg, err := db.SaveTarget(store.Target{Name: "bot", URL: "https://bot.example.com/hook"}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	d := queue(t, db, tg, "m9")
	s := &script{codes: []int{500, 500, 500, 500}}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	due(t, db, now)
	w := &Worker{DB: db, HTTP: s, Now: func() time.Time { return now }}
	for i := 0; i < 4; i++ {
		w.Step(context.Background())
		got, _, _ := db.DeliveryByID(d.ID)
		if got.Status == "dead" {
			break
		}
		now = time.Unix(got.NextAttempt, 0)
		w.Now = func() time.Time { return now }
	}
	got, _, _ := db.DeliveryByID(d.ID)
	if got.Status != "dead" {
		t.Fatalf("status %s attempts %d", got.Status, got.Attempts)
	}
	notes, _ := db.Deliveries("", "", "", 10)
	found := false
	for _, n := range notes {
		if n.Kind == "notify" && n.TargetName == "ops" {
			found = true
		}
	}
	if !found {
		t.Fatal("dead letter was not notified")
	}
}

func TestPauseQuietHoursDigestAndRate(t *testing.T) {
	db := openDB(t)
	paused, err := db.SaveTarget(store.Target{Name: "paused", URL: "https://p.example.com/h", Paused: true}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	queue(t, db, paused, "mp")
	s := &script{}
	now := time.Date(2026, 11, 18, 23, 0, 0, 0, time.UTC)
	due(t, db, now)
	w := &Worker{DB: db, HTTP: s, Now: func() time.Time { return now }, Locate: func() *time.Location { return time.UTC }}
	w.Step(context.Background())
	if len(s.bodies) != 0 {
		t.Fatal("paused target was called")
	}

	quiet, err := db.SaveTarget(store.Target{Name: "night", URL: "https://n.example.com/h", QuietStart: "22:00", QuietEnd: "07:00"}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	qd := queue(t, db, quiet, "mq")
	due(t, db, now)
	w.Step(context.Background())
	got, _, _ := db.DeliveryByID(qd.ID)
	until := time.Unix(got.NextAttempt, 0).UTC()
	if until.Hour() != 7 {
		t.Fatalf("quiet postpones to 07:00, got %s", until)
	}
	if len(s.bodies) != 0 {
		t.Fatal("sent during quiet hours")
	}

	dig, err := db.SaveTarget(store.Target{Name: "digest", URL: "https://d.example.com/h", DigestAt: "08:00"}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	// Pin last_digest to the fake clock, not the wall clock.
	if err := db.SetLastDigest(dig.ID, time.Date(2026, 11, 18, 23, 0, 0, 0, time.UTC).Unix()); err != nil {
		t.Fatal(err)
	}
	queue(t, db, dig, "md1")
	acc, _, _ := db.AccountByEmail("ada@example.com")
	msg := mail.Message{ID: "md2", From: "a@example.com", Subject: "two", Date: time.Now().UTC(), Labels: []string{"INBOX"}}
	_, _ = db.QueueAndAdvance(acc.ID, acc.Email, msg, []store.MatchPlan{{
		RouteKey: "route:d", RouteName: "inbox", TargetID: dig.ID, TargetName: dig.Name,
	}}, "")
	// Keep the quiet-hours row from becoming due while the digest is checked.
	_, _ = db.SQL.Exec(`UPDATE deliveries SET next_attempt=? WHERE target_name='night'`, time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC).Unix())
	morning := time.Date(2026, 11, 19, 7, 30, 0, 0, time.UTC)
	w.Now = func() time.Time { return morning }
	w.Step(context.Background())
	if len(s.bodies) != 0 {
		t.Fatal("digest fired before 08:00")
	}
	at := time.Date(2026, 11, 19, 8, 5, 0, 0, time.UTC)
	w.Now = func() time.Time { return at }
	w.Step(context.Background())
	if len(s.bodies) != 1 || !strings.Contains(s.bodies[0], `"digest":true`) || !strings.Contains(s.bodies[0], `"count":2`) {
		t.Fatalf("digest body: %v", s.bodies)
	}

	fast, err := db.SaveTarget(store.Target{Name: "fast", URL: "https://f.example.com/h", RatePerMin: 1}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.QueueAndAdvance(acc.ID, acc.Email, mail.Message{ID: "mr1", From: "a@example.com", Subject: "r1", Date: time.Now().UTC()}, []store.MatchPlan{{
		RouteKey: "route:r1", RouteName: "inbox", TargetID: fast.ID, TargetName: fast.Name,
	}}, "")
	_, _ = db.QueueAndAdvance(acc.ID, acc.Email, mail.Message{ID: "mr2", From: "a@example.com", Subject: "r2", Date: time.Now().UTC()}, []store.MatchPlan{{
		RouteKey: "route:r2", RouteName: "inbox", TargetID: fast.ID, TargetName: fast.Name,
	}}, "")
	// The rows were queued at the wall clock. Make them due on the fake clock, or the
	// test fails once the fixed date above is in the past.
	_, _ = db.SQL.Exec(`UPDATE deliveries SET next_attempt=? WHERE target_name='fast'`, at.Unix())
	w.Step(context.Background())
	if len(s.bodies) != 2 {
		t.Fatalf("rate limit sent extra, bodies=%d", len(s.bodies))
	}
}

func TestHMACSignature(t *testing.T) {
	db := openDB(t)
	tg, err := db.SaveTarget(store.Target{Name: "hmac", URL: "https://h.example.com/hook", AuthMode: "hmac"}, "topsecret", false)
	if err != nil {
		t.Fatal(err)
	}
	queue(t, db, tg, "mh")
	s := &script{}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	due(t, db, now)
	w := &Worker{DB: db, HTTP: s, Now: func() time.Time { return now }}
	w.Step(context.Background())
	if len(s.sig) != 1 || !strings.HasPrefix(s.sig[0], "sha256=") {
		t.Fatalf("signature %v", s.sig)
	}
	if strings.Contains(s.bodies[0], "topsecret") {
		t.Fatal("secret in body")
	}
}

func TestBackoff(t *testing.T) {
	if Backoff(1, 10*time.Second, time.Minute) != 10*time.Second {
		t.Fatal("attempt 1")
	}
	if Backoff(2, 10*time.Second, time.Minute) != 20*time.Second {
		t.Fatal("attempt 2")
	}
	if Backoff(10, 10*time.Second, time.Minute) != time.Minute {
		t.Fatal("cap")
	}
}

func TestDigestDueNewTargetDoesNotFireAfterTodaysTime(t *testing.T) {
	loc := time.UTC
	created := time.Date(2026, 11, 18, 15, 0, 0, 0, loc)
	if DigestDue(created, loc, "08:00", 0) {
		t.Fatal("last_digest=0 must not fire after today's time")
	}
	if DigestDue(created, loc, "08:00", created.Unix()) {
		t.Fatal("a target created after today's digest time must wait")
	}
	morning := time.Date(2026, 11, 19, 8, 5, 0, 0, loc)
	if !DigestDue(morning, loc, "08:00", created.Unix()) {
		t.Fatal("should fire the next morning")
	}
	before := time.Date(2026, 11, 19, 7, 0, 0, 0, loc)
	if DigestDue(before, loc, "08:00", 0) || DigestDue(before, loc, "08:00", created.Unix()) {
		t.Fatal("must still wait for the clock")
	}
}

func TestNewDigestTargetDoesNotFireImmediately(t *testing.T) {
	db := openDB(t)
	created := time.Date(2026, 11, 18, 15, 0, 0, 0, time.UTC)
	dig, err := db.SaveTarget(store.Target{Name: "digest", URL: "https://d.example.com/h", DigestAt: "08:00"}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetLastDigest(dig.ID, created.Unix()); err != nil {
		t.Fatal(err)
	}
	queue(t, db, dig, "md-new")
	s := &script{}
	w := &Worker{DB: db, HTTP: s, Now: func() time.Time { return created }, Locate: func() *time.Location { return time.UTC }}
	w.Step(context.Background())
	if len(s.bodies) != 0 {
		t.Fatalf("new digest fired immediately: %v", s.bodies)
	}
	later := time.Date(2026, 11, 19, 8, 5, 0, 0, time.UTC)
	w.Now = func() time.Time { return later }
	w.Step(context.Background())
	if len(s.bodies) != 1 || !strings.Contains(s.bodies[0], `"digest":true`) {
		t.Fatalf("should fire the next morning: %v", s.bodies)
	}
}

func TestRequestLogOmitsBodyByDefault(t *testing.T) {
	db := openDB(t)
	tg, err := db.SaveTarget(store.Target{Name: "bot", URL: "https://bot.example.com/hook"}, "super-secret-key", false)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := db.SaveAccount("ada@example.com", "r", "", 0, "", "1")
	if err != nil {
		t.Fatal(err)
	}
	msg := mail.Message{ID: "m-omit", ThreadID: "th", From: "Ada <ada@example.com>", Subject: "A <B> C",
		Snippet: "hi", Date: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC), Labels: []string{"INBOX"}}
	if _, err := db.QueueAndAdvance(acc.ID, acc.Email, msg, []store.MatchPlan{{
		RouteKey: "route:1", RouteName: "inbox", TargetID: tg.ID, TargetName: tg.Name,
	}}, ""); err != nil {
		t.Fatal(err)
	}
	dels, _ := db.Deliveries("", "", "", 5)
	if len(dels) == 0 {
		t.Fatal("no delivery")
	}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	due(t, db, now)
	s := &script{}
	w := &Worker{DB: db, HTTP: s, Now: func() time.Time { return now }}
	w.Step(context.Background())
	got, _, _ := db.DeliveryByID(dels[0].ID)
	if !strings.Contains(got.RequestLog, "[body not stored]") {
		t.Fatalf("expected body omitted, got %s", got.RequestLog)
	}
	if strings.Contains(got.RequestLog, "Ada <ada@example.com>") || strings.Contains(got.RequestLog, "A <B> C") {
		t.Fatalf("request log stored a payload body: %s", got.RequestLog)
	}
}

func TestRequestLogLeavesLessThanSign(t *testing.T) {
	db := openDB(t)
	_ = db.SetSetting("retain_bodies", "1")
	tg, err := db.SaveTarget(store.Target{Name: "bot", URL: "https://bot.example.com/hook"}, "super-secret-key", false)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := db.SaveAccount("ada@example.com", "r", "", 0, "", "1")
	if err != nil {
		t.Fatal(err)
	}
	msg := mail.Message{ID: "m-lt", ThreadID: "th", From: "Ada <ada@example.com>", Subject: "A <B> C",
		Snippet: "hi", Date: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC), Labels: []string{"INBOX"}}
	if _, err := db.QueueAndAdvance(acc.ID, acc.Email, msg, []store.MatchPlan{{
		RouteKey: "route:1", RouteName: "inbox", TargetID: tg.ID, TargetName: tg.Name,
	}}, ""); err != nil {
		t.Fatal(err)
	}
	dels, _ := db.Deliveries("", "", "", 5)
	if len(dels) == 0 {
		t.Fatal("no delivery")
	}
	if dels[0].From != "Ada <ada@example.com>" || dels[0].Subject != "A <B> C" {
		t.Fatalf("stored metadata: from=%q subject=%q", dels[0].From, dels[0].Subject)
	}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	due(t, db, now)
	s := &script{}
	w := &Worker{DB: db, HTTP: s, Now: func() time.Time { return now }}
	w.Step(context.Background())
	got, _, _ := db.DeliveryByID(dels[0].ID)
	if strings.Contains(got.RequestLog, `\`+`u003c`) {
		t.Fatalf("request log escaped <: %s", got.RequestLog)
	}
	if !strings.Contains(got.RequestLog, "Ada <ada@example.com>") || !strings.Contains(got.RequestLog, "A <B> C") {
		t.Fatalf("request log missing raw <: %s", got.RequestLog)
	}
}
