package engine

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/helv-io/ghook/internal/gmailx"
	"github.com/helv-io/ghook/internal/mail"
	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/store"
)

type fakeGmail struct {
	historyErr error
	history    map[string][]mail.Message
	latest     map[string]string
	recent     []mail.Message
}

func (f *fakeGmail) Profile(context.Context) (string, string, error) {
	return "ada@example.com", "10", nil
}
func (f *fakeGmail) Watch(context.Context, string) (string, time.Time, error) {
	return "10", time.Now().Add(7 * 24 * time.Hour), nil
}
func (f *fakeGmail) Stop(context.Context) error { return nil }
func (f *fakeGmail) History(_ context.Context, start string) ([]mail.Message, string, error) {
	if f.historyErr != nil {
		return nil, "", f.historyErr
	}
	return f.history[start], f.latest[start], nil
}
func (f *fakeGmail) ListSince(context.Context, time.Time, int) ([]mail.Message, error) {
	return f.recent, nil
}
func (f *fakeGmail) Get(_ context.Context, id string) (mail.Message, error) {
	return mail.Message{ID: id, Plain: "wire details"}, nil
}
func (f *fakeGmail) Labels(context.Context) ([]gmailx.Label, error) { return nil, nil }
func (f *fakeGmail) CreateLabel(_ context.Context, name string) (gmailx.Label, error) {
	return gmailx.Label{ID: "L", Name: name}, nil
}
func (f *fakeGmail) AddLabels(context.Context, string, []string) error { return nil }
func (f *fakeGmail) CreateFilter(context.Context, gmailx.Filter) error { return nil }

func openDB(t *testing.T) *store.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "ghook.db"), "", filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestParseNoteNumberOrString(t *testing.T) {
	n, err := ParseNote([]byte(`{"emailAddress":"ada@example.com","historyId":12345}`))
	if err != nil || n.History != "12345" || n.Email != "ada@example.com" {
		t.Fatal(n, err)
	}
	n, err = ParseNote([]byte(`{"emailAddress":"ada@example.com","historyId":"99"}`))
	if err != nil || n.History != "99" {
		t.Fatal(n, err)
	}
	if _, err := ParseNote([]byte(`{"emailAddress":"ada@example.com"}`)); err == nil {
		t.Fatal("missing history must fail")
	}
}

func TestSyncAdvancesHistoryAfterQueueAndDedupes(t *testing.T) {
	db := openDB(t)
	if _, err := db.SaveAccount("ada@example.com", "refresh", "", 0, "gmail.readonly", "10"); err != nil {
		t.Fatal(err)
	}
	cfo, err := db.SaveTarget(store.Target{Name: "CFO", URL: "https://cfo.example.com/hook"}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveRoute(store.Route{
		Name: "invoices", Enabled: true, TargetID: cfo.ID,
		Spec: match.Spec{Subject: "Invoice"},
	}); err != nil {
		t.Fatal(err)
	}
	msg := mail.Message{ID: "m1", ThreadID: "t1", From: "ada@example.com", Subject: "Invoice 9", Snippet: "pay",
		Date: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), Labels: []string{"INBOX", "CATEGORY_PERSONAL"}}
	f := &fakeGmail{
		history: map[string][]mail.Message{"10": {msg}, "15": {msg}},
		latest:  map[string]string{"10": "15", "15": "16"},
	}
	eng := &Engine{DB: db, Clients: func(context.Context, string) (gmailx.Client, error) { return f, nil }}
	if err := eng.Sync(context.Background(), "ada@example.com", "15"); err != nil {
		t.Fatal(err)
	}
	acc, _, _ := db.AccountByEmail("ada@example.com")
	if acc.HistoryID != "15" {
		t.Fatalf("history = %s, want 15", acc.HistoryID)
	}
	dels, _ := db.Deliveries("", "", "", 10)
	if len(dels) != 1 || dels[0].RouteName != "invoices" {
		t.Fatalf("deliveries: %+v", dels)
	}
	if err := eng.Sync(context.Background(), "ada@example.com", "16"); err != nil {
		t.Fatal(err)
	}
	dels, _ = db.Deliveries("", "", "", 10)
	if len(dels) != 1 {
		t.Fatalf("dedupe failed, got %d", len(dels))
	}
	acc, _, _ = db.AccountByEmail("ada@example.com")
	if acc.HistoryID != "16" {
		t.Fatalf("history = %s", acc.HistoryID)
	}
}

func TestHistoryNotAdvancedWhenFetchFails(t *testing.T) {
	db := openDB(t)
	_, _ = db.SaveAccount("ada@example.com", "refresh", "", 0, "", "10")
	f := &fakeGmail{historyErr: errors.New("gmail down")}
	eng := &Engine{DB: db, Clients: func(context.Context, string) (gmailx.Client, error) { return f, nil }}
	if err := eng.Sync(context.Background(), "ada@example.com", "20"); err == nil {
		t.Fatal("expected error")
	}
	acc, _, _ := db.AccountByEmail("ada@example.com")
	if acc.HistoryID != "10" {
		t.Fatalf("history moved on failure: %s", acc.HistoryID)
	}
}

func TestHistoryGoneFallsBackAndDedupesOverlap(t *testing.T) {
	db := openDB(t)
	acc, err := db.SaveAccount("ada@example.com", "refresh", "", 0, "", "10")
	if err != nil {
		t.Fatal(err)
	}
	cfo, err := db.SaveTarget(store.Target{Name: "CFO", URL: "https://cfo.example.com/h"}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	ceo, err := db.SaveTarget(store.Target{Name: "CEO", URL: "https://ceo.example.com/h"}, "s", false)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := db.SaveRoute(store.Route{Name: "all", Enabled: true, TargetID: cfo.ID})
	if err != nil {
		t.Fatal(err)
	}
	old := mail.Message{ID: "old", From: "a@example.com", Subject: "old", Date: time.Now().UTC(), Labels: []string{"INBOX"}}
	fresh := mail.Message{ID: "new", From: "a@example.com", Subject: "new", Date: time.Now().UTC(), Labels: []string{"INBOX", "Ghook/CEO"}}
	if _, err := db.QueueAndAdvance(acc.ID, acc.Email, old, []store.MatchPlan{{
		RouteKey: "route:" + itoa(rt.ID), RouteName: "all", TargetID: cfo.ID, TargetName: "CFO",
	}}, ""); err != nil {
		t.Fatal(err)
	}
	f := &fakeGmail{historyErr: gmailx.ErrHistoryGone, recent: []mail.Message{old, fresh}}
	eng := &Engine{DB: db, Clients: func(context.Context, string) (gmailx.Client, error) { return f, nil }}
	if err := eng.Sync(context.Background(), "ada@example.com", "50"); err != nil {
		t.Fatal(err)
	}
	acc, _, _ = db.AccountByEmail("ada@example.com")
	if acc.HistoryID != "50" {
		t.Fatalf("history %s", acc.HistoryID)
	}
	dels, _ := db.Deliveries("", "", "", 20)
	got := map[string]bool{}
	for _, d := range dels {
		got[d.GmailID+":"+d.TargetName] = true
	}
	if !got["old:CFO"] || !got["new:CFO"] || !got["new:CEO"] || len(dels) != 3 {
		t.Fatalf("overlap: %+v", got)
	}
	_ = ceo
}

func TestUnknownAccountIsAckable(t *testing.T) {
	db := openDB(t)
	eng := &Engine{DB: db}
	err := eng.HandleNotification(context.Background(), []byte(`{"emailAddress":"nope@example.com","historyId":1}`))
	if err != nil {
		t.Fatal(err)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
