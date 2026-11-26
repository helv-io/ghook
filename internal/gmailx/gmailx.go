// Package gmailx is the slice of the Gmail API ghook uses. Tests supply a fake.
// The live client is built only when a mailbox is connected.
package gmailx

import (
	"context"
	"errors"
	"time"

	"github.com/helv-io/ghook/internal/mail"
)

// ErrHistoryGone means history.list rejected the stored history id (HTTP 404).
// The caller falls back to a recent messages.list and lets dedupe drop the overlap.
var ErrHistoryGone = errors.New("gmail history id is too old")

// Label is one Gmail label.
type Label struct {
	ID   string
	Name string
}

// Filter is a Gmail filter that adds a label.
type Filter struct {
	ID       string
	From     string
	Subject  string
	Query    string
	AddLabel string
}

// Client talks to one mailbox.
type Client interface {
	Profile(ctx context.Context) (email, historyID string, err error)
	Watch(ctx context.Context, topic string) (historyID string, expiration time.Time, err error)
	Stop(ctx context.Context) error
	History(ctx context.Context, startID string) (msgs []mail.Message, latest string, err error)
	ListSince(ctx context.Context, since time.Time, limit int) ([]mail.Message, error)
	Get(ctx context.Context, id string) (mail.Message, error)
	Labels(ctx context.Context) ([]Label, error)
	CreateLabel(ctx context.Context, name string) (Label, error)
	AddLabels(ctx context.Context, messageID string, labelIDs []string) error
	CreateFilter(ctx context.Context, f Filter) error
	Filters(ctx context.Context) ([]Filter, error)
	DeleteFilter(ctx context.Context, id string) error
}
