// Package runtime wires the database to Gmail, Pub/Sub and the outbox and runs
// the background loops.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/deliver"
	"github.com/helv-io/ghook/internal/engine"
	"github.com/helv-io/ghook/internal/feed"
	"github.com/helv-io/ghook/internal/gmailx"
	"github.com/helv-io/ghook/internal/pubsubx"
	"github.com/helv-io/ghook/internal/store"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// App is the running service behind the HTTP server.
type App struct {
	Cfg    *config.Config
	DB     *store.DB
	Engine *engine.Engine
	Worker *deliver.Worker
	Feed   *feed.Feed

	mu     sync.Mutex
	tokSrc oauth2.TokenSource
	tokKey string
}

// New builds the engine and the worker. It does not start them.
func New(cfg *config.Config, db *store.DB) *App {
	f := feed.New()
	a := &App{Cfg: cfg, DB: db, Feed: f}
	a.Engine = &engine.Engine{DB: db, Feed: f, Clients: a.Client, MaxDeliveries: cfg.MaxDeliveries}
	a.Worker = &deliver.Worker{DB: db, Feed: f, Bodies: a.plain}
	return a
}

// Client opens Gmail for one connected mailbox.
func (a *App) Client(ctx context.Context, email string) (gmailx.Client, error) {
	accs, err := a.DB.Unscoped().AccountsByEmail(email)
	if err != nil {
		return nil, err
	}
	if len(accs) == 0 {
		return nil, errString("mailbox is not connected")
	}
	acc := accs[0]
	db := a.DB.Use(acc.UserID)
	raw := a.Cfg.GoogleClient
	if strings.TrimSpace(raw) == "" {
		return nil, errString("GOOGLE_CLIENT_FILE is not set")
	}
	access, exp := acc.AccessToken()
	scopes := strings.Fields(acc.Scopes)
	if len(scopes) == 0 {
		scopes = gmailx.ScopeList(db.BoolSetting("gmail_modify", false), db.BoolSetting("gmail_settings", false), false)
	}
	return gmailx.Dial(ctx, raw, acc.RefreshToken(), access, time.Unix(exp, 0), scopes, func(refresh, access string, expiry time.Time) {
		_ = db.UpdateTokens(acc.ID, refresh, access, expiry.Unix())
	})
}

func (a *App) plain(ctx context.Context, email, id string) (string, error) {
	c, err := a.Client(ctx, email)
	if err != nil {
		return "", err
	}
	m, err := c.Get(ctx, id)
	if err != nil {
		return "", err
	}
	return m.Plain, nil
}

// Start runs watches, catch-up, the outbox, retention and the pull loop until ctx ends.
func (a *App) Start(ctx context.Context) {
	_ = a.DB.ResetInflight()
	go a.Worker.Run(ctx)
	go a.pull(ctx)
	go a.maintenance(ctx)
}

func (a *App) maintenance(ctx context.Context) {
	a.renew(ctx)
	a.catchUp(ctx)
	watch := time.NewTicker(time.Hour)
	catch := time.NewTicker(time.Minute)
	purge := time.NewTicker(6 * time.Hour)
	defer watch.Stop()
	defer catch.Stop()
	defer purge.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-watch.C:
			a.renew(ctx)
		case <-catch.C:
			a.catchUp(ctx)
		case <-purge.C:
			a.purge()
		}
	}
}

func (a *App) catchUp(ctx context.Context) {
	users, err := a.DB.Unscoped().Users()
	if err != nil {
		return
	}
	for _, u := range users {
		eng := *a.Engine
		eng.DB = a.DB.Use(u.ID)
		eng.CatchUp(ctx)
	}
}

func (a *App) renew(ctx context.Context) {
	if !a.Cfg.PubSubReady() {
		return
	}
	users, err := a.DB.Unscoped().Users()
	if err != nil {
		return
	}
	topic := pubsubx.TopicPath(a.Cfg.PubSubProject, a.Cfg.PubSubTopic)
	for _, u := range users {
		eng := *a.Engine
		eng.DB = a.DB.Use(u.ID)
		eng.RenewWatches(ctx, topic)
	}
}

func (a *App) purge() {
	users, err := a.DB.Unscoped().Users()
	if err != nil {
		return
	}
	var n int
	for _, u := range users {
		db := a.DB.Use(u.ID)
		days := db.IntSetting("retention_days", 30)
		if days < 1 {
			days = 30
		}
		k, err := db.Purge(time.Now().AddDate(0, 0, -days).Unix())
		if err != nil {
			log.Printf("ghook: purge: %v", err)
			continue
		}
		n += k
	}
	if n > 0 {
		a.Feed.Add("sync", "Purged old mail metadata")
	}
}

func (a *App) pull(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if !a.Cfg.PubSubReady() {
			if !sleep(ctx, 5*time.Second) {
				return
			}
			continue
		}
		api := &pubsubx.API{Token: func(ctx context.Context) (string, error) { return a.token(ctx) }}
		sub := pubsubx.SubPath(a.Cfg.PubSubProject, a.Cfg.PubSubSub)
		msgs, err := api.Pull(ctx, sub, 10)
		if err != nil {
			log.Printf("ghook: pubsub pull: %v", err)
			a.Feed.Add("error", "Pub/Sub pull failed")
			if !sleep(ctx, 5*time.Second) {
				return
			}
			continue
		}
		var ack []string
		for _, m := range msgs {
			if err := a.Engine.HandleNotification(ctx, m.Data); err != nil {
				log.Printf("ghook: notification left unacked: %v", err)
				continue
			}
			ack = append(ack, m.AckID)
		}
		if err := api.Ack(ctx, sub, ack); err != nil {
			log.Printf("ghook: pubsub ack: %v", err)
		}
		if !sleep(ctx, 2*time.Second) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// AccessToken is a bearer token for the Pub/Sub API.
func (a *App) AccessToken(ctx context.Context) (string, error) { return a.token(ctx) }

func (a *App) token(ctx context.Context) (string, error) { return a.tokenFor(ctx, a.DB) }

func (a *App) tokenFor(ctx context.Context, _ *store.DB) (string, error) {
	raw := a.Cfg.PubSubSA
	if strings.TrimSpace(raw) == "" {
		return "", pubsubx.ErrNotConfigured
	}
	sum := sha256.Sum256([]byte(raw))
	src, err := a.cached(ctx, "sa:"+hex.EncodeToString(sum[:8]), func() (oauth2.TokenSource, error) {
		cred, err := google.CredentialsFromJSON(ctx, []byte(raw), gmailx.ScopePubSub)
		if err != nil {
			return nil, err
		}
		return cred.TokenSource, nil
	})
	if err != nil {
		return "", err
	}
	t, err := src.Token()
	if err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

func (a *App) cached(ctx context.Context, key string, build func() (oauth2.TokenSource, error)) (oauth2.TokenSource, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tokSrc != nil && a.tokKey == key {
		return a.tokSrc, nil
	}
	src, err := build()
	if err != nil {
		return nil, err
	}
	a.tokSrc, a.tokKey = src, key
	return src, nil
}

type errString string

func (e errString) Error() string { return string(e) }
