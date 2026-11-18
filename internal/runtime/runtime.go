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
	a.Engine = &engine.Engine{DB: db, Feed: f, Clients: a.Client}
	a.Worker = &deliver.Worker{DB: db, Feed: f, Bodies: a.plain}
	return a
}

// Client opens Gmail for one connected mailbox.
func (a *App) Client(ctx context.Context, email string) (gmailx.Client, error) {
	acc, ok, err := a.DB.AccountByEmail(email)
	if err != nil {
		return nil, err
	}
	if !ok {
		accs, err := a.DB.Unscoped().AccountsByEmail(email)
		if err != nil || len(accs) == 0 {
			if err == nil {
				err = errString("mailbox is not connected")
			}
			return nil, err
		}
		acc = accs[0]
	}
	ws := a.DB.Use(acc.WorkspaceID)
	raw, ok, err := ws.GoogleClientJSON()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errString("upload the Google OAuth client first")
	}
	access, exp := acc.AccessToken()
	scopes := strings.Fields(acc.Scopes)
	if len(scopes) == 0 {
		scopes = gmailx.ScopeList(ws.BoolSetting("gmail_modify", false), ws.BoolSetting("gmail_settings", false), false)
	}
	return gmailx.Dial(ctx, raw, acc.RefreshToken(), access, time.Unix(exp, 0), scopes, func(refresh, access string, expiry time.Time) {
		_ = ws.UpdateTokens(acc.ID, refresh, access, expiry.Unix())
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
	wss, err := a.DB.Unscoped().Workspaces()
	if err != nil {
		return
	}
	for _, w := range wss {
		eng := *a.Engine
		eng.DB = a.DB.Use(w.ID)
		eng.CatchUp(ctx)
	}
}

func (a *App) renew(ctx context.Context) {
	wss, err := a.DB.Unscoped().Workspaces()
	if err != nil {
		return
	}
	for _, w := range wss {
		ws := a.DB.Use(w.ID)
		ps := ws.LoadPubSub()
		if ps.Project == "" || ps.Topic == "" {
			continue
		}
		eng := *a.Engine
		eng.DB = ws
		eng.RenewWatches(ctx, pubsubx.TopicPath(ps.Project, ps.Topic))
	}
}

func (a *App) purge() {
	days := a.DB.IntSetting("retention_days", 30)
	if days < 1 {
		days = 30
	}
	n, err := a.DB.Purge(time.Now().AddDate(0, 0, -days).Unix())
	if err != nil {
		log.Printf("ghook: purge: %v", err)
		return
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
		conns, err := a.DB.Unscoped().PubSubs()
		if err != nil || len(conns) == 0 {
			if !sleep(ctx, 5*time.Second) {
				return
			}
			continue
		}
		pulled := false
		for _, ps := range conns {
			if ps.Mode != "pull" || ps.Project == "" || ps.Subscription == "" {
				continue
			}
			pulled = true
			ws := a.DB.Use(ps.WorkspaceID)
			api := &pubsubx.API{Token: func(ctx context.Context) (string, error) { return a.tokenFor(ctx, ws) }}
			sub := pubsubx.SubPath(ps.Project, ps.Subscription)
			msgs, err := api.Pull(ctx, sub, 10)
			if err != nil {
				log.Printf("ghook: pubsub pull: %v", err)
				a.Feed.Add("error", "Pub/Sub pull failed")
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
		}
		if !pulled {
			if !sleep(ctx, 5*time.Second) {
				return
			}
			continue
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

func (a *App) tokenFor(ctx context.Context, ws *store.DB) (string, error) {
	ps := ws.LoadPubSub()
	if ps.HasSA {
		raw, err := ws.ServiceAccountJSON()
		if err != nil {
			return "", err
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
	if !ps.UseOAuth {
		return "", pubsubx.ErrNotConfigured
	}
	accs, err := ws.Accounts()
	if err != nil {
		return "", err
	}
	var chosen *store.Account
	for i := range accs {
		if strings.Contains(accs[i].Scopes, "pubsub") && accs[i].HasToken {
			chosen = &accs[i]
			break
		}
	}
	if chosen == nil {
		return "", errString("no connected account has the Pub/Sub scope")
	}
	raw, _, err := ws.GoogleClientJSON()
	if err != nil {
		return "", err
	}
	cfg, err := gmailx.Config(raw, a.Cfg.GoogleRedirect(), strings.Fields(chosen.Scopes))
	if err != nil {
		return "", err
	}
	access, exp := chosen.AccessToken()
	src := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: chosen.RefreshToken(), AccessToken: access, Expiry: time.Unix(exp, 0)})
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
