// Command ghook routes Gmail push notifications to webhooks.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/helv-io/ghook/internal/bundle"
	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/runtime"
	"github.com/helv-io/ghook/internal/store"
	"github.com/helv-io/ghook/internal/web"
	"github.com/helv-io/ghook/internal/when"
)

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "export":
			os.Exit(exportCmd(os.Args[2:]))
		case "import":
			os.Exit(importCmd(os.Args[2:]))
		case "replay":
			os.Exit(replayCmd(os.Args[2:]))
		case "-h", "--help", "help":
			usage()
			return
		}
	}
	if err := serve(); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ghook routes Gmail to webhooks.

  ghook                 start the server
  ghook healthcheck     exit 0 when /healthz answers
  ghook export          write routes and targets as YAML (secrets omitted)
  ghook import FILE     load that YAML
  ghook replay          re-queue deliveries

Environment: PUBLIC_URL, LISTEN_ADDR, DB_PATH, OIDC_ISSUER, OIDC_CLIENT_ID,
OIDC_CLIENT_SECRET, OIDC_ALLOWED_EMAILS, OIDC_ALLOWED_GROUPS, SECRETS_KEY, PUID, PGID.
`)
}

func serve() error {
	cfg := config.Load()
	if err := prepareData(cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750); err != nil {
		return err
	}
	db, err := store.Open(cfg.DBPath, cfg.SecretsKey, cfg.KeyFile)
	if err != nil {
		return err
	}
	defer db.Close()
	log.Printf("secrets: encryption key from %s", db.Source)
	rt := runtime.New(cfg, db)
	srv, err := web.New(rt)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rt.Start(ctx)
	httpSrv := &http.Server{
		Addr: cfg.Listen, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(c)
	}()
	log.Printf("ghook %s listening on %s (public %s)", config.Version, cfg.Listen, cfg.PublicURL)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func healthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	res, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode != 200 {
		fmt.Fprintln(os.Stderr, res.Status)
		return 1
	}
	return 0
}

func openDB() (*store.DB, error) {
	cfg := config.Load()
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750); err != nil {
		return nil, err
	}
	return store.Open(cfg.DBPath, cfg.SecretsKey, cfg.KeyFile)
}

func exportCmd(args []string) int {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	pass := fs.String("passphrase", "", "seal secrets with this passphrase")
	_ = fs.Parse(args)
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer db.Close()
	raw, err := bundle.Export(db, *pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_, _ = os.Stdout.Write(raw)
	return 0
}

func importCmd(args []string) int {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	pass := fs.String("passphrase", "", "passphrase the file was sealed with")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: ghook import FILE")
		return 2
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer db.Close()
	msg, err := bundle.Import(db, raw, *pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(msg)
	return 0
}

func replayCmd(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	id := fs.Int64("id", 0, "one delivery id")
	route := fs.String("route", "", "route name")
	target := fs.String("target", "", "target name")
	since := fs.String("since", "", "RFC3339 or YYYY-MM-DD, in the workspace display timezone unless an offset is given")
	until := fs.String("until", "", "RFC3339 or YYYY-MM-DD, in the workspace display timezone unless an offset is given")
	workspace := fs.String("workspace", "", "workspace name or id (default workspace if empty)")
	_ = fs.Parse(args)
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer db.Close()
	if *workspace != "" {
		ws, err := db.WorkspaceByRef(*workspace)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		db = db.Use(ws.ID)
	}
	if *id != 0 {
		if err := db.Replay(*id, true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("re-queued delivery %d\n", *id)
		return 0
	}
	loc := time.UTC
	if name := db.Setting("timezone", "UTC"); name != "" {
		if l, err := time.LoadLocation(name); err == nil {
			loc = l
		}
	}
	n, err := db.ReplayWindow(*route, *target, when.Parse(*since, loc), when.Parse(*until, loc))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("re-queued %d deliveries\n", n)
	return 0
}
