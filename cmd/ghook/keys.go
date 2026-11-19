package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/helv-io/ghook/internal/config"
	"github.com/helv-io/ghook/internal/secrets"
	"github.com/helv-io/ghook/internal/store"
)

func keysCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, `ghook keys rotate [--user EMAIL|ID] [--all]
ghook keys rotate-kek
`)
		return 2
	}
	switch args[0] {
	case "rotate":
		return keysRotate(args[1:])
	case "rotate-kek":
		return keysRotateKEK(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown keys command %q\n", args[0])
		return 2
	}
}

func keysRotate(args []string) int {
	fs := flag.NewFlagSet("keys rotate", flag.ExitOnError)
	user := fs.String("user", "", "user email or id")
	all := fs.Bool("all", false, "rotate every user's data key")
	_ = fs.Parse(args)
	if !*all && *user == "" {
		fmt.Fprintln(os.Stderr, "keys rotate requires --user or --all")
		return 2
	}
	db, err := openDB()
	if err != nil {
		log.Print(err)
		return 1
	}
	defer db.Close()
	var ids []int64
	if *all {
		users, err := db.Unscoped().Users()
		if err != nil {
			log.Print(err)
			return 1
		}
		for _, u := range users {
			ids = append(ids, u.ID)
		}
	} else {
		u, err := db.Unscoped().UserByRef(*user)
		if err != nil {
			log.Print(err)
			return 1
		}
		ids = []int64{u.ID}
	}
	for _, id := range ids {
		if err := db.Unscoped().RotateDEK(id); err != nil {
			log.Printf("rotate user %d: %v", id, err)
			return 1
		}
		log.Printf("rotated data key for user %d", id)
	}
	return 0
}

func keysRotateKEK(args []string) int {
	fs := flag.NewFlagSet("keys rotate-kek", flag.ExitOnError)
	_ = fs.Parse(args)
	cfg := config.Load()
	if cfg.SecretsKey != "" {
		fmt.Fprintln(os.Stderr, "keys rotate-kek only works with a key file (unset SECRETS_KEY)")
		return 2
	}
	if cfg.KeyFile == "" {
		fmt.Fprintln(os.Stderr, "keys rotate-kek: no key file")
		return 2
	}
	db, err := store.Open(cfg.DBPath, "", cfg.KeyFile)
	if err != nil {
		log.Print(err)
		return 1
	}
	defer db.Close()
	next, _, err := secrets.RotateLocalKEKFile(cfg.KeyFile)
	if err != nil {
		log.Print(err)
		return 1
	}
	if err := db.RotateKEK(next); err != nil {
		log.Print(err)
		return 1
	}
	if err := secrets.InstallRotatedKEKFile(cfg.KeyFile); err != nil {
		log.Print(err)
		return 1
	}
	log.Printf("rotated instance KEK; previous key kept as %s.bak", cfg.KeyFile)
	return 0
}
