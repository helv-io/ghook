//go:build !linux

package main

import (
	"os"
	"path/filepath"

	"github.com/helv-io/ghook/internal/config"
)

func prepareData(cfg *config.Config) error {
	return os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750)
}
