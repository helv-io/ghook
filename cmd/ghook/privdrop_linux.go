//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/helv-io/ghook/internal/config"
)

func prepareData(cfg *config.Config) error {
	dir := filepath.Dir(cfg.DBPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return nil
	}
	if err := chownR(dir, cfg.PUID, cfg.PGID); err != nil {
		return err
	}
	return drop(cfg.PUID, cfg.PGID)
}

func chownR(root string, uid, gid int) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

func drop(uid, gid int) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if os.Geteuid() != uid || os.Getuid() != uid {
		return fmt.Errorf("still running as uid %d", os.Geteuid())
	}
	if err := syscall.Setuid(0); err == nil {
		return fmt.Errorf("dropped privileges could be regained")
	}
	return nil
}
