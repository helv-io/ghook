package store

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

// Compaction gives freed pages back to the file system and empties the WAL.
// It runs on the one shared connection, so the outbox and the pull loop wait
// for it (busy_timeout) instead of racing it.

// FileStats is the on-disk size of the database.
type FileStats struct {
	Pages, FreePages, PageSize int64
	// WAL is the size of the -wal file in bytes.
	WAL int64
}

// Bytes is the main file plus the WAL.
func (s FileStats) Bytes() int64 { return s.Pages*s.PageSize + s.WAL }

// FreeBytes is the space held by free pages.
func (s FileStats) FreeBytes() int64 { return s.FreePages * s.PageSize }

// Stats reads the page counts and the WAL size.
func (d *DB) Stats() (FileStats, error) {
	var st FileStats
	if err := d.SQL.QueryRow(`PRAGMA page_count`).Scan(&st.Pages); err != nil {
		return st, err
	}
	if err := d.SQL.QueryRow(`PRAGMA freelist_count`).Scan(&st.FreePages); err != nil {
		return st, err
	}
	if err := d.SQL.QueryRow(`PRAGMA page_size`).Scan(&st.PageSize); err != nil {
		return st, err
	}
	if d.path != "" {
		if fi, err := os.Stat(d.path + "-wal"); err == nil {
			st.WAL = fi.Size()
		}
	}
	return st, nil
}

// CompactResult describes one compaction.
type CompactResult struct {
	Before, After FileStats
	// Mode is "vacuum" (a full rewrite, which also switches the file to
	// incremental auto-vacuum) or "incremental".
	Mode string
	Took time.Duration
}

// ErrCompactBusy is returned when another compaction is still running.
var ErrCompactBusy = fmt.Errorf("compaction already running")

// Compact checkpoints and truncates the WAL, then frees unused pages. A file
// that is not yet in incremental auto-vacuum mode gets one full VACUUM, which
// converts it. After that, incremental_vacuum is enough. The time of the last
// run is kept as the instance setting compact_last.
func (d *DB) Compact() (CompactResult, error) {
	mu := d.maint
	if mu == nil {
		mu = &sync.Mutex{}
	}
	if !mu.TryLock() {
		return CompactResult{}, ErrCompactBusy
	}
	defer mu.Unlock()
	start := time.Now()
	var res CompactResult
	var err error
	if res.Before, err = d.Stats(); err != nil {
		return res, err
	}
	if _, err := d.SQL.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return res, fmt.Errorf("checkpoint: %w", err)
	}
	var mode int
	if err := d.SQL.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return res, err
	}
	if mode != 2 {
		res.Mode = "vacuum"
		if _, err := d.SQL.Exec(`PRAGMA auto_vacuum=INCREMENTAL`); err != nil {
			return res, err
		}
		if _, err := d.SQL.Exec(`VACUUM`); err != nil {
			return res, fmt.Errorf("vacuum: %w", err)
		}
	} else {
		res.Mode = "incremental"
		if _, err := d.SQL.Exec(`PRAGMA incremental_vacuum`); err != nil {
			return res, fmt.Errorf("incremental vacuum: %w", err)
		}
	}
	if _, err := d.SQL.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return res, fmt.Errorf("checkpoint: %w", err)
	}
	if res.After, err = d.Stats(); err != nil {
		return res, err
	}
	res.Took = time.Since(start)
	_ = d.Instance().SetSetting("compact_last", strconv.FormatInt(time.Now().Unix(), 10))
	return res, nil
}

// CompactLast is when Compact last finished, or zero.
func (d *DB) CompactLast() time.Time {
	n := d.Instance().IntSetting("compact_last", 0)
	if n <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(n), 0)
}

// NeedsCompact reports whether the file has enough dead space to compact now:
// at least 8 MiB and a quarter of the file free, or a WAL over 64 MiB.
func (s FileStats) NeedsCompact() bool {
	free := s.FreeBytes()
	return (free >= 8<<20 && s.FreePages*4 >= s.Pages) || s.WAL >= 64<<20
}
