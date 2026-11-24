package runtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/store"
)

// ParseClock reads "HH:MM" as minutes after midnight. "off", "none" and
// "disabled" turn the job off and return ok=false.
func ParseClock(s string) (minutes int, ok bool, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "off", "none", "disabled", "false", "0":
		return 0, false, nil
	}
	h, m, found := strings.Cut(s, ":")
	if !found {
		return 0, false, fmt.Errorf("want HH:MM or off, got %q", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, false, fmt.Errorf("want HH:MM or off, got %q", s)
	}
	return hh*60 + mm, true, nil
}

// NextRun is the first moment after now at the given local minute of the day.
func NextRun(now time.Time, minutes int) time.Time {
	y, mo, d := now.Date()
	t := time.Date(y, mo, d, minutes/60, minutes%60, 0, 0, now.Location())
	if !t.After(now) {
		t = time.Date(y, mo, d+1, minutes/60, minutes%60, 0, 0, now.Location())
	}
	return t
}

// compactLoop prunes old rows and compacts the database once a day at
// COMPACT_AT local time. Shortly after start it also compacts once if the
// file is mostly free pages, so an oversized file shrinks on the next deploy.
func (a *App) compactLoop(ctx context.Context) {
	at, on, err := ParseClock(a.Cfg.CompactAt)
	if err != nil {
		log.Printf("ghook: COMPACT_AT: %v; using 03:15", err)
		at, on = 3*60+15, true
	}
	if !on {
		log.Printf("ghook: daily compaction off")
		return
	}
	if !sleep(ctx, 30*time.Second) {
		return
	}
	if st, err := a.DB.Stats(); err == nil && st.NeedsCompact() {
		log.Printf("ghook: %s of %s is free space; compacting now", mib(st.FreeBytes()), mib(st.Bytes()))
		a.compact()
	}
	for {
		next := NextRun(time.Now(), at)
		if !sleep(ctx, time.Until(next)) {
			return
		}
		a.purge()
		a.compact()
	}
}

func (a *App) compact() {
	res, err := a.DB.Compact()
	if errors.Is(err, store.ErrCompactBusy) {
		log.Printf("ghook: compaction skipped: %v", err)
		return
	}
	if err != nil {
		log.Printf("ghook: compaction: %v", err)
		return
	}
	log.Printf("ghook: compacted database (%s): %s -> %s in %s", res.Mode, mib(res.Before.Bytes()), mib(res.After.Bytes()), res.Took.Round(time.Millisecond))
}

func mib(n int64) string {
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}
