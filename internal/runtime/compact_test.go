package runtime

import (
	"testing"
	"time"
)

func TestParseClock(t *testing.T) {
	for in, want := range map[string]int{"03:15": 195, "0:00": 0, " 23:59 ": 1439} {
		got, on, err := ParseClock(in)
		if err != nil || !on || got != want {
			t.Errorf("%q: %d %v %v", in, got, on, err)
		}
	}
	for _, in := range []string{"off", "OFF", "none", "disabled"} {
		if _, on, err := ParseClock(in); on || err != nil {
			t.Errorf("%q should turn it off", in)
		}
	}
	for _, in := range []string{"3", "24:00", "03:60", "x:y"} {
		if _, _, err := ParseClock(in); err == nil {
			t.Errorf("%q should fail", in)
		}
	}
}

func TestNextRun(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip(err)
	}
	cases := []struct{ now, want string }{
		{"2026-03-10 01:00", "2026-03-10 03:15"},
		{"2026-03-10 03:15", "2026-03-11 03:15"},
		{"2026-03-10 22:00", "2026-03-11 03:15"},
		// Clocks spring forward at 02:00 on 2026-03-08; 03:15 still exists.
		{"2026-03-07 23:00", "2026-03-08 03:15"},
	}
	for _, c := range cases {
		now, _ := time.ParseInLocation("2006-01-02 15:04", c.now, ny)
		got := NextRun(now, 195).Format("2006-01-02 15:04")
		if got != c.want {
			t.Errorf("from %s: %s, want %s", c.now, got, c.want)
		}
	}
}
