package when

import (
	"testing"
	"time"
)

func TestParseDisplayTimezoneAndOffset(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	got := Parse("2026-11-18", ny)
	want := time.Date(2026, 11, 18, 0, 0, 0, 0, ny).Unix()
	if got != want {
		t.Fatalf("date-only in NY: %d want %d (UTC would be %d)", got, want, time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC).Unix())
	}
	if Parse("2026-11-18", time.UTC) == want {
		t.Fatal("UTC date-only must differ from NY midnight")
	}
	offset := Parse("2026-11-18T00:00:00-05:00", time.UTC)
	if offset != want {
		t.Fatalf("explicit offset: %d want %d", offset, want)
	}
	if Parse("2026-11-18T13:45:00", ny) != time.Date(2026, 11, 18, 13, 45, 0, 0, ny).Unix() {
		t.Fatal("datetime without zone should use display timezone")
	}
	if Parse("", ny) != 0 || Parse("nope", ny) != 0 {
		t.Fatal("empty or junk is 0")
	}
}
