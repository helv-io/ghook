// Package when parses user-supplied date and time values.
package when

import (
	"strings"
	"time"
)

// Parse reads s as RFC3339 (with an explicit offset when given) or as a
// date/time in loc. Date-only values are midnight in loc. An empty or
// unreadable value is 0.
func Parse(s string, loc *time.Location) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if loc == nil {
		loc = time.UTC
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Unix()
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.Unix()
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t.Unix()
		}
	}
	return 0
}
