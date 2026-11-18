// Package feed is the in-memory activity stream the dashboard reads over SSE.
package feed

import (
	"sync"
	"time"
)

// Event is one line of the activity feed. Text is already safe to show.
type Event struct {
	Time time.Time `json:"-"`
	Kind string    `json:"kind"`
	Text string    `json:"text"`
}

// Feed keeps a short backlog and fans out to listeners.
type Feed struct {
	mu   sync.Mutex
	buf  []Event
	subs map[chan Event]struct{}
	max  int
}

// New returns a feed that keeps the last 200 events.
func New() *Feed {
	return &Feed{subs: map[chan Event]struct{}{}, max: 200}
}

// Add records an event and notifies listeners. A slow listener is skipped.
func (f *Feed) Add(kind, text string) {
	if f == nil {
		return
	}
	ev := Event{Time: time.Now().UTC(), Kind: kind, Text: text}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buf = append(f.buf, ev)
	if len(f.buf) > f.max {
		f.buf = f.buf[len(f.buf)-f.max:]
	}
	for ch := range f.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Backlog returns a copy of the recent events, oldest first.
func (f *Feed) Backlog() []Event {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Event, len(f.buf))
	copy(out, f.buf)
	return out
}

// Subscribe registers a listener. Cancel removes it.
func (f *Feed) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 16)
	f.mu.Lock()
	f.subs[ch] = struct{}{}
	f.mu.Unlock()
	return ch, func() {
		f.mu.Lock()
		delete(f.subs, ch)
		f.mu.Unlock()
	}
}
