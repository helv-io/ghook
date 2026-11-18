// Package mail is the message shape the matcher, the sync engine and the
// delivery worker share.
package mail

import "time"

// Message is one Gmail message reduced to what a route can see.
// Plain is held in memory for matching and for an opt-in body delivery.
// It is not written to the database unless retention is switched on, which
// it is not by default.
type Message struct {
	ID            string
	ThreadID      string
	HistoryID     string
	From          string
	To            string
	Cc            string
	Subject       string
	Snippet       string
	Plain         string
	Date          time.Time
	Labels        []string // human names, plus system ids such as INBOX
	Category      string   // primary, social, promotions, updates, forums
	HasAttachment bool
}

// CategoryFromLabels maps Gmail's category label ids onto the short names
// routes use.
func CategoryFromLabels(ids []string) string {
	for _, id := range ids {
		switch id {
		case "CATEGORY_PERSONAL":
			return "primary"
		case "CATEGORY_SOCIAL":
			return "social"
		case "CATEGORY_PROMOTIONS":
			return "promotions"
		case "CATEGORY_UPDATES":
			return "updates"
		case "CATEGORY_FORUMS":
			return "forums"
		}
	}
	return ""
}
