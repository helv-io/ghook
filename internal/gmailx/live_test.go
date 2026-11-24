package gmailx

import (
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type fixedSource struct{ tok *oauth2.Token }

func (f fixedSource) Token() (*oauth2.Token, error) { return f.tok, nil }

func TestSavingSourceOnlySavesNewTokens(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	saves := 0
	save := func(string, string, time.Time) { saves++ }
	src := &savingSource{base: fixedSource{&oauth2.Token{AccessToken: "cached", Expiry: exp}}, refresh: "r", last: "cached", save: save}
	for i := 0; i < 3; i++ {
		if _, err := src.Token(); err != nil {
			t.Fatal(err)
		}
	}
	if saves != 0 {
		t.Fatalf("saved %d times without a refresh", saves)
	}
	src.base = fixedSource{&oauth2.Token{AccessToken: "fresh", Expiry: exp}}
	_, _ = src.Token()
	_, _ = src.Token()
	if saves != 1 {
		t.Fatalf("saved %d times after one refresh, want 1", saves)
	}
}
