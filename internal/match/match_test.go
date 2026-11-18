package match

import (
	"strings"
	"testing"
	"time"

	"github.com/helv-io/ghook/internal/mail"
)

func msg() mail.Message {
	return mail.Message{
		ID: "m1", From: "Ada Lovelace <ada@example.com>", To: "ceo@example.com, ops@example.com",
		Cc: "cfo@example.com", Subject: "Invoice 1042", Snippet: "please pay the invoice",
		Plain: "wire details attached", Date: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Labels: []string{"INBOX", "Ghook/CFO", "Ghook/Routed/CEO"}, Category: "primary", HasAttachment: true,
	}
}

func TestFromAddressAndDomain(t *testing.T) {
	m := msg()
	if !(Spec{From: []string{"ada@example.com"}}).Match(m) {
		t.Fatal("exact address")
	}
	if !(Spec{From: []string{"@example.com"}}).Match(m) {
		t.Fatal("domain with @")
	}
	if !(Spec{From: []string{"example.com"}}).Match(m) {
		t.Fatal("bare domain")
	}
	if (Spec{From: []string{"other@example.com"}}).Match(m) {
		t.Fatal("different address must not match")
	}
	if (Spec{From: []string{"evil.example.com"}}).Match(m) {
		t.Fatal("lookalike domain must not match")
	}
	if !(Spec{From: []string{"nope@nope.test", "ada@example.com"}}).Match(m) {
		t.Fatal("list is OR")
	}
}

func TestSubjectContainsLabelsCategoryAttachment(t *testing.T) {
	m := msg()
	if !(Spec{Subject: `(?i)^invoice`}).Match(m) {
		t.Fatal("subject regex")
	}
	if (Spec{Subject: `^wire`}).Match(m) {
		t.Fatal("subject should miss")
	}
	if (Spec{Subject: `(`}).Match(m) {
		t.Fatal("invalid regex fails closed")
	}
	if !(Spec{Contains: "wire details"}).Match(m) {
		t.Fatal("body contains")
	}
	if !(Spec{Contains: "PLEASE PAY"}).Match(m) {
		t.Fatal("snippet contains, case insensitive")
	}
	if !(Spec{Labels: []string{"inbox"}}).Match(m) {
		t.Fatal("label")
	}
	if (Spec{Labels: []string{"SPAM"}}).Match(m) {
		t.Fatal("missing label")
	}
	if !(Spec{Categories: []string{"promotions", "Primary"}}).Match(m) {
		t.Fatal("category")
	}
	if !(Spec{Attachment: "yes"}).Match(m) {
		t.Fatal("has attachment")
	}
	if (Spec{Attachment: "no"}).Match(m) {
		t.Fatal("attachment no")
	}
	if !(Spec{To: []string{"ops@example.com"}}).Match(m) {
		t.Fatal("to")
	}
	if !(Spec{Cc: []string{"@example.com"}}).Match(m) {
		t.Fatal("cc domain")
	}
}

func TestAndOrAndEmpty(t *testing.T) {
	m := msg()
	if !(Spec{}).Match(m) {
		t.Fatal("empty matches all")
	}
	and := Spec{Op: "and", From: []string{"ada@example.com"}, Categories: []string{"promotions"}}
	if and.Match(m) {
		t.Fatal("AND should fail")
	}
	or := Spec{Op: "or", From: []string{"ada@example.com"}, Categories: []string{"promotions"}}
	if !or.Match(m) {
		t.Fatal("OR should pass")
	}
	none := Spec{Op: "or", From: []string{"nope@example.com"}, Categories: []string{"social"}}
	if none.Match(m) {
		t.Fatal("OR with no true clause")
	}
}

func TestDecideFirstWinsContinueFallback(t *testing.T) {
	m := msg()
	routes := []Route{
		{Name: "off", Enabled: false, TargetName: "x", Spec: Spec{}},
		{Name: "invoices", Enabled: true, Continue: true, TargetName: "books", Spec: Spec{Subject: "Invoice"}},
		{Name: "ada", Enabled: true, TargetName: "ada-bot", Spec: Spec{From: []string{"@example.com"}}},
		{Name: "later", Enabled: true, TargetName: "nope", Spec: Spec{}},
		{Name: "fallback", Enabled: true, Fallback: true, TargetName: "ceo", Spec: Spec{Categories: []string{"primary"}}},
	}
	hits := Decide(routes, m)
	if len(hits) != 2 || hits[0].Name != "invoices" || hits[1].Name != "ada" {
		t.Fatalf("continue chain: %+v", names(hits))
	}
	routes[1].Continue = false
	hits = Decide(routes, m)
	if len(hits) != 1 || hits[0].Name != "invoices" {
		t.Fatalf("first wins: %+v", names(hits))
	}
	// nothing matches the regular rules, fallback still has a filter
	miss := msg()
	miss.Subject = "hello"
	miss.From = "bob@other.test"
	miss.Category = "promotions"
	routes = []Route{
		{Name: "ada", Enabled: true, TargetName: "ada-bot", Spec: Spec{From: []string{"ada@example.com"}}},
		{Name: "fallback", Enabled: true, Fallback: true, TargetName: "ceo", Spec: Spec{Categories: []string{"primary"}}},
	}
	if hits = Decide(routes, miss); len(hits) != 0 {
		t.Fatalf("fallback filter should exclude promotions: %+v", names(hits))
	}
	miss.Category = "primary"
	hits = Decide(routes, miss)
	if len(hits) != 1 || hits[0].Name != "fallback" {
		t.Fatalf("fallback: %+v", names(hits))
	}
	// a matching regular route suppresses the fallback
	if hits = Decide(routes, msg()); len(hits) != 1 || hits[0].Name != "ada" {
		t.Fatalf("regular suppresses fallback: %+v", names(hits))
	}
}

func TestLabelConvention(t *testing.T) {
	got := LabelTargets("Ghook", []string{"INBOX", "Ghook/CFO", "ghook/ceo", "Ghook/Routed/CFO", "Ghook/CFO/extra", "Other/X"})
	joined := strings.Join(got, ",")
	if joined != "CFO,ceo" {
		t.Fatalf("targets: %s", joined)
	}
	if LabelTargets("", []string{"Ghook/Ops"})[0] != "Ops" {
		t.Fatal("default prefix")
	}
	if RoutedLabel("Ghook", "CFO") != "Ghook/Routed/CFO" {
		t.Fatal(RoutedLabel("Ghook", "CFO"))
	}
}

func names(rs []Route) []string {
	var n []string
	for _, r := range rs {
		n = append(n, r.Name)
	}
	return n
}
