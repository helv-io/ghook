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
	sub := mail.Message{From: "Capital One <alerts@notification.capitalone.com>"}
	if !(Spec{From: []string{"capitalone.com"}}).Match(sub) {
		t.Fatal("bare domain must match a subdomain")
	}
	if !(Spec{From: []string{"@capitalone.com"}}).Match(sub) {
		t.Fatal("@domain must match a subdomain")
	}
	if !(Spec{From: []string{"*.capitalone.com"}}).Match(sub) {
		t.Fatal("*.domain must match a subdomain")
	}
	if !(Spec{From: []string{"*.capitalone.com"}}).Match(mail.Message{From: "a@alerts.email.capitalone.com"}) {
		t.Fatal("*.domain must match a nested subdomain")
	}
	if !(Spec{From: []string{"*.CapitalOne.COM"}}).Match(mail.Message{From: "ALERTS@Notification.CapitalOne.com"}) {
		t.Fatal("*.domain is case-insensitive")
	}
	if (Spec{From: []string{"*.capitalone.com"}}).Match(mail.Message{From: "alerts@capitalone.com"}) {
		t.Fatal("*.domain must not match the apex")
	}
	if (Spec{From: []string{"*.capitalone.com"}}).Match(mail.Message{From: "eve@notcapitalone.com"}) {
		t.Fatal("*.domain must not match a lookalike")
	}
	if (Spec{From: []string{"capitalone.com"}}).Match(mail.Message{From: "eve@notcapitalone.com"}) {
		t.Fatal("suffix lookalike must not match")
	}
	if (Spec{From: []string{"capitalone.com"}}).Match(mail.Message{From: "eve@example.com"}) {
		t.Fatal("unrelated domain must not match")
	}
	if !(Spec{From: []string{"capitalone.com"}}).Match(mail.Message{From: "alerts@capitalone.com"}) {
		t.Fatal("bare domain must still match the apex")
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
	// Existing Gmail labels may still use the old "Ghook/" capitalization.
	got := LabelTargets("ghook", []string{"INBOX", "Ghook/CFO", "ghook/ceo", "Ghook/Routed/CFO", "Ghook/CFO/extra", "Other/X"})
	joined := strings.Join(got, ",")
	if joined != "CFO,ceo" {
		t.Fatalf("targets: %s", joined)
	}
	if LabelTargets("Ghook", []string{"ghook/Ops"})[0] != "Ops" {
		t.Fatal("prefix comparison is case-insensitive")
	}
	if LabelTargets("", []string{"Ghook/Ops"})[0] != "Ops" {
		t.Fatal("default prefix still matches existing Ghook/ labels")
	}
	if RoutedLabel("", "CFO") != "ghook/Routed/CFO" {
		t.Fatal(RoutedLabel("", "CFO"))
	}
	if RoutedLabel("Ghook", "CFO") != "Ghook/Routed/CFO" {
		t.Fatal("an explicit stored prefix is kept as written")
	}
}

func names(rs []Route) []string {
	var n []string
	for _, r := range rs {
		n = append(n, r.Name)
	}
	return n
}

func TestDecideClaimedSuppressesFallback(t *testing.T) {
	m := msg()
	m.From = "billing@other.test"
	m.Subject = "tax bill"
	routes := []Route{
		{Name: "ada", Enabled: true, TargetName: "ada-bot", Spec: Spec{From: []string{"ada@example.com"}}},
		{Name: "fallback", Enabled: true, Fallback: true, TargetName: "ceo", Spec: Spec{Categories: []string{"primary"}}},
	}
	hits := Decide(routes, m)
	if len(hits) != 1 || hits[0].Name != "fallback" {
		t.Fatalf("unclaimed should fall back: %+v", names(hits))
	}
	hits = DecideClaimed(routes, m, true)
	if len(hits) != 0 {
		t.Fatalf("claimed by a ghook/ label must not fall back: %+v", names(hits))
	}
}

func TestSortSendersOrder(t *testing.T) {
	in := []string{"zed@b.com", "*.capitalone.com", "mercury.com", "Ada@example.com", "*.Alpha.com", "chase.com", "@bank.com", "MERCURY.COM", "bob@a.com", "ada@example.com"}
	got := SortSenders(in)
	want := []string{"@bank.com", "chase.com", "mercury.com", "*.Alpha.com", "*.capitalone.com", "Ada@example.com", "bob@a.com", "zed@b.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestNormalizeSortsAddressLists(t *testing.T) {
	s := Spec{From: []string{"x@b.com, a.com\n*.c.com"}, To: []string{"z@x.com", "y.com"}, Labels: []string{"Z", "A"}}.Normalize()
	if strings.Join(s.From, ",") != "a.com,*.c.com,x@b.com" {
		t.Fatalf("from %v", s.From)
	}
	if strings.Join(s.To, ",") != "y.com,z@x.com" {
		t.Fatalf("to %v", s.To)
	}
	if strings.Join(s.Labels, ",") != "Z,A" {
		t.Fatalf("labels keep their order: %v", s.Labels)
	}
}

func TestViewSectionsKeepFieldOrder(t *testing.T) {
	v := Spec{Op: "or", Subject: "(?i)bill", From: []string{"b.com", "a.com"}, Categories: []string{"primary"}, Attachment: "yes", Labels: []string{"INBOX"}}.View()
	var keys []string
	for _, s := range v.Sections {
		keys = append(keys, s.Key)
	}
	if strings.Join(keys, ",") != "from,subject,labels,category,attachment" {
		t.Fatalf("keys %v", keys)
	}
	if v.Op != "or" || v.Sections[0].Values[0] != "a.com" || v.Total() != 6 {
		t.Fatalf("view %+v", v)
	}
	if v.Sections[3].Editable() || !v.Sections[0].Editable() {
		t.Fatal("category is fixed, from is editable")
	}
	if (Spec{}).View().Sections != nil {
		t.Fatal("empty spec has no sections")
	}
	if got := (Spec{From: []string{"a", "b", "c", "d", "e"}, To: []string{"x"}}).View().Hidden(3); got != 2 {
		t.Fatalf("hidden %d", got)
	}
}

func TestWithField(t *testing.T) {
	s, ok := Spec{From: []string{"a.com"}}.WithField("from", "z@x.com\nb.com\n\n")
	if !ok || strings.Join(s.From, ",") != "b.com,z@x.com" {
		t.Fatalf("from %v", s.From)
	}
	if _, ok := s.WithField("category", "primary"); ok {
		t.Fatal("category is not editable in place")
	}
}
