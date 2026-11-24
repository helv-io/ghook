// Package match decides which routes a message hits.
// Routes are ordered. The first match wins unless that route says continue.
// Fallback routes run only when nothing else matched, and they still have a filter.
package match

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/helv-io/ghook/internal/mail"
)

// DefaultPrefix is the Gmail label prefix used when the setting is empty.
const DefaultPrefix = "ghook"

// Prefix returns the configured label prefix, or DefaultPrefix when empty.
func Prefix(p string) string {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return DefaultPrefix
	}
	return p
}

// Spec is one route's filter. An empty spec matches every message.
// Lists inside one field are OR (any sender, any label). Fields combine with Op.
type Spec struct {
	Op         string   `json:"op" yaml:"op,omitempty"`
	From       []string `json:"from,omitempty" yaml:"from,omitempty"`
	To         []string `json:"to,omitempty" yaml:"to,omitempty"`
	Cc         []string `json:"cc,omitempty" yaml:"cc,omitempty"`
	Subject    string   `json:"subject,omitempty" yaml:"subject,omitempty"`
	Contains   string   `json:"contains,omitempty" yaml:"contains,omitempty"`
	Labels     []string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Categories []string `json:"categories,omitempty" yaml:"categories,omitempty"`
	// Attachment is "", "yes" or "no".
	Attachment string `json:"attachment,omitempty" yaml:"attachment,omitempty"`
}

// Route is a rule the decider can see. TargetName is the webhook it posts to.
type Route struct {
	ID         int64
	Name       string
	TargetName string
	TargetID   int64
	Enabled    bool
	Fallback   bool
	Continue   bool
	ApplyLabel bool
	Spec       Spec
}

// Normalize tidies a spec that came from a form or a file.
func (s Spec) Normalize() Spec {
	s.Op = strings.ToLower(strings.TrimSpace(s.Op))
	if s.Op != "or" {
		s.Op = "and"
	}
	s.From = SortSenders(cleanList(s.From))
	s.To = SortSenders(cleanList(s.To))
	s.Cc = SortSenders(cleanList(s.Cc))
	s.Labels = cleanList(s.Labels)
	s.Categories = lowerList(s.Categories)
	s.Subject = strings.TrimSpace(s.Subject)
	s.Contains = strings.TrimSpace(s.Contains)
	switch strings.ToLower(strings.TrimSpace(s.Attachment)) {
	case "yes", "true", "1":
		s.Attachment = "yes"
	case "no", "false", "0":
		s.Attachment = "no"
	default:
		s.Attachment = ""
	}
	return s
}

func cleanList(in []string) []string {
	var out []string
	for _, raw := range in {
		for _, p := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// SortSenders dedupes an address list case-insensitively and orders it:
// bare domains first, then *.domains, then full addresses, each A to Z.
// A leading @ counts as a bare domain.
func SortSenders(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		k := strings.ToLower(v)
		if v == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := senderRank(out[i]), senderRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return senderKey(out[i]) < senderKey(out[j])
	})
	return out
}

func senderRank(v string) int {
	v = strings.TrimPrefix(v, "@")
	switch {
	case strings.HasPrefix(v, "*."):
		return 1
	case strings.Contains(v, "@"):
		return 2
	}
	return 0
}

func senderKey(v string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(v, "@"), "*."))
}

func lowerList(in []string) []string {
	var out []string
	for _, s := range cleanList(in) {
		out = append(out, strings.ToLower(s))
	}
	return out
}

// Summary is a one-line description of the filter for the route list.
func (s Spec) Summary() string {
	s = s.Normalize()
	if s.Empty() {
		return "matches everything"
	}
	var p []string
	if len(s.From) > 0 {
		p = append(p, "from "+strings.Join(s.From, ", "))
	}
	if len(s.To) > 0 {
		p = append(p, "to "+strings.Join(s.To, ", "))
	}
	if len(s.Cc) > 0 {
		p = append(p, "cc "+strings.Join(s.Cc, ", "))
	}
	if s.Subject != "" {
		p = append(p, "subject /"+s.Subject+"/")
	}
	if s.Contains != "" {
		p = append(p, "contains "+s.Contains)
	}
	if len(s.Labels) > 0 {
		p = append(p, "label "+strings.Join(s.Labels, ", "))
	}
	if len(s.Categories) > 0 {
		p = append(p, "category "+strings.Join(s.Categories, ", "))
	}
	if s.Attachment == "yes" {
		p = append(p, "has attachment")
	}
	if s.Attachment == "no" {
		p = append(p, "no attachment")
	}
	joiner := " and "
	if s.Op == "or" {
		joiner = " or "
	}
	return strings.Join(p, joiner)
}

// Empty reports whether the spec has no constraints.
func (s Spec) Empty() bool {
	s = s.Normalize()
	return len(s.From) == 0 && len(s.To) == 0 && len(s.Cc) == 0 && s.Subject == "" &&
		s.Contains == "" && len(s.Labels) == 0 && len(s.Categories) == 0 && s.Attachment == ""
}

// Validate rejects a subject regex that does not compile.
func (s Spec) Validate() error {
	s = s.Normalize()
	if s.Subject == "" {
		return nil
	}
	_, err := regexp.Compile(s.Subject)
	return err
}

// Match reports whether m satisfies the spec.
func (s Spec) Match(m mail.Message) bool {
	s = s.Normalize()
	type clause struct {
		on bool
		ok bool
	}
	clauses := []clause{
		{len(s.From) > 0, anyAddress(s.From, m.From)},
		{len(s.To) > 0, anyAddress(s.To, m.To)},
		{len(s.Cc) > 0, anyAddress(s.Cc, m.Cc)},
		{s.Subject != "", subjectMatch(s.Subject, m.Subject)},
		{s.Contains != "", contains(s.Contains, m)},
		{len(s.Labels) > 0, anyLabel(s.Labels, m.Labels)},
		{len(s.Categories) > 0, anyCategory(s.Categories, m.Category)},
		{s.Attachment == "yes", m.HasAttachment},
		{s.Attachment == "no", !m.HasAttachment},
	}
	anyOn := false
	if s.Op == "or" {
		for _, c := range clauses {
			if c.on {
				anyOn = true
				if c.ok {
					return true
				}
			}
		}
		return !anyOn
	}
	for _, c := range clauses {
		if c.on {
			anyOn = true
			if !c.ok {
				return false
			}
		}
	}
	return true
}

func contains(needle string, m mail.Message) bool {
	n := strings.ToLower(needle)
	return strings.Contains(strings.ToLower(m.Snippet), n) || strings.Contains(strings.ToLower(m.Plain), n) ||
		strings.Contains(strings.ToLower(m.Subject), n)
}

func anyCategory(want []string, got string) bool {
	got = strings.ToLower(got)
	for _, w := range want {
		if w == got {
			return true
		}
	}
	return false
}

func anyLabel(want, have []string) bool {
	for _, w := range want {
		for _, h := range have {
			if strings.EqualFold(w, h) {
				return true
			}
		}
	}
	return false
}

func anyAddress(patterns []string, header string) bool {
	addrs := addresses(header)
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		domain := false
		if strings.HasPrefix(p, "@") {
			domain = true
			p = strings.TrimPrefix(p, "@")
		} else if !strings.Contains(p, "@") {
			domain = true
		}
		for _, a := range addrs {
			if domain {
				if domainMatch(domainOf(a), p) {
					return true
				}
			} else if a == p {
				return true
			}
		}
	}
	return false
}

func addresses(header string) []string {
	var out []string
	for _, part := range strings.Split(header, ",") {
		a := strings.TrimSpace(part)
		if i := strings.LastIndex(a, "<"); i >= 0 {
			if j := strings.Index(a[i:], ">"); j > 1 {
				a = a[i+1 : i+j]
			}
		}
		a = strings.ToLower(strings.Trim(strings.TrimSpace(a), `"'`))
		if strings.Contains(a, "@") {
			out = append(out, a)
		}
	}
	return out
}

func domainOf(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[i+1:]
	}
	return ""
}

// domainMatch reports whether the message domain got matches pattern pat.
// Comparison is case-insensitive.
//
//	example.com      the apex or any subdomain
//	*.example.com    any subdomain of example.com, not the apex itself
//
// A lookalike such as notexample.com does not match example.com.
func domainMatch(got, pat string) bool {
	got = strings.ToLower(strings.TrimSpace(got))
	pat = strings.ToLower(strings.TrimSpace(pat))
	subOnly := false
	if strings.HasPrefix(pat, "*.") {
		subOnly = true
		pat = strings.TrimPrefix(pat, "*.")
	}
	if got == "" || pat == "" {
		return false
	}
	if got == pat {
		return !subOnly
	}
	return strings.HasSuffix(got, "."+pat)
}

var (
	reMu    sync.Mutex
	reCache = map[string]*regexp.Regexp{}
)

func subjectMatch(expr, subject string) bool {
	reMu.Lock()
	re, ok := reCache[expr]
	if !ok {
		compiled, err := regexp.Compile(expr)
		if err != nil {
			reCache[expr] = nil
			reMu.Unlock()
			return false
		}
		re = compiled
		reCache[expr] = re
	}
	reMu.Unlock()
	if re == nil {
		return false
	}
	return re.MatchString(subject)
}

// Decide walks routes in order. Disabled routes are skipped. Fallback routes
// run only when no earlier route matched and the message is not already
// claimed (for example by a ghook/ label).
func Decide(routes []Route, m mail.Message) []Route {
	return DecideClaimed(routes, m, false)
}

// DecideClaimed is Decide with an explicit claimed flag. A label-convention
// hit counts as claimed, so a fallback must not also fire.
func DecideClaimed(routes []Route, m mail.Message, claimed bool) []Route {
	var hits []Route
	for _, r := range routes {
		if !r.Enabled || r.Fallback {
			continue
		}
		if r.Spec.Match(m) {
			hits = append(hits, r)
			if !r.Continue {
				return hits
			}
		}
	}
	if len(hits) > 0 || claimed {
		return hits
	}
	for _, r := range routes {
		if !r.Enabled || !r.Fallback {
			continue
		}
		if r.Spec.Match(m) {
			hits = append(hits, r)
			if !r.Continue {
				return hits
			}
		}
	}
	return hits
}

// LabelTargets returns target names implied by labels of the form "ghook/<target>".
// The segment after the prefix is the target name. Comparison is
// case-insensitive, so an existing Gmail label "Ghook/<target>" still matches
// the default prefix "ghook". Labels under "<prefix>/Routed/..." are the
// labels ghook itself applies and are ignored.
func LabelTargets(prefix string, labels []string) []string {
	prefix = Prefix(prefix)
	var out []string
	seen := map[string]bool{}
	head := prefix + "/"
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if len(l) <= len(head) || !strings.EqualFold(l[:len(head)], head) {
			continue
		}
		rest := l[len(head):]
		if strings.EqualFold(rest, "Routed") || strings.HasPrefix(strings.ToLower(rest), "routed/") {
			continue
		}
		name := rest
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimSpace(name)
		if name == "" || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		out = append(out, name)
	}
	return out
}

// RoutedLabel is the label applied to mail that was sent to a target.
func RoutedLabel(prefix, target string) string {
	return Prefix(prefix) + "/Routed/" + strings.TrimSpace(target)
}
