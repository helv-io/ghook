package match

// Section is one filter field as the route list shows it.
type Section struct {
	// Key is the form field name (from, to, cc, subject, contains, labels, category, attachment).
	Key   string
	Label string
	// Kind is list (any of several values), text, regex or fixed (edited on the route page).
	Kind   string
	Values []string
}

// Editable reports whether the route list may edit this section in place.
func (s Section) Editable() bool { return s.Kind != "fixed" }

// View is a spec laid out for display: sections in field order and the operator between them.
type View struct {
	Op       string
	Sections []Section
}

// Total is the number of values across every section.
func (v View) Total() int {
	n := 0
	for _, s := range v.Sections {
		n += len(s.Values)
	}
	return n
}

// Hidden is how many values a collapsed view leaves out when it shows the first keep of each section.
func (v View) Hidden(keep int) int {
	n := 0
	for _, s := range v.Sections {
		if len(s.Values) > keep {
			n += len(s.Values) - keep
		}
	}
	return n
}

// View lays the spec out for the route list. Lists come back sorted, as they are saved.
func (s Spec) View() View {
	s = s.Normalize()
	v := View{Op: s.Op}
	add := func(key, label, kind string, vals []string) {
		if len(vals) > 0 {
			v.Sections = append(v.Sections, Section{Key: key, Label: label, Kind: kind, Values: vals})
		}
	}
	one := func(x string) []string {
		if x == "" {
			return nil
		}
		return []string{x}
	}
	add("from", "From", "list", s.From)
	add("to", "To", "list", s.To)
	add("cc", "Cc", "list", s.Cc)
	add("subject", "Subject regex", "regex", one(s.Subject))
	add("contains", "Contains", "text", one(s.Contains))
	add("labels", "Labels", "list", s.Labels)
	add("category", "Category", "fixed", s.Categories)
	switch s.Attachment {
	case "yes":
		add("attachment", "Attachment", "fixed", []string{"has an attachment"})
	case "no":
		add("attachment", "Attachment", "fixed", []string{"no attachment"})
	}
	return v
}

// WithField returns the spec with one in-place edit applied. raw is newline-separated for lists.
// ok is false for a field the route list cannot edit.
func (s Spec) WithField(field, raw string) (Spec, bool) {
	switch field {
	case "from":
		s.From = []string{raw}
	case "to":
		s.To = []string{raw}
	case "cc":
		s.Cc = []string{raw}
	case "labels":
		s.Labels = []string{raw}
	case "subject":
		s.Subject = raw
	case "contains":
		s.Contains = raw
	default:
		return s, false
	}
	return s.Normalize(), true
}

// Field returns the current values of an editable field.
func (s Spec) Field(field string) []string {
	s = s.Normalize()
	switch field {
	case "from":
		return s.From
	case "to":
		return s.To
	case "cc":
		return s.Cc
	case "labels":
		return s.Labels
	case "subject":
		if s.Subject != "" {
			return []string{s.Subject}
		}
	case "contains":
		if s.Contains != "" {
			return []string{s.Contains}
		}
	}
	return []string{}
}
