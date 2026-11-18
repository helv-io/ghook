package web

import (
	"html"
	"html/template"
	"regexp"
	"strings"
)

// productName is the visible product word only, as a whole word. Hyphenated
// protocol names such as X-Ghook-Delivery are left alone when this is applied
// to prose; do not run it on code chips, form values, or the document title.
var productName = regexp.MustCompile(`(?i)\bghook\b`)

// wordmark escapes s and wraps each standalone "ghook" or "Ghook" in the
// reusable wordmark element so the name glows in yellow.
func wordmark(s string) template.HTML {
	if s == "" {
		return ""
	}
	esc := html.EscapeString(s)
	return template.HTML(productName.ReplaceAllStringFunc(esc, func(m string) string {
		return `<span class="gh-word">` + m + `</span>`
	}))
}

// pathcode renders a slash-separated label or path as a code chip that may
// wrap at each "/", but not in the middle of a segment.
func pathcode(s string) template.HTML {
	if s == "" {
		return ""
	}
	esc := strings.ReplaceAll(html.EscapeString(s), "/", "/<wbr>")
	return template.HTML(`<code class="path">` + esc + `</code>`)
}
