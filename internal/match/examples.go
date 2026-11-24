package match

// Example is a ready-made subject pattern for the route form.
type Example struct {
	Label, Pattern string
}

// SubjectExamples are shown, collapsed, next to the subject field. Every
// pattern is RE2 (Go regexp), which has no lookahead, so "both words in any
// order" spells out both orders. Excluding a word has no RE2 form.
var SubjectExamples = []Example{
	{"Either word", `(?i)\b(invoice|payment)\b`},
	{"Both words, any order", `(?i)\binvoice\b.*\bdue\b|\bdue\b.*\binvoice\b`},
	{"One whole word, any case", `(?i)\breceipt\b`},
	{"Starts with Re:", `(?i)^re:`},
	{"Has a number like #1234", `#\d+`},
}
