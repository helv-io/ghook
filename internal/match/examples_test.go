package match

import (
	"regexp"
	"testing"

	"github.com/helv-io/ghook/internal/mail"
)

func TestSubjectExamples(t *testing.T) {
	cases := map[string]struct{ yes, no []string }{
		`(?i)\b(invoice|payment)\b`: {
			yes: []string{"Invoice 42 attached", "Your PAYMENT was received", "Re: invoice"},
			no:  []string{"Invoices are late", "Prepayment notice", "Hello"},
		},
		`(?i)\binvoice\b.*\bdue\b|\bdue\b.*\binvoice\b`: {
			yes: []string{"Invoice 7 is due Friday", "Due today: your invoice", "DUE: INVOICE"},
			no:  []string{"Invoice 7 attached", "Payment due", "Invoices overdue"},
		},
		`(?i)\breceipt\b`: {
			yes: []string{"Your Receipt", "receipt for order 9"},
			no:  []string{"Receipts", "Received your order"},
		},
		`(?i)^re:`: {
			yes: []string{"Re: lunch", "RE: status"},
			no:  []string{"Fwd: Re: lunch", "Here: lunch"},
		},
		`#\d+`: {
			yes: []string{"Order #1234 shipped", "Ticket #7"},
			no:  []string{"Order 1234 shipped", "# heading"},
		},
	}
	if len(cases) != len(SubjectExamples) {
		t.Fatalf("%d examples, %d tested", len(SubjectExamples), len(cases))
	}
	for _, ex := range SubjectExamples {
		if _, err := regexp.Compile(ex.Pattern); err != nil {
			t.Fatalf("%s: %v", ex.Label, err)
		}
		if err := (Spec{Subject: ex.Pattern}).Validate(); err != nil {
			t.Fatalf("%s: %v", ex.Label, err)
		}
		c, ok := cases[ex.Pattern]
		if !ok {
			t.Fatalf("%s: no test samples", ex.Label)
		}
		for _, s := range c.yes {
			if !(Spec{Subject: ex.Pattern}).Match(mail.Message{Subject: s}) {
				t.Errorf("%s should match %q", ex.Label, s)
			}
		}
		for _, s := range c.no {
			if (Spec{Subject: ex.Pattern}).Match(mail.Message{Subject: s}) {
				t.Errorf("%s should not match %q", ex.Label, s)
			}
		}
	}
}
