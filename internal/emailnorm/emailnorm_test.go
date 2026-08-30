package emailnorm_test

import (
	"testing"

	"github.com/bernardoforcillo/authlayer/internal/emailnorm"
)

// TestNormalize pins the rule itself: trim the outside, lowercase the rest,
// and touch nothing else. In particular the local part is lowercased too —
// SMTP allows it to be case-sensitive, and this library deliberately does
// not, because treating Bob@ and bob@ as two accounts (or two invitations)
// is the failure mode that actually happens.
func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"\t\n ", ""},
		{"bob@example.com", "bob@example.com"},
		{"Bob@Example.com", "bob@example.com"},
		{"  BOB@EXAMPLE.COM  ", "bob@example.com"},
		{"\tbob@example.com\n", "bob@example.com"},
		// Interior whitespace is not touched: it is not this function's job
		// to decide an address is malformed.
		{"bo b@example.com", "bo b@example.com"},
		// The local part is lowercased along with the domain.
		{"BoB.SmItH+Tag@Example.COM", "bob.smith+tag@example.com"},
	}
	for _, c := range cases {
		if got := emailnorm.Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNormalizeIsIdempotent pins that normalizing an already-normalized
// address is a no-op. Both the service layer and the stores apply it, so a
// value routinely goes through it twice.
func TestNormalizeIsIdempotent(t *testing.T) {
	for _, in := range []string{"", " A@B.C ", "a@b.c", "\tX\t"} {
		once := emailnorm.Normalize(in)
		if twice := emailnorm.Normalize(once); twice != once {
			t.Errorf("Normalize(Normalize(%q)) = %q, want %q", in, twice, once)
		}
	}
}
