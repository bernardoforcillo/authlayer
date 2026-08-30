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

// TestNormalizeFoldsSomeNonASCIIOntoASCII pins the limitation
// auth.NormalizeEmail's doc states, so the doc is checked rather than
// asserted. strings.ToLower applies Unicode SIMPLE lowercasing: a few
// non-ASCII runes collapse onto ASCII ones, and a few that full case folding
// would collapse are left alone. An application running SMTPUTF8 mailboxes
// that differ only by one of these has two addresses this library treats as
// one account.
func TestNormalizeFoldsSomeNonASCIIOntoASCII(t *testing.T) {
	cases := []struct {
		name     string
		in, want string
	}{
		// U+212A KELVIN SIGN lowercases to ASCII k.
		{"kelvin sign", "mi\u212Ae@example.com", "mike@example.com"},
		// U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE lowercases to ASCII i.
		{"dotted capital I", "\u0130stanbul@example.com", "istanbul@example.com"},
		// U+017F LATIN SMALL LETTER LONG S is already lowercase and is NOT
		// folded to s — simple lowercasing, not full case folding.
		{"long s", "\u017Fam@example.com", "\u017Fam@example.com"},
	}
	for _, c := range cases {
		if got := emailnorm.Normalize(c.in); got != c.want {
			t.Errorf("%s: Normalize(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestNormalizeLowercasesTheLocalPart pins the other half of the same
// documented limitation: RFC 5321 makes the local part case-SENSITIVE and
// this library deliberately does not, so a provider's verification of
// MIKE@ is credited to mike@.
func TestNormalizeLowercasesTheLocalPart(t *testing.T) {
	if got := emailnorm.Normalize("MIKE@EXAMPLE.COM"); got != "mike@example.com" {
		t.Fatalf("Normalize(%q) = %q, want %q", "MIKE@EXAMPLE.COM", got, "mike@example.com")
	}
}
