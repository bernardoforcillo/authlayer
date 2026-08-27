package password

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// testCost is used throughout instead of bcrypt.DefaultCost (10) so the
// suite runs quickly: bcrypt is deliberately slow, and DefaultCost-strength
// hashing dozens of times per test run would make the suite noticeably
// slower for no benefit — the cost parameter itself is exercised directly
// by TestBcryptZeroUsesLibraryDefault and TestBcryptExplicitCostHonoured.
const testCost = bcrypt.MinCost

// A hash must verify against the plaintext that produced it, and must not
// verify against a different plaintext.
func TestHashVerifyRoundTrip(t *testing.T) {
	h := Bcrypt(testCost)

	hash, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !h.Verify("correct horse battery staple", hash) {
		t.Fatal("Verify(original plaintext, hash) = false, want true")
	}
	if h.Verify("incorrect horse battery staple", hash) {
		t.Fatal("Verify(different plaintext, hash) = true, want false")
	}
}

// Verify must report false — never panic — for a hash that is empty,
// truncated, or not a bcrypt hash at all. Callers pass through whatever a
// datastore returns without pre-validating it, so this has to be safe on
// arbitrary garbage.
func TestVerifyMalformedOrEmptyHashReturnsFalse(t *testing.T) {
	h := Bcrypt(testCost)

	cases := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"plain garbage", "not-a-bcrypt-hash-at-all"},
		{"truncated bcrypt hash", "$2a$10$short"},
		{"unrelated hash format (md5-shaped)", "$1$abcdefgh$abcdefghijklmnopqrstuv"},
		{"whitespace only", "   "},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Verify(_, %q) panicked: %v", c.hash, r)
				}
			}()
			if h.Verify("whatever the plaintext is", c.hash) {
				t.Fatalf("Verify(_, %q) = true, want false", c.hash)
			}
		})
	}
}

// bcrypt salts independently on every call, so hashing the same plaintext
// twice must produce two different results — and both must still verify.
func TestHashSaltsEachCall(t *testing.T) {
	h := Bcrypt(testCost)
	const plain = "same plaintext both times"

	first, err := h.Hash(plain)
	if err != nil {
		t.Fatalf("first Hash: %v", err)
	}
	second, err := h.Hash(plain)
	if err != nil {
		t.Fatalf("second Hash: %v", err)
	}

	if first == second {
		t.Fatalf("Hash(%q) returned identical output twice: %q; want distinct salts", plain, first)
	}
	if !h.Verify(plain, first) {
		t.Fatal("Verify against first hash = false, want true")
	}
	if !h.Verify(plain, second) {
		t.Fatal("Verify against second hash = false, want true")
	}
}

// Bcrypt(0) must use bcrypt's own library default cost, not 0 itself (cost
// 0 is not a valid bcrypt cost).
func TestBcryptZeroUsesLibraryDefault(t *testing.T) {
	hash, err := Bcrypt(0).Hash("whatever password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("Bcrypt(0) produced a hash at cost %d, want library default %d", cost, bcrypt.DefaultCost)
	}
}

// An explicit, non-zero cost must be honoured verbatim rather than
// silently overridden.
func TestBcryptExplicitCostHonoured(t *testing.T) {
	const want = bcrypt.MinCost + 2 // deliberately distinct from both MinCost and DefaultCost
	hash, err := Bcrypt(want).Hash("whatever password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != want {
		t.Fatalf("Bcrypt(%d) produced a hash at cost %d, want %d", want, cost, want)
	}
}

// DefaultRules must match the spec exactly: minimum length 12, and all four
// character classes required.
func TestDefaultRulesMatchesSpec(t *testing.T) {
	got := DefaultRules()
	want := Rules{
		MinLength:      12,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
	}
	if got != want {
		t.Fatalf("DefaultRules() = %+v, want %+v", got, want)
	}
}

// Validate must return the name of exactly the rules a password violates,
// in a fixed order, and an empty slice for a fully compliant password.
// Cases cover each rule failing alone, several failing together, and every
// rule failing at once.
func TestValidate(t *testing.T) {
	rules := DefaultRules()

	tests := []struct {
		name  string
		plain string
		want  []string
	}{
		{
			name:  "compliant password",
			plain: "Str0ng@Passw0rd", // 15 runes, upper+lower+digit+special all present
			want:  []string{},
		},
		{
			name:  "too short, otherwise compliant",
			plain: "Str0ng@1", // 8 runes: upper, lower, digit, special all present, just short
			want:  []string{"min_length"},
		},
		{
			name:  "missing upper only",
			plain: "str0ng@passw0rd1", // no uppercase letters
			want:  []string{"upper"},
		},
		{
			name:  "missing lower only",
			plain: "STR0NG@PASSW0RD1", // no lowercase letters
			want:  []string{"lower"},
		},
		{
			name:  "missing digit only",
			plain: "StrongPassword@!", // letters and a special, no digit
			want:  []string{"digit"},
		},
		{
			name:  "missing special only",
			plain: "StrongPassw0rd1", // letters and digits, no special/punctuation
			want:  []string{"special"},
		},
		{
			name:  "missing upper, digit, and special (lowercase only, exactly 12 runes)",
			plain: "abcdefghijkl",
			want:  []string{"upper", "digit", "special"},
		},
		{
			name:  "empty string fails every rule",
			plain: "",
			want:  []string{"min_length", "upper", "lower", "digit", "special"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Validate(tt.plain, rules)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("Validate(%q, DefaultRules()) = %v, want %v", tt.plain, got, tt.want)
			}
		})
	}
}

// MinLength must be counted in runes (Unicode code points), not bytes: a
// 12-rune password made entirely of multi-byte characters must satisfy a
// MinLength: 12 rule.
func TestValidateCountsRunesNotBytes(t *testing.T) {
	const multiByteRune = "é" // U+00E9, 2 bytes in UTF-8
	plain := strings.Repeat(multiByteRune, 12)

	if len(plain) == 12 {
		t.Fatalf("test setup invalid: %q encoded to 12 bytes, want more than 12 (need a real multi-byte case)", plain)
	}

	got := Validate(plain, Rules{MinLength: 12})
	if len(got) != 0 {
		t.Fatalf("Validate(12-rune multi-byte string, MinLength: 12) = %v, want no failures (got %d bytes)", got, len(plain))
	}
}

// A near-zero-entropy password — a handful of meaningful characters padded
// out to the minimum length with spaces — must not be certified compliant.
// This is the exact counterexample from code review: before this fix,
// whitespace counted as a qualifying "special" character, so "Aa1" padded
// with nine spaces (12 runes total) satisfied MinLength, RequireUpper,
// RequireLower, RequireDigit, *and* RequireSpecial, despite carrying only
// three characters of real entropy. RequireSpecial must fail here.
func TestValidateWhitespacePaddingDoesNotSatisfySpecial(t *testing.T) {
	plain := "Aa1" + strings.Repeat(" ", 9) // 12 runes: 3 meaningful + 9 spaces
	if n := utf8.RuneCountInString(plain); n != 12 {
		t.Fatalf("test setup invalid: %q is %d runes, want 12", plain, n)
	}

	got := Validate(plain, DefaultRules())
	want := []string{"special"}
	if !slices.Equal(got, want) {
		t.Fatalf("Validate(%q, DefaultRules()) = %v, want %v — whitespace must not satisfy RequireSpecial", plain, got, want)
	}
}

// Excluding whitespace from the "special" character class must not make
// whitespace forbidden — only non-qualifying. A passphrase containing a
// space alongside a real punctuation character must still pass every rule:
// the space neither counts toward RequireSpecial nor blocks the password.
func TestValidateWhitespaceAllowedButNotSpecial(t *testing.T) {
	const plain = "Str0ng Pass@1" // contains a space AND a genuine special character
	got := Validate(plain, DefaultRules())
	if len(got) != 0 {
		t.Fatalf("Validate(%q, DefaultRules()) = %v, want no failures (a space must be allowed, not forbidden)", plain, got)
	}
}

// Dummy must run to completion without panicking for any input, including
// the empty string.
func TestDummyDoesNotPanic(t *testing.T) {
	h := Bcrypt(testCost)
	inputs := []string{
		"",
		"short",
		"a longer password with spaces and symbols !@#$%^&*()",
		strings.Repeat("x", 1000),
	}

	for _, in := range inputs {
		t.Run("len="+strconv.Itoa(len(in)), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Dummy(len=%d) panicked: %v", len(in), r)
				}
			}()
			h.Dummy(in)
		})
	}
}

// Dummy's lazy, once-per-Hasher initialization of its throwaway hash must
// be safe under concurrent first use — nothing in the required surface
// promises this explicitly, but the implementation relies on sync.Once for
// exactly this reason, and a race here would be a data race in production
// under concurrent logins.
func TestDummyConcurrentSafe(t *testing.T) {
	h := Bcrypt(testCost)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Dummy("concurrent-first-use")
		}()
	}
	wg.Wait()
}

// TestDummyBodyCallsBcryptCompare pins a source-level property that no
// black-box test can observe: that Dummy's comparison is a real call to
// bcrypt.CompareHashAndPassword — the same expensive comparison Verify
// performs — rather than a hollowed-out stand-in (a no-op, a sleep, a cheap
// hash) that would return instantly and silently reopen the timing oracle
// Dummy exists to close.
//
// A wall-clock assertion could try to observe this directly, but it would
// be flaky theatre: elapsed time is influenced by machine load, scheduling,
// and thermal throttling in ways a unit test cannot control for, and this
// package cannot assert "Dummy takes about as long as Verify" without
// comparing two noisy measurements against each other. So instead this
// inspects password.go's AST directly — the one place the "is it doing the
// real, expensive comparison" property is visible without a clock — mirroring
// token's TestSignatureComparisonUsesHmacEqual, which does the same for a
// different untestable-by-timing property.
//
// It fails if the bcrypt.CompareHashAndPassword call inside Dummy's method
// body is deleted or replaced by anything else.
func TestDummyBodyCallsBcryptCompare(t *testing.T) {
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, "password.go", nil, 0)
	if err != nil {
		t.Fatalf("parse password.go: %v", err)
	}

	var dummyFn *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "Dummy" && fn.Recv != nil {
			dummyFn = fn
			break
		}
	}
	if dummyFn == nil {
		t.Fatal("password.go: no method named Dummy found on any receiver — this test needs updating to match")
	}

	usesBcryptCompare := false
	ast.Inspect(dummyFn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if ok && pkgIdent.Name == "bcrypt" && sel.Sel.Name == "CompareHashAndPassword" {
			usesBcryptCompare = true
		}
		return true
	})

	if !usesBcryptCompare {
		t.Fatal("password.go: Dummy's body does not contain a call to bcrypt.CompareHashAndPassword — " +
			"Dummy must perform a real bcrypt comparison to spend time comparable to Verify; see the package doc and Dummy's own comment")
	}
}
