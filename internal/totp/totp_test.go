package totp

import (
	"encoding/base32"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"strings"
	"testing"
	"time"
)

// The three seeds RFC 6238 appendix B uses, as the ASCII strings the RFC
// prints. The appendix's own prose gives only "12345678901234567890" and
// leaves the SHA-256 and SHA-512 seeds to a reader who notices the HMAC key
// must match the algorithm; the errata-confirmed reading, and the one every
// interoperable implementation uses, is that the ASCII sequence is REPEATED
// and truncated to the algorithm's key length — 20 bytes for SHA-1, 32 for
// SHA-256, 64 for SHA-512. That reading is not asserted here; it is PROVED
// by the eighteen published codes below matching, which they cannot do under
// any other seed.
const (
	seedSHA1   = "12345678901234567890"
	seedSHA256 = "12345678901234567890123456789012"
	seedSHA512 = "1234567890123456789012345678901234567890123456789012345678901234"
)

// b32 renders an ASCII seed the way this package takes a secret: unpadded
// base32. The RFC prints its seeds as ASCII and hex; base32 is the
// authenticator-app transport, so encoding here also puts the decoder on the
// path every published vector travels.
func b32(seed string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(seed))
}

// TestRFC6238PublishedVectors is the only external check that this package
// implements TOTP rather than something merely self-consistent. Every row is
// RFC 6238 appendix B verbatim: T0 = 0, X = 30 seconds, 8 digits, across all
// three algorithms.
//
// If a row fails, THE IMPLEMENTATION IS WRONG. Do not adjust the table.
func TestRFC6238PublishedVectors(t *testing.T) {
	vectors := []struct {
		unix int64
		algo Algorithm
		want string
	}{
		{59, SHA1, "94287082"},
		{59, SHA256, "46119246"},
		{59, SHA512, "90693936"},
		{1111111109, SHA1, "07081804"},
		{1111111109, SHA256, "68084774"},
		{1111111109, SHA512, "25091201"},
		{1111111111, SHA1, "14050471"},
		{1111111111, SHA256, "67062674"},
		{1111111111, SHA512, "99943326"},
		{1234567890, SHA1, "89005924"},
		{1234567890, SHA256, "91819424"},
		{1234567890, SHA512, "93441116"},
		{2000000000, SHA1, "69279037"},
		{2000000000, SHA256, "90698825"},
		{2000000000, SHA512, "38618901"},
		{20000000000, SHA1, "65353130"},
		{20000000000, SHA256, "77737706"},
		{20000000000, SHA512, "47863826"},
	}

	for _, v := range vectors {
		secret := b32(seedFor(t, v.algo))
		got, err := Code(secret, time.Unix(v.unix, 0).UTC(), 8, 30*time.Second, v.algo)
		if err != nil {
			t.Fatalf("Code(T=%d, %v): unexpected error %v", v.unix, v.algo, err)
		}
		if got != v.want {
			t.Fatalf("RFC 6238 appendix B, T=%d %v: Code = %q, want %q — the published vector is not negotiable; this implementation is wrong",
				v.unix, v.algo, got, v.want)
		}
	}
}

func seedFor(t *testing.T, algo Algorithm) string {
	t.Helper()
	switch algo {
	case SHA1:
		return seedSHA1
	case SHA256:
		return seedSHA256
	case SHA512:
		return seedSHA512
	}
	t.Fatalf("no RFC seed for algorithm %v", algo)
	return ""
}

// TestRFC4226PublishedVectors covers what appendix B cannot: RFC 6238's
// table is entirely 8-digit, so the 6-digit truncation authenticator apps
// actually use is exercised by no row of it. RFC 4226 appendix D publishes
// ten 6-digit HOTP values for the same 20-byte seed at counters 0..9, and
// TOTP is HOTP over floor(unix/period) — so with a 30-second period,
// t = counter*30 addresses exactly counter.
func TestRFC4226PublishedVectors(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	secret := b32(seedSHA1)
	for counter, w := range want {
		at := time.Unix(int64(counter)*30, 0).UTC()
		got, err := Code(secret, at, 6, 30*time.Second, SHA1)
		if err != nil {
			t.Fatalf("Code(counter=%d): unexpected error %v", counter, err)
		}
		if got != w {
			t.Fatalf("RFC 4226 appendix D, counter %d: Code = %q, want %q — the published vector is not negotiable; this implementation is wrong",
				counter, got, w)
		}
	}
}

// TestCodeIsZeroPaddedToDigits pins the padding explicitly rather than
// leaving it to the one published vector that happens to exercise it
// (07081804). A code rendered with %d instead of %0*d is a code an
// authenticator app will never match, and the defect only shows up for
// roughly one step in ten.
func TestCodeIsZeroPaddedToDigits(t *testing.T) {
	secret := b32(seedSHA1)
	got, err := Code(secret, time.Unix(1111111109, 0).UTC(), 8, 30*time.Second, SHA1)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if len(got) != 8 || !strings.HasPrefix(got, "0") {
		t.Fatalf("Code = %q, want the 8-character zero-padded 07081804", got)
	}
}

// TestAlgorithmZeroValueIsSHA1 pins the enum ordering. SHA-1 is TOTP's
// default and the only algorithm every authenticator app implements, so a
// caller who names no algorithm must get it — the same zero-value reasoning
// auth.LinkVerified's own test records.
func TestAlgorithmZeroValueIsSHA1(t *testing.T) {
	var zero Algorithm
	if zero != SHA1 {
		t.Fatalf("the zero Algorithm is %v, want SHA1", zero)
	}
	if SHA1.String() != "SHA1" || SHA256.String() != "SHA256" || SHA512.String() != "SHA512" {
		t.Fatalf("algorithm names = %q/%q/%q, want SHA1/SHA256/SHA512 — these strings go into a provisioning URI",
			SHA1, SHA256, SHA512)
	}
}

// ── GenerateSecret ──────────────────────────────────────────────────────

func TestGenerateSecretIs160BitsOfBase32(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatalf("GenerateSecret returned %q, which is not unpadded base32: %v", s, err)
	}
	if len(raw) != secretBytes {
		t.Fatalf("GenerateSecret returned %d bytes, want %d (160 bits, RFC 4226 §4 R6's recommendation)", len(raw), secretBytes)
	}
	if strings.Contains(s, "=") {
		t.Fatalf("GenerateSecret returned padded base32 %q; authenticator apps take the unpadded form", s)
	}
}

func TestGenerateSecretDiffersEveryCall(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		s, err := GenerateSecret()
		if err != nil {
			t.Fatalf("GenerateSecret: %v", err)
		}
		if seen[s] {
			t.Fatalf("GenerateSecret returned %q twice — the secret is not random", s)
		}
		seen[s] = true
	}
}

// A generated secret must be one this package's own Code accepts. The two
// halves validate independently (length floor, alphabet), so a generator
// that drifted from the validator would only be caught here.
func TestGenerateSecretIsAcceptedByCode(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if _, err := Code(s, time.Unix(0, 0), 6, 30*time.Second, SHA1); err != nil {
		t.Fatalf("Code refused a freshly generated secret: %v", err)
	}
}

// ── input validation ────────────────────────────────────────────────────

func TestCodeRejectsEveryMalformedInput(t *testing.T) {
	good := b32(seedSHA1)
	cases := []struct {
		name   string
		secret string
		digits int
		period time.Duration
		algo   Algorithm
		want   error
	}{
		{"not base32", "not base32!", 6, 30 * time.Second, SHA1, ErrInvalidSecret},
		{"empty secret", "", 6, 30 * time.Second, SHA1, ErrInvalidSecret},
		{"secret under the 128-bit floor", b32("0123456789"), 6, 30 * time.Second, SHA1, ErrSecretTooShort},
		{"five digits", good, 5, 30 * time.Second, SHA1, ErrInvalidDigits},
		{"nine digits", good, 9, 30 * time.Second, SHA1, ErrInvalidDigits},
		{"zero period", good, 6, 0, SHA1, ErrInvalidPeriod},
		{"negative period", good, 6, -time.Second, SHA1, ErrInvalidPeriod},
		{"unknown algorithm", good, 6, 30 * time.Second, Algorithm(7), ErrUnknownAlgorithm},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Code(tc.secret, time.Unix(0, 0), tc.digits, tc.period, tc.algo)
			if !errorIs(err, tc.want) {
				t.Fatalf("Code err = %v, want %v", err, tc.want)
			}
			if got != "" {
				t.Fatalf("Code returned %q alongside an error; a refused call must yield no code", got)
			}
		})
	}
}

func TestValidateRejectsEveryMalformedInput(t *testing.T) {
	good := b32(seedSHA1)
	cases := []struct {
		name   string
		secret string
		code   string
		skew   int
		want   error
	}{
		{"empty code", good, "", 1, ErrEmptyCode},
		{"not base32", "not base32!", "123456", 1, ErrInvalidSecret},
		{"negative skew", good, "123456", -1, ErrInvalidSkew},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			step, ok, err := Validate(tc.secret, tc.code, time.Unix(0, 0), 6, 30*time.Second, SHA1, tc.skew)
			if !errorIs(err, tc.want) {
				t.Fatalf("Validate err = %v, want %v", err, tc.want)
			}
			if ok || step != 0 {
				t.Fatalf("Validate = (%d, %v) alongside an error, want (0, false)", step, ok)
			}
		})
	}
}

// errorIs is errors.Is, spelled out so this file's assertions do not depend
// on the package under test importing errors at all.
func errorIs(got, want error) bool {
	for e := got; e != nil; {
		if e == want {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// ── Validate ────────────────────────────────────────────────────────────

// TestValidateAcceptsTheCurrentStepAndReturnsIt is the property Task 2's
// replay guard is built on: Validate reports WHICH step matched, so a
// caller can refuse that step ever again.
func TestValidateAcceptsTheCurrentStepAndReturnsIt(t *testing.T) {
	secret := b32(seedSHA1)
	at := time.Unix(1111111111, 0).UTC()

	code, err := Code(secret, at, 8, 30*time.Second, SHA1)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	step, ok, err := Validate(secret, code, at, 8, 30*time.Second, SHA1, 1)
	if err != nil || !ok {
		t.Fatalf("Validate = (%d, %v, %v), want the current step accepted", step, ok, err)
	}
	if want := int64(1111111111 / 30); step != want {
		t.Fatalf("Validate returned step %d, want %d — the step is what the replay guard stores", step, want)
	}
}

// TestValidateAcceptsWithinSkewAndReportsThatStep walks every offset in a
// window of ±2 and requires the RETURNED step to be the one the code was
// minted for, not the caller's own. A guard told the wrong step burns the
// wrong number and leaves the presented code replayable.
func TestValidateAcceptsWithinSkewAndReportsThatStep(t *testing.T) {
	secret := b32(seedSHA1)
	const period = 30 * time.Second
	now := time.Unix(1111111111, 0).UTC()
	nowStep := now.Unix() / 30

	for offset := -2; offset <= 2; offset++ {
		at := now.Add(time.Duration(offset) * period)
		code, err := Code(secret, at, 6, period, SHA1)
		if err != nil {
			t.Fatalf("Code(offset %d): %v", offset, err)
		}
		step, ok, err := Validate(secret, code, now, 6, period, SHA1, 2)
		if err != nil || !ok {
			t.Fatalf("offset %d: Validate = (%d, %v, %v), want accepted within skew 2", offset, step, ok, err)
		}
		if want := nowStep + int64(offset); step != want {
			t.Fatalf("offset %d: Validate returned step %d, want %d", offset, step, want)
		}
	}
}

// TestValidateRefusesOutsideTheSkewWindow is the other half: the window is
// a window, not a suggestion. A code beyond it is refused with
// (0, false, nil) — a rejected credential, never an error.
func TestValidateRefusesOutsideTheSkewWindow(t *testing.T) {
	secret := b32(seedSHA1)
	const period = 30 * time.Second
	now := time.Unix(1111111111, 0).UTC()

	for _, offset := range []int{-2, 2, -10, 10} {
		code, err := Code(secret, now.Add(time.Duration(offset)*period), 6, period, SHA1)
		if err != nil {
			t.Fatalf("Code(offset %d): %v", offset, err)
		}
		step, ok, err := Validate(secret, code, now, 6, period, SHA1, 1)
		if err != nil {
			t.Fatalf("offset %d: Validate returned error %v; a wrong code is not an error", offset, err)
		}
		if ok || step != 0 {
			t.Fatalf("offset %d: Validate = (%d, true), want refused outside a skew of 1", offset, step)
		}
	}
}

func TestValidateRefusesAWrongCodeWithoutAnError(t *testing.T) {
	secret := b32(seedSHA1)
	step, ok, err := Validate(secret, "000000", time.Unix(1111111111, 0).UTC(), 6, 30*time.Second, SHA1, 1)
	if err != nil {
		t.Fatalf("Validate returned error %v for a wrong code; that is a rejection, not a failure", err)
	}
	if ok || step != 0 {
		t.Fatalf("Validate = (%d, %v), want (0, false)", step, ok)
	}
}

// A code of the wrong LENGTH must be refused rather than matched on a
// prefix. hmac.Equal reports false for unequal lengths, and this pins that
// nothing upstream trims or pads the caller's input into a match.
func TestValidateRefusesACodeOfTheWrongLength(t *testing.T) {
	secret := b32(seedSHA1)
	at := time.Unix(1111111111, 0).UTC()
	code, err := Code(secret, at, 8, 30*time.Second, SHA1)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	for _, bad := range []string{code[:7], code + "0", " " + code} {
		if _, ok, err := Validate(secret, bad, at, 8, 30*time.Second, SHA1, 1); ok || err != nil {
			t.Fatalf("Validate(%q) = (ok=%v, err=%v), want refused", bad, ok, err)
		}
	}
}

// A secret is a shared key: the same code minted under a different secret
// must not validate. Cheap, and it is the assertion that would catch a
// Validate that compared the presented code against itself.
func TestValidateIsBoundToTheSecret(t *testing.T) {
	at := time.Unix(1111111111, 0).UTC()
	code, err := Code(b32(seedSHA1), at, 6, 30*time.Second, SHA1)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	other, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if _, ok, err := Validate(other, code, at, 6, 30*time.Second, SHA1, 1); ok || err != nil {
		t.Fatalf("Validate under a different secret = (ok=%v, err=%v), want refused", ok, err)
	}
}

// The algorithm is part of the credential: a SHA-1 code must not validate
// against a SHA-256 factor. Enrolment records the algorithm for exactly
// this reason.
func TestValidateIsBoundToTheAlgorithm(t *testing.T) {
	at := time.Unix(1111111111, 0).UTC()
	secret := b32(seedSHA256)
	code, err := Code(secret, at, 8, 30*time.Second, SHA1)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if _, ok, err := Validate(secret, code, at, 8, 30*time.Second, SHA256, 1); ok || err != nil {
		t.Fatalf("Validate of a SHA1 code against SHA256 = (ok=%v, err=%v), want refused", ok, err)
	}
}

// ── secret parsing ──────────────────────────────────────────────────────

// The three forms an authenticator app or a human actually produces —
// lowercase, space-grouped, and RFC 4648 padded — must all decode to the
// same key, because all three name the same secret.
func TestSecretAcceptsTheFormsPeopleActuallyPaste(t *testing.T) {
	canonical := b32(seedSHA1)
	at := time.Unix(1111111111, 0).UTC()
	want, err := Code(canonical, at, 6, 30*time.Second, SHA1)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	grouped := strings.Join(chunk(canonical, 4), " ")
	padded := base32.StdEncoding.EncodeToString([]byte(seedSHA1))
	for _, form := range []string{strings.ToLower(canonical), grouped, padded} {
		got, err := Code(form, at, 6, 30*time.Second, SHA1)
		if err != nil {
			t.Fatalf("Code(%q): %v", form, err)
		}
		if got != want {
			t.Fatalf("Code(%q) = %q, want %q — the same secret in another surface form", form, got, want)
		}
	}
}

func chunk(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

// ── ProvisioningURI ─────────────────────────────────────────────────────

func TestProvisioningURICarriesEveryParameter(t *testing.T) {
	got := ProvisioningURI("JBSWY3DPEHPK3PXP", "Acme Inc", "nia@example.com", 8, 60*time.Second, SHA256)
	want := "otpauth://totp/Acme%20Inc:nia%40example.com" +
		"?secret=JBSWY3DPEHPK3PXP&issuer=Acme%20Inc&algorithm=SHA256&digits=8&period=60"
	if got != want {
		t.Fatalf("ProvisioningURI =\n  %s\nwant\n  %s", got, want)
	}
}

// A space in an issuer must be %20, never '+': the query half of an
// otpauth URI is read by scanners that percent-decode without applying
// form semantics, and "Acme+Inc" reaches them as a literal plus.
func TestProvisioningURIEscapesWithPercentTwenty(t *testing.T) {
	got := ProvisioningURI("JBSWY3DPEHPK3PXP", "A B", "c d", 6, 30*time.Second, SHA1)
	if strings.Contains(got, "+") {
		t.Fatalf("ProvisioningURI = %q, want %%20 rather than '+' for spaces", got)
	}
}

// An empty issuer drops both the label prefix and the issuer parameter,
// rather than rendering a leading colon an app reads as an empty issuer.
func TestProvisioningURIOmitsAnEmptyIssuer(t *testing.T) {
	got := ProvisioningURI("JBSWY3DPEHPK3PXP", "", "nia@example.com", 6, 30*time.Second, SHA1)
	want := "otpauth://totp/nia%40example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"
	if got != want {
		t.Fatalf("ProvisioningURI =\n  %s\nwant\n  %s", got, want)
	}
}

// A colon inside the issuer or the account would be read as the label
// separator and split the label somewhere else entirely, so both arrive
// percent-encoded: the only unescaped colons in the whole URI are the
// scheme's and the one separator.
func TestProvisioningURIEscapesTheLabelSeparator(t *testing.T) {
	got := ProvisioningURI("JBSWY3DPEHPK3PXP", "Acme:Corp", "a:b", 6, 30*time.Second, SHA1)
	label, _, _ := strings.Cut(got, "?")
	if n := strings.Count(label, ":"); n != 2 {
		t.Fatalf("ProvisioningURI label carries %d unescaped colons, want 2 (the scheme's and the separator): %s", n, got)
	}
}

// ── source-level: the comparison must be constant time ──────────────────

// TestCodeComparisonUsesHmacEqual pins a source-level property no black-box
// test can reach: Validate's comparison of the presented code against the
// computed one is literally hmac.Equal, not ==. The two accept and reject
// exactly the same inputs and differ only in how long they take, and a unit
// test observes outcomes rather than wall-clock timing — so the source form
// is the one place the difference is visible. This mirrors
// token.TestSignatureComparisonUsesHmacEqual, which exists for the same
// reason on the same kind of comparison.
func TestCodeComparisonUsesHmacEqual(t *testing.T) {
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, "totp.go", nil, 0)
	if err != nil {
		t.Fatalf("parse totp.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "Validate" {
			fn = d
			break
		}
	}
	if fn == nil {
		t.Fatal("totp.go: no func Validate found — this test needs updating to match")
	}

	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == "hmac" && sel.Sel.Name == "Equal" {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("totp.go: Validate does not compare the presented code with hmac.Equal — " +
			"the comparison must be constant time; see the comment at the comparison site")
	}
}
