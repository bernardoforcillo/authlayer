// Package totp implements RFC 6238 time-based one-time passwords over the
// RFC 4226 HOTP construction, using nothing but the Go standard library's
// crypto primitives.
//
// It is internal: the exported surface an application uses is
// [github.com/bernardoforcillo/authlayer/auth]'s enrolment and login
// methods, which own the secret's storage, its encryption at rest, and the
// replay guard. This package is the algorithm alone. It holds no state,
// reads no clock of its own, and knows nothing about users.
//
// # Why hand-rolling this is defensible, when hand-rolling WebAuthn was not
//
// The whole algorithm is an HMAC, a big-endian counter, and a modulus —
// there is no parser, no negotiation, and no attacker-controlled structure
// to mis-decode. Milestone 3's design records the comparison explicitly:
// authlayer hand-rolls its HS256 JWT and this, and refuses to hand-roll
// WebAuthn, because those two are small single-purpose primitives whose
// inputs are all validated before use, while WebAuthn is CBOR/COSE parsing
// in the authentication path where a subtle decoding bug is a bypass.
//
// # The published vectors are the point
//
// A wrong implementation of this algorithm is usually SELF-CONSISTENT: a
// counter serialized little-endian, a truncation off by a byte, or a
// modulus applied before masking all produce codes that verify perfectly
// against themselves and match no authenticator app on earth. Every such
// defect passes every round-trip test one could write. RFC 6238 appendix B
// and RFC 4226 appendix D are therefore not decoration in totp_test.go,
// they are the only external check that this is TOTP, and they cover all
// three algorithms. If one ever fails, the implementation is wrong; the
// table is not to be adjusted.
//
// # What is deliberately not here
//
// No secret storage, no "is this factor confirmed", no replay memory.
// [Validate] returns the step that matched precisely so its caller can
// refuse that step ever again — the guard is a compare-and-set on a stored
// LastStep, and it belongs with the storage, not here.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// secretBytes is the length of a secret [GenerateSecret] mints: 20 bytes,
// 160 bits, which is what RFC 4226 §4 R6 RECOMMENDS ("This document
// RECOMMENDs a shared secret length of 160 bits") and what every
// authenticator app expects to be handed.
const secretBytes = 20

// minSecretBytes is the floor [Code] and [Validate] enforce on a decoded
// secret: 16 bytes, 128 bits, RFC 4226 §4 R6's MUST ("The length of the
// shared secret MUST be at least 128 bits"). It is the same argument
// token.minKeyLen makes for HS256 keys — a short shared secret is only as
// hard to guess as its own length, and an empty one makes every code
// computable by anyone — so a secret under the floor is refused loudly
// rather than used.
const minSecretBytes = 16

// maxSkew is the widest window [Validate] will accept, in steps either
// side of the caller's own. Beyond this a "clock tolerance" stops being
// tolerance and becomes a longer-lived credential: each extra step admits
// another whole period's worth of codes, and at the 30-second default a
// skew of 10 already spans ten and a half minutes. RFC 6238 §5.2 suggests
// at most one step, so this is generous rather than tight, and it also
// bounds the work one call can be made to do.
const maxSkew = 10

// Algorithm names the HMAC hash a factor is built on. The zero value is
// [SHA1], which is what an authenticator app assumes when a provisioning
// URI names none — a factor enrolled with an unstated algorithm and
// validated as SHA-1 is the only combination that interoperates by
// default.
//
// SHA-1's weaknesses are collision weaknesses. HMAC-SHA-1's security as a
// MAC does not rest on collision resistance, and RFC 6238 specifies it as
// the default; it is kept as the default here for interoperability, with
// the stronger two available to a deployment whose authenticator supports
// them.
type Algorithm int

const (
	// SHA1 is HMAC-SHA-1, RFC 6238's default and the deliberate zero value.
	SHA1 Algorithm = iota
	// SHA256 is HMAC-SHA-256. Supported by most modern authenticators, not
	// all.
	SHA256
	// SHA512 is HMAC-SHA-512. Supported by fewer still.
	SHA512
)

// String renders the algorithm the way an otpauth URI's `algorithm`
// parameter spells it. An Algorithm outside the three declared constants
// renders in Go's own "Algorithm(7)" form rather than silently reading as
// SHA1: it produces a URI no authenticator accepts, which is the visible
// failure, instead of enrolling a factor against one algorithm while
// [Code] refuses to compute any code for it.
func (a Algorithm) String() string {
	switch a {
	case SHA1:
		return "SHA1"
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	}
	return fmt.Sprintf("Algorithm(%d)", int(a))
}

// hasher returns the constructor for a's hash, or [ErrUnknownAlgorithm].
// It is the single gate every code path goes through, so an unrecognized
// Algorithm is one typed refusal in one place rather than a default arm
// that quietly picks SHA-1.
func (a Algorithm) hasher() (func() hash.Hash, error) {
	switch a {
	case SHA1:
		return sha1.New, nil
	case SHA256:
		return sha256.New, nil
	case SHA512:
		return sha512.New, nil
	}
	return nil, fmt.Errorf("%w: %d", ErrUnknownAlgorithm, int(a))
}

// Sentinel errors. Compare with [errors.Is], never by string.
//
// Every one of them reports a MALFORMED CALL — a secret that is not a
// secret, a digit count no authenticator implements, a period that is not a
// period. A wrong CODE is not among them: [Validate] reports that as
// (0, false, nil), because a rejected credential is an ordinary outcome and
// an error return would tempt a caller into treating "wrong code" and
// "misconfigured factor" alike.
var (
	// ErrInvalidSecret: the secret is empty, or is not base32 once
	// whitespace and padding are removed. See [Code] for exactly which
	// surface forms are accepted.
	ErrInvalidSecret = errors.New("authlayer/internal/totp: secret is not valid base32")
	// ErrSecretTooShort: the secret decoded to fewer than 16 bytes (128
	// bits) — see [minSecretBytes] for the RFC 4226 MUST behind the floor.
	ErrSecretTooShort = errors.New("authlayer/internal/totp: secret shorter than 128 bits")
	// ErrInvalidDigits: digits is outside 6–8. Six is RFC 4226's minimum
	// and the universal default; eight is the most the dynamic truncation's
	// 31-bit value can express without a leading digit that is almost
	// always 0 or 1.
	ErrInvalidDigits = errors.New("authlayer/internal/totp: digits must be 6, 7 or 8")
	// ErrInvalidPeriod: the period is not a positive whole number of
	// seconds. RFC 6238 defines the time step in seconds, and a period
	// carrying a sub-second remainder would be silently floored into a
	// different factor than the one the caller asked for.
	ErrInvalidPeriod = errors.New("authlayer/internal/totp: period must be a positive whole number of seconds")
	// ErrInvalidSkew: the skew is negative, or wider than [maxSkew] steps.
	ErrInvalidSkew = errors.New("authlayer/internal/totp: skew must be between 0 and 10 steps")
	// ErrUnknownAlgorithm: the Algorithm is not one of the three declared
	// constants.
	ErrUnknownAlgorithm = errors.New("authlayer/internal/totp: unknown algorithm")
	// ErrEmptyCode: [Validate] was handed an empty code. An empty string is
	// never a credential, and refusing it here keeps a caller that forgot to
	// read a form field from spending a window's worth of HMACs on it.
	ErrEmptyCode = errors.New("authlayer/internal/totp: code is empty")
)

// base32Codec is the encoding secrets are written and read in: RFC 4648
// base32, unpadded. Authenticator apps and QR payloads use exactly this.
var base32Codec = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a fresh 160-bit secret in unpadded base32 — 32
// characters of A–Z and 2–7, the form an authenticator app takes.
//
// It reads from crypto/rand and propagates a failure rather than falling
// back to anything weaker: a second factor built on a predictable secret is
// not a second factor.
func GenerateSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("authlayer/internal/totp: read random secret: %w", err)
	}
	return base32Codec.EncodeToString(b), nil
}

// Code returns the TOTP code for secret at instant t.
//
// digits must be 6, 7 or 8; period must be a positive whole number of
// seconds (30 is RFC 6238's own step and every app's default); algo must be
// one of the three declared [Algorithm] constants. Every one of those, and
// the secret itself, is validated BEFORE any of them is used, and a refused
// call returns an empty code alongside its sentinel — never a code and an
// error together.
//
// # Which secrets are accepted
//
// The canonical form is unpadded RFC 4648 base32. Three other surface forms
// name the same secret and are accepted as it: lower case (apps and humans
// both produce it), ASCII whitespace anywhere (secrets are displayed in
// space-separated groups of four to be transcribed), and trailing '='
// padding (the RFC 4648 form some encoders emit). Nothing else is: the
// leniency covers presentation of the same string, never a different one.
// Unlike token.Parse's strict base64 there is no canonicalization concern
// to protect here — a secret is a key looked up by user id, never an
// identifier some other index is keyed on.
func Code(secret string, t time.Time, digits int, period time.Duration, algo Algorithm) (string, error) {
	key, seconds, newHash, err := prepare(secret, digits, period, algo)
	if err != nil {
		return "", err
	}
	return hotp(key, counterFor(stepAt(t.Unix(), seconds)), digits, newHash), nil
}

// Validate reports whether code is a valid TOTP for secret at instant t,
// and — the part its caller depends on — WHICH step it matched.
//
// skew is how many steps either side of t's own are accepted, absorbing
// clock drift between the server and the authenticator: 0 accepts only the
// current step, 1 also accepts the one before and the one after. It must be
// between 0 and [maxSkew].
//
// The returned step is the whole point of this signature. A code accepted
// anywhere in the window stays valid for the rest of that window, so a code
// read over someone's shoulder is reusable until it expires — unless the
// caller records the step that was used and refuses it and everything
// before it. See auth.MFAStore.AdvanceStep, which is that compare-and-set.
// On a rejection the step is 0, which is a real step number and therefore
// only meaningful when ok is true.
//
// A wrong code is (0, false, nil), not an error. The error return is
// exclusively for a malformed call — see the sentinel block.
func Validate(secret, code string, t time.Time, digits int, period time.Duration, algo Algorithm, skew int) (int64, bool, error) {
	if code == "" {
		return 0, false, ErrEmptyCode
	}
	if skew < 0 || skew > maxSkew {
		return 0, false, fmt.Errorf("%w: got %d", ErrInvalidSkew, skew)
	}
	key, seconds, newHash, err := prepare(secret, digits, period, algo)
	if err != nil {
		return 0, false, err
	}

	presented := []byte(code)
	current := stepAt(t.Unix(), seconds)

	matched := int64(0)
	ok := false
	// Every candidate in the window is computed and compared, with no early
	// exit on a match. Breaking out would make a code from the start of the
	// window answer measurably faster than one from the end, turning the
	// response time into a readout of the client's clock offset; and the
	// saving is at most a handful of HMACs. hmac.Equal is required here, not
	// ==: a string comparison short-circuits on the first differing byte,
	// which leaks (through response timing) how many leading digits of a
	// guessed code were right — the same reasoning token.Parse's own
	// comparison carries, and a test pins this call's source form. Do not
	// "simplify" either property away.
	for offset := -skew; offset <= skew; offset++ {
		step := current + int64(offset)
		candidate := hotp(key, counterFor(step), digits, newHash)
		if hmac.Equal([]byte(candidate), presented) {
			matched = step
			ok = true
		}
	}
	if !ok {
		return 0, false, nil
	}
	return matched, true, nil
}

// ProvisioningURI renders the otpauth URI an authenticator app consumes,
// usually as a QR code:
//
//	otpauth://totp/Acme:nia%40example.com?secret=…&issuer=Acme&algorithm=SHA1&digits=6&period=30
//
// issuer and account are percent-encoded, so a space, an '@' or a ':' in
// either is carried rather than read as syntax — an unescaped colon would
// split the label somewhere the caller did not intend. Spaces are written
// %20 rather than '+': the query half of this URI is read by scanners that
// percent-decode without applying form semantics, which would deliver a
// literal plus. An empty issuer drops both the label prefix and the
// `issuer` parameter instead of emitting a leading colon an app reads as an
// empty issuer name.
//
// algorithm, digits and period are always written out, even at their
// defaults, because apps disagree about what the defaults are.
//
// It validates NOTHING and returns no error: it is pure rendering, and the
// values it renders are the ones [Code] has already accepted. Handed values
// [Code] would refuse, it faithfully renders a URI describing a factor that
// cannot work — which is the visible failure, not a silent substitution.
func ProvisioningURI(secret, issuer, account string, digits int, period time.Duration, algo Algorithm) string {
	var b strings.Builder
	b.WriteString("otpauth://totp/")
	if issuer != "" {
		b.WriteString(escape(issuer))
		b.WriteString(":")
	}
	b.WriteString(escape(account))
	b.WriteString("?secret=")
	b.WriteString(escape(secret))
	if issuer != "" {
		b.WriteString("&issuer=")
		b.WriteString(escape(issuer))
	}
	b.WriteString("&algorithm=")
	b.WriteString(algo.String())
	fmt.Fprintf(&b, "&digits=%d&period=%d", digits, int64(period/time.Second))
	return b.String()
}

// escape percent-encodes one URI component, writing a space as %20 rather
// than url.QueryEscape's '+' — see [ProvisioningURI] for why the difference
// matters to a QR scanner.
func escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// prepare runs every input validation exactly once and returns what the two
// public entry points need: the decoded key, the period in whole seconds,
// and the hash constructor. It exists so [Code] and [Validate] cannot drift
// into validating different things — the defect where one entry point
// enforces the secret floor and the other does not is precisely the kind
// that survives review.
func prepare(secret string, digits int, period time.Duration, algo Algorithm) ([]byte, int64, func() hash.Hash, error) {
	if digits < 6 || digits > 8 {
		return nil, 0, nil, fmt.Errorf("%w: got %d", ErrInvalidDigits, digits)
	}
	if period <= 0 || period%time.Second != 0 {
		return nil, 0, nil, fmt.Errorf("%w: got %s", ErrInvalidPeriod, period)
	}
	newHash, err := algo.hasher()
	if err != nil {
		return nil, 0, nil, err
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return nil, 0, nil, err
	}
	return key, int64(period / time.Second), newHash, nil
}

// decodeSecret turns a base32 secret into its key bytes, accepting the
// surface forms [Code] documents and refusing everything else.
func decodeSecret(secret string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, secret)
	// Padding is stripped only from the end, where RFC 4648 puts it; an '='
	// in the middle is left in place so the decoder refuses it rather than
	// this function quietly closing the gap.
	cleaned = strings.TrimRight(cleaned, "=")
	if cleaned == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidSecret)
	}
	key, err := base32Codec.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSecret, err)
	}
	if len(key) < minSecretBytes {
		return nil, fmt.Errorf("%w: got %d bytes, want at least %d", ErrSecretTooShort, len(key), minSecretBytes)
	}
	return key, nil
}

// stepAt is RFC 6238's T = floor((unix - T0) / X) with T0 = 0, done as
// FLOOR division rather than Go's truncation toward zero so that instants
// before the Unix epoch — outside the algorithm's intended domain, but
// reachable from a caller's clock — map to distinct decreasing steps
// instead of folding onto step 0 from both sides. period is in whole
// seconds and is guaranteed positive by [prepare].
func stepAt(unix, period int64) int64 {
	q := unix / period
	if unix%period != 0 && unix < 0 {
		q--
	}
	return q
}

// counterFor reinterprets a step as the unsigned 64-bit counter RFC 4226
// feeds the MAC. Only a pre-epoch step is negative, and its two's
// complement form is a well-defined counter like any other.
func counterFor(step int64) uint64 { return uint64(step) }

// hotp is RFC 4226's HOTP: HMAC the counter under key, take the dynamic
// truncation of the result, and render it as `digits` decimal digits.
//
// The counter is written BIG-ENDIAN, which RFC 4226 §5.1 requires ("C is
// the 8-byte counter value, the moving factor... in big endian"). This one
// line is the difference between TOTP and a self-consistent private
// algorithm that agrees with itself forever and with no authenticator app
// at all: reversing it changes every code while breaking no round trip, so
// the published vectors in totp_test.go are what defends it. The mutation
// was run.
func hotp(key []byte, counter uint64, digits int, newHash func() hash.Hash) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(newHash, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 §5.3: the low nibble of the last byte
	// picks a 4-byte window, whose top bit is masked off so the value is a
	// positive 31-bit integer on every platform and in every language.
	offset := sum[len(sum)-1] & 0x0f
	truncated := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	// Zero-padded to the full width: a code whose leading digit is 0 is a
	// perfectly ordinary code, and "%d" would silently hand back a shorter
	// string roughly one time in ten.
	return fmt.Sprintf("%0*d", digits, truncated%pow10[digits])
}

// pow10 holds the moduli for the digit counts [prepare] admits. Indices
// below 6 are unreachable and present only to keep the index the digit
// count itself; 10^8 fits comfortably in the uint32 the truncation yields.
var pow10 = [9]uint32{0, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}
