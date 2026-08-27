// Package password hashes and verifies user passwords behind the [Hasher]
// port, and validates password strength against a configurable [Rules]
// policy. [Bcrypt] is the only implementation this package provides; other
// algorithms (argon2id, say) are meant to be drop-in replacements behind
// the same [Hasher] interface, not additions to this package.
//
// # Why Dummy exists, and why its result is ignored on purpose
//
// [Hasher.Dummy] runs a real bcrypt comparison against a fixed, throwaway
// hash and discards the outcome. Its entire reason for existing is timing,
// not correctness: a login flow that looks up a user by email and only
// calls Verify when that lookup succeeds makes the "no such account"
// response measurably faster than the "wrong password" response, because
// the no-such-account path skips the deliberately slow bcrypt comparison
// entirely. That gap is an account-enumeration oracle — an attacker who
// never sees a response body can still tell registered addresses from
// unregistered ones purely by clocking how long the login endpoint takes to
// answer. Calling Dummy on the user-not-found path spends bcrypt work of
// the same order as a real Verify call would, closing that gap.
//
// Concretely: Login is expected to call Dummy exactly when the user lookup
// misses, so both branches — "no such user" and "user exists, wrong
// password" — do comparable bcrypt work before responding.
//
// The call to Dummy on a lookup miss is therefore not incidental,
// defensive, or decorative. Do not delete it because "the result is
// discarded, so this does nothing" — that reasoning is exactly backwards:
// discarding the result is the point, and deleting the call silently
// reintroduces the timing oracle it exists to close.
package password

import (
	"fmt"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Hasher hashes and verifies plaintext passwords, and provides the
// timing-equalizing comparison a login flow needs on a user-not-found path.
// [Bcrypt] is the default implementation; any type satisfying this
// interface (argon2id, say) is a drop-in replacement.
type Hasher interface {
	// Hash returns a hash of plain suitable for storage and later
	// verification via Verify. Implementations must salt independently on
	// every call, so hashing the same plaintext twice yields different
	// results.
	Hash(plain string) (string, error)

	// Verify reports whether plain is the plaintext that produced hash. It
	// returns false — never panics — for any hash that is empty,
	// truncated, or otherwise not a hash this implementation produced, so
	// a caller can pass through whatever a datastore returns without
	// pre-validating it.
	Verify(plain, hash string) bool

	// Dummy performs comparison work of the same order as Verify without
	// checking plain against anything real, and discards the result. See
	// the package doc for why this exists and why ignoring its result is
	// deliberate rather than a bug: a login flow calls Dummy on a
	// user-not-found path so that path takes comparably long to the
	// wrong-password path, closing an account-enumeration timing oracle.
	Dummy(plain string)
}

// dummyPlaintext is the fixed plaintext each bcryptHasher hashes, once, to
// build the throwaway hash Dummy compares against. Its value is arbitrary
// — Dummy never checks plain against it or anything else real — but it
// must stay constant for a given process, since a lazily-cached dummy hash
// is only valid to keep comparing against if the plaintext it was built
// from never changes underneath it.
const dummyPlaintext = "authlayer-password-dummy-comparison-do-not-use-as-a-real-password"

// fallbackDummyHash is a package-level, default-cost dummy hash shared by
// every bcryptHasher whose own configured cost is outside bcrypt's valid
// range (see [bcryptHasher.Dummy]). bcrypt.DefaultCost is always in range,
// so building this can only fail if the process's randomness source is
// broken — a condition that would already be failing every other call into
// this package, not something Dummy needs to survive gracefully beyond not
// panicking on the vastly more common path.
var (
	fallbackDummyHash     []byte
	fallbackDummyHashOnce sync.Once
)

func getFallbackDummyHash() []byte {
	fallbackDummyHashOnce.Do(func() {
		hash, err := bcrypt.GenerateFromPassword([]byte(dummyPlaintext), bcrypt.DefaultCost)
		if err != nil {
			panic("authlayer/password: failed to precompute fallback dummy hash: " + err.Error())
		}
		fallbackDummyHash = hash
	})
	return fallbackDummyHash
}

// bcryptHasher is the [Hasher] returned by [Bcrypt].
type bcryptHasher struct {
	cost int

	dummyOnce sync.Once
	dummyHash []byte
}

// Bcrypt returns a [Hasher] backed by golang.org/x/crypto/bcrypt at the
// given cost. A cost of 0 uses bcrypt's own library default
// ([bcrypt.DefaultCost], currently 10). Any other value is passed through
// to bcrypt as given, and bcrypt's own rules then apply to it: a cost
// below [bcrypt.MinCost] (4) — including 1, 2, and 3, not just 0 — is
// silently promoted to bcrypt's default cost by the library itself,
// while a cost above [bcrypt.MaxCost] (31) is rejected outright,
// surfacing as an error from Hash. This package does not re-validate or
// clamp cost itself beyond translating the cost == 0 case.
func Bcrypt(cost int) Hasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &bcryptHasher{cost: cost}
}

// Hash implements [Hasher.Hash] using bcrypt at this Hasher's configured
// cost. bcrypt salts every call independently, so the same plain hashed
// twice produces two different, equally valid results.
func (h *bcryptHasher) Hash(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), h.cost)
	if err != nil {
		return "", fmt.Errorf("authlayer/password: hash: %w", err)
	}
	return string(hash), nil
}

// Verify implements [Hasher.Verify]. bcrypt.CompareHashAndPassword returns
// a non-nil error both for a genuine mismatch and for a hash that is
// malformed, truncated, or otherwise not a bcrypt hash — Verify collapses
// every such case to false rather than panicking or distinguishing them,
// which is the contract [Hasher.Verify] documents.
func (h *bcryptHasher) Verify(plain, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// Dummy implements [Hasher.Dummy]; see the package doc for why it exists
// and why its result is discarded rather than returned.
//
// The throwaway hash it compares against is built once per Hasher, on this
// Hasher's first call to Dummy — not per call, and not eagerly in [Bcrypt]
// — because bcrypt hashing costs far more than a single comparison; doing
// it on every call would make Dummy itself slower than the Verify call it
// stands in for, which is its own timing signal. It is built at this
// Hasher's own configured cost (falling back to bcrypt's default cost only
// if that cost is outside bcrypt's valid range) rather than some fixed
// constant, so that Dummy's running time stays in the same ballpark as a
// real Verify call against a hash this same Hasher produced — the entire
// property this method exists to provide.
func (h *bcryptHasher) Dummy(plain string) {
	h.dummyOnce.Do(func() {
		hash, err := bcrypt.GenerateFromPassword([]byte(dummyPlaintext), h.cost)
		if err != nil {
			// h.cost is outside bcrypt's valid range: Hash would already be
			// failing for every caller of this Hasher. Fall back to a
			// default-cost hash so Dummy still does comparable bcrypt work
			// instead of silently degrading into a no-op.
			hash = getFallbackDummyHash()
		}
		h.dummyHash = hash
	})

	// The result is deliberately discarded — see the package doc and the
	// Hasher.Dummy comment. This is not dead code.
	_ = bcrypt.CompareHashAndPassword(h.dummyHash, []byte(plain))
}

// Rules configures the password strength policy [Validate] checks a
// plaintext password against. The zero value requires nothing (MinLength
// 0, no character classes required); use [DefaultRules] for authlayer's
// baseline policy.
type Rules struct {
	// MinLength is the minimum number of Unicode code points (runes) the
	// password must contain. Counted in runes, not bytes: a password made
	// entirely of multi-byte characters is judged by its character count,
	// not its encoded size.
	MinLength int
	// RequireUpper requires at least one Unicode uppercase letter.
	RequireUpper bool
	// RequireLower requires at least one Unicode lowercase letter.
	RequireLower bool
	// RequireDigit requires at least one Unicode decimal digit.
	RequireDigit bool
	// RequireSpecial requires at least one character that is neither a
	// Unicode letter, a Unicode digit, nor Unicode whitespace —
	// punctuation and symbols satisfy it, whitespace does not. Excluding
	// whitespace from this class does not forbid it: a password may still
	// contain spaces anywhere, they simply do not count toward
	// RequireSpecial, so padding a short password with spaces alone
	// cannot satisfy it.
	RequireSpecial bool
}

// DefaultRules is authlayer's baseline password policy: at least 12
// characters, requiring at least one uppercase letter, one lowercase
// letter, one digit, and one special character.
func DefaultRules() Rules {
	return Rules{
		MinLength:      12,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
	}
}

// Validate checks plain against rules and returns the name of every rule it
// violates — "min_length", "upper", "lower", "digit", "special", always in
// that order — so a caller can build a stable, machine-checkable error
// message. A password that satisfies every rule enabled in rules returns
// an empty slice — callers can treat len(Validate(...)) == 0 as the
// pass/fail check.
//
// MinLength is counted in runes (Unicode code points), not bytes: see
// [Rules.MinLength].
func Validate(plain string, rules Rules) []string {
	failed := []string{}

	if utf8.RuneCountInString(plain) < rules.MinLength {
		failed = append(failed, "min_length")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range plain {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case !unicode.IsLetter(r) && !unicode.IsSpace(r):
			// Punctuation and symbols count as "special"; whitespace does
			// not — see Rules.RequireSpecial. Without the IsSpace
			// exclusion, a password like "Aa1" padded with nine spaces
			// would satisfy RequireSpecial (and MinLength) on padding
			// alone, certifying a near-zero-entropy password as compliant.
			hasSpecial = true
		}
	}

	if rules.RequireUpper && !hasUpper {
		failed = append(failed, "upper")
	}
	if rules.RequireLower && !hasLower {
		failed = append(failed, "lower")
	}
	if rules.RequireDigit && !hasDigit {
		failed = append(failed, "digit")
	}
	if rules.RequireSpecial && !hasSpecial {
		failed = append(failed, "special")
	}

	return failed
}
