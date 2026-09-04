package token

import (
	"errors"
	"fmt"
	"time"
)

// The two JOSE "alg" values this package knows how to write and verify — one
// per [Signer] implementation, and never both on the same Signer. See the
// package doc, "Why a hand-rolled JWT is safe here, and only here", for why
// the split is by CONSTRUCTOR rather than by header.
const (
	// AlgHS256 is the "alg" the [HS256] signer, and the released [Issue] /
	// [Parse] free functions beneath it, write and accept.
	AlgHS256 = hs256Alg
	// AlgEdDSA is the "alg" the [EdDSA] signer writes and accepts: Ed25519
	// over the JWS signing input, per RFC 8037 §3.1.
	AlgEdDSA = "EdDSA"
)

// Sentinel errors added with the [Signer] abstraction. Compare with
// [errors.Is], never by string.
var (
	// ErrUnknownKey: an [EdDSA] signer was presented a token whose header
	// carries no "kid", or a "kid" naming no key that signer holds — its
	// own signing key or one of its verifiers. Returned after the alg check
	// and before any signature verification is attempted, so a token for a
	// retired or foreign key is refused without a single Ed25519 operation.
	ErrUnknownKey = errors.New("authlayer/token: unknown signing key id")
	// ErrInvalidKey: key material handed to a [Signer] constructor is not
	// usable — an empty kid, an Ed25519 private or public key of the wrong
	// length, or two different public keys registered under one kid.
	// Construction refuses rather than building a Signer that would fail,
	// or worse quietly verify nothing, at its first use. It is also what
	// [EdDSAVerifier]'s Issue returns: a verifier holds no private key and
	// can sign nothing. The HMAC key floor keeps its own, older sentinel,
	// [ErrKeyTooShort].
	ErrInvalidKey = errors.New("authlayer/token: key material is not usable")
)

// Signer issues and verifies this package's access tokens under ONE
// algorithm, chosen at construction and never read from a token. [HS256] and
// [EdDSA] are the two implementations; each writes exactly one "alg" value
// and refuses every other with [ErrUnsupportedAlgorithm], so the two-signer
// package keeps the single-algorithm parser's safety argument intact — see
// the package doc.
//
// A Signer is safe for concurrent use: it holds key material and nothing
// else, and neither method mutates it.
type Signer interface {
	// Issue signs c and returns the compact serialization. IssuedAt and
	// ExpiresAt are set from now and ttl, overriding whatever c carried,
	// exactly as the free function [Issue] does; ttl <= 0 is
	// [ErrInvalidTTL].
	Issue(c Claims, ttl time.Duration) (string, error)
	// Parse verifies raw against the keys this Signer holds and returns its
	// claims. The header's "alg" must equal Alg() exactly, or the token is
	// refused with [ErrUnsupportedAlgorithm] before anything else is
	// checked. Every other failure is one of this package's sentinels —
	// see [Parse] for the HS256 set and [EdDSA] for the one it adds.
	Parse(raw string) (Claims, error)
	// Alg is the JOSE "alg" this Signer writes and accepts: [AlgHS256] or
	// [AlgEdDSA]. It is a constant of the implementation, not a property of
	// any token.
	Alg() string
}

// hs256Signer is [HS256]'s implementation: a key list handed, unchanged, to
// the released [Issue] and [Parse] free functions. It adds no code path of
// its own to either.
type hs256Signer struct {
	keys [][]byte
}

// HS256 returns a [Signer] over keys: keys[0] signs every token it issues,
// and every key in the list is tried on Parse, which is how an HMAC secret
// is rotated — prepend the new key, deploy, drop the old one once every
// token signed under it has expired. It is [Issue] and [Parse] behind the
// Signer interface, and nothing more: the two free functions remain the
// HS256 path, unchanged, and this constructor is how the same path is
// handed to something that takes a Signer, such as
// [github.com/bernardoforcillo/authlayer/auth.WithSigner].
//
// It refuses fewer than one key, and any key under 32 bytes, with
// [ErrKeyTooShort] — the same floor and the same sentinel [Issue] and
// [Parse] apply, checked once here instead of on every call. A missing key
// is indistinguishable from a zero-length one for that check, which is why
// "no keys" is not a sentinel of its own: an unset environment variable
// must fail loudly at construction, not mint a forgeable token.
//
// The keys are copied, so a caller that later mutates its own slice does
// not change what this Signer signs or verifies with.
func HS256(keys ...[]byte) (Signer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: HS256 needs at least one key, got none", ErrKeyTooShort)
	}
	held := make([][]byte, len(keys))
	for i, k := range keys {
		if len(k) < minKeyLen {
			return nil, fmt.Errorf("%w: key %d is %d bytes, want at least %d", ErrKeyTooShort, i, len(k), minKeyLen)
		}
		held[i] = append([]byte(nil), k...)
	}
	return &hs256Signer{keys: held}, nil
}

// Issue implements [Signer] by calling [Issue] with the signing key,
// keys[0].
func (s *hs256Signer) Issue(c Claims, ttl time.Duration) (string, error) {
	return Issue(c, s.keys[0], ttl)
}

// Parse implements [Signer] by calling [Parse] with every held key.
func (s *hs256Signer) Parse(raw string) (Claims, error) {
	return Parse(raw, s.keys...)
}

// Alg implements [Signer]: always [AlgHS256].
func (s *hs256Signer) Alg() string { return AlgHS256 }
