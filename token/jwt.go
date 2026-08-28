package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// hs256Alg is the only value Parse ever accepts in a token's header "alg"
// field. It is unexported and used nowhere but that one comparison — see the
// package doc for why that single check is what makes this parser safe to
// hand-roll.
const hs256Alg = "HS256"

// minKeyLen is the minimum HMAC key length this package accepts: 32 bytes
// (256 bits), matching the SHA-256 output size and the floor RFC 7518 §3.2
// sets for HS256 ("A key of the same size as the hash output ... MUST be
// used"). A shorter key is only as hard to guess as its own length — and a
// nil or empty key, the realistic case when a secret comes from an unset
// environment variable, makes the MAC computable by anyone. That is "alg:
// none" reached through the key parameter instead of the header: the exact
// class of bug this package's single-algorithm design exists to rule out.
// Issue and Parse both refuse anything shorter, loudly.
const minKeyLen = 32

// Sentinel errors returned by [Issue] and [Parse]. Compare with [errors.Is],
// never by string.
var (
	// ErrMalformedToken: raw is not a syntactically valid JWS compact
	// serialization — wrong segment count, invalid base64, or a header/payload
	// segment that does not decode as JSON.
	ErrMalformedToken = errors.New("authlayer/token: malformed token")
	// ErrUnsupportedAlgorithm: the header's "alg" is not the exact string
	// "HS256". Returned before any signature verification is attempted.
	ErrUnsupportedAlgorithm = errors.New("authlayer/token: unsupported algorithm")
	// ErrInvalidSignature: none of the keys passed to Parse produced a
	// signature matching the token's.
	ErrInvalidSignature = errors.New("authlayer/token: invalid signature")
	// ErrExpiredToken: the signature verified, but the claims' ExpiresAt is
	// not in the future.
	ErrExpiredToken = errors.New("authlayer/token: token expired")
	// ErrKeyTooShort: a key shorter than 32 bytes (256 bits) was passed to
	// Issue, or appears anywhere in the key list passed to Parse. See
	// [minKeyLen] for why the floor exists.
	ErrKeyTooShort = errors.New("authlayer/token: HMAC key shorter than 32 bytes")
	// ErrInvalidTTL: Issue was given a zero or negative ttl, which would
	// mint a token already expired at the moment it is issued.
	ErrInvalidTTL = errors.New("authlayer/token: ttl must be positive")
)

// jwtHeader is the JOSE header this package writes and reads. It carries
// nothing beyond alg/typ because nothing else is ever consulted.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims are the fields carried in an access token's JWT payload: who the
// token is for (Subject), which session it belongs to (SessionID, so the
// session can be looked up or revoked independently of the token's own
// validity), a denormalized Email for display without a lookup, and the
// standard JWT IssuedAt/ExpiresAt timestamps (Unix seconds).
//
// [Issue] sets IssuedAt and ExpiresAt itself from the ttl it is given;
// values set on the Claims passed in are ignored for those two fields.
type Claims struct {
	Subject   string `json:"sub"`
	SessionID string `json:"sid"`
	Email     string `json:"email"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	// Extra carries additional, application-defined claims beyond the fixed
	// set above — populated by
	// [github.com/bernardoforcillo/authlayer/auth]'s WithClaimsExtender, nil
	// otherwise. This package neither reads nor interprets it: Issue
	// marshals whatever the caller set on Claims (Extra included) exactly
	// like every other field, and Parse decodes it back the same way — this
	// is a plain, additive data field, not a second code path, so none of
	// the alg/key/signature checks documented on Parse are affected by its
	// presence, absence, or contents. omitempty keeps an unset Extra out of
	// the token entirely, so a caller that never sets it gets byte-for-byte
	// the same payload shape this package produced before the field
	// existed.
	Extra map[string]any `json:"ext,omitempty"`
}

// Issue signs c as a compact-serialized HS256 JWT using key, and returns the
// result. IssuedAt is set to now and ExpiresAt to now+ttl, overriding
// whatever c.IssuedAt/c.ExpiresAt already held — callers control the
// lifetime through ttl, not by pre-populating those fields. ttl must be
// positive; Issue refuses to mint a token that is already expired, returning
// [ErrInvalidTTL].
//
// key is the only key this token is ever signed with. When keys are
// rotated, callers pass the current signing key here — conventionally
// keys[0] of whatever list is also passed to [Parse] — never an old one.
// key must be at least 32 bytes (see [minKeyLen]); a nil, empty, or
// otherwise undersized key is refused with [ErrKeyTooShort] rather than
// silently accepted — an unset environment variable must fail loudly here,
// not mint a forgeable token.
func Issue(c Claims, key []byte, ttl time.Duration) (string, error) {
	if len(key) < minKeyLen {
		return "", fmt.Errorf("%w: got %d bytes, want at least %d", ErrKeyTooShort, len(key), minKeyLen)
	}
	if ttl <= 0 {
		return "", fmt.Errorf("%w: got %s", ErrInvalidTTL, ttl)
	}

	now := time.Now()
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(ttl).Unix()

	headerJSON, err := json.Marshal(jwtHeader{Alg: hs256Alg, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("authlayer/token: marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("authlayer/token: marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := signHS256(key, signingInput)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Parse verifies raw and returns its claims. It tries each of keys in turn,
// so a rotated secret can still verify tokens signed under a retired one —
// pass the current key first and any keys being retired after it.
//
// The header's "alg" must be the exact string "HS256"; every other value,
// including a missing field or any other casing, is rejected with
// [ErrUnsupportedAlgorithm] before any key is tried. This is checked before
// signature verification, before the payload is even decoded, and is what
// makes this single-algorithm parser immune to the "alg: none" and
// RS256/HS256 key-confusion attacks — see the package doc.
//
// An expired token (ExpiresAt not in the future) is rejected with
// [ErrExpiredToken] only after its signature has verified, so an attacker
// cannot use the expiry check to probe for a valid signature on claims they
// forged.
//
// Every key in keys must be at least 32 bytes (see [minKeyLen]); if any one
// of them is shorter, Parse refuses the whole call with [ErrKeyTooShort]
// rather than silently skipping just that key and trying the rest — a
// caller passing a bad key wants to know, not have it quietly ignored.
//
// Each segment is decoded with strict (canonical) base64: a segment whose
// unused trailing bits are non-zero is rejected as malformed rather than
// silently accepted, so a given signature has exactly one valid string
// encoding rather than several that all decode the same. That makes the raw
// token string usable as a canonical identifier — for a denylist or replay
// cache, say — which a permissive decoder would quietly undermine.
func Parse(raw string, keys ...[]byte) (Claims, error) {
	for i, key := range keys {
		if len(key) < minKeyLen {
			return Claims{}, fmt.Errorf("%w: key %d is %d bytes, want at least %d", ErrKeyTooShort, i, len(key), minKeyLen)
		}
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: expected 3 segments, got %d", ErrMalformedToken, len(parts))
	}
	headerPart, payloadPart, sigPart := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.Strict().DecodeString(headerPart)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header is not valid base64: %v", ErrMalformedToken, err)
	}
	var h jwtHeader
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return Claims{}, fmt.Errorf("%w: header is not valid JSON: %v", ErrMalformedToken, err)
	}

	// The one check that matters: reject anything but our exact algorithm,
	// before verifying or trusting a single other byte of the token.
	if h.Alg != hs256Alg {
		return Claims{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, h.Alg)
	}

	sig, err := base64.RawURLEncoding.Strict().DecodeString(sigPart)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature is not valid base64: %v", ErrMalformedToken, err)
	}

	signingInput := headerPart + "." + payloadPart
	verified := false
	for _, key := range keys {
		want := signHS256(key, signingInput)
		// hmac.Equal is required here, not ==: a byte-by-byte string/slice
		// comparison short-circuits on the first mismatching byte, which
		// leaks (via response timing) how many leading bytes of a guessed
		// signature were correct. hmac.Equal runs in time independent of
		// where the signatures differ. Do not "simplify" this to ==.
		if hmac.Equal(want, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return Claims{}, ErrInvalidSignature
	}

	payloadJSON, err := base64.RawURLEncoding.Strict().DecodeString(payloadPart)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload is not valid base64: %v", ErrMalformedToken, err)
	}
	var c Claims
	if err := json.Unmarshal(payloadJSON, &c); err != nil {
		return Claims{}, fmt.Errorf("%w: payload is not valid JSON: %v", ErrMalformedToken, err)
	}

	if time.Now().Unix() >= c.ExpiresAt {
		return Claims{}, ErrExpiredToken
	}

	return c, nil
}

// signHS256 computes the raw HMAC-SHA256 signature of signingInput under
// key. Callers compare the result with [hmac.Equal], never by equality on
// the returned bytes or on any string built from them.
func signHS256(key []byte, signingInput string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}
