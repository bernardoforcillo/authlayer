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

// Sentinel errors returned by [Parse]. Compare with [errors.Is], never by
// string.
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
}

// Issue signs c as a compact-serialized HS256 JWT using key, and returns the
// result. IssuedAt is set to now and ExpiresAt to now+ttl, overriding
// whatever c.IssuedAt/c.ExpiresAt already held — callers control the
// lifetime through ttl, not by pre-populating those fields.
//
// key is the only key this token is ever signed with. When keys are
// rotated, callers pass the current signing key here — conventionally
// keys[0] of whatever list is also passed to [Parse] — never an old one.
func Issue(c Claims, key []byte, ttl time.Duration) (string, error) {
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
func Parse(raw string, keys ...[]byte) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: expected 3 segments, got %d", ErrMalformedToken, len(parts))
	}
	headerPart, payloadPart, sigPart := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerPart)
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

	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
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

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadPart)
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
