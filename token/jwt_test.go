package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// keyA and keyB are exactly minKeyLen (32) bytes — the RFC 7518 §3.2 floor
// for HS256 — and built with bytes.Repeat rather than a hand-counted string
// literal so their length is not a place a typo can hide.
var (
	keyA = bytes.Repeat([]byte("A"), 32)
	keyB = bytes.Repeat([]byte("B"), 32)
)

func sampleClaims() Claims {
	return Claims{
		Subject:   "user-123",
		SessionID: "session-456",
		Email:     "alice@example.com",
	}
}

// rawURL base64-encodes b the way RFC 7515 compact serialization requires:
// unpadded, URL-safe. Tests use this directly (not any package helper) so a
// broken encoding inside the package would still be caught.
func rawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// craftToken assembles a JWS compact token from an arbitrary raw header
// string, arbitrary claims, and a signature computed independently of
// Issue/Parse's own code path, using only crypto/hmac and crypto/sha256
// directly. This lets tests hand Parse malicious or malformed headers that
// Issue itself would never produce.
func craftToken(t *testing.T, headerJSON string, claims Claims, key []byte) string {
	t.Helper()
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := rawURL([]byte(headerJSON)) + "." + rawURL(payloadJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return signingInput + "." + rawURL(mac.Sum(nil))
}

// Issue then Parse with the same key must hand back the claims that were
// issued, with IssuedAt/ExpiresAt set from the ttl Issue was given.
func TestIssueParseRoundTrip(t *testing.T) {
	before := time.Now()
	raw, err := Issue(sampleClaims(), keyA, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	after := time.Now()

	got, err := Parse(raw, keyA)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Subject != "user-123" || got.SessionID != "session-456" || got.Email != "alice@example.com" {
		t.Fatalf("Parse claims = %+v, want subject/session/email preserved from Issue", got)
	}
	if got.IssuedAt < before.Unix() || got.IssuedAt > after.Unix() {
		t.Fatalf("IssuedAt = %d, want within [%d, %d]", got.IssuedAt, before.Unix(), after.Unix())
	}
	wantExp := before.Add(time.Hour).Unix()
	if got.ExpiresAt < wantExp || got.ExpiresAt > after.Add(time.Hour).Unix() {
		t.Fatalf("ExpiresAt = %d, want approximately %d (issued-at + ttl)", got.ExpiresAt, wantExp)
	}
}

// Base64 segments must be raw (unpadded) URL encoding per RFC 7515: no '='
// padding and no '+'/'/' std-alphabet characters.
func TestIssueUsesRawURLBase64(t *testing.T) {
	raw, err := Issue(sampleClaims(), keyA, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	for i, p := range parts {
		if strings.ContainsAny(p, "+/=") {
			t.Fatalf("segment %d (%q) contains std-base64 or padding characters, want raw URL encoding", i, p)
		}
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			t.Fatalf("segment %d (%q) is not valid raw URL base64: %v", i, p, err)
		}
	}
}

// alg: none must never verify — the entire point of this package.
func TestParseRejectsAlgNone(t *testing.T) {
	raw := craftToken(t, `{"alg":"none","typ":"JWT"}`, sampleClaims(), keyA)
	if _, err := Parse(raw, keyA); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Parse(alg=none) err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// RS256/HS256 confusion also depends on the parser accepting an alg it
// wasn't built for; this must be refused the same way alg:none is.
func TestParseRejectsAlgRS256(t *testing.T) {
	raw := craftToken(t, `{"alg":"RS256","typ":"JWT"}`, sampleClaims(), keyA)
	if _, err := Parse(raw, keyA); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Parse(alg=RS256) err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// A header with no alg field at all must not default to accepted.
func TestParseRejectsMissingAlg(t *testing.T) {
	raw := craftToken(t, `{"typ":"JWT"}`, sampleClaims(), keyA)
	if _, err := Parse(raw, keyA); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Parse(no alg) err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// The comparison against "HS256" must be exact, not case-insensitive.
func TestParseRejectsLowercaseAlg(t *testing.T) {
	raw := craftToken(t, `{"alg":"hs256","typ":"JWT"}`, sampleClaims(), keyA)
	if _, err := Parse(raw, keyA); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Parse(alg=hs256) err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// A token signed with a key that is second in Parse's key list must still
// verify — this is what lets a secret be rotated without invalidating every
// outstanding token signed under the old one.
func TestParseKeyRotationSecondKeyStillVerifies(t *testing.T) {
	raw, err := Issue(sampleClaims(), keyB, time.Hour) // signed with the "old" key
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// keyA is the new/current key, listed first; keyB (old) is second.
	got, err := Parse(raw, keyA, keyB)
	if err != nil {
		t.Fatalf("Parse with rotated key list: %v", err)
	}
	if got.Subject != "user-123" {
		t.Fatalf("Parse claims = %+v, want the issued subject", got)
	}
}

// Issue always signs with the single key it is given (conventionally the
// caller's keys[0]); a token it produces must fail to verify against a
// key list that does not contain that key at all.
func TestIssueSignsOnlyWithGivenKey(t *testing.T) {
	raw, err := Issue(sampleClaims(), keyA, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := Parse(raw, keyB); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Parse with unrelated key err = %v, want ErrInvalidSignature", err)
	}
}

// An expired token (exp in the past) must be rejected even though its
// signature is valid. Issue itself now refuses a negative ttl (see
// TestIssueRejectsNonPositiveTTL), so this crafts the already-expired token
// directly rather than going through Issue.
func TestParseRejectsExpiredToken(t *testing.T) {
	c := sampleClaims()
	c.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()
	c.ExpiresAt = time.Now().Add(-time.Minute).Unix() // already expired
	raw := craftToken(t, `{"alg":"HS256","typ":"JWT"}`, c, keyA)
	if _, err := Parse(raw, keyA); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("Parse(expired) err = %v, want ErrExpiredToken", err)
	}
}

// A token whose exp is in the future must be accepted (given a valid
// signature) — the mirror image of the expired-token check.
func TestParseAcceptsFutureExp(t *testing.T) {
	raw, err := Issue(sampleClaims(), keyA, 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := Parse(raw, keyA); err != nil {
		t.Fatalf("Parse(future exp) err = %v, want nil", err)
	}
}

// Flipping a character in the payload segment must invalidate the
// signature — a tampered payload must never be trusted just because it is
// well-formed JSON.
func TestParseRejectsTamperedPayload(t *testing.T) {
	raw, err := Issue(sampleClaims(), keyA, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	tamperedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var c Claims
	if err := json.Unmarshal(tamperedPayload, &c); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	c.Subject = "someone-else" // escalate to a different subject
	tampered, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal tampered claims: %v", err)
	}
	parts[1] = rawURL(tampered)
	tamperedRaw := strings.Join(parts, ".")

	if _, err := Parse(tamperedRaw, keyA); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Parse(tampered payload) err = %v, want ErrInvalidSignature", err)
	}
}

// A structurally valid, correctly-signed-by-someone token signed under a
// key not offered to Parse must fail — same property as key rotation, but
// phrased as "wrong key" rather than "old key not offered".
func TestParseRejectsSignatureFromDifferentKey(t *testing.T) {
	raw := craftToken(t, `{"alg":"HS256","typ":"JWT"}`, sampleClaims(), keyB)
	if _, err := Parse(raw, keyA); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Parse(wrong key) err = %v, want ErrInvalidSignature", err)
	}
}

// A token that does not have exactly three dot-separated segments must be
// rejected outright.
func TestParseRejectsMalformedToken(t *testing.T) {
	cases := []string{
		"",
		"only-one-segment",
		"two.segments",
		"way.too.many.segments",
	}
	for _, raw := range cases {
		if _, err := Parse(raw, keyA); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("Parse(%q) err = %v, want ErrMalformedToken", raw, err)
		}
	}
}

// Non-base64 garbage in any segment must be rejected as malformed, not
// panic and not silently coerce.
func TestParseRejectsInvalidBase64Segments(t *testing.T) {
	if _, err := Parse("not!base64.not!base64.not!base64", keyA); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("Parse(invalid base64) err = %v, want ErrMalformedToken", err)
	}
}

// A header that decodes from base64 but is not valid JSON must be rejected
// as malformed rather than reaching the alg check with a zero-valued header.
func TestParseRejectsNonJSONHeader(t *testing.T) {
	raw := rawURL([]byte("not-json")) + "." + rawURL([]byte(`{"sub":"x"}`)) + "." + rawURL([]byte("sig"))
	if _, err := Parse(raw, keyA); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("Parse(non-JSON header) err = %v, want ErrMalformedToken", err)
	}
}

// Issue must refuse an HMAC key shorter than minKeyLen (32 bytes). A nil key
// is the realistic trigger — []byte(os.Getenv("JWT_SECRET")) with the
// variable unset — and must fail loudly rather than mint a token anyone
// could forge with an empty-key HMAC.
func TestIssueRejectsShortKey(t *testing.T) {
	cases := map[string][]byte{
		"nil key":     nil,
		"empty key":   {},
		"31-byte key": bytes.Repeat([]byte("x"), 31),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Issue(sampleClaims(), key, time.Hour); !errors.Is(err, ErrKeyTooShort) {
				t.Fatalf("Issue(%s) err = %v, want ErrKeyTooShort", name, err)
			}
		})
	}
}

// Parse must refuse the same undersized keys when they are the only key
// offered.
func TestParseRejectsShortKey(t *testing.T) {
	raw, err := Issue(sampleClaims(), keyA, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cases := map[string][]byte{
		"nil key":     nil,
		"empty key":   {},
		"31-byte key": bytes.Repeat([]byte("x"), 31),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw, key); !errors.Is(err, ErrKeyTooShort) {
				t.Fatalf("Parse(%s alone) err = %v, want ErrKeyTooShort", name, err)
			}
		})
	}
}

// A short key anywhere in the list must reject the whole call, even when a
// valid, correctly-sized key elsewhere in the same list would otherwise
// verify the token — Parse must not silently skip the bad key and check the
// rest.
func TestParseRejectsShortKeyAmongValidKeys(t *testing.T) {
	raw, err := Issue(sampleClaims(), keyA, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	short := bytes.Repeat([]byte("x"), 31)
	if _, err := Parse(raw, keyA, short); !errors.Is(err, ErrKeyTooShort) {
		t.Fatalf("Parse(valid, short) err = %v, want ErrKeyTooShort", err)
	}
	if _, err := Parse(raw, short, keyA); !errors.Is(err, ErrKeyTooShort) {
		t.Fatalf("Parse(short, valid) err = %v, want ErrKeyTooShort", err)
	}
}

// Issue must refuse a zero or negative ttl — it would mint a token that is
// already expired the instant it is issued, silently.
func TestIssueRejectsNonPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, -time.Hour} {
		if _, err := Issue(sampleClaims(), keyA, ttl); !errors.Is(err, ErrInvalidTTL) {
			t.Fatalf("Issue(ttl=%v) err = %v, want ErrInvalidTTL", ttl, err)
		}
	}
}
