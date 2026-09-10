package token

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// craftEdDSA assembles a token with an arbitrary header, signed with priv
// directly through crypto/ed25519 rather than through the package, so tests
// can hand the signer headers its own Issue would never write.
func craftEdDSA(t *testing.T, headerJSON string, claims Claims, priv ed25519.PrivateKey) string {
	t.Helper()
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := rawURL([]byte(headerJSON)) + "." + rawURL(payloadJSON)
	return signingInput + "." + rawURL(ed25519.Sign(priv, []byte(signingInput)))
}

// liveClaims is sampleClaims with an ExpiresAt an hour out, for tokens
// crafted around Issue (which would otherwise carry the zero exp and be
// expired on arrival).
func liveClaims() Claims {
	c := sampleClaims()
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = time.Now().Add(time.Hour).Unix()
	return c
}

// pubOf returns priv's public key.
func pubOf(t *testing.T, priv ed25519.PrivateKey) ed25519.PublicKey {
	t.Helper()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("private key did not yield an ed25519.PublicKey")
	}
	return pub
}

// Issue then Parse round-trips the claims, sets iat/exp from the ttl, and
// writes the kid into the header.
func TestEdDSAIssueParseRoundTrip(t *testing.T) {
	s, _ := newEdDSA(t, "2026-09", nil)
	if got := s.Alg(); got != AlgEdDSA || AlgEdDSA != "EdDSA" {
		t.Fatalf("Alg() = %q, want EdDSA", got)
	}

	before := time.Now()
	raw, err := s.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	after := time.Now()

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if want := `{"alg":"EdDSA","typ":"JWT","kid":"2026-09"}`; string(headerJSON) != want {
		t.Fatalf("header = %s, want %s", headerJSON, want)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	got, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Subject != "user-123" || got.SessionID != "session-456" || got.Email != "alice@example.com" {
		t.Fatalf("Parse claims = %+v, want the issued subject/session/email", got)
	}
	if got.IssuedAt < before.Unix() || got.IssuedAt > after.Unix() {
		t.Fatalf("IssuedAt = %d, want within [%d, %d]", got.IssuedAt, before.Unix(), after.Unix())
	}
	if got.ExpiresAt < before.Add(time.Hour).Unix() || got.ExpiresAt > after.Add(time.Hour).Unix() {
		t.Fatalf("ExpiresAt = %d, want issued-at + 1h", got.ExpiresAt)
	}
}

// The kid is REQUIRED and must name a held key: a token with no kid, or with
// a kid the signer has never heard of, is ErrUnknownKey — even when the
// signature under it would have verified against a key the signer holds.
func TestEdDSAParseRequiresKnownKid(t *testing.T) {
	s, priv := newEdDSA(t, "k1", nil)

	noKid := craftEdDSA(t, `{"alg":"EdDSA","typ":"JWT"}`, sampleClaims(), priv)
	if _, err := s.Parse(noKid); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Parse(no kid) = %v, want ErrUnknownKey", err)
	}
	unknown := craftEdDSA(t, `{"alg":"EdDSA","typ":"JWT","kid":"k9"}`, sampleClaims(), priv)
	if _, err := s.Parse(unknown); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Parse(unknown kid) = %v, want ErrUnknownKey", err)
	}
	// Right kid, same key, live claims: the control.
	known := craftEdDSA(t, `{"alg":"EdDSA","typ":"JWT","kid":"k1"}`, liveClaims(), priv)
	if _, err := s.Parse(known); err != nil {
		t.Fatalf("Parse(known kid) = %v, want nil", err)
	}
}

// The alg check runs BEFORE the kid check: a token that says HS256 with an
// unknown kid is ErrUnsupportedAlgorithm, not ErrUnknownKey, so an attacker
// cannot use the kid error to learn which algorithm a verifier speaks.
func TestEdDSAAlgCheckPrecedesKidCheck(t *testing.T) {
	s, priv := newEdDSA(t, "k1", nil)
	raw := craftEdDSA(t, `{"alg":"HS256","typ":"JWT","kid":"nope"}`, sampleClaims(), priv)
	if _, err := s.Parse(raw); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Parse(alg=HS256, unknown kid) = %v, want ErrUnsupportedAlgorithm", err)
	}
	lower := craftEdDSA(t, `{"alg":"eddsa","typ":"JWT","kid":"k1"}`, sampleClaims(), priv)
	if _, err := s.Parse(lower); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Parse(alg=eddsa) = %v, want ErrUnsupportedAlgorithm (exact match required)", err)
	}
}

// The classic confusion: a header that says EdDSA, a known kid, and a
// signature that is an HMAC-SHA256 computed with the PUBLIC key bytes as the
// secret. A verifier that let the header pick the algorithm and then used
// "the key it has" would accept this. Ours must refuse it as an invalid
// signature — and must never have tried HMAC at all.
func TestEdDSARefusesHMACWithPublicKeyBytes(t *testing.T) {
	s, priv := newEdDSA(t, "k1", nil)
	pub := pubOf(t, priv)

	payloadJSON, err := json.Marshal(sampleClaims())
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := rawURL([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"k1"}`)) + "." + rawURL(payloadJSON)
	mac := hmac.New(sha256.New, pub)
	mac.Write([]byte(signingInput))
	forged := signingInput + "." + rawURL(mac.Sum(nil))

	if _, err := s.Parse(forged); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Parse(HMAC-with-public-key forgery) = %v, want ErrInvalidSignature", err)
	}

	// The same forgery padded out to 64 bytes must fail too — the length
	// check is a legibility aid, not the defence.
	padded := signingInput + "." + rawURL(append(mac.Sum(nil), mac.Sum(nil)...))
	if _, err := s.Parse(padded); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Parse(64-byte HMAC forgery) = %v, want ErrInvalidSignature", err)
	}
}

// A token signed by a DIFFERENT private key under a kid the signer knows
// must fail signature verification, and a tampered payload must too.
func TestEdDSARejectsWrongKeyAndTamperedPayload(t *testing.T) {
	s, _ := newEdDSA(t, "k1", nil)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrongKey := craftEdDSA(t, `{"alg":"EdDSA","typ":"JWT","kid":"k1"}`, sampleClaims(), other)
	if _, err := s.Parse(wrongKey); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Parse(signed by another key) = %v, want ErrInvalidSignature", err)
	}

	raw, err := s.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.Split(raw, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	c.Subject = "someone-else"
	tampered, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parts[1] = rawURL(tampered)
	if _, err := s.Parse(strings.Join(parts, ".")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Parse(tampered payload) = %v, want ErrInvalidSignature", err)
	}
}

// Malformed inputs are ErrMalformedToken, and expiry is checked only after
// the signature verifies.
func TestEdDSAMalformedAndExpired(t *testing.T) {
	s, priv := newEdDSA(t, "k1", nil)
	for _, raw := range []string{"", "one", "two.segments", "a.b.c.d", "not!base64.x.y"} {
		if _, err := s.Parse(raw); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("Parse(%q) = %v, want ErrMalformedToken", raw, err)
		}
	}
	nonJSONHeader := rawURL([]byte("not-json")) + "." + rawURL([]byte(`{}`)) + "." + rawURL([]byte("sig"))
	if _, err := s.Parse(nonJSONHeader); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("Parse(non-JSON header) = %v, want ErrMalformedToken", err)
	}

	c := sampleClaims()
	c.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()
	c.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	expired := craftEdDSA(t, `{"alg":"EdDSA","typ":"JWT","kid":"k1"}`, c, priv)
	if _, err := s.Parse(expired); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("Parse(expired) = %v, want ErrExpiredToken", err)
	}

	// Non-canonical base64 in the signature segment is malformed, as at Parse.
	raw, err := s.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.Split(raw, ".")
	sigPart := parts[2]
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	canonical, _ := base64.RawURLEncoding.DecodeString(sigPart)
	siblings := 0
	for _, ch := range alphabet {
		if byte(ch) == sigPart[len(sigPart)-1] {
			continue
		}
		candidate := sigPart[:len(sigPart)-1] + string(ch)
		decoded, err := base64.RawURLEncoding.DecodeString(candidate)
		if err != nil || string(decoded) != string(canonical) {
			continue
		}
		siblings++
		if _, err := s.Parse(parts[0] + "." + parts[1] + "." + candidate); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("Parse(non-canonical signature) = %v, want ErrMalformedToken", err)
		}
	}
	if siblings == 0 {
		t.Fatal("no non-canonical siblings found — the strict-decode requirement was not exercised")
	}
}

// Key rotation through verifiers: a token signed under a retired key, whose
// public half is listed as a verifier, still parses; a fresh token names the
// new kid; and dropping the retired key from the verifiers makes its tokens
// ErrUnknownKey.
func TestEdDSARotationViaVerifiers(t *testing.T) {
	old, oldPriv := newEdDSA(t, "2026-01", nil)
	oldTok, err := old.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("old.Issue: %v", err)
	}

	rotated, _ := newEdDSA(t, "2026-09", map[string]ed25519.PublicKey{"2026-01": pubOf(t, oldPriv)})
	if _, err := rotated.Parse(oldTok); err != nil {
		t.Fatalf("rotated.Parse(token under retired key) = %v, want nil", err)
	}
	newTok, err := rotated.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("rotated.Issue: %v", err)
	}
	header, _ := base64.RawURLEncoding.DecodeString(strings.Split(newTok, ".")[0])
	if !strings.Contains(string(header), `"kid":"2026-09"`) {
		t.Fatalf("new token header = %s, want kid 2026-09", header)
	}
	// The retired signer never learned the new key.
	if _, err := old.Parse(newTok); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("old.Parse(token under new key) = %v, want ErrUnknownKey", err)
	}

	// Retirement complete: the verifier is dropped and its tokens are gone.
	final, _ := newEdDSA(t, "2026-09", nil)
	if _, err := final.Parse(oldTok); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("final.Parse(token under dropped key) = %v, want ErrUnknownKey", err)
	}
}

// Construction refuses unusable material with ErrInvalidKey.
func TestEdDSARefusesBadKeyMaterial(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := pubOf(t, priv)

	cases := map[string]func() (Signer, error){
		"empty kid":               func() (Signer, error) { return EdDSA("", priv, nil) },
		"nil private key":         func() (Signer, error) { return EdDSA("k", nil, nil) },
		"short private key":       func() (Signer, error) { return EdDSA("k", priv[:32], nil) },
		"verifier with empty kid": func() (Signer, error) { return EdDSA("k", priv, map[string]ed25519.PublicKey{"": pub}) },
		"verifier short key":      func() (Signer, error) { return EdDSA("k", priv, map[string]ed25519.PublicKey{"v": pub[:16]}) },
		"verifier under signing kid, different key": func() (Signer, error) {
			return EdDSA("k", priv, map[string]ed25519.PublicKey{"k": pubOf(t, other)})
		},
		"empty verifier set":         func() (Signer, error) { return EdDSAVerifier(nil) },
		"verifier-only with bad key": func() (Signer, error) { return EdDSAVerifier(map[string]ed25519.PublicKey{"k": pub[:5]}) },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := build()
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("err = %v, want ErrInvalidKey", err)
			}
			if s != nil {
				t.Fatal("returned a non-nil Signer alongside the error")
			}
		})
	}

	// The same public key under the signing kid is not a conflict.
	if _, err := EdDSA("k", priv, map[string]ed25519.PublicKey{"k": pub}); err != nil {
		t.Fatalf("EdDSA with a verifier equal to the signing key = %v, want nil", err)
	}
}

// The JWKS has the RFC 7517 / RFC 8037 shape, lists the signing key first
// and verifiers sorted by kid, and round-trips through PublicKeys into a
// verifier that accepts the issuer's tokens.
func TestEdDSAPublicKeySetShapeAndRoundTrip(t *testing.T) {
	_, vB, _ := ed25519.GenerateKey(rand.Reader)
	_, vA, _ := ed25519.GenerateKey(rand.Reader)
	s, priv := newEdDSA(t, "signing", map[string]ed25519.PublicKey{
		"b-old": pubOf(t, vB),
		"a-old": pubOf(t, vA),
	})

	pks, ok := s.(PublicKeySetter)
	if !ok {
		t.Fatal("EdDSA signer does not implement PublicKeySetter")
	}
	set := pks.PublicKeySet()
	if len(set.Keys) != 3 {
		t.Fatalf("JWKS has %d keys, want 3", len(set.Keys))
	}
	if set.Keys[0].Kid != "signing" || set.Keys[1].Kid != "a-old" || set.Keys[2].Kid != "b-old" {
		t.Fatalf("JWKS kid order = %q, %q, %q; want signing, a-old, b-old", set.Keys[0].Kid, set.Keys[1].Kid, set.Keys[2].Kid)
	}
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Use != "sig" || k.Alg != "EdDSA" {
			t.Fatalf("JWK %q = %+v, want kty OKP, crv Ed25519, use sig, alg EdDSA", k.Kid, k)
		}
	}
	if set.Keys[0].X != base64.RawURLEncoding.EncodeToString(pubOf(t, priv)) {
		t.Fatalf("JWKS x for the signing key = %q, want base64url of the public key", set.Keys[0].X)
	}

	// The wire shape, pinned exactly.
	out, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	want := `{"keys":[` +
		`{"kty":"OKP","crv":"Ed25519","kid":"signing","use":"sig","alg":"EdDSA","x":"` + set.Keys[0].X + `"},` +
		`{"kty":"OKP","crv":"Ed25519","kid":"a-old","use":"sig","alg":"EdDSA","x":"` + set.Keys[1].X + `"},` +
		`{"kty":"OKP","crv":"Ed25519","kid":"b-old","use":"sig","alg":"EdDSA","x":"` + set.Keys[2].X + `"}]}`
	if string(out) != want {
		t.Fatalf("JWKS JSON =\n%s\nwant\n%s", out, want)
	}

	// A verifier built from the published document — as another service
	// would build it — accepts the issuer's tokens and cannot issue.
	var fetched JWKS
	if err := json.Unmarshal(out, &fetched); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	keys, err := fetched.PublicKeys()
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	verifier, err := EdDSAVerifier(keys)
	if err != nil {
		t.Fatalf("EdDSAVerifier: %v", err)
	}
	if verifier.Alg() != AlgEdDSA {
		t.Fatalf("verifier.Alg() = %q, want EdDSA", verifier.Alg())
	}
	tok, err := s.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := verifier.Parse(tok); err != nil {
		t.Fatalf("verifier.Parse(issuer token) = %v, want nil", err)
	}
	if _, err := verifier.Issue(sampleClaims(), time.Hour); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("verifier.Issue = %v, want ErrInvalidKey (a verifier holds no private key)", err)
	}
	if _, isSetter := verifier.(PublicKeySetter); isSetter {
		t.Fatal("a verifier must not implement PublicKeySetter — the keys are not its to publish")
	}
	// And an HS256 signer has nothing to publish.
	hs, _ := HS256(keyA)
	if _, isSetter := hs.(PublicKeySetter); isSetter {
		t.Fatal("an HS256 signer must not implement PublicKeySetter")
	}
}

// PublicKeys refuses a document it does not fully understand rather than
// silently dropping the key it did not.
func TestJWKSPublicKeysRefusesForeignShapes(t *testing.T) {
	good := JWK{Kty: "OKP", Crv: "Ed25519", Kid: "k", Use: "sig", Alg: "EdDSA",
		X: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))}
	mutate := func(f func(*JWK)) JWKS {
		k := good
		f(&k)
		return JWKS{Keys: []JWK{k}}
	}
	cases := map[string]JWKS{
		"rsa kty":       mutate(func(k *JWK) { k.Kty = "RSA" }),
		"other curve":   mutate(func(k *JWK) { k.Crv = "X25519" }),
		"other alg":     mutate(func(k *JWK) { k.Alg = "RS256" }),
		"enc use":       mutate(func(k *JWK) { k.Use = "enc" }),
		"empty kid":     mutate(func(k *JWK) { k.Kid = "" }),
		"bad base64":    mutate(func(k *JWK) { k.X = "not*base64" }),
		"short x":       mutate(func(k *JWK) { k.X = "AAAA" }),
		"duplicate kid": {Keys: []JWK{good, mutate(func(k *JWK) { k.X = base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...)) }).Keys[0]}},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := set.PublicKeys(); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("PublicKeys(%s) = %v, want ErrInvalidKey", name, err)
			}
		})
	}
	// Empty alg and use are the RFC's optional fields and are accepted.
	if _, err := mutate(func(k *JWK) { k.Alg, k.Use = "", "" }).PublicKeys(); err != nil {
		t.Fatalf("PublicKeys with alg/use omitted = %v, want nil", err)
	}
}
