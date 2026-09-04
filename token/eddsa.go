package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// eddsaSigner is [EdDSA]'s and [EdDSAVerifier]'s implementation. kid and
// priv are the signing key — priv is nil on a verifier, which is what makes
// its Issue refuse — and keys is every public key Parse accepts, the signing
// key's included, addressed by the "kid" a token's header must carry. order
// is kids in the sequence PublicKeySet lists them: the signing key first,
// then the verifiers sorted, so the JWKS is deterministic.
type eddsaSigner struct {
	kid   string
	priv  ed25519.PrivateKey
	keys  map[string]ed25519.PublicKey
	order []string
}

// EdDSA returns an Ed25519 [Signer]. kid names the signing key: it is
// written into every issued token's header and is the "kid" of the first
// entry of [PublicKeySetter.PublicKeySet]. verifiers are ADDITIONAL public
// keys, by kid, accepted on Parse and listed in the JWKS — the rotation
// story: generate the new pair, construct with the new key signing and the
// old public key among the verifiers, deploy, and drop the old key once
// every token it signed has expired. verifiers may be nil.
//
// Parse REQUIRES a "kid" header that names a key this Signer holds; a token
// with no kid, or with one it does not know, is [ErrUnknownKey]. That check
// comes after the alg check and before any signature verification, so a
// token for a retired or foreign key costs no Ed25519 operation and the
// signature is only ever checked against the ONE key the token names,
// never tried against every key in turn.
//
// Construction refuses, with [ErrInvalidKey]: an empty kid; a priv that is
// not [ed25519.PrivateKeySize] bytes; a verifier with an empty kid or a
// public key that is not [ed25519.PublicKeySize] bytes; and a verifier
// registered under the signing kid with a DIFFERENT public key, which
// would leave the kid ambiguous. A verifier under the signing kid with the
// SAME public key is accepted and de-duplicated. Every key is copied.
//
// # When to reach for this instead of HS256
//
// HS256 is the right choice when the party that issues a token is the only
// party that verifies it — one application holding one secret. The moment
// anyone ELSE must verify — another service, an agent, an MCP client, a
// gateway — HS256 means sharing the signing secret with them, and a
// verifier holding the secret can mint. EdDSA separates the two: the
// private key stays with the issuer, and verifiers hold only the public
// half, published as a JWKS (see [PublicKeySetter]) and loaded with
// [EdDSAVerifier]. The [Signer] interface is identical either way, so an
// application built on HS256 moves by changing one constructor.
func EdDSA(kid string, priv ed25519.PrivateKey, verifiers map[string]ed25519.PublicKey) (Signer, error) {
	if kid == "" {
		return nil, fmt.Errorf("%w: signing kid must not be empty", ErrInvalidKey)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key is %d bytes, want %d", ErrInvalidKey, len(priv), ed25519.PrivateKeySize)
	}
	held := append(ed25519.PrivateKey(nil), priv...)
	pub, ok := held.Public().(ed25519.PublicKey)
	if !ok {
		// ed25519.PrivateKey.Public always returns an ed25519.PublicKey;
		// this branch exists so the assertion above can never panic.
		return nil, fmt.Errorf("%w: Ed25519 private key did not yield a public key", ErrInvalidKey)
	}
	s := &eddsaSigner{
		kid:   kid,
		priv:  held,
		keys:  map[string]ed25519.PublicKey{kid: pub},
		order: []string{kid},
	}
	if err := s.addVerifiers(verifiers); err != nil {
		return nil, err
	}
	return s, nil
}

// EdDSAVerifier returns a verify-only [Signer] over the public keys in
// verifiers, by kid — what a party that is NOT the issuer constructs, from
// the JWKS the issuer publishes ([JWKS.PublicKeys] turns one into this
// argument). Its Parse behaves exactly as [EdDSA]'s, including
// [ErrUnknownKey] for a token naming a kid it does not hold; its Alg is
// [AlgEdDSA]; and its Issue always fails with [ErrInvalidKey], because a
// verifier holds no private key and can sign nothing — that refusal is the
// property a verifier is chosen for, not a limitation.
//
// It refuses, with [ErrInvalidKey], an empty verifiers, a verifier with an
// empty kid, and a public key that is not [ed25519.PublicKeySize] bytes.
// The keys are copied. It does not implement [PublicKeySetter]: a verifier
// re-publishing the issuer's keys as its own would misstate who holds the
// private half.
func EdDSAVerifier(verifiers map[string]ed25519.PublicKey) (Signer, error) {
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("%w: a verifier needs at least one public key, got none", ErrInvalidKey)
	}
	s := &eddsaSigner{keys: make(map[string]ed25519.PublicKey, len(verifiers))}
	if err := s.addVerifiers(verifiers); err != nil {
		return nil, err
	}
	return &eddsaVerifier{keys: s}, nil
}

// addVerifiers registers verifiers on s, validating each and keeping order
// deterministic (sorted by kid, after whatever s.order already holds).
func (s *eddsaSigner) addVerifiers(verifiers map[string]ed25519.PublicKey) error {
	kids := make([]string, 0, len(verifiers))
	for kid := range verifiers {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		pub := verifiers[kid]
		if kid == "" {
			return fmt.Errorf("%w: verifier kid must not be empty", ErrInvalidKey)
		}
		if len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: verifier %q public key is %d bytes, want %d", ErrInvalidKey, kid, len(pub), ed25519.PublicKeySize)
		}
		if existing, dup := s.keys[kid]; dup {
			if !existing.Equal(pub) {
				return fmt.Errorf("%w: kid %q is registered twice with different public keys", ErrInvalidKey, kid)
			}
			continue
		}
		s.keys[kid] = append(ed25519.PublicKey(nil), pub...)
		s.order = append(s.order, kid)
	}
	return nil
}

// Issue implements [Signer]: an Ed25519 signature over the JWS signing
// input, with the signing kid in the header. IssuedAt and ExpiresAt are set
// from now and ttl exactly as [Issue] sets them; ttl <= 0 is
// [ErrInvalidTTL].
func (s *eddsaSigner) Issue(c Claims, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("%w: got %s", ErrInvalidTTL, ttl)
	}

	now := time.Now()
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(ttl).Unix()

	headerJSON, err := json.Marshal(jwtHeader{Alg: AlgEdDSA, Typ: "JWT", Kid: s.kid})
	if err != nil {
		return "", fmt.Errorf("authlayer/token: marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("authlayer/token: marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := ed25519.Sign(s.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Parse implements [Signer]. The ladder, in order, each rung a distinct
// sentinel: segment count and header decoding ([ErrMalformedToken]); the
// header's "alg" equal to exactly "EdDSA" ([ErrUnsupportedAlgorithm] — a
// token that says HS256, "none", or anything else is refused here, before
// the kid is even read); a "kid" naming a held key ([ErrUnknownKey]); a
// signature that is [ed25519.SignatureSize] bytes and verifies under THAT
// key ([ErrInvalidSignature] — a 32-byte HMAC computed with the public key
// bytes, the classic confusion, fails on length alone); payload decoding
// ([ErrMalformedToken]); expiry ([ErrExpiredToken], only after the
// signature verified, for the reason [Parse] gives).
//
// Segments are decoded with strict base64 exactly as [Parse] decodes them,
// so one token has exactly one valid encoding here too.
func (s *eddsaSigner) Parse(raw string) (Claims, error) {
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

	// The one check that matters, and it is the same check [Parse] makes
	// with the other literal: this Signer accepts exactly one algorithm.
	if h.Alg != AlgEdDSA {
		return Claims{}, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, h.Alg)
	}

	// The key is the one the token NAMES, or nothing — never "try them all".
	pub, ok := s.keys[h.Kid]
	if !ok {
		return Claims{}, fmt.Errorf("%w: %q", ErrUnknownKey, h.Kid)
	}

	sig, err := base64.RawURLEncoding.Strict().DecodeString(sigPart)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature is not valid base64: %v", ErrMalformedToken, err)
	}
	// ed25519.Verify itself returns false for a wrong-length signature;
	// the explicit check is so the reason is legible at the one place a
	// key-confusion forgery lands (an HMAC is 32 bytes, an Ed25519
	// signature 64).
	if len(sig) != ed25519.SignatureSize {
		return Claims{}, ErrInvalidSignature
	}
	if !ed25519.Verify(pub, []byte(headerPart+"."+payloadPart), sig) {
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

// Alg implements [Signer]: always [AlgEdDSA].
func (s *eddsaSigner) Alg() string { return AlgEdDSA }

// PublicKeySet implements [PublicKeySetter]: the signing key first, then
// every verifier sorted by kid.
func (s *eddsaSigner) PublicKeySet() JWKS {
	set := JWKS{Keys: make([]JWK, 0, len(s.order))}
	for _, kid := range s.order {
		set.Keys = append(set.Keys, JWK{
			Kty: jwkKtyOKP,
			Crv: jwkCrvEd25519,
			Kid: kid,
			Use: jwkUseSig,
			Alg: AlgEdDSA,
			X:   base64.RawURLEncoding.EncodeToString(s.keys[kid]),
		})
	}
	return set
}

// eddsaVerifier is [EdDSAVerifier]'s type: an eddsaSigner with no private
// key, whose Issue refuses and which deliberately does not expose
// PublicKeySet — see EdDSAVerifier's doc for both. It holds the signer as a
// named field rather than embedding it, so PublicKeySet is not promoted.
type eddsaVerifier struct {
	keys *eddsaSigner
}

// Issue implements [Signer] by refusing: a verifier holds no private key.
func (v *eddsaVerifier) Issue(Claims, time.Duration) (string, error) {
	return "", fmt.Errorf("%w: an EdDSA verifier holds no private key and cannot issue", ErrInvalidKey)
}

// Parse implements [Signer] exactly as [EdDSA]'s Parse does.
func (v *eddsaVerifier) Parse(raw string) (Claims, error) { return v.keys.Parse(raw) }

// Alg implements [Signer]: always [AlgEdDSA].
func (v *eddsaVerifier) Alg() string { return AlgEdDSA }

// PublicKeySetter is implemented by a [Signer] that holds public key
// material worth publishing — today only the concrete type [EdDSA]
// returns. An HS256 signer has no public half, so the method is not on the
// [Signer] interface; reach it through an assertion:
//
//	if pks, ok := signer.(token.PublicKeySetter); ok {
//		json.NewEncoder(w).Encode(pks.PublicKeySet()) // your JWKS endpoint
//	}
//
// [EdDSAVerifier]'s Signer does not implement it either, deliberately: the
// keys it holds are somebody else's to publish.
type PublicKeySetter interface {
	// PublicKeySet is the RFC 7517 JWK Set describing every key this
	// Signer accepts on Parse: the signing key first, then the verifiers.
	PublicKeySet() JWKS
}

// The RFC 7517 / RFC 8037 field values this package writes into a [JWK].
// They are the only values [JWKS.PublicKeys] accepts back.
const (
	jwkKtyOKP     = "OKP"
	jwkCrvEd25519 = "Ed25519"
	jwkUseSig     = "sig"
)

// JWK is one RFC 7517 JSON Web Key as this package publishes it: an RFC
// 8037 Octet Key Pair on Ed25519, for signature use. It is a plain struct
// with JSON tags; serving it is the application's job, exactly as every
// other document in this module is — no handler is provided.
type JWK struct {
	// Kty is the key type: always "OKP" (RFC 8037 §2).
	Kty string `json:"kty"`
	// Crv is the curve: always "Ed25519" (RFC 8037 §3.1).
	Crv string `json:"crv"`
	// Kid is the key id a token's header "kid" names — the one [EdDSA] was
	// constructed with, or a verifier's.
	Kid string `json:"kid"`
	// Use is the public key use: always "sig" (RFC 7517 §4.2).
	Use string `json:"use"`
	// Alg is the algorithm the key is for: always "EdDSA" (RFC 8037 §3.1).
	Alg string `json:"alg"`
	// X is the 32-byte public key, base64url-encoded without padding (RFC
	// 8037 §2, RFC 7515 §2).
	X string `json:"x"`
}

// JWKS is an RFC 7517 §5 JWK Set: the document an issuer publishes so a
// verifier that is not the issuer can check its tokens. [PublicKeySetter]
// produces one; [JWKS.PublicKeys] consumes one.
type JWKS struct {
	// Keys is every key the issuer currently accepts. Order is the signing
	// key first, then verifiers sorted by kid, when this package built it;
	// a consumer must not depend on order.
	Keys []JWK `json:"keys"`
}

// PublicKeys decodes the set into the map [EdDSAVerifier] takes, keyed by
// kid. It accepts only what this package publishes — kty "OKP", crv
// "Ed25519", alg "EdDSA" or empty, use "sig" or empty, a non-empty kid, and
// an x that decodes to exactly [ed25519.PublicKeySize] bytes — and refuses
// anything else with [ErrInvalidKey] rather than skipping it: a verifier
// that silently dropped a key it did not understand would then refuse
// every token signed under it with [ErrUnknownKey], and nothing would say
// why. A kid appearing twice with different keys is refused for the same
// reason [EdDSA] refuses it.
func (s JWKS) PublicKeys() (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(s.Keys))
	for i, k := range s.Keys {
		switch {
		case k.Kty != jwkKtyOKP:
			return nil, fmt.Errorf("%w: key %d: kty %q, want %q", ErrInvalidKey, i, k.Kty, jwkKtyOKP)
		case k.Crv != jwkCrvEd25519:
			return nil, fmt.Errorf("%w: key %d: crv %q, want %q", ErrInvalidKey, i, k.Crv, jwkCrvEd25519)
		case k.Alg != "" && k.Alg != AlgEdDSA:
			return nil, fmt.Errorf("%w: key %d: alg %q, want %q", ErrInvalidKey, i, k.Alg, AlgEdDSA)
		case k.Use != "" && k.Use != jwkUseSig:
			return nil, fmt.Errorf("%w: key %d: use %q, want %q", ErrInvalidKey, i, k.Use, jwkUseSig)
		case k.Kid == "":
			return nil, fmt.Errorf("%w: key %d: kid must not be empty", ErrInvalidKey, i)
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("%w: key %d (%q): x is not valid base64url: %v", ErrInvalidKey, i, k.Kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: key %d (%q): x is %d bytes, want %d", ErrInvalidKey, i, k.Kid, len(raw), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(raw)
		if existing, dup := keys[k.Kid]; dup && !existing.Equal(pub) {
			return nil, fmt.Errorf("%w: kid %q appears twice with different public keys", ErrInvalidKey, k.Kid)
		}
		keys[k.Kid] = pub
	}
	return keys, nil
}
