package token

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"
)

// newEdDSA generates a fresh key pair and returns a signer over it plus the
// private key, for tests that need to sign independently of the package.
func newEdDSA(t *testing.T, kid string, verifiers map[string]ed25519.PublicKey) (Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := EdDSA(kid, priv, verifiers)
	if err != nil {
		t.Fatalf("EdDSA: %v", err)
	}
	return s, priv
}

// HS256 must report its algorithm and round-trip claims through the released
// free functions: a token it issues is one Parse accepts with the same key,
// and vice versa, because it is the same code path.
func TestHS256SignerMatchesTheFreeFunctions(t *testing.T) {
	s, err := HS256(keyA)
	if err != nil {
		t.Fatalf("HS256: %v", err)
	}
	if got := s.Alg(); got != AlgHS256 || AlgHS256 != "HS256" {
		t.Fatalf("Alg() = %q, want HS256", got)
	}

	raw, err := s.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	viaFree, err := Parse(raw, keyA)
	if err != nil {
		t.Fatalf("Parse(signer token): %v", err)
	}
	viaSigner, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("signer.Parse: %v", err)
	}
	if !reflect.DeepEqual(viaFree, viaSigner) || viaSigner.Subject != "user-123" {
		t.Fatalf("claims differ between Parse and signer.Parse: %+v vs %+v", viaFree, viaSigner)
	}

	fromFree, err := Issue(sampleClaims(), keyA, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Parse(fromFree); err != nil {
		t.Fatalf("signer.Parse(free-function token) = %v, want nil", err)
	}
}

// keys[0] signs; every key verifies. This is the rotation convention the
// free functions document, carried onto the Signer.
func TestHS256SignerRotation(t *testing.T) {
	old, err := HS256(keyB)
	if err != nil {
		t.Fatalf("HS256(old): %v", err)
	}
	raw, err := old.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	rotated, err := HS256(keyA, keyB)
	if err != nil {
		t.Fatalf("HS256(rotated): %v", err)
	}
	if _, err := rotated.Parse(raw); err != nil {
		t.Fatalf("rotated.Parse(token under retired key) = %v, want nil", err)
	}

	fresh, err := rotated.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Signed with keyA (keys[0]), so a signer holding only keyB refuses it.
	if _, err := old.Parse(fresh); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("old.Parse(token under new key) = %v, want ErrInvalidSignature", err)
	}
}

// HS256 refuses at construction what Issue and Parse refuse per call, and
// with the same sentinel: no keys, and any short key anywhere in the list.
func TestHS256RefusesNoKeysAndShortKeys(t *testing.T) {
	short := bytes.Repeat([]byte("x"), 31)
	cases := map[string][][]byte{
		"no keys":          nil,
		"nil key":          {nil},
		"short key alone":  {short},
		"short key second": {keyA, short},
		"short key first":  {short, keyA},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := HS256(keys...)
			if !errors.Is(err, ErrKeyTooShort) {
				t.Fatalf("HS256(%s) err = %v, want ErrKeyTooShort", name, err)
			}
			if s != nil {
				t.Fatalf("HS256(%s) returned a non-nil Signer alongside the error", name)
			}
		})
	}
}

// A caller mutating its key slice after construction must not change what
// the Signer signs with — the keys are copied.
func TestHS256CopiesKeys(t *testing.T) {
	mine := append([]byte(nil), keyA...)
	s, err := HS256(mine)
	if err != nil {
		t.Fatalf("HS256: %v", err)
	}
	raw, err := s.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for i := range mine {
		mine[i] = 'Z'
	}
	if _, err := s.Parse(raw); err != nil {
		t.Fatalf("Parse after caller mutated its slice = %v, want nil (keys must be copied)", err)
	}
}

// Each Signer accepts exactly ONE alg and refuses the other's tokens with
// ErrUnsupportedAlgorithm — in both directions. This is the property the
// package doc's "Two signers, still one algorithm each" section rests on.
func TestSignersRefuseEachOthersAlgorithm(t *testing.T) {
	hs, err := HS256(keyA)
	if err != nil {
		t.Fatalf("HS256: %v", err)
	}
	ed, _ := newEdDSA(t, "k1", nil)

	hsTok, err := hs.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("hs.Issue: %v", err)
	}
	edTok, err := ed.Issue(sampleClaims(), time.Hour)
	if err != nil {
		t.Fatalf("ed.Issue: %v", err)
	}

	if _, err := ed.Parse(hsTok); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("EdDSA.Parse(HS256 token) = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := hs.Parse(edTok); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("HS256.Parse(EdDSA token) = %v, want ErrUnsupportedAlgorithm", err)
	}
	// And the released free function, which IS the HS256 path, agrees.
	if _, err := Parse(edTok, keyA); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Parse(EdDSA token) = %v, want ErrUnsupportedAlgorithm", err)
	}

	// Each accepts its own.
	if _, err := hs.Parse(hsTok); err != nil {
		t.Fatalf("HS256.Parse(own token) = %v", err)
	}
	if _, err := ed.Parse(edTok); err != nil {
		t.Fatalf("EdDSA.Parse(own token) = %v", err)
	}
}

// Both signers must refuse "none" — the package's founding property — and
// must refuse a non-positive ttl at Issue.
func TestSignersRefuseAlgNoneAndBadTTL(t *testing.T) {
	hs, err := HS256(keyA)
	if err != nil {
		t.Fatalf("HS256: %v", err)
	}
	ed, _ := newEdDSA(t, "k1", nil)

	none := craftToken(t, `{"alg":"none","typ":"JWT","kid":"k1"}`, sampleClaims(), keyA)
	for name, s := range map[string]Signer{"HS256": hs, "EdDSA": ed} {
		if _, err := s.Parse(none); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("%s.Parse(alg=none) = %v, want ErrUnsupportedAlgorithm", name, err)
		}
		for _, ttl := range []time.Duration{0, -time.Second} {
			if _, err := s.Issue(sampleClaims(), ttl); !errors.Is(err, ErrInvalidTTL) {
				t.Fatalf("%s.Issue(ttl=%v) = %v, want ErrInvalidTTL", name, ttl, err)
			}
		}
	}
}
