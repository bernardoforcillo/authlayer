package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// newEdDSASigner generates a fresh Ed25519 pair and returns a signer over it.
func newEdDSASigner(t *testing.T, kid string) token.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := token.EdDSA(kid, priv, nil)
	if err != nil {
		t.Fatalf("EdDSA: %v", err)
	}
	return s
}

// TestWithSignerEdDSAMintsTokensTheServiceVerifiesAndHS256Rejects pins the
// contract for WithSigner: a Service configured with an EdDSA signer mints
// access tokens its own VerifyAccessToken accepts, and the released HS256
// path — token.Parse — refuses them with ErrUnsupportedAlgorithm rather than
// with a signature failure, because it never gets as far as a signature.
func TestWithSignerEdDSAMintsTokensTheServiceVerifiesAndHS256Rejects(t *testing.T) {
	signer := newEdDSASigner(t, "2026-09")
	svc := auth.New(memory.NewAuthStore(),
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithSigner(signer),
	)
	ctx := context.Background()
	user := mustSignUp(t, svc, "ed@example.com", validPassword)

	login, err := svc.Login(ctx, "ed@example.com", validPassword, "1.2.3.4", "agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	claims, err := svc.VerifyAccessToken(login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken(own EdDSA token): %v", err)
	}
	if claims.Subject != user.ID || claims.Email != "ed@example.com" || claims.SessionID == "" {
		t.Fatalf("claims = %+v, want sub/email/sid from the login", claims)
	}

	// The HS256 path refuses it on alg alone.
	if _, err := token.Parse(login.AccessToken, testSigningKey); !errors.Is(err, token.ErrUnsupportedAlgorithm) {
		t.Fatalf("token.Parse(EdDSA token) = %v, want token.ErrUnsupportedAlgorithm", err)
	}
	// And so does a Service configured with WithJWT.
	hs, _ := newTestService(t)
	if _, err := hs.VerifyAccessToken(login.AccessToken); !errors.Is(err, token.ErrUnsupportedAlgorithm) {
		t.Fatalf("HS256 Service.VerifyAccessToken(EdDSA token) = %v, want token.ErrUnsupportedAlgorithm", err)
	}

	// Refresh mints through the same signer.
	next, err := svc.Refresh(ctx, login.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := svc.VerifyAccessToken(next.AccessToken); err != nil {
		t.Fatalf("VerifyAccessToken(refreshed EdDSA token): %v", err)
	}

	// A verifier built from the published JWKS — another service, an agent —
	// accepts the token too, and it is the whole point of choosing EdDSA.
	pks, ok := svc.Signer().(token.PublicKeySetter)
	if !ok {
		t.Fatal("Signer() did not expose a PublicKeySetter for an EdDSA signer")
	}
	keys, err := pks.PublicKeySet().PublicKeys()
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	verifier, err := token.EdDSAVerifier(keys)
	if err != nil {
		t.Fatalf("EdDSAVerifier: %v", err)
	}
	if _, err := verifier.Parse(next.AccessToken); err != nil {
		t.Fatalf("verifier.Parse = %v, want nil", err)
	}
}

// TestSignerReturnsWhatWasConfigured pins Signer(): the exact value
// WithSigner was given, the HS256 signer WithJWT built, nil when neither was
// called, and the last of the two options winning.
func TestSignerReturnsWhatWasConfigured(t *testing.T) {
	ed := newEdDSASigner(t, "k")

	if got := auth.New(memory.NewAuthStore(), auth.WithSigner(ed)).Signer(); got != ed {
		t.Fatalf("Signer() = %v, want the exact Signer passed to WithSigner", got)
	}

	hs := auth.New(memory.NewAuthStore(), auth.WithJWT([][]byte{testSigningKey}, time.Minute)).Signer()
	if hs == nil || hs.Alg() != token.AlgHS256 {
		t.Fatalf("Signer() after WithJWT = %v, want an HS256 signer", hs)
	}

	if got := auth.New(memory.NewAuthStore()).Signer(); got != nil {
		t.Fatalf("Signer() with no option = %v, want nil", got)
	}
	if got := auth.New(memory.NewAuthStore(), auth.WithSigner(nil)).Signer(); got != nil {
		t.Fatalf("Signer() after WithSigner(nil) = %v, want nil (a nil signer is ignored)", got)
	}

	// Last option wins, in both orders.
	lastEd := auth.New(memory.NewAuthStore(),
		auth.WithJWT([][]byte{testSigningKey}, time.Minute), auth.WithSigner(ed)).Signer()
	if lastEd != ed {
		t.Fatalf("WithJWT then WithSigner: Signer() = %v, want the EdDSA signer", lastEd)
	}
	lastHS := auth.New(memory.NewAuthStore(),
		auth.WithSigner(ed), auth.WithJWT([][]byte{testSigningKey}, time.Minute)).Signer()
	if lastHS == nil || lastHS.Alg() != token.AlgHS256 {
		t.Fatalf("WithSigner then WithJWT: Signer() = %v, want an HS256 signer", lastHS)
	}
	// A WithJWT that is ignored (short key) does not clobber a prior signer.
	kept := auth.New(memory.NewAuthStore(),
		auth.WithSigner(ed), auth.WithJWT([][]byte{[]byte("short")}, time.Minute)).Signer()
	if kept != ed {
		t.Fatalf("WithSigner then an unusable WithJWT: Signer() = %v, want the EdDSA signer kept", kept)
	}
}

// TestWithAccessTTLBoundsTheAccessToken pins that WithAccessTTL sets the
// lifetime an EdDSA deployment has no WithJWT to set through, and that a
// non-positive value is ignored.
func TestWithAccessTTLBoundsTheAccessToken(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	svc := auth.New(memory.NewAuthStore(),
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithSigner(newEdDSASigner(t, "k")),
		auth.WithAccessTTL(2*time.Hour),
		auth.WithClock(func() time.Time { return fixed }),
	)
	mustSignUp(t, svc, "ttl@example.com", validPassword)
	login, err := svc.Login(ctx, "ttl@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	claims, err := svc.VerifyAccessToken(login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	// Issue stamps from the wall clock, not the Service clock, so compare
	// the span rather than the absolute values.
	if span := claims.ExpiresAt - claims.IssuedAt; span != int64((2 * time.Hour).Seconds()) {
		t.Fatalf("exp-iat = %ds, want 7200 (WithAccessTTL)", span)
	}

	// Ignored: zero and negative.
	def := auth.New(memory.NewAuthStore(),
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithSigner(newEdDSASigner(t, "k")),
		auth.WithAccessTTL(0), auth.WithAccessTTL(-time.Minute),
	)
	mustSignUp(t, def, "def@example.com", validPassword)
	l2, err := def.Login(ctx, "def@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	c2, err := def.VerifyAccessToken(l2.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if span := c2.ExpiresAt - c2.IssuedAt; span != int64((15 * time.Minute).Seconds()) {
		t.Fatalf("exp-iat = %ds, want 900 (default kept after WithAccessTTL(0))", span)
	}
}

// TestEdDSAServiceWithUnknownKidFailsClosed pins that a token an EdDSA
// Service does not hold the key for — here one minted by a different key
// pair under a kid this Service never learned — is ErrUnknownKey, one of the
// token package's own sentinels handed back unwrapped.
func TestEdDSAServiceWithUnknownKidFailsClosed(t *testing.T) {
	ctx := context.Background()
	a := auth.New(memory.NewAuthStore(),
		auth.WithHasher(password.Bcrypt(testCost)), auth.WithSigner(newEdDSASigner(t, "a")))
	b := auth.New(memory.NewAuthStore(),
		auth.WithHasher(password.Bcrypt(testCost)), auth.WithSigner(newEdDSASigner(t, "b")))
	mustSignUp(t, a, "a@example.com", validPassword)
	login, err := a.Login(ctx, "a@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := b.VerifyAccessToken(login.AccessToken); !errors.Is(err, token.ErrUnknownKey) {
		t.Fatalf("VerifyAccessToken(token under a kid this Service lacks) = %v, want token.ErrUnknownKey", err)
	}
}
