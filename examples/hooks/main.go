// Command hooks is a runnable, database-free tour of two additions to the
// auth package: lifecycle hooks, and signing access tokens with EdDSA instead
// of HS256 so a party that is not the issuer can verify them.
//
//	go run ./examples/hooks
//
// It runs against store/memory, so there is no database and no setup, and it
// prints a trace of every lifecycle event the Service emits while a user
// signs up, fails a login, signs in, refreshes, replays a stolen token, and
// signs out — followed by the JWKS an application would serve and a second,
// verify-only party checking a token against it.
//
// # What is deliberately NOT here
//
// A transport, an audit database, and a real key store. The hook here prints;
// yours writes an audit row, enqueues a webhook, or drops a cache key — and
// returns nil for all of them, because a hook error aborts the call it
// observes with the store change already in place. The Ed25519 private key is
// generated on the spot; in production it comes from wherever your secrets
// live, and the JWKS is served from a URL your verifiers are configured with.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

const demoPassword = "Correct-Horse-Battery-9!"

// kindNames turns an EventKind into something readable for the trace. The
// constants are an iota block, so this mirrors their declaration order; a
// real audit sink would store the integer and keep its own mapping.
var kindNames = map[auth.EventKind]string{
	auth.SignedUp: "SignedUp", auth.EmailVerified: "EmailVerified", auth.LoggedIn: "LoggedIn",
	auth.LoginFailed: "LoginFailed", auth.MFAChallenged: "MFAChallenged", auth.SessionRefreshed: "SessionRefreshed",
	auth.TokenReuseDetected: "TokenReuseDetected", auth.LoggedOut: "LoggedOut", auth.LoggedOutAll: "LoggedOutAll",
	auth.SessionRevoked: "SessionRevoked", auth.PasswordChanged: "PasswordChanged", auth.PasswordReset: "PasswordReset",
	auth.EmailChanged: "EmailChanged", auth.MagicLinkRedeemed: "MagicLinkRedeemed", auth.IdentityLinked: "IdentityLinked",
	auth.IdentityUnlinked: "IdentityUnlinked", auth.MFAEnrolled: "MFAEnrolled", auth.MFADisabled: "MFADisabled",
	auth.PasskeyRegistered: "PasskeyRegistered", auth.PasskeyDeleted: "PasskeyDeleted", auth.DeviceTrusted: "DeviceTrusted",
	auth.TrustedDeviceRevoked: "TrustedDeviceRevoked", auth.AccountDeleted: "AccountDeleted", auth.AccountAnonymized: "AccountAnonymized",
}

func main() {
	ctx := context.Background()

	// -- 1. An EdDSA signer, and the hook -----------------------------------
	//
	// HS256 needs every verifier to hold the signing secret, which makes
	// every verifier an issuer. EdDSA keeps the private key here and hands
	// verifiers only the public half — the right shape as soon as anything
	// that is not this service must check a token: another service, an
	// agent, an MCP client, a gateway. kid names this key in every token's
	// header and in the JWKS, so a rotation is "construct with the new key
	// signing and the old public key as a verifier".
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	signer, err := token.EdDSA("2026-09", priv, nil)
	must(err)

	// The hook: every lifecycle event, printed. Note what is NOT on an
	// event: the attempted email address. A failed login for an unknown
	// address says unknown_user and nothing else, so an audit log built from
	// these cannot become a list of which addresses exist.
	trace := auth.HookFunc(func(_ context.Context, e auth.Event) error {
		fmt.Printf("  event %-19s user=%-8s session=%-8s ip=%-12s detail=%s\n",
			kindNames[e.Kind], short(e.UserID), short(e.SessionID), e.IP, e.Detail)
		return nil // best-effort: never fail the mutation because the log did
	})

	svc := auth.New(memory.NewAuthStore(),
		auth.WithSigner(signer),            // instead of WithJWT
		auth.WithAccessTTL(15*time.Minute), // the TTL WithJWT would have set
		auth.WithHooks(trace))

	// -- 2. Sign up, verify, fail a login, log in ----------------------------
	step("sign up and verify")
	signup, err := svc.SignUp(ctx, "alice@example.com", demoPassword)
	must(err)
	_, err = svc.VerifyEmail(ctx, signup.VerifyToken)
	must(err)

	// A second SignUp for the same address emits NOTHING — not a
	// SignedUp, not a "duplicate" — because that branch is
	// enumeration-hardened and a hook is a caller-visible side effect.
	dup, err := svc.SignUp(ctx, "alice@example.com", demoPassword)
	must(err)
	fmt.Printf("  duplicate sign-up: created=%v, and no event above it\n", dup.Created)

	step("a wrong password, then an unknown address")
	if _, err := svc.Login(ctx, "alice@example.com", "not-her-password", "203.0.113.9", "demo"); !errors.Is(err, auth.ErrInvalidCredentials) {
		panic(fmt.Sprintf("want ErrInvalidCredentials, got %v", err))
	}
	if _, err := svc.Login(ctx, "nobody@example.com", demoPassword, "203.0.113.9", "demo"); !errors.Is(err, auth.ErrInvalidCredentials) {
		panic(fmt.Sprintf("want ErrInvalidCredentials, got %v", err))
	}
	fmt.Println("  both refusals are the same ErrInvalidCredentials; the hook saw which was which, and never the address")

	step("log in")
	login, err := svc.Login(ctx, "alice@example.com", demoPassword, "203.0.113.9", "demo")
	must(err)

	// -- 3. The token is EdDSA: the service verifies it, HS256 refuses it ---
	step("verify the access token")
	claims, err := svc.VerifyAccessToken(login.AccessToken)
	must(err)
	fmt.Printf("  alg=%s  sub=%s  sid=%s\n", svc.Signer().Alg(), short(claims.Subject), short(claims.SessionID))
	_, err = token.Parse(login.AccessToken, []byte("32-bytes-or-more-from-your-vault"))
	fmt.Printf("  the HS256 path refuses it before any signature check: %v\n", errors.Is(err, token.ErrUnsupportedAlgorithm))

	// -- 4. Refresh, then replay the old token -------------------------------
	step("refresh, then replay")
	next, err := svc.Refresh(ctx, login.RefreshToken)
	must(err)
	if _, err := svc.Refresh(ctx, login.RefreshToken); !errors.Is(err, auth.ErrTokenReuse) {
		panic(fmt.Sprintf("want ErrTokenReuse, got %v", err))
	}
	fmt.Println("  the replay revoked the whole family; TokenReuseDetected fired after the revocation, not before")

	step("log in again and log out")
	again, err := svc.Login(ctx, "alice@example.com", demoPassword, "203.0.113.9", "demo")
	must(err)
	must(svc.Logout(ctx, again.RefreshToken))

	// -- 5. The JWKS, and a verifier that is not the issuer -----------------
	//
	// This is the document an application serves at its jwks_uri. HS256 has
	// nothing to publish, so the method is not on the Signer interface;
	// reach it through the assertion.
	step("publish the JWKS")
	pks, ok := svc.Signer().(token.PublicKeySetter)
	if !ok {
		panic("an EdDSA signer must implement PublicKeySetter")
	}
	jwks, err := json.MarshalIndent(pks.PublicKeySet(), "  ", "  ")
	must(err)
	fmt.Printf("  %s\n", jwks)

	// The other party — a service, an agent, an MCP client — fetches that
	// document, builds a verify-only Signer from it, and checks tokens
	// without ever holding anything it could sign with.
	step("verify as another party")
	var fetched token.JWKS
	must(json.Unmarshal(jwks, &fetched))
	keys, err := fetched.PublicKeys()
	must(err)
	verifier, err := token.EdDSAVerifier(keys)
	must(err)
	verified, err := verifier.Parse(next.AccessToken)
	must(err)
	fmt.Printf("  verifier accepted the token for sub=%s\n", short(verified.Subject))
	_, err = verifier.Issue(token.Claims{Subject: "forged"}, time.Minute)
	fmt.Printf("  verifier cannot issue: %v\n", errors.Is(err, token.ErrInvalidKey))

	fmt.Println("\ndone")
}

func step(label string) {
	fmt.Printf("\n== %s ==\n", strings.ToUpper(label))
}

// short truncates an id for display — the LAST eight characters, because the
// ids are UUIDv7 and share a time-ordered prefix that would make every one
// look the same. Never do this to a value you are comparing — only to one
// you are printing.
func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[len(s)-8:]
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
