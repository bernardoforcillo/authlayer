package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// The four sign-in doors and what each one owes the second factor.
//
// Every test in this file exercises ONE door. That is the point of the file:
// each door carries its own explicit check in the service (never one shared
// guard several paths reach), so removing the check from one door must fail
// exactly one of these tests and leave the others green. The mutation that
// proves it is recorded in auth/mfa_service.go's package doc, "What the
// second factor gates, door by door".

// doorFixture is an mfaFixture with all three optional ports wired —
// identities and credentials alongside the MFA store — so one fixture can
// drive every door.
func doorFixture(t *testing.T, opts ...auth.Option) (mfaFixture, *memory.IdentityStore, *memory.CredentialStore) {
	t.Helper()
	ids := memory.NewIdentityStore()
	creds := memory.NewCredentialStore()
	base := []auth.Option{
		auth.WithIdentityStore(ids),
		auth.WithCredentialStore(creds),
		auth.WithLinking(auth.LinkAlways),
	}
	return newMFAService(t, append(base, opts...)...), ids, creds
}

// wantNoSession asserts the account holds no [auth.Session] rows at all — the
// negative half of every "this door stopped short of a session" assertion. A
// challenge handed back beside a live session would be a bypass wearing a
// challenge's clothes.
func wantNoSession(t *testing.T, f mfaFixture, userID, door string) {
	t.Helper()
	sessions, err := f.store.ListSessionsByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("%s left %d session(s) behind; a door that owes a second factor must mint none", door, len(sessions))
	}
}

// --- the magic-link door ---------------------------------------------------

// TestRedeemMagicLinkOwesTheSecondFactor is the magic-link door's own check.
// A link proves control of a mailbox, and the mailbox is also this package's
// password-reset channel, so it stands in for the FIRST factor and never for
// the second: an account with a confirmed factor gets a challenge and no
// session, exactly as Login does.
func TestRedeemMagicLinkOwesTheSecondFactor(t *testing.T) {
	f, _, _ := doorFixture(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "mira@example.com")

	link, ok, err := f.svc.RequestMagicLink(ctx, "mira@example.com", "203.0.113.7")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink: ok=%v err=%v", ok, err)
	}

	res, err := f.svc.RedeemMagicLink(ctx, link, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v, want a nil error — the link was valid", err)
	}
	if res.MFA == nil {
		t.Fatal("RedeemMagicLink returned no MFA challenge for an account with a confirmed factor: a mailbox is not a second factor")
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("RedeemMagicLink handed back tokens (access=%q refresh=%q) alongside a challenge", res.AccessToken, res.RefreshToken)
	}
	wantNoSession(t, f, e.user.ID, "RedeemMagicLink")

	// And the challenge finishes the sign-in, so the door is gated rather
	// than closed. The clock steps one TOTP period first: enrolment already
	// spent the current step, and AdvanceStep refuses a replay of it.
	f.clock.advance(30 * time.Second)
	done, err := f.svc.CompleteMFA(ctx, res.MFA.Token, totpCodeAt(t, e.secret, f.clock.now()), "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("CompleteMFA after a magic link: %v", err)
	}
	if done.AccessToken == "" || done.RefreshToken == "" || done.MFA != nil {
		t.Fatalf("CompleteMFA after a magic link = %+v, want a full session", done)
	}
}

// TestRedeemMagicLinkRefusesWhenEnforcementRequiresAFactorNobodyHas is the
// other half of the same door: EnforcementRequired means every account must
// hold a confirmed factor, and a link cannot substitute for one that was
// never enrolled.
func TestRedeemMagicLinkRefusesWhenEnforcementRequiresAFactorNobodyHas(t *testing.T) {
	f, _, _ := doorFixture(t, auth.WithMFAEnforcement(auth.EnforcementRequired))
	ctx := context.Background()
	u := mustSignUp(t, f.svc, "noah@example.com", validPassword)

	link, ok, err := f.svc.RequestMagicLink(ctx, "noah@example.com", "203.0.113.7")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink: ok=%v err=%v", ok, err)
	}

	res, err := f.svc.RedeemMagicLink(ctx, link, "203.0.113.7", "agent")
	if !errors.Is(err, auth.ErrMFARequired) {
		t.Fatalf("RedeemMagicLink = %v, want ErrMFARequired", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatal("a refused RedeemMagicLink handed back tokens")
	}
	wantNoSession(t, f, u.ID, "RedeemMagicLink under EnforcementRequired")
}

// --- the external-identity door, both rungs --------------------------------

// TestSignInWithOwesTheSecondFactorOnTheSubjectRung covers the rung that
// resolves an ALREADY-linked (provider, subject) pair straight to an account.
// It is a separate check from the address rung's, and this test is what
// proves it separate.
func TestSignInWithOwesTheSecondFactorOnTheSubjectRung(t *testing.T) {
	f, _, _ := doorFixture(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "iris@example.com")

	ext := googleExt("iris@example.com", true)
	if _, err := f.svc.LinkIdentity(ctx, e.user.ID, ext); err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}

	res, err := f.svc.SignInWith(ctx, signInReq(ext))
	if err != nil {
		t.Fatalf("SignInWith: %v, want a nil error — the provider's assertion was good", err)
	}
	if res.MFA == nil {
		t.Fatal("SignInWith (subject rung) returned no MFA challenge for an account with a confirmed factor")
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("SignInWith handed back tokens (access=%q refresh=%q) alongside a challenge", res.AccessToken, res.RefreshToken)
	}
	wantNoSession(t, f, e.user.ID, "SignInWith (subject rung)")

	f.clock.advance(30 * time.Second)
	done, err := f.svc.CompleteMFA(ctx, res.MFA.Token, totpCodeAt(t, e.secret, f.clock.now()), "198.51.100.7", "oauth-agent")
	if err != nil {
		t.Fatalf("CompleteMFA after an external sign-in: %v", err)
	}
	if done.AccessToken == "" || done.MFA != nil {
		t.Fatalf("CompleteMFA after an external sign-in = %+v, want a full session", done)
	}
}

// TestSignInWithOwesTheSecondFactorOnTheAddressRung covers the OTHER rung:
// an unlinked external identity resolved onto an existing account by address.
// The link is created before the challenge is returned — see
// [auth.Service.SignInWith]'s doc — and this test pins that too, so the
// disclosure cannot drift from the behaviour.
func TestSignInWithOwesTheSecondFactorOnTheAddressRung(t *testing.T) {
	f, ids, _ := doorFixture(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "omar@example.com")

	res, err := f.svc.SignInWith(ctx, signInReq(googleExt("omar@example.com", true)))
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if res.MFA == nil {
		t.Fatal("SignInWith (address rung) returned no MFA challenge for an account with a confirmed factor")
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("SignInWith handed back tokens (access=%q refresh=%q) alongside a challenge", res.AccessToken, res.RefreshToken)
	}
	wantNoSession(t, f, e.user.ID, "SignInWith (address rung)")

	linked, err := ids.ListIdentitiesByUser(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	if len(linked) != 1 {
		t.Fatalf("identities after a challenged sign-in = %d, want 1 — the link is created before the challenge, as the doc discloses", len(linked))
	}
}

// TestSignInWithRefusesWhenEnforcementRequiresAFactorNobodyHas pins that an
// external provider's own second factor, which this package cannot see, does
// not satisfy EnforcementRequired.
func TestSignInWithRefusesWhenEnforcementRequiresAFactorNobodyHas(t *testing.T) {
	f, _, _ := doorFixture(t, auth.WithMFAEnforcement(auth.EnforcementRequired))
	ctx := context.Background()
	u := signUpVerified(t, f.svc, "petra@example.com", validPassword)

	res, err := f.svc.SignInWith(ctx, signInReq(googleExt("petra@example.com", true)))
	if !errors.Is(err, auth.ErrMFARequired) {
		t.Fatalf("SignInWith = %v, want ErrMFARequired", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatal("a refused SignInWith handed back tokens")
	}
	wantNoSession(t, f, u.ID, "SignInWith under EnforcementRequired")
}

// --- the passkey door ------------------------------------------------------

// TestFinishPasskeyLoginSatisfiesTheSecondFactor is the door that is decided
// the OTHER way, and the test exists to keep that decision deliberate: a
// passkey is a possession credential bound to hardware and scoped to the
// account by this package, so it IS a second factor rather than a way past
// one. An account with a confirmed TOTP factor signs in outright.
func TestFinishPasskeyLoginSatisfiesTheSecondFactor(t *testing.T) {
	f, _, _ := doorFixture(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "quinn@example.com")
	cred := registerPasskey(t, f.svc, e.user.ID, newCred(1))

	res, err := f.svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		CredentialID: cred.CredentialID,
		Challenge:    mustBeginLogin(t, f.svc),
	}, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("FinishPasskeyLogin: %v", err)
	}
	if res.MFA != nil {
		t.Fatal("FinishPasskeyLogin returned an MFA challenge; a passkey satisfies the second factor — update auth/mfa_service.go's door-by-door section with whatever it does instead")
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("FinishPasskeyLogin minted no session for an account with a confirmed factor")
	}
}

// TestFinishPasskeyLoginIsNotRefusedUnderEnforcementRequired is the same
// decision seen from the enforcement side: a passkey-only account is not told
// to go and enrol a TOTP factor, because it already holds a second factor.
func TestFinishPasskeyLoginIsNotRefusedUnderEnforcementRequired(t *testing.T) {
	f, _, _ := doorFixture(t, auth.WithMFAEnforcement(auth.EnforcementRequired))
	ctx := context.Background()
	u := mustSignUp(t, f.svc, "rafa@example.com", validPassword)
	cred := registerPasskey(t, f.svc, u.ID, newCred(2))

	res, err := f.svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		CredentialID: cred.CredentialID,
		Challenge:    mustBeginLogin(t, f.svc),
	}, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("FinishPasskeyLogin under EnforcementRequired = %v, want a session — the passkey IS the factor", err)
	}
	if res.AccessToken == "" {
		t.Fatal("FinishPasskeyLogin under EnforcementRequired minted no session")
	}
}
