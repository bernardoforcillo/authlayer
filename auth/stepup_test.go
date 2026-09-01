package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Step-up: what auth.Service.RequireFreshMFA refuses, what it deliberately
// does not, and the five methods that call it.
//
// Each of those five calls it on its own line rather than through a guard
// they share, so removing any one call fails exactly one test below. The two
// mutations the plan requires are recorded in auth/stepup.go's own doc.

// sessionIDOf reads the session id out of an access token, which is the
// pairing an application uses too — see auth.Service.VerifyAccessToken.
func sessionIDOf(t *testing.T, svc *auth.Service, accessToken string) string {
	t.Helper()
	claims, err := svc.VerifyAccessToken(accessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.SessionID == "" {
		t.Fatal("access token carries no session id")
	}
	return claims.SessionID
}

// steppedUp is one account with a confirmed factor and two of its sessions:
// one minted BEFORE enrolment, which has therefore never proved a factor,
// and one minted by [auth.Service.CompleteMFA], which just did.
type steppedUp struct {
	enrolled
	fresh string // session id, stamped at the fixture clock's current instant
	stale string // session id, MFAAt nil — a session older than the enrolment
}

// enrolWithSessions builds that account. The stale session is real rather
// than contrived: a user who enrols a second factor from a browser they are
// already signed into is left holding exactly one.
func enrolWithSessions(t *testing.T, f mfaFixture, email string) steppedUp {
	t.Helper()
	ctx := context.Background()

	u := mustSignUp(t, f.svc, email, validPassword)

	// Before enrolment there is no factor, so this is an ordinary login.
	before, err := f.svc.Login(ctx, email, validPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login before enrolment: %v", err)
	}
	if before.MFA != nil {
		t.Fatal("Login before enrolment owed a second factor")
	}
	stale := sessionIDOf(t, f.svc, before.AccessToken)

	secret, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}
	codes, err := f.svc.ConfirmMFAEnrolment(ctx, u.ID, totpCodeAt(t, secret, f.clock.now()))
	if err != nil {
		t.Fatalf("ConfirmMFAEnrolment: %v", err)
	}

	// One TOTP period on, so the code below is not the one enrolment spent.
	f.clock.advance(30 * time.Second)
	pending := loginOwingMFA(t, f, email)
	done, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, totpCodeAt(t, secret, f.clock.now()), "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}

	return steppedUp{
		enrolled: enrolled{user: u, secret: secret, recovery: codes},
		fresh:    sessionIDOf(t, f.svc, done.AccessToken),
		stale:    stale,
	}
}

// freshSessionFor signs an already-enrolled account in through the FULL
// second-factor exchange and returns the id of the session that produced —
// one [auth.Session.MFAAt] has just stamped. It advances the fixture clock
// one TOTP period first, because the code enrolment (or the previous login)
// spent is refused as a replay.
//
// The step-up gate on DisableMFA and the two deletion postures means a test
// that wants those methods to SUCCEED needs one of these, which is exactly
// the position an application is in.
func freshSessionFor(t *testing.T, f mfaFixture, e enrolled, email string) string {
	t.Helper()
	f.clock.advance(30 * time.Second)
	pending := loginOwingMFA(t, f, email)
	done, err := f.svc.CompleteMFA(context.Background(), pending.MFA.Token,
		totpCodeAt(t, e.secret, f.clock.now()), "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("CompleteMFA(%q): %v", email, err)
	}
	return sessionIDOf(t, f.svc, done.AccessToken)
}

// --- the refusal that must not exist ---------------------------------------

// TestRequireFreshMFAIsANoOpForAnAccountWithNoConfirmedFactor is the single
// most important test in this task, and it was written before the feature.
//
// An account with no second factor CANNOT step up: there is nothing it could
// present. If RequireFreshMFA refused such a session, enabling step-up would
// lock every non-MFA user out of changing their own password, with a refusal
// they have no way to satisfy — a self-inflicted denial of service on the
// majority of a typical deployment's users.
func TestRequireFreshMFAIsANoOpForAnAccountWithNoConfirmedFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	mustSignUp(t, f.svc, "ada@example.com", validPassword)
	res, err := f.svc.Login(ctx, "ada@example.com", validPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	sid := sessionIDOf(t, f.svc, res.AccessToken)

	if err := f.svc.RequireFreshMFA(ctx, res.User.ID, sid); err != nil {
		t.Fatalf("RequireFreshMFA on an account with no factor = %v, want nil — such an account cannot step up, so refusing it is an unsatisfiable lockout", err)
	}

	// And the sensitive method it guards still works, which is the failure
	// a user would actually meet.
	if err := f.svc.ChangePassword(ctx, res.User.ID, sid, validPassword, "Another-Good-Password-2!"); err != nil {
		t.Fatalf("ChangePassword for an account with no factor = %v, want nil", err)
	}
}

// TestRequireFreshMFAIsANoOpForAnUnconfirmedFactor extends the same rule one
// step: an abandoned enrolment gates nothing anywhere else in this package
// (see auth/mfa_service.go), and it must gate nothing here either.
func TestRequireFreshMFAIsANoOpForAnUnconfirmedFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	u := mustSignUp(t, f.svc, "bram@example.com", validPassword)
	if _, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID); err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}
	res, err := f.svc.Login(ctx, "bram@example.com", validPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := f.svc.RequireFreshMFA(ctx, u.ID, sessionIDOf(t, f.svc, res.AccessToken)); err != nil {
		t.Fatalf("RequireFreshMFA with an UNCONFIRMED factor = %v, want nil", err)
	}
}

// TestRequireFreshMFAIsANoOpWithoutAnMFAStore pins the third no-op: a
// deployment with no [auth.WithMFAStore] holds no factors at all, so no
// account in it can step up.
func TestRequireFreshMFAIsANoOpWithoutAnMFAStore(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	u := mustSignUp(t, svc, "cleo@example.com", validPassword)
	res, err := svc.Login(ctx, "cleo@example.com", validPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := svc.RequireFreshMFA(ctx, u.ID, sessionIDOf(t, svc, res.AccessToken)); err != nil {
		t.Fatalf("RequireFreshMFA with no MFAStore = %v, want nil", err)
	}
}

// --- freshness is a time, not a flag ---------------------------------------

// TestRequireFreshMFARefusesASessionThatNeverProvedAFactor covers the nil
// stamp. The session predates the enrolment, so nobody ever presented a code
// for it.
//
// Mutation anchor (a): let RequireFreshMFA accept a nil MFAAt and this test
// must fail.
func TestRequireFreshMFARefusesASessionThatNeverProvedAFactor(t *testing.T) {
	f := newMFAService(t)
	acct := enrolWithSessions(t, f, "dara@example.com")

	err := f.svc.RequireFreshMFA(context.Background(), acct.user.ID, acct.stale)
	if !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("RequireFreshMFA on a session that never completed MFA = %v, want ErrStepUpRequired", err)
	}
}

// TestRequireFreshMFAAcceptsASessionStampedInsideTheWindow is the positive
// case, checked at both ends of the window: immediately, and one second
// before it closes.
func TestRequireFreshMFAAcceptsASessionStampedInsideTheWindow(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "elif@example.com")

	if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, acct.fresh); err != nil {
		t.Fatalf("RequireFreshMFA immediately after CompleteMFA = %v, want nil", err)
	}

	f.clock.advance(15*time.Minute - time.Second)
	if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, acct.fresh); err != nil {
		t.Fatalf("RequireFreshMFA one second inside the default window = %v, want nil", err)
	}
}

// TestRequireFreshMFARefusesASessionStampedOutsideTheWindow is the reason
// freshness is a TIME. A session that proved a factor long enough ago has
// proved nothing about who is holding it now.
//
// Mutation anchor (b): remove the window comparison so any stamp passes, and
// this test must fail.
func TestRequireFreshMFARefusesASessionStampedOutsideTheWindow(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "fumi@example.com")

	// Exactly at the boundary: the window is half-open, so the stamp is
	// stale the instant it turns fifteen minutes old.
	f.clock.advance(15 * time.Minute)
	if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, acct.fresh); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("RequireFreshMFA at exactly the window's edge = %v, want ErrStepUpRequired", err)
	}

	f.clock.advance(24 * time.Hour)
	if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, acct.fresh); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("RequireFreshMFA a day later = %v, want ErrStepUpRequired", err)
	}
}

// TestWithStepUpWindowConfiguresTheWindow proves the option is read rather
// than the default being hard-coded at the comparison.
func TestWithStepUpWindowConfiguresTheWindow(t *testing.T) {
	f := newMFAService(t, auth.WithStepUpWindow(time.Hour))
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "gita@example.com")

	f.clock.advance(59 * time.Minute)
	if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, acct.fresh); err != nil {
		t.Fatalf("RequireFreshMFA 59 minutes into a one-hour window = %v, want nil", err)
	}
	f.clock.advance(2 * time.Minute)
	if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, acct.fresh); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("RequireFreshMFA past a one-hour window = %v, want ErrStepUpRequired", err)
	}
}

// TestWithStepUpWindowZeroDisablesStepUp pins the opt-out: a deployment that
// does not want step-up gets the behaviour it had before this feature, for
// an account with a confirmed factor and a session that never proved one.
func TestWithStepUpWindowZeroDisablesStepUp(t *testing.T) {
	f := newMFAService(t, auth.WithStepUpWindow(0))
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "hana@example.com")

	if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, acct.stale); err != nil {
		t.Fatalf("RequireFreshMFA with WithStepUpWindow(0) = %v, want nil — the check is off", err)
	}
	if err := f.svc.ChangePassword(ctx, acct.user.ID, acct.stale, validPassword, "Another-Good-Password-2!"); err != nil {
		t.Fatalf("ChangePassword with step-up disabled = %v, want nil", err)
	}
}

// TestRequireFreshMFARefusesAFreshSessionBelongingToAnotherAccount is why
// this method takes a userID as well as a session id. Without that pairing,
// anyone who could freshly step up their OWN account would hold a session id
// that satisfies the check for SOMEBODY ELSE's — and every caller of this
// method passes a session id it received from the request it is serving.
func TestRequireFreshMFARefusesAFreshSessionBelongingToAnotherAccount(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	attacker := enrolWithSessions(t, f, "ivan@example.com")
	victim := enrolWithSessions(t, f, "juno@example.com")

	if err := f.svc.RequireFreshMFA(ctx, attacker.user.ID, attacker.fresh); err != nil {
		t.Fatalf("the attacker's own fresh session = %v, want nil (fixture check)", err)
	}
	err := f.svc.RequireFreshMFA(ctx, victim.user.ID, attacker.fresh)
	if !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("RequireFreshMFA(victim, attacker's fresh session) = %v, want ErrStepUpRequired", err)
	}
}

// TestRequireFreshMFARefusesASessionIDNobodyHolds covers the fail-closed
// default the sweep-matrix methods rely on: an empty or unknown id is a
// refusal, never a pass.
func TestRequireFreshMFARefusesASessionIDNobodyHolds(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "kian@example.com")

	for _, sid := range []string{"", "no-such-session-id"} {
		if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, sid); !errors.Is(err, auth.ErrStepUpRequired) {
			t.Fatalf("RequireFreshMFA(%q) = %v, want ErrStepUpRequired", sid, err)
		}
	}
}

// --- what stamps the session -----------------------------------------------

// TestCompleteMFAStampsTheSession pins the stamp itself, read off the stored
// row rather than inferred from a later refusal.
func TestCompleteMFAStampsTheSession(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "lena@example.com")

	sessions, err := f.store.ListSessionsByUser(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	var fresh, stale *auth.Session
	for i := range sessions {
		switch sessions[i].ID {
		case acct.fresh:
			fresh = &sessions[i]
		case acct.stale:
			stale = &sessions[i]
		}
	}
	if fresh == nil || stale == nil {
		t.Fatalf("expected both fixture sessions in the store, got %d rows", len(sessions))
	}
	if fresh.MFAAt == nil {
		t.Fatal("Session.MFAAt is nil on the session CompleteMFA minted; that is what freshness is read from")
	}
	if !fresh.MFAAt.Equal(f.clock.now()) {
		t.Fatalf("Session.MFAAt = %v, want the instant the factor was proven (%v)", fresh.MFAAt, f.clock.now())
	}
	if stale.MFAAt != nil {
		t.Fatalf("Session.MFAAt = %v on a session minted by an ordinary login, want nil", stale.MFAAt)
	}
}

// TestFinishPasskeyLoginStampsFreshness ties Task 0's passkey decision to
// this one. A passkey IS the second factor, so a session it mints has proved
// one — and without this stamp an account holding both a passkey and a TOTP
// factor could sign in by passkey and never satisfy step-up again.
func TestFinishPasskeyLoginStampsFreshness(t *testing.T) {
	creds := memory.NewCredentialStore()
	f := newMFAService(t, auth.WithCredentialStore(creds))
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "milo@example.com")

	// acct.fresh is the session CompleteMFA minted, which is what the newly
	// step-up-gated FinishPasskeyRegistration requires of an account holding
	// a confirmed factor.
	cred := registerPasskeyFrom(t, f.svc, acct.user.ID, acct.fresh, newCred(3))
	res, err := f.svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		CredentialID: cred.CredentialID,
		Challenge:    mustBeginLogin(t, f.svc),
	}, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("FinishPasskeyLogin: %v", err)
	}

	if err := f.svc.RequireFreshMFA(ctx, acct.user.ID, sessionIDOf(t, f.svc, res.AccessToken)); err != nil {
		t.Fatalf("RequireFreshMFA on a session a passkey minted = %v, want nil", err)
	}
}

// TestRefreshCarriesTheFreshnessStampForward pins the rotation rule: a
// successor inherits its predecessor's stamp, exactly as it inherits
// FamilyID, IP and UserAgent. A rotation is not a re-authentication, so it
// neither proves a factor nor un-proves one — the stamp keeps its original
// time and keeps ageing.
func TestRefreshCarriesTheFreshnessStampForward(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	u := mustSignUp(t, f.svc, "nero@example.com", validPassword)

	secret, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}
	if _, err := f.svc.ConfirmMFAEnrolment(ctx, u.ID, totpCodeAt(t, secret, f.clock.now())); err != nil {
		t.Fatalf("ConfirmMFAEnrolment: %v", err)
	}
	f.clock.advance(30 * time.Second)
	pending := loginOwingMFA(t, f, "nero@example.com")
	stampedAt := f.clock.now()
	done, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, totpCodeAt(t, secret, stampedAt), "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}

	f.clock.advance(time.Minute)
	rotated, err := f.svc.Refresh(ctx, done.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	successor := sessionIDOf(t, f.svc, rotated.AccessToken)
	if err := f.svc.RequireFreshMFA(ctx, u.ID, successor); err != nil {
		t.Fatalf("RequireFreshMFA on a rotated session = %v, want nil — a rotation is not a new authentication, but it is not a de-authentication either", err)
	}

	// The stamp did not move forward with the rotation: it still ages out
	// fifteen minutes after the factor was actually proven.
	f.clock.advance(15*time.Minute - time.Minute)
	if err := f.svc.RequireFreshMFA(ctx, u.ID, successor); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("RequireFreshMFA fifteen minutes after the FACTOR = %v, want ErrStepUpRequired — a refresh must not renew freshness", err)
	}
}

// --- the five sensitive methods, one test each -----------------------------

// TestChangePasswordRequiresAFreshSecondFactor: the password is not enough
// on its own for an account that holds a second factor.
func TestChangePasswordRequiresAFreshSecondFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "otto@example.com")
	const next = "Another-Good-Password-2!"

	if err := f.svc.ChangePassword(ctx, acct.user.ID, acct.stale, validPassword, next); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("ChangePassword from a stale session = %v, want ErrStepUpRequired", err)
	}
	// Nothing was written: the old password still authenticates.
	if _, err := f.svc.Login(ctx, "otto@example.com", validPassword, "203.0.113.7", "agent"); err != nil {
		t.Fatalf("the old password stopped working after a refused ChangePassword: %v", err)
	}

	// The credential check still comes FIRST: a caller who does not know
	// the password is told that, not which second factor to present.
	if err := f.svc.ChangePassword(ctx, acct.user.ID, acct.stale, "not-the-password-9!", next); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("ChangePassword with a wrong password = %v, want ErrInvalidCredentials", err)
	}

	if err := f.svc.ChangePassword(ctx, acct.user.ID, acct.fresh, validPassword, next); err != nil {
		t.Fatalf("ChangePassword from a freshly stepped-up session = %v, want nil", err)
	}
}

// TestRequestEmailChangeRequiresAFreshSecondFactor: arming an identifier
// rotation is the same kind of act as rotating the password.
func TestRequestEmailChangeRequiresAFreshSecondFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "pia@example.com")

	if _, err := f.svc.RequestEmailChange(ctx, acct.user.ID, acct.stale, validPassword, "pia-new@example.com"); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("RequestEmailChange from a stale session = %v, want ErrStepUpRequired", err)
	}
	tok, err := f.svc.RequestEmailChange(ctx, acct.user.ID, acct.fresh, validPassword, "pia-new@example.com")
	if err != nil {
		t.Fatalf("RequestEmailChange from a fresh session = %v, want nil", err)
	}
	if tok == "" {
		t.Fatal("RequestEmailChange returned an empty token")
	}
}

// TestDeleteAccountRequiresAFreshSecondFactor: the account is still there
// afterwards, which is the assertion that matters for an irreversible call.
func TestDeleteAccountRequiresAFreshSecondFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "raul@example.com")

	if err := f.svc.DeleteAccount(ctx, acct.user.ID, acct.stale, validPassword); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("DeleteAccount from a stale session = %v, want ErrStepUpRequired", err)
	}
	if _, err := f.svc.User(ctx, acct.user.ID); err != nil {
		t.Fatalf("the account is gone after a refused DeleteAccount: %v", err)
	}

	if err := f.svc.DeleteAccount(ctx, acct.user.ID, acct.fresh, validPassword); err != nil {
		t.Fatalf("DeleteAccount from a freshly stepped-up session = %v, want nil", err)
	}
}

// TestAnonymizeAccountRequiresAFreshSecondFactor: the soft posture, gated on
// its own line rather than by anything DeleteAccount does.
func TestAnonymizeAccountRequiresAFreshSecondFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "sena@example.com")

	if err := f.svc.AnonymizeAccount(ctx, acct.user.ID, acct.stale, validPassword); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("AnonymizeAccount from a stale session = %v, want ErrStepUpRequired", err)
	}
	still, err := f.svc.User(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("User after a refused AnonymizeAccount: %v", err)
	}
	if still.DeletedAt != nil {
		t.Fatal("the account was stamped anyway by a refused AnonymizeAccount")
	}

	if err := f.svc.AnonymizeAccount(ctx, acct.user.ID, acct.fresh, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount from a freshly stepped-up session = %v, want nil", err)
	}
}

// TestDisableMFARequiresAFreshSecondFactor is the one whose absence would be
// most obviously wrong: turning the second factor off is the single most
// valuable action for whoever holds a stolen session.
func TestDisableMFARequiresAFreshSecondFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "tomas@example.com")

	if err := f.svc.DisableMFA(ctx, acct.user.ID, acct.stale, validPassword); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("DisableMFA from a stale session = %v, want ErrStepUpRequired", err)
	}
	// The factor survived: the login still owes one.
	loginOwingMFA(t, f, "tomas@example.com")

	if err := f.svc.DisableMFA(ctx, acct.user.ID, acct.fresh, validPassword); err != nil {
		t.Fatalf("DisableMFA from a freshly stepped-up session = %v, want nil", err)
	}
}

// TestARecoveryCodeCanStepUp closes the lockout question DisableMFA's gate
// raises: a user who has lost their authenticator must still be able to turn
// the factor off, and a recovery code is how. It is a second factor, so the
// session it mints is stamped like any other.
func TestARecoveryCodeCanStepUp(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	acct := enrolWithSessions(t, f, "uma@example.com")

	f.clock.advance(time.Hour) // the fresh session is long stale by now
	pending := loginOwingMFA(t, f, "uma@example.com")
	done, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, acct.recovery[0], "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("CompleteMFA with a recovery code: %v", err)
	}
	if err := f.svc.DisableMFA(ctx, acct.user.ID, sessionIDOf(t, f.svc, done.AccessToken), validPassword); err != nil {
		t.Fatalf("DisableMFA after a recovery-code login = %v, want nil — otherwise losing a phone is a permanent lockout", err)
	}
}

// --- the sixth and seventh gates -------------------------------------------

// TestFinishPasskeyRegistrationRequiresAFreshSecondFactor pins the gate Task
// 3 added, and it is a step-up BYPASS that is being closed rather than a
// policy being tightened: a passkey is a sign-in credential, and
// [auth.Service.FinishPasskeyLogin] stamps [auth.Session.MFAAt] on the
// session it mints, so an ungated registration lets a stale session mint
// itself a fresh one.
//
// It also pins the ORDER: the refusal happens before the challenge is
// claimed, so a refused registration does not cost the user the ceremony
// they are in the middle of.
func TestFinishPasskeyRegistrationRequiresAFreshSecondFactor(t *testing.T) {
	creds := memory.NewCredentialStore()
	f := newMFAService(t, auth.WithCredentialStore(creds))
	ctx := context.Background()

	acct := enrolWithSessions(t, f, "petra@example.com")

	challenge, err := f.svc.BeginPasskeyRegistration(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	cred := newCred(7)
	cred.Challenge = challenge

	// acct.stale is a real session minted before the factor was enrolled —
	// exactly what a thief holds.
	if _, err := f.svc.FinishPasskeyRegistration(ctx, acct.user.ID, acct.stale, cred); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("FinishPasskeyRegistration from a session that never proved a factor = %v, want ErrStepUpRequired", err)
	}
	if rows, err := creds.ListCredentialsByUser(ctx, acct.user.ID); err != nil || len(rows) != 0 {
		t.Fatalf("the refused registration stored %v (%v), want nothing", rows, err)
	}

	// The SAME challenge still works from a stepped-up session: the refusal
	// ran before the claim, so the ceremony survived it.
	if _, err := f.svc.FinishPasskeyRegistration(ctx, acct.user.ID, acct.fresh, cred); err != nil {
		t.Fatalf("FinishPasskeyRegistration from a fresh session = %v, want nil — a refusal must not burn the ceremony", err)
	}
}

// TestFinishPasskeyRegistrationIsUngatedForAnAccountWithNoFactor is the other
// half, and the one that decides whether the gate is shippable: an account
// with no confirmed factor cannot step up, so registering a FIRST passkey
// must be exactly as easy as it was before this gate existed.
func TestFinishPasskeyRegistrationIsUngatedForAnAccountWithNoFactor(t *testing.T) {
	creds := memory.NewCredentialStore()
	svc, _ := newTestService(t, auth.WithCredentialStore(creds))
	ctx := context.Background()

	u := mustSignUp(t, svc, "rhea@example.com", validPassword)
	// An empty session id, which is what an application that has never heard
	// of step-up passes: still nil, because the account has nothing to prove.
	registerPasskey(t, svc, u.ID, newCred(8))

	rows, err := creds.ListCredentialsByUser(ctx, u.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("credentials = %v (%v), want the one just registered", rows, err)
	}
}

// TestAStolenSessionCannotStepUpByRegisteringItsOwnPasskey is the attack the
// gate exists for, driven end to end.
//
// The account is PASSWORD-LESS (provisioned by a magic link) and holds a
// confirmed factor, which is the configuration where step-up is the only
// credential [auth.Service.DeleteAccount] checks at all. The attacker holds a
// session minted before the factor was enrolled. Ungated, the route is:
// register your own passkey, sign in with it, receive a session stamped
// MFAAt, and delete the victim's account without ever holding their factor.
func TestAStolenSessionCannotStepUpByRegisteringItsOwnPasskey(t *testing.T) {
	creds := memory.NewCredentialStore()
	f := newMFAService(t,
		auth.WithCredentialStore(creds),
		auth.WithMagicLinkProvisioning(true))
	ctx := context.Background()

	// A password-less account: provisioned by a magic link, never by SignUp.
	link, ok, err := f.svc.RequestMagicLink(ctx, "sasha@example.com", "203.0.113.7")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink = (_, %v, %v), want a token", ok, err)
	}
	stolen, err := f.svc.RedeemMagicLink(ctx, link, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if stolen.MFA != nil {
		t.Fatal("fixture error: the account owed a second factor before it had one")
	}
	stolenSession := sessionIDOf(t, f.svc, stolen.AccessToken)
	userID := stolen.User.ID

	// The victim then enrols a second factor. The attacker's session predates
	// it and has proved nothing.
	secret, _, err := f.svc.BeginMFAEnrolment(ctx, userID)
	if err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}
	if _, err := f.svc.ConfirmMFAEnrolment(ctx, userID, totpCodeAt(t, secret, f.clock.now())); err != nil {
		t.Fatalf("ConfirmMFAEnrolment: %v", err)
	}

	// Step-up already refuses the direct route.
	if err := f.svc.DeleteAccount(ctx, userID, stolenSession, ""); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("DeleteAccount from the stolen session = %v, want ErrStepUpRequired", err)
	}

	// The route around it: register an authenticator of the attacker's own.
	challenge, err := f.svc.BeginPasskeyRegistration(ctx, userID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	cred := newCred(6)
	cred.Challenge = challenge
	if _, err := f.svc.FinishPasskeyRegistration(ctx, userID, stolenSession, cred); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("FinishPasskeyRegistration from the stolen session = %v, want ErrStepUpRequired.\n"+
			"Ungated, this is a complete step-up bypass: the attacker signs in with the passkey they just registered, FinishPasskeyLogin stamps Session.MFAAt on the session it mints, and every action RequireFreshMFA guards — including DeleteAccount on this password-less account, where step-up is the ONLY credential in the call — becomes available without the victim's second factor ever being presented.", err)
	}
	if rows, err := creds.ListCredentialsByUser(ctx, userID); err != nil || len(rows) != 0 {
		t.Fatalf("the attacker registered %v (%v) — want nothing", rows, err)
	}

	// And the account is still there.
	if _, err := f.svc.User(ctx, userID); err != nil {
		t.Fatalf("the account is gone: %v", err)
	}
}
