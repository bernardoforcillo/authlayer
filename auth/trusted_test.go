package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// Trusted devices: what one skips, what it emphatically does not, and what
// it takes to mint one.
//
// The two tests this file exists for are
// TestTrustThisDeviceRefusesASessionThatHasNotFreshlyProvedAFactor — without
// that check a stolen session mints a thirty-day second-factor bypass — and
// TestATrustedDeviceDoesNotSkipThePassword, which is the difference between
// a weaker second factor and no authentication at all. The three mutations
// the plan requires are recorded in auth/trusted.go's own doc.

// trustDevice takes an enrolled account all the way to a device token: a
// fresh sign-in through the full second-factor exchange, then
// TrustThisDevice on the session that produced. It is exactly the sequence
// an application performs behind a "remember this browser" checkbox.
func trustDevice(t *testing.T, f mfaFixture, e enrolled, email, label string) string {
	t.Helper()
	sid := freshSessionFor(t, f, e, email)
	tok, err := f.svc.TrustThisDevice(context.Background(), e.user.ID, sid, label)
	if err != nil {
		t.Fatalf("TrustThisDevice(%q): %v", email, err)
	}
	if tok == "" {
		t.Fatal("TrustThisDevice returned an empty token")
	}
	return tok
}

// devicesOf reads the account's stored devices straight out of the store, so
// a test can assert on what was persisted rather than on what was returned.
func devicesOf(t *testing.T, f mfaFixture, userID string) []auth.TrustedDevice {
	t.Helper()
	got, err := f.mfa.ListTrustedDevices(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListTrustedDevices(%s): %v", userID, err)
	}
	return got
}

// --- what a trusted device buys, and what it does not ----------------------

// TestATrustedDeviceSkipsTheSecondFactorChallenge is the feature working: a
// login that would otherwise stop and owe a code returns a live session
// instead, and that session is FRESH for step-up — the machine proved a
// factor when it was trusted, and this sign-in inherits that standing.
func TestATrustedDeviceSkipsTheSecondFactorChallenge(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "ada@example.com")
	device := trustDevice(t, f, e, "ada@example.com", "Ada's laptop")

	res, err := f.svc.LoginWithTrustedDevice(ctx, "ada@example.com", validPassword, "203.0.113.7", "agent", device)
	if err != nil {
		t.Fatalf("LoginWithTrustedDevice: %v", err)
	}
	if res.MFA != nil {
		t.Fatalf("a login from a trusted device still owed a second factor — the whole feature is that it does not")
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("access=%q refresh=%q, want a live session", res.AccessToken, res.RefreshToken)
	}

	// The session is stamped, so it satisfies step-up exactly as one from
	// CompleteMFA does.
	sid := sessionIDOf(t, f.svc, res.AccessToken)
	if err := f.svc.RequireFreshMFA(ctx, e.user.ID, sid); err != nil {
		t.Fatalf("RequireFreshMFA on a session minted from a trusted device = %v, want nil — the device stood in for the factor, so the session it minted is as fresh as one CompleteMFA hands back", err)
	}
}

// TestATrustedDeviceDoesNotSkipThePassword is the test whose failure message
// matters more than its assertion. A trusted device replaces the SECOND
// factor; letting it replace the first is not a weaker second factor, it is
// a full authentication bypass — one opaque cookie standing in for the
// entire credential.
//
// Mutation anchor (b): move the trusted-device branch above the password
// check and this must fail.
func TestATrustedDeviceDoesNotSkipThePassword(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "bram@example.com")
	device := trustDevice(t, f, e, "bram@example.com", "Bram's desktop")
	// The sessions the fixture's own stepped-up login left behind, so the
	// assertion below is about what THIS call minted.
	before := sessionCount(t, f.store, e.user.ID)

	_, err := f.svc.LoginWithTrustedDevice(ctx, "bram@example.com", "Completely-Wrong-Password-9!", "203.0.113.7", "agent", device)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("LoginWithTrustedDevice with the WRONG password = %v, want ErrInvalidCredentials.\n"+
			"A trusted device replaces the SECOND factor and never the first. Accepting it here is not a weaker second factor — it is a FULL AUTHENTICATION BYPASS: the device token is a single opaque string in a cookie, readable by any XSS payload and copyable off a borrowed laptop, and this login would have handed a live session to whoever holds it with no credential presented at all.", err)
	}

	// And nothing was minted: a refusal that still created a session would
	// be the same bypass wearing an error's clothes.
	if n := sessionCount(t, f.store, e.user.ID); n != before {
		t.Errorf("sessions after the refused login = %d, want the %d there already were", n, before)
	}
	// The device was not even touched — the refusal happens before the token
	// is looked up, so a wrong password cannot be used to probe which
	// devices an account trusts.
	for _, d := range devicesOf(t, f, e.user.ID) {
		if d.LastUsedAt != nil {
			t.Errorf("the trusted device was stamped LastUsedAt by a login that failed its password check")
		}
	}
}

// TestARevokedTrustedDeviceDoesNotSkipTheChallenge pins that revocation
// bites: after RevokeTrustedDevice the same cookie is worth exactly nothing,
// and the login falls back to the ordinary challenge rather than failing —
// the user simply types a code again.
func TestARevokedTrustedDeviceDoesNotSkipTheChallenge(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "cleo@example.com")
	device := trustDevice(t, f, e, "cleo@example.com", "Cleo's phone")

	devices := devicesOf(t, f, e.user.ID)
	if len(devices) != 1 {
		t.Fatalf("devices after TrustThisDevice = %d, want 1", len(devices))
	}
	if err := f.svc.RevokeTrustedDevice(ctx, e.user.ID, devices[0].ID); err != nil {
		t.Fatalf("RevokeTrustedDevice: %v", err)
	}

	res, err := f.svc.LoginWithTrustedDevice(ctx, "cleo@example.com", validPassword, "203.0.113.7", "agent", device)
	if err != nil {
		t.Fatalf("LoginWithTrustedDevice after revocation = %v, want a challenge and no error — a stale cookie must not lock a user out", err)
	}
	if res.MFA == nil {
		t.Fatalf("a REVOKED device still skipped the second factor")
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("the pending login carried tokens: access=%q refresh=%q", res.AccessToken, res.RefreshToken)
	}
}

// TestAnExpiredTrustedDeviceDoesNotSkipTheChallenge pins the TTL. The device
// is minted under a one-hour window, the clock moves past it, and the same
// token stops working — without erroring, because a cookie going stale after
// its window is the ordinary case, not a failure.
//
// Mutation anchor (c): drop the ExpiresAt comparison in
// trustedDeviceAtSignIn and this must fail.
func TestAnExpiredTrustedDeviceDoesNotSkipTheChallenge(t *testing.T) {
	f := newMFAService(t, auth.WithTrustedDeviceTTL(time.Hour))
	ctx := context.Background()

	e := enrolConfirmed(t, f, "dara@example.com")
	device := trustDevice(t, f, e, "dara@example.com", "Dara's tablet")

	// Inside the window it works.
	inside, err := f.svc.LoginWithTrustedDevice(ctx, "dara@example.com", validPassword, "203.0.113.7", "agent", device)
	if err != nil {
		t.Fatalf("LoginWithTrustedDevice inside the window: %v", err)
	}
	if inside.MFA != nil {
		t.Fatalf("fixture error: the device did not skip the challenge even inside its window, so the assertion below would pass for the wrong reason")
	}

	f.clock.advance(time.Hour + time.Second)

	outside, err := f.svc.LoginWithTrustedDevice(ctx, "dara@example.com", validPassword, "203.0.113.7", "agent", device)
	if err != nil {
		t.Fatalf("LoginWithTrustedDevice past the window = %v, want a challenge and no error", err)
	}
	if outside.MFA == nil {
		t.Fatalf("an EXPIRED device still skipped the second factor — WithTrustedDeviceTTL is the only knob bounding what a stolen cookie is worth, and it bounds nothing if the expiry is not read")
	}
}

// TestATrustedDeviceIsBoundToItsAccount pins the ownership check: a device
// minted for one account does nothing for another, even though the token is
// perfectly valid and unexpired.
//
// Without it, one user's "remember this browser" cookie would skip the
// second factor on every account in the deployment whose password the holder
// also knew.
func TestATrustedDeviceIsBoundToItsAccount(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	ada := enrolConfirmed(t, f, "ada-owner@example.com")
	bob := enrolConfirmed(t, f, "bob-other@example.com")
	adaDevice := trustDevice(t, f, ada, "ada-owner@example.com", "Ada's laptop")

	res, err := f.svc.LoginWithTrustedDevice(ctx, "bob-other@example.com", validPassword, "203.0.113.7", "agent", adaDevice)
	if err != nil {
		t.Fatalf("LoginWithTrustedDevice with another account's device = %v, want a challenge and no error", err)
	}
	if res.MFA == nil {
		t.Fatalf("a device minted for %s skipped the second factor for %s — a trusted device is trusted for ONE account", ada.user.ID, bob.user.ID)
	}
}

// TestATrustedDeviceDoesNotBypassEnforcementRequired pins the interaction
// with [auth.EnforcementRequired]. An account with no confirmed factor must
// still be refused with ErrMFARequired, and a device token — however it was
// obtained — must not turn that refusal into a session.
//
// The check that makes this true is in trustedDeviceAtSignIn: with no
// confirmed factor there is nothing for a device to stand in for, so
// mfaAtSignIn runs and applies the policy exactly as it would have.
func TestATrustedDeviceDoesNotBypassEnforcementRequired(t *testing.T) {
	f := newMFAService(t, auth.WithMFAEnforcement(auth.EnforcementRequired))
	ctx := context.Background()

	// An enrolled account, a trusted device, and then the factor is turned
	// off — the only route by which a live device token and a factor-less
	// account can coexist.
	e := enrolConfirmed(t, f, "eve@example.com")
	device := trustDevice(t, f, e, "eve@example.com", "Eve's laptop")
	// Written straight through the store: DisableMFA sweeps the devices (see
	// the sweep matrix), and this test is about the door, not the sweep.
	if err := f.mfa.DeleteFactor(ctx, e.user.ID); err != nil {
		t.Fatalf("DeleteFactor (fixture): %v", err)
	}

	if _, err := f.svc.LoginWithTrustedDevice(ctx, "eve@example.com", validPassword, "203.0.113.7", "agent", device); !errors.Is(err, auth.ErrMFARequired) {
		t.Fatalf("LoginWithTrustedDevice under EnforcementRequired for an account with no factor = %v, want ErrMFARequired — a trusted device stands in for a factor that exists, and can never manufacture one", err)
	}
}

// TestALoginFromATrustedDeviceStampsLastUsedAt pins the audit field a "your
// devices" screen renders, and with it the fact that the touch happens on
// the path that actually skipped a challenge.
func TestALoginFromATrustedDeviceStampsLastUsedAt(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "faye@example.com")
	device := trustDevice(t, f, e, "faye@example.com", "Faye's laptop")

	if d := devicesOf(t, f, e.user.ID); len(d) != 1 || d[0].LastUsedAt != nil {
		t.Fatalf("a freshly trusted device already carries LastUsedAt — trusting is not using")
	}

	f.clock.advance(2 * time.Hour)
	if _, err := f.svc.LoginWithTrustedDevice(ctx, "faye@example.com", validPassword, "203.0.113.7", "agent", device); err != nil {
		t.Fatalf("LoginWithTrustedDevice: %v", err)
	}

	d := devicesOf(t, f, e.user.ID)
	if len(d) != 1 || d[0].LastUsedAt == nil {
		t.Fatalf("LastUsedAt is still nil after the device skipped a challenge")
	}
	if !d[0].LastUsedAt.Equal(f.clock.now()) {
		t.Errorf("LastUsedAt = %v, want the service clock's %v", d[0].LastUsedAt, f.clock.now())
	}
}

// revokedBeforeTouch delegates everything except TouchTrustedDevice, which
// reports false — the store's answer when the row went between the lookup
// and the stamp, which is what a RevokeTrustedDevice landing mid-login
// produces.
//
// It is a deterministic stand-in for that race rather than a goroutine pair:
// the window is a few microseconds wide in store/memory, so a concurrent
// version would explore essentially one interleaving and prove nothing.
type revokedBeforeTouch struct {
	*memory.MFAStore
}

func (s revokedBeforeTouch) TouchTrustedDevice(context.Context, string, time.Time) (bool, error) {
	return false, nil
}

// TestADeviceRevokedBetweenTheLookupAndTheTouchDoesNotSkipTheChallenge pins
// why [auth.MFAStore.TouchTrustedDevice]'s bool is a decision rather than
// bookkeeping. A revocation that commits after the device is resolved and
// before the session is minted must win: the login falls back to the
// challenge instead of skipping a factor for a row that no longer exists.
func TestADeviceRevokedBetweenTheLookupAndTheTouchDoesNotSkipTheChallenge(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "gita@example.com")
	device := trustDevice(t, f, e, "gita@example.com", "Gita's laptop")

	// The same stores, behind a Service whose touch reports the row as gone.
	racing := newServiceOver(t, f.store,
		auth.WithMFAStore(revokedBeforeTouch{f.mfa}),
		auth.WithMFASecretCipher(testCipher{}),
		auth.WithClock(f.clock.now),
	)

	res, err := racing.LoginWithTrustedDevice(ctx, "gita@example.com", validPassword, "203.0.113.7", "agent", device)
	if err != nil {
		t.Fatalf("LoginWithTrustedDevice: %v", err)
	}
	if res.MFA == nil {
		t.Fatalf("a device the store reported as gone still skipped the second factor — TouchTrustedDevice's false is what a revocation racing a login has to say, and ignoring it lets a revoked device sign in one last time")
	}
}

// --- minting one ------------------------------------------------------------

// TestTrustThisDeviceRefusesASessionThatHasNotFreshlyProvedAFactor is the
// single most important test in this task.
//
// Without the freshness requirement, whoever holds a stolen session — a
// borrowed laptop, an exfiltrated access token, an XSS payload — mints
// themselves a trusted device on the way out, and a compromise that would
// have ended when the session expired instead skips the second factor for
// thirty days.
//
// Mutation anchor (a): remove the RequireFreshMFA call from TrustThisDevice
// and this must fail.
func TestTrustThisDeviceRefusesASessionThatHasNotFreshlyProvedAFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	// A session minted BEFORE enrolment: real, live, and never having proved
	// a factor — exactly what a user who enrols from a browser they are
	// already signed into is left holding, and exactly what a thief holds.
	s := enrolWithSessions(t, f, "hana@example.com")

	if _, err := f.svc.TrustThisDevice(ctx, s.user.ID, s.stale, "a thief's laptop"); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("TrustThisDevice from a session that never proved a factor = %v, want ErrStepUpRequired — otherwise a stolen session mints a thirty-day second-factor bypass, which is this feature's whole danger", err)
	}
	if n := len(devicesOf(t, f, s.user.ID)); n != 0 {
		t.Fatalf("the refused call left %d devices behind, want 0", n)
	}

	// The same account, from a freshly stepped-up session, succeeds — so the
	// refusal above is about freshness and not about something else.
	if _, err := f.svc.TrustThisDevice(ctx, s.user.ID, s.fresh, "Hana's laptop"); err != nil {
		t.Fatalf("TrustThisDevice from a freshly stepped-up session = %v, want nil", err)
	}
}

// TestTrustThisDeviceRefusesAStaleSession is the other half of "fresh is a
// time": a session that DID prove a factor, but longer ago than
// [auth.WithStepUpWindow] allows, is refused too.
func TestTrustThisDeviceRefusesAStaleSession(t *testing.T) {
	f := newMFAService(t, auth.WithStepUpWindow(15*time.Minute))
	ctx := context.Background()

	e := enrolConfirmed(t, f, "iris@example.com")
	sid := freshSessionFor(t, f, e, "iris@example.com")

	f.clock.advance(16 * time.Minute)

	if _, err := f.svc.TrustThisDevice(ctx, e.user.ID, sid, "Iris's laptop"); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("TrustThisDevice from a session stamped 16 minutes ago = %v, want ErrStepUpRequired", err)
	}
}

// TestTrustThisDeviceRefusesAnotherUsersSession pins the pairing
// [auth.Service.RequireFreshMFA] takes both a userID and a sessionID for: a
// caller holding a freshly stepped-up session on their OWN account must not
// be able to mint a device for somebody else's.
func TestTrustThisDeviceRefusesAnotherUsersSession(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	attacker := enrolConfirmed(t, f, "mallory@example.com")
	victim := enrolConfirmed(t, f, "victim@example.com")
	attackerSession := freshSessionFor(t, f, attacker, "mallory@example.com")

	if _, err := f.svc.TrustThisDevice(ctx, victim.user.ID, attackerSession, "not mine"); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("TrustThisDevice for the victim from the attacker's own fresh session = %v, want ErrStepUpRequired", err)
	}
	if n := len(devicesOf(t, f, victim.user.ID)); n != 0 {
		t.Fatalf("the victim gained %d trusted devices, want 0", n)
	}
}

// TestTrustThisDeviceRefusesAnAccountWithNoConfirmedFactor is the check that
// closes the other end of the freshness argument.
//
// [auth.Service.RequireFreshMFA] is deliberately a NO-OP for an account with
// no confirmed factor — it has to be, or enabling step-up would lock every
// non-MFA user out. So without an explicit refusal here, a stolen session on
// a factor-less account could mint a trusted device that grants nothing
// today and silently skips the factor the user enrols next week: a bypass
// armed before the thing it bypasses exists.
func TestTrustThisDeviceRefusesAnAccountWithNoConfirmedFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	// No factor at all.
	u := mustSignUp(t, f.svc, "jules@example.com", validPassword)
	res, err := f.svc.Login(ctx, "jules@example.com", validPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	sid := sessionIDOf(t, f.svc, res.AccessToken)

	if _, err := f.svc.TrustThisDevice(ctx, u.ID, sid, "no factor here"); !errors.Is(err, auth.ErrMFARequired) {
		t.Fatalf("TrustThisDevice on an account with no factor = %v, want ErrMFARequired — RequireFreshMFA is a no-op for such an account, so this refusal is the only thing standing between a stolen session and a bypass armed for a factor that does not exist yet", err)
	}

	// An UNCONFIRMED factor is the same answer: it gates nothing anywhere
	// else in this package either.
	if _, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID); err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}
	if _, err := f.svc.TrustThisDevice(ctx, u.ID, sid, "half-enrolled"); !errors.Is(err, auth.ErrMFARequired) {
		t.Fatalf("TrustThisDevice with an UNCONFIRMED factor = %v, want ErrMFARequired", err)
	}
	if n := len(devicesOf(t, f, u.ID)); n != 0 {
		t.Fatalf("the refused calls left %d devices behind, want 0", n)
	}
}

// TestATrustedDeviceTokenIsStoredOnlyAsAHash walks the whole store and
// requires the plaintext to appear in no field of any device row. The token
// IS a credential — a dump of plaintext ones is a working second-factor
// bypass for every user who ever clicked "remember this browser" — so it
// gets refresh-token treatment: hashed on the way in, returned once, never
// again.
func TestATrustedDeviceTokenIsStoredOnlyAsAHash(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "kira@example.com")
	plain := trustDevice(t, f, e, "kira@example.com", "Kira's laptop")

	devices := devicesOf(t, f, e.user.ID)
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}
	d := devices[0]
	for what, got := range map[string]string{
		"ID": d.ID, "UserID": d.UserID, "TokenHash": d.TokenHash, "Label": d.Label,
	} {
		if got == plain {
			t.Fatalf("TrustedDevice.%s holds the PLAINTEXT token — a dump of this table would be a working second-factor bypass for every trusted device in the deployment", what)
		}
	}
	if d.TokenHash != token.HashOpaque(plain) {
		t.Fatalf("TokenHash is not HashOpaque(plaintext); the lookup at sign-in cannot match it")
	}

	// The plaintext is not a key into the store either.
	if _, err := f.mfa.FindTrustedDeviceByHash(ctx, plain); !errors.Is(err, auth.ErrTrustedDeviceNotFound) {
		t.Fatalf("FindTrustedDeviceByHash(plaintext) = %v, want ErrTrustedDeviceNotFound", err)
	}
}

// TestTrustThisDeviceRefusesAnAnonymizedAccount pins this method's place in
// [auth.Service.AnonymizeAccount]'s "Every entry point that refuses a
// stamped account": a scrubbed row must never acquire a fresh credential.
func TestTrustThisDeviceRefusesAnAnonymizedAccount(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "lena@example.com")
	sid := freshSessionFor(t, f, e, "lena@example.com")
	if err := f.svc.AnonymizeAccount(ctx, e.user.ID, sid, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}

	if _, err := f.svc.TrustThisDevice(ctx, e.user.ID, sid, "too late"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("TrustThisDevice on an anonymized account = %v, want ErrUserNotFound", err)
	}
}

// TestTrustedDeviceMethodsRefuseAServiceWithNoMFAStore pins the fail-closed
// answer for the optional port, on each of the three entry points, since a
// nil interface would otherwise be dereferenced somewhere down the ladder.
func TestTrustedDeviceMethodsRefuseAServiceWithNoMFAStore(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	u := mustSignUp(t, svc, "milo@example.com", validPassword)

	if _, err := svc.TrustThisDevice(ctx, u.ID, "any-session", "nope"); !errors.Is(err, auth.ErrMFANotConfigured) {
		t.Errorf("TrustThisDevice with no MFAStore = %v, want ErrMFANotConfigured", err)
	}
	if _, err := svc.ListTrustedDevices(ctx, u.ID); !errors.Is(err, auth.ErrMFANotConfigured) {
		t.Errorf("ListTrustedDevices with no MFAStore = %v, want ErrMFANotConfigured", err)
	}
	if err := svc.RevokeTrustedDevice(ctx, u.ID, "any-device"); !errors.Is(err, auth.ErrMFANotConfigured) {
		t.Errorf("RevokeTrustedDevice with no MFAStore = %v, want ErrMFANotConfigured", err)
	}
}

// --- listing and revoking ---------------------------------------------------

// TestListTrustedDevicesReturnsThisAccountsDevices pins what a "your trusted
// devices" screen renders, including the label it was given.
func TestListTrustedDevicesReturnsThisAccountsDevices(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	ada := enrolConfirmed(t, f, "nadia@example.com")
	bob := enrolConfirmed(t, f, "omar@example.com")
	trustDevice(t, f, ada, "nadia@example.com", "laptop")
	trustDevice(t, f, ada, "nadia@example.com", "phone")
	trustDevice(t, f, bob, "omar@example.com", "omar's desktop")

	got, err := f.svc.ListTrustedDevices(ctx, ada.user.ID)
	if err != nil {
		t.Fatalf("ListTrustedDevices: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListTrustedDevices returned %d devices, want ada's 2", len(got))
	}
	labels := map[string]bool{}
	for _, d := range got {
		if d.UserID != ada.user.ID {
			t.Errorf("the listing includes a device belonging to %s", d.UserID)
		}
		labels[d.Label] = true
	}
	if !labels["laptop"] || !labels["phone"] {
		t.Errorf("labels = %v, want laptop and phone", labels)
	}
}

// TestRevokeTrustedDeviceRefusesAnotherAccountsDevice pins the ownership
// check. deviceID is a bare surrogate key, so without the scan over the
// caller's own devices anyone holding or guessing one could revoke a
// stranger's — and the answer for "not yours" is the same
// ErrTrustedDeviceNotFound "not there" gets.
func TestRevokeTrustedDeviceRefusesAnotherAccountsDevice(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	ada := enrolConfirmed(t, f, "pia@example.com")
	bob := enrolConfirmed(t, f, "quinn@example.com")
	trustDevice(t, f, bob, "quinn@example.com", "Quinn's laptop")
	bobDevices := devicesOf(t, f, bob.user.ID)
	if len(bobDevices) != 1 {
		t.Fatalf("fixture error: bob has %d devices, want 1", len(bobDevices))
	}

	if err := f.svc.RevokeTrustedDevice(ctx, ada.user.ID, bobDevices[0].ID); !errors.Is(err, auth.ErrTrustedDeviceNotFound) {
		t.Fatalf("RevokeTrustedDevice on another account's device = %v, want ErrTrustedDeviceNotFound", err)
	}
	if n := len(devicesOf(t, f, bob.user.ID)); n != 1 {
		t.Fatalf("bob's devices after the refused revocation = %d, want 1", n)
	}
	if err := f.svc.RevokeTrustedDevice(ctx, ada.user.ID, "no-such-device"); !errors.Is(err, auth.ErrTrustedDeviceNotFound) {
		t.Errorf("RevokeTrustedDevice on an unknown id = %v, want ErrTrustedDeviceNotFound", err)
	}
}

// TestRevokeTrustedDeviceLeavesTheSessionsAlone pins the boundary between
// the two revocation controls: dropping a device is a statement about the
// second factor, not about access, so the machine stays signed in.
func TestRevokeTrustedDeviceLeavesTheSessionsAlone(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "rui@example.com")
	trustDevice(t, f, e, "rui@example.com", "Rui's laptop")
	before := sessionCount(t, f.store, e.user.ID)
	if before == 0 {
		t.Fatal("fixture error: no sessions to leave alone")
	}

	devices := devicesOf(t, f, e.user.ID)
	if err := f.svc.RevokeTrustedDevice(ctx, e.user.ID, devices[0].ID); err != nil {
		t.Fatalf("RevokeTrustedDevice: %v", err)
	}
	if after := sessionCount(t, f.store, e.user.ID); after != before {
		t.Errorf("sessions = %d after revoking a device, want the %d there were — revoking a device is not signing one out", after, before)
	}
}

// --- housekeeping -----------------------------------------------------------

// TestPurgeExpiredRemovesExpiredTrustedDevices pins the janitor's third
// table. It is housekeeping rather than a boundary — an expired device is
// already refused at sign-in — but a deployment that never purges keeps
// every device row it has ever minted.
func TestPurgeExpiredRemovesExpiredTrustedDevices(t *testing.T) {
	f := newMFAService(t, auth.WithTrustedDeviceTTL(time.Hour))
	ctx := context.Background()

	e := enrolConfirmed(t, f, "sena@example.com")
	trustDevice(t, f, e, "sena@example.com", "Sena's laptop")
	if n := len(devicesOf(t, f, e.user.ID)); n != 1 {
		t.Fatalf("fixture error: devices = %d, want 1", n)
	}

	// Before the window closes, nothing goes.
	if _, err := f.svc.PurgeExpired(ctx, f.clock.now()); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n := len(devicesOf(t, f, e.user.ID)); n != 1 {
		t.Fatalf("a live device was purged: devices = %d, want 1", n)
	}

	f.clock.advance(2 * time.Hour)
	if _, err := f.svc.PurgeExpired(ctx, f.clock.now()); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n := len(devicesOf(t, f, e.user.ID)); n != 0 {
		t.Fatalf("devices after purging past the TTL = %d, want 0", n)
	}
}

// TestWithTrustedDeviceTTLIgnoresANonPositiveDuration pins the option's
// treatment of nonsense input, matching [auth.WithMagicLinkTTL]: zero and
// negative leave the default in place rather than minting a device that
// expires immediately — or, worse for a zero read as "unbounded", one that
// never does.
func TestWithTrustedDeviceTTLIgnoresANonPositiveDuration(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Hour} {
		f := newMFAService(t, auth.WithTrustedDeviceTTL(d))
		e := enrolConfirmed(t, f, "tomas@example.com")
		trustDevice(t, f, e, "tomas@example.com", "Tomas's laptop")

		devices := devicesOf(t, f, e.user.ID)
		if len(devices) != 1 {
			t.Fatalf("devices = %d, want 1", len(devices))
		}
		want := f.clock.now().Add(30 * 24 * time.Hour)
		if !devices[0].ExpiresAt.Equal(want) {
			t.Errorf("WithTrustedDeviceTTL(%v) produced ExpiresAt %v, want the 30-day default's %v", d, devices[0].ExpiresAt, want)
		}
	}
}
