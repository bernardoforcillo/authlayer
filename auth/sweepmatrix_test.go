package auth_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// ============================================================
// THE SWEEP MATRIX
// ============================================================
//
// This file is the executable form of the table in [auth.Service.ChangePassword]'s
// doc, "The sweep matrix". Thirteen paths against eight credential kinds, and
// EVERY cell is asserted — the deliberate non-sweeps included.
//
// Testing the non-sweeps matters as much as testing the sweeps. Milestone
// 2's worst Critical was a fix applied to half a remediation surface; the
// countermeasure is a table nobody can extend without filling in every
// column. But the opposite mistake is just as easy: a later "make it
// consistent" change that starts sweeping magic links on Logout breaks
// "request a link on your laptop, sign that laptop out, click it on your
// phone" for every user, silently, with every test still green. A cell that
// pins deliberate non-behaviour is what stops that.
//
// The cells are asserted from ONE fixture per row, so a path that swept a
// column it should not have is caught by the same run that checks the
// columns it should.
//
// # Mutations, recorded
//
// The point of a matrix is that its cells are INDEPENDENT calls rather than
// one call reached from several places, so the mutations that matter here
// remove a single cell's sweep and require exactly that cell to fail. Two
// were run and both restored:
//
//   - Removing the trusted-device sweep from [auth.Service.ChangePassword]
//     ONLY: failed TestSweepMatrix/ChangePassword's trusted-device cell,
//     that path's fail-closed sub-test, and
//     TestChangePasswordRevokesADeviceThatWasActuallyTrusted. Every other
//     row's trusted-device cell — ResetPassword, LogoutAll, DeleteAccount,
//     AnonymizeAccount, DisableMFA — still passed.
//   - Removing the MFA-state sweep from [auth.Service.DeleteAccount] ONLY:
//     failed that row's two MFA cells (factor and recovery codes) and its
//     fail-closed sub-test, and nothing else. AnonymizeAccount's identical
//     cells still passed, which is what proves the two postures make two
//     calls.
//   - Removing the PASSKEY sweep from [auth.Service.DeleteAccount] ONLY:
//     failed TestSweepMatrix/DeleteAccount's passkey cell, that row's
//     fail-closed sub-test, and
//     TestAPasskeyDoesNotOutliveTheAccountItAuthenticated. Every other row's
//     passkey cell — AnonymizeAccount's identical one included — still
//     passed, which is again what proves the two postures make two calls
//     rather than reaching one shared cascade.
//   - Rewriting [auth.Service.sweepCredentials] as a loop over
//     [auth.Service.DeletePasskey] — the tempting reuse, since that method
//     already removes a credential: failed
//     TestTerminationSweepsAPasskeyOnlyAccount on BOTH postures with
//     auth.ErrLastCredential, and both halves of the passkey fail-closed
//     suite. That is the whole reason the sweep calls the port's unchecked
//     by-user delete instead: a reachability guard on a termination path
//     preserves exactly what the path is destroying.
//
// The passkey column is also where the deliberate non-sweeps carry the most
// weight in this file. Eleven of the thirteen rows say "not swept" there, and
// they say it against a real argument rather than by omission — see the
// matrix's "The passkey column, and why ResetPassword does not sweep it". A
// later change that makes a remediation path "consistent" by sweeping
// passkeys destroys hardware credentials on a flow an attacker can trigger
// from a compromised mailbox, and TestSweepMatrix/ResetPassword is the thing
// standing in its way.

// verdict is what the matrix says about one (path, credential) cell.
type verdict int

const (
	// gone: the credential must not survive the path.
	gone verdict = iota
	// survives: the credential must STILL be there afterwards. These are
	// the deliberate non-sweeps, and they are the cells a later change is
	// most likely to break by accident.
	survives
	// notApplicable: the path cannot be reached with that credential armed,
	// or the credential is the one the path consumes by definition. The
	// matrix marks these rather than pretending they were tested.
	notApplicable
	// justThatOne: the path removes the ONE credential it was told to and
	// leaves that account's others standing. It exists for the passkey
	// column's DeletePasskey cell, where neither "swept" nor "not swept" is
	// the truth and asserting either would pin the wrong behaviour: the
	// matrix's own table says "that one's" there, and this is that cell.
	justThatOne
)

func (v verdict) String() string {
	switch v {
	case gone:
		return "swept"
	case survives:
		return "not swept"
	case justThatOne:
		return "that one's"
	default:
		return "n/a"
	}
}

// sweepRow is one row of the matrix: a path, what it needs to run, and the
// five verdicts.
type sweepRow struct {
	name string
	// run performs the path against the armed fixture.
	run func(t *testing.T, f *sweepFixture)
	// The four Verification purposes, then the identity and session
	// columns. "signup" has no column in the doc's table because only the
	// two termination rows touch it; it is asserted here anyway, because
	// "only those two touch it" is itself a claim.
	signup, reset, change, magic verdict
	identity                     verdict
	// trusted is the trusted-device column: a device is a long-lived bearer
	// token that skips the SECOND factor, so every path that sweeps anything
	// at all sweeps these.
	trusted verdict
	// passkey is the eighth column: the [auth.Credential]s
	// [auth.Service.FinishPasskeyRegistration] writes. Only the two
	// TERMINATION rows sweep it and only DeletePasskey removes one of them,
	// so eleven of the thirteen cells here are deliberate non-behaviour — the
	// densest block of it in the table, and the reason is that a passkey is
	// bound to hardware nobody who compromised the mailbox holds. See the
	// matrix doc's "The passkey column, and why ResetPassword does not sweep
	// it".
	passkey verdict
	// mfa is the second-factor column — the [auth.MFAFactor] and its
	// [auth.RecoveryCode]s together, asserted separately but always with the
	// same verdict, because nothing in this package removes one without the
	// other. Only the two TERMINATION rows and DisableMFA fill it in; see
	// the doc's "Reading the matrix" for why no remediation path may.
	mfa verdict
	// families is how many of the TWO seeded session families must survive.
	families int
	// extraSessions is how many session rows the path itself is expected to
	// mint (RedeemMagicLink mints one).
	extraSessions int
}

// sweepFixture is one account with every credential kind this package can
// hold, armed at once: four outstanding verifications spanning all four
// purposes, one linked external identity, two registered passkeys, and two
// session families.
type sweepFixture struct {
	svc   *auth.Service
	store *memory.AuthStore
	ids   *memory.IdentityStore
	mfa   *memory.MFAStore
	creds *memory.CredentialStore

	user auth.UserBase

	// The two passkeys the fixture registers, by surrogate id. Two rather
	// than one for the trusted-device column's reason — a path that took
	// SOME of them is half a sweep — and because DeletePasskey's cell is
	// about which ONE went.
	passkeyA, passkeyB string

	signupTok string
	resetTok  string
	changeTok string
	magicTok  string

	familyA, familyB     string
	sessionAID           string
	refreshA, refreshB   string
	accessA              string
	newAddress, provider string
}

const (
	sweepPassword    = "Sweep-Horse-Battery-1!"
	sweepNextPass    = "Sweep-Horse-Battery-2!"
	sweepProvider    = "google"
	sweepSubject     = "google-subject-sweep"
	sweepNewAddrTmpl = "moved-%s"
)

func newSweepFixture(t *testing.T, email string) *sweepFixture {
	t.Helper()
	ctx := context.Background()

	store := memory.NewAuthStore()
	ids := memory.NewIdentityStore()
	mfa := memory.NewMFAStore()
	creds := memory.NewCredentialStore()
	svc := newServiceOver(t, store, sweepOptions(ids, mfa, creds)...)

	// Deliberately NOT verified: the signup token has to stay outstanding
	// so its column can be asserted, and nothing in this file needs a
	// verified address (WithRequireVerifiedEmail is off, and LinkIdentity
	// is not gated by the Linking policy).
	res, err := svc.SignUp(ctx, email, sweepPassword)
	if err != nil {
		t.Fatalf("SignUp(%q): %v", email, err)
	}
	user := res.User

	_, accessA, refreshA := mustLogin(t, svc, email, sweepPassword)
	_, _, refreshB := mustLogin(t, svc, email, sweepPassword)

	resetTok, ok, err := svc.RequestPasswordReset(ctx, email, "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset(%q) = (_, %v, %v), want a token", email, ok, err)
	}
	newAddress := fmt.Sprintf(sweepNewAddrTmpl, email)
	changeTok, err := svc.RequestEmailChange(ctx, user.ID, "", sweepPassword, newAddress)
	if err != nil {
		t.Fatalf("RequestEmailChange(%q): %v", email, err)
	}
	magicTok, ok, err := svc.RequestMagicLink(ctx, email, "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink(%q) = (_, %v, %v), want a token", email, ok, err)
	}

	if _, err := svc.LinkIdentity(ctx, user.ID, auth.ExternalIdentity{
		Provider:      sweepProvider,
		Subject:       sweepSubject,
		Email:         email,
		EmailVerified: true,
	}); err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}

	// The second-factor state and the two trusted devices are seeded
	// STRAIGHT INTO THE STORE, and the factor is left UNCONFIRMED.
	//
	// Both choices keep the eleven pre-existing rows meaning exactly what
	// they meant before this column existed. An unconfirmed factor gates
	// nothing anywhere in this package — [auth.Service.RequireFreshMFA] is a
	// documented no-op for it — so every path below behaves as it always
	// did, and a fixture that confirmed one would instead be testing the
	// step-up ladder in eleven places at once. Nothing under test here reads
	// ConfirmedAt: the sweeps are unconditional by construction.
	//
	// The realism the shortcut gives up is bought back by
	// TestChangePasswordRevokesADeviceThatWasActuallyTrusted, which mints a
	// device through [auth.Service.TrustThisDevice] on an account with a
	// confirmed factor and requires the same sweep to take it.
	seedMFAState(t, mfa, user.ID)

	// The passkeys go through the real ceremony, unlike the MFA state above:
	// [auth.Service.FinishPasskeyRegistration] is not gated for this account
	// (the seeded factor is UNCONFIRMED, so RequireFreshMFA is a documented
	// no-op), so there is no reason to reach past the service and every
	// reason not to — a row written straight into the store could not catch a
	// registration path that stopped writing one.
	//
	// Each fixture owns its own CredentialStore, so the credential-id labels
	// may repeat across fixtures but must not repeat within one.
	passkeyA := registerPasskey(t, svc, user.ID, newCred('p'))
	passkeyB := registerPasskey(t, svc, user.ID, newCred('q'))

	f := &sweepFixture{
		svc: svc, store: store, ids: ids, mfa: mfa, creds: creds, user: user,
		signupTok: res.VerifyToken, resetTok: resetTok, changeTok: changeTok, magicTok: magicTok,
		passkeyA: passkeyA.ID, passkeyB: passkeyB.ID,
		refreshA: refreshA, refreshB: refreshB, accessA: accessA,
		newAddress: newAddress, provider: sweepProvider,
	}

	sessA := f.sessionByRefresh(t, refreshA)
	sessB := f.sessionByRefresh(t, refreshB)
	f.familyA, f.sessionAID = sessA.FamilyID, sessA.ID
	f.familyB = sessB.FamilyID
	if f.familyA == f.familyB {
		t.Fatalf("fixture error: both logins landed in one family (%q) — the two-family assertions below would be vacuous", f.familyA)
	}

	// Every column starts armed. A fixture that seeded a credential the
	// path then found missing would report "swept" for free.
	f.assertArmed(t)
	return f
}

// sweepOptions is the wiring every Service in this file is built with, so a
// fail-closed test that swaps one store out keeps the other three ports. A
// rebuild that forgot [auth.WithMFAStore] or [auth.WithCredentialStore] would
// make those columns' sweeps silent no-ops and every one of their cells pass
// for the wrong reason.
func sweepOptions(ids *memory.IdentityStore, mfa *memory.MFAStore, creds *memory.CredentialStore) []auth.Option {
	return []auth.Option{
		auth.WithIdentityStore(ids),
		auth.WithMFAStore(mfa),
		auth.WithCredentialStore(creds),
	}
}

// seedMFAState arms the two new columns: one factor, two recovery codes and
// two trusted devices. See newSweepFixture for why the factor is left
// unconfirmed and why the devices are written directly.
func seedMFAState(t *testing.T, mfa *memory.MFAStore, userID string) {
	t.Helper()
	ctx := context.Background()
	at := time.Now().UTC()

	if err := mfa.UpsertFactor(ctx, auth.MFAFactor{
		UserID:    userID,
		SecretEnc: "enc-sweep-secret",
		CreatedAt: at,
	}); err != nil {
		t.Fatalf("seeding the factor: %v", err)
	}
	codes := make([]auth.RecoveryCode, 2)
	for i := range codes {
		codes[i] = auth.RecoveryCode{
			ID:        fmt.Sprintf("%s-rc-%d", userID, i),
			UserID:    userID,
			CodeHash:  fmt.Sprintf("rc-hash-%s-%d", userID, i),
			CreatedAt: at,
		}
	}
	if err := mfa.ReplaceRecoveryCodes(ctx, userID, codes); err != nil {
		t.Fatalf("seeding the recovery codes: %v", err)
	}
	for i := range 2 {
		if _, err := mfa.CreateTrustedDevice(ctx, auth.TrustedDevice{
			ID:        fmt.Sprintf("%s-td-%d", userID, i),
			UserID:    userID,
			TokenHash: fmt.Sprintf("td-hash-%s-%d", userID, i),
			Label:     fmt.Sprintf("device %d", i),
			CreatedAt: at,
			ExpiresAt: at.Add(30 * 24 * time.Hour),
		}); err != nil {
			t.Fatalf("seeding trusted device %d: %v", i, err)
		}
	}
}

// passkeyIDs is the passkey column's reading: the surrogate ids of whatever
// credentials the account still holds, sorted so a comparison against the two
// the fixture registered does not depend on the store's iteration order.
func (f *sweepFixture) passkeyIDs(t *testing.T) []string {
	t.Helper()
	rows, err := f.creds.ListCredentialsByUser(context.Background(), f.user.ID)
	if err != nil {
		t.Fatalf("ListCredentialsByUser: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, c := range rows {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

// checkPasskeyCell asserts the passkey column for one row. It is its own
// function rather than a [checkCell] call because this column has three
// possible verdicts and because "some of them went" is a real, catchable
// failure here: a sweep that removed one of two passkeys would read as
// "survives" to a present/absent check and would leave half an account's
// credentials behind.
func (f *sweepFixture) checkPasskeyCell(t *testing.T, path string, want verdict) {
	t.Helper()
	got := f.passkeyIDs(t)
	switch want {
	case gone:
		if len(got) != 0 {
			t.Errorf("%s / passkey: %d of the 2 registered passkeys SURVIVED, and the matrix says %q — a credential outliving the account it authenticates is a working sign-in filed under an id that no longer resolves, and a later account issued that id inherits it", path, len(got), want)
		}
	case survives:
		if len(got) != 2 {
			t.Errorf("%s / passkey: %d of the 2 registered passkeys survived, and the matrix says %q — this cell is deliberate non-behaviour, and sweeping here destroys hardware credentials on a path an attacker can trigger from a compromised mailbox (see ChangePassword's doc, \"The passkey column, and why ResetPassword does not sweep it\")", path, len(got), want)
		}
	case justThatOne:
		if len(got) != 1 || got[0] != f.passkeyB {
			t.Errorf("%s / passkey: passkeys left = %v, want exactly the one that was NOT named (%q) — the matrix says %q, and a by-id removal that widened would be an account losing credentials it did not ask to lose", path, got, f.passkeyB, want)
		}
	}
}

// trustedCount is the trusted-device column's reading.
func (f *sweepFixture) trustedCount(t *testing.T) int {
	t.Helper()
	rows, err := f.mfa.ListTrustedDevices(context.Background(), f.user.ID)
	if err != nil {
		t.Fatalf("ListTrustedDevices: %v", err)
	}
	return len(rows)
}

// factorPresent and recoveryCodeCount are the MFA column's two readings. They
// are asserted against the SAME verdict but read separately, because "the
// factor went and the codes did not" is a live credential for a second factor
// that no longer exists — the exact half-swept state this file exists to
// catch.
func (f *sweepFixture) factorPresent(t *testing.T) bool {
	t.Helper()
	_, err := f.mfa.FindFactor(context.Background(), f.user.ID)
	switch {
	case err == nil:
		return true
	case errors.Is(err, auth.ErrFactorNotFound):
		return false
	default:
		t.Fatalf("FindFactor: %v", err)
		return false
	}
}

func (f *sweepFixture) recoveryCodeCount(t *testing.T) int {
	t.Helper()
	rows, err := f.mfa.ListRecoveryCodes(context.Background(), f.user.ID)
	if err != nil {
		t.Fatalf("ListRecoveryCodes: %v", err)
	}
	return len(rows)
}

func (f *sweepFixture) sessionByRefresh(t *testing.T, refresh string) auth.Session {
	t.Helper()
	sess, err := f.store.FindSessionByHash(context.Background(), token.HashOpaque(refresh))
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	return sess
}

// present reports whether the verification behind a plaintext token is still
// in the store.
func (f *sweepFixture) present(t *testing.T, plain string) bool {
	t.Helper()
	_, err := f.store.FindVerificationByHash(context.Background(), token.HashOpaque(plain))
	switch {
	case err == nil:
		return true
	case errors.Is(err, auth.ErrVerificationNotFound):
		return false
	default:
		t.Fatalf("FindVerificationByHash: %v", err)
		return false
	}
}

func (f *sweepFixture) identityCount(t *testing.T) int {
	t.Helper()
	rows, err := f.ids.ListIdentitiesByUser(context.Background(), f.user.ID)
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	return len(rows)
}

// seededFamilies reports how many of the two families the fixture created
// still have rows, and how many rows belong to neither of them (a session
// the path itself minted).
func (f *sweepFixture) seededFamilies(t *testing.T) (seeded, extra int) {
	t.Helper()
	sessions, err := f.store.ListSessionsByUser(context.Background(), f.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	live := map[string]bool{}
	for _, s := range sessions {
		switch s.FamilyID {
		case f.familyA, f.familyB:
			live[s.FamilyID] = true
		default:
			extra++
		}
	}
	return len(live), extra
}

func (f *sweepFixture) assertArmed(t *testing.T) {
	t.Helper()
	for name, tok := range map[string]string{
		"signup": f.signupTok, "password_reset": f.resetTok,
		"email_change": f.changeTok, "magic_link": f.magicTok,
	} {
		if !f.present(t, tok) {
			t.Fatalf("fixture error: the %s verification is not armed before the path runs", name)
		}
	}
	if n := f.identityCount(t); n != 1 {
		t.Fatalf("fixture error: identities = %d, want 1", n)
	}
	if got := f.passkeyIDs(t); len(got) != 2 {
		t.Fatalf("fixture error: passkeys = %v, want 2", got)
	}
	if seeded, extra := f.seededFamilies(t); seeded != 2 || extra != 0 {
		t.Fatalf("fixture error: seeded families = %d (want 2), extra sessions = %d (want 0)", seeded, extra)
	}
	if n := f.trustedCount(t); n != 2 {
		t.Fatalf("fixture error: trusted devices = %d, want 2", n)
	}
	if !f.factorPresent(t) {
		t.Fatalf("fixture error: no MFA factor is armed before the path runs")
	}
	if n := f.recoveryCodeCount(t); n != 2 {
		t.Fatalf("fixture error: recovery codes = %d, want 2", n)
	}
}

// checkCell asserts one cell and names the column, the path and the
// direction, so a failure reads as a row of the table rather than as a
// boolean.
func checkCell(t *testing.T, path, column string, want verdict, isPresent bool) {
	t.Helper()
	if want == notApplicable {
		return
	}
	switch {
	case want == gone && isPresent:
		t.Errorf("%s / %s: the credential SURVIVED, and the matrix says %q — a credential left armed by a remediation path hands the account back the moment the path finishes", path, column, want)
	case want == survives && !isPresent:
		t.Errorf("%s / %s: the credential was SWEPT, and the matrix says %q — this cell is deliberate non-behaviour, and sweeping here breaks a legitimate flow with no attacker in it (see ChangePassword's doc, \"Reading the matrix\")", path, column, want)
	}
}

// sweepMatrix is the table from [auth.Service.ChangePassword]'s doc, in
// executable form. Keep the two in the same order, and change neither
// without the other.
func sweepMatrix() []sweepRow {
	return []sweepRow{
		{
			name: "ChangePassword",
			run: func(t *testing.T, f *sweepFixture) {
				claims, err := f.svc.VerifyAccessToken(f.accessA)
				if err != nil {
					t.Fatalf("VerifyAccessToken: %v", err)
				}
				if err := f.svc.ChangePassword(context.Background(), f.user.ID, claims.SessionID, sweepPassword, sweepNextPass); err != nil {
					t.Fatalf("ChangePassword: %v", err)
				}
			},
			signup: survives, reset: gone, change: gone, magic: gone,
			// An AUTHENTICATED rotation does not disconnect identities and
			// does not destroy passkeys either, and the passkey cell is the
			// easier of the two: this caller proved they hold the current
			// password, and rotating it says nothing about the authenticator
			// in their pocket.
			identity: survives, passkey: survives, trusted: gone, mfa: survives, families: 1,
		},
		{
			name: "ResetPassword",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.ResetPassword(context.Background(), f.resetTok, sweepNextPass); err != nil {
					t.Fatalf("ResetPassword: %v", err)
				}
			},
			signup: survives, reset: gone, change: gone, magic: gone,
			// The two cells this row exists to keep apart. An identity is
			// swept because an attacker can PROVISION one before the victim
			// ever holds the account, so the documented recovery has to take
			// it. A passkey is NOT, because there is no unauthenticated write
			// path to one, because it is bound to hardware the mailbox
			// compromise did not yield — and because this call is
			// unauthenticated, so the person making it may be the attacker
			// and the surviving passkey may be the owner's last door.
			// TestAPasskeyPlantedFromAStolenSessionIsRemovableAfterAReset
			// pins the residual that leaves.
			identity: gone, passkey: survives, trusted: gone, mfa: survives, families: 0,
		},
		{
			name: "LogoutAll",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.LogoutAll(context.Background(), f.user.ID); err != nil {
					t.Fatalf("LogoutAll: %v", err)
				}
			},
			signup: survives, reset: gone, change: gone, magic: gone,
			// It only ever removes ACCESS. A passkey is a credential the user
			// still holds, exactly like the second factor beside it.
			identity: survives, passkey: survives, trusted: gone, mfa: survives, families: 0,
		},
		{
			name: "DeleteAccount",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.DeleteAccount(context.Background(), f.user.ID, "", sweepPassword); err != nil {
					t.Fatalf("DeleteAccount: %v", err)
				}
			},
			// The termination rows sweep by USER, not by purpose, so
			// "signup" goes too — the one column no other row touches.
			signup: gone, reset: gone, change: gone, magic: gone,
			identity: gone, passkey: gone, trusted: gone, mfa: gone, families: 0,
		},
		{
			name: "AnonymizeAccount",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.AnonymizeAccount(context.Background(), f.user.ID, "", sweepPassword); err != nil {
					t.Fatalf("AnonymizeAccount: %v", err)
				}
			},
			// Identical to DeleteAccount's, and asserted from its own
			// fixture: the two postures make their own calls, so a sweep
			// removed from one must fail only that one's cells.
			signup: gone, reset: gone, change: gone, magic: gone,
			identity: gone, passkey: gone, trusted: gone, mfa: gone, families: 0,
		},
		{
			name: "DisableMFA",
			run: func(t *testing.T, f *sweepFixture) {
				claims, err := f.svc.VerifyAccessToken(f.accessA)
				if err != nil {
					t.Fatalf("VerifyAccessToken: %v", err)
				}
				if err := f.svc.DisableMFA(context.Background(), f.user.ID, claims.SessionID, sweepPassword); err != nil {
					t.Fatalf("DisableMFA: %v", err)
				}
			},
			// The mfa cell is the point of the call. The trusted cell is the
			// one that needed arguing: a token whose only meaning is "skip
			// the second factor" is not merely inert once there is none, it
			// is a bypass waiting for the user to re-enrol — and re-enrolment
			// necessarily runs through this method. Everything else is
			// untouched: turning an authenticator off is not a statement that
			// the mailbox or the devices are compromised, and signing the
			// user out of everything for it would be a surprise, not a
			// safeguard.
			signup: survives, reset: survives, change: survives, magic: survives,
			// The passkey cell is not a near-miss of the mfa cell beside it.
			// Turning a TOTP authenticator off says nothing about a hardware
			// credential that is a DOOR rather than a gate on one — and
			// sweeping here could remove the account's last way in, on a
			// method whose whole purpose is to leave the user signed in.
			identity: survives, passkey: survives, trusted: gone, mfa: gone, families: 2,
		},
		{
			name: "UnlinkIdentity",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.UnlinkIdentity(context.Background(), f.user.ID, f.provider); err != nil {
					t.Fatalf("UnlinkIdentity: %v", err)
				}
			},
			// Removing a credential the account was not relying on is not
			// a remediation event for the mailbox: the pending tokens are
			// none of its business. The sessions ARE, because a session
			// minted through the identity would otherwise keep rotating.
			signup: survives, reset: survives, change: survives, magic: survives,
			// Disconnecting a provider takes that provider's rows and nothing
			// else. A passkey is a different credential kind entirely, and it
			// is frequently what keeps the account reachable at all —
			// [auth.Service.hasWayInBesides] counts it, which is what let the
			// unlink above proceed.
			identity: gone, passkey: survives, trusted: survives, mfa: survives, families: 0,
		},
		{
			name: "DeletePasskey",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.DeletePasskey(context.Background(), f.user.ID, f.passkeyA); err != nil {
					t.Fatalf("DeletePasskey: %v", err)
				}
			},
			// UnlinkIdentity's mirror, differing in exactly one cell: an
			// unlink revokes every session and this revokes none. That is
			// argued on the method — an unlink is a categorical statement
			// about a whole credential SOURCE, while this removes one
			// credential out of a set whose other members are still working,
			// and a Session records no credential provenance for a narrower
			// sweep to use. Signing a user out on their phone because they
			// tidied an old laptop off a list is not what that screen says it
			// does.
			signup: survives, reset: survives, change: survives, magic: survives,
			identity: survives, passkey: justThatOne, trusted: survives, mfa: survives, families: 2,
		},
		{
			name: "VerifyEmail (email_change)",
			run: func(t *testing.T, f *sweepFixture) {
				if _, err := f.svc.VerifyEmail(context.Background(), f.changeTok); err != nil {
					t.Fatalf("VerifyEmail(email_change): %v", err)
				}
			},
			// The ADDRESS moved, so both purposes whose tokens are
			// deliverable only to the OLD one go. change is the token this
			// call burns. Sessions are deliberately untouched: this method
			// is unauthenticated by construction.
			signup: survives, reset: gone, change: gone, magic: gone,
			// A passkey is not deliverable to a mailbox, so moving the
			// ADDRESS strands nothing about it.
			identity: survives, passkey: survives, trusted: survives, mfa: survives, families: 2,
		},
		{
			name: "VerifyEmail (signup)",
			run: func(t *testing.T, f *sweepFixture) {
				if _, err := f.svc.VerifyEmail(context.Background(), f.signupTok); err != nil {
					t.Fatalf("VerifyEmail(signup): %v", err)
				}
			},
			// Certifies the address the account already holds and rotates
			// nothing, so a token for that same mailbox is still a token
			// for that same mailbox.
			signup: gone, reset: survives, change: survives, magic: survives,
			identity: survives, passkey: survives, trusted: survives, mfa: survives, families: 2,
		},
		{
			name: "RedeemMagicLink",
			run: func(t *testing.T, f *sweepFixture) {
				if _, err := f.svc.RedeemMagicLink(context.Background(), f.magicTok, "203.0.113.9", "ua"); err != nil {
					t.Fatalf("RedeemMagicLink: %v", err)
				}
			},
			// Burns its own token and nothing else. Signing in on a new
			// device is not a revocation event.
			signup: survives, reset: survives, change: survives, magic: gone,
			identity: survives, passkey: survives, trusted: survives, mfa: survives, families: 2, extraSessions: 1,
		},
		{
			name: "Logout",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.Logout(context.Background(), f.refreshA); err != nil {
					t.Fatalf("Logout: %v", err)
				}
			},
			signup: survives, reset: survives, change: survives, magic: survives,
			identity: survives, passkey: survives, trusted: survives, mfa: survives, families: 1,
		},
		{
			name: "RevokeSession",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.RevokeSession(context.Background(), f.user.ID, f.sessionAID); err != nil {
					t.Fatalf("RevokeSession: %v", err)
				}
			},
			signup: survives, reset: survives, change: survives, magic: survives,
			identity: survives, passkey: survives, trusted: survives, mfa: survives, families: 1,
		},
	}
}

// TestSweepMatrix asserts every cell of the table in
// [auth.Service.ChangePassword]'s doc.
func TestSweepMatrix(t *testing.T) {
	for i, row := range sweepMatrix() {
		t.Run(row.name, func(t *testing.T) {
			f := newSweepFixture(t, fmt.Sprintf("matrix-%d@example.com", i))
			row.run(t, f)

			checkCell(t, row.name, "signup", row.signup, f.present(t, f.signupTok))
			checkCell(t, row.name, "password_reset", row.reset, f.present(t, f.resetTok))
			checkCell(t, row.name, "email_change", row.change, f.present(t, f.changeTok))
			checkCell(t, row.name, "magic_link", row.magic, f.present(t, f.magicTok))
			checkCell(t, row.name, "identity", row.identity, f.identityCount(t) > 0)
			f.checkPasskeyCell(t, row.name, row.passkey)
			checkCell(t, row.name, "trusted device", row.trusted, f.trustedCount(t) > 0)
			// The MFA column is read twice against ONE verdict: a path that
			// took the factor and left the codes has left live credentials
			// for a second factor that no longer exists, and one that did
			// the reverse has left a factor nobody can recover.
			checkCell(t, row.name, "mfa factor", row.mfa, f.factorPresent(t))
			checkCell(t, row.name, "recovery codes", row.mfa, f.recoveryCodeCount(t) > 0)
			if row.trusted == survives {
				if n := f.trustedCount(t); n != 2 {
					t.Errorf("%s / trusted device: %d of the 2 seeded devices survived, want both — a path that took SOME of them is half a sweep, which is the shape of defect this matrix exists to catch", row.name, n)
				}
			}

			seeded, extra := f.seededFamilies(t)
			if seeded != row.families {
				t.Errorf("%s / session: %d of the 2 seeded families survived, want %d", row.name, seeded, row.families)
			}
			if extra != row.extraSessions {
				t.Errorf("%s / session: the path minted %d new session rows, want %d", row.name, extra, row.extraSessions)
			}
		})
	}
}

// TestSweepMatrixIsExhaustive pins the matrix's SHAPE, not its contents: it
// fails if a row is added without a verdict for every column, or if the
// table shrinks below the paths the doc lists. A matrix with a blank cell is
// the exact failure mode this whole file exists to prevent, and Go's zero
// value for verdict is "gone" — a silently-added row would otherwise assert
// something plausible by accident.
func TestSweepMatrixIsExhaustive(t *testing.T) {
	rows := sweepMatrix()
	if len(rows) != 13 {
		t.Fatalf("the matrix has %d rows, and [auth.Service.ChangePassword]'s doc lists 13 — the table and the test must be changed together", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.name] {
			t.Errorf("duplicate row %q", r.name)
		}
		seen[r.name] = true
		if r.families < 0 || r.families > 2 {
			t.Errorf("%s: families = %d, outside the 0..2 the fixture seeds", r.name, r.families)
		}
	}
	for _, want := range []string{
		"ChangePassword", "ResetPassword", "LogoutAll", "DeleteAccount",
		"AnonymizeAccount", "DisableMFA", "UnlinkIdentity", "DeletePasskey",
		"VerifyEmail (email_change)", "VerifyEmail (signup)", "RedeemMagicLink",
		"Logout", "RevokeSession",
	} {
		if !seen[want] {
			t.Errorf("the matrix has no row for %s, and the doc's table does", want)
		}
	}
}

// TestSweepMatrixFailsClosedOnEveryVerificationSweep is the other half of
// every "swept" cell. A sweep that ran and errored must reach the caller:
// the alternative — swallowing it and returning nil — leaves the credential
// armed while telling the caller the remediation succeeded, which is worse
// than not sweeping at all, because nothing prompts a retry.
//
// It covers the three purpose-scoped remediation paths plus the by-user
// sweep the two termination paths use, so no "swept" cell in the table is
// left with its error path unasserted.
func TestSweepMatrixFailsClosedOnEveryVerificationSweep(t *testing.T) {
	paths := []struct {
		name   string
		method string // the Store method scripted to fail
		run    func(f *sweepFixture) error
	}{
		{"ChangePassword", "DeleteVerificationsByUserAndPurpose", func(f *sweepFixture) error {
			claims, err := f.svc.VerifyAccessToken(f.accessA)
			if err != nil {
				return err
			}
			return f.svc.ChangePassword(context.Background(), f.user.ID, claims.SessionID, sweepPassword, sweepNextPass)
		}},
		{"ResetPassword", "DeleteVerificationsByUserAndPurpose", func(f *sweepFixture) error {
			return f.svc.ResetPassword(context.Background(), f.resetTok, sweepNextPass)
		}},
		{"LogoutAll", "DeleteVerificationsByUserAndPurpose", func(f *sweepFixture) error {
			return f.svc.LogoutAll(context.Background(), f.user.ID)
		}},
		{"VerifyEmail (email_change)", "DeleteVerificationsByUserAndPurpose", func(f *sweepFixture) error {
			_, err := f.svc.VerifyEmail(context.Background(), f.changeTok)
			return err
		}},
		{"DeleteAccount", "DeleteVerificationsByUser", func(f *sweepFixture) error {
			return f.svc.DeleteAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
		{"AnonymizeAccount", "DeleteVerificationsByUser", func(f *sweepFixture) error {
			return f.svc.AnonymizeAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
	}

	for i, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			// Seed through a plain store, then swap in one scripted to fail
			// the sweep, so the seeding itself is not the thing that breaks.
			f := newSweepFixture(t, fmt.Sprintf("failclosed-%d@example.com", i))
			rec := &deletionRecorder{AuthStore: f.store, fail: map[string]error{p.method: errCascadeBoom}}
			f.svc = newServiceOver(t, rec, sweepOptions(f.ids, f.mfa, f.creds)...)

			if err := p.run(f); !errors.Is(err, errCascadeBoom) {
				t.Fatalf("%s with %s failing = %v, want the store's own error — a sweep that errors must never be swallowed", p.name, p.method, err)
			}
		})
	}
}

// TestSweepMatrixFailsClosedOnTheIdentitySweep is the identity column's
// half of the same rule, for the three paths whose identity cell says
// "swept". The port is a different one, so it needs a different double.
func TestSweepMatrixFailsClosedOnTheIdentitySweep(t *testing.T) {
	paths := []struct {
		name string
		run  func(f *sweepFixture) error
	}{
		{"ResetPassword", func(f *sweepFixture) error {
			return f.svc.ResetPassword(context.Background(), f.resetTok, sweepNextPass)
		}},
		{"DeleteAccount", func(f *sweepFixture) error {
			return f.svc.DeleteAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
		{"AnonymizeAccount", func(f *sweepFixture) error {
			return f.svc.AnonymizeAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
	}

	for i, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			f := newSweepFixture(t, fmt.Sprintf("idfailclosed-%d@example.com", i))
			f.svc = newServiceOver(t, f.store,
				auth.WithIdentityStore(failingDeleteIdentityStore{f.ids}),
				auth.WithMFAStore(f.mfa),
				auth.WithCredentialStore(f.creds))

			if err := p.run(f); !errors.Is(err, errCascadeBoom) {
				t.Fatalf("%s with DeleteIdentity failing = %v, want the store's own error — an identity left standing is a live credential the path did not remove", p.name, err)
			}
		})
	}
}

// failingDeleteIdentityStore delegates everything except DeleteIdentity,
// which is the one call the identity sweep makes.
type failingDeleteIdentityStore struct {
	*memory.IdentityStore
}

func (s failingDeleteIdentityStore) DeleteIdentity(context.Context, string) error {
	return errCascadeBoom
}

// TestSweepMatrixIdentityColumnIsNotConfusedWithTheSessionColumn guards the
// one shape a single-fixture matrix could get wrong: UnlinkIdentity and
// LogoutAll both end with every session gone, so a bug that made LogoutAll
// sweep identities (or UnlinkIdentity sweep verifications) would still leave
// a plausible-looking store. This asserts the two rows differ where the
// table says they differ.
func TestSweepMatrixIdentityColumnIsNotConfusedWithTheSessionColumn(t *testing.T) {
	logoutAll := newSweepFixture(t, "column-logoutall@example.com")
	if err := logoutAll.svc.LogoutAll(context.Background(), logoutAll.user.ID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	if n := logoutAll.identityCount(t); n != 1 {
		t.Errorf("LogoutAll left %d identities, want 1 — it revokes sessions on the authority of a caller who is already signed in, and does not disconnect connected accounts", n)
	}

	unlink := newSweepFixture(t, "column-unlink@example.com")
	if err := unlink.svc.UnlinkIdentity(context.Background(), unlink.user.ID, unlink.provider); err != nil {
		t.Fatalf("UnlinkIdentity: %v", err)
	}
	if !unlink.present(t, unlink.magicTok) || !unlink.present(t, unlink.resetTok) {
		t.Errorf("UnlinkIdentity swept a pending verification — disconnecting a provider is not a mailbox remediation event")
	}
}

// TestVerifyEmailChangeSweepsTheMagicLinkInTheAbandonedMailbox is the cell
// that was missing until this branch, spelled out as the scenario rather
// than as a row: it is the same defect milestone 2 shipped for
// "email_change", one credential kind later.
//
// A user moves their address away from a mailbox they no longer trust. A
// magic link minted for the OLD address is still live, and
// [auth.Service.RedeemMagicLink] does not refuse a link whose
// [auth.Verification].Email no longer matches the account — it merely
// declines to stamp EmailVerifiedAt and signs the holder in anyway. Without
// this sweep, whoever holds that mailbox has a full session on the account
// at its NEW address for the remainder of the link's TTL.
func TestVerifyEmailChangeSweepsTheMagicLinkInTheAbandonedMailbox(t *testing.T) {
	f := newSweepFixture(t, "abandoned@example.com")
	ctx := context.Background()

	moved, err := f.svc.VerifyEmail(ctx, f.changeTok)
	if err != nil {
		t.Fatalf("VerifyEmail(email_change): %v", err)
	}
	if moved.Email != f.newAddress {
		t.Fatalf("address after the change = %q, want %q", moved.Email, f.newAddress)
	}

	if _, err := f.svc.RedeemMagicLink(ctx, f.magicTok, "203.0.113.9", "ua"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("redeeming a link minted for the ABANDONED address = %v, want ErrVerificationNotFound — a magic link is not a step towards a credential, it IS one", err)
	}
}

// TestVerifyEmailChangeFailsClosedWhenTheMagicLinkSweepFails is the new
// sweep's own fail-closed half, isolated from the reset sweep beside it so a
// failure names which of the two did not report.
func TestVerifyEmailChangeFailsClosedWhenTheMagicLinkSweepFails(t *testing.T) {
	f := newSweepFixture(t, "abandoned-failclosed@example.com")

	rec := &purposeFailStore{AuthStore: f.store, failPurpose: auth.PurposeMagicLink}
	svc := newServiceOver(t, rec, sweepOptions(f.ids, f.mfa, f.creds)...)

	if _, err := svc.VerifyEmail(context.Background(), f.changeTok); !errors.Is(err, errCascadeBoom) {
		t.Fatalf("VerifyEmail(email_change) with the magic_link sweep failing = %v, want the store's own error", err)
	}
	if !rec.sawPasswordReset {
		t.Errorf("the password_reset sweep did not run at all — this test would then be asserting the wrong sweep's failure")
	}
}

// purposeFailStore fails DeleteVerificationsByUserAndPurpose for ONE purpose
// and delegates every other call, so a fail-closed test can name which sweep
// it broke. sawPasswordReset records that the neighbouring sweep really ran,
// which is what keeps this test from passing for the wrong reason.
type purposeFailStore struct {
	*memory.AuthStore
	failPurpose      string
	sawPasswordReset bool
}

func (s *purposeFailStore) DeleteVerificationsByUserAndPurpose(ctx context.Context, userID, purpose string) error {
	if purpose == auth.PurposePasswordReset {
		s.sawPasswordReset = true
	}
	if purpose == s.failPurpose {
		return errCascadeBoom
	}
	return s.AuthStore.DeleteVerificationsByUserAndPurpose(ctx, userID, purpose)
}

// --- the two columns this branch added -------------------------------------

// errMFABoom is the failure the two new columns' fail-closed doubles inject.
var errMFABoom = errors.New("mfa store exploded")

// failingTrustedSweep delegates everything except the by-user device sweep.
type failingTrustedSweep struct {
	*memory.MFAStore
}

func (failingTrustedSweep) DeleteTrustedDevicesByUser(context.Context, string) error {
	return errMFABoom
}

// failingMFASweep fails the recovery-code half of the MFA sweep and delegates
// everything else, including the trusted-device sweep — so a failure here
// names the MFA column and not its neighbour.
type failingMFASweep struct {
	*memory.MFAStore
}

func (failingMFASweep) ReplaceRecoveryCodes(context.Context, string, []auth.RecoveryCode) error {
	return errMFABoom
}

// TestSweepMatrixFailsClosedOnTheTrustedDeviceSweep is the trusted-device
// column's half of the rule every "swept" cell carries: a sweep that ran and
// errored must reach the caller. Swallowing it would leave a live
// second-factor bypass behind while telling the user their remediation
// succeeded — worse than not sweeping at all, because nothing prompts a
// retry.
func TestSweepMatrixFailsClosedOnTheTrustedDeviceSweep(t *testing.T) {
	paths := []struct {
		name string
		run  func(f *sweepFixture) error
	}{
		{"ChangePassword", func(f *sweepFixture) error {
			claims, err := f.svc.VerifyAccessToken(f.accessA)
			if err != nil {
				return err
			}
			return f.svc.ChangePassword(context.Background(), f.user.ID, claims.SessionID, sweepPassword, sweepNextPass)
		}},
		{"ResetPassword", func(f *sweepFixture) error {
			return f.svc.ResetPassword(context.Background(), f.resetTok, sweepNextPass)
		}},
		{"LogoutAll", func(f *sweepFixture) error {
			return f.svc.LogoutAll(context.Background(), f.user.ID)
		}},
		{"DeleteAccount", func(f *sweepFixture) error {
			return f.svc.DeleteAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
		{"AnonymizeAccount", func(f *sweepFixture) error {
			return f.svc.AnonymizeAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
		{"DisableMFA", func(f *sweepFixture) error {
			return f.svc.DisableMFA(context.Background(), f.user.ID, "", sweepPassword)
		}},
	}

	for i, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			f := newSweepFixture(t, fmt.Sprintf("tdfailclosed-%d@example.com", i))
			f.svc = newServiceOver(t, f.store,
				auth.WithIdentityStore(f.ids),
				auth.WithMFAStore(failingTrustedSweep{f.mfa}),
				auth.WithCredentialStore(f.creds))

			if err := p.run(f); !errors.Is(err, errMFABoom) {
				t.Fatalf("%s with DeleteTrustedDevicesByUser failing = %v, want the store's own error — a trusted device left standing is a live second-factor bypass the path did not remove", p.name, err)
			}
		})
	}
}

// TestSweepMatrixFailsClosedOnTheMFASweep is the same rule for the MFA
// column, on the two TERMINATION rows that fill it in.
func TestSweepMatrixFailsClosedOnTheMFASweep(t *testing.T) {
	paths := []struct {
		name string
		run  func(f *sweepFixture) error
	}{
		{"DeleteAccount", func(f *sweepFixture) error {
			return f.svc.DeleteAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
		{"AnonymizeAccount", func(f *sweepFixture) error {
			return f.svc.AnonymizeAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
	}

	for i, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			f := newSweepFixture(t, fmt.Sprintf("mfafailclosed-%d@example.com", i))
			f.svc = newServiceOver(t, f.store,
				auth.WithIdentityStore(f.ids),
				auth.WithMFAStore(failingMFASweep{f.mfa}),
				auth.WithCredentialStore(f.creds))

			if err := p.run(f); !errors.Is(err, errMFABoom) {
				t.Fatalf("%s with ReplaceRecoveryCodes failing = %v, want the store's own error — recovery codes left behind after an account ends are live credentials for a factor nobody owns", p.name, err)
			}
		})
	}
}

// TestSweepsAreNoOpsWithoutTheOptionalStores pins the optional ports' other
// half: a Service built with no [auth.WithMFAStore] and no
// [auth.WithCredentialStore] has no devices, no factors and no passkeys to
// sweep, so every row of the matrix must still run to completion rather than
// failing on a port that is not there. It is the same stated limit
// sweepIdentities carries, and it is the failure mode a missing nil check
// would produce for EVERY deployment that enables neither — which is most of
// them, and none of which would be covered by any other test in this file,
// since every fixture above wires all three.
func TestSweepsAreNoOpsWithoutTheOptionalStores(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	u := mustSignUp(t, svc, "no-mfa-store@example.com", sweepPassword)
	_, access, _ := mustLogin(t, svc, "no-mfa-store@example.com", sweepPassword)
	claims, err := svc.VerifyAccessToken(access)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	if err := svc.ChangePassword(ctx, u.ID, claims.SessionID, sweepPassword, sweepNextPass); err != nil {
		t.Fatalf("ChangePassword with no MFAStore = %v, want nil", err)
	}
	if err := svc.LogoutAll(ctx, u.ID); err != nil {
		t.Fatalf("LogoutAll with no MFAStore = %v, want nil", err)
	}
	if err := svc.ResetPassword(ctx, mustRequestReset(t, svc, "no-mfa-store@example.com"), sweepPassword); err != nil {
		t.Fatalf("ResetPassword with neither optional store = %v, want nil", err)
	}
	if err := svc.DeleteAccount(ctx, u.ID, "", sweepPassword); err != nil {
		t.Fatalf("DeleteAccount with neither optional store = %v, want nil", err)
	}
	if _, err := store.FindUserByID(ctx, u.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("the account survived DeleteAccount: %v", err)
	}

	// The soft posture separately, since it makes its own calls.
	other := mustSignUp(t, svc, "no-cred-store@example.com", sweepPassword)
	if err := svc.AnonymizeAccount(ctx, other.ID, "", sweepPassword); err != nil {
		t.Fatalf("AnonymizeAccount with neither optional store = %v, want nil", err)
	}
}

// mustRequestReset mints a password_reset token, failing the test if the
// address is not one the Service knows.
func mustRequestReset(t *testing.T, svc *auth.Service, email string) string {
	t.Helper()
	tok, ok, err := svc.RequestPasswordReset(context.Background(), email, "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset(%q) = (_, %v, %v), want a token", email, ok, err)
	}
	return tok
}

// TestChangePasswordRevokesADeviceThatWasActuallyTrusted is the realism the
// matrix fixture gives up when it seeds its devices straight into the store.
//
// Here the device is minted the way an application mints one — a confirmed
// factor, a session that has just completed [auth.Service.CompleteMFA], and
// [auth.Service.TrustThisDevice] — and the assertion is not that a row
// vanished but that the TOKEN stops working: after the password change the
// same cookie no longer skips the second factor.
func TestChangePasswordRevokesADeviceThatWasActuallyTrusted(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()

	e := enrolConfirmed(t, f, "sweep-real@example.com")
	device := trustDevice(t, f, e, "sweep-real@example.com", "the laptop")

	// It works before the rotation, so the assertion after it is about the
	// sweep and not about the device never having worked.
	before, err := f.svc.LoginWithTrustedDevice(ctx, "sweep-real@example.com", validPassword, "203.0.113.7", "agent", device)
	if err != nil {
		t.Fatalf("LoginWithTrustedDevice before the rotation: %v", err)
	}
	if before.MFA != nil {
		t.Fatal("fixture error: the device did not skip the challenge before the rotation")
	}

	sid := sessionIDOf(t, f.svc, before.AccessToken)
	next := "Another-Good-Password-7!"
	if err := f.svc.ChangePassword(ctx, e.user.ID, sid, validPassword, next); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	after, err := f.svc.LoginWithTrustedDevice(ctx, "sweep-real@example.com", next, "203.0.113.7", "agent", device)
	if err != nil {
		t.Fatalf("LoginWithTrustedDevice after the rotation = %v, want a challenge and no error", err)
	}
	if after.MFA == nil {
		t.Fatal("the trusted device still skipped the second factor after ChangePassword — the whole point of the sweep is that a rotation leaves nothing armed that can quietly undo it")
	}
}

// --- the eighth column ------------------------------------------------------

// failingPasskeySweep delegates everything except the by-user credential
// sweep, so a fail-closed failure names the passkey column and not a
// neighbour.
type failingPasskeySweep struct {
	*memory.CredentialStore
}

func (failingPasskeySweep) DeleteCredentialsByUser(context.Context, string) error {
	return errPasskeyBoom
}

// errPasskeyBoom is the failure the passkey column's fail-closed double
// injects.
var errPasskeyBoom = errors.New("credential store exploded")

// TestSweepMatrixFailsClosedOnThePasskeySweep is the passkey column's half of
// the rule every "swept" cell carries: a sweep that ran and errored must
// reach the caller. Swallowing it here is the worst version of that mistake
// in the whole table — the caller is deleting an account, the sessions and
// verifications are already gone, and a swallowed error would report a
// completed deletion while leaving behind the one surviving credential that
// needs no password, no mailbox and no second factor to use.
func TestSweepMatrixFailsClosedOnThePasskeySweep(t *testing.T) {
	paths := []struct {
		name string
		run  func(f *sweepFixture) error
	}{
		{"DeleteAccount", func(f *sweepFixture) error {
			return f.svc.DeleteAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
		{"AnonymizeAccount", func(f *sweepFixture) error {
			return f.svc.AnonymizeAccount(context.Background(), f.user.ID, "", sweepPassword)
		}},
	}

	for i, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			f := newSweepFixture(t, fmt.Sprintf("pkfailclosed-%d@example.com", i))
			f.svc = newServiceOver(t, f.store,
				auth.WithIdentityStore(f.ids),
				auth.WithMFAStore(f.mfa),
				auth.WithCredentialStore(failingPasskeySweep{f.creds}))

			if err := p.run(f); !errors.Is(err, errPasskeyBoom) {
				t.Fatalf("%s with DeleteCredentialsByUser failing = %v, want the store's own error — a passkey left standing after a termination path is a way in that needs nothing else at all", p.name, err)
			}
			// The user row must still be there to retry against. This is the
			// step order's promise, and it is what makes returning the error
			// safe rather than merely honest.
			if _, err := f.store.FindUserByID(context.Background(), f.user.ID); err != nil {
				t.Fatalf("the account is gone after a failed passkey sweep (%v) — the sweep runs BEFORE the user row precisely so a failure leaves something to retry against", err)
			}
		})
	}
}

// TestAPasskeyDoesNotOutliveTheAccountItAuthenticated is the scenario the
// eighth column was added for, and it replaces the test that used to pin the
// gap's absence.
//
// It states the harm rather than the row count: under a NON-RANDOM
// [auth.WithIDGenerator] — a supported configuration, which is what makes
// "ids are never reused" a property of the default generator and not of this
// package — the id a deleted account held is handed to the next account. If
// the credential rows survived, that account would inherit a working passkey
// it never registered, and [auth.Service.FinishPasskeyLogin] would sign its
// holder in with no password, no mailbox and no second factor.
func TestAPasskeyDoesNotOutliveTheAccountItAuthenticated(t *testing.T) {
	ctx := context.Background()
	creds := memory.NewCredentialStore()

	// An id generator that hands the SAME user id out twice — once to each
	// SignUp below — and unique values to everything else, since sessions,
	// verifications and credential rows all draw from the same generator. The
	// switch is armed by the test immediately before each SignUp rather than
	// by a call count, so the fixture does not depend on how many ids the
	// calls in between happen to consume.
	var handedOut int
	giveReused := true
	reused := "reused-user-id"
	svc, _ := newTestService(t,
		auth.WithCredentialStore(creds),
		auth.WithIDGenerator(func() string {
			handedOut++
			if giveReused {
				giveReused = false
				return reused
			}
			return fmt.Sprintf("uid-%d", handedOut)
		}))

	first := mustSignUp(t, svc, "inheritor-1@example.com", sweepPassword)
	if first.ID != reused {
		t.Fatalf("fixture error: the first account got id %q, want %q", first.ID, reused)
	}
	registerPasskey(t, svc, first.ID, newCred('i'))

	if err := svc.DeleteAccount(ctx, first.ID, "", sweepPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	// The successor: a different person, the same id.
	giveReused = true
	second := mustSignUp(t, svc, "inheritor-2@example.com", sweepPassword)
	if second.ID != reused {
		t.Fatalf("fixture error: the second account got id %q, want the SAME id %q — without the reuse this test asserts nothing", second.ID, reused)
	}

	inherited, err := svc.ListPasskeys(ctx, second.ID)
	if err != nil {
		t.Fatalf("ListPasskeys: %v", err)
	}
	if len(inherited) != 0 {
		t.Fatalf("the new account inherited %d passkeys it never registered: %+v", len(inherited), inherited)
	}

	// And the credential is not merely invisible to the list: the login path
	// resolves by the AUTHENTICATOR's id, which is the route that would
	// actually sign the wrong person in.
	challenge := mustBeginLogin(t, svc)
	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    challenge,
		CredentialID: credID('i'),
		SignCount:    1,
	}, "203.0.113.9", "agent")
	if !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("asserting the DELETED account's authenticator = %v, want ErrCredentialNotFound — a surviving credential row signs its holder into whoever now holds that id", err)
	}
	assertNoLoginResult(t, res)
}

// TestAPasskeyPlantedFromAStolenSessionIsRemovableAfterAReset pins the
// residual the passkey column's ResetPassword cell deliberately accepts, and
// the property that makes accepting it defensible.
//
// The attack is real: [auth.Service.FinishPasskeyRegistration] is step-up
// gated only for an account with a CONFIRMED second factor, so whoever holds
// a live session on an ordinary account can register their own authenticator.
// The reset does not sweep it — see the matrix's "The passkey column, and why
// ResetPassword does not sweep it" — so the owner's remedy is
// [auth.Service.ListPasskeys] and [auth.Service.DeletePasskey], and that
// remedy must not be refusable.
//
// It cannot be. [auth.Service.hasWayInBesides] counts the working password
// the reset has just written, so [auth.ErrLastCredential] cannot fire — even
// on an account that had NO password before and no identity, and even under
// [auth.WithRequireVerifiedEmail](true), because the completed reset stamps
// the address too. That last clause is the one worth a test: without the
// stamp this would be an account holding a hash its own configuration
// refuses, and the removal WOULD be refused as the last way in.
func TestAPasskeyPlantedFromAStolenSessionIsRemovableAfterAReset(t *testing.T) {
	ctx := context.Background()
	creds := memory.NewCredentialStore()
	svc, store := newTestService(t,
		auth.WithCredentialStore(creds),
		auth.WithRequireVerifiedEmail(true))

	// A password-less account: nothing but the planted passkey opens it, which
	// is the hardest case for the removal below.
	const email = "planted@example.com"
	user, err := store.CreateUser(ctx, auth.UserBase{ID: "planted-user", Email: email, CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	planted := registerPasskey(t, svc, user.ID, newCred('x'))

	// The owner recovers through the mailbox.
	tok, ok, err := svc.RequestPasswordReset(ctx, email, "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset = (_, %v, %v), want a token", ok, err)
	}
	if err := svc.ResetPassword(ctx, tok, sweepNextPass); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// The passkey survived, which is the cell under test rather than a
	// surprise: TestSweepMatrix/ResetPassword says so, and this is the same
	// claim from the attacker's side.
	rows, err := svc.ListPasskeys(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListPasskeys: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != planted.ID {
		t.Fatalf("passkeys after the reset = %+v, want the planted one — the matrix's ResetPassword row says this cell is not swept", rows)
	}

	// And it is removable, which is what makes the non-sweep a recovery
	// procedure rather than an apology.
	if err := svc.DeletePasskey(ctx, user.ID, planted.ID); err != nil {
		t.Fatalf("DeletePasskey after the reset = %v, want nil — the reset wrote a working password AND certified the address, so hasWayInBesides must count it and ErrLastCredential must not fire", err)
	}
	if rows, err := svc.ListPasskeys(ctx, user.ID); err != nil || len(rows) != 0 {
		t.Fatalf("passkeys after the removal = %v (%v), want none", rows, err)
	}

	// The owner is left with a way in, which is the other half of the claim:
	// removing the attacker's credential must not have locked them out.
	if _, _, refresh := mustLogin(t, svc, email, sweepNextPass); refresh == "" {
		t.Fatal("the owner cannot log in after removing the planted passkey")
	}
}

// TestTerminationSweepsAPasskeyOnlyAccount is the ErrLastCredential half of
// the eighth column, and the one case where getting the arithmetic wrong
// would be silent rather than loud.
//
// [auth.Service.hasWayInBesides] spans all three credential kinds, and
// [auth.ErrLastCredential] is the refusal it feeds: a user may not remove the
// credential that is the only thing opening their account. A termination path
// must be exempt from that rule, because refusing to remove the last
// credential there would preserve EXACTLY what the caller is destroying — and
// would make a passkey-only account permanently undeletable, on a method
// whose whole purpose is to honour "delete my account".
//
// That is why [auth.Service.sweepCredentials] calls the port's by-user delete
// and not [auth.Service.DeletePasskey] in a loop, and this test is what would
// catch the loop: the account below is refused its own removal first, which
// is what makes the deletion afterwards a statement about the exemption
// rather than about an account that had another door all along.
func TestTerminationSweepsAPasskeyOnlyAccount(t *testing.T) {
	ctx := context.Background()

	newPasskeyOnly := func(t *testing.T, email string) (*auth.Service, *memory.AuthStore, *memory.CredentialStore, auth.UserBase, auth.Credential) {
		t.Helper()
		creds := memory.NewCredentialStore()
		svc, store := newTestService(t, auth.WithCredentialStore(creds))
		// No password hash and no identity store: the passkey is the only
		// thing in this package that can sign this account in.
		u, err := store.CreateUser(ctx, auth.UserBase{ID: "only-" + email, Email: email, CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		only := registerPasskey(t, svc, u.ID, newCred('z'))

		// The premise, asserted rather than assumed: this credential really
		// is the last way in, so the user cannot remove it themselves.
		if err := svc.DeletePasskey(ctx, u.ID, only.ID); !errors.Is(err, auth.ErrLastCredential) {
			t.Fatalf("fixture error: DeletePasskey on the only credential = %v, want ErrLastCredential — if the account had another way in, the deletion below would prove nothing", err)
		}
		return svc, store, creds, u, only
	}

	t.Run("DeleteAccount", func(t *testing.T) {
		svc, store, creds, u, _ := newPasskeyOnly(t, "passkey-only-hard@example.com")

		if err := svc.DeleteAccount(ctx, u.ID, "", ""); err != nil {
			t.Fatalf("DeleteAccount on a passkey-only account = %v, want nil — ErrLastCredential must not reach a caller that is removing the account", err)
		}
		if rows, err := creds.ListCredentialsByUser(ctx, u.ID); err != nil || len(rows) != 0 {
			t.Fatalf("credentials after DeleteAccount = %v (%v), want none", rows, err)
		}
		if _, err := store.FindUserByID(ctx, u.ID); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("the account survived DeleteAccount: %v", err)
		}
	})

	t.Run("AnonymizeAccount", func(t *testing.T) {
		svc, store, creds, u, _ := newPasskeyOnly(t, "passkey-only-soft@example.com")

		if err := svc.AnonymizeAccount(ctx, u.ID, "", ""); err != nil {
			t.Fatalf("AnonymizeAccount on a passkey-only account = %v, want nil", err)
		}
		if rows, err := creds.ListCredentialsByUser(ctx, u.ID); err != nil || len(rows) != 0 {
			t.Fatalf("credentials after AnonymizeAccount = %v (%v), want none — the row SURVIVES this posture with its password cleared, so a passkey left behind would be the only thing able to authenticate an account the deployment has closed", rows, err)
		}
		stamped, err := store.FindUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("FindUserByID: %v", err)
		}
		if stamped.DeletedAt == nil {
			t.Fatal("the account was not stamped")
		}
	})
}
