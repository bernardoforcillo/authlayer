package auth_test

import (
	"context"
	"errors"
	"fmt"
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
// doc, "The sweep matrix". Twelve paths against seven credential kinds, and
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
)

func (v verdict) String() string {
	switch v {
	case gone:
		return "swept"
	case survives:
		return "not swept"
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
// purposes, one linked external identity, and two session families.
type sweepFixture struct {
	svc   *auth.Service
	store *memory.AuthStore
	ids   *memory.IdentityStore
	mfa   *memory.MFAStore

	user auth.UserBase

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
	svc := newServiceOver(t, store, sweepOptions(ids, mfa)...)

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

	f := &sweepFixture{
		svc: svc, store: store, ids: ids, mfa: mfa, user: user,
		signupTok: res.VerifyToken, resetTok: resetTok, changeTok: changeTok, magicTok: magicTok,
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
// fail-closed test that swaps one store out keeps the other two ports. A
// rebuild that forgot [auth.WithMFAStore] would make both new columns' sweeps
// silent no-ops and every one of their cells pass for the wrong reason.
func sweepOptions(ids *memory.IdentityStore, mfa *memory.MFAStore) []auth.Option {
	return []auth.Option{auth.WithIdentityStore(ids), auth.WithMFAStore(mfa)}
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
			identity: survives, trusted: gone, mfa: survives, families: 1,
		},
		{
			name: "ResetPassword",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.ResetPassword(context.Background(), f.resetTok, sweepNextPass); err != nil {
					t.Fatalf("ResetPassword: %v", err)
				}
			},
			signup: survives, reset: gone, change: gone, magic: gone,
			identity: gone, trusted: gone, mfa: survives, families: 0,
		},
		{
			name: "LogoutAll",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.LogoutAll(context.Background(), f.user.ID); err != nil {
					t.Fatalf("LogoutAll: %v", err)
				}
			},
			signup: survives, reset: gone, change: gone, magic: gone,
			identity: survives, trusted: gone, mfa: survives, families: 0,
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
			identity: gone, trusted: gone, mfa: gone, families: 0,
		},
		{
			name: "AnonymizeAccount",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.AnonymizeAccount(context.Background(), f.user.ID, "", sweepPassword); err != nil {
					t.Fatalf("AnonymizeAccount: %v", err)
				}
			},
			signup: gone, reset: gone, change: gone, magic: gone,
			identity: gone, trusted: gone, mfa: gone, families: 0,
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
			identity: survives, trusted: gone, mfa: gone, families: 2,
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
			identity: gone, trusted: survives, mfa: survives, families: 0,
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
			identity: survives, trusted: survives, mfa: survives, families: 2,
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
			identity: survives, trusted: survives, mfa: survives, families: 2,
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
			identity: survives, trusted: survives, mfa: survives, families: 2, extraSessions: 1,
		},
		{
			name: "Logout",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.Logout(context.Background(), f.refreshA); err != nil {
					t.Fatalf("Logout: %v", err)
				}
			},
			signup: survives, reset: survives, change: survives, magic: survives,
			identity: survives, trusted: survives, mfa: survives, families: 1,
		},
		{
			name: "RevokeSession",
			run: func(t *testing.T, f *sweepFixture) {
				if err := f.svc.RevokeSession(context.Background(), f.user.ID, f.sessionAID); err != nil {
					t.Fatalf("RevokeSession: %v", err)
				}
			},
			signup: survives, reset: survives, change: survives, magic: survives,
			identity: survives, trusted: survives, mfa: survives, families: 1,
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
// table shrinks below the eleven paths the doc lists. A matrix with a blank
// cell is the exact failure mode this whole file exists to prevent, and Go's
// zero value for verdict is "gone" — a silently-added row would otherwise
// assert something plausible by accident.
func TestSweepMatrixIsExhaustive(t *testing.T) {
	rows := sweepMatrix()
	if len(rows) != 12 {
		t.Fatalf("the matrix has %d rows, and [auth.Service.ChangePassword]'s doc lists 12 — the table and the test must be changed together", len(rows))
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
		"AnonymizeAccount", "DisableMFA", "UnlinkIdentity", "VerifyEmail (email_change)",
		"VerifyEmail (signup)", "RedeemMagicLink", "Logout", "RevokeSession",
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
			f.svc = newServiceOver(t, rec, sweepOptions(f.ids, f.mfa)...)

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
			f.svc = newServiceOver(t, f.store, auth.WithIdentityStore(failingDeleteIdentityStore{f.ids}), auth.WithMFAStore(f.mfa))

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
	svc := newServiceOver(t, rec, sweepOptions(f.ids, f.mfa)...)

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
				auth.WithMFAStore(failingTrustedSweep{f.mfa}))

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
				auth.WithMFAStore(failingMFASweep{f.mfa}))

			if err := p.run(f); !errors.Is(err, errMFABoom) {
				t.Fatalf("%s with ReplaceRecoveryCodes failing = %v, want the store's own error — recovery codes left behind after an account ends are live credentials for a factor nobody owns", p.name, err)
			}
		})
	}
}

// TestSweepsAreNoOpsWithoutAnMFAStore pins the optional port's other half: a
// Service built with no [auth.WithMFAStore] has no devices and no factors to
// sweep, so every row of the matrix must still run to completion rather than
// failing on a port that is not there. It is the same stated limit
// sweepIdentities carries, and it is the failure mode a missing nil check
// would produce for EVERY deployment that never enables MFA.
func TestSweepsAreNoOpsWithoutAnMFAStore(t *testing.T) {
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
	if err := svc.DeleteAccount(ctx, u.ID, "", sweepNextPass); err != nil {
		t.Fatalf("DeleteAccount with no MFAStore = %v, want nil", err)
	}
	if _, err := store.FindUserByID(ctx, u.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("the account survived DeleteAccount: %v", err)
	}
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

// TestTheMatrixHasNoPasskeyColumnAndThatIsDisclosed pins a GAP, not a
// decision, so that it stays visible instead of being rediscovered.
//
// A [auth.Credential] registered through
// [auth.Service.FinishPasskeyRegistration] survives every row of the table,
// the two TERMINATION rows included: a hard DeleteAccount leaves the
// credential rows behind, filed under a user id that no longer resolves, and
// a later account issued that id under a non-random [auth.WithIDGenerator]
// would inherit a working passkey it never registered. That is the identical
// argument DeleteAccount's step 6 makes for sweeping identities.
//
// It is not closed here because [auth.CredentialStore] has no by-user delete
// to call — closing it is a change to the passkey port, not to this row set.
// Until then a deployment offering passkeys removes them from
// [auth.WithAccountDeletionHook]. When that method lands, this test should
// FAIL, and the right response is to give passkeys a column rather than to
// delete the test.
func TestTheMatrixHasNoPasskeyColumnAndThatIsDisclosed(t *testing.T) {
	ctx := context.Background()
	creds := memory.NewCredentialStore()
	svc, _ := newTestService(t, auth.WithCredentialStore(creds))

	u := mustSignUp(t, svc, "passkey-gap@example.com", sweepPassword)
	registerPasskey(t, svc, u.ID, newCred('g'))
	if rows, err := creds.ListCredentialsByUser(ctx, u.ID); err != nil || len(rows) != 1 {
		t.Fatalf("fixture error: credentials = %v (%v), want 1", rows, err)
	}

	if err := svc.DeleteAccount(ctx, u.ID, "", sweepPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	rows, err := creds.ListCredentialsByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListCredentialsByUser: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("passkeys after DeleteAccount = %d, want the 1 this DISCLOSED GAP leaves behind.\n"+
			"If a by-user passkey sweep has since landed, this test has done its job: give passkeys a COLUMN in auth.Service.ChangePassword's matrix, fill in every row, and replace this test with those cells — do not simply delete it.", len(rows))
	}
}
