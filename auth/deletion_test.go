package auth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// ============================================================
// DeleteAccount
// ============================================================

// errCascadeBoom is the arbitrary, non-sentinel Store error this file
// injects to park the cascade part-way through. It is deliberately not one
// of the package's sentinels: the point of the fail-safe tests is what the
// STORE state looks like after an outage the service cannot interpret, not
// how a particular sentinel is classified.
var errCascadeBoom = errors.New("boom: simulated store outage mid-cascade")

// errHookBoom is what a deletion hook returns when the application's own
// cleanup could not be completed.
var errHookBoom = errors.New("boom: the application could not delete its own rows")

// --- deletionRecorder: wraps memory.AuthStore and records, in order, every
// call to every MUTATING method on the port — not merely the three the
// cascade is expected to make. That breadth is the point: "the hook fires
// before any authlayer row is written" is a claim about every write, so a
// test that only watched the three deletes would pass just as happily if
// DeleteAccount had stamped a row somewhere first. The hook under test
// records into the same log through record, so one slice orders the hook
// against the writes.
//
// fail nominates methods that must return an error instead of delegating;
// the call is still recorded, because it did happen. ---

type deletionRecorder struct {
	*memory.AuthStore

	mu     sync.Mutex
	events []string
	fail   map[string]error
}

func newDeletionRecorder() *deletionRecorder {
	return &deletionRecorder{AuthStore: memory.NewAuthStore(), fail: map[string]error{}}
}

// record appends a name to the log. Exported to this file's tests so the
// hook closure can mark its own position in the same sequence.
func (s *deletionRecorder) record(name string) {
	s.mu.Lock()
	s.events = append(s.events, name)
	s.mu.Unlock()
}

// enter records a store call and reports the error it was scripted to fail
// with, if any.
func (s *deletionRecorder) enter(name string) error {
	s.mu.Lock()
	s.events = append(s.events, name)
	err := s.fail[name]
	s.mu.Unlock()
	return err
}

func (s *deletionRecorder) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.events))
	copy(out, s.events)
	return out
}

// reset clears the log, so a test can seed an account through the ordinary
// service methods (which write plenty) and then observe only what
// DeleteAccount itself does.
func (s *deletionRecorder) reset() {
	s.mu.Lock()
	s.events = nil
	s.mu.Unlock()
}

func (s *deletionRecorder) CreateUser(ctx context.Context, u auth.UserBase) (auth.UserBase, error) {
	if err := s.enter("CreateUser"); err != nil {
		return auth.UserBase{}, err
	}
	return s.AuthStore.CreateUser(ctx, u)
}

func (s *deletionRecorder) MarkEmailVerified(ctx context.Context, userID, email string, now time.Time) error {
	if err := s.enter("MarkEmailVerified"); err != nil {
		return err
	}
	return s.AuthStore.MarkEmailVerified(ctx, userID, email, now)
}

func (s *deletionRecorder) UpdateUserPassword(ctx context.Context, userID, passwordHash string, now time.Time) error {
	if err := s.enter("UpdateUserPassword"); err != nil {
		return err
	}
	return s.AuthStore.UpdateUserPassword(ctx, userID, passwordHash, now)
}

func (s *deletionRecorder) UpdateUserEmail(ctx context.Context, userID, email string, now time.Time) error {
	if err := s.enter("UpdateUserEmail"); err != nil {
		return err
	}
	return s.AuthStore.UpdateUserEmail(ctx, userID, email, now)
}

func (s *deletionRecorder) DeleteUser(ctx context.Context, userID string) error {
	if err := s.enter("DeleteUser"); err != nil {
		return err
	}
	return s.AuthStore.DeleteUser(ctx, userID)
}

func (s *deletionRecorder) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	if err := s.enter("CreateSession"); err != nil {
		return auth.Session{}, err
	}
	return s.AuthStore.CreateSession(ctx, sess)
}

func (s *deletionRecorder) CreateSuccessorSession(ctx context.Context, predecessorID string, sess auth.Session) (auth.Session, bool, error) {
	if err := s.enter("CreateSuccessorSession"); err != nil {
		return auth.Session{}, false, err
	}
	return s.AuthStore.CreateSuccessorSession(ctx, predecessorID, sess)
}

func (s *deletionRecorder) MarkRotated(ctx context.Context, tokenHash string, now time.Time) (auth.Session, bool, error) {
	if err := s.enter("MarkRotated"); err != nil {
		return auth.Session{}, false, err
	}
	return s.AuthStore.MarkRotated(ctx, tokenHash, now)
}

func (s *deletionRecorder) DeleteSession(ctx context.Context, id string) error {
	if err := s.enter("DeleteSession"); err != nil {
		return err
	}
	return s.AuthStore.DeleteSession(ctx, id)
}

func (s *deletionRecorder) DeleteSessionsByFamily(ctx context.Context, familyID string) error {
	if err := s.enter("DeleteSessionsByFamily"); err != nil {
		return err
	}
	return s.AuthStore.DeleteSessionsByFamily(ctx, familyID)
}

func (s *deletionRecorder) DeleteSessionsByUser(ctx context.Context, userID string) error {
	if err := s.enter("DeleteSessionsByUser"); err != nil {
		return err
	}
	return s.AuthStore.DeleteSessionsByUser(ctx, userID)
}

func (s *deletionRecorder) CreateVerification(ctx context.Context, v auth.Verification) (auth.Verification, error) {
	if err := s.enter("CreateVerification"); err != nil {
		return auth.Verification{}, err
	}
	return s.AuthStore.CreateVerification(ctx, v)
}

func (s *deletionRecorder) DeleteVerification(ctx context.Context, id string) error {
	if err := s.enter("DeleteVerification"); err != nil {
		return err
	}
	return s.AuthStore.DeleteVerification(ctx, id)
}

func (s *deletionRecorder) DeleteVerificationsByUserAndPurpose(ctx context.Context, userID, purpose string) error {
	if err := s.enter("DeleteVerificationsByUserAndPurpose"); err != nil {
		return err
	}
	return s.AuthStore.DeleteVerificationsByUserAndPurpose(ctx, userID, purpose)
}

func (s *deletionRecorder) DeleteVerificationsByUser(ctx context.Context, userID string) error {
	if err := s.enter("DeleteVerificationsByUser"); err != nil {
		return err
	}
	return s.AuthStore.DeleteVerificationsByUser(ctx, userID)
}

func (s *deletionRecorder) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	if err := s.enter("PurgeExpired"); err != nil {
		return 0, err
	}
	return s.AuthStore.PurgeExpired(ctx, before)
}

// --- helpers ---

// newServiceOver is newTestService's sibling for the tests that need to
// supply their OWN Store — a recorder, or one scripted to fail a specific
// method — rather than take the fresh memory.AuthStore newTestService
// builds. Same fast Hasher and same fixed signing key.
func newServiceOver(t *testing.T, store auth.Store, opts ...auth.Option) *auth.Service {
	t.Helper()
	base := []auth.Option{
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	}
	return auth.New(store, append(base, opts...)...)
}

// seedDeletableAccount registers an account and gives it everything
// authlayer can hold for one: two session families (so a sweep that covers
// only the newest is caught), and three verifications spanning a purpose
// this package mints ("password_reset"), the strongest one it mints
// ("email_change"), and one it does not know about at all, which stands in
// for a purpose a later flow or a deployment itself defines.
type deletableAccount struct {
	user         auth.UserBase
	refreshFirst string
	refreshLater string
	resetToken   string
	changeToken  string
	customHash   string
}

const customPurposeToken = "a-token-minted-by-a-purpose-auth-does-not-define"

func seedDeletableAccount(t *testing.T, svc *auth.Service, store auth.Store, email string) deletableAccount {
	t.Helper()
	ctx := context.Background()

	u := mustSignUp(t, svc, email, validPassword)
	_, _, first := mustLogin(t, svc, email, validPassword)
	_, _, later := mustLogin(t, svc, email, validPassword)

	reset, ok, err := svc.RequestPasswordReset(ctx, email, "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset(%q) = (_, %v, %v), want (token, true, nil)", email, ok, err)
	}
	change, err := svc.RequestEmailChange(ctx, u.ID, validPassword, "moved-"+email)
	if err != nil {
		t.Fatalf("RequestEmailChange(%q): %v", email, err)
	}

	customHash := token.HashOpaque(customPurposeToken)
	if _, err := store.CreateVerification(ctx, auth.Verification{
		ID:        "verification-of-an-unknown-purpose-" + u.ID,
		UserID:    u.ID,
		TokenHash: customHash,
		Purpose:   "totp_enrolment",
		Email:     u.Email,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateVerification (custom purpose): %v", err)
	}

	return deletableAccount{
		user:         u,
		refreshFirst: first,
		refreshLater: later,
		resetToken:   reset,
		changeToken:  change,
		customHash:   customHash,
	}
}

// assertAccountIntact reports every part of the account that is missing.
// The tests that use it are the ones asserting that a refusal or an abort
// wrote NOTHING, so it names what was destroyed rather than stopping at
// the first thing.
func assertAccountIntact(t *testing.T, store auth.Store, acct deletableAccount, why string) {
	t.Helper()
	ctx := context.Background()

	if _, err := store.FindUserByID(ctx, acct.user.ID); err != nil {
		t.Errorf("%s: the user row is gone (FindUserByID: %v) — nothing may be written", why, err)
	}
	sessions, err := store.ListSessionsByUser(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("%s: %d sessions survive, want 2 — nothing may be written", why, len(sessions))
	}
	for name, hash := range map[string]string{
		"password_reset": token.HashOpaque(acct.resetToken),
		"email_change":   token.HashOpaque(acct.changeToken),
		"totp_enrolment": acct.customHash,
	} {
		if _, err := store.FindVerificationByHash(ctx, hash); err != nil {
			t.Errorf("%s: the %q verification is gone (FindVerificationByHash: %v) — nothing may be written", why, name, err)
		}
	}
}

func TestDeleteAccountRemovesEverythingAuthlayerHolds(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "dana@example.com")

	if err := svc.DeleteAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if _, err := store.FindUserByID(ctx, acct.user.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("FindUserByID after DeleteAccount = %v, want ErrUserNotFound — the user row must be gone", err)
	}
	sessions, err := store.ListSessionsByUser(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("%d sessions survive DeleteAccount, want 0 — every family must be swept, not just the newest", len(sessions))
	}
	for name, hash := range map[string]string{
		"password_reset": token.HashOpaque(acct.resetToken),
		"email_change":   token.HashOpaque(acct.changeToken),
		"totp_enrolment": acct.customHash,
	} {
		if _, err := store.FindVerificationByHash(ctx, hash); !errors.Is(err, auth.ErrVerificationNotFound) {
			t.Errorf("the %q verification survives DeleteAccount (FindVerificationByHash = %v), want ErrVerificationNotFound — no pending token may outlive the account", name, err)
		}
	}
}

func TestDeleteAccountFreesTheAddressForReuse(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "erin@example.com")

	if err := svc.DeleteAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	res, err := svc.SignUp(ctx, "erin@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp after DeleteAccount: %v", err)
	}
	if !res.Created {
		t.Error("SignUp after a hard DeleteAccount reported the address already registered — a removed row must free its address")
	}
}

func TestDeleteAccountWrongPasswordDeletesNothing(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "fay@example.com")

	err := svc.DeleteAccount(ctx, acct.user.ID, "not-the-password-9!")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("DeleteAccount with the wrong password = %v, want ErrInvalidCredentials — re-authentication is what gates this", err)
	}
	assertAccountIntact(t, store, acct, "a refused (wrong-password) DeleteAccount")
}

func TestDeleteAccountWithoutAPasswordProceedsOnTheCallersAuthority(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	// An OAuth-only / magic-link-only account: a real row with no password
	// credential at all. There is nothing for currentPassword to be checked
	// against, so DeleteAccount proceeds — see its doc, "An account with no
	// password".
	now := time.Now().UTC()
	u, err := store.CreateUser(ctx, auth.UserBase{
		ID:        "user-with-no-password-credential",
		Email:     "gale@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := svc.DeleteAccount(ctx, u.ID, ""); err != nil {
		t.Fatalf("DeleteAccount on a password-less account = %v, want nil — there is nothing to re-authenticate against", err)
	}
	if _, err := store.FindUserByID(ctx, u.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("FindUserByID after DeleteAccount = %v, want ErrUserNotFound", err)
	}
}

func TestDeleteAccountWithoutAPasswordIgnoresWhateverWasPassed(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	now := time.Now().UTC()
	u, err := store.CreateUser(ctx, auth.UserBase{
		ID:        "another-user-with-no-password",
		Email:     "hana@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// A non-empty currentPassword against an account with no hash must not
	// become a refusal: the asymmetry is "nothing to check", not "check it
	// against the empty string".
	if err := svc.DeleteAccount(ctx, u.ID, "whatever-the-caller-happened-to-send"); err != nil {
		t.Fatalf("DeleteAccount on a password-less account with a non-empty currentPassword = %v, want nil", err)
	}
}

func TestDeleteAccountUnknownUser(t *testing.T) {
	svc, _ := newTestService(t)

	err := svc.DeleteAccount(context.Background(), "no-such-user-id", validPassword)
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("DeleteAccount on an unknown id = %v, want ErrUserNotFound", err)
	}
}

func TestDeleteAccountHookErrorAbortsWithNothingDeleted(t *testing.T) {
	store := memory.NewAuthStore()
	var hookCalls int
	svc := newServiceOver(t, store, auth.WithAccountDeletionHook(func(context.Context, string) error {
		hookCalls++
		return errHookBoom
	}))
	acct := seedDeletableAccount(t, svc, store, "iris@example.com")

	err := svc.DeleteAccount(context.Background(), acct.user.ID, validPassword)
	if !errors.Is(err, errHookBoom) {
		t.Errorf("DeleteAccount with a failing hook = %v, want the hook's own error — a hook error aborts", err)
	}
	if hookCalls != 1 {
		t.Errorf("the hook ran %d times, want 1", hookCalls)
	}
	assertAccountIntact(t, store, acct, "an aborted (hook error) DeleteAccount")
}

func TestDeleteAccountHookRunsBeforeAnyStoreWrite(t *testing.T) {
	rec := newDeletionRecorder()
	svc := newServiceOver(t, rec, auth.WithAccountDeletionHook(func(context.Context, string) error {
		rec.record("hook")
		return nil
	}))
	acct := seedDeletableAccount(t, svc, rec, "jo@example.com")

	rec.reset()
	if err := svc.DeleteAccount(context.Background(), acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	got := rec.snapshot()
	if len(got) == 0 || got[0] != "hook" {
		t.Fatalf("DeleteAccount call sequence = %v; want the hook first, before ANY store write — the hook is where the application deletes the rows authlayer cannot reach, and it can only abort cleanly if nothing has been written yet", got)
	}
}

func TestDeleteAccountAbortingHookWritesNothingAtAll(t *testing.T) {
	rec := newDeletionRecorder()
	svc := newServiceOver(t, rec, auth.WithAccountDeletionHook(func(context.Context, string) error {
		rec.record("hook")
		return errHookBoom
	}))
	acct := seedDeletableAccount(t, svc, rec, "kai@example.com")

	rec.reset()
	if err := svc.DeleteAccount(context.Background(), acct.user.ID, validPassword); !errors.Is(err, errHookBoom) {
		t.Fatalf("DeleteAccount with a failing hook = %v, want errHookBoom", err)
	}

	got := rec.snapshot()
	if len(got) != 1 || got[0] != "hook" {
		t.Errorf("an aborted DeleteAccount touched the store: sequence = %v, want exactly [hook] — a hook error must leave nothing written", got)
	}
}

func TestDeleteAccountOrdersSessionsBeforeVerificationsBeforeTheUserRow(t *testing.T) {
	rec := newDeletionRecorder()
	svc := newServiceOver(t, rec, auth.WithAccountDeletionHook(func(context.Context, string) error {
		rec.record("hook")
		return nil
	}))
	acct := seedDeletableAccount(t, svc, rec, "lee@example.com")

	rec.reset()
	if err := svc.DeleteAccount(context.Background(), acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	want := []string{"hook", "DeleteSessionsByUser", "DeleteVerificationsByUser", "DeleteUser"}
	got := rec.snapshot()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("DeleteAccount call sequence =\n  %v\nwant\n  %v\nSessions go first so access stops before anything irreversible; the user row goes last.", got, want)
	}
}

// TestDeleteAccountMidCascadeFailureLeavesTheFailSafeDirection is the
// fail-safe ordering test. Steps 4-7 are not atomic across stores (see
// DeleteAccount's doc), so the question is not whether a partial state is
// reachable — it is — but WHICH partial state. Parking the cascade at the
// verification sweep must leave an account with no sessions and a row still
// present: unusable, and still there to retry against. The opposite
// direction — the row gone while live refresh tokens survive it — is the
// one this ordering exists to make unreachable.
func TestDeleteAccountMidCascadeFailureLeavesTheFailSafeDirection(t *testing.T) {
	rec := newDeletionRecorder()
	rec.fail["DeleteVerificationsByUser"] = errCascadeBoom
	svc := newServiceOver(t, rec)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, rec, "mo@example.com")

	if err := svc.DeleteAccount(ctx, acct.user.ID, validPassword); !errors.Is(err, errCascadeBoom) {
		t.Fatalf("DeleteAccount = %v, want the store's own error — a cascade failure must be reported, not swallowed", err)
	}

	sessions, err := rec.ListSessionsByUser(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("%d sessions survive a cascade that failed at the verification sweep, want 0 — sessions are revoked FIRST so a partial deletion stops access rather than leaving it live", len(sessions))
	}
	if _, err := rec.FindUserByID(ctx, acct.user.ID); err != nil {
		t.Errorf("the user row was already removed when the cascade failed at the verification sweep (FindUserByID: %v) — the row must go LAST, so a partial deletion leaves an unusable account that can be retried, never one whose data is gone", err)
	}
}

func TestDeleteAccountRevokedSessionNoLongerRefreshes(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "nina@example.com")

	if err := svc.DeleteAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	for name, refresh := range map[string]string{
		"the first login's":  acct.refreshFirst,
		"the second login's": acct.refreshLater,
	} {
		if _, err := svc.Refresh(ctx, refresh); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Errorf("Refresh with %s refresh token after DeleteAccount = %v, want ErrTokenInvalid — every family is revoked, not just the newest", name, err)
		}
	}
}

func TestDeleteAccountPendingResetTokenNoLongerRedeems(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "omar@example.com")

	if err := svc.DeleteAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if err := svc.ResetPassword(ctx, acct.resetToken, "Another-Horse-Battery-9!"); err == nil {
		t.Error("a password-reset token minted before DeleteAccount still redeems — no pending credential may outlive the account")
	}
	if _, err := svc.VerifyEmail(ctx, acct.changeToken); err == nil {
		t.Error("an email-change token minted before DeleteAccount still redeems — no pending credential may outlive the account")
	}
}

func TestDeleteAccountWithNoHookConfigured(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "pia@example.com")

	if err := svc.DeleteAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount without a hook configured: %v", err)
	}
	if _, err := store.FindUserByID(ctx, acct.user.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("FindUserByID after DeleteAccount = %v, want ErrUserNotFound", err)
	}
}

func TestDeleteAccountHookReceivesTheUserID(t *testing.T) {
	store := memory.NewAuthStore()
	var seen []string
	svc := newServiceOver(t, store, auth.WithAccountDeletionHook(func(_ context.Context, userID string) error {
		seen = append(seen, userID)
		return nil
	}))
	acct := seedDeletableAccount(t, svc, store, "quinn@example.com")

	if err := svc.DeleteAccount(context.Background(), acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if len(seen) != 1 || seen[0] != acct.user.ID {
		t.Errorf("hook saw %v, want exactly [%s]", seen, acct.user.ID)
	}
}

func TestDeleteAccountDoesNotFireTheHookForAnUnknownUser(t *testing.T) {
	store := memory.NewAuthStore()
	fired := false
	svc := newServiceOver(t, store, auth.WithAccountDeletionHook(func(context.Context, string) error {
		fired = true
		return nil
	}))

	if err := svc.DeleteAccount(context.Background(), "no-such-user-id", validPassword); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("DeleteAccount on an unknown id = %v, want ErrUserNotFound", err)
	}
	if fired {
		t.Error("the deletion hook fired for an id that identifies no account — an application must not be told to tear down data for a user that does not exist")
	}
}

func TestDeleteAccountDoesNotFireTheHookOnAFailedReauthentication(t *testing.T) {
	store := memory.NewAuthStore()
	fired := false
	svc := newServiceOver(t, store, auth.WithAccountDeletionHook(func(context.Context, string) error {
		fired = true
		return nil
	}))
	acct := seedDeletableAccount(t, svc, store, "rae@example.com")

	if err := svc.DeleteAccount(context.Background(), acct.user.ID, "not-the-password-9!"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("DeleteAccount with the wrong password = %v, want ErrInvalidCredentials", err)
	}
	if fired {
		t.Error("the deletion hook fired after a failed re-authentication — the hook destroys the application's own data and must run only once the caller has proven the credential")
	}
}

func TestDeleteAccountOnAnAnonymizedAccount(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	// An already-anonymized row: DeletedAt stamped, password hash cleared.
	// A hard delete supersedes a soft one — see DeleteAccount's doc.
	now := time.Now().UTC()
	stamped := now.Add(-24 * time.Hour)
	u, err := store.CreateUser(ctx, auth.UserBase{
		ID:        "an-already-anonymized-account",
		Email:     "deleted-an-already-anonymized-account@example.invalid",
		CreatedAt: now,
		UpdatedAt: now,
		DeletedAt: &stamped,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := svc.DeleteAccount(ctx, u.ID, ""); err != nil {
		t.Fatalf("DeleteAccount on an anonymized account = %v, want nil — a hard delete supersedes a soft one", err)
	}
	if _, err := store.FindUserByID(ctx, u.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("FindUserByID after DeleteAccount = %v, want ErrUserNotFound", err)
	}
}

func TestDeleteAccountPropagatesTheFirstSweepsOutage(t *testing.T) {
	rec := newDeletionRecorder()
	svc := newServiceOver(t, rec)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, rec, "sam@example.com")

	rec.fail["DeleteSessionsByUser"] = errCascadeBoom
	if err := svc.DeleteAccount(ctx, acct.user.ID, validPassword); !errors.Is(err, errCascadeBoom) {
		t.Fatalf("DeleteAccount = %v, want the store's own error as-is", err)
	}
	assertAccountIntact(t, rec, acct, "a DeleteAccount whose very first sweep failed")
}

func TestWithAccountDeletionHookNilIsIgnored(t *testing.T) {
	svc, store := newTestService(t, auth.WithAccountDeletionHook(nil))
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "tess@example.com")

	if err := svc.DeleteAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount with a nil hook configured = %v, want nil — a nil f leaves the default (no hook) in place", err)
	}
}
