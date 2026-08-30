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

func (s *deletionRecorder) MarkUserDeleted(ctx context.Context, userID, anonymizedEmail string, now time.Time) error {
	if err := s.enter("MarkUserDeleted"); err != nil {
		return err
	}
	return s.AuthStore.MarkUserDeleted(ctx, userID, anonymizedEmail, now)
}

// ============================================================
// AnonymizeAccount
// ============================================================

// anonymizedEmailFor is the scrubbed address
// [auth.Service.AnonymizeAccount] documents, spelled out here independently
// of the implementation so a change to either has to be a deliberate change
// to both. An operator reading the users table recognises an anonymized row
// by exactly this shape.
func anonymizedEmailFor(userID string) string {
	return "deleted-" + strings.ToLower(userID) + "@example.invalid"
}

func TestAnonymizeAccountScrubsStampsAndSweeps(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "uma@example.com")

	before := time.Now().UTC()
	if err := svc.AnonymizeAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}

	got, err := store.FindUserByID(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("FindUserByID after AnonymizeAccount = %v, want the row to SURVIVE — that is the whole point of the soft posture", err)
	}
	if want := anonymizedEmailFor(acct.user.ID); got.Email != want {
		t.Errorf("Email = %q after AnonymizeAccount, want %q — the documented scrubbed form is what an operator recognises in the table", got.Email, want)
	}
	if got.PasswordHash != "" {
		t.Error("PasswordHash survives AnonymizeAccount — an anonymized account must keep no credential")
	}
	if got.EmailVerifiedAt != nil {
		t.Errorf("EmailVerifiedAt = %v after AnonymizeAccount, want nil — it certified an address the row no longer holds", got.EmailVerifiedAt)
	}
	if got.DeletedAt == nil {
		t.Fatal("DeletedAt = nil after AnonymizeAccount — an unstamped row reports as a live account to every entry point that checks")
	}
	if got.DeletedAt.Before(before) {
		t.Errorf("DeletedAt = %v, want an instant at or after the call began (%v)", got.DeletedAt, before)
	}

	sessions, err := store.ListSessionsByUser(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("%d sessions survive AnonymizeAccount, want 0 — every family is revoked, not just the newest", len(sessions))
	}
	for name, hash := range map[string]string{
		"password_reset": token.HashOpaque(acct.resetToken),
		"email_change":   token.HashOpaque(acct.changeToken),
		"totp_enrolment": acct.customHash,
	} {
		if _, err := store.FindVerificationByHash(ctx, hash); !errors.Is(err, auth.ErrVerificationNotFound) {
			t.Errorf("the %q verification survives AnonymizeAccount (FindVerificationByHash = %v), want ErrVerificationNotFound", name, err)
		}
	}
}

func TestAnonymizeAccountFreesTheOriginalAddressForANewSignUp(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "vera@example.com")

	if err := svc.AnonymizeAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}

	res, err := svc.SignUp(ctx, "vera@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp after AnonymizeAccount: %v", err)
	}
	if !res.Created {
		t.Fatal("SignUp after AnonymizeAccount reported the address already registered — scrubbing the address is what gives it back")
	}
	if res.User.ID == acct.user.ID {
		t.Error("the new sign-up reused the anonymized account's id — it must be a genuinely new row")
	}
	if _, err := store.FindUserByID(ctx, acct.user.ID); err != nil {
		t.Errorf("the anonymized row is gone after the address was reused (%v) — both must coexist", err)
	}
}

// TestAnonymizeAccountScrubbedAddressesDoNotCollide is the check the
// derived-from-the-user-id form exists for: two anonymizations must not
// produce one address, because [auth.UserBase.Email] is UNIQUE and the
// second would be refused with ErrEmailTaken — leaving an account the caller
// asked to close still open.
func TestAnonymizeAccountScrubbedAddressesDoNotCollide(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	// Two ordinary sign-ups rather than two seedDeletableAccount calls: that
	// helper mints a fixed-token verification, and one store cannot hold two
	// of those. Nothing about this check needs the extra fixtures.
	first := mustSignUp(t, svc, "wren@example.com", validPassword)
	second := mustSignUp(t, svc, "xu@example.com", validPassword)

	if err := svc.AnonymizeAccount(ctx, first.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount(first): %v", err)
	}
	if err := svc.AnonymizeAccount(ctx, second.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount(second) = %v, want nil — two anonymized accounts must not collide on the users.email UNIQUE constraint", err)
	}

	a, err := store.FindUserByID(ctx, first.ID)
	if err != nil {
		t.Fatalf("FindUserByID(first): %v", err)
	}
	b, err := store.FindUserByID(ctx, second.ID)
	if err != nil {
		t.Fatalf("FindUserByID(second): %v", err)
	}
	if a.Email == b.Email {
		t.Fatalf("both anonymized accounts hold %q — the scrubbed address must be derived from the user's own id", a.Email)
	}
	if a.DeletedAt == nil || b.DeletedAt == nil {
		t.Error("one of the two accounts is not stamped")
	}
}

func TestAnonymizeAccountWrongPasswordChangesNothing(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "yara@example.com")

	err := svc.AnonymizeAccount(ctx, acct.user.ID, "not-the-password-9!")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("AnonymizeAccount with the wrong password = %v, want ErrInvalidCredentials — re-authentication gates this exactly as it gates DeleteAccount", err)
	}
	assertAccountIntact(t, store, acct, "a refused (wrong-password) AnonymizeAccount")

	got, ferr := store.FindUserByID(ctx, acct.user.ID)
	if ferr != nil {
		t.Fatalf("FindUserByID: %v", ferr)
	}
	if got.DeletedAt != nil {
		t.Error("a refused AnonymizeAccount stamped DeletedAt anyway")
	}
	if got.Email != acct.user.Email {
		t.Errorf("Email = %q after a refused AnonymizeAccount, want the unchanged %q", got.Email, acct.user.Email)
	}
}

func TestAnonymizeAccountWithoutAPasswordProceedsOnTheCallersAuthority(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	now := time.Now().UTC()
	u, err := store.CreateUser(ctx, auth.UserBase{
		ID:        "an-oauth-only-account-to-anonymize",
		Email:     "zack@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := svc.AnonymizeAccount(ctx, u.ID, "whatever-the-caller-happened-to-send"); err != nil {
		t.Fatalf("AnonymizeAccount on a password-less account = %v, want nil — there is nothing to re-authenticate against", err)
	}
	got, err := store.FindUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.DeletedAt == nil {
		t.Error("DeletedAt = nil — the account was not anonymized")
	}
}

// TestAnonymizeAccountOnAnAlreadyAnonymizedAccountIsIdempotent pins the
// consequence of the no-password branch an anonymized account falls into by
// construction: a second call must succeed and leave the row where it was,
// not fail on its own scrubbed address — which the row already holds, and
// which is not a self-conflict.
func TestAnonymizeAccountOnAnAlreadyAnonymizedAccountIsIdempotent(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "abe@example.com")

	if err := svc.AnonymizeAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}
	first, err := store.FindUserByID(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}

	if err := svc.AnonymizeAccount(ctx, acct.user.ID, ""); err != nil {
		t.Fatalf("AnonymizeAccount on an already-anonymized account = %v, want nil", err)
	}
	second, err := store.FindUserByID(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if second.Email != first.Email {
		t.Errorf("Email = %q after a second AnonymizeAccount, want the unchanged %q", second.Email, first.Email)
	}
	if second.DeletedAt == nil {
		t.Error("DeletedAt = nil after a second AnonymizeAccount")
	}
}

func TestAnonymizeAccountUnknownUser(t *testing.T) {
	svc, _ := newTestService(t)
	err := svc.AnonymizeAccount(context.Background(), "no-such-user-id", validPassword)
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("AnonymizeAccount on an unknown id = %v, want ErrUserNotFound", err)
	}
}

func TestAnonymizeAccountHookErrorAbortsWithNothingWritten(t *testing.T) {
	store := memory.NewAuthStore()
	var hookCalls int
	svc := newServiceOver(t, store, auth.WithAccountDeletionHook(func(context.Context, string) error {
		hookCalls++
		return errHookBoom
	}))
	acct := seedDeletableAccount(t, svc, store, "bea@example.com")

	err := svc.AnonymizeAccount(context.Background(), acct.user.ID, validPassword)
	if !errors.Is(err, errHookBoom) {
		t.Errorf("AnonymizeAccount with a failing hook = %v, want the hook's own error — a hook error aborts, exactly as it does for DeleteAccount", err)
	}
	if hookCalls != 1 {
		t.Errorf("the hook ran %d times, want 1", hookCalls)
	}
	assertAccountIntact(t, store, acct, "an aborted (hook error) AnonymizeAccount")
}

func TestAnonymizeAccountOrdersTheHookThenSessionsThenVerificationsThenTheStamp(t *testing.T) {
	rec := newDeletionRecorder()
	svc := newServiceOver(t, rec, auth.WithAccountDeletionHook(func(context.Context, string) error {
		rec.record("hook")
		return nil
	}))
	acct := seedDeletableAccount(t, svc, rec, "cleo@example.com")

	rec.reset()
	if err := svc.AnonymizeAccount(context.Background(), acct.user.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}

	want := []string{"hook", "DeleteSessionsByUser", "DeleteVerificationsByUser", "MarkUserDeleted"}
	got := rec.snapshot()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("AnonymizeAccount call sequence =\n  %v\nwant\n  %v\nThe hook runs before ANY store write so its error can abort cleanly; sessions go first so access stops before anything irreversible.", got, want)
	}
}

func TestAnonymizeAccountAbortingHookWritesNothingAtAll(t *testing.T) {
	rec := newDeletionRecorder()
	svc := newServiceOver(t, rec, auth.WithAccountDeletionHook(func(context.Context, string) error {
		rec.record("hook")
		return errHookBoom
	}))
	acct := seedDeletableAccount(t, svc, rec, "dov@example.com")

	rec.reset()
	if err := svc.AnonymizeAccount(context.Background(), acct.user.ID, validPassword); !errors.Is(err, errHookBoom) {
		t.Fatalf("AnonymizeAccount with a failing hook = %v, want errHookBoom", err)
	}
	got := rec.snapshot()
	if len(got) != 1 || got[0] != "hook" {
		t.Errorf("an aborted AnonymizeAccount touched the store: sequence = %v, want exactly [hook]", got)
	}
}

func TestAnonymizeAccountDoesNotFireTheHookOnAFailedReauthentication(t *testing.T) {
	store := memory.NewAuthStore()
	fired := false
	svc := newServiceOver(t, store, auth.WithAccountDeletionHook(func(context.Context, string) error {
		fired = true
		return nil
	}))
	acct := seedDeletableAccount(t, svc, store, "eli@example.com")

	if err := svc.AnonymizeAccount(context.Background(), acct.user.ID, "not-the-password-9!"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("AnonymizeAccount with the wrong password = %v, want ErrInvalidCredentials", err)
	}
	if fired {
		t.Error("the deletion hook fired after a failed re-authentication")
	}
}

// TestAnonymizeAccountMidCascadeFailureLeavesTheFailSafeDirection parks the
// cascade at the stamp itself — the last step — and asserts the partial
// state falls on the safe side: every session already revoked, the row still
// there and still retryable, and NOT stamped. A stamp with the account's
// real address still on the row is the state
// [auth.Store.MarkUserDeleted]'s MUST rules out.
func TestAnonymizeAccountMidCascadeFailureLeavesTheFailSafeDirection(t *testing.T) {
	rec := newDeletionRecorder()
	rec.fail["MarkUserDeleted"] = errCascadeBoom
	svc := newServiceOver(t, rec)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, rec, "fern@example.com")

	if err := svc.AnonymizeAccount(ctx, acct.user.ID, validPassword); !errors.Is(err, errCascadeBoom) {
		t.Fatalf("AnonymizeAccount = %v, want the store's own error — a cascade failure must be reported, not swallowed", err)
	}

	sessions, err := rec.ListSessionsByUser(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("%d sessions survive an anonymization that failed at the stamp, want 0 — sessions are revoked FIRST", len(sessions))
	}
	got, err := rec.FindUserByID(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("the user row is gone after a failed anonymization (%v) — the soft posture never removes it", err)
	}
	if got.DeletedAt != nil {
		t.Error("DeletedAt is stamped even though MarkUserDeleted failed")
	}
}

func TestAnonymizeAccountPropagatesTheFirstSweepsOutage(t *testing.T) {
	rec := newDeletionRecorder()
	svc := newServiceOver(t, rec)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, rec, "gus@example.com")

	rec.fail["DeleteSessionsByUser"] = errCascadeBoom
	if err := svc.AnonymizeAccount(ctx, acct.user.ID, validPassword); !errors.Is(err, errCascadeBoom) {
		t.Fatalf("AnonymizeAccount = %v, want the store's own error as-is", err)
	}
	assertAccountIntact(t, rec, acct, "an AnonymizeAccount whose very first sweep failed")
}

func TestAnonymizeAccountWithNoHookConfigured(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "hugo@example.com")

	if err := svc.AnonymizeAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount without a hook configured: %v", err)
	}
	got, err := store.FindUserByID(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.DeletedAt == nil {
		t.Error("DeletedAt = nil")
	}
}

// ============================================================
// Refusing a stamped account, one entry point at a time
// ============================================================

// stampedStore hands back userID's record with DeletedAt set while leaving
// every other field exactly as stored — the real address, the live password
// hash, the verification stamp.
//
// That combination is the whole point. Anonymization scrubs the address and
// clears the credential too, so a test that anonymized for real could not
// tell an entry point's DeletedAt CHECK apart from the incidental fact that
// the password no longer verifies and the address no longer resolves. Every
// refusal test below therefore runs against a row that is stamped and
// otherwise untouched, so the only thing that can refuse it is the check
// itself. That is also what makes the mutation "remove the DeletedAt check
// from Login" fail Login's test and no other.
//
// It is not a hypothetical state either: DeletedAt is a plain column, and a
// deployment that stamps it from its own admin tooling or migration — which
// [auth.UserBase.DeletedAt] describes as the field's meaning, not as
// something only this package may write — produces exactly this row.
type stampedStore struct {
	*memory.AuthStore
	userID string
	at     time.Time
}

func (s stampedStore) stamp(u auth.UserBase) auth.UserBase {
	if u.ID == s.userID {
		at := s.at
		u.DeletedAt = &at
	}
	return u
}

func (s stampedStore) FindUserByID(ctx context.Context, id string) (auth.UserBase, error) {
	u, err := s.AuthStore.FindUserByID(ctx, id)
	if err != nil {
		return u, err
	}
	return s.stamp(u), nil
}

func (s stampedStore) FindUserByEmail(ctx context.Context, email string) (auth.UserBase, error) {
	u, err := s.AuthStore.FindUserByEmail(ctx, email)
	if err != nil {
		return u, err
	}
	return s.stamp(u), nil
}

// stampedFixture is one seeded account plus two services over the same rows:
// live, which sees the account as it is, and stamped, which sees it with
// DeletedAt set. Seeding runs through live so every credential and token is
// genuine.
type stampedFixture struct {
	store   *memory.AuthStore
	live    *auth.Service
	stamped *auth.Service
	acct    deletableAccount
}

func newStampedFixture(t *testing.T, email string) stampedFixture {
	t.Helper()
	store := memory.NewAuthStore()
	live := newServiceOver(t, store)
	acct := seedDeletableAccount(t, live, store, email)
	stamped := newServiceOver(t, stampedStore{
		AuthStore: store,
		userID:    acct.user.ID,
		at:        time.Now().UTC().Add(-time.Hour),
	})
	return stampedFixture{store: store, live: live, stamped: stamped, acct: acct}
}

// storedHash reads the account's password hash straight off the store —
// the seeded [deletableAccount] cannot supply it, because every UserBase the
// service hands back has PasswordHash cleared (see that field's own doc).
func (f stampedFixture) storedHash(t *testing.T) string {
	t.Helper()
	u, err := f.store.FindUserByID(context.Background(), f.acct.user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if u.PasswordHash == "" {
		t.Fatalf("fixture error: the seeded account has no password hash to compare against")
	}
	return u.PasswordHash
}

func TestLoginRefusesAnAnonymizedAccount(t *testing.T) {
	f := newStampedFixture(t, "iggy@example.com")

	_, err := f.stamped.Login(context.Background(), "iggy@example.com", validPassword, "203.0.113.4", "ua")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login with the CORRECT password against a stamped account = %v, want ErrInvalidCredentials — a non-nil DeletedAt means no one may authenticate as this account, and the refusal must be indistinguishable from a wrong password", err)
	}
}

func TestLoginRefusalOfAnAnonymizedAccountIsIndistinguishable(t *testing.T) {
	f := newStampedFixture(t, "jules@example.com")
	ctx := context.Background()

	stampedErr := errFromLogin(f.stamped, ctx, "jules@example.com", validPassword)
	wrongErr := errFromLogin(f.live, ctx, "jules@example.com", "not-the-password-9!")
	unknownErr := errFromLogin(f.live, ctx, "nobody-here@example.com", validPassword)

	if stampedErr == nil || wrongErr == nil || unknownErr == nil {
		t.Fatalf("all three probes must fail: stamped=%v wrong=%v unknown=%v", stampedErr, wrongErr, unknownErr)
	}
	if stampedErr.Error() != wrongErr.Error() || stampedErr.Error() != unknownErr.Error() {
		t.Errorf("a stamped account answers %q while a wrong password answers %q and an unknown address answers %q — the three must be indistinguishable from the error alone", stampedErr, wrongErr, unknownErr)
	}
}

func errFromLogin(svc *auth.Service, ctx context.Context, email, pass string) error {
	_, err := svc.Login(ctx, email, pass, "203.0.113.4", "ua")
	return err
}

// TestRequestPasswordResetStaysIndistinguishableForAnAnonymizedAccount is
// the one refusal that must NOT become an error. This method's whole
// contract is that a caller cannot learn whether an address is registered,
// so an anonymized account has to answer exactly as an unknown address does:
// ("", false, nil).
func TestRequestPasswordResetStaysIndistinguishableForAnAnonymizedAccount(t *testing.T) {
	f := newStampedFixture(t, "kit@example.com")
	ctx := context.Background()

	tok, ok, err := f.stamped.RequestPasswordReset(ctx, "kit@example.com", "203.0.113.5")
	if err != nil {
		t.Fatalf("RequestPasswordReset against a stamped account = %v, want nil — a refusal here must never become a new error, or it is an existence oracle", err)
	}
	if ok || tok != "" {
		t.Fatalf("RequestPasswordReset against a stamped account = (%q, %v, nil), want (\"\", false, nil) — no reset token may be minted for an account no one may authenticate as", tok, ok)
	}

	unknownTok, unknownOK, unknownErr := f.stamped.RequestPasswordReset(ctx, "nobody-here@example.com", "203.0.113.5")
	if unknownTok != tok || unknownOK != ok || unknownErr != err {
		t.Errorf("a stamped account answers (%q, %v, %v) while an unknown address answers (%q, %v, %v) — the two must be identical", tok, ok, err, unknownTok, unknownOK, unknownErr)
	}
}

// TestRequestPasswordResetMintsNothingForAnAnonymizedAccount is the half the
// indistinguishability test cannot see: the return value being ("", false,
// nil) does not by itself prove no verification row was written.
func TestRequestPasswordResetMintsNothingForAnAnonymizedAccount(t *testing.T) {
	store := memory.NewAuthStore()
	live := newServiceOver(t, store)
	acct := seedDeletableAccount(t, live, store, "lior@example.com")
	rec := &deletionRecorder{AuthStore: store, fail: map[string]error{}}
	stamped := newServiceOver(t, stampedRecorder{rec, acct.user.ID})

	rec.reset()
	if _, ok, err := stamped.RequestPasswordReset(context.Background(), "lior@example.com", "203.0.113.5"); ok || err != nil {
		t.Fatalf("RequestPasswordReset = (_, %v, %v), want (\"\", false, nil)", ok, err)
	}
	for _, ev := range rec.snapshot() {
		if ev == "CreateVerification" {
			t.Fatalf("RequestPasswordReset minted a verification for a stamped account: %v", rec.snapshot())
		}
	}
}

// stampedRecorder is [stampedStore]'s trick applied over a
// [deletionRecorder], so a refusal test can watch which store calls a
// refused entry point made.
type stampedRecorder struct {
	*deletionRecorder
	userID string
}

func (s stampedRecorder) FindUserByID(ctx context.Context, id string) (auth.UserBase, error) {
	u, err := s.deletionRecorder.FindUserByID(ctx, id)
	if err != nil {
		return u, err
	}
	return s.stamp(u), nil
}

func (s stampedRecorder) FindUserByEmail(ctx context.Context, email string) (auth.UserBase, error) {
	u, err := s.deletionRecorder.FindUserByEmail(ctx, email)
	if err != nil {
		return u, err
	}
	return s.stamp(u), nil
}

func (s stampedRecorder) stamp(u auth.UserBase) auth.UserBase {
	if u.ID == s.userID {
		at := time.Now().UTC().Add(-time.Hour)
		u.DeletedAt = &at
	}
	return u
}

func TestRefreshRefusesAnAnonymizedAccount(t *testing.T) {
	f := newStampedFixture(t, "mira@example.com")

	_, err := f.stamped.Refresh(context.Background(), f.acct.refreshLater)
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("Refresh with a valid refresh token for a stamped account = %v, want ErrUserNotFound — a live session must not survive the stamp", err)
	}
}

func TestChangePasswordRefusesAnAnonymizedAccount(t *testing.T) {
	f := newStampedFixture(t, "nils@example.com")

	hashBefore := f.storedHash(t)
	err := f.stamped.ChangePassword(context.Background(), f.acct.user.ID, "", validPassword, "Another-Horse-Battery-9!")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("ChangePassword with the CORRECT current password against a stamped account = %v, want ErrUserNotFound — no credential rotation may be armed on an account no one may authenticate as", err)
	}
	if after := f.storedHash(t); after != hashBefore {
		t.Error("a refused ChangePassword rotated the password hash anyway")
	}
}

func TestRequestEmailChangeRefusesAnAnonymizedAccount(t *testing.T) {
	f := newStampedFixture(t, "orly@example.com")

	_, err := f.stamped.RequestEmailChange(context.Background(), f.acct.user.ID, validPassword, "orly-moved@example.com")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("RequestEmailChange with the CORRECT password against a stamped account = %v, want ErrUserNotFound — arming an identifier rotation on an anonymized row would put a real address back on it", err)
	}
}

func TestResetPasswordRefusesAnAnonymizedAccount(t *testing.T) {
	f := newStampedFixture(t, "pav@example.com")

	hashBefore := f.storedHash(t)
	err := f.stamped.ResetPassword(context.Background(), f.acct.resetToken, "Another-Horse-Battery-9!")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("ResetPassword with a valid reset token for a stamped account = %v, want ErrUserNotFound — a reset token minted before the stamp must not set a working password on it", err)
	}
	if after := f.storedHash(t); after != hashBefore {
		t.Error("a refused ResetPassword rotated the password hash anyway")
	}
	if _, verr := f.store.FindVerificationByHash(context.Background(), token.HashOpaque(f.acct.resetToken)); verr != nil {
		t.Errorf("a refused ResetPassword burned the token (%v) — the refusal comes before the claim", verr)
	}
}

// TestVerifyEmailRefusesAnAnonymizedAccount covers the entry point the plan
// did not list, and the one with the sharpest consequence: an "email_change"
// redemption calls [auth.Store.UpdateUserEmail], which would move a REAL,
// verified address back onto a stamped row — un-scrubbing it and taking that
// address out of circulation again.
func TestVerifyEmailRefusesAnAnonymizedAccount(t *testing.T) {
	f := newStampedFixture(t, "quill@example.com")

	_, err := f.stamped.VerifyEmail(context.Background(), f.acct.changeToken)
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("VerifyEmail with a valid email-change token for a stamped account = %v, want ErrUserNotFound — redeeming it would put a real address back on an anonymized row", err)
	}

	got, ferr := f.store.FindUserByID(context.Background(), f.acct.user.ID)
	if ferr != nil {
		t.Fatalf("FindUserByID: %v", ferr)
	}
	if got.Email != f.acct.user.Email {
		t.Errorf("Email = %q after a refused VerifyEmail, want the unchanged %q", got.Email, f.acct.user.Email)
	}
	if _, verr := f.store.FindVerificationByHash(context.Background(), token.HashOpaque(f.acct.changeToken)); verr != nil {
		t.Errorf("a refused VerifyEmail burned the token (%v) — the refusal comes before the claim", verr)
	}
}

// TestAnonymizedAccountIsRefusedEndToEnd is the same sweep driven through a
// REAL AnonymizeAccount rather than a stamped double: belt and braces, and
// the shape a reader of this file will actually recognise as the product
// behaviour. It cannot replace the per-entry-point tests above, because here
// the address and the credential are gone too, so it cannot say WHICH of
// those three facts refused any given call.
func TestAnonymizedAccountIsRefusedEndToEnd(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "rune@example.com")

	if err := svc.AnonymizeAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}

	if _, err := svc.Login(ctx, "rune@example.com", validPassword, "203.0.113.6", "ua"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("Login after AnonymizeAccount = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.Login(ctx, anonymizedEmailFor(acct.user.ID), validPassword, "203.0.113.6", "ua"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("Login at the SCRUBBED address = %v, want ErrInvalidCredentials — the anonymized address is derived from the user id and is not a secret", err)
	}
	if tok, ok, err := svc.RequestPasswordReset(ctx, anonymizedEmailFor(acct.user.ID), "203.0.113.6"); ok || tok != "" || err != nil {
		t.Errorf("RequestPasswordReset at the scrubbed address = (%q, %v, %v), want (\"\", false, nil)", tok, ok, err)
	}
	for name, refresh := range map[string]string{
		"the first login's":  acct.refreshFirst,
		"the second login's": acct.refreshLater,
	} {
		if _, err := svc.Refresh(ctx, refresh); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Errorf("Refresh with %s token after AnonymizeAccount = %v, want ErrTokenInvalid", name, err)
		}
	}
	if err := svc.ChangePassword(ctx, acct.user.ID, "", validPassword, "Another-Horse-Battery-9!"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("ChangePassword after AnonymizeAccount = %v, want ErrUserNotFound", err)
	}
	if _, err := svc.RequestEmailChange(ctx, acct.user.ID, validPassword, "rune-moved@example.com"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("RequestEmailChange after AnonymizeAccount = %v, want ErrUserNotFound", err)
	}
	if err := svc.ResetPassword(ctx, acct.resetToken, "Another-Horse-Battery-9!"); err == nil {
		t.Error("a reset token minted before AnonymizeAccount still redeems")
	}
	if _, err := svc.VerifyEmail(ctx, acct.changeToken); err == nil {
		t.Error("an email-change token minted before AnonymizeAccount still redeems")
	}
}

// TestAnonymizeAccountLeavesTheRowReadable is the counterpart to the
// refusal sweep: [auth.Service.User] is NOT an authentication entry point
// and deliberately keeps working, because reading the stamped row is how an
// application discovers the account is anonymized at all.
func TestAnonymizeAccountLeavesTheRowReadable(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	acct := seedDeletableAccount(t, svc, store, "sage@example.com")

	if err := svc.AnonymizeAccount(ctx, acct.user.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}

	got, err := svc.User(ctx, acct.user.ID)
	if err != nil {
		t.Fatalf("User after AnonymizeAccount = %v, want the stamped row — reading it is how an application learns the account is anonymized", err)
	}
	if got.DeletedAt == nil {
		t.Error("User returned a record with DeletedAt = nil for an anonymized account")
	}
	if got.PasswordHash != "" {
		t.Error("User returned a password hash")
	}
}

// TestDeleteAccountStillWorksOnAStampedAccount pins that the refusal sweep
// did NOT catch the two deletion methods themselves. A stamped account must
// stay hard-deletable — refusing here would leave a row nothing could ever
// remove.
func TestDeleteAccountStillWorksOnAStampedAccount(t *testing.T) {
	f := newStampedFixture(t, "tova@example.com")

	if err := f.stamped.DeleteAccount(context.Background(), f.acct.user.ID, validPassword); err != nil {
		t.Fatalf("DeleteAccount on a stamped account = %v, want nil — a hard delete supersedes a soft one", err)
	}
	if _, err := f.store.FindUserByID(context.Background(), f.acct.user.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("FindUserByID after DeleteAccount = %v, want ErrUserNotFound", err)
	}
}
