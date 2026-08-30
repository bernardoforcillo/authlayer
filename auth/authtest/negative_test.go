package authtest

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// errDuplicateTokenHash is what [refStore] reports when a second row would
// take a token hash another row already holds. [auth.Store] classifies only
// ErrIDTaken on the Create* methods and leaves token-hash uniqueness to the
// backend's own constraint, so this is deliberately not one of the package's
// sentinels — exactly like store/drops, which lets PostgreSQL's own unique
// violation through unwrapped on that path.
var errDuplicateTokenHash = errors.New("authtest: token hash already exists")

// gap is how long the deliberately non-atomic doubles below hold their
// check-then-write window open.
//
// A real split-lock implementation's window is sub-microsecond, and this
// project has measured twice (store/memory's MarkRotated mutation
// experiment, store/drops' unwarmed-pool measurement) that a window that
// narrow is caught only a few percent of the time — far too unreliable for a
// control whose whole job is to prove a check bites. Widening the window to
// milliseconds makes each control deterministic: the concurrent caller
// always lands inside it. What these controls therefore prove is that the
// check DETECTS the defect when the interleaving occurs, not that it forces
// the interleaving on a subtly broken backend — a limit the contract checks'
// own doc comments state rather than paper over.
const gap = 5 * time.Millisecond

// ── The non-compliant doubles ───────────────────────────────────────────
//
// Each is exactly one defect away from [refStore]: it embeds one and
// overrides a single method with a deliberately wrong shape. That is what
// makes "this check failed" evidence about the defect and nothing else — see
// TestTheReferenceStorePassesTheContract.

// everyCallerWins has no compare-and-set at all: MarkRotated stamps
// RotatedAt and reports ok=true for every caller, however many present the
// same token and whether or not the session is already rotated. It is the
// grossly non-atomic shape [auth.Store.MarkRotated]'s MUST forbids.
type everyCallerWins struct{ *refStore }

func (s everyCallerWins) MarkRotated(_ context.Context, tokenHash string, now time.Time) (auth.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.TokenHash != tokenHash {
			continue
		}
		sess.RotatedAt = &now
		s.sessions[id] = sess
		return sess, true, nil
	}
	return auth.Session{}, false, auth.ErrSessionNotFound
}

// expiryFoldedIntoRotation "helpfully" refuses to rotate an expired session,
// which the port explicitly forbids: an expired token is ordinary
// end-of-life, and reporting it the way a replay is reported makes every
// expired refresh revoke a whole family.
type expiryFoldedIntoRotation struct{ *refStore }

func (s expiryFoldedIntoRotation) MarkRotated(_ context.Context, tokenHash string, now time.Time) (auth.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.TokenHash != tokenHash {
			continue
		}
		if sess.RotatedAt != nil || sess.ExpiresAt.Before(now) {
			return sess, false, nil
		}
		sess.RotatedAt = &now
		s.sessions[id] = sess
		return sess, true, nil
	}
	return auth.Session{}, false, auth.ErrSessionNotFound
}

// splitCreateUser decides ErrEmailTaken from a read, releases its lock, and
// only then writes — the check-then-write shape [auth.Store.CreateUser]'s
// MUST forbids for any backend whose write can fail independently of the
// read.
type splitCreateUser struct{ *refStore }

func (s splitCreateUser) CreateUser(_ context.Context, u auth.UserBase) (auth.UserBase, error) {
	u.Email = auth.NormalizeEmail(u.Email)
	s.mu.Lock()
	if _, exists := s.users[u.ID]; exists {
		s.mu.Unlock()
		return auth.UserBase{}, auth.ErrIDTaken
	}
	taken := s.emailHeldBy(u.Email, "")
	s.mu.Unlock()
	if taken {
		return auth.UserBase{}, auth.ErrEmailTaken
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = u
	return u, nil
}

// laggingReplicaReads answers FindUserByEmail from a snapshot that is
// refreshed only when the next write arrives — the read/write topology
// [auth.Store.FindUserByEmail]'s read-your-writes MUST rules out. A row
// CreateUser has just returned successfully for is invisible to the
// FindUserByEmail that follows it, while an address created earlier resolves
// normally: precisely the asymmetry that turns Service.SignUp into an
// enumeration oracle.
type laggingReplicaReads struct {
	*refStore
	replicaMu sync.Mutex
	replica   map[string]auth.UserBase
}

func newLaggingReplicaReads() *laggingReplicaReads {
	return &laggingReplicaReads{refStore: newRefStore(), replica: map[string]auth.UserBase{}}
}

func (s *laggingReplicaReads) CreateUser(ctx context.Context, u auth.UserBase) (auth.UserBase, error) {
	s.replicaMu.Lock()
	s.mu.Lock()
	s.replica = make(map[string]auth.UserBase, len(s.users))
	for id, existing := range s.users {
		s.replica[id] = existing
	}
	s.mu.Unlock()
	s.replicaMu.Unlock()
	return s.refStore.CreateUser(ctx, u)
}

func (s *laggingReplicaReads) FindUserByEmail(_ context.Context, email string) (auth.UserBase, error) {
	s.replicaMu.Lock()
	defer s.replicaMu.Unlock()
	email = auth.NormalizeEmail(email)
	for _, u := range s.replica {
		if u.Email == email {
			return u, nil
		}
	}
	return auth.UserBase{}, auth.ErrUserNotFound
}

// splitMarkEmailVerified compares the address under one lock acquisition and
// stamps under a second — the read-then-write shape
// [auth.Store.MarkEmailVerified]'s MUST forbids. A concurrent
// UpdateUserEmail landing in the window makes it certify an address it never
// checked.
type splitMarkEmailVerified struct{ *refStore }

func (s splitMarkEmailVerified) MarkEmailVerified(_ context.Context, userID, email string, now time.Time) error {
	s.mu.Lock()
	u, ok := s.users[userID]
	s.mu.Unlock()
	if !ok {
		return auth.ErrUserNotFound
	}
	if u.Email != auth.NormalizeEmail(email) {
		return auth.ErrEmailMismatch
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.users[userID]
	if !ok {
		return auth.ErrUserNotFound
	}
	current.EmailVerifiedAt = &now
	current.UpdatedAt = now
	s.users[userID] = current
	return nil
}

// splitUpdateUserEmail looks for a conflicting row under one lock
// acquisition and writes under a second — the read-then-write shape
// [auth.Store.UpdateUserEmail]'s MUST forbids. Two callers naming the same
// address both find it free and both take it.
type splitUpdateUserEmail struct{ *refStore }

func (s splitUpdateUserEmail) UpdateUserEmail(_ context.Context, userID, email string, now time.Time) error {
	email = auth.NormalizeEmail(email)
	s.mu.Lock()
	if _, ok := s.users[userID]; !ok {
		s.mu.Unlock()
		return auth.ErrUserNotFound
	}
	taken := s.emailHeldBy(email, userID)
	s.mu.Unlock()
	if taken {
		return auth.ErrEmailTaken
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[userID]
	u.Email = email
	u.EmailVerifiedAt = nil
	u.UpdatedAt = now
	s.users[userID] = u
	return nil
}

// splitCreateSuccessorSession checks the predecessor under one lock
// acquisition and inserts under a second — the read-then-write shape
// [auth.Store.CreateSuccessorSession]'s MUST forbids. A family revocation
// landing in the window is invisible to a caller that has already finished
// checking, and the insert resurrects the family anyway.
type splitCreateSuccessorSession struct{ *refStore }

func (s splitCreateSuccessorSession) CreateSuccessorSession(_ context.Context, predecessorID string, sess auth.Session) (auth.Session, bool, error) {
	s.mu.Lock()
	if _, exists := s.sessions[sess.ID]; exists {
		s.mu.Unlock()
		return auth.Session{}, false, auth.ErrIDTaken
	}
	_, alive := s.sessions[predecessorID]
	s.mu.Unlock()
	if !alive {
		return auth.Session{}, false, nil
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return sess, true, nil
}

// resurrectingSuccessor drops the liveness check entirely and inserts
// unconditionally — [auth.Store.CreateSession]'s behaviour under
// CreateSuccessorSession's name, which is exactly what the port says a
// caller that already won MarkRotated must NOT do.
type resurrectingSuccessor struct{ *refStore }

func (s resurrectingSuccessor) CreateSuccessorSession(_ context.Context, _ string, sess auth.Session) (auth.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[sess.ID]; exists {
		return auth.Session{}, false, auth.ErrIDTaken
	}
	s.sessions[sess.ID] = sess
	return sess, true, nil
}

// preWaitSnapshotDelete is the single-autocommit-DELETE shape
// [auth.Store.DeleteSessionsByFamily]'s first MUST calls out as NOT
// sufficient: it takes its snapshot of the family BEFORE the wait and then
// removes only what that earlier snapshot held, so a successor another
// caller committed while it waited survives the revocation.
type preWaitSnapshotDelete struct{ *refStore }

func (s preWaitSnapshotDelete) DeleteSessionsByFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	var snapshot []string
	for id, sess := range s.sessions {
		if sess.FamilyID == familyID {
			snapshot = append(snapshot, id)
		}
	}
	s.mu.Unlock()

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range snapshot {
		delete(s.sessions, id)
	}
	return nil
}

// deadlockingFamilyDelete stands in for the backend
// [auth.Store.DeleteSessionsByFamily]'s second MUST describes: one that
// takes row locks in an unordered scan and does not serialize per family, so
// two concurrent calls on one family can deadlock each other and the loser
// comes back with an error instead of a completed revocation.
type deadlockingFamilyDelete struct {
	*refStore
	inFlightMu sync.Mutex
	inFlight   map[string]bool
}

func newDeadlockingFamilyDelete() *deadlockingFamilyDelete {
	return &deadlockingFamilyDelete{refStore: newRefStore(), inFlight: map[string]bool{}}
}

func (s *deadlockingFamilyDelete) DeleteSessionsByFamily(ctx context.Context, familyID string) error {
	s.inFlightMu.Lock()
	if s.inFlight[familyID] {
		s.inFlightMu.Unlock()
		return errors.New("authtest: deadlock detected (SQLSTATE 40P01)")
	}
	s.inFlight[familyID] = true
	s.inFlightMu.Unlock()

	time.Sleep(gap)
	err := s.refStore.DeleteSessionsByFamily(ctx, familyID)

	s.inFlightMu.Lock()
	delete(s.inFlight, familyID)
	s.inFlightMu.Unlock()
	return err
}

// silentOverwrites replaces an existing row instead of reporting ErrIDTaken,
// on all three Create* methods — the one thing the port says a backend must
// never do on an id collision.
type silentOverwrites struct{ *refStore }

func (s silentOverwrites) CreateUser(_ context.Context, u auth.UserBase) (auth.UserBase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u.Email = auth.NormalizeEmail(u.Email)
	if s.emailHeldBy(u.Email, u.ID) {
		return auth.UserBase{}, auth.ErrEmailTaken
	}
	s.users[u.ID] = u
	return u, nil
}

func (s silentOverwrites) CreateSession(_ context.Context, sess auth.Session) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return sess, nil
}

func (s silentOverwrites) CreateVerification(_ context.Context, v auth.Verification) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Email = auth.NormalizeEmail(v.Email)
	s.verifications[v.ID] = v
	return v, nil
}

// rawUserEmail stores and matches addresses exactly as given, skipping
// [auth.NormalizeEmail] on the user write and read paths — so a case or
// whitespace variant creates a second account for one address.
type rawUserEmail struct{ *refStore }

func (s rawUserEmail) CreateUser(_ context.Context, u auth.UserBase) (auth.UserBase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[u.ID]; exists {
		return auth.UserBase{}, auth.ErrIDTaken
	}
	if s.emailHeldBy(u.Email, "") {
		return auth.UserBase{}, auth.ErrEmailTaken
	}
	s.users[u.ID] = u
	return u, nil
}

// rawVerificationEmail skips normalization on Verification.Email — the
// omission that field's doc calls out by name, because an un-normalized
// stored address breaks MarkEmailVerified's own comparison for a variant
// that is in fact the same address.
type rawVerificationEmail struct{ *refStore }

func (s rawVerificationEmail) CreateVerification(_ context.Context, v auth.Verification) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.verifications[v.ID]; exists {
		return auth.Verification{}, auth.ErrIDTaken
	}
	s.verifications[v.ID] = v
	return v, nil
}

// inclusivePurge treats the cutoff as "expired at or before", not "expired
// strictly before", so a record whose ExpiresAt is exactly the cutoff is
// swept when the port says it survives.
type inclusivePurge struct{ *refStore }

func (s inclusivePurge) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.sessions {
		if !sess.ExpiresAt.After(before) {
			delete(s.sessions, id)
			n++
		}
	}
	for id, v := range s.verifications {
		if !v.ExpiresAt.After(before) {
			delete(s.verifications, id)
			n++
		}
	}
	return n, nil
}

// sharedTokenHashes lets two rows of the same kind hold one token hash — the
// uniqueness MUST [auth.Session.TokenHash] and [auth.Verification.TokenHash]
// state on the record types, checked by "CreateSession/TokenHashIsUnique"
// and "CreateVerification/TokenHashIsUnique" inside [RunStoreContract].
type sharedTokenHashes struct{ *refStore }

func (s sharedTokenHashes) CreateSession(_ context.Context, sess auth.Session) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[sess.ID]; exists {
		return auth.Session{}, auth.ErrIDTaken
	}
	s.sessions[sess.ID] = sess
	return sess, nil
}

func (s sharedTokenHashes) CreateVerification(_ context.Context, v auth.Verification) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.verifications[v.ID]; exists {
		return auth.Verification{}, auth.ErrIDTaken
	}
	v.Email = auth.NormalizeEmail(v.Email)
	s.verifications[v.ID] = v
	return v, nil
}

// droppedDeletedAt stores a user without its DeletedAt, the way a backend
// whose table has no deleted_at column at all behaves — store/drops'
// CREATE TABLE IF NOT EXISTS cannot add the column to a users table that
// already exists, so this is the shape a v0.1.0 database that skipped the
// ALTER TABLE actually presents. A dropped stamp makes an anonymized
// account indistinguishable from a live one.
type droppedDeletedAt struct{ *refStore }

func (s droppedDeletedAt) CreateUser(ctx context.Context, u auth.UserBase) (auth.UserBase, error) {
	u.DeletedAt = nil
	return s.refStore.CreateUser(ctx, u)
}

// cascadingDeleteUser takes the user's sessions with it, the ON DELETE
// CASCADE shape [auth.Store.DeleteUser]'s "the user row only" rules out: the
// service orders the cascade so access stops first, and a store that
// performs its own hides whether that order was followed.
type cascadingDeleteUser struct{ *refStore }

func (s cascadingDeleteUser) DeleteUser(ctx context.Context, userID string) error {
	if err := s.refStore.DeleteUser(ctx, userID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

// silentDeleteUser answers a missing user with nil instead of
// ErrUserNotFound, so a caller deleting an account that was never there
// cannot tell.
type silentDeleteUser struct{ *refStore }

func (s silentDeleteUser) DeleteUser(ctx context.Context, userID string) error {
	if err := s.refStore.DeleteUser(ctx, userID); errors.Is(err, auth.ErrUserNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	return nil
}

// oneFamilyOnlySessionDelete revokes a single one of the user's families
// rather than all of them — the defect [auth.Store.DeleteSessionsByUser]'s
// own doc says a caller cannot work around, since it is precisely why the
// method exists instead of a loop over DeleteSessionsByFamily. It is the
// committed form of this task's mandatory mutation.
type oneFamilyOnlySessionDelete struct{ *refStore }

func (s oneFamilyOnlySessionDelete) DeleteSessionsByUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	family := ""
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			family = sess.FamilyID
			break
		}
	}
	s.mu.Unlock()
	if family == "" {
		return nil
	}
	// Not s.refStore.DeleteSessionsByFamily: this type overrides only
	// DeleteSessionsByUser, so the promoted method is the same one.
	return s.DeleteSessionsByFamily(ctx, family)
}

// notFoundOnEmptySweep reports a sweep that matched no rows as a not-found
// error on both by-user methods, which the port says is not an error at all:
// a user with no session and no pending token is the ordinary case, and a
// caller that treats it as a failure aborts a deletion that had nothing to
// do.
type notFoundOnEmptySweep struct{ *refStore }

func (s notFoundOnEmptySweep) DeleteSessionsByUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	found := false
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return auth.ErrSessionNotFound
	}
	return s.refStore.DeleteSessionsByUser(ctx, userID)
}

func (s notFoundOnEmptySweep) DeleteVerificationsByUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	found := false
	for _, v := range s.verifications {
		if v.UserID == userID {
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return auth.ErrVerificationNotFound
	}
	return s.refStore.DeleteVerificationsByUser(ctx, userID)
}

// onePurposeOnlyVerificationDelete sweeps only "password_reset", the shape a
// backend implemented as a delegation to
// [auth.Store.DeleteVerificationsByUserAndPurpose] over a hard-coded list
// takes — leaving a pending magic link or email-change token alive for an
// account being deleted. Purpose is an open string the service layer
// defines, so no such list can be complete.
type onePurposeOnlyVerificationDelete struct{ *refStore }

func (s onePurposeOnlyVerificationDelete) DeleteVerificationsByUser(ctx context.Context, userID string) error {
	return s.DeleteVerificationsByUserAndPurpose(ctx, userID, "password_reset")
}

// ── Driving a check and capturing its verdict ──────────────────────────

// recorder is a [tb] that records failures instead of reporting them to the
// test framework, so a check can be run against a store that is SUPPOSED to
// fail it. Fatalf calls runtime.Goexit, exactly as testing.T.Fatalf does, so
// a check that gives up mid-way stops where it would have stopped for real.
type recorder struct {
	mu       sync.Mutex
	failures []string
}

func (r *recorder) Helper()                           {}
func (r *recorder) Logf(string, ...any)               {}
func (r *recorder) Errorf(format string, args ...any) { r.record(format, args) }

func (r *recorder) Fatalf(format string, args ...any) {
	r.record(format, args)
	runtime.Goexit()
}

func (r *recorder) record(format string, args []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// runCheck runs one check against st and reports what it complained about.
// The check runs in its own goroutine so the recorder's Fatalf can end it
// with runtime.Goexit the way testing.T.Fatalf would.
func runCheck(c check, st auth.Store) []string {
	r := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.fn(r, st)
	}()
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.failures...)
}

// allChecks is every check [RunStoreContract] runs. It stays a named helper
// rather than a direct call so the negative-control loop below reads as
// "run the whole suite against this defective store".
func allChecks() []check {
	return storeContractChecks()
}

func findCheck(t *testing.T, name string) check {
	t.Helper()
	for _, c := range allChecks() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no check named %q — the negative-control table names a check that does not exist", name)
	return check{}
}

// TestTheReferenceStorePassesTheContract is the control on the controls
// below. [refStore] is a correct store, so [RunStoreContract] must pass it
// end to end; if it did not, a non-compliant double failing a check would
// prove nothing about the defect injected into it.
func TestTheReferenceStorePassesTheContract(t *testing.T) {
	RunStoreContract(t, func(*testing.T) auth.Store { return newRefStore() })
}

// TestTheContractRejectsNonCompliantStores is what makes this suite worth
// having: a contract suite that passes everything is worthless, and that
// failure mode is invisible without controls. Each row below is a store that
// is exactly one defect away from [refStore], paired with the check that
// must catch that defect. The whole suite is run against each one, the named
// check is required to have failed, and every check that failed is logged so
// the blast radius of each defect is on the record rather than inferred.
func TestTheContractRejectsNonCompliantStores(t *testing.T) {
	cases := []struct {
		defect   string
		check    string
		newStore func() auth.Store
	}{
		{
			defect:   "MarkRotated lets every caller win",
			check:    "MarkRotated/ConcurrentCallersAdmitExactlyOneWinner",
			newStore: func() auth.Store { return everyCallerWins{newRefStore()} },
		},
		{
			defect:   "MarkRotated lets every caller win (sequentially, too)",
			check:    "MarkRotated/WinsOnceThenReportsTheRotatedSession",
			newStore: func() auth.Store { return everyCallerWins{newRefStore()} },
		},
		{
			defect:   "MarkRotated refuses an expired but unrotated session",
			check:    "MarkRotated/IgnoresExpiry",
			newStore: func() auth.Store { return expiryFoldedIntoRotation{newRefStore()} },
		},
		{
			defect:   "CreateUser checks the address, then writes under a second lock",
			check:    "CreateUser/ConcurrentSameAddressAdmitsOneWinner",
			newStore: func() auth.Store { return splitCreateUser{newRefStore()} },
		},
		{
			defect:   "FindUserByEmail answers from a lagging replica",
			check:    "FindUserByEmail/ReadsItsOwnWrites",
			newStore: func() auth.Store { return newLaggingReplicaReads() },
		},
		{
			defect:   "MarkEmailVerified compares under one lock and stamps under another",
			check:    "MarkEmailVerified/NeverCertifiesAnAddressBeingChangedAway",
			newStore: func() auth.Store { return splitMarkEmailVerified{newRefStore()} },
		},
		{
			defect:   "UpdateUserEmail checks for a conflict, then writes under a second lock",
			check:    "UpdateUserEmail/ConcurrentSameAddressAdmitsOneWinner",
			newStore: func() auth.Store { return splitUpdateUserEmail{newRefStore()} },
		},
		{
			defect:   "CreateSuccessorSession checks the predecessor, then inserts under a second lock",
			check:    "CreateSuccessorSession/NeverSurvivesAConcurrentFamilyRevocation",
			newStore: func() auth.Store { return splitCreateSuccessorSession{newRefStore()} },
		},
		{
			defect:   "CreateSuccessorSession inserts unconditionally",
			check:    "CreateSuccessorSession/RefusesWhenThePredecessorIsGone",
			newStore: func() auth.Store { return resurrectingSuccessor{newRefStore()} },
		},
		{
			defect:   "DeleteSessionsByFamily snapshots the family before the wait, like a single autocommit DELETE",
			check:    "CreateSuccessorSession/NeverSurvivesAConcurrentFamilyRevocation",
			newStore: func() auth.Store { return preWaitSnapshotDelete{newRefStore()} },
		},
		{
			defect:   "DeleteSessionsByFamily does not serialize concurrent calls on one family",
			check:    "DeleteSessionsByFamily/ConcurrentCallsOnOneFamilyAllSucceed",
			newStore: func() auth.Store { return newDeadlockingFamilyDelete() },
		},
		{
			defect:   "CreateUser silently replaces a row on an id collision",
			check:    "CreateUser/DuplicateIDReturnsErrIDTakenAndKeepsTheRow",
			newStore: func() auth.Store { return silentOverwrites{newRefStore()} },
		},
		{
			defect:   "CreateSession silently replaces a row on an id collision",
			check:    "CreateSession/DuplicateIDReturnsErrIDTakenAndKeepsTheRow",
			newStore: func() auth.Store { return silentOverwrites{newRefStore()} },
		},
		{
			defect:   "CreateVerification silently replaces a row on an id collision",
			check:    "CreateVerification/DuplicateIDReturnsErrIDTakenAndKeepsTheRow",
			newStore: func() auth.Store { return silentOverwrites{newRefStore()} },
		},
		{
			defect:   "CreateUser stores the address without normalizing it",
			check:    "CreateUser/NormalizesTheAddress",
			newStore: func() auth.Store { return rawUserEmail{newRefStore()} },
		},
		{
			defect:   "CreateVerification stores Verification.Email without normalizing it",
			check:    "CreateVerification/RoundTripAndNormalizesForEveryPurpose",
			newStore: func() auth.Store { return rawVerificationEmail{newRefStore()} },
		},
		{
			defect:   "PurgeExpired treats the cutoff as inclusive",
			check:    "PurgeExpired/CutoffIsStrictAcrossBothKinds",
			newStore: func() auth.Store { return inclusivePurge{newRefStore()} },
		},
		{
			defect:   "two sessions may share one token hash",
			check:    "CreateSession/TokenHashIsUnique",
			newStore: func() auth.Store { return sharedTokenHashes{newRefStore()} },
		},
		{
			defect:   "two verifications may share one token hash",
			check:    "CreateVerification/TokenHashIsUnique",
			newStore: func() auth.Store { return sharedTokenHashes{newRefStore()} },
		},
		{
			defect:   "CreateUser drops UserBase.DeletedAt",
			check:    "CreateUser/RoundTripsDeletedAt",
			newStore: func() auth.Store { return droppedDeletedAt{newRefStore()} },
		},
		{
			defect:   "DeleteUser cascades to the user's sessions",
			check:    "DeleteUser/RemovesTheUserRowOnly",
			newStore: func() auth.Store { return cascadingDeleteUser{newRefStore()} },
		},
		{
			defect:   "DeleteUser answers a missing user with nil",
			check:    "DeleteUser/UnknownIDReturnsErrUserNotFound",
			newStore: func() auth.Store { return silentDeleteUser{newRefStore()} },
		},
		{
			defect:   "DeleteSessionsByUser revokes only one of the user's families",
			check:    "DeleteSessionsByUser/RemovesEveryFamilyAndOnlyThatUser",
			newStore: func() auth.Store { return oneFamilyOnlySessionDelete{newRefStore()} },
		},
		{
			defect:   "DeleteSessionsByUser reports a user with no sessions as not found",
			check:    "DeleteSessionsByUser/ZeroRowsIsNotAnError",
			newStore: func() auth.Store { return notFoundOnEmptySweep{newRefStore()} },
		},
		{
			defect:   "DeleteVerificationsByUser sweeps only one purpose",
			check:    "DeleteVerificationsByUser/RemovesEveryPurposeAndOnlyThatUser",
			newStore: func() auth.Store { return onePurposeOnlyVerificationDelete{newRefStore()} },
		},
		{
			defect:   "DeleteVerificationsByUser reports a user with no verifications as not found",
			check:    "DeleteVerificationsByUser/ZeroRowsIsNotAnError",
			newStore: func() auth.Store { return notFoundOnEmptySweep{newRefStore()} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.defect, func(t *testing.T) {
			want := findCheck(t, tc.check)

			var caught []string
			var firstMessage string
			for _, c := range allChecks() {
				failures := runCheck(c, tc.newStore())
				if len(failures) == 0 {
					continue
				}
				caught = append(caught, c.name)
				if c.name == want.name {
					firstMessage = failures[0]
				}
			}
			sort.Strings(caught)

			if firstMessage == "" {
				t.Fatalf("%s PASSED %s — the check does not catch this defect. Checks that did fail: %v", tc.defect, tc.check, caught)
			}
			t.Logf("%s\n  caught by %s: %s\n  all checks that failed: %v", tc.defect, tc.check, firstMessage, caught)
		})
	}
}
