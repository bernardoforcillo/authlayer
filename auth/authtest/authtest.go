// Package authtest is the executable contract for
// [github.com/bernardoforcillo/authlayer/auth.Store].
//
// auth.Store is an eighteen-method port, and seven of those methods carry an
// explicit MUST — normative requirements on the implementation, not on its
// callers, several of which exist because violating them reopens a specific
// security hole (an enumeration oracle at sign-up, a silently certified
// address nobody proved control of, two successful rotations of one refresh
// token, a revoked session family resurrected by the rotation that was
// racing its revocation). Until this package existed those seven were
// enforced by prose and by the two backends this repository happens to
// ship. A third-party backend author had no way to check their work.
//
// # Using it
//
// Write one test per backend:
//
//	func TestMyStoreSatisfiesTheAuthContract(t *testing.T) {
//	    authtest.RunStoreContract(t, func(t *testing.T) auth.Store {
//	        return myStoreWithEmptyTables(t)
//	    })
//	}
//
// The factory is called once per sub-check and MUST return a store whose
// three record kinds are EMPTY. Every check builds its own fixtures, so a
// store carrying rows from a previous check will produce spurious failures
// (a duplicate-email probe that finds an unexpected row, a
// ListSessionsByUser count that does not match). Register whatever teardown
// the backend needs with t.Cleanup inside the factory; the *testing.T handed
// to it is the sub-check's own, so cleanups run between checks rather than
// at the end of the suite. A factory is free to t.Skip — the live-PostgreSQL
// backend in this repository skips when its DSN is unset.
//
// Ids are UUIDv7 and emails are unique per call, so the suite runs against a
// backend that types its id columns as uuid (which store/drops does) as well
// as one that accepts any string.
//
// # What it checks, and what it deliberately does not
//
// Every check is named for the method and the obligation it exercises, and
// the doc comment on each one states exactly what it asserts. Six checks are
// races, because the obligations behind them are unreachable sequentially:
// [auth.Store.MarkRotated]'s single-winner compare-and-set;
// [auth.Store.CreateUser]'s and [auth.Store.UpdateUserEmail]'s
// one-address-one-account atomicity, one check each; a
// [auth.Store.MarkEmailVerified] racing the [auth.Store.UpdateUserEmail]
// that moves the address out from under it; the
// [auth.Store.CreateSuccessorSession] versus
// [auth.Store.DeleteSessionsByFamily] pair that must never leave a revoked
// family alive; and concurrent [auth.Store.DeleteSessionsByFamily] calls on
// one family. See concurrency.go for what each race can and cannot prove.
//
// The suite does NOT assert the points the port leaves to the
// implementation. ListSessionsByUser's order is unspecified, so results are
// sorted before comparison; "may be an empty slice or nil" is read through
// len only; the error a backend returns for a duplicate token hash is not
// classified into a sentinel because the port classifies only ErrIDTaken
// there; and [auth.Store.CreateSuccessorSession]'s returned Session on the
// ok=false path is not asserted, because the port specifies only that s was
// not persisted (unlike [auth.Store.MarkRotated]'s not-found path, which the
// port does spell out as a zero Session, and which is asserted).
//
// Two obligations this suite CANNOT fully check from outside the port, and
// does not pretend to:
//
//   - [auth.Store.CreateUser]'s MUST is that ErrEmailTaken is decided by the
//     same attempt that performs the write, so that a condition denying
//     writes but not reads cannot turn a duplicate address into a fast,
//     distinguishable answer. Whether a backend consulted a separate read
//     first is invisible to a caller; the port itself says an in-process map
//     may check before writing precisely because its write cannot
//     independently fail. What IS observable is the consequence when the
//     check and the write are not one atomic step — two concurrent creates
//     of one address both succeeding — and that is what
//     "CreateUser/ConcurrentSameAddressAdmitsOneWinner" asserts. The
//     read-authorization half is not testable here and is left to review of
//     the backend.
//   - [auth.Store.DeleteSessionsByFamily]'s second MUST — a backend using
//     the row-lock-then-delete shape must serialize concurrent calls on the
//     same family, because two unordered locking SELECTs can deadlock each
//     other — is asserted only through its observable consequence: K
//     concurrent calls on one family must all return nil and leave no
//     survivors. Forcing the lock-order inversion requires issuing
//     backend-specific SQL on a second connection in the opposite order,
//     which no port-level suite can do. store/drops carries that test
//     itself.
//
// # Token-hash uniqueness
//
// [auth.Session.TokenHash] and [auth.Verification.TokenHash] each carry a
// uniqueness MUST on the record type rather than on a method. Both are part
// of [RunStoreContract] like every other obligation — the checks are named
// "CreateSession/TokenHashIsUnique" and
// "CreateVerification/TokenHashIsUnique", after the write paths that have to
// enforce them.
//
// They were briefly a second exported entry point, because store/memory did
// not enforce them and folding them in would have failed one of this
// repository's own backends. That was the wrong way round, and the backend
// changed instead. A shared hash defeats [auth.Store.MarkRotated]'s
// single-winner contract with no atomicity defect at all — two concurrent
// callers each atomically win a DIFFERENT one of the colliding rows and both
// report a successful rotation — so this is the same property refresh-token
// rotation rests on, reached by another route, not a nicety a backend may
// decline. Shipping it as an opt-in extra would have told the next in-memory
// backend author it was optional, and would have let a caller develop
// against store/memory and meet the constraint for the first time in
// production against store/drops.
//
// What a rejected duplicate returns is still not asserted, for the reason
// the previous section gives.
package authtest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/internal/uid"
)

// RaceGoroutines is how many goroutines the mass-contention checks
// (MarkRotated's single winner, CreateUser's and UpdateUserEmail's
// one-address-one-account races) release against one record at once.
//
// It is exported so a backend can prepare for that much concurrency before
// the suite starts — a database-backed store whose connection pool grows on
// demand should raise its limits and warm the pool to at least this many
// connections in its factory, because goroutines that trickle in across a
// wide connection-setup window never actually contend, which silently
// weakens every race in this package. store/drops' own live suite does
// exactly that; see warmPool there.
const RaceGoroutines = 32

// RaceRounds is how many times the TWO-PARTY races are repeated against a
// fresh fixture: a rotation against a family revocation, and a verification
// against an address change. They resolve differently run to run, so a single
// round can miss an interleaving that a non-atomic implementation only
// exhibits sometimes, and the roles are swapped between rounds (see pair in
// concurrency.go). Rounds are cheap for an in-process store and cost a
// handful of round trips each for a database-backed one. The
// RaceGoroutines-wide races use their own, smaller round count — see
// massRaceRounds.
const RaceRounds = 8

// tb is the subset of *testing.T the checks use. It exists so this package's
// own tests can run a check against a deliberately non-compliant store and
// assert that the check FAILS — impossible with a concrete *testing.T, whose
// failures cannot be captured. Fatalf must abort the check, exactly as
// testing.T.Fatalf does.
type tb interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// check is one named obligation. fn is handed a store the caller has already
// guaranteed is empty.
type check struct {
	name string
	fn   func(t tb, st auth.Store)
}

// storeContractChecks is every check [RunStoreContract] runs, in order:
// records first, then the obligations that only appear under concurrency.
func storeContractChecks() []check {
	var all []check
	all = append(all, userChecks()...)
	all = append(all, sessionChecks()...)
	all = append(all, verificationChecks()...)
	all = append(all, housekeepingChecks()...)
	all = append(all, concurrencyChecks()...)
	return all
}

// RunStoreContract exercises every documented obligation of [auth.Store]
// against the implementation newStore returns, as one sub-test per
// obligation.
//
// newStore is called once per sub-test and must return a store with no
// users, sessions or verifications in it; see the package doc for why, and
// for what this suite deliberately does not assert. It must not return nil.
//
// This is the only entry point: every obligation [auth.Store] states is
// in here, token-hash uniqueness included.
func RunStoreContract(t *testing.T, newStore func(t *testing.T) auth.Store) {
	t.Helper()
	runChecks(t, storeContractChecks(), newStore)
}

func runChecks(t *testing.T, checks []check, newStore func(t *testing.T) auth.Store) {
	t.Helper()
	if newStore == nil {
		t.Fatalf("authtest: newStore must not be nil")
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			st := newStore(t)
			if st == nil {
				t.Fatalf("authtest: newStore returned a nil auth.Store")
			}
			c.fn(t, st)
		})
	}
}

// --- shared fixtures ---

// newID returns a fresh UUIDv7. Ids are UUIDs so the suite runs unchanged
// against a backend that types its id columns as uuid; see the package doc.
func newID() string { return uid.NewV7() }

// newEmail returns an address no other call in this package will produce, so
// checks never collide on the one uniqueness constraint every backend
// enforces. The unique part is a UUID, whose hyphens and hex digits are all
// legal in a local part.
func newEmail() string { return "authtest-" + uid.NewV7() + "@example.test" }

// stamp returns a UTC instant truncated to microseconds — the precision
// PostgreSQL's timestamptz keeps — so a round trip through a database-backed
// store compares equal to what was written.
func stamp() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// newUser builds a user record with the given address, unverified, with a
// non-empty password hash so a store that drops the field is caught.
func newUser(email string, at time.Time) auth.UserBase {
	return auth.UserBase{
		ID:           newID(),
		Email:        email,
		PasswordHash: "hash-" + uid.NewV7(),
		CreatedAt:    at,
		UpdatedAt:    at,
	}
}

// newSession builds a current (unrotated) session for userID in familyID,
// expiring an hour after at.
func newSession(userID, familyID string, at time.Time) auth.Session {
	return auth.Session{
		ID:        newID(),
		UserID:    userID,
		TokenHash: "sh-" + uid.NewV7(),
		FamilyID:  familyID,
		ExpiresAt: at.Add(time.Hour),
		CreatedAt: at,
		UserAgent: "authtest/1",
		IP:        "203.0.113.7",
	}
}

// newVerification builds a verification of the given purpose bound to email,
// expiring an hour after at.
func newVerification(userID, purpose, email string, at time.Time) auth.Verification {
	return auth.Verification{
		ID:        newID(),
		UserID:    userID,
		TokenHash: "vh-" + uid.NewV7(),
		Purpose:   purpose,
		Email:     email,
		ExpiresAt: at.Add(time.Hour),
		CreatedAt: at,
	}
}

// mustCreateUser creates u, failing the check if the store refuses it. Used
// for fixtures, never as the assertion itself.
func mustCreateUser(t tb, st auth.Store, u auth.UserBase) auth.UserBase {
	t.Helper()
	got, err := st.CreateUser(context.Background(), u)
	if err != nil {
		t.Fatalf("fixture CreateUser(%q): unexpected error %v", u.Email, err)
	}
	return got
}

// mustCreateSession persists s, failing the check if the store refuses it.
func mustCreateSession(t tb, st auth.Store, s auth.Session) auth.Session {
	t.Helper()
	got, err := st.CreateSession(context.Background(), s)
	if err != nil {
		t.Fatalf("fixture CreateSession(%s): unexpected error %v", s.ID, err)
	}
	return got
}

// mustCreateVerification persists v, failing the check if the store refuses
// it.
func mustCreateVerification(t tb, st auth.Store, v auth.Verification) auth.Verification {
	t.Helper()
	got, err := st.CreateVerification(context.Background(), v)
	if err != nil {
		t.Fatalf("fixture CreateVerification(%s): unexpected error %v", v.ID, err)
	}
	return got
}

// wantErrIs fails the check unless got matches want under errors.Is. The
// sentinels are compared with errors.Is, never by message, as [auth.Store]'s
// own doc requires.
func wantErrIs(t tb, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("%s: error = %v, want %v", what, got, want)
	}
}

// wantNoErr fails the check if got is non-nil.
func wantNoErr(t tb, what string, got error) {
	t.Helper()
	if got != nil {
		t.Fatalf("%s: unexpected error %v", what, got)
	}
}

// wantTimeEqual compares two instants with time.Time.Equal, so a backend
// that returns them in a different location than it was given still passes.
func wantTimeEqual(t tb, what string, got, want time.Time) {
	t.Helper()
	if !got.Equal(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}
