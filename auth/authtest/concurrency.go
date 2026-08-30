package authtest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// massRaceRounds is how many times the RaceGoroutines-wide races are
// repeated against a fresh fixture. They are far more expensive than the
// two-party races — RaceGoroutines calls each — and a single-winner
// violation shows up on essentially every round when it exists at all, so a
// handful of rounds buys what [RaceRounds] buys the two-party races.
const massRaceRounds = 3

func concurrencyChecks() []check {
	return []check{
		{"MarkRotated/ConcurrentCallersAdmitExactlyOneWinner", checkMarkRotatedOneWinner},
		{"CreateUser/ConcurrentSameAddressAdmitsOneWinner", checkCreateUserOneWinner},
		{"UpdateUserEmail/ConcurrentSameAddressAdmitsOneWinner", checkUpdateUserEmailOneWinner},
		{"MarkEmailVerified/NeverCertifiesAnAddressBeingChangedAway", checkMarkEmailVerifiedRace},
		{"CreateSuccessorSession/NeverSurvivesAConcurrentFamilyRevocation", checkSuccessorVersusRevocation},
		{"DeleteSessionsByFamily/ConcurrentCallsOnOneFamilyAllSucceed", checkConcurrentFamilyRevocations},
	}
}

// release runs fn in n goroutines, all blocked on one channel and released
// at the same instant to maximize contention, and returns once every one has
// finished. fn is handed its own index so it can pick a distinct fixture.
//
// The goroutines never touch the tb: reporting a failure from a goroutine
// other than the test's own is not valid with testing.T, so every check
// collects results here and asserts on them afterwards.
func release(n int, fn func(i int)) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			fn(i)
		}(i)
	}
	close(start)
	wg.Wait()
}

// pair runs two operations concurrently through [release], swapping which one
// is handed index 0 on odd rounds.
//
// The swap is load-bearing, not tidiness. Closing a channel readies its
// waiters in the order they blocked, and each readied goroutine displaces the
// previous one from the P's runnext slot, so the LAST goroutine started is
// overwhelmingly the first to run: measured at 198 of 200 rounds, by a
// throwaway probe run while building this package rather than by any
// committed test. A two-party race that always gives the same operation the
// same index therefore explores essentially one interleaving, with the other
// operation running to completion before its partner starts. The committed
// evidence for that is the consequence: two of this package's own split-lock
// negative controls PASSED the unswapped version of these checks — which is
// how the bias was found — and fail them once the roles alternate.
func pair(round int, a, b func()) {
	first, second := a, b
	if round%2 == 1 {
		first, second = b, a
	}
	release(2, func(i int) {
		if i == 0 {
			first()
			return
		}
		second()
	})
}

// checkMarkRotatedOneWinner is [auth.Store.MarkRotated]'s central MUST:
// however many callers present the same refresh token at once, exactly one
// may see ok=true. RaceGoroutines goroutines, all released together, race one
// freshly created and unrotated session; the tally must be one winner and no
// errors, and the stored RotatedAt must be the single instant every caller
// raced with — pinning that the winner's write persisted the value it was
// asked to, not some other one a subtler bug could substitute while leaving
// the count at one.
//
// A read-then-write MarkRotated lets two callers both observe the session
// unrotated and both mint a successor, after which the presented token is
// never replayed, reuse detection never fires, and a stolen token becomes an
// undetectable parallel session.
//
// How reliably this catches a SUBTLY non-atomic implementation depends on
// the backend, and this suite cannot promise more than the contention it can
// create from outside: a split-lock in-process store has a sub-microsecond
// window that most interleavings resolve past, while a database-backed store
// with a cold connection pool lets goroutines trickle in across a window far
// wider than the race itself (see [RaceGoroutines] on warming the pool
// first). It catches a grossly non-atomic implementation — one with no
// compare-and-set at all — every time.
func checkMarkRotatedOneWinner(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	for round := 0; round < massRaceRounds; round++ {
		s := mustCreateSession(t, st, newSession(newID(), newID(), at))
		shared := at.Add(time.Duration(round+1) * time.Minute)

		var mu sync.Mutex
		winners, failures := 0, 0
		var firstErr error
		release(RaceGoroutines, func(int) {
			_, ok, err := st.MarkRotated(ctx, s.TokenHash, shared)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failures++
				if firstErr == nil {
					firstErr = err
				}
			case ok:
				winners++
			}
		})

		if failures != 0 {
			t.Fatalf("round %d: %d of %d concurrent MarkRotated calls returned an error, first: %v — losing the race is (session, false, nil), not an error", round, failures, RaceGoroutines, firstErr)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d of %d concurrent MarkRotated calls reported ok=true against one session, want exactly 1 — the compare-and-set is not atomic", round, winners, RaceGoroutines)
		}

		got, err := st.FindSessionByHash(ctx, s.TokenHash)
		wantNoErr(t, "FindSessionByHash", err)
		if got.RotatedAt == nil {
			t.Fatalf("round %d: stored RotatedAt = nil after a winning MarkRotated", round)
		}
		wantTimeEqual(t, "stored RotatedAt", *got.RotatedAt, shared)
	}
}

// checkCreateUserOneWinner drives the observable half of
// [auth.Store.CreateUser]'s MUST: RaceGoroutines goroutines, released
// together, each create a distinct user id under ONE normalized address.
// Exactly one may succeed and every other must be told ErrEmailTaken, and
// the address must afterwards resolve to the winner.
//
// A check-then-write CreateUser whose check and write are not one atomic
// step lets several goroutines all find the address free and all go on to
// write it, leaving several users sharing one address — after which
// Service.Login and Service.RequestPasswordReset, which both resolve a user
// by address, stop being well-defined and start depending on row order.
//
// This does NOT check the other half of that MUST — that ErrEmailTaken is
// decided by the write attempt rather than by a separately-authorized read,
// so that a role granted SELECT but not INSERT cannot make a duplicate
// address answer faster than a new one. That is a property of the backend's
// own failure topology, invisible to any caller; see the package doc.
func checkCreateUserOneWinner(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < massRaceRounds; round++ {
		at := stamp()
		email := newEmail()
		users := make([]auth.UserBase, RaceGoroutines)
		for i := range users {
			users[i] = newUser(email, at)
		}

		errs := make([]error, RaceGoroutines)
		release(RaceGoroutines, func(i int) {
			_, errs[i] = st.CreateUser(ctx, users[i])
		})

		winner := -1
		for i, err := range errs {
			switch {
			case err == nil:
				if winner >= 0 {
					t.Fatalf("round %d: CreateUser succeeded for both %s and %s under one address — two accounts now share it", round, users[winner].ID, users[i].ID)
				}
				winner = i
			case errors.Is(err, auth.ErrEmailTaken):
			default:
				t.Fatalf("round %d: CreateUser returned %v for a losing caller, want ErrEmailTaken", round, err)
			}
		}
		if winner < 0 {
			t.Fatalf("round %d: all %d concurrent CreateUser calls for one address failed, want exactly one winner", round, RaceGoroutines)
		}

		got, err := st.FindUserByEmail(ctx, email)
		wantNoErr(t, "FindUserByEmail after the race", err)
		if got.ID != users[winner].ID {
			t.Fatalf("round %d: the contested address resolves to %q, want the one caller CreateUser reported success to, %q", round, got.ID, users[winner].ID)
		}
	}
}

// checkUpdateUserEmailOneWinner is [auth.Store.UpdateUserEmail]'s MUST:
// RaceGoroutines existing users, each with its own address, all move to ONE
// target address at the same instant. Exactly one may succeed; every other
// must be told ErrEmailTaken, and afterwards exactly one user may hold the
// address.
//
// A read-then-write implementation — a SELECT for a conflicting row, then a
// separate UPDATE — lets two callers both find the address free and both
// write it. This is the one place that race is caught: Service's
// RequestEmailChange deliberately performs no pre-check of its own, because
// a pre-check there would be an un-rate-limited "is this address
// registered?" oracle, so the store at redemption is the only enforcement
// point there is.
func checkUpdateUserEmailOneWinner(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < massRaceRounds; round++ {
		at := stamp()
		movers := make([]auth.UserBase, RaceGoroutines)
		for i := range movers {
			movers[i] = mustCreateUser(t, st, newUser(newEmail(), at))
		}
		target := newEmail()
		changedAt := at.Add(time.Minute)

		errs := make([]error, RaceGoroutines)
		release(RaceGoroutines, func(i int) {
			errs[i] = st.UpdateUserEmail(ctx, movers[i].ID, target, changedAt)
		})

		winner := -1
		for i, err := range errs {
			switch {
			case err == nil:
				if winner >= 0 {
					t.Fatalf("round %d: UpdateUserEmail succeeded for both %s and %s onto one address — two accounts now share it", round, movers[winner].ID, movers[i].ID)
				}
				winner = i
			case errors.Is(err, auth.ErrEmailTaken):
			default:
				t.Fatalf("round %d: UpdateUserEmail returned %v for a losing caller, want ErrEmailTaken", round, err)
			}
		}
		if winner < 0 {
			t.Fatalf("round %d: all %d concurrent UpdateUserEmail calls onto one address failed, want exactly one winner", round, RaceGoroutines)
		}

		holders := 0
		for i := range movers {
			got, err := st.FindUserByID(ctx, movers[i].ID)
			wantNoErr(t, "FindUserByID after the race", err)
			if got.Email == target {
				holders++
				if i != winner {
					t.Fatalf("round %d: user %s holds the contested address but UpdateUserEmail told it %v", round, movers[i].ID, errs[i])
				}
			}
		}
		if holders != 1 {
			t.Fatalf("round %d: %d users hold the contested address after the race, want exactly 1", round, holders)
		}
	}
}

// checkMarkEmailVerifiedRace is [auth.Store.MarkEmailVerified]'s MUST,
// driven as the race the MUST exists to close: a verification redemption for
// the address a user currently holds, running at the same instant as an
// UpdateUserEmail moving that user to a different address.
//
// The assertion is a linearizability argument, not a timing guess. Both
// serial orders end in exactly the same state:
//
//   - verify, then change — the stamp lands, then UpdateUserEmail overwrites
//     the address and clears EmailVerifiedAt unconditionally;
//   - change, then verify — UpdateUserEmail moves the address, and
//     MarkEmailVerified is refused with ErrEmailMismatch because the address
//     it was asked to certify is no longer the user's.
//
// Either way the user ends on the NEW address with EmailVerifiedAt nil. A
// row that ends on the new address WITH a verification stamp is reachable by
// no serial order at all: it means MarkEmailVerified compared the address
// under one lock or statement and wrote under another, and the change landed
// in between — certifying an address the store had not, in fact, checked.
// That is the silent false verification the MUST exists to prevent, and it
// is what this check fails on.
func checkMarkEmailVerifiedRace(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < RaceRounds; round++ {
		at := stamp()
		u := mustCreateUser(t, st, newUser(newEmail(), at))
		next := newEmail()
		when := at.Add(time.Minute)

		var verifyErr, changeErr error
		pair(round,
			func() { verifyErr = st.MarkEmailVerified(ctx, u.ID, u.Email, when) },
			func() { changeErr = st.UpdateUserEmail(ctx, u.ID, next, when) })

		if changeErr != nil {
			t.Fatalf("round %d: UpdateUserEmail returned %v, want nil — no other user holds the new address", round, changeErr)
		}
		if verifyErr != nil && !errors.Is(verifyErr, auth.ErrEmailMismatch) {
			t.Fatalf("round %d: MarkEmailVerified returned %v, want nil or ErrEmailMismatch", round, verifyErr)
		}

		got, err := st.FindUserByID(ctx, u.ID)
		wantNoErr(t, "FindUserByID after the race", err)
		if got.Email != next {
			t.Fatalf("round %d: Email = %q after a successful UpdateUserEmail, want %q", round, got.Email, next)
		}
		if got.EmailVerifiedAt != nil {
			t.Fatalf("round %d: the user ended on the new address %q WITH EmailVerifiedAt = %v (MarkEmailVerified returned %v). No serial order of these two calls produces that: MarkEmailVerified checked one address and certified another, which is the false verification its MUST exists to prevent",
				round, got.Email, got.EmailVerifiedAt, verifyErr)
		}
	}
}

// checkSuccessorVersusRevocation drives [auth.Store.CreateSuccessorSession]'s
// MUST and the first of [auth.Store.DeleteSessionsByFamily]'s together,
// because they are two halves of one race and neither can be observed
// without the other: a rotation minting a successor at the same instant as
// the family-wide revocation a replay of an older token in that same family
// triggers.
//
// The assertion is again a linearizability argument. CreateSuccessorSession
// reports ok=true only if the predecessor still existed at the instant of
// its own atomic step, so ok=true places it BEFORE the revocation — and a
// revocation that runs after it must remove the successor along with
// everything else. ok=false places it after, and then nothing was inserted.
// Either way the family is empty once both calls have returned. A surviving
// row means one of two defects: CreateSuccessorSession inserted against a
// predecessor that was already gone (resurrecting a family the reuse alarm
// correctly revoked), or DeleteSessionsByFamily took its snapshot BEFORE
// waiting for the successor's insert and so deleted only what existed at the
// earlier instant — the single-autocommit-DELETE shape the port calls out as
// NOT sufficient on a backend whose CreateSuccessorSession holds a row lock.
//
// Whether a given round actually interleaves the two calls is not under this
// suite's control, which is why it runs [RaceRounds] of them; a backend that
// serializes the two internally (a single mutex spanning both method bodies)
// passes every round trivially and correctly.
func checkSuccessorVersusRevocation(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < RaceRounds; round++ {
		at := stamp()
		userID := newID()
		familyID := newID()
		predSession := newSession(userID, familyID, at)
		rotatedAt := at
		predSession.RotatedAt = &rotatedAt
		pred := mustCreateSession(t, st, predSession)
		succ := newSession(userID, familyID, at)

		var (
			ok       bool
			succErr  error
			revError error
		)
		pair(round,
			func() { _, ok, succErr = st.CreateSuccessorSession(ctx, pred.ID, succ) },
			func() { revError = st.DeleteSessionsByFamily(ctx, familyID) })

		if succErr != nil {
			t.Fatalf("round %d: CreateSuccessorSession returned %v, want nil — a lost race is ok=false, not an error", round, succErr)
		}
		if revError != nil {
			t.Fatalf("round %d: DeleteSessionsByFamily returned %v, want nil", round, revError)
		}

		left, err := st.ListSessionsByUser(ctx, userID)
		wantNoErr(t, "ListSessionsByUser after the race", err)
		if len(left) != 0 {
			t.Fatalf("round %d: %d session(s) of family %s survived a revocation that ran concurrently with a rotation (CreateSuccessorSession reported ok=%t), want 0 — the revoked family is still alive",
				round, len(left), familyID, ok)
		}
	}
}

// checkConcurrentFamilyRevocations asserts the observable consequence of
// [auth.Store.DeleteSessionsByFamily]'s second MUST: concurrent calls on the
// SAME family — two browser tabs both triggering LogoutAll, or a
// reuse-detection revocation racing an explicit logout — must all succeed
// and leave no survivors.
//
// A backend that takes row locks in an unordered SELECT ... FOR UPDATE and
// does not serialize per family can have two such calls acquire the family's
// row locks in opposite orders and deadlock each other, which surfaces here
// as a non-nil error from one of them.
//
// This check cannot FORCE that inversion. Doing so needs a second connection
// issuing the backend's own locking statement in a deliberately reversed
// order, which is backend-specific SQL no port-level suite can write — and
// waiting for it to arise on its own is not a plan either: store/drops
// measured 1960 rounds of exactly this scenario against its own
// pre-advisory-lock code and saw zero deadlocks, because two identical
// unordered scans over a small family visited the rows in the same physical
// order every time. What is asserted here is therefore the consequence — all
// callers succeed, nothing survives — not the mechanism. A backend using the
// row-lock-then-delete shape should additionally test the inversion
// directly; store/drops does, in
// TestDeleteSessionsByFamilyOppositeLockOrderRequiresAdvisoryLockLive.
func checkConcurrentFamilyRevocations(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	const (
		rows    = 20
		callers = 4
	)
	at := stamp()
	userID := newID()
	familyID := newID()
	for i := 0; i < rows; i++ {
		s := newSession(userID, familyID, at)
		rotatedAt := at
		s.RotatedAt = &rotatedAt
		mustCreateSession(t, st, s)
	}

	errs := make([]error, callers)
	release(callers, func(i int) {
		errs[i] = st.DeleteSessionsByFamily(ctx, familyID)
	})

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent DeleteSessionsByFamily call %d returned %v, want nil — concurrent calls on one family must not fail each other", i, err)
		}
	}
	left, err := st.ListSessionsByUser(ctx, userID)
	wantNoErr(t, "ListSessionsByUser after the concurrent revocations", err)
	if len(left) != 0 {
		t.Fatalf("%d session(s) survived %d concurrent revocations of family %s, want 0", len(left), callers, familyID)
	}
}
