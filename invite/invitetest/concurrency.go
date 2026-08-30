package invitetest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
)

// massRaceRounds is how many times the RaceGoroutines-wide races are
// repeated against a fresh fixture. They are far more expensive than the
// two-party race — RaceGoroutines calls each — and an over-admission shows
// up on essentially every round when it exists at all, so a handful of
// rounds buys what [RaceRounds] buys the two-party race.
const massRaceRounds = 3

func concurrencyChecks() []check {
	return []check{
		{"ConsumeLink/ConcurrentCallersAdmitExactlyOneWinner", checkConsumeLinkOneWinner},
		{"ConsumeLink/ConcurrentCallersNeverExceedMaxUses", checkConsumeLinkNeverExceedsMaxUses},
		{"ConsumeLink/ConcurrentCallersOnAnUnlimitedLinkAllSucceed", checkConsumeLinkUnlimitedLosesNoIncrement},
		{"DeleteEmailInvite/ConcurrentCallersAdmitExactlyOneWinner", checkDeleteEmailInviteOneWinner},
		{"CreateEmailInvite/ConcurrentSameTokenHashAdmitsOneWinner", checkCreateEmailInviteSameHashOneWinner},
		{"CreateEmailInvite/ConcurrentSamePairAdmitsOneWinner", checkCreateEmailInviteSamePairOneWinner},
		{"CreateLink/ConcurrentSameCodeAdmitsOneWinner", checkCreateLinkSameCodeOneWinner},
		{"DeleteEmailInvitesFor/RacingCreateEmailInviteLeavesNoDuplicate", checkReinviteRace},
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
// overwhelmingly the first to run — measured at 198 of 200 rounds while the
// auth counterpart of this package was being built. A two-party race that
// always gives the same operation the same index therefore explores
// essentially ONE interleaving, with the other operation running to
// completion before its partner starts, and two of that package's own
// deliberately broken stores PASSED its unswapped checks for exactly that
// reason. The one two-party race here — [checkReinviteRace] — is caught in
// only one of its two orders, so without the swap it would be a check that
// never bites.
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

// checkConsumeLinkOneWinner is [invite.Store.ConsumeLink]'s central MUST:
// however many callers present the same MaxUses:1 code at once, exactly one
// may see ok=true. RaceGoroutines goroutines, all released together, race one
// freshly created link; the tally must be one winner and no errors, and the
// stored UseCount must be exactly 1.
//
// This is the failure the port describes in full: "two concurrent callers can
// both read UseCount below MaxUses, both decide ok, and both increment, so a
// MaxUses:1 link ends up admitting two people instead of one. That is a
// fail-open bug, not a cosmetic race, because MaxUses exists specifically to
// bound who gets in." Service.JoinViaLink consumes BEFORE granting the
// membership precisely so this atomic step is the only thing standing between
// a shared link and unbounded admission.
//
// How reliably this catches a SUBTLY non-atomic implementation depends on the
// backend, and this suite cannot promise more than the contention it can
// create from outside: store/memory measured a deliberately split-lock
// ConsumeLink passing its own version of this race 20 times out of 20, even
// at 2000 goroutines, because the window between an unlocked read and the
// next Lock is sub-microsecond and Go's mutex fast path lets the same
// goroutine barge straight back onto it. A database-backed store with a cold
// connection pool has the opposite problem — goroutines trickle in across a
// window far wider than the race itself (see [RaceGoroutines] on warming the
// pool first). What it catches every time is a grossly non-atomic
// implementation: one with no guard at all, or one whose guard is on the
// wrong side of the comparison.
// "ConsumeLink/ConcurrentCallersOnAnUnlimitedLinkAllSucceed" is the
// deterministic complement — a split read-then-write loses increments there
// whatever the timing.
func checkConsumeLinkOneWinner(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	for round := 0; round < massRaceRounds; round++ {
		l := newLink(newID(), at)
		l.MaxUses = 1
		l = mustCreateLink(t, st, l)

		var mu sync.Mutex
		winners, failures := 0, 0
		var firstErr error
		release(RaceGoroutines, func(int) {
			ok, err := st.ConsumeLink(ctx, l.ID, at)
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
			t.Fatalf("round %d: %d of %d concurrent ConsumeLink calls returned an error, first: %v — losing the race is (false, nil), not an error", round, failures, RaceGoroutines, firstErr)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d of %d concurrent ConsumeLink calls reported ok=true against one MaxUses:1 link, want exactly 1 — the check and the increment are not one atomic step, and the link admitted %d people it was minted to keep out", round, winners, RaceGoroutines, winners-1)
		}

		got, err := st.FindLink(ctx, l.ID)
		wantNoErr(t, "FindLink after the race", err)
		if got.UseCount != 1 {
			t.Fatalf("round %d: stored UseCount = %d after exactly one reported winner, want 1", round, got.UseCount)
		}
	}
}

// checkConsumeLinkNeverExceedsMaxUses is the same obligation with a limit
// above one, which is where an off-by-one that a MaxUses:1 link happens to
// mask shows up: RaceGoroutines callers race a MaxUses:4 link, and exactly 4
// may win.
//
// A MaxUses:1 link cannot distinguish "stops at the limit" from "allows one
// through"; this one can.
func checkConsumeLinkNeverExceedsMaxUses(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	const limit = 4

	for round := 0; round < massRaceRounds; round++ {
		l := newLink(newID(), at)
		l.MaxUses = limit
		l = mustCreateLink(t, st, l)

		var mu sync.Mutex
		winners := 0
		var firstErr error
		release(RaceGoroutines, func(int) {
			ok, err := st.ConsumeLink(ctx, l.ID, at)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				if firstErr == nil {
					firstErr = err
				}
			case ok:
				winners++
			}
		})

		if firstErr != nil {
			t.Fatalf("round %d: a concurrent ConsumeLink call returned %v, want nil — losing the race is (false, nil)", round, firstErr)
		}
		if winners != limit {
			t.Fatalf("round %d: %d of %d concurrent ConsumeLink calls won against a MaxUses:%d link, want exactly %d", round, winners, RaceGoroutines, limit, limit)
		}

		got, err := st.FindLink(ctx, l.ID)
		wantNoErr(t, "FindLink after the race", err)
		if got.UseCount != limit {
			t.Fatalf("round %d: stored UseCount = %d after the race on a MaxUses:%d link, want %d", round, got.UseCount, limit, limit)
		}
	}
}

// checkConsumeLinkUnlimitedLosesNoIncrement drives the OTHER half of
// ConsumeLink's atomicity, the one that is deterministic rather than
// timing-dependent: RaceGoroutines callers consume one UNLIMITED link, every
// one must win, and the stored UseCount must be exactly RaceGoroutines.
//
// With no limit to enforce there is no admission decision to get wrong, so
// every caller wins on any implementation. What cannot survive a split
// read-then-write is the COUNT: N callers that each read the same UseCount
// and then each write read+1 leave the link at a small number rather than at
// N, because their writes overwrite one another instead of composing. That
// is a lost update, and unlike the single-winner races above it does not
// depend on landing in a sub-microsecond window — the increments are lost
// whenever two callers overlap at all.
//
// It matters beyond the count itself: UseCount is what MaxUses is compared
// against, so a store that loses increments here under-counts uses on a
// LIMITED link too, and hands out more admissions than the limit names.
func checkConsumeLinkUnlimitedLosesNoIncrement(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := mustCreateLink(t, st, newLink(newID(), at))

	var mu sync.Mutex
	winners := 0
	var firstErr error
	release(RaceGoroutines, func(int) {
		ok, err := st.ConsumeLink(ctx, l.ID, at)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err != nil:
			if firstErr == nil {
				firstErr = err
			}
		case ok:
			winners++
		}
	})

	if firstErr != nil {
		t.Fatalf("a concurrent ConsumeLink call on an unlimited link returned %v, want nil", firstErr)
	}
	if winners != RaceGoroutines {
		t.Fatalf("%d of %d concurrent ConsumeLink calls won against an UNLIMITED link, want all %d — nothing there should refuse anyone", winners, RaceGoroutines, RaceGoroutines)
	}

	got, err := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink after the race", err)
	if got.UseCount != RaceGoroutines {
		t.Fatalf("stored UseCount = %d after %d successful concurrent consumes, want %d — %d increment(s) were lost, which means the check and the increment are not one atomic step. UseCount is what MaxUses is compared against, so the same defect over-admits on a limited link",
			got.UseCount, RaceGoroutines, RaceGoroutines, RaceGoroutines-got.UseCount)
	}
}

// checkDeleteEmailInviteOneWinner asserts the property
// Service.AcceptInvite's one-time-credential guarantee rests on: of any
// number of callers racing to delete the SAME invite id — which is what two
// presentations of one emailed token become, since both resolve the same row
// by token hash — at most one may see a nil error. Every other must be told
// ErrInviteNotFound, indistinguishable from the token never having existed.
//
// The port states this as a rows-affected gate ("removes an invite by id,
// returning ErrInviteNotFound when no row matched... at most one caller can
// see a nil error"), and acceptance is ordered claim-first, grant-second
// precisely so that gate is what bounds admission. A store that answers nil
// to a delete that removed nothing lets every concurrent presentation of one
// token proceed to GrantMembership.
func checkDeleteEmailInviteOneWinner(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < massRaceRounds; round++ {
		at := stamp()
		inv := mustCreateEmailInvite(t, st, newInvite(newID(), newEmail(), at))

		errs := make([]error, RaceGoroutines)
		release(RaceGoroutines, func(i int) {
			errs[i] = st.DeleteEmailInvite(ctx, inv.ID)
		})

		winner := -1
		for i, err := range errs {
			switch {
			case err == nil:
				if winner >= 0 {
					t.Fatalf("round %d: DeleteEmailInvite returned nil to callers %d and %d for one invite id — a one-time invitation was claimed twice, and both claimants go on to be admitted", round, winner, i)
				}
				winner = i
			case errors.Is(err, invite.ErrInviteNotFound):
			default:
				t.Fatalf("round %d: DeleteEmailInvite returned %v to a losing caller, want ErrInviteNotFound", round, err)
			}
		}
		if winner < 0 {
			t.Fatalf("round %d: all %d concurrent DeleteEmailInvite calls for one id failed, want exactly one winner", round, RaceGoroutines)
		}

		if _, err := st.FindEmailInvite(ctx, inv.ID); !errors.Is(err, invite.ErrInviteNotFound) {
			t.Fatalf("round %d: FindEmailInvite after the race: error = %v, want ErrInviteNotFound — the claimed invite is gone", round, err)
		}
	}
}

// checkCreateEmailInviteSameHashOneWinner drives the concurrent form of
// [invite.EmailInvite.TokenHash]'s uniqueness MUST: RaceGoroutines
// goroutines, released together, each create a DISTINCT invite — its own id,
// its own container, its own address — under one shared token hash. Exactly
// one may succeed, and the hash must afterwards resolve to that winner.
//
// A check-then-write whose check and write are not one atomic step lets
// several goroutines all find the hash free and all write it, which is the
// state the sequential check
// "CreateEmailInvite/TokenHashIsUnique" forbids, reached by a route that
// check cannot see.
func checkCreateEmailInviteSameHashOneWinner(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < massRaceRounds; round++ {
		at := stamp()
		hash := newHash()
		invites := make([]invite.EmailInvite, RaceGoroutines)
		for i := range invites {
			invites[i] = newInvite(newID(), newEmail(), at)
			invites[i].TokenHash = hash
		}

		errs := make([]error, RaceGoroutines)
		release(RaceGoroutines, func(i int) {
			_, errs[i] = st.CreateEmailInvite(ctx, invites[i])
		})

		winner := oneCreateWinner(t, round, errs, "CreateEmailInvite", "one token hash")

		got, err := st.FindEmailInviteByTokenHash(ctx, hash)
		wantNoErr(t, "FindEmailInviteByTokenHash after the race", err)
		if got.ID != invites[winner].ID {
			t.Fatalf("round %d: the contested token hash resolves to %q, want the one caller CreateEmailInvite reported success to, %q", round, got.ID, invites[winner].ID)
		}
	}
}

// checkCreateEmailInviteSamePairOneWinner drives the concurrent form of the
// (ContainerID, Email) uniqueness MUST: RaceGoroutines goroutines each mint a
// distinct invite — its own id, its own token hash — for ONE container and
// ONE address. Exactly one may succeed, and the container must afterwards
// hold exactly one pending invite for that address.
//
// This is the race the constraint exists to lose safely: two admins
// re-inviting the same person at the same moment. Without it both writes
// land and the container carries two live tokens where its
// pending-invitations screen shows one row.
func checkCreateEmailInviteSamePairOneWinner(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < massRaceRounds; round++ {
		at := stamp()
		containerID := newID()
		email := newEmail()
		invites := make([]invite.EmailInvite, RaceGoroutines)
		for i := range invites {
			invites[i] = newInvite(containerID, email, at)
		}

		errs := make([]error, RaceGoroutines)
		release(RaceGoroutines, func(i int) {
			_, errs[i] = st.CreateEmailInvite(ctx, invites[i])
		})

		winner := oneCreateWinner(t, round, errs, "CreateEmailInvite", "one (container, email) pair")

		list, err := st.ListEmailInvites(ctx, containerID)
		wantNoErr(t, "ListEmailInvites after the race", err)
		wantSameIDs(t, "ListEmailInvites after the race", inviteIDs(list), []string{invites[winner].ID})
	}
}

// checkCreateLinkSameCodeOneWinner drives the concurrent form of
// [invite.Link.Code]'s uniqueness MUST: RaceGoroutines goroutines each mint a
// distinct link, in its own container, under one shared code. Exactly one may
// succeed, and the code must afterwards resolve to that winner.
func checkCreateLinkSameCodeOneWinner(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < massRaceRounds; round++ {
		at := stamp()
		code := newCode()
		links := make([]invite.Link, RaceGoroutines)
		for i := range links {
			links[i] = newLink(newID(), at)
			links[i].Code = code
		}

		errs := make([]error, RaceGoroutines)
		release(RaceGoroutines, func(i int) {
			_, errs[i] = st.CreateLink(ctx, links[i])
		})

		winner := oneCreateWinner(t, round, errs, "CreateLink", "one code")

		got, err := st.FindLinkByCode(ctx, code)
		wantNoErr(t, "FindLinkByCode after the race", err)
		if got.ID != links[winner].ID {
			t.Fatalf("round %d: the contested code resolves to %q, want the one caller CreateLink reported success to, %q", round, got.ID, links[winner].ID)
		}
	}
}

// oneCreateWinner tallies a concurrent-create race and returns the index of
// the single caller that succeeded, failing the check if there was not
// exactly one.
//
// The losers' errors are NOT classified: [invite.Store] names no
// conflict-on-create sentinel, and the two backends in this repository
// answer differently on purpose (a driver-level unique violation, and a
// package-local sentinel). All that is required of a loser is that it
// FAILED. See the package doc.
func oneCreateWinner(t tb, round int, errs []error, method, contested string) int {
	t.Helper()
	winner := -1
	for i, err := range errs {
		if err != nil {
			continue
		}
		if winner >= 0 {
			t.Fatalf("round %d: %s succeeded for both caller %d and caller %d under %s — two rows now share it, and every lookup through it resolves to whichever one the backend happens to return first", round, method, winner, i, contested)
		}
		winner = i
	}
	if winner < 0 {
		t.Fatalf("round %d: all %d concurrent %s calls under %s failed, want exactly one winner", round, len(errs), method, contested)
	}
	return winner
}

// checkReinviteRace is the one TWO-PARTY race in this package, and it drives
// the sequence Service.InviteByEmail performs — DeleteEmailInvitesFor for
// (container, email), then CreateEmailInvite for the same pair — against
// itself, with an invite for that pair already pending.
//
// The assertion is a linearizability argument, not a timing guess. Both
// serial orders end somewhere well-defined:
//
//   - sweep, then create — the pending row is gone when the create runs, so
//     the create succeeds and the container holds exactly ONE invite for the
//     address: the new one.
//   - create, then sweep — the pending row is still there when the create
//     runs, so the (ContainerID, Email) constraint refuses it, and the sweep
//     then removes the pending row: the container holds NONE.
//
// So a successful create must leave exactly one row, and a refused one
// exactly zero. The state this rejects — the create reporting success while
// the container ends up with no invite for the address at all — is reachable
// by no serial order: it means the create was allowed to add a SECOND row
// alongside the pending one, which the sweep then removed along with the
// first. The caller was told their invitation was sent, and it is not there.
// The same missing constraint produces the mirror-image failure just as
// often, two live tokens for one address, which this check sees as a
// two-row list.
//
// The roles alternate by round ([pair]), and that is what makes this check
// bite at all: only the create-then-sweep order exposes the defect, and the
// goroutine started last is overwhelmingly the one that runs first, so a
// fixed assignment would explore essentially one order forever.
func checkReinviteRace(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()

	for round := 0; round < RaceRounds; round++ {
		at := stamp()
		containerID := newID()
		email := newEmail()
		mustCreateEmailInvite(t, st, newInvite(containerID, email, at))

		fresh := newInvite(containerID, email, at.Add(time.Minute))
		var createErr, sweepErr error
		pair(round,
			func() { _, createErr = st.CreateEmailInvite(ctx, fresh) },
			func() { sweepErr = st.DeleteEmailInvitesFor(ctx, containerID, email) })

		if sweepErr != nil {
			t.Fatalf("round %d: DeleteEmailInvitesFor returned %v, want nil — deleting zero rows is not an error either", round, sweepErr)
		}

		list, err := st.ListEmailInvites(ctx, containerID)
		wantNoErr(t, "ListEmailInvites after the race", err)

		if createErr == nil {
			if len(list) != 1 || list[0].ID != fresh.ID {
				t.Fatalf("round %d: CreateEmailInvite reported success, yet the container holds %v for %q rather than exactly the new invite %s. No serial order of these two calls produces that: a successful create means the sweep had already removed the pending row, so nothing was left for the sweep to take away. What did happen is that the create was allowed to add a SECOND row for the pair — the (ContainerID, Email) uniqueness MUST is not enforced — and the sweep removed both",
					round, inviteIDs(list), email, fresh.ID)
			}
			continue
		}
		if len(list) != 0 {
			t.Fatalf("round %d: CreateEmailInvite was refused (%v) yet %d invite(s) for %q remain in the container, want 0 — the sweep runs before the create in that order and removes the pending row", round, createErr, len(list), email)
		}
	}
}
