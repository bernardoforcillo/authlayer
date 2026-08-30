// Package invitetest is the executable contract for
// [github.com/bernardoforcillo/authlayer/invite.Store].
//
// invite.Store is a thirteen-method port holding two credential kinds — a
// one-time emailed token and a reusable link — and the obligations that
// matter most about it are the ones that bound WHO GETS IN: [invite.Store.ConsumeLink]'s
// single-winner atomicity (a naive read-then-increment lets N callers each
// claim a MaxUses:1 link), [invite.Store.DeleteEmailInvite]'s rows-affected
// gate (which is how one emailed token pays out at most once), and the three
// uniqueness constraints that keep a lookup by token hash, by code, or by
// invited address resolving to exactly one row. Until this package existed
// none of them had an exported check, so a third-party backend author had
// nothing to test their work against, and the two backends this repository
// ships disagreed about all three uniqueness constraints without any test
// able to notice.
//
// # Using it
//
// Write one test per backend:
//
//	func TestMyStoreSatisfiesTheInviteContract(t *testing.T) {
//	    invitetest.RunStoreContract(t, func(t *testing.T) invite.Store {
//	        return myStoreWithEmptyTables(t)
//	    })
//	}
//
// The factory is called once per sub-check and MUST return a store whose two
// record kinds are EMPTY. Every check builds its own fixtures, and several
// assert counts over the whole table (a ListEmailInvites length,
// PurgeExpired's total across both kinds), so a store carrying rows from a
// previous check produces spurious failures. Register whatever teardown the
// backend needs with t.Cleanup inside the factory; the *testing.T handed to
// it is the sub-check's own, so cleanups run between checks rather than at
// the end of the suite. A factory is free to t.Skip — the live-PostgreSQL
// backend in this repository skips when its DSN is unset.
//
// Ids and container ids are UUIDv7, so the suite runs against a backend that
// types those columns as uuid (which store/drops does) as well as one that
// accepts any string. Addresses, token hashes and codes are unique per call
// unless a check is deliberately forcing a collision.
//
// # What it checks, and what it deliberately does not
//
// Every check is named for the method and the obligation it exercises, and
// the doc comment on each one states exactly what it asserts. Eight checks
// are races, because the obligations behind them are unreachable
// sequentially: ConsumeLink's single winner against a MaxUses:1 link, its
// use-limit ceiling against a MaxUses:K one, and the lost-update its
// increment must not have on an unlimited one; DeleteEmailInvite's
// at-most-one-nil claim; the three uniqueness constraints under concurrent
// creates; and a DeleteEmailInvitesFor racing the CreateEmailInvite that
// re-invites the same address. See concurrency.go for what each race can and
// cannot prove.
//
// The suite does NOT assert the points the port leaves to the
// implementation:
//
//   - ListEmailInvites' and ListLinks' order is unspecified, so results are
//     compared as sets.
//   - "may be an empty slice or nil, which len and range treat alike, so do
//     not distinguish them" is read through len only.
//   - What a REJECTED duplicate returns is not classified into a sentinel.
//     [invite.Store]'s error contract names not-found errors and the three
//     redemption refusals; it classifies no conflict-on-create at all, and
//     the two backends answer differently on purpose (store/drops lets
//     PostgreSQL's own unique violation through unwrapped; store/memory
//     answers with its own package-local sentinels). Every uniqueness check
//     here therefore asserts only that the write FAILED and that the
//     original row survived it.
//   - ConsumeLink's ok=false path does not distinguish revoked from expired
//     from exhausted, by design — the port says so, and says why — so the
//     refusal checks assert (false, nil) and re-read the record themselves
//     to confirm nothing moved.
//   - Nothing here asserts that a Store performs no authorization of its
//     own. That is a real statement in the port's doc, but it constrains
//     what a backend must not consult, and a port-level caller has no
//     subject to withhold and no way to observe the difference.
//
// # One obligation this suite CANNOT fully check from outside the port
//
// [invite.Store.ConsumeLink]'s MUST is that the check and the increment are
// a single atomic step "whose outcome cannot be split by a concurrent caller
// of the same method", and it names the two acceptable shapes: one
// UPDATE ... WHERE whose rows-affected count IS ok, or one critical section
// held across both. WHICH shape a backend used is invisible to a caller.
// What is observable is the consequence when neither holds — several callers
// admitted past one MaxUses, or increments lost — and that is what
// "ConsumeLink/ConcurrentCallersAdmitExactlyOneWinner",
// "ConsumeLink/ConcurrentCallersNeverExceedMaxUses" and
// "ConsumeLink/ConcurrentCallersOnAnUnlimitedLinkAllSucceed" assert. The
// first two catch a grossly non-atomic implementation (no guard at all)
// every time and a subtly non-atomic one (a split lock whose window is
// sub-microsecond) only sometimes: store/memory measured a split-lock
// ConsumeLink passing its own N=2000 single-winner race 20 times out of 20.
// The third is the deterministic one — a split read-then-write loses every
// increment but one, whatever the timing, because the writes overwrite each
// other rather than merely racing. None of the three proves the mechanism.
//
// # The three uniqueness constraints
//
// [invite.EmailInvite.TokenHash], [invite.Link.Code] and the
// (ContainerID, Email) pair each carry a uniqueness MUST on the record type
// rather than on a method. They are part of [RunStoreContract] like every
// other obligation — the checks are "CreateEmailInvite/TokenHashIsUnique",
// "CreateLink/CodeIsUnique" and
// "CreateEmailInvite/ContainerEmailPairIsUnique", after the write paths that
// have to enforce them, plus a concurrent form of each.
//
// They are not niceties a backend may decline. The first two defeat
// ConsumeLink's and DeleteEmailInvite's single-winner properties with no
// atomicity defect at all: two rows sharing a Code means two concurrent
// redeemers resolve DIFFERENT rows through FindLinkByCode and each
// atomically wins ConsumeLink on the row it happened to pick, so a MaxUses:1
// link admits two people; two rows sharing a TokenHash means the same for
// one emailed token through FindEmailInviteByTokenHash and
// DeleteEmailInvite. The third is what makes re-inviting an address REPLACE
// rather than duplicate when two such calls race, which is what keeps a
// pending-invitations screen — and the revocation performed from it —
// complete.
//
// store/memory did not enforce any of the three when this package was
// written, and its own doc said so; folding them in would have failed one of
// this repository's own backends. That was the wrong way round, exactly as
// it was for auth, and the backend changed instead. Shipping them as an
// opt-in extra would have told the next in-memory backend author they were
// optional, and would have let a caller develop against store/memory and
// meet the constraint for the first time in production against store/drops.
package invitetest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/invite"
)

// RaceGoroutines is how many goroutines the mass-contention checks
// (ConsumeLink's single winner and use-limit ceiling, DeleteEmailInvite's
// single claim, the three concurrent-uniqueness races) release against one
// record at once.
//
// It is exported so a backend can prepare for that much concurrency before
// the suite starts — a database-backed store whose connection pool grows on
// demand should raise its limits and warm the pool to at least this many
// connections in its factory, because goroutines that trickle in across a
// wide connection-setup window never actually contend, which silently
// weakens every race in this package. store/drops' own live suite does
// exactly that; see warmPool there.
const RaceGoroutines = 32

// RaceRounds is how many times the TWO-PARTY race — a DeleteEmailInvitesFor
// against the CreateEmailInvite that re-invites the same address — is
// repeated against a fresh fixture. It resolves differently run to run, so a
// single round can miss the interleaving a non-compliant implementation only
// exhibits in one of the two orders, and the roles are swapped between
// rounds (see pair in concurrency.go). The RaceGoroutines-wide races use
// their own, smaller round count — see massRaceRounds.
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
	fn   func(t tb, st invite.Store)
}

// storeContractChecks is every check [RunStoreContract] runs, in order:
// records first, then housekeeping, then the obligations that only appear
// under concurrency.
func storeContractChecks() []check {
	var all []check
	all = append(all, emailInviteChecks()...)
	all = append(all, linkChecks()...)
	all = append(all, housekeepingChecks()...)
	all = append(all, concurrencyChecks()...)
	return all
}

// RunStoreContract exercises every documented obligation of [invite.Store]
// against the implementation newStore returns, as one sub-test per
// obligation.
//
// newStore is called once per sub-test and must return a store with no email
// invites and no links in it; see the package doc for why, and for what this
// suite deliberately does not assert. It must not return nil.
//
// This is the only entry point: every obligation [invite.Store] states is in
// here, the three uniqueness MUSTs included.
func RunStoreContract(t *testing.T, newStore func(t *testing.T) invite.Store) {
	t.Helper()
	runChecks(t, storeContractChecks(), newStore)
}

func runChecks(t *testing.T, checks []check, newStore func(t *testing.T) invite.Store) {
	t.Helper()
	if newStore == nil {
		t.Fatalf("invitetest: newStore must not be nil")
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			st := newStore(t)
			if st == nil {
				t.Fatalf("invitetest: newStore returned a nil invite.Store")
			}
			c.fn(t, st)
		})
	}
}

// --- shared fixtures ---

// newID returns a fresh UUIDv7. Ids and container ids are UUIDs so the suite
// runs unchanged against a backend that types those columns as uuid; see the
// package doc.
func newID() string { return uid.NewV7() }

// newEmail returns an address no other call in this package will produce, so
// checks never collide on the (ContainerID, Email) constraint except where
// they mean to. The unique part is a UUID, whose hyphens and hex digits are
// all legal in a local part.
func newEmail() string { return "invitetest-" + uid.NewV7() + "@example.test" }

// mixedCase returns email with its case flipped and surrounding whitespace
// added — a variant [invite.NormalizeEmail] collapses back to email, and
// therefore one that must resolve to the same row on every path that writes
// or matches an address. It is authtest's helper of the same name, for the
// same obligation on the other half of the library.
func mixedCase(email string) string { return "  " + strings.ToUpper(email) + "\t" }

// newHash returns a token hash no other call will produce. The suite never
// hashes anything — the port stores an already-computed hash and the
// plaintext never reaches a Store at all — so any distinct string does the
// job of one.
func newHash() string { return "th-" + uid.NewV7() }

// newCode returns a link code no other call will produce.
func newCode() string { return "code-" + uid.NewV7() }

// stamp returns a UTC instant truncated to microseconds — the precision
// PostgreSQL's timestamptz keeps — so a round trip through a database-backed
// store compares equal to what was written.
func stamp() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// newInvite builds an email invite for containerID and email, expiring an
// hour after at, with every field populated so a store that drops one is
// caught.
func newInvite(containerID, email string, at time.Time) invite.EmailInvite {
	return invite.EmailInvite{
		ID:          newID(),
		ContainerID: containerID,
		Email:       email,
		RoleKey:     "member",
		TokenHash:   newHash(),
		InvitedBy:   newID(),
		ExpiresAt:   at.Add(time.Hour),
		CreatedAt:   at,
	}
}

// newLink builds an unrevoked, never-expiring, unlimited link in
// containerID. Checks that care about a limit, an expiry or a revocation set
// those fields themselves, so the zero-ish defaults here are the ones the
// port calls out: MaxUses 0 meaning unlimited, ExpiresAt nil meaning never,
// RevokedAt nil meaning not revoked.
func newLink(containerID string, at time.Time) invite.Link {
	return invite.Link{
		ID:          newID(),
		ContainerID: containerID,
		Code:        newCode(),
		RoleKey:     "member",
		CreatedBy:   newID(),
		CreatedAt:   at,
	}
}

// mustCreateEmailInvite persists inv, failing the check if the store refuses
// it. Used for fixtures, never as the assertion itself.
func mustCreateEmailInvite(t tb, st invite.Store, inv invite.EmailInvite) invite.EmailInvite {
	t.Helper()
	got, err := st.CreateEmailInvite(context.Background(), inv)
	if err != nil {
		t.Fatalf("fixture CreateEmailInvite(%s): unexpected error %v", inv.ID, err)
	}
	return got
}

// mustCreateLink persists l, failing the check if the store refuses it.
func mustCreateLink(t tb, st invite.Store, l invite.Link) invite.Link {
	t.Helper()
	got, err := st.CreateLink(context.Background(), l)
	if err != nil {
		t.Fatalf("fixture CreateLink(%s): unexpected error %v", l.ID, err)
	}
	return got
}

// wantErrIs fails the check unless got matches want under errors.Is. The
// sentinels are compared with errors.Is, never by message, as [invite.Store]'s
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

// wantTimePtrEqual is wantTimeEqual for the two nullable instants on
// [invite.Link]: nil must round-trip as nil, and a set value by Equal.
func wantTimePtrEqual(t tb, what string, got, want *time.Time) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Fatalf("%s = nil, want %v", what, *want)
	case want == nil:
		t.Fatalf("%s = %v, want nil", what, *got)
	default:
		wantTimeEqual(t, what, *got, *want)
	}
}

// inviteIDs collects the ids of a ListEmailInvites result. Order is
// unspecified by the port, so callers compare these as sets (see idSet).
func inviteIDs(list []invite.EmailInvite) []string {
	out := make([]string, 0, len(list))
	for _, inv := range list {
		out = append(out, inv.ID)
	}
	return out
}

// linkIDs is inviteIDs' counterpart for ListLinks.
func linkIDs(list []invite.Link) []string {
	out := make([]string, 0, len(list))
	for _, l := range list {
		out = append(out, l.ID)
	}
	return out
}

// idSet turns an id slice into a set, so a list result can be compared
// without imposing an order the port does not specify.
func idSet(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// wantSameIDs fails the check unless got and want hold the same ids,
// whatever order they arrived in.
func wantSameIDs(t tb, what string, got, want []string) {
	t.Helper()
	g, w := idSet(got), idSet(want)
	if len(g) != len(w) {
		t.Fatalf("%s returned %d id(s) %v, want %d %v", what, len(got), got, len(want), want)
	}
	for id := range w {
		if !g[id] {
			t.Fatalf("%s returned %v, want %v — %s is missing", what, got, want, id)
		}
	}
}
