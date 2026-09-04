// Package apikeytest is the executable contract for
// [github.com/bernardoforcillo/authlayer/apikey.Store].
//
// apikey.Store is a fourteen-method port holding two record kinds — a
// service account and the keys that authenticate as it — and the
// obligations that matter most about it are the ones that bound WHO A KEY
// IS: [apikey.Key.TokenHash]'s uniqueness (two rows sharing a hash would
// make a bearer credential resolve to whichever the backend returned first,
// so which account, at which cap, a presented key acts as would be decided
// by row order), [apikey.Store.DeleteServiceAccount]'s atomic cascade (no
// key may outlive its account), and [apikey.Store.CreateKey]'s refusal of a
// key naming no account. Each is a MUST on the port, and each is a check
// here with a deliberately non-compliant double proving the check bites.
//
// # Using it
//
// Write one test per backend:
//
//	func TestMyStoreSatisfiesTheAPIKeyContract(t *testing.T) {
//	    apikeytest.RunStoreContract(t, func(t *testing.T) apikey.Store {
//	        return myStoreWithEmptyTables(t)
//	    })
//	}
//
// The factory is called once per sub-check and MUST return a store whose two
// record kinds are EMPTY. Every check builds its own fixtures, and several
// assert counts over the whole table (a ListKeys length, PurgeExpired's
// total), so a store carrying rows from a previous check produces spurious
// failures. Register whatever teardown the backend needs with t.Cleanup
// inside the factory; the *testing.T handed to it is the sub-check's own. A
// factory is free to t.Skip — the live-PostgreSQL backend in this repository
// skips when its DSN is unset.
//
// Ids, container ids and creator ids are UUIDv7, so the suite runs against a
// backend that types those columns as uuid (which store/drops does) as well
// as one that accepts any string. Token hashes are unique per call unless a
// check is deliberately forcing a collision.
//
// # What it checks, and what it deliberately does not
//
// Every check is named for the method and the obligation it exercises, and
// the doc comment on each one states exactly what it asserts. Four checks
// are races, because the obligations behind them are unreachable
// sequentially: one winner among concurrent creates of one token hash, one
// winner among concurrent creates of one account id, one winner among
// concurrent deletes of one account, and — the cascade — a CreateKey racing
// the DeleteServiceAccount of its account, after which no key may exist for
// an account that does not. See concurrency.go for what each race can and
// cannot prove.
//
// The suite does NOT assert the points the port leaves to the
// implementation: list order (results are compared as sets), empty slice
// versus nil (read through len only), and what a REJECTED duplicate token
// hash returns — apikey.Store classifies id collisions (ErrIDTaken) but not
// hash collisions, and the two shipped backends answer differently on
// purpose (store/drops lets PostgreSQL's own unique violation through
// unwrapped; store/memory answers with its own ErrTokenHashTaken). Those
// checks assert only that the write FAILED and that the original row
// survived it. Nothing here asserts that a Store performs no authorization
// of its own: a port-level caller has no subject to withhold and no way to
// observe the difference.
//
// # One obligation this suite CANNOT fully check from outside the port
//
// [apikey.Store.DeleteServiceAccount]'s MUST is that the cascade is atomic
// with the delete, and it names three acceptable shapes: one transaction,
// one ON DELETE CASCADE, or one critical section. WHICH a backend used is
// invisible. What is observable is the consequence when none holds — a key
// created in the gap between the two halves and left behind, a credential
// row for an account nothing knows — and that is what
// "DeleteServiceAccount/NoKeyOutlivesItsAccount" asserts, by racing a create
// against the delete and requiring the end state to be one a serial order
// could produce. It catches a grossly non-atomic implementation every time
// and a subtly non-atomic one only sometimes: the window in a real split
// implementation is sub-microsecond, and this project's own negative control
// widens it to milliseconds to make the control deterministic. It proves the
// check detects the defect when the interleaving occurs, not that it forces
// the interleaving on a subtly broken backend.
package apikeytest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/internal/uid"
)

// RaceGoroutines is how many goroutines the mass-contention checks release
// against one record at once. It is exported so a backend can prepare for
// that much concurrency before the suite starts — a database-backed store
// whose connection pool grows on demand should raise its limits and warm the
// pool to at least this many connections in its factory, because goroutines
// that trickle in across a wide connection-setup window never actually
// contend, which silently weakens every race in this package. store/drops'
// own live suite does exactly that.
const RaceGoroutines = 32

// RaceRounds is how many times the TWO-PARTY race — a CreateKey against the
// DeleteServiceAccount of its account — is repeated against a fresh fixture.
// It resolves differently run to run, so a single round can miss the
// interleaving a non-compliant implementation only exhibits in one order.
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
	fn   func(t tb, st apikey.Store)
}

// storeContractChecks is every check [RunStoreContract] runs, in order:
// accounts, then keys, then housekeeping, then the obligations that only
// appear under concurrency.
func storeContractChecks() []check {
	var all []check
	all = append(all, serviceAccountChecks()...)
	all = append(all, keyChecks()...)
	all = append(all, housekeepingChecks()...)
	all = append(all, concurrencyChecks()...)
	return all
}

// RunStoreContract exercises every documented obligation of [apikey.Store]
// against the implementation newStore returns, as one sub-test per
// obligation.
//
// newStore is called once per sub-test and must return a store with no
// service accounts and no keys in it; see the package doc for why, and for
// what this suite deliberately does not assert. It must not return nil.
func RunStoreContract(t *testing.T, newStore func(t *testing.T) apikey.Store) {
	t.Helper()
	if newStore == nil {
		t.Fatalf("apikeytest: newStore must not be nil")
	}
	for _, c := range storeContractChecks() {
		t.Run(c.name, func(t *testing.T) {
			st := newStore(t)
			if st == nil {
				t.Fatalf("apikeytest: newStore returned a nil apikey.Store")
			}
			c.fn(t, st)
		})
	}
}

// --- shared fixtures ---

// newID returns a fresh UUIDv7, so the suite runs unchanged against a backend
// that types id columns as uuid.
func newID() string { return uid.NewV7() }

// newHash returns a token hash no other call will produce. The suite never
// hashes anything — the port stores an already-computed hash and the
// plaintext never reaches a Store — so any distinct string does the job.
func newHash() string { return "th-" + uid.NewV7() }

// stamp returns a UTC instant truncated to microseconds — the precision
// PostgreSQL's timestamptz keeps — so a round trip through a database-backed
// store compares equal to what was written.
func stamp() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// newAccount builds an active service account in containerID with every
// field populated, so a store that drops one is caught.
func newAccount(containerID string, at time.Time) apikey.ServiceAccount {
	return apikey.ServiceAccount{
		ID:          newID(),
		ContainerID: containerID,
		Name:        "ci",
		Description: "deploys things",
		CreatedBy:   newID(),
		CreatedAt:   at,
		UpdatedAt:   at,
	}
}

// newKey builds a live, never-expiring, unrestricted key for sa with every
// non-nullable field populated. Checks that care about an expiry, a cap or a
// revocation set those fields themselves, so the nil defaults here are the
// ones the port calls out: Permissions nil meaning no cap, ExpiresAt nil
// meaning never, RevokedAt nil meaning live, LastUsedAt nil meaning unused.
func newKey(sa apikey.ServiceAccount, at time.Time) apikey.Key {
	return apikey.Key{
		ID:               newID(),
		ServiceAccountID: sa.ID,
		ContainerID:      sa.ContainerID,
		Name:             "github",
		Prefix:           "sk_ab12cd34",
		TokenHash:        newHash(),
		CreatedBy:        newID(),
		CreatedAt:        at,
	}
}

// mustCreateAccount persists sa, failing the check if the store refuses it.
// Used for fixtures, never as the assertion itself.
func mustCreateAccount(t tb, st apikey.Store, sa apikey.ServiceAccount) apikey.ServiceAccount {
	t.Helper()
	got, err := st.CreateServiceAccount(context.Background(), sa)
	if err != nil {
		t.Fatalf("fixture CreateServiceAccount(%s): unexpected error %v", sa.ID, err)
	}
	return got
}

// mustCreateKey persists k, failing the check if the store refuses it.
func mustCreateKey(t tb, st apikey.Store, k apikey.Key) apikey.Key {
	t.Helper()
	got, err := st.CreateKey(context.Background(), k)
	if err != nil {
		t.Fatalf("fixture CreateKey(%s): unexpected error %v", k.ID, err)
	}
	return got
}

// wantErrIs fails the check unless got matches want under errors.Is. The
// sentinels are compared with errors.Is, never by message.
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

// wantTimePtrEqual is wantTimeEqual for the nullable instants: nil must
// round-trip as nil, and a set value by Equal.
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
	if len(g) != len(w) || len(got) != len(want) {
		t.Fatalf("%s returned %d id(s) %v, want %d %v", what, len(got), got, len(want), want)
	}
	for id := range w {
		if !g[id] {
			t.Fatalf("%s returned %v, want %v — %s is missing", what, got, want, id)
		}
	}
}

func accountIDs(list []apikey.ServiceAccount) []string {
	out := make([]string, 0, len(list))
	for _, sa := range list {
		out = append(out, sa.ID)
	}
	return out
}

func keyIDs(list []apikey.Key) []string {
	out := make([]string, 0, len(list))
	for _, k := range list {
		out = append(out, k.ID)
	}
	return out
}
