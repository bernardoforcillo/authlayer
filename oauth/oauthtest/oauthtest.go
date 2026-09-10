// Package oauthtest is the executable contract for
// [github.com/bernardoforcillo/authlayer/oauth.Store].
//
// oauth.Store is a twenty-four-method port holding five record kinds, and
// the obligations that matter most about it are the ones that bound WHO A
// TOKEN IS and HOW MANY TIMES a credential pays out: four uniqueness MUSTs
// on the record types (a code hash, a device-code hash, a user code, a
// refresh-token hash — two rows sharing any of them let two concurrent
// callers each atomically win a different row), three compare-and-sets
// ([oauth.Store.RedeemCode], [oauth.Store.SetDeviceStatus],
// [oauth.Store.MarkRefreshRotated] — split into a read and a later write,
// a code redeems twice and a replayed refresh token is never detected), two
// atomic cascades ([oauth.Store.DeleteClient], [oauth.Store.RevokeGrant] —
// a refresh token outliving its revoked grant still rotates), and the
// referential refusals on every create. Each is a MUST on the port, and
// each is a check here with a deliberately non-compliant double proving the
// check bites.
//
// # Using it
//
// Write one test per backend:
//
//	func TestMyStoreSatisfiesTheOAuthContract(t *testing.T) {
//	    oauthtest.RunStoreContract(t, func(t *testing.T) oauth.Store {
//	        return myStoreWithEmptyTables(t)
//	    })
//	}
//
// The factory is called once per sub-check and MUST return a store whose
// five record kinds are EMPTY. Every check builds its own fixtures, and
// several assert counts over a whole table (a ListClients length,
// PurgeExpired's total), so a store carrying rows from a previous check
// produces spurious failures. Register whatever teardown the backend needs
// with t.Cleanup inside the factory; the *testing.T handed to it is the
// sub-check's own. A factory is free to t.Skip — the live-PostgreSQL backend
// in this repository skips when its DSN is unset.
//
// Ids, container ids, client ids, grant ids, family ids and user ids are
// UUIDv7, so the suite runs against a backend that types those columns as
// uuid (which store/drops does) as well as one that accepts any string.
// Hashes and user codes are unique per call unless a check is deliberately
// forcing a collision.
//
// # What it checks, and what it deliberately does not
//
// Every check is named for the method and the obligation it exercises, and
// the doc comment on each one states exactly what it asserts. Eight checks
// are races, because the obligations behind them are unreachable
// sequentially: one winner among concurrent redemptions of one code, one
// among concurrent transitions of one device authorization, one among
// concurrent rotations of one refresh token, one among concurrent creates
// of one code hash, one refresh-token hash and one user code, one among
// concurrent deletes of one client, and — the cascade — a CreateGrant
// racing the DeleteClient of its client, after which no grant may exist
// for a client that does not. See concurrency.go for what each race can
// and cannot prove.
//
// The suite does NOT assert the points the port leaves to the
// implementation: list order (results are compared as sets), empty slice
// versus nil (read through len only), and what a REJECTED duplicate hash or
// user code returns — oauth.Store classifies id collisions (ErrIDTaken) and
// nothing else, and the two shipped backends answer differently on purpose
// (store/drops lets PostgreSQL's own unique violation through unwrapped;
// store/memory answers with its own ErrTokenHashTaken or ErrUserCodeTaken).
// Those checks assert only that the write FAILED and that the original row
// survived it. Nothing here asserts that a Store performs no authorization
// of its own: a port-level caller has no subject to withhold.
//
// # One obligation this suite CANNOT fully check from outside the port
//
// The cascade MUSTs name their acceptable shapes — one transaction, ON
// DELETE CASCADE, or one critical section — and WHICH a backend used is
// invisible. What is observable is the consequence when none holds — a
// grant created in the gap between the halves of a DeleteClient and left
// behind — and that is what "DeleteClient/NoGrantOutlivesItsClient"
// asserts, by racing a create against the delete and requiring the end
// state to be one a serial order could produce. It catches a grossly
// non-atomic implementation every time and a subtly non-atomic one only
// sometimes: the window in a real split implementation is sub-microsecond,
// and this project's own negative control widens it to milliseconds to make
// the control deterministic.
package oauthtest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/oauth"
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

// RaceRounds is how many times the TWO-PARTY race — a CreateGrant against
// the DeleteClient of its client — is repeated against a fresh fixture. It
// resolves differently run to run, so a single round can miss the
// interleaving a non-compliant implementation only exhibits in one order.
const RaceRounds = 8

// massRaceRounds is how many times the RaceGoroutines-wide compare-and-set
// races are repeated. They are far more expensive than the two-party race,
// and a single-winner violation shows up on essentially every round when it
// exists at all, so a handful of rounds buys what RaceRounds buys the
// two-party one.
const massRaceRounds = 3

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
	fn   func(t tb, st oauth.Store)
}

// storeContractChecks is every check [RunStoreContract] runs, in order:
// clients, grants, codes, device authorizations, refresh tokens,
// housekeeping, then the obligations that only appear under concurrency.
func storeContractChecks() []check {
	var all []check
	all = append(all, clientChecks()...)
	all = append(all, grantChecks()...)
	all = append(all, codeChecks()...)
	all = append(all, deviceChecks()...)
	all = append(all, refreshChecks()...)
	all = append(all, housekeepingChecks()...)
	all = append(all, concurrencyChecks()...)
	return all
}

// RunStoreContract exercises every documented obligation of [oauth.Store]
// against the implementation newStore returns, as one sub-test per
// obligation.
//
// newStore is called once per sub-test and must return a store with no rows
// of any kind in it; see the package doc for why, and for what this suite
// deliberately does not assert. It must not return nil.
func RunStoreContract(t *testing.T, newStore func(t *testing.T) oauth.Store) {
	t.Helper()
	if newStore == nil {
		t.Fatalf("oauthtest: newStore must not be nil")
	}
	for _, c := range storeContractChecks() {
		t.Run(c.name, func(t *testing.T) {
			st := newStore(t)
			if st == nil {
				t.Fatalf("oauthtest: newStore returned a nil oauth.Store")
			}
			c.fn(t, st)
		})
	}
}

// --- shared fixtures ---

// newID returns a fresh UUIDv7, so the suite runs unchanged against a backend
// that types id columns as uuid.
func newID() string { return uid.NewV7() }

// newHash returns a hash no other call will produce. The suite never hashes
// anything — the port stores an already-computed hash and the plaintext
// never reaches a Store — so any distinct string does the job.
func newHash() string { return "h-" + uid.NewV7() }

// newUserCode returns a user code no other call will produce: eight
// characters from the RFC 8628 alphabet, derived from a fresh UUID so it is
// unique per call without a global counter.
func newUserCode() string {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ"
	id := uid.NewV7()
	out := make([]byte, 8)
	for i := range out {
		out[i] = alphabet[int(id[i*2]+id[i*2+1])%len(alphabet)]
	}
	// The derivation above can collide across two ids whose bytes happen
	// to agree at eight positions; append the id's tail to keep it unique
	// per call — the port constrains nothing about a code's length.
	return string(out) + "-" + id[24:]
}

// stamp returns a UTC instant truncated to microseconds — the precision
// PostgreSQL's timestamptz keeps — so a round trip through a database-backed
// store compares equal to what was written.
func stamp() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// newClient builds a confidential, container-owned client with every field
// populated — slices included, so a store that drops or reorders one is
// caught.
func newClient(containerID string, at time.Time) oauth.Client {
	return oauth.Client{
		ID:               newID(),
		ContainerID:      containerID,
		Name:             "deploy bot",
		SecretHash:       newHash(),
		RedirectURIs:     []string{"https://app.example/cb", "http://127.0.0.1/cb"},
		GrantTypes:       []string{oauth.GrantAuthorizationCode, oauth.GrantRefreshToken, oauth.GrantClientCredentials},
		Scopes:           []string{"project:read", "project:deploy"},
		ServiceAccountID: newID(),
		Permissions:      []byte("project:read"),
		CreatedBy:        newID(),
		CreatedAt:        at,
		UpdatedAt:        at,
	}
}

// newPublicClient builds an application-level public client: no container,
// no secret, no service account, no creator — every nullable-in-practice
// field at its zero value, which is the shape dynamic registration writes.
func newPublicClient(at time.Time) oauth.Client {
	return oauth.Client{
		ID:           newID(),
		Name:         "cli agent",
		Public:       true,
		RedirectURIs: []string{"http://127.0.0.1/cb"},
		GrantTypes:   []string{oauth.GrantAuthorizationCode, oauth.GrantRefreshToken, oauth.GrantDeviceCode},
		CreatedAt:    at,
		UpdatedAt:    at,
	}
}

// newGrant builds a live, never-expiring, uncapped grant of userID to c in
// c's container (or a fresh one for an application-level client).
func newGrant(c oauth.Client, userID string, at time.Time) oauth.Grant {
	containerID := c.ContainerID
	if containerID == "" {
		containerID = newID()
	}
	return oauth.Grant{
		ID:          newID(),
		ClientID:    c.ID,
		UserID:      userID,
		ContainerID: containerID,
		Scope:       "project:read project:deploy",
		CreatedAt:   at,
	}
}

// newCode builds an unredeemed code for g, expiring an hour after at.
func newCode(g oauth.Grant, at time.Time) oauth.AuthorizationCode {
	return oauth.AuthorizationCode{
		ID:            newID(),
		CodeHash:      newHash(),
		ClientID:      g.ClientID,
		GrantID:       g.ID,
		RedirectURI:   "https://app.example/cb",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		ExpiresAt:     at.Add(time.Hour),
		CreatedAt:     at,
	}
}

// newDevice builds a pending device authorization for c, expiring an hour
// after at, with no grant and never polled.
func newDevice(c oauth.Client, at time.Time) oauth.DeviceAuthorization {
	return oauth.DeviceAuthorization{
		ID:             newID(),
		DeviceCodeHash: newHash(),
		UserCode:       newUserCode(),
		ClientID:       c.ID,
		Scope:          "project:read",
		Status:         oauth.DeviceStatusPending,
		Interval:       5,
		ExpiresAt:      at.Add(time.Hour),
		CreatedAt:      at,
	}
}

// newRefresh builds a current refresh token for g, the first of its family,
// expiring a day after at.
func newRefresh(g oauth.Grant, at time.Time) oauth.RefreshToken {
	id := newID()
	return oauth.RefreshToken{
		ID:        id,
		TokenHash: newHash(),
		GrantID:   g.ID,
		ClientID:  g.ClientID,
		FamilyID:  id,
		ExpiresAt: at.Add(24 * time.Hour),
		CreatedAt: at,
	}
}

// The must* helpers persist a fixture, failing the check if the store
// refuses it. Used for fixtures, never as the assertion itself.

func mustCreateClient(t tb, st oauth.Store, c oauth.Client) oauth.Client {
	t.Helper()
	got, err := st.CreateClient(context.Background(), c)
	if err != nil {
		t.Fatalf("fixture CreateClient(%s): unexpected error %v", c.ID, err)
	}
	return got
}

func mustCreateGrant(t tb, st oauth.Store, g oauth.Grant) oauth.Grant {
	t.Helper()
	got, err := st.CreateGrant(context.Background(), g)
	if err != nil {
		t.Fatalf("fixture CreateGrant(%s): unexpected error %v", g.ID, err)
	}
	return got
}

func mustCreateCode(t tb, st oauth.Store, c oauth.AuthorizationCode) oauth.AuthorizationCode {
	t.Helper()
	got, err := st.CreateCode(context.Background(), c)
	if err != nil {
		t.Fatalf("fixture CreateCode(%s): unexpected error %v", c.ID, err)
	}
	return got
}

func mustCreateDevice(t tb, st oauth.Store, d oauth.DeviceAuthorization) oauth.DeviceAuthorization {
	t.Helper()
	got, err := st.CreateDeviceAuthorization(context.Background(), d)
	if err != nil {
		t.Fatalf("fixture CreateDeviceAuthorization(%s): unexpected error %v", d.ID, err)
	}
	return got
}

func mustCreateRefresh(t tb, st oauth.Store, r oauth.RefreshToken) oauth.RefreshToken {
	t.Helper()
	got, err := st.CreateRefreshToken(context.Background(), r)
	if err != nil {
		t.Fatalf("fixture CreateRefreshToken(%s): unexpected error %v", r.ID, err)
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

// wantStringsEqual compares two string slices element for element, with nil
// and empty treated alike: a store may hand an empty list back as either.
func wantStringsEqual(t tb, what string, got, want []string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", what, got, want)
	}
}

// wantBytesEqual compares two byte slices with nil and empty treated alike
// (both mean "no cap" to the Service).
func wantBytesEqual(t tb, what string, got, want []byte) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if string(got) != string(want) {
		t.Fatalf("%s = %q, want %q", what, got, want)
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

func clientIDs(list []oauth.Client) []string {
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, c.ID)
	}
	return out
}

func grantIDs(list []oauth.Grant) []string {
	out := make([]string, 0, len(list))
	for _, g := range list {
		out = append(out, g.ID)
	}
	return out
}
