package authtest

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/internal/uid"
)

// credentialCheck is one named obligation of [auth.CredentialStore]. It is a
// second type rather than a reuse of check because the two ports are
// independent: a backend may implement either without the other, and
// [RunCredentialStoreContract] must not require an [auth.Store].
type credentialCheck struct {
	name string
	fn   func(t tb, st auth.CredentialStore)
}

// credentialContractChecks is every check [RunCredentialStoreContract] runs,
// in order: the credential records, then the challenges, then the
// obligations that only appear under concurrency.
func credentialContractChecks() []credentialCheck {
	return []credentialCheck{
		{"CreateCredential/RoundTripsEveryField", checkCreateCredentialRoundTrip},
		{"CreateCredential/DuplicateIDIsRefused", checkCreateCredentialDuplicateID},
		{"CreateCredential/DuplicateCredentialIDIsRefused", checkCreateCredentialDuplicateCredentialID},
		{"FindCredentialByCredentialID/MatchesBytesExactly", checkFindCredentialByteExact},
		{"ListCredentialsByUser/ReturnsOnlyThatUsersRows", checkListCredentialsByUser},
		{"UpdateSignCount/AppliesAnIncreaseAndStampsLastUsedAt", checkUpdateSignCountApplies},
		{"UpdateSignCount/RefusesACountThatDidNotIncrease", checkUpdateSignCountRefuses},
		{"UpdateSignCount/UnknownIDIsNotFound", checkUpdateSignCountNotFound},
		{"TouchCredential/StampsLastUsedAtWithoutMovingTheCounter", checkTouchCredential},
		{"DeleteCredential/RemovesExactlyThatRow", checkDeleteCredential},
		{"DeleteCredentialIfNotLast/RefusesTheAccountsLastWayIn", checkDeleteIfNotLastRefuses},
		{"DeleteCredentialIfNotLast/AllowsWhenASiblingSurvives", checkDeleteIfNotLastSibling},
		{"DeleteCredentialIfNotLast/AllowsWhenTheAccountHasAnotherCredentialKind", checkDeleteIfNotLastOtherKind},
		{"DeleteCredentialIfNotLast/AnotherUsersCredentialIsNotFound", checkDeleteIfNotLastOtherUser},
		{"DeleteCredentialsByUser/RemovesEveryRowOfThatUserAndNoOther", checkDeleteCredentialsByUser},
		{"DeleteCredentialsByUser/MatchingNoRowsIsSuccess", checkDeleteCredentialsByUserNoRows},
		{"CreateChallenge/RoundTripsBothCeremonies", checkCreateChallengeRoundTrip},
		{"CreateChallenge/DuplicateIDIsRefused", checkCreateChallengeDuplicateID},
		{"FindChallengeByHash/UnknownHashIsNotFound", checkFindChallengeNotFound},
		{"DeleteChallenge/BurnsTheChallengeExactlyOnce", checkDeleteChallengeOnce},
		{"PurgeExpiredChallenges/RemovesOnlyTheExpiredOnes", checkPurgeExpiredChallenges},
		{"UpdateSignCount/ConcurrentReplayAdmitsExactlyOneWinner", checkUpdateSignCountOneWinner},
		{"DeleteChallenge/ConcurrentClaimsAdmitExactlyOneWinner", checkDeleteChallengeOneWinner},
		{"DeleteCredentialIfNotLast/ConcurrentRemovalsLeaveOneWayIn", checkDeleteIfNotLastAtomic},
	}
}

// RunCredentialStoreContract exercises every documented obligation of
// [auth.CredentialStore] — the OPTIONAL passkey port — against the
// implementation newStore returns, as one sub-test per obligation.
//
// newStore is called once per sub-test and must return a store with no
// credentials and no challenges in it; see [RunStoreContract] for why, and
// the package doc for what these suites deliberately do not assert. It must
// not return nil.
//
// It is a separate entry point from RunStoreContract because the port is
// separate and optional: a backend that implements [auth.Store] and no
// passkeys runs only that one, and a backend that implements only the passkey
// port (a deployment splitting its tables across two databases can) runs only
// this one.
//
// The three concurrency checks at the end are the ones that matter most, and
// two of them are the reason the port has the shape it does:
// [auth.CredentialStore.UpdateSignCount]'s compare-and-set is the only clone
// detection in the package, and
// [auth.CredentialStore.DeleteCredentialIfNotLast]'s atomicity is what stands
// between a user with two passkeys and a permanent lockout. What a race can
// and cannot prove from outside a port is stated on each check.
func RunCredentialStoreContract(t *testing.T, newStore func(t *testing.T) auth.CredentialStore) {
	t.Helper()
	if newStore == nil {
		t.Fatalf("authtest: newStore must not be nil")
	}
	for _, c := range credentialContractChecks() {
		t.Run(c.name, func(t *testing.T) {
			st := newStore(t)
			if st == nil {
				t.Fatalf("authtest: newStore returned a nil auth.CredentialStore")
			}
			c.fn(t, st)
		})
	}
}

// --- shared fixtures ---

// newCredentialID returns credential-id bytes no other call in this package
// will produce, including bytes outside the printable range so a backend that
// stores them as text rather than bytea is caught.
func newCredentialID() []byte {
	return append([]byte{0x00, 0xff, 0xfe}, uid.NewV7()...)
}

// newCredential builds a registered-but-never-used credential for userID:
// LastUsedAt nil, which is the state every fresh registration is in, and a
// SignCount above 2^31 so a backend that types the column as a signed 32-bit
// integer fails here rather than silently comparing wrong later.
func newCredential(userID string, at time.Time) auth.Credential {
	return auth.Credential{
		ID:           newID(),
		UserID:       userID,
		CredentialID: newCredentialID(),
		PublicKey:    []byte("cose-public-key-" + uid.NewV7()),
		SignCount:    4_000_000_000,
		Transports:   "usb,nfc",
		Label:        "authtest key",
		CreatedAt:    at,
	}
}

// newLoginChallenge builds a live login-ceremony challenge, whose UserID is
// nil because a passkey login begins before anyone is identified.
func newLoginChallenge(at time.Time) auth.Challenge {
	return auth.Challenge{
		ID:        newID(),
		Ceremony:  auth.CeremonyLogin,
		Hash:      "ch-" + uid.NewV7(),
		ExpiresAt: at.Add(5 * time.Minute),
		CreatedAt: at,
	}
}

// newRegistrationChallenge builds a live registration-ceremony challenge
// bound to userID.
func newRegistrationChallenge(userID string, at time.Time) auth.Challenge {
	c := newLoginChallenge(at)
	c.Ceremony = auth.CeremonyRegistration
	c.UserID = &userID
	return c
}

// mustCreateCredential persists c, failing the check if the store refuses it.
func mustCreateCredential(t tb, st auth.CredentialStore, c auth.Credential) auth.Credential {
	t.Helper()
	got, err := st.CreateCredential(context.Background(), c)
	if err != nil {
		t.Fatalf("fixture CreateCredential(%s): unexpected error %v", c.ID, err)
	}
	return got
}

// mustCreateChallenge persists c, failing the check if the store refuses it.
func mustCreateChallenge(t tb, st auth.CredentialStore, c auth.Challenge) auth.Challenge {
	t.Helper()
	got, err := st.CreateChallenge(context.Background(), c)
	if err != nil {
		t.Fatalf("fixture CreateChallenge(%s): unexpected error %v", c.ID, err)
	}
	return got
}

// loadCredential re-reads a credential by its authenticator id, failing the
// check if it has gone. Every assertion about persisted state goes through a
// re-read rather than trusting a returned value.
func loadCredential(t tb, st auth.CredentialStore, credentialID []byte) auth.Credential {
	t.Helper()
	got, err := st.FindCredentialByCredentialID(context.Background(), credentialID)
	if err != nil {
		t.Fatalf("FindCredentialByCredentialID: unexpected error %v", err)
	}
	return got
}

// --- the credential records ---

// checkCreateCredentialRoundTrip pins that every field survives a write and a
// read, including the three a backend is most likely to get wrong: the
// credential id as EXACT bytes (not text, not base64), a SignCount above
// 2^31 (which does not fit a signed 32-bit column), and a nil LastUsedAt
// (which must stay nil rather than becoming a zero timestamp — nil is what
// tells an application the credential has never signed anyone in).
func checkCreateCredentialRoundTrip(t tb, st auth.CredentialStore) {
	t.Helper()
	at := stamp()
	want := newCredential(newID(), at)

	created, err := st.CreateCredential(context.Background(), want)
	wantNoErr(t, "CreateCredential", err)
	if created.ID != want.ID {
		t.Fatalf("CreateCredential returned ID %q, want %q", created.ID, want.ID)
	}

	got := loadCredential(t, st, want.CredentialID)
	if got.ID != want.ID || got.UserID != want.UserID {
		t.Fatalf("round trip = %+v, want ID %q and UserID %q", got, want.ID, want.UserID)
	}
	if !bytes.Equal(got.CredentialID, want.CredentialID) {
		t.Fatalf("CredentialID round-tripped as %x, want %x — it MUST be stored as exact bytes", got.CredentialID, want.CredentialID)
	}
	if !bytes.Equal(got.PublicKey, want.PublicKey) {
		t.Fatalf("PublicKey round-tripped as %x, want %x", got.PublicKey, want.PublicKey)
	}
	if got.SignCount != want.SignCount {
		t.Fatalf("SignCount round-tripped as %d, want %d — the column must hold the whole uint32 range", got.SignCount, want.SignCount)
	}
	if got.Transports != want.Transports || got.Label != want.Label {
		t.Fatalf("Transports/Label round-tripped as %q/%q, want %q/%q", got.Transports, got.Label, want.Transports, want.Label)
	}
	wantTimeEqual(t, "CreatedAt", got.CreatedAt, want.CreatedAt)
	if got.LastUsedAt != nil {
		t.Fatalf("LastUsedAt = %v after a fresh registration, want nil — nil is how a caller tells 'never used' from a timestamp", got.LastUsedAt)
	}
}

// checkCreateCredentialDuplicateID pins that a second row under an existing
// surrogate id is auth.ErrIDTaken and overwrites nothing.
func checkCreateCredentialDuplicateID(t tb, st auth.CredentialStore) {
	t.Helper()
	at := stamp()
	first := mustCreateCredential(t, st, newCredential(newID(), at))

	clash := newCredential(newID(), at)
	clash.ID = first.ID
	_, err := st.CreateCredential(context.Background(), clash)
	wantErrIs(t, "CreateCredential with a taken id", err, auth.ErrIDTaken)

	if _, err := st.FindCredentialByCredentialID(context.Background(), clash.CredentialID); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("the refused row was written anyway: err = %v, want ErrCredentialNotFound", err)
	}
}

// checkCreateCredentialDuplicateCredentialID is
// [auth.Credential.CredentialID]'s uniqueness MUST, and the one whose absence
// is an authentication bypass rather than a duplicate record: two rows naming
// one authenticator credential against two different users make a login
// resolve to whichever the backend returns first.
//
// It asserts both halves — the refusal, and that the existing row was not
// re-pointed at the second user — because a backend that "helpfully"
// overwrote would pass a refusal-only check while doing the very thing the
// constraint exists to prevent.
func checkCreateCredentialDuplicateCredentialID(t tb, st auth.CredentialStore) {
	t.Helper()
	at := stamp()
	alice, bob := newID(), newID()
	first := mustCreateCredential(t, st, newCredential(alice, at))

	second := newCredential(bob, at)
	second.CredentialID = first.CredentialID
	second.PublicKey = []byte("attacker-supplied-key")
	_, err := st.CreateCredential(context.Background(), second)
	wantErrIs(t, "CreateCredential with a registered credential id", err, auth.ErrCredentialRegistered)

	got := loadCredential(t, st, first.CredentialID)
	if got.ID != first.ID || got.UserID != alice {
		t.Fatalf("the existing credential was re-pointed: %+v, want id %q for user %q", got, first.ID, alice)
	}
	if !bytes.Equal(got.PublicKey, first.PublicKey) {
		t.Fatalf("the existing credential's public key was overwritten: %x, want %x", got.PublicKey, first.PublicKey)
	}
}

// checkFindCredentialByteExact pins byte-for-byte matching: a credential id
// that shares a prefix, one that differs in a single byte, and an unknown one
// must all miss. A backend that stored these as text with a collation, or
// that decoded/re-encoded them, fails here.
func checkFindCredentialByteExact(t tb, st auth.CredentialStore) {
	t.Helper()
	at := stamp()
	c := mustCreateCredential(t, st, newCredential(newID(), at))
	ctx := context.Background()

	prefix := c.CredentialID[:len(c.CredentialID)-1]
	if _, err := st.FindCredentialByCredentialID(ctx, prefix); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("a prefix of the credential id matched: err = %v, want ErrCredentialNotFound", err)
	}

	flipped := append([]byte(nil), c.CredentialID...)
	flipped[0] ^= 0xff
	if _, err := st.FindCredentialByCredentialID(ctx, flipped); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("a one-byte-different credential id matched: err = %v, want ErrCredentialNotFound", err)
	}

	if _, err := st.FindCredentialByCredentialID(ctx, newCredentialID()); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("an unknown credential id matched: err = %v, want ErrCredentialNotFound", err)
	}

	got := loadCredential(t, st, c.CredentialID)
	if got.ID != c.ID {
		t.Fatalf("the exact credential id returned %q, want %q", got.ID, c.ID)
	}
}

// checkListCredentialsByUser pins the scoping: a user's own rows and no
// others, and an empty result for a user with none. It reads through len
// rather than a nil comparison, since the port leaves empty-versus-nil
// unspecified.
func checkListCredentialsByUser(t tb, st auth.CredentialStore) {
	t.Helper()
	at := stamp()
	alice, bob := newID(), newID()
	a1 := mustCreateCredential(t, st, newCredential(alice, at))
	a2 := mustCreateCredential(t, st, newCredential(alice, at))
	mustCreateCredential(t, st, newCredential(bob, at))

	got, err := st.ListCredentialsByUser(context.Background(), alice)
	wantNoErr(t, "ListCredentialsByUser", err)
	if len(got) != 2 {
		t.Fatalf("ListCredentialsByUser returned %d rows, want 2: %+v", len(got), got)
	}
	ids := []string{got[0].ID, got[1].ID}
	sort.Strings(ids)
	want := []string{a1.ID, a2.ID}
	sort.Strings(want)
	if ids[0] != want[0] || ids[1] != want[1] {
		t.Fatalf("ListCredentialsByUser returned ids %v, want %v", ids, want)
	}

	none, err := st.ListCredentialsByUser(context.Background(), newID())
	wantNoErr(t, "ListCredentialsByUser for a user with none", err)
	if len(none) != 0 {
		t.Fatalf("ListCredentialsByUser for an unknown user returned %d rows, want 0", len(none))
	}
}

// checkUpdateSignCountApplies pins the winning half of the compare-and-set:
// a strictly greater counter is stored, LastUsedAt is stamped with the
// instant passed in, and both survive a re-read.
func checkUpdateSignCountApplies(t tb, st auth.CredentialStore) {
	t.Helper()
	at := stamp()
	c := mustCreateCredential(t, st, newCredential(newID(), at))
	used := at.Add(time.Minute)

	ok, err := st.UpdateSignCount(context.Background(), c.ID, c.SignCount+1, used)
	wantNoErr(t, "UpdateSignCount with a higher count", err)
	if !ok {
		t.Fatalf("UpdateSignCount(%d -> %d) = false, want true", c.SignCount, c.SignCount+1)
	}

	got := loadCredential(t, st, c.CredentialID)
	if got.SignCount != c.SignCount+1 {
		t.Fatalf("stored SignCount = %d, want %d", got.SignCount, c.SignCount+1)
	}
	if got.LastUsedAt == nil {
		t.Fatalf("LastUsedAt = nil after a winning UpdateSignCount, want the instant passed in")
	}
	wantTimeEqual(t, "LastUsedAt", *got.LastUsedAt, used)
}

// checkUpdateSignCountRefuses is the clone-detection obligation: a counter
// that did not INCREASE must be refused, and refusing must write nothing at
// all — neither the counter nor LastUsedAt.
//
// Both the equal and the lower case are asserted. Equal is the one an
// implementation is most likely to get wrong (a `<=` where a `<` belongs, or
// the reverse), and it is not a nicety: an authenticator that maintains a
// counter increments it on every assertion, so the same value arriving twice
// is a replayed assertion or a second copy of the credential.
func checkUpdateSignCountRefuses(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateCredential(t, st, newCredential(newID(), at))
	later := at.Add(time.Hour)

	for _, tc := range []struct {
		name  string
		count uint32
	}{
		{"the same count again", c.SignCount},
		{"a lower count", c.SignCount - 1},
		{"zero", 0},
	} {
		ok, err := st.UpdateSignCount(ctx, c.ID, tc.count, later)
		wantNoErr(t, "UpdateSignCount with "+tc.name, err)
		if ok {
			t.Fatalf("UpdateSignCount(stored %d -> %s, %d) = true, want false — a counter that did not increase is the cloned-authenticator signal and MUST be refused",
				c.SignCount, tc.name, tc.count)
		}

		got := loadCredential(t, st, c.CredentialID)
		if got.SignCount != c.SignCount {
			t.Fatalf("a refused UpdateSignCount wrote the counter anyway: %d, want %d", got.SignCount, c.SignCount)
		}
		if got.LastUsedAt != nil {
			t.Fatalf("a refused UpdateSignCount stamped LastUsedAt (%v) — a refused use is not a use", got.LastUsedAt)
		}
	}
}

// checkUpdateSignCountNotFound pins that an unknown id is an ERROR and not a
// quiet (false, nil): the two mean different things to
// [auth.Service.FinishPasskeyLogin], which turns a false into
// [auth.ErrClonedAuthenticator] and would otherwise accuse a caller of
// cloning an authenticator that does not exist.
func checkUpdateSignCountNotFound(t tb, st auth.CredentialStore) {
	t.Helper()
	ok, err := st.UpdateSignCount(context.Background(), newID(), 7, stamp())
	wantErrIs(t, "UpdateSignCount for an unknown id", err, auth.ErrCredentialNotFound)
	if ok {
		t.Fatalf("UpdateSignCount for an unknown id reported ok = true")
	}
}

// checkTouchCredential pins the counter-less path: LastUsedAt moves,
// SignCount does not, and an unknown id is auth.ErrCredentialNotFound. A
// backend that folded this into UpdateSignCount would move the counter here
// and break every zero-counter authenticator's clone detection baseline.
func checkTouchCredential(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateCredential(t, st, newCredential(newID(), at))
	used := at.Add(2 * time.Minute)

	wantNoErr(t, "TouchCredential", st.TouchCredential(ctx, c.ID, used))

	got := loadCredential(t, st, c.CredentialID)
	if got.SignCount != c.SignCount {
		t.Fatalf("TouchCredential moved SignCount to %d, want %d unchanged", got.SignCount, c.SignCount)
	}
	if got.LastUsedAt == nil {
		t.Fatalf("TouchCredential left LastUsedAt nil")
	}
	wantTimeEqual(t, "LastUsedAt", *got.LastUsedAt, used)

	wantErrIs(t, "TouchCredential for an unknown id", st.TouchCredential(ctx, newID(), used), auth.ErrCredentialNotFound)
}

// checkDeleteCredential pins the unconditional by-id removal: exactly the
// named row goes, the user's sibling stays, another user's row stays, and a
// second delete of the same id reports not-found rather than succeeding
// twice.
func checkDeleteCredential(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()
	target := mustCreateCredential(t, st, newCredential(alice, at))
	sibling := mustCreateCredential(t, st, newCredential(alice, at))
	stranger := mustCreateCredential(t, st, newCredential(bob, at))

	wantNoErr(t, "DeleteCredential", st.DeleteCredential(ctx, target.ID))

	if _, err := st.FindCredentialByCredentialID(ctx, target.CredentialID); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("the named row survived: err = %v, want ErrCredentialNotFound", err)
	}
	mine, err := st.ListCredentialsByUser(ctx, alice)
	wantNoErr(t, "ListCredentialsByUser", err)
	if len(mine) != 1 || mine[0].ID != sibling.ID {
		t.Fatalf("rows for the user = %+v, want only the sibling — a by-id DELETE must not widen", mine)
	}
	theirs, err := st.ListCredentialsByUser(ctx, bob)
	wantNoErr(t, "ListCredentialsByUser (other user)", err)
	if len(theirs) != 1 || theirs[0].ID != stranger.ID {
		t.Fatalf("another user's rows were touched: %+v", theirs)
	}

	wantErrIs(t, "second DeleteCredential of the same id",
		st.DeleteCredential(ctx, target.ID), auth.ErrCredentialNotFound)
}

// checkDeleteIfNotLastRefuses is the lockout guard: the account's only
// credential, with no other way in, must be refused with
// auth.ErrLastCredential and MUST still be there afterwards. A refusal that
// deleted anyway would be the permanent, silent lockout this method exists to
// prevent, wearing an error's clothes.
func checkDeleteIfNotLastRefuses(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	user := newID()
	only := mustCreateCredential(t, st, newCredential(user, at))

	err := st.DeleteCredentialIfNotLast(ctx, user, only.ID, false)
	wantErrIs(t, "DeleteCredentialIfNotLast on the last way in", err, auth.ErrLastCredential)

	got := loadCredential(t, st, only.CredentialID)
	if got.ID != only.ID {
		t.Fatalf("the refused delete removed the row anyway")
	}
}

// checkDeleteIfNotLastSibling pins that the reachability test is on what
// REMAINS: with a sibling credential surviving, the delete proceeds even
// though the account has no password and no identity.
func checkDeleteIfNotLastSibling(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	user := newID()
	doomed := mustCreateCredential(t, st, newCredential(user, at))
	sibling := mustCreateCredential(t, st, newCredential(user, at))

	wantNoErr(t, "DeleteCredentialIfNotLast with a sibling",
		st.DeleteCredentialIfNotLast(ctx, user, doomed.ID, false))

	left, err := st.ListCredentialsByUser(ctx, user)
	wantNoErr(t, "ListCredentialsByUser", err)
	if len(left) != 1 || left[0].ID != sibling.ID {
		t.Fatalf("rows left = %+v, want only the sibling", left)
	}
}

// checkDeleteIfNotLastOtherKind pins the parameter's meaning: with
// userHasOtherCredential true — the caller has established the account can
// authenticate by something this port cannot see, a password or a linked
// identity — the last passkey may go.
func checkDeleteIfNotLastOtherKind(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	user := newID()
	only := mustCreateCredential(t, st, newCredential(user, at))

	wantNoErr(t, "DeleteCredentialIfNotLast with another credential kind",
		st.DeleteCredentialIfNotLast(ctx, user, only.ID, true))

	left, err := st.ListCredentialsByUser(ctx, user)
	wantNoErr(t, "ListCredentialsByUser", err)
	if len(left) != 0 {
		t.Fatalf("rows left = %+v, want none", left)
	}
}

// checkDeleteIfNotLastOtherUser pins the scoping: naming somebody else's
// credential id is auth.ErrCredentialNotFound and removes nothing, whatever
// the flag says. Without this, one account could remove another's last way in
// by naming it — the id is the caller's input, not a capability.
func checkDeleteIfNotLastOtherUser(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()
	hers := mustCreateCredential(t, st, newCredential(alice, at))
	mustCreateCredential(t, st, newCredential(bob, at))

	err := st.DeleteCredentialIfNotLast(ctx, bob, hers.ID, true)
	wantErrIs(t, "DeleteCredentialIfNotLast naming another user's credential", err, auth.ErrCredentialNotFound)

	got := loadCredential(t, st, hers.CredentialID)
	if got.UserID != alice {
		t.Fatalf("the other user's credential was touched: %+v", got)
	}
}

// checkDeleteCredentialsByUser is the sweep the two TERMINATION rows of
// auth.Service.ChangePassword's matrix depend on: EVERY credential of that
// user goes, in one call, and nobody else's does.
//
// It seeds THREE credentials for the user deliberately. One would be caught
// by nothing a by-id delete does not already cover, and two would still pass
// a backend that removed the first row it found and then a second one on the
// retry. Three is what makes "it removed some and reported success" — the one
// shape auth.CredentialStore.DeleteCredentialsByUser forbids — visible in a
// single call, and a survivor here is a live, password-less way into an
// account whose sessions the caller has already deleted.
func checkDeleteCredentialsByUser(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()
	mine := []auth.Credential{
		mustCreateCredential(t, st, newCredential(alice, at)),
		mustCreateCredential(t, st, newCredential(alice, at)),
		mustCreateCredential(t, st, newCredential(alice, at)),
	}
	stranger := mustCreateCredential(t, st, newCredential(bob, at))

	wantNoErr(t, "DeleteCredentialsByUser", st.DeleteCredentialsByUser(ctx, alice))

	left, err := st.ListCredentialsByUser(ctx, alice)
	wantNoErr(t, "ListCredentialsByUser", err)
	if len(left) != 0 {
		t.Fatalf("%d of the user's 3 credentials survived the sweep (%+v), want none — a passkey outliving the account it authenticates is a working sign-in credential filed under an id that no longer resolves", len(left), left)
	}
	// The list is not the only way back to a row: a login resolves by the
	// AUTHENTICATOR's id, so each of the three must be unreachable that way
	// too. A backend that unlinked rather than deleted would pass the list
	// assertion above and still sign somebody in.
	for i, c := range mine {
		if _, err := st.FindCredentialByCredentialID(ctx, c.CredentialID); !errors.Is(err, auth.ErrCredentialNotFound) {
			t.Fatalf("credential %d is still resolvable by its authenticator id: err = %v, want ErrCredentialNotFound", i, err)
		}
	}

	theirs, err := st.ListCredentialsByUser(ctx, bob)
	wantNoErr(t, "ListCredentialsByUser (other user)", err)
	if len(theirs) != 1 || theirs[0].ID != stranger.ID {
		t.Fatalf("another user's rows were swept: %+v — a by-user DELETE must not widen past its user_id", theirs)
	}
}

// checkDeleteCredentialsByUserNoRows pins the half of the contract an account
// deletion depends on far more often than the sweep itself: most accounts
// hold no passkey at all, so a user with none — and a user whose credentials
// a previous, half-finished attempt already removed — must both be SUCCESS.
// auth.ErrCredentialNotFound here would fail the deletion of every
// passkey-less account in a deployment that wires this port.
func checkDeleteCredentialsByUserNoRows(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	user, bystander := newID(), newID()
	mustCreateCredential(t, st, newCredential(bystander, at))

	wantNoErr(t, "DeleteCredentialsByUser for a user that never registered one",
		st.DeleteCredentialsByUser(ctx, user))

	only := mustCreateCredential(t, st, newCredential(user, at))
	wantNoErr(t, "DeleteCredentialsByUser", st.DeleteCredentialsByUser(ctx, user))
	wantNoErr(t, "DeleteCredentialsByUser a second time — a retried deletion runs it again",
		st.DeleteCredentialsByUser(ctx, user))

	if _, err := st.FindCredentialByCredentialID(ctx, only.CredentialID); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("the swept credential is still resolvable: err = %v, want ErrCredentialNotFound", err)
	}
	left, err := st.ListCredentialsByUser(ctx, bystander)
	wantNoErr(t, "ListCredentialsByUser (bystander)", err)
	if len(left) != 1 {
		t.Fatalf("sweeping two users who hold nothing between them removed a third party's row: %+v", left)
	}
}

// --- the challenges ---

// checkCreateChallengeRoundTrip pins both ceremonies, and the field a backend
// is most likely to get wrong: a LOGIN challenge's nil UserID. A passkey
// login begins before anyone is identified, so there is no account to bind
// it to, and a backend that cannot store the absence (a NOT NULL column, or
// one that coerces nil to "") fails every login ceremony.
func checkCreateChallengeRoundTrip(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	user := newID()

	login := mustCreateChallenge(t, st, newLoginChallenge(at))
	registration := mustCreateChallenge(t, st, newRegistrationChallenge(user, at))

	gotLogin, err := st.FindChallengeByHash(ctx, login.Hash)
	wantNoErr(t, "FindChallengeByHash (login)", err)
	if gotLogin.ID != login.ID || gotLogin.Ceremony != auth.CeremonyLogin {
		t.Fatalf("login challenge round trip = %+v, want id %q and ceremony %q", gotLogin, login.ID, auth.CeremonyLogin)
	}
	if gotLogin.UserID != nil {
		t.Fatalf("login challenge round-tripped with UserID %q, want nil — a login ceremony names no account", *gotLogin.UserID)
	}
	wantTimeEqual(t, "login challenge ExpiresAt", gotLogin.ExpiresAt, login.ExpiresAt)
	wantTimeEqual(t, "login challenge CreatedAt", gotLogin.CreatedAt, login.CreatedAt)

	gotReg, err := st.FindChallengeByHash(ctx, registration.Hash)
	wantNoErr(t, "FindChallengeByHash (registration)", err)
	if gotReg.UserID == nil || *gotReg.UserID != user {
		t.Fatalf("registration challenge round-tripped with UserID %v, want %q", gotReg.UserID, user)
	}
	if gotReg.Ceremony != auth.CeremonyRegistration {
		t.Fatalf("registration challenge ceremony = %q, want %q", gotReg.Ceremony, auth.CeremonyRegistration)
	}
}

// checkCreateChallengeDuplicateID pins auth.ErrIDTaken on a second row under
// an existing challenge id, and that the refusal wrote nothing.
func checkCreateChallengeDuplicateID(t tb, st auth.CredentialStore) {
	t.Helper()
	at := stamp()
	first := mustCreateChallenge(t, st, newLoginChallenge(at))

	clash := newLoginChallenge(at)
	clash.ID = first.ID
	_, err := st.CreateChallenge(context.Background(), clash)
	wantErrIs(t, "CreateChallenge with a taken id", err, auth.ErrIDTaken)

	if _, err := st.FindChallengeByHash(context.Background(), clash.Hash); !errors.Is(err, auth.ErrChallengeNotFound) {
		t.Fatalf("the refused challenge was written anyway: err = %v, want ErrChallengeNotFound", err)
	}
}

// checkFindChallengeNotFound pins that an unknown hash is
// auth.ErrChallengeNotFound rather than a zero value with a nil error — a
// zero Challenge has an empty Ceremony and a zero ExpiresAt, which a caller
// reading it as a live ceremony would treat as expired at best and as a
// ceremony-less challenge at worst.
func checkFindChallengeNotFound(t tb, st auth.CredentialStore) {
	t.Helper()
	_, err := st.FindChallengeByHash(context.Background(), "ch-"+uid.NewV7())
	wantErrIs(t, "FindChallengeByHash for an unknown hash", err, auth.ErrChallengeNotFound)
}

// checkDeleteChallengeOnce pins the claim: the first delete succeeds, the
// challenge is then unfindable, and a second delete of the same id reports
// auth.ErrChallengeNotFound. That "exactly once" is what makes a challenge
// single-use — a second presentation of the same ceremony must find nothing
// to claim.
func checkDeleteChallengeOnce(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	c := mustCreateChallenge(t, st, newLoginChallenge(stamp()))

	wantNoErr(t, "DeleteChallenge", st.DeleteChallenge(ctx, c.ID))
	if _, err := st.FindChallengeByHash(ctx, c.Hash); !errors.Is(err, auth.ErrChallengeNotFound) {
		t.Fatalf("the claimed challenge is still findable: err = %v, want ErrChallengeNotFound", err)
	}
	wantErrIs(t, "second DeleteChallenge of the same id",
		st.DeleteChallenge(ctx, c.ID), auth.ErrChallengeNotFound)
}

// checkPurgeExpiredChallenges pins the janitor: strictly-expired rows go,
// a row expiring exactly AT the boundary instant stays (the comparison is
// strictly-before, matching [auth.Store.PurgeExpired]), a live row stays, and
// the count is what was actually removed.
func checkPurgeExpiredChallenges(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	expired := newLoginChallenge(at)
	expired.ExpiresAt = at.Add(-time.Hour)
	mustCreateChallenge(t, st, expired)

	boundary := newLoginChallenge(at)
	boundary.ExpiresAt = at
	mustCreateChallenge(t, st, boundary)

	live := mustCreateChallenge(t, st, newLoginChallenge(at))

	n, err := st.PurgeExpiredChallenges(ctx, at)
	wantNoErr(t, "PurgeExpiredChallenges", err)
	if n != 1 {
		t.Fatalf("PurgeExpiredChallenges removed %d rows, want 1", n)
	}
	if _, err := st.FindChallengeByHash(ctx, expired.Hash); !errors.Is(err, auth.ErrChallengeNotFound) {
		t.Fatalf("the expired challenge survived the purge: err = %v", err)
	}
	if _, err := st.FindChallengeByHash(ctx, boundary.Hash); err != nil {
		t.Fatalf("a challenge expiring exactly at the boundary was purged: %v — the comparison is strictly-before", err)
	}
	if _, err := st.FindChallengeByHash(ctx, live.Hash); err != nil {
		t.Fatalf("a live challenge was purged: %v", err)
	}
}

// --- concurrency ---

// checkUpdateSignCountOneWinner is
// [auth.CredentialStore.UpdateSignCount]'s central MUST: however many callers
// present the SAME counter at once — which is exactly what replaying one
// captured assertion N times looks like — at most one may see ok=true.
//
// The stored counter afterwards must be the value they all raced with, which
// pins that the winner's write persisted what it was asked to rather than
// some other value a subtler bug could substitute while leaving the count at
// one.
//
// A read-then-write UpdateSignCount lets every caller observe the old counter,
// every one conclude theirs is greater, and every one win — after which the
// only clone detection in the package is gone and a captured assertion
// replays for as long as its challenge lives.
//
// How reliably this catches a SUBTLY non-atomic implementation depends on the
// backend, and this suite cannot promise more than the contention it can
// create from outside — see [checkMarkRotatedOneWinner], whose doc states the
// same limit at length. It catches a grossly non-atomic implementation — one
// with no compare-and-set at all — every time, and this package's own
// negative control widens the window so the check is deterministic against
// it.
func checkUpdateSignCountOneWinner(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	for round := 0; round < massRaceRounds; round++ {
		c := mustCreateCredential(t, st, newCredential(newID(), at))
		replayed := c.SignCount + 1
		used := at.Add(time.Duration(round+1) * time.Minute)

		var mu sync.Mutex
		winners, failures := 0, 0
		var firstErr error
		release(RaceGoroutines, func(int) {
			ok, err := st.UpdateSignCount(ctx, c.ID, replayed, used)
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
			t.Fatalf("round %d: %d of %d concurrent UpdateSignCount calls failed; first error %v",
				round, failures, RaceGoroutines, firstErr)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d of %d concurrent presentations of the same counter won, want exactly 1 — a replayed assertion must not be accepted twice",
				round, winners, RaceGoroutines)
		}

		got := loadCredential(t, st, c.CredentialID)
		if got.SignCount != replayed {
			t.Fatalf("round %d: stored SignCount = %d, want %d", round, got.SignCount, replayed)
		}
	}
}

// checkDeleteChallengeOneWinner is the claim's single-winner MUST: however
// many callers present one challenge at once, exactly one DeleteChallenge may
// return nil. That is what stops two people finishing one ceremony and both
// getting a session — the service claims before it issues anything, so "two
// winners here" is "two sessions there".
//
// The losers must all see auth.ErrChallengeNotFound, not some other error: the
// service maps that sentinel to a refusal, and a store reporting anything
// else would surface as an outage rather than as the ordinary "somebody got
// there first".
func checkDeleteChallengeOneWinner(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	for round := 0; round < massRaceRounds; round++ {
		c := mustCreateChallenge(t, st, newLoginChallenge(at))

		var mu sync.Mutex
		winners, unexpected := 0, 0
		var firstErr error
		release(RaceGoroutines, func(int) {
			err := st.DeleteChallenge(ctx, c.ID)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
			case !errors.Is(err, auth.ErrChallengeNotFound):
				unexpected++
				if firstErr == nil {
					firstErr = err
				}
			}
		})

		if unexpected != 0 {
			t.Fatalf("round %d: %d losing DeleteChallenge calls returned something other than ErrChallengeNotFound; first %v",
				round, unexpected, firstErr)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d of %d concurrent claims of one challenge succeeded, want exactly 1 — a challenge is single-use",
				round, winners, RaceGoroutines)
		}
	}
}

// checkDeleteIfNotLastAtomic is
// [auth.CredentialStore.DeleteCredentialIfNotLast]'s "It MUST be atomic": a
// user whose only two ways in are two passkeys removes both at once, and the
// account MUST still have one afterwards.
//
// A read-then-write implementation admits the permanent, silent lockout the
// port's doc describes: each call reads the list, sees the other credential,
// concludes the account stays reachable, and deletes. Both succeed, nothing
// in the package can sign that user in again, and both callers were told it
// worked.
//
// The two removals are run through [pair], so the roles alternate between
// rounds — closing a channel readies its waiters LIFO, so a fixed-role
// two-party race explores essentially one interleaving (measured at 198 of
// 200), and two of this package's own negative controls passed the unswapped
// version of an equivalent check. The assertion is on the surviving row
// count, never on which call won: both orderings are correct outcomes.
func checkDeleteIfNotLastAtomic(t tb, st auth.CredentialStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	for round := 0; round < RaceRounds; round++ {
		user := newID()
		first := mustCreateCredential(t, st, newCredential(user, at))
		second := mustCreateCredential(t, st, newCredential(user, at))

		var mu sync.Mutex
		var errs []error
		remove := func(id string) func() {
			return func() {
				// userHasOtherCredential is false: this account has no
				// password and no identity, so these two passkeys are the
				// only ways in and the store owns the whole decision.
				err := st.DeleteCredentialIfNotLast(ctx, user, id, false)
				mu.Lock()
				defer mu.Unlock()
				errs = append(errs, err)
			}
		}
		pair(round, remove(first.ID), remove(second.ID))

		for _, err := range errs {
			if err != nil && !errors.Is(err, auth.ErrLastCredential) {
				t.Fatalf("round %d: unexpected error from a concurrent removal: %v", round, err)
			}
		}

		left, err := st.ListCredentialsByUser(ctx, user)
		wantNoErr(t, "ListCredentialsByUser after the race", err)
		if len(left) == 0 {
			t.Fatalf("round %d: both concurrent removals succeeded and the account has no credential left — errors were %v. That is the permanent, silent lockout DeleteCredentialIfNotLast exists to prevent",
				round, errs)
		}
	}
}
