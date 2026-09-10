package apikeytest

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
)

func keyChecks() []check {
	return []check{
		{"CreateKey/RoundTrip", checkCreateKeyRoundTrip},
		{"CreateKey/IDIsUnique", checkCreateKeyIDUnique},
		{"CreateKey/TokenHashIsUnique", checkCreateKeyTokenHashUnique},
		{"CreateKey/UnknownAccountIsRefused", checkCreateKeyRefusesOrphan},
		{"FindKeyByHash/UnknownHashReturnsErrKeyNotFound", checkFindKeyByHashNotFound},
		{"FindKeyByHash/ReturnsRevokedAndExpiredRowsToo", checkFindKeyByHashIncludesDead},
		{"FindKey/UnknownIDReturnsErrKeyNotFound", checkFindKeyNotFound},
		{"ListKeys/ScopesToTheAccount", checkListKeysScopes},
		{"ListKeys/ReturnsRevokedAndExpiredRowsToo", checkListKeysIncludesDead},
		{"ListKeys/EmptyAccountIsNotAnError", checkListKeysEmpty},
		{"RevokeKey/StampsRevokedAt", checkRevokeKeyStamps},
		{"RevokeKey/IsIdempotent", checkRevokeKeyIdempotent},
		{"RevokeKey/UnknownIDReturnsErrKeyNotFound", checkRevokeKeyNotFound},
		{"TouchKey/StampsLastUsedAt", checkTouchKeyStamps},
		{"TouchKey/UnknownIDReturnsErrKeyNotFound", checkTouchKeyNotFound},
		{"DeleteKey/RemovesExactlyOneRow", checkDeleteKey},
		{"DeleteKey/UnknownIDReturnsErrKeyNotFound", checkDeleteKeyNotFound},
	}
}

// checkCreateKeyRoundTrip asserts CreateKey returns what it stored and that
// every read path — by id, by hash, by account — returns the same record,
// for both shapes a key takes: the nil-everything default (no cap, no
// expiry, live, unused) and one with every nullable field set and a
// Permissions blob. The blob is opaque to a Store and must come back
// byte-identical: it is the key's cap, and a store that trims or re-encodes
// it changes what the key may do.
func checkCreateKeyRoundTrip(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))

	plain := newKey(sa, at)
	created := mustCreateKey(t, st, plain)
	assertKeyEqual(t, "CreateKey returned", created, plain)

	full := newKey(sa, at)
	expires, used, revoked := at.Add(time.Hour), at.Add(time.Minute), at.Add(2*time.Minute)
	full.Permissions = []byte("project:read\nproject:update")
	full.ExpiresAt = &expires
	full.LastUsedAt = &used
	full.RevokedAt = &revoked
	mustCreateKey(t, st, full)

	for _, want := range []apikey.Key{plain, full} {
		byID, err := st.FindKey(ctx, want.ID)
		wantNoErr(t, "FindKey", err)
		assertKeyEqual(t, "FindKey returned", byID, want)
		byHash, err := st.FindKeyByHash(ctx, want.TokenHash)
		wantNoErr(t, "FindKeyByHash", err)
		assertKeyEqual(t, "FindKeyByHash returned", byHash, want)
	}
	list, err := st.ListKeys(ctx, sa.ID)
	wantNoErr(t, "ListKeys", err)
	wantSameIDs(t, "ListKeys", keyIDs(list), []string{plain.ID, full.ID})
	for _, got := range list {
		if got.ID == full.ID {
			assertKeyEqual(t, "ListKeys returned", got, full)
		}
	}
}

// assertKeyEqual compares every field of a Key: strings exactly, the
// Permissions blob byte-for-byte with nil and empty treated alike (both mean
// "no cap" to the Service), instants by Equal.
func assertKeyEqual(t tb, what string, got, want apikey.Key) {
	t.Helper()
	if got.ID != want.ID {
		t.Fatalf("%s ID %q, want %q", what, got.ID, want.ID)
	}
	if got.ServiceAccountID != want.ServiceAccountID {
		t.Fatalf("%s ServiceAccountID %q, want %q", what, got.ServiceAccountID, want.ServiceAccountID)
	}
	if got.ContainerID != want.ContainerID {
		t.Fatalf("%s ContainerID %q, want %q", what, got.ContainerID, want.ContainerID)
	}
	if got.Name != want.Name {
		t.Fatalf("%s Name %q, want %q", what, got.Name, want.Name)
	}
	if got.Prefix != want.Prefix {
		t.Fatalf("%s Prefix %q, want %q", what, got.Prefix, want.Prefix)
	}
	if got.TokenHash != want.TokenHash {
		t.Fatalf("%s TokenHash %q, want %q", what, got.TokenHash, want.TokenHash)
	}
	if !bytes.Equal(got.Permissions, want.Permissions) {
		t.Fatalf("%s Permissions %q, want %q — the cap must round-trip byte-for-byte", what, got.Permissions, want.Permissions)
	}
	if got.CreatedBy != want.CreatedBy {
		t.Fatalf("%s CreatedBy %q, want %q", what, got.CreatedBy, want.CreatedBy)
	}
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
	wantTimePtrEqual(t, what+" ExpiresAt", got.ExpiresAt, want.ExpiresAt)
	wantTimePtrEqual(t, what+" LastUsedAt", got.LastUsedAt, want.LastUsedAt)
	wantTimePtrEqual(t, what+" RevokedAt", got.RevokedAt, want.RevokedAt)
}

// checkCreateKeyIDUnique asserts a second create under a taken key id is
// apikey.ErrIDTaken and leaves the first row — its hash, its account — as it
// was. The clash carries its own hash and names another account, so only the
// id collides.
func checkCreateKeyIDUnique(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	other := mustCreateAccount(t, st, newAccount(newID(), at))
	first := mustCreateKey(t, st, newKey(sa, at))

	clash := newKey(other, at)
	clash.ID = first.ID
	if _, err := st.CreateKey(ctx, clash); !errors.Is(err, apikey.ErrIDTaken) {
		t.Fatalf("CreateKey with a taken id: error = %v, want ErrIDTaken", err)
	}
	got, err := st.FindKey(ctx, first.ID)
	wantNoErr(t, "FindKey", err)
	assertKeyEqual(t, "after the refused create, FindKey returned", got, first)
}

// checkCreateKeyTokenHashUnique asserts the uniqueness MUST
// [apikey.Key.TokenHash] states: a second key holding a hash another key
// already holds is refused — by whatever error the backend chooses, which
// the port leaves unclassified — and the original row is untouched, so a
// lookup by that hash still resolves to the first key's account. The clash
// names ANOTHER account, which is exactly the shape that matters: were it
// accepted, one plaintext would authenticate as either account depending on
// which row the backend returned first.
func checkCreateKeyTokenHashUnique(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	other := mustCreateAccount(t, st, newAccount(newID(), at))
	first := mustCreateKey(t, st, newKey(sa, at))

	clash := newKey(other, at)
	clash.TokenHash = first.TokenHash
	if _, err := st.CreateKey(ctx, clash); err == nil {
		t.Fatalf("CreateKey accepted a second key with token hash %q — two rows now answer one presented plaintext, and which account it acts as is decided by row order", first.TokenHash)
	}
	got, err := st.FindKeyByHash(ctx, first.TokenHash)
	wantNoErr(t, "FindKeyByHash", err)
	assertKeyEqual(t, "after the refused create, FindKeyByHash returned", got, first)
	if _, err := st.FindKey(ctx, clash.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("the refused key was written anyway: FindKey error = %v, want ErrKeyNotFound", err)
	}
}

// checkCreateKeyRefusesOrphan asserts the port's third MUST: a key whose
// ServiceAccountID names no account is refused with
// apikey.ErrServiceAccountNotFound and not written. Such a row would be a
// credential for a principal that does not exist; the Service refuses it at
// authentication, but the row itself must not be there to refuse.
func checkCreateKeyRefusesOrphan(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	ghost := newAccount(newID(), stamp()) // never created
	k := newKey(ghost, stamp())
	if _, err := st.CreateKey(ctx, k); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("CreateKey for an account that does not exist: error = %v, want ErrServiceAccountNotFound", err)
	}
	if _, err := st.FindKey(ctx, k.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("the orphan key was written anyway: FindKey error = %v, want ErrKeyNotFound", err)
	}
	if _, err := st.FindKeyByHash(ctx, k.TokenHash); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("the orphan key resolves by hash: error = %v, want ErrKeyNotFound", err)
	}
}

// checkFindKeyByHashNotFound asserts an unknown hash is the sentinel — the
// answer the Service turns into a refused authentication — not a zero key
// with a nil error, which would authenticate as the zero account.
func checkFindKeyByHashNotFound(t tb, st apikey.Store) {
	t.Helper()
	_, err := st.FindKeyByHash(context.Background(), newHash())
	wantErrIs(t, "FindKeyByHash(unknown)", err, apikey.ErrKeyNotFound)
}

// checkFindKeyByHashIncludesDead asserts a revoked key and an expired key
// still resolve by hash: the port leaves classification to the Service, so
// it can tell the holder WHY, and a store that hid them would turn every
// revoked-key presentation into an indistinguishable not-found.
func checkFindKeyByHashIncludesDead(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	revoked := newKey(sa, at)
	past := at.Add(-time.Minute)
	revoked.RevokedAt = &past
	mustCreateKey(t, st, revoked)
	expired := newKey(sa, at)
	expired.ExpiresAt = &past
	mustCreateKey(t, st, expired)

	for _, k := range []apikey.Key{revoked, expired} {
		got, err := st.FindKeyByHash(ctx, k.TokenHash)
		wantNoErr(t, "FindKeyByHash(dead key)", err)
		assertKeyEqual(t, "FindKeyByHash(dead key) returned", got, k)
	}
}

// checkFindKeyNotFound asserts an unknown id is the sentinel.
func checkFindKeyNotFound(t tb, st apikey.Store) {
	t.Helper()
	_, err := st.FindKey(context.Background(), newID())
	wantErrIs(t, "FindKey(unknown)", err, apikey.ErrKeyNotFound)
}

// checkListKeysScopes asserts ListKeys returns exactly the keys of the
// account asked for — two accounts in ONE container, so a store scoping by
// container rather than by account is caught.
func checkListKeysScopes(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	a := mustCreateAccount(t, st, newAccount(containerID, at))
	b := mustCreateAccount(t, st, newAccount(containerID, at))
	a1 := mustCreateKey(t, st, newKey(a, at))
	a2 := mustCreateKey(t, st, newKey(a, at))
	b1 := mustCreateKey(t, st, newKey(b, at))

	list, err := st.ListKeys(ctx, a.ID)
	wantNoErr(t, "ListKeys(a)", err)
	wantSameIDs(t, "ListKeys(a)", keyIDs(list), []string{a1.ID, a2.ID})
	list, err = st.ListKeys(ctx, b.ID)
	wantNoErr(t, "ListKeys(b)", err)
	wantSameIDs(t, "ListKeys(b)", keyIDs(list), []string{b1.ID})
}

// checkListKeysIncludesDead asserts revoked and expired keys are listed: the
// management screen that shows what happened to a key, and the purge that
// removes it, both need to see it.
func checkListKeysIncludesDead(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	live := mustCreateKey(t, st, newKey(sa, at))
	past := at.Add(-time.Minute)
	revoked := newKey(sa, at)
	revoked.RevokedAt = &past
	mustCreateKey(t, st, revoked)
	expired := newKey(sa, at)
	expired.ExpiresAt = &past
	mustCreateKey(t, st, expired)

	list, err := st.ListKeys(ctx, sa.ID)
	wantNoErr(t, "ListKeys", err)
	wantSameIDs(t, "ListKeys", keyIDs(list), []string{live.ID, revoked.ID, expired.ID})
}

// checkListKeysEmpty asserts an account with no keys is an empty result, not
// an error — and so is an account id that does not exist, since ListKeys
// answers "which keys" and not "does this account exist".
func checkListKeysEmpty(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	sa := mustCreateAccount(t, st, newAccount(newID(), stamp()))
	list, err := st.ListKeys(ctx, sa.ID)
	wantNoErr(t, "ListKeys(no keys)", err)
	if len(list) != 0 {
		t.Fatalf("ListKeys(no keys) returned %d row(s), want 0", len(list))
	}
	list, err = st.ListKeys(ctx, newID())
	wantNoErr(t, "ListKeys(unknown account)", err)
	if len(list) != 0 {
		t.Fatalf("ListKeys(unknown account) returned %d row(s), want 0", len(list))
	}
}

// checkRevokeKeyStamps asserts RevokeKey writes RevokedAt with the instant
// it is handed and changes nothing else on the row.
func checkRevokeKeyStamps(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	k := mustCreateKey(t, st, newKey(sa, at))
	later := at.Add(time.Minute)

	wantNoErr(t, "RevokeKey", st.RevokeKey(ctx, k.ID, later))
	got, err := st.FindKey(ctx, k.ID)
	wantNoErr(t, "FindKey", err)
	want := k
	want.RevokedAt = &later
	assertKeyEqual(t, "after revoke, FindKey returned", got, want)
}

// checkRevokeKeyIdempotent asserts a second revocation is not an error and
// leaves the key revoked (at the later instant, matching
// invite.Store.RevokeLink's overwrite).
func checkRevokeKeyIdempotent(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	k := mustCreateKey(t, st, newKey(sa, at))
	t1, t2 := at.Add(time.Minute), at.Add(2*time.Minute)

	wantNoErr(t, "first RevokeKey", st.RevokeKey(ctx, k.ID, t1))
	wantNoErr(t, "second RevokeKey", st.RevokeKey(ctx, k.ID, t2))
	got, err := st.FindKey(ctx, k.ID)
	wantNoErr(t, "FindKey", err)
	if got.RevokedAt == nil {
		t.Fatalf("RevokedAt is nil after two revocations")
	}
	wantTimeEqual(t, "RevokedAt after the second revoke", *got.RevokedAt, t2)
}

// checkRevokeKeyNotFound asserts an unknown id is the sentinel, not a nil
// that would let a caller believe a leaked key was revoked.
func checkRevokeKeyNotFound(t tb, st apikey.Store) {
	t.Helper()
	wantErrIs(t, "RevokeKey(unknown)", st.RevokeKey(context.Background(), newID(), stamp()), apikey.ErrKeyNotFound)
}

// checkTouchKeyStamps asserts TouchKey writes LastUsedAt and nothing else.
func checkTouchKeyStamps(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	k := mustCreateKey(t, st, newKey(sa, at))
	later := at.Add(time.Minute)

	wantNoErr(t, "TouchKey", st.TouchKey(ctx, k.ID, later))
	got, err := st.FindKey(ctx, k.ID)
	wantNoErr(t, "FindKey", err)
	want := k
	want.LastUsedAt = &later
	assertKeyEqual(t, "after touch, FindKey returned", got, want)
}

// checkTouchKeyNotFound asserts an unknown id is the sentinel: the Service
// treats a touch failure as bookkeeping, but a nil for a row that does not
// exist would still be a lie.
func checkTouchKeyNotFound(t tb, st apikey.Store) {
	t.Helper()
	wantErrIs(t, "TouchKey(unknown)", st.TouchKey(context.Background(), newID(), stamp()), apikey.ErrKeyNotFound)
}

// checkDeleteKey asserts DeleteKey removes the one row named and leaves the
// account's other key, and the account itself, in place.
func checkDeleteKey(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	doomed := mustCreateKey(t, st, newKey(sa, at))
	survivor := mustCreateKey(t, st, newKey(sa, at))

	wantNoErr(t, "DeleteKey", st.DeleteKey(ctx, doomed.ID))
	if _, err := st.FindKey(ctx, doomed.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("FindKey(deleted) error = %v, want ErrKeyNotFound", err)
	}
	if _, err := st.FindKey(ctx, survivor.ID); err != nil {
		t.Fatalf("DeleteKey removed the account's other key too: %v", err)
	}
	if _, err := st.FindServiceAccount(ctx, sa.ID); err != nil {
		t.Fatalf("DeleteKey removed the account: %v", err)
	}
}

// checkDeleteKeyNotFound asserts an unknown id — and a second delete of a
// just-deleted one — is the sentinel.
func checkDeleteKeyNotFound(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	wantErrIs(t, "DeleteKey(unknown)", st.DeleteKey(ctx, newID()), apikey.ErrKeyNotFound)
	sa := mustCreateAccount(t, st, newAccount(newID(), stamp()))
	k := mustCreateKey(t, st, newKey(sa, stamp()))
	wantNoErr(t, "DeleteKey", st.DeleteKey(ctx, k.ID))
	wantErrIs(t, "second DeleteKey", st.DeleteKey(ctx, k.ID), apikey.ErrKeyNotFound)
}
