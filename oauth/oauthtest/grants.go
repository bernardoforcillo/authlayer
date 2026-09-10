package oauthtest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

func grantChecks() []check {
	return []check{
		{"CreateGrant/RoundTrip", checkCreateGrantRoundTrip},
		{"CreateGrant/IDIsUnique", checkCreateGrantIDUnique},
		{"CreateGrant/UnknownClientIsRefused", checkCreateGrantRefusesOrphan},
		{"FindGrant/UnknownIDReturnsErrGrantNotFound", checkFindGrantNotFound},
		{"ListGrantsByUser/ScopesToTheUser", checkListGrantsScopes},
		{"ListGrantsByUser/ReturnsRevokedAndExpiredRowsToo", checkListGrantsIncludesDead},
		{"ListGrantsByUser/EmptyUserIsNotAnError", checkListGrantsEmpty},
		{"RevokeGrant/StampsRevokedAtAndDeletesItsRefreshTokens", checkRevokeGrantCascades},
		{"RevokeGrant/LeavesOtherGrantsAlone", checkRevokeGrantScoped},
		{"RevokeGrant/IsIdempotent", checkRevokeGrantIdempotent},
		{"RevokeGrant/UnknownIDReturnsErrGrantNotFound", checkRevokeGrantNotFound},
		{"TouchGrant/StampsLastUsedAt", checkTouchGrantStamps},
		{"TouchGrant/UnknownIDReturnsErrGrantNotFound", checkTouchGrantNotFound},
	}
}

// assertGrantEqual compares every field of a Grant: strings exactly, the
// Permissions blob byte for byte with nil and empty alike, instants by
// Equal.
func assertGrantEqual(t tb, what string, got, want oauth.Grant) {
	t.Helper()
	if got.ID != want.ID || got.ClientID != want.ClientID || got.UserID != want.UserID ||
		got.ContainerID != want.ContainerID || got.Scope != want.Scope {
		t.Fatalf("%s %+v, want %+v", what, got, want)
	}
	wantBytesEqual(t, what+" Permissions", got.Permissions, want.Permissions)
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
	wantTimePtrEqual(t, what+" ExpiresAt", got.ExpiresAt, want.ExpiresAt)
	wantTimePtrEqual(t, what+" LastUsedAt", got.LastUsedAt, want.LastUsedAt)
	wantTimePtrEqual(t, what+" RevokedAt", got.RevokedAt, want.RevokedAt)
}

// checkCreateGrantRoundTrip asserts CreateGrant returns what it stored and
// that FindGrant and ListGrantsByUser return the same record, for both
// shapes: the nil-everything default (no cap, no expiry, live, unused) and
// one with every nullable field set and a Permissions blob — the cap, which
// must come back byte-identical.
func checkCreateGrantRoundTrip(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	user := newID()

	plain := mustCreateGrant(t, st, newGrant(c, user, at))
	full := newGrant(c, user, at)
	expires, used, revoked := at.Add(time.Hour), at.Add(time.Minute), at.Add(2*time.Minute)
	full.Permissions = []byte("project:read\nproject:deploy")
	full.ExpiresAt = &expires
	full.LastUsedAt = &used
	full.RevokedAt = &revoked
	created := mustCreateGrant(t, st, full)
	assertGrantEqual(t, "CreateGrant returned", created, full)

	for _, want := range []oauth.Grant{plain, full} {
		got, err := st.FindGrant(ctx, want.ID)
		wantNoErr(t, "FindGrant", err)
		assertGrantEqual(t, "FindGrant returned", got, want)
	}
	list, err := st.ListGrantsByUser(ctx, user)
	wantNoErr(t, "ListGrantsByUser", err)
	wantSameIDs(t, "ListGrantsByUser", grantIDs(list), []string{plain.ID, full.ID})
	for _, got := range list {
		if got.ID == full.ID {
			assertGrantEqual(t, "ListGrantsByUser returned", got, full)
		}
	}
}

// checkCreateGrantIDUnique asserts a second grant under a taken id is
// ErrIDTaken and the original survives.
func checkCreateGrantIDUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	first := mustCreateGrant(t, st, newGrant(c, newID(), at))
	clash := newGrant(c, newID(), at)
	clash.ID = first.ID
	_, err := st.CreateGrant(ctx, clash)
	wantErrIs(t, "CreateGrant(taken id)", err, oauth.ErrIDTaken)
	got, err := st.FindGrant(ctx, first.ID)
	wantNoErr(t, "FindGrant", err)
	assertGrantEqual(t, "the original grant after the refused create", got, first)
}

// checkCreateGrantRefusesOrphan asserts a grant naming no client is
// ErrClientNotFound and nothing is written: a delegation to a client that
// does not exist is a row the DeleteClient cascade exists to prevent.
func checkCreateGrantRefusesOrphan(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	ghost := newClient(newID(), at) // never created
	g := newGrant(ghost, newID(), at)
	_, err := st.CreateGrant(ctx, g)
	wantErrIs(t, "CreateGrant(unknown client)", err, oauth.ErrClientNotFound)
	if _, err := st.FindGrant(ctx, g.ID); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("the refused grant is readable: %v", err)
	}
}

// checkFindGrantNotFound asserts an unknown id is ErrGrantNotFound.
func checkFindGrantNotFound(t tb, st oauth.Store) {
	t.Helper()
	_, err := st.FindGrant(context.Background(), newID())
	wantErrIs(t, "FindGrant(unknown)", err, oauth.ErrGrantNotFound)
}

// checkListGrantsScopes asserts ListGrantsByUser returns exactly one
// user's grants — across clients and containers, since a connected-apps
// screen spans them — and none of another user's.
func checkListGrantsScopes(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c1 := mustCreateClient(t, st, newClient(newID(), at))
	c2 := mustCreateClient(t, st, newClient(newID(), at))
	alice, bob := newID(), newID()
	a1 := mustCreateGrant(t, st, newGrant(c1, alice, at))
	a2 := mustCreateGrant(t, st, newGrant(c2, alice, at))
	mustCreateGrant(t, st, newGrant(c1, bob, at))

	list, err := st.ListGrantsByUser(ctx, alice)
	wantNoErr(t, "ListGrantsByUser", err)
	wantSameIDs(t, "ListGrantsByUser(alice)", grantIDs(list), []string{a1.ID, a2.ID})
}

// checkListGrantsIncludesDead asserts revoked and expired grants are
// listed: the port leaves filtering to the caller.
func checkListGrantsIncludesDead(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	user := newID()
	live := mustCreateGrant(t, st, newGrant(c, user, at))
	revoked := newGrant(c, user, at)
	revoked.RevokedAt = &at
	mustCreateGrant(t, st, revoked)
	expired := newGrant(c, user, at)
	past := at.Add(-time.Hour)
	expired.ExpiresAt = &past
	mustCreateGrant(t, st, expired)

	list, err := st.ListGrantsByUser(ctx, user)
	wantNoErr(t, "ListGrantsByUser", err)
	wantSameIDs(t, "ListGrantsByUser", grantIDs(list), []string{live.ID, revoked.ID, expired.ID})
}

// checkListGrantsEmpty asserts a user with no grants yields an empty
// result and no error.
func checkListGrantsEmpty(t tb, st oauth.Store) {
	t.Helper()
	list, err := st.ListGrantsByUser(context.Background(), newID())
	wantNoErr(t, "ListGrantsByUser(empty)", err)
	if len(list) != 0 {
		t.Fatalf("ListGrantsByUser on a user with none returned %d row(s), want 0", len(list))
	}
}

// checkRevokeGrantCascades asserts RevokeGrant stamps RevokedAt with the
// instant it was given and deletes every refresh token of the grant —
// across families — while the grant's codes and device authorizations,
// which the Service checks against the grant after redeeming, are left
// alone.
func checkRevokeGrantCascades(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	r1 := mustCreateRefresh(t, st, newRefresh(g, at))
	r2 := mustCreateRefresh(t, st, newRefresh(g, at)) // a second family
	code := mustCreateCode(t, st, newCode(g, at))
	when := at.Add(time.Minute)

	wantNoErr(t, "RevokeGrant", st.RevokeGrant(ctx, g.ID, when))

	got, err := st.FindGrant(ctx, g.ID)
	wantNoErr(t, "FindGrant", err)
	wantTimePtrEqual(t, "RevokedAt", got.RevokedAt, &when)
	for _, r := range []oauth.RefreshToken{r1, r2} {
		if _, err := st.FindRefreshTokenByHash(ctx, r.TokenHash); !errors.Is(err, oauth.ErrRefreshNotFound) {
			t.Fatalf("refresh token %s outlived its grant's revocation: %v", r.ID, err)
		}
	}
	if _, _, err := st.RedeemCode(ctx, code.CodeHash, at); err != nil {
		t.Fatalf("RevokeGrant removed the grant's code: %v — codes are left for the Service and PurgeExpired", err)
	}
}

// checkRevokeGrantScoped asserts the refresh tokens of OTHER grants — of
// the same client, of the same user — survive a revocation.
func checkRevokeGrantScoped(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	user := newID()
	doomed := mustCreateGrant(t, st, newGrant(c, user, at))
	mustCreateRefresh(t, st, newRefresh(doomed, at))
	other := mustCreateGrant(t, st, newGrant(c, user, at))
	rt := mustCreateRefresh(t, st, newRefresh(other, at))

	wantNoErr(t, "RevokeGrant", st.RevokeGrant(ctx, doomed.ID, at))

	got, err := st.FindGrant(ctx, other.ID)
	wantNoErr(t, "FindGrant(other)", err)
	if got.RevokedAt != nil {
		t.Fatalf("the other grant was revoked too")
	}
	if _, err := st.FindRefreshTokenByHash(ctx, rt.TokenHash); err != nil {
		t.Fatalf("the other grant's refresh token was deleted: %v", err)
	}
}

// checkRevokeGrantIdempotent asserts a second revocation is not an error
// and overwrites the timestamp.
func checkRevokeGrantIdempotent(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	first, second := at.Add(time.Minute), at.Add(2*time.Minute)
	wantNoErr(t, "RevokeGrant", st.RevokeGrant(ctx, g.ID, first))
	wantNoErr(t, "second RevokeGrant", st.RevokeGrant(ctx, g.ID, second))
	got, err := st.FindGrant(ctx, g.ID)
	wantNoErr(t, "FindGrant", err)
	wantTimePtrEqual(t, "RevokedAt after the second revocation", got.RevokedAt, &second)
}

// checkRevokeGrantNotFound asserts an unknown id is ErrGrantNotFound.
func checkRevokeGrantNotFound(t tb, st oauth.Store) {
	t.Helper()
	wantErrIs(t, "RevokeGrant(unknown)", st.RevokeGrant(context.Background(), newID(), stamp()), oauth.ErrGrantNotFound)
}

// checkTouchGrantStamps asserts TouchGrant writes exactly LastUsedAt and
// nothing else.
func checkTouchGrantStamps(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	used := at.Add(time.Minute)
	wantNoErr(t, "TouchGrant", st.TouchGrant(ctx, g.ID, used))
	got, err := st.FindGrant(ctx, g.ID)
	wantNoErr(t, "FindGrant", err)
	want := g
	want.LastUsedAt = &used
	assertGrantEqual(t, "FindGrant after TouchGrant", got, want)
}

// checkTouchGrantNotFound asserts an unknown id is ErrGrantNotFound.
func checkTouchGrantNotFound(t tb, st oauth.Store) {
	t.Helper()
	wantErrIs(t, "TouchGrant(unknown)", st.TouchGrant(context.Background(), newID(), stamp()), oauth.ErrGrantNotFound)
}
