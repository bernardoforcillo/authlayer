package oauthtest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

func refreshChecks() []check {
	return []check{
		{"CreateRefreshToken/RoundTrip", checkCreateRefreshRoundTrip},
		{"CreateRefreshToken/IDIsUnique", checkCreateRefreshIDUnique},
		{"CreateRefreshToken/TokenHashIsUnique", checkCreateRefreshHashUnique},
		{"CreateRefreshToken/UnknownGrantIsRefused", checkCreateRefreshRefusesOrphan},
		{"FindRefreshTokenByHash/UnknownHashReturnsErrRefreshNotFound", checkFindRefreshNotFound},
		{"FindRefreshTokenByHash/ReturnsRotatedAndExpiredRowsToo", checkFindRefreshIncludesDead},
		{"MarkRefreshRotated/FirstCallWinsAndStampsRotatedAt", checkMarkRotatedWins},
		{"MarkRefreshRotated/SecondCallLosesWithoutError", checkMarkRotatedLoses},
		{"MarkRefreshRotated/ExpiryIsNotPartOfThePredicate", checkMarkRotatedIgnoresExpiry},
		{"MarkRefreshRotated/UnknownHashReturnsErrRefreshNotFound", checkMarkRotatedNotFound},
		{"DeleteRefreshFamily/RemovesEveryTokenOfTheFamily", checkDeleteFamily},
		{"DeleteRefreshFamily/LeavesOtherFamiliesAlone", checkDeleteFamilyScoped},
		{"DeleteRefreshFamily/EmptyFamilyIsNotAnError", checkDeleteFamilyEmpty},
	}
}

// assertRefreshEqual compares every field of a RefreshToken.
func assertRefreshEqual(t tb, what string, got, want oauth.RefreshToken) {
	t.Helper()
	if got.ID != want.ID || got.TokenHash != want.TokenHash || got.GrantID != want.GrantID ||
		got.ClientID != want.ClientID || got.FamilyID != want.FamilyID {
		t.Fatalf("%s %+v, want %+v", what, got, want)
	}
	wantTimeEqual(t, what+" ExpiresAt", got.ExpiresAt, want.ExpiresAt)
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
	wantTimePtrEqual(t, what+" RotatedAt", got.RotatedAt, want.RotatedAt)
}

// checkCreateRefreshRoundTrip asserts CreateRefreshToken returns what it
// stored and FindRefreshTokenByHash returns the same record, for a current
// token and for one already rotated.
func checkCreateRefreshRoundTrip(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	current := mustCreateRefresh(t, st, newRefresh(g, at))
	rotated := newRefresh(g, at)
	rotated.FamilyID = current.FamilyID
	when := at.Add(time.Minute)
	rotated.RotatedAt = &when
	created := mustCreateRefresh(t, st, rotated)
	assertRefreshEqual(t, "CreateRefreshToken returned", created, rotated)

	for _, want := range []oauth.RefreshToken{current, rotated} {
		got, err := st.FindRefreshTokenByHash(ctx, want.TokenHash)
		wantNoErr(t, "FindRefreshTokenByHash", err)
		assertRefreshEqual(t, "FindRefreshTokenByHash returned", got, want)
	}
}

// checkCreateRefreshIDUnique asserts a second token under a taken id is
// ErrIDTaken and the original survives.
func checkCreateRefreshIDUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	first := mustCreateRefresh(t, st, newRefresh(g, at))
	clash := newRefresh(g, at)
	clash.ID = first.ID
	_, err := st.CreateRefreshToken(ctx, clash)
	wantErrIs(t, "CreateRefreshToken(taken id)", err, oauth.ErrIDTaken)
	got, err := st.FindRefreshTokenByHash(ctx, first.TokenHash)
	wantNoErr(t, "FindRefreshTokenByHash", err)
	assertRefreshEqual(t, "the original token after the refused create", got, first)
	if _, err := st.FindRefreshTokenByHash(ctx, clash.TokenHash); !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("the refused token is readable: %v", err)
	}
}

// checkCreateRefreshHashUnique asserts a second token under a taken hash —
// for another grant, so only the hash collides — FAILS and the original is
// untouched. Which error is not asserted.
func checkCreateRefreshHashUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g1 := mustCreateGrant(t, st, newGrant(c, newID(), at))
	g2 := mustCreateGrant(t, st, newGrant(c, newID(), at))
	first := mustCreateRefresh(t, st, newRefresh(g1, at))
	clash := newRefresh(g2, at)
	clash.TokenHash = first.TokenHash
	if _, err := st.CreateRefreshToken(ctx, clash); err == nil {
		t.Fatalf("CreateRefreshToken accepted a second token under a taken hash — two rows now answer one presented token")
	}
	got, err := st.FindRefreshTokenByHash(ctx, first.TokenHash)
	wantNoErr(t, "FindRefreshTokenByHash", err)
	if got.ID != first.ID || got.GrantID != g1.ID {
		t.Fatalf("the hash resolves to %+v, want the original token %s", got, first.ID)
	}
}

// checkCreateRefreshRefusesOrphan asserts a token naming no grant is
// ErrGrantNotFound and nothing is written.
func checkCreateRefreshRefusesOrphan(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	ghost := newGrant(c, newID(), at) // never created
	rt := newRefresh(ghost, at)
	_, err := st.CreateRefreshToken(ctx, rt)
	wantErrIs(t, "CreateRefreshToken(unknown grant)", err, oauth.ErrGrantNotFound)
	if _, err := st.FindRefreshTokenByHash(ctx, rt.TokenHash); !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("the refused token is readable: %v", err)
	}
}

// checkFindRefreshNotFound asserts an unknown hash is ErrRefreshNotFound.
func checkFindRefreshNotFound(t tb, st oauth.Store) {
	t.Helper()
	_, err := st.FindRefreshTokenByHash(context.Background(), newHash())
	wantErrIs(t, "FindRefreshTokenByHash(unknown)", err, oauth.ErrRefreshNotFound)
}

// checkFindRefreshIncludesDead asserts a rotated token and an expired one
// are both returned: Introspect reads the row to answer, and the Service
// classifies.
func checkFindRefreshIncludesDead(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	rotated := newRefresh(g, at)
	rotated.RotatedAt = &at
	mustCreateRefresh(t, st, rotated)
	expired := newRefresh(g, at)
	expired.ExpiresAt = at.Add(-time.Hour)
	mustCreateRefresh(t, st, expired)
	for _, want := range []oauth.RefreshToken{rotated, expired} {
		got, err := st.FindRefreshTokenByHash(ctx, want.TokenHash)
		wantNoErr(t, "FindRefreshTokenByHash", err)
		assertRefreshEqual(t, "FindRefreshTokenByHash returned", got, want)
	}
}

// checkMarkRotatedWins asserts the first rotation reports won=true and
// persists exactly the instant it was given as RotatedAt.
func checkMarkRotatedWins(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	rt := mustCreateRefresh(t, st, newRefresh(g, at))
	when := at.Add(time.Minute)
	got, won, err := st.MarkRefreshRotated(ctx, rt.TokenHash, when)
	wantNoErr(t, "MarkRefreshRotated", err)
	if !won {
		t.Fatalf("MarkRefreshRotated of a current token reported won=false")
	}
	want := rt
	want.RotatedAt = &when
	assertRefreshEqual(t, "MarkRefreshRotated returned", got, want)
	stored, err := st.FindRefreshTokenByHash(ctx, rt.TokenHash)
	wantNoErr(t, "FindRefreshTokenByHash", err)
	wantTimePtrEqual(t, "stored RotatedAt", stored.RotatedAt, &when)
}

// checkMarkRotatedLoses asserts the second rotation is (row, false, nil)
// with the first stamp intact — the row, so the Service can revoke the
// family and the grant it names.
func checkMarkRotatedLoses(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	rt := mustCreateRefresh(t, st, newRefresh(g, at))
	first := at.Add(time.Minute)
	_, _, err := st.MarkRefreshRotated(ctx, rt.TokenHash, first)
	wantNoErr(t, "MarkRefreshRotated", err)
	got, won, err := st.MarkRefreshRotated(ctx, rt.TokenHash, first.Add(time.Minute))
	wantNoErr(t, "second MarkRefreshRotated", err)
	if won {
		t.Fatalf("second MarkRefreshRotated reported won=true — the token rotated twice")
	}
	if got.ID != rt.ID || got.FamilyID != rt.FamilyID || got.GrantID != g.ID {
		t.Fatalf("the loser was handed %+v, want the token row so it can revoke family %s and grant %s", got, rt.FamilyID, g.ID)
	}
	wantTimePtrEqual(t, "RotatedAt after the loss", got.RotatedAt, &first)
}

// checkMarkRotatedIgnoresExpiry asserts an expired but current token is
// still rotated (won=true): the Service checks expiry after winning, so a
// replay of an expired token is consumed and detected like any other.
func checkMarkRotatedIgnoresExpiry(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	rt := newRefresh(g, at)
	rt.ExpiresAt = at.Add(-time.Hour)
	mustCreateRefresh(t, st, rt)
	_, won, err := st.MarkRefreshRotated(ctx, rt.TokenHash, at)
	wantNoErr(t, "MarkRefreshRotated(expired)", err)
	if !won {
		t.Fatalf("MarkRefreshRotated refused an expired-but-current token — expiry must not be part of the predicate")
	}
}

// checkMarkRotatedNotFound asserts an unknown hash is ErrRefreshNotFound,
// never (zero, false, nil), which would read as a replay.
func checkMarkRotatedNotFound(t tb, st oauth.Store) {
	t.Helper()
	_, _, err := st.MarkRefreshRotated(context.Background(), newHash(), stamp())
	wantErrIs(t, "MarkRefreshRotated(unknown)", err, oauth.ErrRefreshNotFound)
}

// checkDeleteFamily asserts DeleteRefreshFamily removes every token
// sharing the family id — current and rotated alike.
func checkDeleteFamily(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	first := newRefresh(g, at)
	first.RotatedAt = &at // superseded, kept for reuse detection
	mustCreateRefresh(t, st, first)
	second := newRefresh(g, at)
	second.FamilyID = first.FamilyID
	mustCreateRefresh(t, st, second)
	wantNoErr(t, "DeleteRefreshFamily", st.DeleteRefreshFamily(ctx, first.FamilyID))
	for _, r := range []oauth.RefreshToken{first, second} {
		if _, err := st.FindRefreshTokenByHash(ctx, r.TokenHash); !errors.Is(err, oauth.ErrRefreshNotFound) {
			t.Fatalf("token %s survived its family's deletion: %v", r.ID, err)
		}
	}
}

// checkDeleteFamilyScoped asserts another family of the same grant
// survives.
func checkDeleteFamilyScoped(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	doomed := mustCreateRefresh(t, st, newRefresh(g, at))
	other := mustCreateRefresh(t, st, newRefresh(g, at))
	wantNoErr(t, "DeleteRefreshFamily", st.DeleteRefreshFamily(ctx, doomed.FamilyID))
	if _, err := st.FindRefreshTokenByHash(ctx, other.TokenHash); err != nil {
		t.Fatalf("a token of another family was deleted: %v", err)
	}
}

// checkDeleteFamilyEmpty asserts deleting a family with no rows is nil.
func checkDeleteFamilyEmpty(t tb, st oauth.Store) {
	t.Helper()
	wantNoErr(t, "DeleteRefreshFamily(empty)", st.DeleteRefreshFamily(context.Background(), newID()))
}
