package oauthtest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

func codeChecks() []check {
	return []check{
		{"CreateCode/RoundTrip", checkCreateCodeRoundTrip},
		{"CreateCode/IDIsUnique", checkCreateCodeIDUnique},
		{"CreateCode/CodeHashIsUnique", checkCreateCodeHashUnique},
		{"CreateCode/UnknownGrantIsRefused", checkCreateCodeRefusesOrphan},
		{"RedeemCode/FirstCallWinsAndStampsRedeemedAt", checkRedeemCodeWins},
		{"RedeemCode/SecondCallLosesWithoutError", checkRedeemCodeLoses},
		{"RedeemCode/ExpiryIsNotPartOfThePredicate", checkRedeemCodeIgnoresExpiry},
		{"RedeemCode/UnknownHashReturnsErrCodeNotFound", checkRedeemCodeNotFound},
	}
}

// assertCodeEqual compares every field of an AuthorizationCode.
func assertCodeEqual(t tb, what string, got, want oauth.AuthorizationCode) {
	t.Helper()
	if got.ID != want.ID || got.CodeHash != want.CodeHash || got.ClientID != want.ClientID ||
		got.GrantID != want.GrantID || got.RedirectURI != want.RedirectURI || got.CodeChallenge != want.CodeChallenge {
		t.Fatalf("%s %+v, want %+v", what, got, want)
	}
	wantTimeEqual(t, what+" ExpiresAt", got.ExpiresAt, want.ExpiresAt)
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
	wantTimePtrEqual(t, what+" RedeemedAt", got.RedeemedAt, want.RedeemedAt)
}

// checkCreateCodeRoundTrip asserts CreateCode returns what it stored and
// that RedeemCode — the port's only read of a code — hands the same record
// back, challenge and redirect URI included: both are compared byte for
// byte at exchange, so a store that trims either changes what redeems.
func checkCreateCodeRoundTrip(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	code := newCode(g, at)
	created := mustCreateCode(t, st, code)
	assertCodeEqual(t, "CreateCode returned", created, code)

	got, won, err := st.RedeemCode(ctx, code.CodeHash, at)
	wantNoErr(t, "RedeemCode", err)
	if !won {
		t.Fatalf("RedeemCode of a fresh code reported won=false")
	}
	want := code
	want.RedeemedAt = &at
	assertCodeEqual(t, "RedeemCode returned", got, want)
}

// checkCreateCodeIDUnique asserts a second code under a taken id is
// ErrIDTaken and the original survives.
func checkCreateCodeIDUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	first := mustCreateCode(t, st, newCode(g, at))
	clash := newCode(g, at)
	clash.ID = first.ID
	_, err := st.CreateCode(ctx, clash)
	wantErrIs(t, "CreateCode(taken id)", err, oauth.ErrIDTaken)
	got, _, err := st.RedeemCode(ctx, first.CodeHash, at)
	wantNoErr(t, "RedeemCode(original)", err)
	if got.ID != first.ID {
		t.Fatalf("the original code was replaced: %+v", got)
	}
	if _, _, err := st.RedeemCode(ctx, clash.CodeHash, at); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("the refused code is readable: %v", err)
	}
}

// checkCreateCodeHashUnique asserts a second code under a taken hash — for
// another grant, so only the hash collides — FAILS, and that the original
// row is untouched. Which error is deliberately not asserted.
func checkCreateCodeHashUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g1 := mustCreateGrant(t, st, newGrant(c, newID(), at))
	g2 := mustCreateGrant(t, st, newGrant(c, newID(), at))
	first := mustCreateCode(t, st, newCode(g1, at))
	clash := newCode(g2, at)
	clash.CodeHash = first.CodeHash
	if _, err := st.CreateCode(ctx, clash); err == nil {
		t.Fatalf("CreateCode accepted a second code under a taken code hash — two rows now answer one presented code")
	}
	got, _, err := st.RedeemCode(ctx, first.CodeHash, at)
	wantNoErr(t, "RedeemCode", err)
	if got.ID != first.ID || got.GrantID != g1.ID {
		t.Fatalf("the hash resolves to %+v, want the original code %s", got, first.ID)
	}
}

// checkCreateCodeRefusesOrphan asserts a code naming no grant is
// ErrGrantNotFound and nothing is written.
func checkCreateCodeRefusesOrphan(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	ghost := newGrant(c, newID(), at) // never created
	code := newCode(ghost, at)
	_, err := st.CreateCode(ctx, code)
	wantErrIs(t, "CreateCode(unknown grant)", err, oauth.ErrGrantNotFound)
	if _, _, err := st.RedeemCode(ctx, code.CodeHash, at); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("the refused code is readable: %v", err)
	}
}

// checkRedeemCodeWins asserts the first redemption of a code reports
// won=true and persists exactly the instant it was given as RedeemedAt.
func checkRedeemCodeWins(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	code := mustCreateCode(t, st, newCode(g, at))
	when := at.Add(time.Second)
	got, won, err := st.RedeemCode(ctx, code.CodeHash, when)
	wantNoErr(t, "RedeemCode", err)
	if !won {
		t.Fatalf("RedeemCode of a fresh code reported won=false")
	}
	wantTimePtrEqual(t, "RedeemedAt", got.RedeemedAt, &when)
	// A later loser sees the same stamp.
	again, _, err := st.RedeemCode(ctx, code.CodeHash, when.Add(time.Second))
	wantNoErr(t, "RedeemCode(again)", err)
	wantTimePtrEqual(t, "RedeemedAt seen by the loser", again.RedeemedAt, &when)
}

// checkRedeemCodeLoses asserts the second redemption is (row, false, nil)
// — the row, so the Service can revoke its grant; false, so it knows it
// lost; nil, because losing is an answer, not a failure — and that the
// first stamp is not overwritten.
func checkRedeemCodeLoses(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	code := mustCreateCode(t, st, newCode(g, at))
	first := at.Add(time.Second)
	_, _, err := st.RedeemCode(ctx, code.CodeHash, first)
	wantNoErr(t, "RedeemCode", err)
	got, won, err := st.RedeemCode(ctx, code.CodeHash, first.Add(time.Second))
	wantNoErr(t, "second RedeemCode", err)
	if won {
		t.Fatalf("second RedeemCode reported won=true — the code redeemed twice")
	}
	if got.ID != code.ID || got.GrantID != g.ID {
		t.Fatalf("the loser was handed %+v, want the code row so it can revoke grant %s", got, g.ID)
	}
	wantTimePtrEqual(t, "RedeemedAt after the loss", got.RedeemedAt, &first)
}

// checkRedeemCodeIgnoresExpiry asserts an expired but unredeemed code is
// still redeemed (won=true): expiry is the Service's check, after winning,
// so a replay of an expired code is consumed and detected like any other.
func checkRedeemCodeIgnoresExpiry(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	code := newCode(g, at)
	code.ExpiresAt = at.Add(-time.Hour)
	mustCreateCode(t, st, code)
	_, won, err := st.RedeemCode(ctx, code.CodeHash, at)
	wantNoErr(t, "RedeemCode(expired)", err)
	if !won {
		t.Fatalf("RedeemCode refused an expired-but-unredeemed code — expiry must not be part of the predicate")
	}
}

// checkRedeemCodeNotFound asserts an unknown hash is ErrCodeNotFound, and
// never (zero, false, nil), which would be indistinguishable from a loss.
func checkRedeemCodeNotFound(t tb, st oauth.Store) {
	t.Helper()
	_, _, err := st.RedeemCode(context.Background(), newHash(), stamp())
	wantErrIs(t, "RedeemCode(unknown)", err, oauth.ErrCodeNotFound)
}
