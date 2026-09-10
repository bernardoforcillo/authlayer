package oauthtest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

func housekeepingChecks() []check {
	return []check{
		{"PurgeExpired/CutoffIsStrictOnCodesDevicesAndRefreshTokens", checkPurgeExpiredStrict},
		{"PurgeExpired/RemovesRevokedAndExpiredGrantsWithWhatHangsOffThem", checkPurgeExpiredGrants},
		{"PurgeExpired/LeavesLiveRowsAndEveryClientAlone", checkPurgeExpiredKeepsLive},
		{"PurgeExpired/NothingToPurgeReturnsZero", checkPurgeExpiredNothingToDo},
	}
}

// checkPurgeExpiredStrict asserts the cutoff is STRICT on ExpiresAt for
// each of the three expiring kinds: a row expiring an hour before the
// cutoff goes, one expiring exactly at it stays (the Service already
// refuses it; it goes on a later pass), a later one stays. The count is
// exactly three — one per kind — and a second pass finds nothing.
func checkPurgeExpiredStrict(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	cutoff := at
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))

	var codes []oauth.AuthorizationCode
	var devices []oauth.DeviceAuthorization
	var tokens []oauth.RefreshToken
	for _, exp := range []time.Time{cutoff.Add(-time.Hour), cutoff, cutoff.Add(time.Hour)} {
		code := newCode(g, at)
		code.ExpiresAt = exp
		codes = append(codes, mustCreateCode(t, st, code))
		dev := newDevice(c, at)
		dev.ExpiresAt = exp
		devices = append(devices, mustCreateDevice(t, st, dev))
		rt := newRefresh(g, at)
		rt.ExpiresAt = exp
		tokens = append(tokens, mustCreateRefresh(t, st, rt))
	}

	n, err := st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "PurgeExpired", err)
	if n != 3 {
		t.Fatalf("PurgeExpired returned %d, want 3 — one code, one device authorization and one refresh token expired strictly before the cutoff", n)
	}
	for i, label := range []string{"expired", "at the cutoff", "future"} {
		_, _, codeErr := st.RedeemCode(ctx, codes[i].CodeHash, at)
		_, devErr := st.FindDeviceByCodeHash(ctx, devices[i].DeviceCodeHash)
		_, rtErr := st.FindRefreshTokenByHash(ctx, tokens[i].TokenHash)
		if i == 0 {
			if !errors.Is(codeErr, oauth.ErrCodeNotFound) || !errors.Is(devErr, oauth.ErrDeviceNotFound) || !errors.Is(rtErr, oauth.ErrRefreshNotFound) {
				t.Fatalf("an %s row survived PurgeExpired: code=%v device=%v refresh=%v", label, codeErr, devErr, rtErr)
			}
			continue
		}
		if codeErr != nil || devErr != nil || rtErr != nil {
			t.Fatalf("a row %s was purged: code=%v device=%v refresh=%v — the cutoff is strictly before", label, codeErr, devErr, rtErr)
		}
	}
	n, err = st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "second PurgeExpired", err)
	if n != 0 {
		t.Fatalf("second PurgeExpired with the same cutoff returned %d, want 0", n)
	}
}

// checkPurgeExpiredGrants asserts a grant revoked or expired strictly
// before the cutoff is purged together with its codes and refresh tokens —
// even live-looking ones — while a grant revoked exactly at the cutoff
// stays. The count covers every row that went: two grants, their code and
// their refresh token each.
func checkPurgeExpiredGrants(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	cutoff := at
	c := mustCreateClient(t, st, newClient(newID(), at))
	user := newID()

	revoked := newGrant(c, user, at)
	long := cutoff.Add(-time.Hour)
	revoked.RevokedAt = &long
	mustCreateGrant(t, st, revoked)
	expired := newGrant(c, user, at)
	expired.ExpiresAt = &long
	mustCreateGrant(t, st, expired)
	boundary := newGrant(c, user, at)
	boundary.RevokedAt = &cutoff
	mustCreateGrant(t, st, boundary)

	var hanging []oauth.AuthorizationCode
	var hangingRT []oauth.RefreshToken
	for _, g := range []oauth.Grant{revoked, expired} {
		hanging = append(hanging, mustCreateCode(t, st, newCode(g, at)))
		hangingRT = append(hangingRT, mustCreateRefresh(t, st, newRefresh(g, at)))
	}
	keptCode := mustCreateCode(t, st, newCode(boundary, at))

	n, err := st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "PurgeExpired", err)
	if n != 6 {
		t.Fatalf("PurgeExpired returned %d, want 6 — two grants, two codes, two refresh tokens", n)
	}
	for _, g := range []oauth.Grant{revoked, expired} {
		if _, err := st.FindGrant(ctx, g.ID); !errors.Is(err, oauth.ErrGrantNotFound) {
			t.Fatalf("a dead grant survived PurgeExpired: %v", err)
		}
	}
	for i := range hanging {
		if _, _, err := st.RedeemCode(ctx, hanging[i].CodeHash, at); !errors.Is(err, oauth.ErrCodeNotFound) {
			t.Fatalf("a code of a purged grant survived: %v — nothing may name a grant that is gone", err)
		}
		if _, err := st.FindRefreshTokenByHash(ctx, hangingRT[i].TokenHash); !errors.Is(err, oauth.ErrRefreshNotFound) {
			t.Fatalf("a refresh token of a purged grant survived: %v", err)
		}
	}
	if _, err := st.FindGrant(ctx, boundary.ID); err != nil {
		t.Fatalf("the grant revoked exactly at the cutoff was purged: %v", err)
	}
	if _, _, err := st.RedeemCode(ctx, keptCode.CodeHash, at); err != nil {
		t.Fatalf("the surviving grant's code was purged: %v", err)
	}
}

// checkPurgeExpiredKeepsLive asserts a live grant with no expiry, its live
// code, device authorization and refresh token, and every client — even a
// disabled one — survive any cutoff.
func checkPurgeExpiredKeepsLive(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	disabled := newClient(newID(), at)
	long := at.Add(-24 * time.Hour)
	disabled.DisabledAt = &long
	mustCreateClient(t, st, disabled)
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	far := at.Add(1000 * time.Hour)
	code := newCode(g, at)
	code.ExpiresAt = far.Add(time.Hour)
	mustCreateCode(t, st, code)
	dev := newDevice(c, at)
	dev.ExpiresAt = far.Add(time.Hour)
	mustCreateDevice(t, st, dev)
	rt := newRefresh(g, at)
	rt.ExpiresAt = far.Add(time.Hour)
	mustCreateRefresh(t, st, rt)

	n, err := st.PurgeExpired(ctx, far)
	wantNoErr(t, "PurgeExpired", err)
	if n != 0 {
		t.Fatalf("PurgeExpired returned %d, want 0 — nothing here is expired or revoked", n)
	}
	if _, err := st.FindGrant(ctx, g.ID); err != nil {
		t.Fatalf("a live grant with no expiry was purged: %v", err)
	}
	if _, _, err := st.RedeemCode(ctx, code.CodeHash, at); err != nil {
		t.Fatalf("a live code was purged: %v", err)
	}
	if _, err := st.FindDeviceByCodeHash(ctx, dev.DeviceCodeHash); err != nil {
		t.Fatalf("a live device authorization was purged: %v", err)
	}
	if _, err := st.FindRefreshTokenByHash(ctx, rt.TokenHash); err != nil {
		t.Fatalf("a live refresh token was purged: %v", err)
	}
	for _, id := range []string{c.ID, disabled.ID} {
		if _, err := st.FindClient(ctx, id); err != nil {
			t.Fatalf("PurgeExpired removed a client: %v", err)
		}
	}
}

// checkPurgeExpiredNothingToDo asserts an empty store purges zero rows
// without error.
func checkPurgeExpiredNothingToDo(t tb, st oauth.Store) {
	t.Helper()
	n, err := st.PurgeExpired(context.Background(), stamp())
	wantNoErr(t, "PurgeExpired", err)
	if n != 0 {
		t.Fatalf("PurgeExpired on an empty store returned %d, want 0", n)
	}
}
