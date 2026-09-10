package apikeytest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
)

func housekeepingChecks() []check {
	return []check{
		{"PurgeExpired/CutoffIsStrictOnExpiry", checkPurgeExpiredStrictOnExpiry},
		{"PurgeExpired/CutoffIsStrictOnRevocation", checkPurgeExpiredStrictOnRevocation},
		{"PurgeExpired/LeavesLiveKeysAndEveryAccountAlone", checkPurgeExpiredKeepsLiveRows},
		{"PurgeExpired/NothingToPurgeReturnsZero", checkPurgeExpiredNothingToDo},
	}
}

// keyWithExpiry builds a key for sa expiring at the given instant.
func keyWithExpiry(sa apikey.ServiceAccount, at, expires time.Time) apikey.Key {
	k := newKey(sa, at)
	k.ExpiresAt = &expires
	return k
}

// keyRevokedAt builds a key for sa revoked at the given instant.
func keyRevokedAt(sa apikey.ServiceAccount, at, revoked time.Time) apikey.Key {
	k := newKey(sa, at)
	k.RevokedAt = &revoked
	return k
}

// checkPurgeExpiredStrictOnExpiry asserts the cutoff is STRICT on ExpiresAt:
// a key expiring an hour before the cutoff goes, one expiring exactly at the
// cutoff stays ("strictly before", so the boundary survives one more pass —
// Authenticate already refuses it), and a later one stays. The count is
// exactly 1. A second pass with the same cutoff finds nothing.
func checkPurgeExpiredStrictOnExpiry(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	cutoff := at
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	expired := mustCreateKey(t, st, keyWithExpiry(sa, at, cutoff.Add(-time.Hour)))
	boundary := mustCreateKey(t, st, keyWithExpiry(sa, at, cutoff))
	future := mustCreateKey(t, st, keyWithExpiry(sa, at, cutoff.Add(time.Hour)))

	n, err := st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "PurgeExpired", err)
	if n != 1 {
		t.Fatalf("PurgeExpired returned %d, want 1 — one key expired strictly before the cutoff", n)
	}
	if _, err := st.FindKey(ctx, expired.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("the expired key survived PurgeExpired: error = %v, want ErrKeyNotFound", err)
	}
	if _, err := st.FindKey(ctx, boundary.ID); err != nil {
		t.Fatalf("the key expiring exactly at the cutoff was purged: %v — the cutoff is strictly before", err)
	}
	if _, err := st.FindKey(ctx, future.ID); err != nil {
		t.Fatalf("a key expiring after the cutoff was purged: %v", err)
	}
	n, err = st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "second PurgeExpired", err)
	if n != 0 {
		t.Fatalf("second PurgeExpired with the same cutoff returned %d, want 0", n)
	}
}

// checkPurgeExpiredStrictOnRevocation asserts the same strict cutoff applies
// to RevokedAt — a revoked key is purged once its revocation is strictly
// before the cutoff, and a key revoked exactly at it stays.
func checkPurgeExpiredStrictOnRevocation(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	cutoff := at
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	old := mustCreateKey(t, st, keyRevokedAt(sa, at, cutoff.Add(-time.Hour)))
	boundary := mustCreateKey(t, st, keyRevokedAt(sa, at, cutoff))
	recent := mustCreateKey(t, st, keyRevokedAt(sa, at, cutoff.Add(time.Hour)))

	n, err := st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "PurgeExpired", err)
	if n != 1 {
		t.Fatalf("PurgeExpired returned %d, want 1 — one key revoked strictly before the cutoff", n)
	}
	if _, err := st.FindKey(ctx, old.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("the long-revoked key survived PurgeExpired: error = %v, want ErrKeyNotFound — revocation is a purge reason too", err)
	}
	if _, err := st.FindKey(ctx, boundary.ID); err != nil {
		t.Fatalf("the key revoked exactly at the cutoff was purged: %v", err)
	}
	if _, err := st.FindKey(ctx, recent.ID); err != nil {
		t.Fatalf("a key revoked after the cutoff was purged: %v", err)
	}
}

// checkPurgeExpiredKeepsLiveRows asserts a live key with no expiry is never
// purged, at any cutoff, and that accounts — active or disabled, keyed or
// not — are never purged: PurgeExpired is about keys.
func checkPurgeExpiredKeepsLiveRows(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	live := mustCreateKey(t, st, newKey(sa, at))
	mustCreateKey(t, st, keyWithExpiry(sa, at, at.Add(-time.Hour)))
	disabled := mustCreateAccount(t, st, newAccount(newID(), at))
	long := at.Add(-24 * time.Hour)
	wantNoErr(t, "SetServiceAccountDisabled", st.SetServiceAccountDisabled(ctx, disabled.ID, &long, long))

	n, err := st.PurgeExpired(ctx, at.Add(1000*time.Hour))
	wantNoErr(t, "PurgeExpired", err)
	if n != 1 {
		t.Fatalf("PurgeExpired returned %d, want 1 — only the expired key", n)
	}
	if _, err := st.FindKey(ctx, live.ID); err != nil {
		t.Fatalf("a live key with no expiry was purged: %v", err)
	}
	for _, id := range []string{sa.ID, disabled.ID} {
		if _, err := st.FindServiceAccount(ctx, id); err != nil {
			t.Fatalf("PurgeExpired removed an account: %v", err)
		}
	}
}

// checkPurgeExpiredNothingToDo asserts an empty store purges zero rows
// without error.
func checkPurgeExpiredNothingToDo(t tb, st apikey.Store) {
	t.Helper()
	n, err := st.PurgeExpired(context.Background(), stamp())
	wantNoErr(t, "PurgeExpired", err)
	if n != 0 {
		t.Fatalf("PurgeExpired on an empty store returned %d, want 0", n)
	}
}
