package invitetest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
)

func housekeepingChecks() []check {
	return []check{
		{"PurgeExpired/CutoffIsStrictAcrossBothKinds", checkPurgeExpiredStrictCutoff},
		{"PurgeExpired/NeverPurgesALinkWithNoExpiry", checkPurgeExpiredKeepsNeverExpiringLinks},
		{"PurgeExpired/LeavesARevokedButUnexpiredLinkAlone", checkPurgeExpiredKeepsRevokedLinks},
		{"PurgeExpired/NothingToPurgeReturnsZero", checkPurgeExpiredNothingToDo},
	}
}

// checkPurgeExpiredStrictCutoff asserts the cutoff is STRICT and applies to
// both kinds at once: an email invite and a link expiring an hour before the
// cutoff go, one of each whose ExpiresAt is exactly the cutoff stays
// ("strictly before", so the boundary survives one more pass), and later ones
// stay. The returned count is the total across both kinds, so it must be
// exactly 2 — a store that counts only the invites it deleted, or only the
// links, reports 1.
//
// It then re-runs the same cutoff and requires 0: purging is not supposed to
// keep finding work that is already done.
func checkPurgeExpiredStrictCutoff(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	cutoff := at
	containerID := newID()

	mk := func(offset time.Duration) (invite.EmailInvite, invite.Link) {
		inv := newInvite(containerID, newEmail(), at)
		inv.ExpiresAt = cutoff.Add(offset)
		l := newLink(containerID, at)
		expires := cutoff.Add(offset)
		l.ExpiresAt = &expires
		return mustCreateEmailInvite(t, st, inv), mustCreateLink(t, st, l)
	}
	expiredInvite, expiredLink := mk(-time.Hour)
	boundaryInvite, boundaryLink := mk(0)
	futureInvite, futureLink := mk(time.Hour)

	n, err := st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "PurgeExpired", err)
	if n != 2 {
		t.Fatalf("PurgeExpired returned %d, want 2 — one email invite and one link expired strictly before the cutoff, counted together across both kinds", n)
	}

	if _, err := st.FindEmailInvite(ctx, expiredInvite.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("the expired email invite survived PurgeExpired: error = %v, want ErrInviteNotFound", err)
	}
	if _, err := st.FindLink(ctx, expiredLink.ID); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("the expired link survived PurgeExpired: error = %v, want ErrLinkNotFound", err)
	}

	for _, inv := range []invite.EmailInvite{boundaryInvite, futureInvite} {
		if _, err := st.FindEmailInvite(ctx, inv.ID); err != nil {
			t.Fatalf("email invite expiring at %v was purged by a cutoff of %v: error = %v — the cutoff is strictly before", inv.ExpiresAt, cutoff, err)
		}
	}
	for _, l := range []invite.Link{boundaryLink, futureLink} {
		if _, err := st.FindLink(ctx, l.ID); err != nil {
			t.Fatalf("link expiring at %v was purged by a cutoff of %v: error = %v — the cutoff is strictly before", *l.ExpiresAt, cutoff, err)
		}
	}

	again, err := st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "PurgeExpired (same cutoff, second call)", err)
	if again != 0 {
		t.Fatalf("a second PurgeExpired at the same cutoff returned %d, want 0 — the rows it would remove are already gone", again)
	}
}

// checkPurgeExpiredKeepsNeverExpiringLinks asserts the port's "a link with a
// nil ExpiresAt ('never') is never purged by this call", however far in the
// future the cutoff is. The nil is a real, common case — a link minted
// without a deadline — and a store that reads it as a zero time sweeps every
// such link on the first housekeeping pass.
func checkPurgeExpiredKeepsNeverExpiringLinks(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	forever := mustCreateLink(t, st, newLink(newID(), at))

	n, err := st.PurgeExpired(ctx, at.Add(100*365*24*time.Hour))
	wantNoErr(t, "PurgeExpired", err)
	if n != 0 {
		t.Fatalf("PurgeExpired removed %d row(s) with only a never-expiring link in the store, want 0", n)
	}
	if _, err := st.FindLink(ctx, forever.ID); err != nil {
		t.Fatalf("FindLink(a link with nil ExpiresAt) after PurgeExpired: error = %v, want nil — nil means never, and never is not purged", err)
	}
}

// checkPurgeExpiredKeepsRevokedLinks asserts the port's "a
// revoked-but-unexpired link is left alone — revocation and expiry are
// different reasons and this method only acts on the latter".
//
// The distinction is not cosmetic: a revoked link is the audit record of a
// deliberate act, and a store that quietly folds revocation into expiry
// deletes the evidence that someone revoked it.
func checkPurgeExpiredKeepsRevokedLinks(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := newLink(newID(), at)
	expires := at.Add(24 * time.Hour)
	l.ExpiresAt = &expires
	l = mustCreateLink(t, st, l)
	wantNoErr(t, "RevokeLink (fixture)", st.RevokeLink(ctx, l.ID, at))

	n, err := st.PurgeExpired(ctx, at)
	wantNoErr(t, "PurgeExpired", err)
	if n != 0 {
		t.Fatalf("PurgeExpired removed %d row(s) with only a revoked but unexpired link in the store, want 0", n)
	}

	got, ferr := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink(a revoked but unexpired link) after PurgeExpired", ferr)
	if got.RevokedAt == nil {
		t.Fatalf("the surviving link came back with RevokedAt = nil, want the revocation intact")
	}
}

// checkPurgeExpiredNothingToDo asserts a cutoff nothing has passed removes
// nothing and reports 0, across every shape the store holds: a future email
// invite, a future link, a never-expiring link, and a revoked-but-unexpired
// one.
func checkPurgeExpiredNothingToDo(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()

	inv := newInvite(containerID, newEmail(), at)
	inv.ExpiresAt = at.Add(24 * time.Hour)
	inv = mustCreateEmailInvite(t, st, inv)

	future := newLink(containerID, at)
	expires := at.Add(24 * time.Hour)
	future.ExpiresAt = &expires
	future = mustCreateLink(t, st, future)

	forever := mustCreateLink(t, st, newLink(containerID, at))

	revoked := newLink(containerID, at)
	revokedExpires := at.Add(24 * time.Hour)
	revoked.ExpiresAt = &revokedExpires
	revoked = mustCreateLink(t, st, revoked)
	wantNoErr(t, "RevokeLink (fixture)", st.RevokeLink(ctx, revoked.ID, at))

	n, err := st.PurgeExpired(ctx, at)
	wantNoErr(t, "PurgeExpired", err)
	if n != 0 {
		t.Fatalf("PurgeExpired returned %d with nothing expired before the cutoff, want 0", n)
	}

	if _, err := st.FindEmailInvite(ctx, inv.ID); err != nil {
		t.Fatalf("FindEmailInvite after a no-op PurgeExpired: error = %v, want nil", err)
	}
	links, err := st.ListLinks(ctx, containerID)
	wantNoErr(t, "ListLinks after a no-op PurgeExpired", err)
	wantSameIDs(t, "ListLinks after a no-op PurgeExpired", linkIDs(links), []string{future.ID, forever.ID, revoked.ID})
}
