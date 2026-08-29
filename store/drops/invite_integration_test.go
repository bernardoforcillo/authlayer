//go:build integration

// Live end-to-end tests for the invite store against a real PostgreSQL. Run
// with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...`
// stays database-free.
package dropsstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/invite"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// newLiveInviteStore opens a connection from AUTHLAYER_TEST_DSN, builds a
// fresh InviteStore, and drops/recreates both tables so each test starts
// from an empty schema. It registers sqlDB.Close() as a cleanup BEFORE the
// table-dropping cleanup: t.Cleanup callbacks run after a test function's
// defers, in LIFO order, so registering Close first means it runs LAST —
// the drop-tables cleanup still has a live connection when it runs. See
// store/drops/integration_test.go's dropAll for the same pattern.
func newLiveInviteStore(t *testing.T) *dropsstore.InviteStore {
	t.Helper()
	dsn := os.Getenv("AUTHLAYER_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUTHLAYER_TEST_DSN to run the drops invite store integration test")
	}

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	db := pg.New(stdlib.New(sqlDB))
	st := dropsstore.NewInviteStore(db)
	ctx := context.Background()

	dropInviteTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropInviteTables(t, db, st) })

	return st
}

// equalEmailInvite compares every field, but time.Time fields via Equal
// rather than ==. PostgreSQL's timestamptz round-trips the same instant but
// not the same time.Time.Location — a session may return it in the server's
// local zone rather than UTC — and Go's == on time.Time compares the struct
// layout (wall, ext, loc) verbatim, so two values naming the same instant in
// different locations are == false even though .Equal reports them equal.
// store/memory never hits this because nothing there crosses the wire.
func equalEmailInvite(a, b invite.EmailInvite) bool {
	return a.ID == b.ID && a.ContainerID == b.ContainerID && a.Email == b.Email &&
		a.RoleKey == b.RoleKey && a.TokenHash == b.TokenHash && a.InvitedBy == b.InvitedBy &&
		a.ExpiresAt.Equal(b.ExpiresAt) && a.CreatedAt.Equal(b.CreatedAt)
}

// equalLink is equalEmailInvite's counterpart for Link, whose two nullable
// timestamp fields need a nil-aware Equal.
func equalLink(a, b invite.Link) bool {
	return a.ID == b.ID && a.ContainerID == b.ContainerID && a.Code == b.Code &&
		a.RoleKey == b.RoleKey && a.CreatedBy == b.CreatedBy &&
		a.MaxUses == b.MaxUses && a.UseCount == b.UseCount &&
		equalTimePtr(a.ExpiresAt, b.ExpiresAt) && equalTimePtr(a.RevokedAt, b.RevokedAt) &&
		a.CreatedAt.Equal(b.CreatedAt)
}

func equalTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func dropInviteTables(t *testing.T, db *pg.DB, st *dropsstore.InviteStore) {
	t.Helper()
	s := st.Schema()
	for _, tbl := range []*pg.Table{s.Links, s.EmailInvites} {
		if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
			t.Fatalf("drop %s: %v", tbl.Name(), err)
		}
	}
}

// TestInviteStoreEmailInviteLifecycleLive exercises CreateEmailInvite,
// FindEmailInvite, FindEmailInviteByTokenHash, ListEmailInvites,
// DeleteEmailInvite and DeleteEmailInvitesFor against a real server —
// mirroring store/memory/invite_test.go's EmailInvite cases, but here also
// proving the (container_id, email) UNIQUE constraint actually lands (see
// [dropsstore.InviteSchema]'s doc for why it is load-bearing).
func TestInviteStoreEmailInviteLifecycleLive(t *testing.T) {
	st := newLiveInviteStore(t)
	ctx := context.Background()

	containerID, otherContainerID := uid.NewV7(), uid.NewV7()
	invitedBy := uid.NewV7()
	// Truncate to microsecond: PostgreSQL's timestamptz has microsecond
	// precision, Go's time.Time has nanosecond, and CreateEmailInvite
	// returns its argument unchanged rather than re-reading the row — only
	// FindEmailInvite round-trips through the wire, so only values compared
	// after a Find need truncating to survive that precision drop.
	now := time.Now().UTC().Truncate(time.Microsecond)

	in := invite.EmailInvite{
		ID: uid.NewV7(), ContainerID: containerID, Email: "bob@example.com",
		RoleKey: "member", TokenHash: "hash-abc", InvitedBy: invitedBy,
		ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}
	created, err := st.CreateEmailInvite(ctx, in)
	if err != nil {
		t.Fatalf("CreateEmailInvite: %v", err)
	}
	if created != in {
		t.Fatalf("CreateEmailInvite returned %+v, want %+v unchanged", created, in)
	}

	got, err := st.FindEmailInvite(ctx, in.ID)
	if err != nil {
		t.Fatalf("FindEmailInvite: %v", err)
	}
	if !equalEmailInvite(got, in) {
		t.Fatalf("FindEmailInvite round-trip = %+v, want %+v", got, in)
	}

	if _, err := st.FindEmailInvite(ctx, uid.NewV7()); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite(unknown) err = %v, want ErrInviteNotFound", err)
	}

	byHash, err := st.FindEmailInviteByTokenHash(ctx, "hash-abc")
	if err != nil {
		t.Fatalf("FindEmailInviteByTokenHash: %v", err)
	}
	if byHash.ID != in.ID {
		t.Fatalf("FindEmailInviteByTokenHash returned id %q, want %q", byHash.ID, in.ID)
	}
	if _, err := st.FindEmailInviteByTokenHash(ctx, "no-such-hash"); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInviteByTokenHash(unknown) err = %v, want ErrInviteNotFound", err)
	}

	// A second invite for the SAME (container, email) must collide on the
	// UNIQUE constraint — proving it actually reached the database, not
	// just the in-memory Table registry.
	dup := invite.EmailInvite{
		ID: uid.NewV7(), ContainerID: containerID, Email: "bob@example.com",
		RoleKey: "member", TokenHash: "hash-dup", InvitedBy: invitedBy,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if _, err := st.CreateEmailInvite(ctx, dup); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate (container,email) CreateEmailInvite err = %v, want pg.ErrUniqueViolation", err)
	}

	// A different invite entirely — different container, different email —
	// reusing the same TokenHash must ALSO collide, on the separate
	// UNIQUE(token_hash) constraint. This proves that constraint lands on
	// its own, independent of (container_id, email): a hash collision (or a
	// token-generation bug) is caught here even when nothing else about the
	// row conflicts.
	sameHash := invite.EmailInvite{
		ID: uid.NewV7(), ContainerID: otherContainerID, Email: "nobody@example.com",
		RoleKey: "member", TokenHash: "hash-abc", InvitedBy: invitedBy,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if _, err := st.CreateEmailInvite(ctx, sameHash); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate token_hash CreateEmailInvite err = %v, want pg.ErrUniqueViolation", err)
	}

	// A different email in the same container, and the same email in a
	// different container, are both unaffected by that constraint — each
	// given its own TokenHash, since token_hash is now unique across the
	// whole table too.
	other := invite.EmailInvite{
		ID: uid.NewV7(), ContainerID: containerID, Email: "carol@example.com",
		RoleKey: "member", TokenHash: "hash-other", InvitedBy: invitedBy, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if _, err := st.CreateEmailInvite(ctx, other); err != nil {
		t.Fatalf("CreateEmailInvite (different email): %v", err)
	}
	elsewhere := invite.EmailInvite{
		ID: uid.NewV7(), ContainerID: otherContainerID, Email: "bob@example.com",
		RoleKey: "member", TokenHash: "hash-elsewhere", InvitedBy: invitedBy, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if _, err := st.CreateEmailInvite(ctx, elsewhere); err != nil {
		t.Fatalf("CreateEmailInvite (different container): %v", err)
	}

	// ListEmailInvites scopes to the container: in + other, not elsewhere.
	list, err := st.ListEmailInvites(ctx, containerID)
	if err != nil {
		t.Fatalf("ListEmailInvites: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListEmailInvites = %d invites, want 2: %+v", len(list), list)
	}

	empty, err := st.ListEmailInvites(ctx, uid.NewV7())
	if err != nil {
		t.Fatalf("ListEmailInvites(unknown container): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListEmailInvites(unknown container) = %d, want 0", len(empty))
	}

	// DeleteEmailInvitesFor removes every row for (containerID, "bob@..."),
	// which today is just `in` (dup never landed), and leaves other/elsewhere.
	if err := st.DeleteEmailInvitesFor(ctx, containerID, "bob@example.com"); err != nil {
		t.Fatalf("DeleteEmailInvitesFor: %v", err)
	}
	if _, err := st.FindEmailInvite(ctx, in.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("in.ID after DeleteEmailInvitesFor err = %v, want ErrInviteNotFound", err)
	}
	if _, err := st.FindEmailInvite(ctx, other.ID); err != nil {
		t.Fatalf("other.ID after DeleteEmailInvitesFor: %v, want it to survive", err)
	}
	if _, err := st.FindEmailInvite(ctx, elsewhere.ID); err != nil {
		t.Fatalf("elsewhere.ID after DeleteEmailInvitesFor: %v, want it to survive", err)
	}

	// A DeleteEmailInvitesFor call matching nothing is not an error.
	if err := st.DeleteEmailInvitesFor(ctx, containerID, "nobody@example.com"); err != nil {
		t.Fatalf("DeleteEmailInvitesFor with no matches: %v", err)
	}

	if err := st.DeleteEmailInvite(ctx, other.ID); err != nil {
		t.Fatalf("DeleteEmailInvite: %v", err)
	}
	if err := st.DeleteEmailInvite(ctx, other.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("second DeleteEmailInvite err = %v, want ErrInviteNotFound", err)
	}
}

// TestInviteStoreLinkLifecycleLive exercises CreateLink, FindLink,
// FindLinkByCode, ListLinks and RevokeLink against a real server, mirroring
// store/memory/invite_test.go's Link cases and proving the UNIQUE(code)
// constraint (see [dropsstore.InviteSchema]) actually lands.
func TestInviteStoreLinkLifecycleLive(t *testing.T) {
	st := newLiveInviteStore(t)
	ctx := context.Background()

	containerID, otherContainerID := uid.NewV7(), uid.NewV7()
	createdBy := uid.NewV7()
	now := time.Now().UTC().Truncate(time.Microsecond)

	l := invite.Link{
		ID: uid.NewV7(), ContainerID: containerID, Code: "code-abc",
		RoleKey: "member", CreatedBy: createdBy, MaxUses: 5, CreatedAt: now,
	}
	created, err := st.CreateLink(ctx, l)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if created != l {
		t.Fatalf("CreateLink returned %+v, want %+v unchanged", created, l)
	}

	got, err := st.FindLink(ctx, l.ID)
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if !equalLink(got, l) {
		t.Fatalf("FindLink round-trip = %+v, want %+v", got, l)
	}
	if got.ExpiresAt != nil || got.RevokedAt != nil {
		t.Fatalf("fresh link has non-nil nullable columns: %+v", got)
	}

	if _, err := st.FindLink(ctx, uid.NewV7()); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("FindLink(unknown) err = %v, want ErrLinkNotFound", err)
	}

	byCode, err := st.FindLinkByCode(ctx, "code-abc")
	if err != nil {
		t.Fatalf("FindLinkByCode: %v", err)
	}
	if byCode.ID != l.ID {
		t.Fatalf("FindLinkByCode returned id %q, want %q", byCode.ID, l.ID)
	}
	if _, err := st.FindLinkByCode(ctx, "no-such-code"); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("FindLinkByCode(unknown) err = %v, want ErrLinkNotFound", err)
	}

	// A second link reusing the same code must collide on UNIQUE(code).
	dup := invite.Link{ID: uid.NewV7(), ContainerID: containerID, Code: "code-abc", CreatedBy: createdBy, CreatedAt: now}
	if _, err := st.CreateLink(ctx, dup); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate-code CreateLink err = %v, want pg.ErrUniqueViolation", err)
	}

	other := invite.Link{ID: uid.NewV7(), ContainerID: containerID, Code: "code-other", CreatedBy: createdBy, CreatedAt: now}
	if _, err := st.CreateLink(ctx, other); err != nil {
		t.Fatalf("CreateLink (other code): %v", err)
	}
	elsewhere := invite.Link{ID: uid.NewV7(), ContainerID: otherContainerID, Code: "code-elsewhere", CreatedBy: createdBy, CreatedAt: now}
	if _, err := st.CreateLink(ctx, elsewhere); err != nil {
		t.Fatalf("CreateLink (other container): %v", err)
	}

	list, err := st.ListLinks(ctx, containerID)
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListLinks = %d links, want 2: %+v", len(list), list)
	}

	empty, err := st.ListLinks(ctx, uid.NewV7())
	if err != nil {
		t.Fatalf("ListLinks(unknown container): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListLinks(unknown container) = %d, want 0", len(empty))
	}

	// RevokeLink stamps RevokedAt and is idempotent (overwrites, not error).
	first := time.Now().UTC().Truncate(time.Microsecond)
	if err := st.RevokeLink(ctx, l.ID, first); err != nil {
		t.Fatalf("RevokeLink: %v", err)
	}
	revoked, err := st.FindLink(ctx, l.ID)
	if err != nil {
		t.Fatalf("FindLink after revoke: %v", err)
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(first) {
		t.Fatalf("RevokedAt = %v, want %v", revoked.RevokedAt, first)
	}
	second := first.Add(time.Hour)
	if err := st.RevokeLink(ctx, l.ID, second); err != nil {
		t.Fatalf("second RevokeLink: %v", err)
	}
	revoked, err = st.FindLink(ctx, l.ID)
	if err != nil {
		t.Fatalf("FindLink after second revoke: %v", err)
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(second) {
		t.Fatalf("RevokedAt = %v, want the overwritten %v", revoked.RevokedAt, second)
	}

	if err := st.RevokeLink(ctx, uid.NewV7(), time.Now()); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("RevokeLink(unknown) err = %v, want ErrLinkNotFound", err)
	}
}

// TestConsumeLinkBoundariesLive pins invite.Store.ConsumeLink's documented
// boundaries against a real server — the MaxUses edge, revocation, the two
// expiry directions, and the now == ExpiresAt instant itself — mirroring
// store/memory/invite_test.go's ConsumeLink cases. This is the confirmation
// the task brief asks for: store/memory rejects the boundary via
// !now.Before(*ExpiresAt), and the SQL's "expires_at > $2" rejects equality
// the same way — both sides land on "expired", proven here against
// PostgreSQL's own comparison semantics rather than assumed.
func TestConsumeLinkBoundariesLive(t *testing.T) {
	st := newLiveInviteStore(t)
	ctx := context.Background()
	containerID, createdBy := uid.NewV7(), uid.NewV7()

	mustCreate := func(l invite.Link) invite.Link {
		t.Helper()
		l.ContainerID, l.CreatedBy = containerID, createdBy
		l.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
		created, err := st.CreateLink(ctx, l)
		if err != nil {
			t.Fatalf("CreateLink: %v", err)
		}
		return created
	}

	t.Run("NotFound", func(t *testing.T) {
		ok, err := st.ConsumeLink(ctx, uid.NewV7(), time.Now())
		if ok {
			t.Fatal("ConsumeLink ok = true for a nonexistent link")
		}
		if !errors.Is(err, invite.ErrLinkNotFound) {
			t.Fatalf("ConsumeLink(unknown id) err = %v, want ErrLinkNotFound", err)
		}
	})

	t.Run("MaxUsesBoundary", func(t *testing.T) {
		l := mustCreate(invite.Link{ID: uid.NewV7(), Code: "boundary-maxuses", MaxUses: 2})
		ok, err := st.ConsumeLink(ctx, l.ID, time.Now()) // 0 -> 1
		if err != nil || !ok {
			t.Fatalf("first ConsumeLink: ok=%v err=%v, want ok=true", ok, err)
		}
		ok, err = st.ConsumeLink(ctx, l.ID, time.Now()) // 1 -> 2, must still succeed
		if err != nil || !ok {
			t.Fatalf("second ConsumeLink: ok=%v err=%v, want ok=true", ok, err)
		}
		ok, err = st.ConsumeLink(ctx, l.ID, time.Now()) // == MaxUses, must fail
		if err != nil {
			t.Fatalf("third ConsumeLink err = %v, want nil", err)
		}
		if ok {
			t.Fatal("third ConsumeLink ok = true at UseCount == MaxUses, want false")
		}
		got, err := st.FindLink(ctx, l.ID)
		if err != nil {
			t.Fatalf("FindLink: %v", err)
		}
		if got.UseCount != 2 {
			t.Fatalf("UseCount = %d, want 2 (the third call must not have incremented it)", got.UseCount)
		}
	})

	t.Run("MaxUsesZeroIsUnlimited", func(t *testing.T) {
		l := mustCreate(invite.Link{ID: uid.NewV7(), Code: "boundary-unlimited", MaxUses: 0})
		for i := 0; i < 10; i++ {
			ok, err := st.ConsumeLink(ctx, l.ID, time.Now())
			if err != nil || !ok {
				t.Fatalf("ConsumeLink #%d: ok=%v err=%v, want ok=true", i, ok, err)
			}
		}
		got, err := st.FindLink(ctx, l.ID)
		if err != nil {
			t.Fatalf("FindLink: %v", err)
		}
		if got.UseCount != 10 {
			t.Fatalf("UseCount = %d, want 10", got.UseCount)
		}
	})

	t.Run("RevokedFails", func(t *testing.T) {
		l := mustCreate(invite.Link{ID: uid.NewV7(), Code: "boundary-revoked", MaxUses: 5})
		if err := st.RevokeLink(ctx, l.ID, time.Now()); err != nil {
			t.Fatalf("RevokeLink: %v", err)
		}
		ok, err := st.ConsumeLink(ctx, l.ID, time.Now())
		if err != nil {
			t.Fatalf("ConsumeLink err = %v, want nil", err)
		}
		if ok {
			t.Fatal("ConsumeLink ok = true for a revoked link")
		}
	})

	t.Run("ExpiredInThePastFails", func(t *testing.T) {
		past := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		l := mustCreate(invite.Link{ID: uid.NewV7(), Code: "boundary-past", MaxUses: 5, ExpiresAt: &past})
		ok, err := st.ConsumeLink(ctx, l.ID, time.Now())
		if err != nil {
			t.Fatalf("ConsumeLink err = %v, want nil", err)
		}
		if ok {
			t.Fatal("ConsumeLink ok = true for a link expired in the past")
		}
	})

	// The boundary the task brief asks to confirm rather than assume: SQL's
	// "expires_at > $2" rejects now == ExpiresAt exactly, matching
	// store/memory's !now.Before(*ExpiresAt) convention.
	t.Run("NowEqualToExpiresAtIsExpired", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Microsecond)
		l := mustCreate(invite.Link{ID: uid.NewV7(), Code: "boundary-equal", MaxUses: 5, ExpiresAt: &at})
		ok, err := st.ConsumeLink(ctx, l.ID, at)
		if err != nil {
			t.Fatalf("ConsumeLink err = %v, want nil", err)
		}
		if ok {
			t.Fatal("ConsumeLink ok = true when now == ExpiresAt exactly, want false: PostgreSQL's expires_at > $2 must reject equality, matching store/memory")
		}
	})

	t.Run("UnexpiredSucceeds", func(t *testing.T) {
		future := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
		l := mustCreate(invite.Link{ID: uid.NewV7(), Code: "boundary-future", MaxUses: 5, ExpiresAt: &future})
		ok, err := st.ConsumeLink(ctx, l.ID, time.Now())
		if err != nil {
			t.Fatalf("ConsumeLink: %v", err)
		}
		if !ok {
			t.Fatal("ConsumeLink ok = false for a link that has not expired yet")
		}
	})

	t.Run("NilExpiresAtNeverExpires", func(t *testing.T) {
		l := mustCreate(invite.Link{ID: uid.NewV7(), Code: "boundary-never", MaxUses: 5, ExpiresAt: nil})
		ok, err := st.ConsumeLink(ctx, l.ID, time.Now().Add(100*365*24*time.Hour))
		if err != nil {
			t.Fatalf("ConsumeLink: %v", err)
		}
		if !ok {
			t.Fatal("ConsumeLink ok = false for a link with nil ExpiresAt")
		}
	})
}

// TestPurgeExpiredLive mirrors store/memory/invite_test.go's PurgeExpired
// case against a real server: it removes rows expired strictly before the
// cutoff on both tables, sums the count across both, and leaves a
// never-expiring link (nil ExpiresAt) untouched.
func TestPurgeExpiredLive(t *testing.T) {
	st := newLiveInviteStore(t)
	ctx := context.Background()
	containerID, invitedBy := uid.NewV7(), uid.NewV7()

	now := time.Now().UTC().Truncate(time.Microsecond)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// Distinct TokenHash values: the two invites would otherwise both carry
	// the zero value "" and collide on the UNIQUE(token_hash) constraint.
	inv1 := invite.EmailInvite{ID: uid.NewV7(), ContainerID: containerID, Email: "a@x.com", TokenHash: "purge-hash-1", InvitedBy: invitedBy, ExpiresAt: past, CreatedAt: now}
	inv2 := invite.EmailInvite{ID: uid.NewV7(), ContainerID: containerID, Email: "b@x.com", TokenHash: "purge-hash-2", InvitedBy: invitedBy, ExpiresAt: future, CreatedAt: now}
	for _, in := range []invite.EmailInvite{inv1, inv2} {
		if _, err := st.CreateEmailInvite(ctx, in); err != nil {
			t.Fatalf("CreateEmailInvite %s: %v", in.ID, err)
		}
	}

	link1 := invite.Link{ID: uid.NewV7(), ContainerID: containerID, Code: "purge-past", CreatedBy: invitedBy, ExpiresAt: &past, CreatedAt: now}
	link2 := invite.Link{ID: uid.NewV7(), ContainerID: containerID, Code: "purge-future", CreatedBy: invitedBy, ExpiresAt: &future, CreatedAt: now}
	link3 := invite.Link{ID: uid.NewV7(), ContainerID: containerID, Code: "purge-never", CreatedBy: invitedBy, ExpiresAt: nil, CreatedAt: now}
	for _, l := range []invite.Link{link1, link2, link3} {
		if _, err := st.CreateLink(ctx, l); err != nil {
			t.Fatalf("CreateLink %s: %v", l.ID, err)
		}
	}

	n, err := st.PurgeExpired(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 2 {
		t.Fatalf("PurgeExpired removed %d rows, want 2 (inv1, link1)", n)
	}

	if _, err := st.FindEmailInvite(ctx, inv1.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("inv1 err = %v, want ErrInviteNotFound (should be purged)", err)
	}
	if _, err := st.FindEmailInvite(ctx, inv2.ID); err != nil {
		t.Fatalf("inv2 err = %v, want it to survive", err)
	}
	if _, err := st.FindLink(ctx, link1.ID); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("link1 err = %v, want ErrLinkNotFound (should be purged)", err)
	}
	if _, err := st.FindLink(ctx, link2.ID); err != nil {
		t.Fatalf("link2 err = %v, want it to survive", err)
	}
	if _, err := st.FindLink(ctx, link3.ID); err != nil {
		t.Fatalf("link3 (never expires) err = %v, want it to survive", err)
	}
}

// TestConsumeLinkConcurrencyExactlyOneWinnerLive is the live counterpart to
// store/memory's TestConsumeLinkConcurrencyExactlyOneWinner. A fake driver
// cannot prove atomicity — it has no lock contention or wire round trips to
// interleave — so this is the test that actually exercises PostgreSQL's row
// lock: N goroutines race ConsumeLink against one MaxUses:1 link, and the
// UPDATE ... WHERE's row-affected count must admit exactly one of them.
func TestConsumeLinkConcurrencyExactlyOneWinnerLive(t *testing.T) {
	st := newLiveInviteStore(t)
	ctx := context.Background()

	l, err := st.CreateLink(ctx, invite.Link{
		ID: uid.NewV7(), ContainerID: uid.NewV7(), Code: "race-code",
		CreatedBy: uid.NewV7(), MaxUses: 1, CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	const n = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, errs := 0, 0

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			ok, err := st.ConsumeLink(ctx, l.ID, time.Now())
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			if ok {
				successes++
			}
		}()
	}
	close(start)
	wg.Wait()

	if errs != 0 {
		t.Fatalf("got %d unexpected errors from ConsumeLink", errs)
	}
	if successes != 1 {
		t.Fatalf("got %d successful ConsumeLink calls against a MaxUses:1 link, want exactly 1", successes)
	}

	got, err := st.FindLink(ctx, l.ID)
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.UseCount != 1 {
		t.Fatalf("final UseCount = %d, want 1", got.UseCount)
	}
}

// TestDeleteEmailInviteConcurrencyExactlyOneWinnerLive is the email claim's
// counterpart to TestConsumeLinkConcurrencyExactlyOneWinnerLive above, and
// exists because DeleteEmailInvite was promoted to a load-bearing atomic
// claim: invite.Service.AcceptInvite now deletes the invitation FIRST and
// grants membership SECOND, so this rows-affected gate is the only thing
// standing between a token presented twice and two admissions. The
// sequential case (second delete -> ErrInviteNotFound) was already covered
// in TestInviteStoreEmailInviteLifecycleLive; sequential coverage cannot
// distinguish "at most one caller wins" from "the second read happened to
// come after the first commit". The unit tests cannot either — a fake
// driver has no row locks or wire round trips to interleave.
//
// So: N goroutines race DeleteEmailInvite against one invitation row.
// Exactly one must see a nil error; every loser must see
// invite.ErrInviteNotFound and nothing else. Under PostgreSQL's default READ
// COMMITTED, the losers block on the winner's row lock and re-evaluate the
// predicate after it commits, finding no row and reporting 0 affected.
func TestDeleteEmailInviteConcurrencyExactlyOneWinnerLive(t *testing.T) {
	st := newLiveInviteStore(t)
	ctx := context.Background()

	inv, err := st.CreateEmailInvite(ctx, invite.EmailInvite{
		ID: uid.NewV7(), ContainerID: uid.NewV7(), Email: "race@example.com",
		RoleKey: "member", TokenHash: "race-token-hash", InvitedBy: uid.NewV7(),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		t.Fatalf("CreateEmailInvite: %v", err)
	}

	const n = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, notFound := 0, 0
	var others []error

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			err := st.DeleteEmailInvite(ctx, inv.ID)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, invite.ErrInviteNotFound):
				notFound++
			default:
				others = append(others, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(others) != 0 {
		t.Fatalf("got %d unexpected errors from DeleteEmailInvite, first = %v", len(others), others[0])
	}
	if successes != 1 {
		t.Fatalf("got %d successful DeleteEmailInvite calls against one invitation, want exactly 1 — the claim is not atomic", successes)
	}
	if notFound != n-1 {
		t.Fatalf("got %d ErrInviteNotFound, want %d — every loser must be refused", notFound, n-1)
	}

	if _, err := st.FindEmailInvite(ctx, inv.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite after the race: err = %v, want ErrInviteNotFound — the row must be gone", err)
	}
}

// TestInviteStoreCreateSchemaLandsConstraintsOnRealPostgres is the invite
// counterpart to store/drops/schema_integration_test.go's
// TestCreateSchemaLandsConstraintsOnRealPostgres: it proves all three UNIQUE
// constraints (container_id+email, token_hash, code) actually reach the
// database via CreateSchema's ALTER TABLE statements, by reading them back
// out of pg_constraint, rather than inferring their existence indirectly
// from a duplicate-insert error. Also re-runs CreateSchema to confirm it
// stays idempotent against a real server.
func TestInviteStoreCreateSchemaLandsConstraintsOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("AUTHLAYER_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUTHLAYER_TEST_DSN to run the drops invite store integration test")
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	db := pg.New(stdlib.New(sqlDB))
	st := dropsstore.NewInviteStore(db)
	ctx := context.Background()

	for _, tbl := range []string{"organization_invite_links", "organization_invites"} {
		if _, err := sqlDB.ExecContext(ctx, "DROP TABLE IF EXISTS "+tbl+" CASCADE"); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	// Re-run: CreateSchema must stay idempotent on a real server.
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (second run): %v", err)
	}
	t.Cleanup(func() {
		for _, tbl := range []string{"organization_invite_links", "organization_invites"} {
			_, _ = sqlDB.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+tbl+" CASCADE")
		}
	})

	rows, err := sqlDB.QueryContext(ctx, `
		SELECT c.conname, c.contype, pg_get_constraintdef(c.oid)
		FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname IN ('organization_invites','organization_invite_links')
		ORDER BY t.relname, c.conname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]string{}
	for rows.Next() {
		var name, typ, def string
		if err := rows.Scan(&name, &typ, &def); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-42s %s  %s", name, typ, def)
		found[name] = def
	}

	for _, want := range []struct{ name, def string }{
		{"organization_invites_container_email", "UNIQUE (container_id, email)"},
		{"organization_invites_token_hash", "UNIQUE (token_hash)"},
		{"organization_invite_links_code", "UNIQUE (code)"},
	} {
		def, ok := found[want.name]
		if !ok {
			t.Errorf("MISSING: %s on the invite tables", want.name)
			continue
		}
		if def != want.def {
			t.Errorf("%s definition = %q, want %q", want.name, def, want.def)
		}
	}
}
