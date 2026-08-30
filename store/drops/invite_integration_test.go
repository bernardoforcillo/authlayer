//go:build integration

// Live end-to-end tests for the invite store against a real PostgreSQL. Run
// with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...`
// stays database-free.
//
// The invite.Store contract itself is no longer reimplemented here.
// TestInviteStoreSatisfiesTheStoreContractLive below runs the exported
// authlayer/invite/invitetest suite — the same checks store/memory runs,
// driven against a live server. That suite exists because the previous
// arrangement could not be shared: every property lived in a _test.go file in
// package memory_test, and Go test files are never part of a package's
// importable surface regardless of export, so this file had to carry an
// independent implementation of the same lifecycle, boundary, purge and
// single-winner tests. Six of them are gone; what remains here is what stays
// BACKEND-SPECIFIC — the DDL the suite cannot see, and the error class
// PostgreSQL answers a rejected duplicate with, which the port deliberately
// leaves unclassified.
package dropsstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/invite"
	"github.com/bernardoforcillo/authlayer/invite/invitetest"
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

func dropInviteTables(t *testing.T, db *pg.DB, st *dropsstore.InviteStore) {
	t.Helper()
	s := st.Schema()
	for _, tbl := range []*pg.Table{s.Links, s.EmailInvites} {
		if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
			t.Fatalf("drop %s: %v", tbl.Name(), err)
		}
	}
}

// TestInviteStoreSatisfiesTheStoreContractLive runs the exported
// authlayer/invite/invitetest suite against a real server: every documented
// obligation of invite.Store, including the ConsumeLink single-winner race
// and the DeleteEmailInvite claim this file used to reimplement, and the
// three uniqueness constraints this backend has always enforced and
// store/memory now does too, and the address normalization neither of them
// did before.
//
// A fake driver has no lock contention or wire round trips to interleave, so
// it cannot demonstrate atomicity; only a real server's row lock can. That is
// why the suite is run here as well as against store/memory, and it is why
// this test warms the pool ([warmPool]) before anything runs: the pool is
// pre-warmed to invitetest.RaceGoroutines connections before any race starts,
// rather than left to grow on demand. That warming is load-bearing and was
// measured on the auth side of this repository — against an UNWARMED pool a
// deliberately broken read-then-write was caught only ~40-70% of the time,
// because opening a fresh connection is slow and uneven, so goroutines
// trickle into the contended statement across a window far wider than the
// race itself. Pre-warming closed that gap to 10/10.
//
// The suite calls the factory once per check and requires the store it gets
// back to be EMPTY: several checks assert counts over the whole table (a
// ListEmailInvites length, PurgeExpired's total across both kinds), which
// mean nothing against leftover rows. TRUNCATE, not a drop-and-recreate, is
// what gives them that here.
func TestInviteStoreSatisfiesTheStoreContractLive(t *testing.T) {
	// One pool and one schema, prepared once and shared by every check — not
	// a fresh, separately warmed pool and a drop-and-recreate per check. The
	// suite calls the factory around forty times, and both of those cost real
	// time against a live server for no added isolation: what a check needs
	// isolated is the DATA. TRUNCATE gives it that, and the pool being warm is
	// what makes the races in the suite actually contend rather than trickle.
	sqlDB, db := openLiveDB(t)
	sqlDB.SetMaxOpenConns(invitetest.RaceGoroutines)
	sqlDB.SetMaxIdleConns(invitetest.RaceGoroutines)
	warmPool(t, sqlDB, invitetest.RaceGoroutines)

	st := dropsstore.NewInviteStore(db)
	ctx := context.Background()
	dropInviteTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropInviteTables(t, db, st) })

	s := st.Schema()
	truncate := fmt.Sprintf("TRUNCATE %s, %s", s.EmailInvites.Name(), s.Links.Name())
	newStore := func(t *testing.T) invite.Store {
		if _, err := sqlDB.ExecContext(ctx, truncate); err != nil {
			t.Fatalf("%s: %v", truncate, err)
		}
		return st
	}
	invitetest.RunStoreContract(t, newStore)
}

// TestInviteStoreDuplicatesSurfaceAsUniqueViolationsLive covers the one thing
// the port-level suite deliberately does not: WHICH error a rejected
// duplicate comes back as.
//
// invite.Store classifies no conflict-on-create at all, so invitetest asserts
// only that each of the three colliding writes FAILED and left the original
// row alone. This backend's answer is the driver's own pg.ErrUniqueViolation,
// unwrapped — no sentinel is invented for it — and a caller that branches on
// it is entitled to keep working. Each case is built so exactly ONE
// constraint can fire: the token-hash clash is in another container for
// another address, the pair clash carries its own hash, and the code clash is
// in another container.
func TestInviteStoreDuplicatesSurfaceAsUniqueViolationsLive(t *testing.T) {
	st := newLiveInviteStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	containerID, otherContainerID := uid.NewV7(), uid.NewV7()
	invitedBy := uid.NewV7()

	mkInvite := func(container, email, hash string) invite.EmailInvite {
		return invite.EmailInvite{
			ID: uid.NewV7(), ContainerID: container, Email: email,
			RoleKey: "member", TokenHash: hash, InvitedBy: invitedBy,
			ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
		}
	}
	first := mkInvite(containerID, "bob@example.com", "hash-abc")
	if _, err := st.CreateEmailInvite(ctx, first); err != nil {
		t.Fatalf("CreateEmailInvite(first): %v", err)
	}

	// UNIQUE (container_id, email): a second pending invite for the same
	// address in the same container, carrying its own token hash.
	if _, err := st.CreateEmailInvite(ctx, mkInvite(containerID, "bob@example.com", "hash-dup")); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate (container,email) CreateEmailInvite err = %v, want pg.ErrUniqueViolation", err)
	}

	// UNIQUE (token_hash): a wholly unrelated invite reusing the hash. This
	// proves that constraint lands on its own, independent of the pair.
	if _, err := st.CreateEmailInvite(ctx, mkInvite(otherContainerID, "nobody@example.com", "hash-abc")); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate token_hash CreateEmailInvite err = %v, want pg.ErrUniqueViolation", err)
	}

	// The two legitimate neighbours the constraints must NOT refuse: another
	// address in the same container, and the same address in another one.
	if _, err := st.CreateEmailInvite(ctx, mkInvite(containerID, "carol@example.com", "hash-other")); err != nil {
		t.Fatalf("CreateEmailInvite (different address, same container): %v", err)
	}
	if _, err := st.CreateEmailInvite(ctx, mkInvite(otherContainerID, "bob@example.com", "hash-elsewhere")); err != nil {
		t.Fatalf("CreateEmailInvite (same address, different container): %v", err)
	}

	// UNIQUE (code).
	l := invite.Link{
		ID: uid.NewV7(), ContainerID: containerID, Code: "code-abc",
		RoleKey: "member", CreatedBy: invitedBy, CreatedAt: now,
	}
	if _, err := st.CreateLink(ctx, l); err != nil {
		t.Fatalf("CreateLink(first): %v", err)
	}
	dup := invite.Link{
		ID: uid.NewV7(), ContainerID: otherContainerID, Code: "code-abc",
		RoleKey: "member", CreatedBy: invitedBy, CreatedAt: now,
	}
	if _, err := st.CreateLink(ctx, dup); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate-code CreateLink err = %v, want pg.ErrUniqueViolation", err)
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
