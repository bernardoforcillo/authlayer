//go:build integration

// Live end-to-end tests for the identity store against a real PostgreSQL.
// Run with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...`
// stays database-free.
//
// # Why this file exists at all
//
// store/drops/identity_test.go is a UNIT suite over a fake driver. It can
// prove that NewIdentitySchema called AddUnique and AddIndex, and that
// CreateSchema rendered the statements it was supposed to render. It cannot
// prove any of the four things this backend actually promises, because every
// one of them is a property of a SERVER rather than of a builder:
//
//  1. UNIQUE (provider, subject) is really ON the table, and CreateSchema is
//     really idempotent — TestIdentityStoreCreateSchemaLandsConstraintsOnRealPostgres
//     and TestIdentityStoreDuplicateLinkIsRefusedLive.
//  2. last_used_at is really NULLABLE and really round-trips nil —
//     TestIdentityStoreLastUsedAtRoundTripsNullThenValueLive.
//  3. The planner really PICKS the user_id index —
//     TestIdentityStoreListIdentitiesByUserUsesTheIndexLive.
//  4. DeleteIdentityIfNotLast is really atomic —
//     TestDeleteIdentityIfNotLastIsAtomicUnderConcurrencyLive and
//     TestDeleteIdentityIfNotLastSerializesAgainstAConcurrentSiblingUnlinkLive.
//
// This project has already shipped a Critical by treating a `go vet -tags
// integration` pass as evidence about a database-shaped change; a suite that
// asserts a method was CALLED is the same mistake wearing test clothes.
package dropsstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// newLiveIdentityStore builds an IdentityStore over AUTHLAYER_TEST_DSN and
// drops/recreates the identities table so each test starts from an empty
// schema. It returns the raw *sql.DB too, since every test here needs it
// directly — reading pg_constraint, EXPLAINing, or staging a second session.
//
// Cleanup ordering follows [openLiveDB]'s own doc: Close is registered there
// FIRST so it runs LAST, leaving the drop-table cleanup registered here a
// live connection to work with.
func newLiveIdentityStore(t *testing.T) (*sql.DB, *dropsstore.IdentityStore) {
	t.Helper()
	sqlDB, db := openLiveDB(t)
	st := dropsstore.NewIdentityStore(db)

	dropIdentityTable(t, db, st)
	if err := st.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropIdentityTable(t, db, st) })
	return sqlDB, st
}

func dropIdentityTable(t *testing.T, db *pg.DB, st *dropsstore.IdentityStore) {
	t.Helper()
	tbl := st.Schema().Identities
	if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
		t.Fatalf("drop %s: %v", tbl.Name(), err)
	}
}

// liveIdentity builds a well-formed identity for userID at provider with the
// given subject, with LastUsedAt nil — the state every freshly linked row is
// in, and the one that only a real server can prove is representable.
func liveIdentity(userID, provider, subject string) auth.Identity {
	return auth.Identity{
		ID:        uid.NewV7(),
		UserID:    userID,
		Provider:  provider,
		Subject:   subject,
		Email:     "live-" + subject + "@example.com",
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
}

// ── 1. the schema, on a real server ─────────────────────────────────────────

// TestIdentityStoreCreateSchemaLandsConstraintsOnRealPostgres proves the
// UNIQUE (provider, subject) constraint registered by NewIdentitySchema
// actually REACHES the database, by reading it back out of pg_constraint —
// rather than inferring it from a builder call the unit suite can see. The
// constraint is composite, so CREATE TABLE cannot carry it; it exists only
// because CreateSchema emits a guarded ALTER TABLE, and that emission is
// exactly the step a fake driver cannot evaluate.
//
// It also pins, on the same server:
//
//   - the user_id INDEX, which is not a constraint and so does not appear in
//     pg_constraint at all — read from pg_indexes instead;
//   - last_used_at being NULLABLE and every other column not being, from
//     information_schema, since a NOT NULL there would fail every
//     LinkIdentity (a link made with no sign-in behind it);
//   - both id columns landing as uuid, the default authlayer's UUIDv7
//     generator requires;
//   - CreateSchema staying IDEMPOTENT across two runs, which is the whole
//     point of the plpgsql guard around the ALTER TABLE — an unguarded one
//     fails the second run with 42710 and takes the whole call with it;
//   - CreateSchema SELF-HEALING a table whose constraint was dropped, the
//     property that makes it safe to re-run against an existing deployment.
//
// Mirrors schema_integration_test.go's
// TestCreateSchemaLandsConstraintsOnRealPostgres, auth's
// TestAuthStoreCreateSchemaLandsConstraintsOnRealPostgres and invite's
// TestInviteStoreCreateSchemaLandsConstraintsOnRealPostgres.
func TestIdentityStoreCreateSchemaLandsConstraintsOnRealPostgres(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	st := dropsstore.NewIdentityStore(db)
	ctx := context.Background()
	table := st.Schema().Identities.Name()

	if _, err := sqlDB.ExecContext(ctx, "DROP TABLE IF EXISTS "+table+" CASCADE"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	// Re-run: CreateSchema must stay idempotent on a real server. The
	// guarded ALTER TABLE is the statement at risk — PostgreSQL has no ADD
	// CONSTRAINT IF NOT EXISTS.
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (second run): %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+table+" CASCADE")
	})

	found := identityConstraints(t, sqlDB, table)
	for _, want := range []struct{ name, def string }{
		{table + "_provider_subject", "UNIQUE (provider, subject)"},
		{table + "_pkey", "PRIMARY KEY (id)"},
	} {
		def, ok := found[want.name]
		if !ok {
			t.Errorf("MISSING: %s on the identities table", want.name)
			continue
		}
		if def != want.def {
			t.Errorf("%s definition = %q, want %q", want.name, def, want.def)
		}
	}

	// The index is a plain, non-unique index, so pg_constraint knows nothing
	// about it.
	idxName := table + "_user_id_idx"
	var idxDef string
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT indexdef FROM pg_indexes WHERE tablename = $1 AND indexname = $2`,
		table, idxName).Scan(&idxDef); err != nil {
		t.Fatalf("%s: %v", idxName, err)
	}
	if !strings.Contains(idxDef, "(user_id)") {
		t.Fatalf("%s definition = %q, want it to index (user_id)", idxName, idxDef)
	}
	t.Logf("%-34s i  %s", idxName, idxDef)

	// Column typing and nullability, read from the server rather than from
	// the DDL string the unit suite matches on.
	rows, err := sqlDB.QueryContext(ctx, `
		SELECT column_name, data_type, is_nullable
		FROM information_schema.columns
		WHERE table_name = $1
		ORDER BY column_name`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	nullable := map[string]string{}
	types := map[string]string{}
	for rows.Next() {
		var name, typ, null string
		if err := rows.Scan(&name, &typ, &null); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-14s %-28s nullable=%s", name, typ, null)
		nullable[name], types[name] = null, typ
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if nullable["last_used_at"] != "YES" {
		t.Errorf("last_used_at is_nullable = %q, want YES — a link made without a sign-in could never be written", nullable["last_used_at"])
	}
	// The control on that assertion: if the renderer had stopped emitting
	// NOT NULL altogether, the check above would pass for the wrong reason.
	for _, col := range []string{"id", "user_id", "provider", "subject", "created_at"} {
		if nullable[col] != "NO" {
			t.Errorf("%s is_nullable = %q, want NO — the last_used_at assertion proves nothing if every column is nullable", col, nullable[col])
		}
	}
	for _, col := range []string{"id", "user_id"} {
		if types[col] != "uuid" {
			t.Errorf("identities.%s data_type = %q, want uuid (the default authlayer's UUIDv7 ids need)", col, types[col])
		}
	}

	// Self-heal: a table that already exists but has LOST the constraint
	// gets it back, which is what makes CreateSchema safe to re-run against
	// a deployment that predates it.
	if _, err := sqlDB.ExecContext(ctx,
		fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s_provider_subject", table, table)); err != nil {
		t.Fatalf("DROP CONSTRAINT: %v", err)
	}
	if _, ok := identityConstraints(t, sqlDB, table)[table+"_provider_subject"]; ok {
		t.Fatal("the constraint survived DROP CONSTRAINT, so the self-heal below proves nothing")
	}
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (self-heal): %v", err)
	}
	def, ok := identityConstraints(t, sqlDB, table)[table+"_provider_subject"]
	if !ok {
		t.Fatal("CreateSchema did not restore UNIQUE (provider, subject) onto the existing table")
	}
	t.Logf("SELF-HEAL      %s_provider_subject  %s", table, def)
}

// identityConstraints reads every constraint on table back out of the
// server, keyed by name, and logs each one.
func identityConstraints(t *testing.T, sqlDB *sql.DB, table string) map[string]string {
	t.Helper()
	rows, err := sqlDB.QueryContext(context.Background(), `
		SELECT c.conname, c.contype, pg_get_constraintdef(c.oid)
		FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid
		WHERE r.relname = $1
		ORDER BY c.conname`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, typ, def string
		if err := rows.Scan(&name, &typ, &def); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-34s %s  %s", name, typ, def)
		out[name] = def
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestIdentityStoreDuplicateLinkIsRefusedLive is the behavioural half of the
// constraint check above: the DATABASE, not the store's Go code, is what
// refuses a second row for the same (provider, subject).
//
// It is the property auth.Identity.Subject states as a MUST. Without the
// constraint two rows can name one external account against two DIFFERENT
// local users, and a sign-in resolving that subject lands on whichever row
// the server happens to return first — one Google account silently able to
// sign in as either of two people, decided by row order. The test proves the
// refusal AND that the refusal was a refusal: the pair still resolves to the
// original user, and the loser was left with nothing.
//
// It also pins the classification boundary the fake-driver suite can only
// simulate: a real 23505 from THIS table, with the constraint name the
// server itself reports, must come back as ErrIdentityLinked rather than
// ErrIDTaken — while a genuine id collision must still come back as
// ErrIDTaken.
func TestIdentityStoreDuplicateLinkIsRefusedLive(t *testing.T) {
	_, st := newLiveIdentityStore(t)
	ctx := context.Background()
	alice, bob := uid.NewV7(), uid.NewV7()

	first := liveIdentity(alice, "google", "sub-shared")
	if _, err := st.CreateIdentity(ctx, first); err != nil {
		t.Fatalf("CreateIdentity(first): %v", err)
	}

	second := liveIdentity(bob, "google", "sub-shared")
	_, err := st.CreateIdentity(ctx, second)
	if !errors.Is(err, auth.ErrIdentityLinked) {
		t.Fatalf("second CreateIdentity for the same (provider, subject) err = %v, want ErrIdentityLinked — the database must refuse it", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("err = %v, want it to still wrap pg.ErrUniqueViolation so a caller can reach the driver error", err)
	}

	got, err := st.FindIdentityByProviderSubject(ctx, "google", "sub-shared")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if got.UserID != alice {
		t.Fatalf("(google, sub-shared) resolves to %q, want alice %q — the refused link re-pointed the row", got.UserID, alice)
	}
	if list, err := st.ListIdentitiesByUser(ctx, bob); err != nil || len(list) != 0 {
		t.Fatalf("bob has %d identities (%v), want 0 — the refused link was written anyway", len(list), err)
	}

	// The pair is what is unique, not either column: the same subject at a
	// different provider, and a different subject at the same provider, are
	// both ordinary rows. Without this control a store that had accidentally
	// made provider or subject unique on its own would pass the check above.
	if _, err := st.CreateIdentity(ctx, liveIdentity(bob, "github", "sub-shared")); err != nil {
		t.Fatalf("same subject at another provider: %v, want it allowed", err)
	}
	if _, err := st.CreateIdentity(ctx, liveIdentity(bob, "google", "sub-other")); err != nil {
		t.Fatalf("another subject at the same provider: %v, want it allowed", err)
	}

	// A genuine id collision must stay classified as ErrIDTaken — the
	// classification split is read off the server's own constraint name.
	clash := liveIdentity(uid.NewV7(), "entra", "sub-clash")
	clash.ID = first.ID
	if _, err := st.CreateIdentity(ctx, clash); !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("duplicate-id CreateIdentity err = %v, want ErrIDTaken, not ErrIdentityLinked", err)
	}
}

// TestIdentityStoreConcurrentFirstLinkExactlyOneWinnerLive is why the
// constraint is load-bearing rather than cosmetic, and it is the property
// auth.Service.SignInWith's documented "what is not atomic here" window
// leans on: two concurrent FIRST sign-ins for the same brand-new external
// account both pass the lookup, both reach CreateIdentity, and the
// constraint is the only thing that fails the loser instead of letting both
// write. Task 4's ladder has a committed test that depends on exactly this
// rescue.
//
// A fake driver cannot demonstrate it — there is no server to arbitrate —
// so it is pinned here, with the pool pre-warmed so the callers genuinely
// contend rather than trickle in one at a time (see [warmPool]'s doc for
// why that warming is load-bearing).
func TestIdentityStoreConcurrentFirstLinkExactlyOneWinnerLive(t *testing.T) {
	sqlDB, st := newLiveIdentityStore(t)
	ctx := context.Background()

	const n = 16
	sqlDB.SetMaxOpenConns(n)
	sqlDB.SetMaxIdleConns(n)
	warmPool(t, sqlDB, n)

	var mu sync.Mutex
	var winners, linked int
	var others []error
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := st.CreateIdentity(ctx, liveIdentity(uid.NewV7(), "google", "contested-sub"))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
			case errors.Is(err, auth.ErrIdentityLinked):
				linked++
			default:
				others = append(others, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(others) > 0 {
		t.Fatalf("unexpected errors from CreateIdentity: %v", others)
	}
	if winners != 1 {
		t.Fatalf("%d concurrent first links succeeded, want exactly 1 — one external account must never map to two local users", winners)
	}
	if linked != n-1 {
		t.Fatalf("%d callers got ErrIdentityLinked, want %d", linked, n-1)
	}
	// Read the final state back from the server rather than inferring it
	// from the counts.
	var rowsHeld int
	if err := sqlDB.QueryRowContext(ctx,
		fmt.Sprintf("SELECT count(*) FROM %s WHERE provider = $1 AND subject = $2", st.Schema().Identities.Name()),
		"google", "contested-sub").Scan(&rowsHeld); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rowsHeld != 1 {
		t.Fatalf("%d rows hold (google, contested-sub) after the race, want exactly 1", rowsHeld)
	}
}

// ── 2. last_used_at, nil and not ────────────────────────────────────────────

// TestIdentityStoreLastUsedAtRoundTripsNullThenValueLive proves the schema's
// only nullable column really is nullable on a real server, and that nil
// survives the trip out and back.
//
// auth.Identity.LastUsedAt is a *time.Time whose nil means "this link has
// never signed the user in" — a fact an application acts on, distinct from
// any timestamp value. Two separate things have to hold for that to be
// representable, and neither is visible to a fake driver: the INSERT has to
// bind a nil pointer as the NULL keyword rather than as a parameter (see
// colSet.bind's col.Expr(drops.Raw("NULL")) branch in columns.go), and the
// column has to accept it. A NOT NULL column would fail every LinkIdentity,
// which by definition creates a row with no sign-in behind it.
//
// The test therefore asserts NULL-ness from the SERVER's point of view
// (`last_used_at IS NULL`) as well as from the scan's, then stamps it via
// TouchIdentity and requires both views to flip together. A non-nil pointer
// written at CREATE time is included as the control on the insert path: if
// the binder wrote NULL for every *time.Time, the nil case would pass for
// entirely the wrong reason.
func TestIdentityStoreLastUsedAtRoundTripsNullThenValueLive(t *testing.T) {
	sqlDB, st := newLiveIdentityStore(t)
	ctx := context.Background()
	table := st.Schema().Identities.Name()
	user := uid.NewV7()

	isNull := func(id string) bool {
		t.Helper()
		var null bool
		if err := sqlDB.QueryRowContext(ctx,
			fmt.Sprintf("SELECT last_used_at IS NULL FROM %s WHERE id = $1", table), id).Scan(&null); err != nil {
			t.Fatalf("last_used_at IS NULL: %v", err)
		}
		return null
	}

	// (a) A freshly linked identity: nil in, NULL on the server, nil back.
	fresh := liveIdentity(user, "google", "never-used")
	if fresh.LastUsedAt != nil {
		t.Fatal("fixture is wrong: a freshly linked identity must carry a nil LastUsedAt")
	}
	if _, err := st.CreateIdentity(ctx, fresh); err != nil {
		t.Fatalf("CreateIdentity(nil LastUsedAt): %v — the column is not nullable, or nil was bound as a parameter", err)
	}
	if !isNull(fresh.ID) {
		t.Fatal("last_used_at is NOT NULL on the server after a nil write — nil was bound as a zero timestamp")
	}
	got, err := st.FindIdentityByProviderSubject(ctx, "google", "never-used")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if got.LastUsedAt != nil {
		t.Fatalf("LastUsedAt = %v, want nil — NULL did not survive the read back", got.LastUsedAt)
	}
	// The list path scans into the same model and must agree: a store that
	// only got the single-row scan right would still hand a connected-
	// accounts screen a zero time where "never" belongs.
	list, err := st.ListIdentitiesByUser(ctx, user)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListIdentitiesByUser = %v (%d), %v", list, len(list), err)
	}
	if list[0].LastUsedAt != nil {
		t.Fatalf("ListIdentitiesByUser LastUsedAt = %v, want nil", list[0].LastUsedAt)
	}

	// (b) TouchIdentity moves it to a value, and the value round-trips.
	used := time.Now().UTC().Truncate(time.Microsecond)
	if err := st.TouchIdentity(ctx, fresh.ID, used); err != nil {
		t.Fatalf("TouchIdentity: %v", err)
	}
	if isNull(fresh.ID) {
		t.Fatal("last_used_at is still NULL on the server after TouchIdentity")
	}
	got, err = st.FindIdentityByProviderSubject(ctx, "google", "never-used")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject after TouchIdentity: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Fatal("LastUsedAt = nil after TouchIdentity, want the stamped time")
	}
	if !got.LastUsedAt.Equal(used) {
		t.Fatalf("LastUsedAt = %v, want %v", got.LastUsedAt, used)
	}
	// Nothing else on the row moved.
	if got.ID != fresh.ID || got.UserID != user || !got.CreatedAt.Equal(fresh.CreatedAt) {
		t.Fatalf("TouchIdentity disturbed the row: %+v, want the seeded %+v", got, fresh)
	}
	if err := st.TouchIdentity(ctx, uid.NewV7(), used); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("TouchIdentity(unknown id) err = %v, want ErrIdentityNotFound", err)
	}

	// (c) The control on the INSERT path: a non-nil *time.Time written at
	// create time must land as a VALUE. Without this, a binder that wrote
	// NULL for every *time.Time would pass (a) perfectly.
	stamped := liveIdentity(user, "github", "used-at-link")
	stamped.LastUsedAt = &used
	if _, err := st.CreateIdentity(ctx, stamped); err != nil {
		t.Fatalf("CreateIdentity(non-nil LastUsedAt): %v", err)
	}
	if isNull(stamped.ID) {
		t.Fatal("a non-nil LastUsedAt was written as NULL — the nil assertion above proves nothing")
	}
	got, err = st.FindIdentityByProviderSubject(ctx, "github", "used-at-link")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) {
		t.Fatalf("LastUsedAt = %v, want %v", got.LastUsedAt, used)
	}
}

// ── 3. the index the planner has to actually pick ───────────────────────────

// identityQueryRecorder wraps a real drops driver and keeps every statement
// it QUERIES, so a test can recover the exact SELECT a store method issued
// and then EXPLAIN that same string. [recordingDriver] in
// auth_integration_test.go does the same for Exec; ListIdentitiesByUser is a
// read, so it needs the Query half.
//
// Writing the SELECT out by hand in the test instead would EXPLAIN a query
// the store does not run, and would keep passing if the store's projection
// or predicate ever changed.
type identityQueryRecorder struct {
	drops.Driver
	queries []string
}

func (d *identityQueryRecorder) Query(ctx context.Context, query string, args ...any) (drops.Rows, error) {
	d.queries = append(d.queries, query)
	return d.Driver.Query(ctx, query, args...)
}

func (d *identityQueryRecorder) last() string {
	if len(d.queries) == 0 {
		return ""
	}
	return d.queries[len(d.queries)-1]
}

// TestIdentityStoreListIdentitiesByUserUsesTheIndexLive proves the
// identities(user_id) index registered by NewIdentitySchema is one the
// PLANNER ACTUALLY PICKS, not merely one that exists. An index the planner
// ignores is not an index.
//
// Two methods filter on user_id alone: ListIdentitiesByUser, which every
// connected-accounts screen calls, and DeleteIdentityIfNotLast, whose
// locking SELECT reads exactly the user's rows on every unlink — while
// holding a transaction and a per-user advisory lock open. A sequential scan
// there costs the whole deployment's identity count on a path that is
// serialized per user, so it is the unlink that degrades worst.
//
// The test carries its own CONTROL: it drops the index, re-EXPLAINs, and
// requires the plan to become a sequential scan. Without that step a planner
// that had chosen a seq scan anyway — or an assertion matching something
// that appears in every plan — would pass silently, and the test would prove
// nothing about the index. CreateSchema then puts the index back, which
// re-exercises its self-healing property against a real server.
//
// Mirrors auth's TestDeleteVerificationsByUserAndPurposeUsesTheIndexLive.
// TestDeleteIdentityRemovesOneRowLive proves the by-id retraction against a
// real server: exactly the named row goes, the user's sibling at the SAME
// provider stays, another user's row stays, and a second delete of the same
// id reports ErrIdentityNotFound rather than succeeding twice.
//
// The unit suite can only see the statement this method renders. Whether that
// statement's WHERE clause actually selects one row on a server holding three
// near-identical ones is a property of the server, and it is the property
// [github.com/bernardoforcillo/authlayer/auth.Service.SignInWith]'s
// compensating delete depends on: retracting one row too many there would
// remove a link the account was already relying on.
func TestDeleteIdentityRemovesOneRowLive(t *testing.T) {
	_, st := newLiveIdentityStore(t)
	ctx := context.Background()
	user, other := uid.NewV7(), uid.NewV7()

	target := liveIdentity(user, "google", "del-target")
	sibling := liveIdentity(user, "google", "del-sibling") // same user, same provider
	stranger := liveIdentity(other, "google", "del-stranger")
	for _, i := range []auth.Identity{target, sibling, stranger} {
		if _, err := st.CreateIdentity(ctx, i); err != nil {
			t.Fatalf("CreateIdentity(%s): %v", i.Subject, err)
		}
	}

	if err := st.DeleteIdentity(ctx, target.ID); err != nil {
		t.Fatalf("DeleteIdentity: %v", err)
	}
	if _, err := st.FindIdentityByProviderSubject(ctx, "google", "del-target"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("the named row survived: err = %v, want ErrIdentityNotFound", err)
	}

	mine, err := st.ListIdentitiesByUser(ctx, user)
	if err != nil || len(mine) != 1 || mine[0].ID != sibling.ID {
		t.Fatalf("rows for the user = %+v (err %v), want only the sibling — a by-id DELETE must not widen to (user, provider)", mine, err)
	}
	theirs, err := st.ListIdentitiesByUser(ctx, other)
	if err != nil || len(theirs) != 1 {
		t.Fatalf("rows for the other user = %+v (err %v), want their row untouched", theirs, err)
	}

	if err := st.DeleteIdentity(ctx, target.ID); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("second DeleteIdentity of the same id: err = %v, want ErrIdentityNotFound — zero rows affected is a miss, not a success", err)
	}
}

func TestIdentityStoreListIdentitiesByUserUsesTheIndexLive(t *testing.T) {
	sqlDB, rawDB := openLiveDB(t)
	rec := &identityQueryRecorder{Driver: stdlib.New(sqlDB)}
	st := dropsstore.NewIdentityStore(pg.New(rec))
	ctx := context.Background()

	dropIdentityTable(t, rawDB, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropIdentityTable(t, rawDB, st) })

	// Seed enough rows, spread over enough distinct users, that an index
	// scan is the cheaper plan. On a table of a handful of rows PostgreSQL
	// correctly prefers a sequential scan whatever indexes exist, so a
	// near-empty table cannot answer the question this test asks.
	const users, perUser = 400, 3
	providers := []string{"google", "github", "entra"}
	var probeUser string
	for i := range users {
		userID := uid.NewV7()
		if i == users/2 {
			probeUser = userID
		}
		for j := range perUser {
			if _, err := st.CreateIdentity(ctx, liveIdentity(userID, providers[j], uid.NewV7())); err != nil {
				t.Fatalf("CreateIdentity: %v", err)
			}
		}
	}
	table := st.Schema().Identities.Name()
	if _, err := sqlDB.ExecContext(ctx, "ANALYZE "+table); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	// Recover the store's own SELECT by listing a user that owns no rows:
	// the statement is issued and recorded, and the table's contents and
	// statistics are left exactly as ANALYZE saw them.
	if _, err := st.ListIdentitiesByUser(ctx, uid.NewV7()); err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	stmt := rec.last()
	if !strings.Contains(stmt, "SELECT") || !strings.Contains(stmt, "user_id") {
		t.Fatalf("recorded statement is not the query under test: %q", stmt)
	}
	t.Logf("STATEMENT %s", stmt)

	idx := table + "_user_id_idx"
	withIndex := explain(t, sqlDB, stmt, probeUser)
	t.Logf("PLAN with the index:\n%s", withIndex)
	if !strings.Contains(withIndex, idx) {
		t.Fatalf("the planner did not use %s — an index it ignores is not an index. Plan:\n%s", idx, withIndex)
	}
	if strings.Contains(withIndex, "Seq Scan on "+table) {
		t.Fatalf("plan still contains a sequential scan of the identities table:\n%s", withIndex)
	}

	// The control: without the index the same statement on the same data
	// must fall back to a sequential scan. If it does not, the assertion
	// above was not measuring the index.
	if _, err := sqlDB.ExecContext(ctx, "DROP INDEX "+idx); err != nil {
		t.Fatalf("DROP INDEX %s: %v", idx, err)
	}
	withoutIndex := explain(t, sqlDB, stmt, probeUser)
	t.Logf("PLAN without the index (control):\n%s", withoutIndex)
	if !strings.Contains(withoutIndex, "Seq Scan on "+table) {
		t.Fatalf("control failed: dropping %s did not produce a sequential scan, so the plan above proves nothing about the index. Plan:\n%s", idx, withoutIndex)
	}

	// CreateSchema self-heals the index back onto the existing table.
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (self-heal after DROP INDEX): %v", err)
	}
	var def string
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT indexdef FROM pg_indexes WHERE tablename = $1 AND indexname = $2`,
		table, idx).Scan(&def); err != nil {
		t.Fatalf("index %s did not come back after CreateSchema: %v", idx, err)
	}
	t.Logf("SELF-HEAL %s", def)
}

// ── 4. atomicity of the unlink ──────────────────────────────────────────────

// TestDeleteIdentityIfNotLastIsAtomicUnderConcurrencyLive is the live half of
// store/memory's TestDeleteIdentityIfNotLastIsAtomicUnderConcurrency, and the
// reason DeleteIdentityIfNotLast is a transaction rather than the single
// conditional DELETE its own doc quotes and rejects.
//
// A password-less user holds two identities, one per provider. N callers
// unlink concurrently. Exactly one delete may succeed and exactly one
// identity must remain: if the decision and the delete are not one step,
// callers targeting DIFFERENT providers each read a snapshot in which the
// other's row is still present, each conclude the account stays reachable,
// and each delete — leaving an account with no identity and no password that
// nothing in this package can ever sign in again, with every caller told it
// succeeded. This project has shipped that exact read-then-write shape four
// times elsewhere.
//
// # Why rounds, and why the roles rotate
//
// Closing a channel readies its waiters LIFO, so a two-party race with FIXED
// roles explores one interleaving over and over — measured at 198 of 200
// rounds on this project. Two things are done about it here. The race is N
// callers wide rather than two, and the provider each goroutine targets is
// rotated by round, so the goroutine the runtime happens to ready first is
// unlinking google on even rounds and github on odd ones. Any single round
// that reaches the forbidden state fails the test, so the rounds are a
// detector, not an average.
//
// The pool is pre-warmed to N connections first: opening a connection is
// slow and uneven, so an unwarmed pool trickles callers into the contended
// statement across a window far wider than the race itself. That warming was
// measured on the auth side of this repository as the difference between
// catching a deliberately broken read-then-write ~40-70% of the time and
// 10/10 — see [warmPool] and TestAuthStoreSatisfiesTheStoreContractLive.
//
// TestDeleteIdentityIfNotLastSerializesAgainstAConcurrentSiblingUnlinkLive
// is the timing-free companion: it stages the same lockout through a second
// session at a gate both a correct and a broken implementation must pass,
// so the property is pinned once by contention and once deterministically.
func TestDeleteIdentityIfNotLastIsAtomicUnderConcurrencyLive(t *testing.T) {
	sqlDB, st := newLiveIdentityStore(t)
	ctx := context.Background()

	const n, rounds = 8, 25
	sqlDB.SetMaxOpenConns(n)
	sqlDB.SetMaxIdleConns(n)
	warmPool(t, sqlDB, n)

	providers := []string{"google", "github"}
	for round := range rounds {
		user := uid.NewV7()
		for _, p := range providers {
			if _, err := st.CreateIdentity(ctx, liveIdentity(user, p, uid.NewV7())); err != nil {
				t.Fatalf("round %d: CreateIdentity(%s): %v", round, p, err)
			}
		}

		var mu sync.Mutex
		var deleted, notFound, lastCredential int
		var others []error
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range n {
			// Rotate the role by round so the goroutine the runtime readies
			// first is not always unlinking the same provider.
			provider := providers[(i+round)%len(providers)]
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := st.DeleteIdentityIfNotLast(ctx, user, provider, false)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					deleted++
				case errors.Is(err, auth.ErrIdentityNotFound):
					notFound++
				case errors.Is(err, auth.ErrLastCredential):
					lastCredential++
				default:
					others = append(others, err)
				}
			}()
		}
		close(start)
		wg.Wait()

		left, err := st.ListIdentitiesByUser(ctx, user)
		if err != nil {
			t.Fatalf("round %d: ListIdentitiesByUser: %v", round, err)
		}
		// THE property: the account must still be reachable. A user with no
		// identity and no password is permanently and silently locked out.
		if len(left) != 1 {
			t.Fatalf("round %d: %d identities left, want exactly 1 — the user was locked out (%d deletes reported success, %d ErrLastCredential, %d ErrIdentityNotFound)",
				round, len(left), deleted, lastCredential, notFound)
		}
		if len(others) > 0 {
			t.Fatalf("round %d: unexpected errors from DeleteIdentityIfNotLast: %v", round, others)
		}
		// The outcome is fully determined, not merely bounded: exactly one
		// caller deletes, the rest either find their provider already gone
		// or are refused for being the last credential.
		if deleted != 1 {
			t.Fatalf("round %d: %d callers were told the unlink succeeded, want exactly 1", round, deleted)
		}
		if notFound+lastCredential != n-1 {
			t.Fatalf("round %d: %d ErrIdentityNotFound + %d ErrLastCredential = %d, want %d",
				round, notFound, lastCredential, notFound+lastCredential, n-1)
		}
		// Both refusals must actually occur: the callers still targeting the
		// deleted provider get ErrIdentityNotFound, the ones targeting the
		// survivor get ErrLastCredential. A round where one of them is zero
		// would mean the rotation collapsed and only one provider was ever
		// contended.
		if lastCredential == 0 {
			t.Fatalf("round %d: nobody was refused as the last credential, so nothing contended for the survivor", round)
		}
	}
}

// TestDeleteIdentityIfNotLastSerializesAgainstAConcurrentSiblingUnlinkLive
// stages the same lockout DETERMINISTICALLY, with no reliance on which
// goroutine the runtime happens to schedule first.
//
// A second session opens a transaction and takes a row lock on the user's
// github identity — the row a concurrent unlink of google would count as the
// survivor — but does not yet delete it. The store is then asked to unlink
// google, and the test advances only once that call has provably either
// parked on a lock or returned, both of which are observable conditions
// rather than elapsed time. The peer then deletes github and commits.
//
// Correct implementation: the transaction's SELECT ... FOR UPDATE covers ALL
// of the user's rows, so it parks on the peer's lock. When the peer commits,
// READ COMMITTED re-evaluates and the github row is gone, so the store sees
// a single google row, refuses with ErrLastCredential, and deletes nothing.
// One identity survives.
//
// The single conditional DELETE the method's doc quotes and rejects — its
// EXISTS subquery neither locking what it reads nor seeing the peer's
// uncommitted work — parks on nothing, deletes google immediately and
// reports success. The peer then removes github and the account is left with
// no identity and no password. Zero identities survive, and that is what
// this test fails on.
func TestDeleteIdentityIfNotLastSerializesAgainstAConcurrentSiblingUnlinkLive(t *testing.T) {
	sqlDB, st := newLiveIdentityStore(t)
	ctx := context.Background()
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(8)

	table := st.Schema().Identities.Name()
	user := uid.NewV7()
	for _, p := range []string{"google", "github"} {
		if _, err := st.CreateIdentity(ctx, liveIdentity(user, p, uid.NewV7())); err != nil {
			t.Fatalf("CreateIdentity(%s): %v", p, err)
		}
	}

	// The peer: its own session, holding a row lock on the sibling.
	peer, err := sqlDB.Conn(ctx)
	if err != nil {
		t.Fatalf("peer conn: %v", err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.ExecContext(ctx, "BEGIN"); err != nil {
		t.Fatalf("peer BEGIN: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = peer.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if _, err := peer.ExecContext(ctx,
		fmt.Sprintf("SELECT id FROM %s WHERE user_id = $1 AND provider = 'github' FOR UPDATE", table),
		user); err != nil {
		t.Fatalf("peer FOR UPDATE: %v", err)
	}

	done := make(chan struct{})
	var callErr error
	go func() {
		defer close(done)
		callErr = st.DeleteIdentityIfNotLast(ctx, user, "google", false)
	}()

	awaitParkedOrDone(t, sqlDB, done)

	// The peer now removes the sibling and commits, so a correct
	// implementation's re-evaluated snapshot contains only the google row.
	if _, err := peer.ExecContext(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE user_id = $1 AND provider = 'github'", table), user); err != nil {
		t.Fatalf("peer DELETE: %v", err)
	}
	if _, err := peer.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatalf("peer COMMIT: %v", err)
	}
	committed = true
	<-done

	left, err := st.ListIdentitiesByUser(ctx, user)
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("%d identities left, want exactly 1 — the unlink was decided against a sibling another session was already removing, and the account is now permanently unreachable (DeleteIdentityIfNotLast returned %v)", len(left), callErr)
	}
	if !errors.Is(callErr, auth.ErrLastCredential) {
		t.Fatalf("DeleteIdentityIfNotLast err = %v, want ErrLastCredential — nothing else could survive the delete", callErr)
	}
}

// awaitParkedOrDone blocks until the call under test has either returned or
// is provably parked on a lock some other session holds. Both are conditions
// read off the server, not durations waited out, so the caller advances at
// the same point against a correct implementation (which parks) and against
// a broken one (which does not park and simply finishes) — which is what
// makes the staging deterministic in BOTH directions rather than only when
// the code is right.
func awaitParkedOrDone(t *testing.T, sqlDB *sql.DB, done <-chan struct{}) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-done:
			return
		default:
		}
		var waiting int
		if err := sqlDB.QueryRowContext(context.Background(),
			"SELECT count(*) FROM pg_locks WHERE NOT granted").Scan(&waiting); err != nil {
			t.Fatalf("pg_locks: %v", err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the unlink neither returned nor parked on a lock within 30s")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
