//go:build integration

// Live end-to-end tests for the passkey store against a real PostgreSQL.
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
// store/drops/credential_test.go is a UNIT suite over a fake driver. It can
// prove that NewCredentialSchema declared bigint and registered AddUnique and
// AddIndex, and that UpdateSignCount rendered a statement with a
// strictly-less predicate in it. It cannot prove any of the things this
// backend actually promises, because every one is a property of a SERVER:
//
//  1. UNIQUE (credential_id) is really ON the table, and CreateSchema is
//     really idempotent —
//     TestCredentialStoreCreateSchemaLandsConstraintsOnRealPostgres and
//     TestCredentialStoreDuplicateRegistrationIsRefusedLive.
//  2. sign_count really holds the whole uint32 range, and the two nullable
//     columns really round-trip nil — the contract suite below, plus
//     TestCredentialStoreCreateSchemaLandsConstraintsOnRealPostgres reading
//     the column types back out of information_schema.
//  3. The compare-and-set is really atomic under a row lock —
//     TestUpdateSignCountRefusesAConcurrentReplayLive.
//  4. DeleteCredentialIfNotLast is really serialized —
//     TestDeleteCredentialIfNotLastIsAtomicUnderConcurrencyLive.
//  5. The planner really PICKS the user_id index —
//     TestCredentialStoreListCredentialsByUserUsesTheIndexLive.
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
	"github.com/bernardoforcillo/authlayer/auth/authtest"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// newLiveCredentialStore builds a CredentialStore over AUTHLAYER_TEST_DSN and
// drops/recreates both tables so each test starts from an empty schema. It
// returns the raw *sql.DB too, since several tests need it directly — reading
// pg_constraint, EXPLAINing, or staging a second session.
//
// Cleanup ordering follows [openLiveDB]'s own doc: Close is registered there
// FIRST so it runs LAST, leaving the drop-table cleanup registered here a
// live connection to work with.
func newLiveCredentialStore(t *testing.T) (*sql.DB, *dropsstore.CredentialStore) {
	t.Helper()
	sqlDB, db := openLiveDB(t)
	st := dropsstore.NewCredentialStore(db)

	dropCredentialTables(t, db, st)
	if err := st.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropCredentialTables(t, db, st) })
	return sqlDB, st
}

func dropCredentialTables(t *testing.T, db *pg.DB, st *dropsstore.CredentialStore) {
	t.Helper()
	s := st.Schema()
	for _, tbl := range []*pg.Table{s.Credentials, s.Challenges} {
		if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
			t.Fatalf("drop %s: %v", tbl.Name(), err)
		}
	}
}

// liveCredential builds a well-formed credential for userID, with LastUsedAt
// nil — the state every fresh registration is in, and one only a real server
// can prove is representable — and a counter above 2^31, which only a bigint
// column can hold.
func liveCredential(userID string, at time.Time) auth.Credential {
	return auth.Credential{
		ID:           uid.NewV7(),
		UserID:       userID,
		CredentialID: append([]byte{0x00, 0xff}, uid.NewV7()...),
		PublicKey:    []byte("cose-" + uid.NewV7()),
		SignCount:    3_000_000_000,
		Transports:   "internal,hybrid",
		Label:        "live key",
		CreatedAt:    at,
	}
}

// ── 1. the contract, against a real server ──────────────────────────────────

// TestCredentialStoreSatisfiesTheCredentialContractLive runs the exported
// authtest suite against a real server. A fake driver has no lock contention
// or wire round trips to interleave, so it cannot demonstrate atomicity; only
// a real server's row lock can, and the two obligations that matter most here
// — the sign-counter compare-and-set and the last-credential removal — are
// both atomicity obligations.
//
// The factory TRUNCATEs rather than dropping and recreating, for the reason
// TestAuthStoreSatisfiesTheStoreContractLive's own factory gives: what a
// check needs isolated is the DATA, and a warm pool is what makes the races
// actually contend rather than trickle.
func TestCredentialStoreSatisfiesTheCredentialContractLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	sqlDB.SetMaxOpenConns(authtest.RaceGoroutines)
	sqlDB.SetMaxIdleConns(authtest.RaceGoroutines)
	warmPool(t, sqlDB, authtest.RaceGoroutines)

	st := dropsstore.NewCredentialStore(db)
	ctx := context.Background()
	dropCredentialTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropCredentialTables(t, db, st) })

	s := st.Schema()
	truncate := fmt.Sprintf("TRUNCATE %s, %s", s.Credentials.Name(), s.Challenges.Name())
	newStore := func(t *testing.T) auth.CredentialStore {
		if _, err := sqlDB.ExecContext(ctx, truncate); err != nil {
			t.Fatalf("%s: %v", truncate, err)
		}
		return st
	}
	authtest.RunCredentialStoreContract(t, newStore)
}

// ── 2. the schema, on a real server ─────────────────────────────────────────

// TestCredentialStoreCreateSchemaLandsConstraintsOnRealPostgres proves the
// constraints registered by NewCredentialSchema actually REACH the database,
// by reading them back out of pg_constraint rather than inferring them from a
// builder call the unit suite can see. Neither is declared inline, so both
// exist only because CreateSchema emits a guarded ALTER TABLE — exactly the
// step a fake driver cannot evaluate.
//
// It also pins, on the same server:
//
//   - the user_id INDEX, which is not a constraint and so does not appear in
//     pg_constraint at all — read from pg_indexes instead;
//   - sign_count landing as BIGINT, without which every counter above 2^31
//     would be rejected or silently wrapped, and the compare-and-set would
//     compare the wrong number;
//   - credential_id and public_key landing as BYTEA, which is what makes the
//     lookup byte-exact rather than collation-dependent;
//   - credentials.last_used_at and passkey_challenges.user_id being NULLABLE
//     and everything else NOT NULL — a NOT NULL on either would fail every
//     fresh registration and every login ceremony respectively;
//   - CreateSchema staying IDEMPOTENT across two runs, which is the whole
//     point of the plpgsql guard around each ALTER TABLE.
func TestCredentialStoreCreateSchemaLandsConstraintsOnRealPostgres(t *testing.T) {
	sqlDB, st := newLiveCredentialStore(t)
	ctx := context.Background()
	credentials := st.Schema().Credentials.Name()
	challenges := st.Schema().Challenges.Name()

	for _, tc := range []struct{ table, constraint, def string }{
		{credentials, credentials + "_credential_id", "UNIQUE (credential_id)"},
		{challenges, challenges + "_challenge_hash", "UNIQUE (challenge_hash)"},
	} {
		var def string
		if err := sqlDB.QueryRowContext(ctx,
			`SELECT pg_get_constraintdef(c.oid)
			   FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
			  WHERE t.relname = $1 AND c.conname = $2`,
			tc.table, tc.constraint).Scan(&def); err != nil {
			t.Fatalf("constraint %s is not on %s: %v", tc.constraint, tc.table, err)
		}
		if !strings.Contains(def, tc.def) {
			t.Fatalf("constraint %s = %q, want %s", tc.constraint, def, tc.def)
		}
		t.Logf("CONSTRAINT %s %s", tc.constraint, def)
	}

	var idxDef string
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT indexdef FROM pg_indexes WHERE tablename = $1 AND indexname = $2`,
		credentials, credentials+"_user_id_idx").Scan(&idxDef); err != nil {
		t.Fatalf("the user_id index is not on %s: %v", credentials, err)
	}
	t.Logf("INDEX %s", idxDef)

	types := map[string]struct{ table, want string }{
		"sign_count":    {credentials, "bigint"},
		"credential_id": {credentials, "bytea"},
		"public_key":    {credentials, "bytea"},
		"user_id":       {credentials, "uuid"},
	}
	for column, tc := range types {
		var got string
		if err := sqlDB.QueryRowContext(ctx,
			`SELECT data_type FROM information_schema.columns
			  WHERE table_name = $1 AND column_name = $2`,
			tc.table, column).Scan(&got); err != nil {
			t.Fatalf("reading %s.%s: %v", tc.table, column, err)
		}
		if got != tc.want {
			t.Errorf("%s.%s landed as %s, want %s", tc.table, column, got, tc.want)
		}
	}

	nullable := func(table, column string) string {
		t.Helper()
		var isNullable string
		if err := sqlDB.QueryRowContext(ctx,
			`SELECT is_nullable FROM information_schema.columns
			  WHERE table_name = $1 AND column_name = $2`,
			table, column).Scan(&isNullable); err != nil {
			t.Fatalf("reading %s.%s nullability: %v", table, column, err)
		}
		return isNullable
	}
	if got := nullable(credentials, "last_used_at"); got != "YES" {
		t.Errorf("%s.last_used_at is_nullable = %s, want YES — every fresh registration writes nil", credentials, got)
	}
	if got := nullable(challenges, "user_id"); got != "YES" {
		t.Errorf("%s.user_id is_nullable = %s, want YES — a login ceremony names no account", challenges, got)
	}
	for _, column := range []string{"credential_id", "public_key", "sign_count", "user_id", "created_at"} {
		if got := nullable(credentials, column); got != "NO" {
			t.Errorf("%s.%s is_nullable = %s, want NO", credentials, column, got)
		}
	}

	// Idempotent: the guarded ALTER TABLEs must swallow "already there".
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("second CreateSchema: %v", err)
	}
}

// ── 3. the constraint doing its job ─────────────────────────────────────────

// TestCredentialStoreDuplicateRegistrationIsRefusedLive is the live proof of
// [auth.Credential.CredentialID]'s uniqueness MUST: the server, not the
// store's Go code, is what refuses a second row for one authenticator
// credential — and this backend deliberately has no preliminary SELECT, so
// there is nothing else that could.
//
// The consequence of losing it is not a duplicate record. It is one
// authenticator credential mapped to two accounts, with a login resolving to
// whichever row the server returns first: an authentication bypass decided by
// row order. The test therefore asserts BOTH the refusal and that the
// original row still belongs to the original user with its original key.
func TestCredentialStoreDuplicateRegistrationIsRefusedLive(t *testing.T) {
	_, st := newLiveCredentialStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	alice, bob := uid.NewV7(), uid.NewV7()

	first := liveCredential(alice, at)
	if _, err := st.CreateCredential(ctx, first); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	second := liveCredential(bob, at)
	second.CredentialID = first.CredentialID
	second.PublicKey = []byte("attacker-supplied-key")
	if _, err := st.CreateCredential(ctx, second); !errors.Is(err, auth.ErrCredentialRegistered) {
		t.Fatalf("duplicate CreateCredential err = %v, want ErrCredentialRegistered", err)
	}

	got, err := st.FindCredentialByCredentialID(ctx, first.CredentialID)
	if err != nil {
		t.Fatalf("FindCredentialByCredentialID: %v", err)
	}
	if got.ID != first.ID || got.UserID != alice {
		t.Fatalf("the credential was re-pointed: %+v, want %s for %s", got, first.ID, alice)
	}
	if string(got.PublicKey) != string(first.PublicKey) {
		t.Fatalf("the public key was overwritten: %q", got.PublicKey)
	}
}

// TestCredentialStoreConcurrentRegistrationsAdmitOneWinnerLive is the other
// half: the constraint is also what fails the loser of two concurrent
// registrations of one authenticator credential, since this backend's
// CreateCredential is a single INSERT with no read to race.
func TestCredentialStoreConcurrentRegistrationsAdmitOneWinnerLive(t *testing.T) {
	sqlDB, st := newLiveCredentialStore(t)
	sqlDB.SetMaxOpenConns(authtest.RaceGoroutines)
	warmPool(t, sqlDB, authtest.RaceGoroutines)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)

	shared := liveCredential(uid.NewV7(), at).CredentialID

	var mu sync.Mutex
	winners, unexpected := 0, 0
	var firstErr error
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < authtest.RaceGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := liveCredential(uid.NewV7(), at)
			c.CredentialID = shared
			<-start
			_, err := st.CreateCredential(ctx, c)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
			case !errors.Is(err, auth.ErrCredentialRegistered):
				unexpected++
				if firstErr == nil {
					firstErr = err
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	if unexpected != 0 {
		t.Fatalf("%d losers returned something other than ErrCredentialRegistered; first %v", unexpected, firstErr)
	}
	if winners != 1 {
		t.Fatalf("%d of %d concurrent registrations of one credential id succeeded, want exactly 1",
			winners, authtest.RaceGoroutines)
	}
}

// ── 4. the compare-and-set, on a real server ────────────────────────────────

// TestUpdateSignCountRefusesAConcurrentReplayLive is the live half of the
// contract's single-winner check, and it is the property the whole
// clone-detection story rests on: replaying one captured assertion N times
// concurrently is exactly N callers presenting the same counter, and the
// server's row lock is what makes at most one of them win.
//
// A fake driver cannot show this at all — there is no lock and no
// interleaving — and store/memory shows it only under a mutex. Here the
// atomicity comes from `UPDATE ... WHERE id = $1 AND sign_count < $2` being
// one statement, which is the claim this test actually tests.
func TestUpdateSignCountRefusesAConcurrentReplayLive(t *testing.T) {
	sqlDB, st := newLiveCredentialStore(t)
	sqlDB.SetMaxOpenConns(authtest.RaceGoroutines)
	warmPool(t, sqlDB, authtest.RaceGoroutines)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)

	c := liveCredential(uid.NewV7(), at)
	if _, err := st.CreateCredential(ctx, c); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	replayed := c.SignCount + 1

	var mu sync.Mutex
	winners, failures := 0, 0
	var firstErr error
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < authtest.RaceGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := st.UpdateSignCount(ctx, c.ID, replayed, at.Add(time.Minute))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failures++
				if firstErr == nil {
					firstErr = err
				}
			case ok:
				winners++
			}
		}()
	}
	close(start)
	wg.Wait()

	if failures != 0 {
		t.Fatalf("%d concurrent UpdateSignCount calls failed; first %v", failures, firstErr)
	}
	if winners != 1 {
		t.Fatalf("%d of %d concurrent presentations of the same counter won, want exactly 1 — a replayed assertion must be accepted at most once",
			winners, authtest.RaceGoroutines)
	}

	got, err := st.FindCredentialByCredentialID(ctx, c.CredentialID)
	if err != nil {
		t.Fatalf("FindCredentialByCredentialID: %v", err)
	}
	if got.SignCount != replayed {
		t.Fatalf("stored SignCount = %d, want %d", got.SignCount, replayed)
	}
}

// ── 5. atomicity of the removal ─────────────────────────────────────────────

// TestDeleteCredentialIfNotLastIsAtomicUnderConcurrencyLive is the reason
// DeleteCredentialIfNotLast is a transaction with a per-user advisory lock
// rather than the single conditional DELETE its own doc quotes and rejects.
//
// A user holds two passkeys and nothing else — no password, no identity. N
// callers remove them concurrently, and the account MUST still have one
// afterwards. Against the conditional-DELETE shape both callers' EXISTS
// subqueries see the sibling under READ COMMITTED, both delete, and the
// account is locked out permanently with both callers told they succeeded.
func TestDeleteCredentialIfNotLastIsAtomicUnderConcurrencyLive(t *testing.T) {
	sqlDB, st := newLiveCredentialStore(t)
	sqlDB.SetMaxOpenConns(authtest.RaceGoroutines)
	warmPool(t, sqlDB, authtest.RaceGoroutines)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)

	for round := 0; round < 5; round++ {
		user := uid.NewV7()
		first := liveCredential(user, at)
		second := liveCredential(user, at)
		for _, c := range []auth.Credential{first, second} {
			if _, err := st.CreateCredential(ctx, c); err != nil {
				t.Fatalf("CreateCredential: %v", err)
			}
		}

		var mu sync.Mutex
		var errs []error
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, id := range []string{first.ID, second.ID} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				<-start
				err := st.DeleteCredentialIfNotLast(ctx, user, id, false)
				mu.Lock()
				defer mu.Unlock()
				errs = append(errs, err)
			}(id)
		}
		close(start)
		wg.Wait()

		for _, err := range errs {
			if err != nil && !errors.Is(err, auth.ErrLastCredential) {
				t.Fatalf("round %d: unexpected error %v", round, err)
			}
		}
		left, err := st.ListCredentialsByUser(ctx, user)
		if err != nil {
			t.Fatalf("round %d: ListCredentialsByUser: %v", round, err)
		}
		if len(left) != 1 {
			t.Fatalf("round %d: %d credentials left, want 1 — the account was locked out (errs: %v)", round, len(left), errs)
		}
	}
}

// ── 6. the index the planner has to pick ────────────────────────────────────

// credentialQueryRecorder wraps the driver so a test can recover the exact
// SELECT the store issued and then EXPLAIN that same string. Writing the
// SELECT out by hand in the test instead would EXPLAIN a query the store does
// not run, and would keep passing if the store's projection or predicate ever
// changed.
type credentialQueryRecorder struct {
	drops.Driver
	queries []string
}

func (d *credentialQueryRecorder) Query(ctx context.Context, query string, args ...any) (drops.Rows, error) {
	d.queries = append(d.queries, query)
	return d.Driver.Query(ctx, query, args...)
}

func (d *credentialQueryRecorder) last() string {
	if len(d.queries) == 0 {
		return ""
	}
	return d.queries[len(d.queries)-1]
}

// TestCredentialStoreListCredentialsByUserUsesTheIndexLive proves the
// credentials(user_id) index registered by NewCredentialSchema is one the
// PLANNER ACTUALLY PICKS, not merely one that exists. An index the planner
// ignores is not an index.
//
// Three paths filter on user_id alone: ListCredentialsByUser (every "your
// passkeys" screen, and the last-credential arithmetic behind every unlink),
// DeleteCredentialIfNotLast's locking SELECT — which runs inside a
// transaction holding a per-user advisory lock, so a sequential scan there
// costs the whole deployment's passkey count on a path that is serialized per
// user — and the service's own sweeps.
//
// The test carries its own CONTROL: it drops the index, re-EXPLAINs, and
// requires the plan to become a sequential scan. Without that step a planner
// that had chosen a seq scan anyway — or an assertion matching something that
// appears in every plan — would pass silently, and the test would prove
// nothing about the index. CreateSchema then puts the index back, which
// re-exercises its self-healing property against a real server.
//
// Mirrors TestIdentityStoreListIdentitiesByUserUsesTheIndexLive.
func TestCredentialStoreListCredentialsByUserUsesTheIndexLive(t *testing.T) {
	sqlDB, rawDB := openLiveDB(t)
	rec := &credentialQueryRecorder{Driver: stdlib.New(sqlDB)}
	st := dropsstore.NewCredentialStore(pg.New(rec))
	ctx := context.Background()

	dropCredentialTables(t, rawDB, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropCredentialTables(t, rawDB, st) })

	// Seed enough rows, spread over enough distinct users, that an index scan
	// is the cheaper plan. On a table of a handful of rows PostgreSQL
	// correctly prefers a sequential scan whatever indexes exist, so a
	// near-empty table cannot answer the question this test asks.
	const users, perUser = 400, 3
	at := time.Now().UTC().Truncate(time.Microsecond)
	var probeUser string
	for i := range users {
		userID := uid.NewV7()
		if i == users/2 {
			probeUser = userID
		}
		for range perUser {
			if _, err := st.CreateCredential(ctx, liveCredential(userID, at)); err != nil {
				t.Fatalf("CreateCredential: %v", err)
			}
		}
	}
	table := st.Schema().Credentials.Name()
	if _, err := sqlDB.ExecContext(ctx, "ANALYZE "+table); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	// Recover the store's own SELECT by listing a user that owns no rows: the
	// statement is issued and recorded, and the table's contents and
	// statistics are left exactly as ANALYZE saw them.
	if _, err := st.ListCredentialsByUser(ctx, uid.NewV7()); err != nil {
		t.Fatalf("ListCredentialsByUser: %v", err)
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
		t.Fatalf("plan still contains a sequential scan of the credentials table:\n%s", withIndex)
	}

	// The control: without the index the same statement on the same data must
	// fall back to a sequential scan. If it does not, the assertion above was
	// not measuring the index.
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
		t.Fatalf("index %s did not come back after CreateSchema: %v", table, err)
	}
	t.Logf("SELF-HEAL %s", def)
}
