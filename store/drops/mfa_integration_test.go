//go:build integration

// Live end-to-end tests for the MFA store against a real PostgreSQL. Run
// with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...`
// stays database-free.
//
// # Why this file exists at all
//
// store/drops/mfa_test.go is a UNIT suite over a fake driver. It can prove
// that NewMFASchema declared a primary key and an index, and that each
// method rendered the SQL it was supposed to render. It cannot prove any of
// the things this backend actually promises, because every one of them is a
// property of a SERVER rather than of a builder:
//
//  1. The three compare-and-sets really admit exactly one winner under real
//     row-lock contention — TestMFAStoreSatisfiesTheContractLive, which runs
//     the whole exported contract, races included, against a warmed pool.
//  2. PRIMARY KEY (user_id) is really on the factors table, so two rows for
//     one user are impossible rather than merely unintended —
//     TestMFAStoreCreateSchemaLandsTheFactorKeyOnRealPostgres.
//  3. last_step is really a NULLABLE BIGINT that round-trips nil and a step
//     beyond int32's range — TestMFAStoreLastStepRoundTripsNullThenABigValueLive.
//  4. The planner really PICKS the (user_id, code_hash) index —
//     TestMFAStoreRecoveryCodeLookupsUseTheIndexLive.
//
// This project has already shipped a Critical by treating a `go vet -tags
// integration` pass as evidence about a database-shaped change.
package dropsstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/auth/authtest"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// newLiveMFAStore builds an MFAStore over AUTHLAYER_TEST_DSN and
// drops/recreates both tables so each test starts from an empty schema. It
// returns the raw *sql.DB too, since several tests need it directly — to
// read pg_constraint, or to EXPLAIN.
//
// Cleanup ordering follows [openLiveDB]'s own doc: Close is registered
// there FIRST so it runs LAST, leaving the drop-table cleanup registered
// here a live connection to work with.
func newLiveMFAStore(t *testing.T) (*sql.DB, *dropsstore.MFAStore) {
	t.Helper()
	sqlDB, db := openLiveDB(t)
	st := dropsstore.NewMFAStore(db)

	dropMFATables(t, db, st)
	if err := st.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropMFATables(t, db, st) })
	return sqlDB, st
}

func dropMFATables(t *testing.T, db *pg.DB, st *dropsstore.MFAStore) {
	t.Helper()
	s := st.Schema()
	for _, tbl := range []*pg.Table{s.RecoveryCodes, s.Factors} {
		if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
			t.Fatalf("drop %s: %v", tbl.Name(), err)
		}
	}
}

func liveFactor(userID string, at time.Time) auth.MFAFactor {
	return auth.MFAFactor{UserID: userID, SecretEnc: "enc-" + uid.NewV7(), CreatedAt: at}
}

func liveCode(userID string, at time.Time) auth.RecoveryCode {
	return auth.RecoveryCode{ID: uid.NewV7(), UserID: userID, CodeHash: "rc-" + uid.NewV7(), CreatedAt: at}
}

// TestMFAStoreSatisfiesTheContractLive runs the exported
// authlayer/auth/authtest MFA suite against a real server: every documented
// obligation of auth.MFAStore, the three compare-and-set races included.
//
// A fake driver has no lock contention or wire round trips to interleave,
// so it cannot demonstrate atomicity; only a real server's row lock can.
// That is why the suite runs here as well as against store/memory, and why
// this test warms the pool to authtest.RaceGoroutines connections before
// anything starts. The warming is load-bearing and was measured on this
// project against an unwarmed pool at the MarkRotated contract: goroutines
// that trickle in across a wide connection-setup window never genuinely
// contend, which turns a single-winner assertion into a coin flip. See
// TestAuthStoreSatisfiesTheStoreContractLive's own doc for the numbers.
//
// The suite calls the factory once per check and requires an EMPTY store;
// TRUNCATE, not a drop-and-recreate, is what gives it that here, for the
// same reason the auth suite does it that way — what a check needs isolated
// is the DATA, and re-running the DDL and re-warming a pool per check costs
// real time for no added isolation.
func TestMFAStoreSatisfiesTheContractLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	sqlDB.SetMaxOpenConns(authtest.RaceGoroutines)
	sqlDB.SetMaxIdleConns(authtest.RaceGoroutines)
	warmPool(t, sqlDB, authtest.RaceGoroutines)

	st := dropsstore.NewMFAStore(db)
	ctx := context.Background()
	dropMFATables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropMFATables(t, db, st) })

	s := st.Schema()
	truncate := fmt.Sprintf("TRUNCATE %s, %s", s.Factors.Name(), s.RecoveryCodes.Name())
	authtest.RunMFAStoreContract(t, func(t *testing.T) auth.MFAStore {
		if _, err := sqlDB.ExecContext(ctx, truncate); err != nil {
			t.Fatalf("%s: %v", truncate, err)
		}
		return st
	})
}

// TestMFAStoreCreateSchemaLandsTheFactorKeyOnRealPostgres reads the primary
// key back out of pg_constraint rather than inferring it, and then proves
// what it BUYS: a second row for one user is impossible at the server, not
// merely avoided by the upsert's ON CONFLICT clause.
//
// The key is what makes "at most one factor per user" a fact. Without it,
// two rows could exist and which secret authenticates the account — and
// which last_step guards it — would be decided by whichever row the server
// returned first.
//
// It also re-runs CreateSchema to prove idempotence: every statement it
// issues is guarded, so a second call against the same database must
// succeed and change nothing.
func TestMFAStoreCreateSchemaLandsTheFactorKeyOnRealPostgres(t *testing.T) {
	sqlDB, st := newLiveMFAStore(t)
	ctx := context.Background()
	s := st.Schema()

	var keyCols string
	err := sqlDB.QueryRowContext(ctx, `
		SELECT string_agg(a.attname, ',' ORDER BY k.ord)
		  FROM pg_constraint c
		  JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
		 WHERE c.conrelid = $1::regclass AND c.contype = 'p'`,
		s.Factors.Name()).Scan(&keyCols)
	if err != nil {
		t.Fatalf("reading the primary key of %s: %v", s.Factors.Name(), err)
	}
	if keyCols != "user_id" {
		t.Fatalf("%s primary key = (%s), want (user_id)", s.Factors.Name(), keyCols)
	}

	// What the key buys, exercised rather than assumed.
	at := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()
	if err := st.UpsertFactor(ctx, liveFactor(userID, at)); err != nil {
		t.Fatalf("UpsertFactor: %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx,
		fmt.Sprintf("INSERT INTO %s (user_id, secret_enc, created_at) VALUES ($1, $2, $3)", s.Factors.Name()),
		userID, "a second secret for one user", at); err == nil {
		t.Fatal("a second mfa_factors row for one user was accepted — the primary key is not on the table, so which secret authenticates the account is decided by row order")
	}

	// Idempotent: every statement CreateSchema issues is guarded.
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("second CreateSchema: %v", err)
	}
}

// TestMFAStoreLastStepRoundTripsNullThenABigValueLive pins the column type
// this package had to grow support for. last_step must be a NULLABLE
// BIGINT: nil is "this factor has authenticated no step yet", which the
// replay guard treats as "accept any step", and a step is a Unix time
// divided by the period — 58,023,700 today, which fits an int32, but the
// column outlives 2038 and an integer column would overflow there rather
// than at some obvious boundary.
func TestMFAStoreLastStepRoundTripsNullThenABigValueLive(t *testing.T) {
	sqlDB, st := newLiveMFAStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()

	if err := st.UpsertFactor(ctx, liveFactor(userID, at)); err != nil {
		t.Fatalf("UpsertFactor: %v", err)
	}
	got, err := st.FindFactor(ctx, userID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if got.LastStep != nil {
		t.Fatalf("a fresh factor came back with LastStep = %d, want nil", *got.LastStep)
	}
	if got.ConfirmedAt != nil {
		t.Fatalf("a fresh factor came back confirmed at %v, want nil", *got.ConfirmedAt)
	}

	// A step from the year 2200, comfortably beyond int32.
	const bigStep = int64(7_258_118_400 / 30)
	ok, err := st.AdvanceStep(ctx, userID, bigStep)
	if err != nil || !ok {
		t.Fatalf("AdvanceStep(%d) = (%v, %v), want (true, nil) — an integer column would have overflowed here", bigStep, ok, err)
	}
	got, err = st.FindFactor(ctx, userID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if got.LastStep == nil || *got.LastStep != bigStep {
		t.Fatalf("LastStep = %v, want %d", got.LastStep, bigStep)
	}

	var typ string
	var nullable string
	if err := sqlDB.QueryRowContext(ctx, `
		SELECT data_type, is_nullable FROM information_schema.columns
		 WHERE table_name = $1 AND column_name = 'last_step'`,
		st.Schema().Factors.Name()).Scan(&typ, &nullable); err != nil {
		t.Fatalf("reading last_step's type: %v", err)
	}
	if typ != "bigint" || nullable != "YES" {
		t.Fatalf("last_step is %s (nullable %s), want a nullable bigint", typ, nullable)
	}
}

// TestMFAStoreAdvanceStepRefusesAReplayLive is the replay guard end to end
// against a real server: the same step twice, then every step below it, and
// finally the next one. The contract suite asserts this too; running it
// here as well is what proves the SQL predicate — `last_step IS NULL OR
// last_step < $` — behaves against PostgreSQL's own NULL semantics, where a
// comparison against NULL is neither true nor false.
func TestMFAStoreAdvanceStepRefusesAReplayLive(t *testing.T) {
	_, st := newLiveMFAStore(t)
	ctx := context.Background()
	userID := uid.NewV7()
	if err := st.UpsertFactor(ctx, liveFactor(userID, time.Now().UTC())); err != nil {
		t.Fatalf("UpsertFactor: %v", err)
	}

	const spent = int64(58023700)
	if ok, err := st.AdvanceStep(ctx, userID, spent); err != nil || !ok {
		t.Fatalf("first AdvanceStep = (%v, %v), want (true, nil) — a NULL last_step must accept any step", ok, err)
	}
	for _, replay := range []int64{spent, spent - 1, 0} {
		ok, err := st.AdvanceStep(ctx, userID, replay)
		if err != nil {
			t.Fatalf("AdvanceStep(%d): %v", replay, err)
		}
		if ok {
			t.Fatalf("AdvanceStep(%d) accepted a step at or below the spent %d — a captured code stays valid for its whole skew window", replay, spent)
		}
	}
	if ok, err := st.AdvanceStep(ctx, userID, spent+1); err != nil || !ok {
		t.Fatalf("AdvanceStep(%d) = (%v, %v), want (true, nil) — the guard is refusing legitimate logins", spent+1, ok, err)
	}
}

// TestMFAStoreRecoveryCodeLookupsUseTheIndexLive proves the planner
// actually picks (user_id, code_hash) for both shapes that read it — the
// user-only filter ListRecoveryCodes issues, and the pair
// ConsumeRecoveryCode's UPDATE matches on — with a control that drops the
// index and requires the plan to degrade. An index the planner ignores is
// not an index.
//
// enable_seqscan is left alone deliberately: forcing the planner would
// prove only that the index CAN be used, not that it is chosen for a table
// of this shape.
func TestMFAStoreRecoveryCodeLookupsUseTheIndexLive(t *testing.T) {
	sqlDB, st := newLiveMFAStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	tbl := st.Schema().RecoveryCodes.Name()

	// Enough rows across enough users that a sequential scan is the more
	// expensive plan.
	target := uid.NewV7()
	targetCodes := []auth.RecoveryCode{liveCode(target, at), liveCode(target, at)}
	if err := st.ReplaceRecoveryCodes(ctx, target, targetCodes); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}
	for range 400 {
		other := uid.NewV7()
		if err := st.ReplaceRecoveryCodes(ctx, other, []auth.RecoveryCode{liveCode(other, at)}); err != nil {
			t.Fatalf("ReplaceRecoveryCodes: %v", err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx, "ANALYZE "+tbl); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	byUser := fmt.Sprintf("SELECT id FROM %s WHERE user_id = $1", tbl)
	byPair := fmt.Sprintf("SELECT id FROM %s WHERE user_id = $1 AND code_hash = $2", tbl)

	if plan := explain(t, sqlDB, byUser, target); !strings.Contains(plan, "Index") {
		t.Fatalf("ListRecoveryCodes' filter does not use an index:\n%s", plan)
	}
	if plan := explain(t, sqlDB, byPair, target, targetCodes[0].CodeHash); !strings.Contains(plan, "Index") {
		t.Fatalf("ConsumeRecoveryCode's filter does not use an index:\n%s", plan)
	}

	// The control: without the index, the same queries must fall back to a
	// sequential scan. Without this half, a plan that says "Index" could be
	// picking up the primary key or some incidental structure rather than
	// the index this schema declares.
	if _, err := sqlDB.ExecContext(ctx, "DROP INDEX "+tbl+"_user_id_code_hash_idx"); err != nil {
		t.Fatalf("dropping the index: %v", err)
	}
	if plan := explain(t, sqlDB, byUser, target); !strings.Contains(plan, "Seq Scan") {
		t.Fatalf("with the index dropped the plan did not degrade to a sequential scan, so the earlier plan proves nothing:\n%s", plan)
	}
}

// TestMFAStoreReplaceRecoveryCodesRollsBackOnADuplicateIDLive proves the
// transaction is real: a batch carrying an id another user already holds
// must leave the user's PREVIOUS set exactly as it was. The unit suite can
// only see that a transaction was opened; whether the DELETE inside it is
// actually undone is the server's business.
func TestMFAStoreReplaceRecoveryCodesRollsBackOnADuplicateIDLive(t *testing.T) {
	_, st := newLiveMFAStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	alice, bob := uid.NewV7(), uid.NewV7()

	bobCodes := []auth.RecoveryCode{liveCode(bob, at)}
	if err := st.ReplaceRecoveryCodes(ctx, bob, bobCodes); err != nil {
		t.Fatalf("ReplaceRecoveryCodes(bob): %v", err)
	}
	original := []auth.RecoveryCode{liveCode(alice, at), liveCode(alice, at)}
	if err := st.ReplaceRecoveryCodes(ctx, alice, original); err != nil {
		t.Fatalf("ReplaceRecoveryCodes(alice): %v", err)
	}

	stolen := []auth.RecoveryCode{liveCode(alice, at), liveCode(alice, at)}
	stolen[1].ID = bobCodes[0].ID
	if err := st.ReplaceRecoveryCodes(ctx, alice, stolen); !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("ReplaceRecoveryCodes with another user's id = %v, want ErrIDTaken", err)
	}

	got, err := st.ListRecoveryCodes(ctx, alice)
	if err != nil {
		t.Fatalf("ListRecoveryCodes: %v", err)
	}
	if len(got) != len(original) {
		t.Fatalf("alice holds %d codes after a refused replacement, want her original %d — the transaction did not roll the DELETE back, so a failed regeneration destroyed her working codes", len(got), len(original))
	}
	have := map[string]bool{}
	for _, c := range got {
		have[c.ID] = true
	}
	for _, want := range original {
		if !have[want.ID] {
			t.Fatalf("code %s is gone after a refused replacement", want.ID)
		}
	}
}

// TestMFAStoreUpsertFactorReplacesEveryColumnLive is UpsertFactor's MUST
// against a real ON CONFLICT DO UPDATE. A re-enrolment must clear
// confirmed_at and last_step, not inherit them: a merged upsert leaves a
// brand-new secret already confirmed, so an enrolment the user abandoned
// half way gates every later login with a secret no authenticator holds.
func TestMFAStoreUpsertFactorReplacesEveryColumnLive(t *testing.T) {
	_, st := newLiveMFAStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()

	if err := st.UpsertFactor(ctx, liveFactor(userID, at)); err != nil {
		t.Fatalf("UpsertFactor: %v", err)
	}
	if ok, err := st.ConfirmFactor(ctx, userID, at.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("ConfirmFactor = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := st.AdvanceStep(ctx, userID, 4242); err != nil || !ok {
		t.Fatalf("AdvanceStep = (%v, %v), want (true, nil)", ok, err)
	}

	reEnrolled := liveFactor(userID, at.Add(time.Hour))
	if err := st.UpsertFactor(ctx, reEnrolled); err != nil {
		t.Fatalf("re-enrolling UpsertFactor: %v", err)
	}

	got, err := st.FindFactor(ctx, userID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if got.SecretEnc != reEnrolled.SecretEnc {
		t.Fatalf("SecretEnc = %q, want the re-enrolled %q", got.SecretEnc, reEnrolled.SecretEnc)
	}
	if got.ConfirmedAt != nil {
		t.Fatalf("re-enrolment left ConfirmedAt = %v, want NULL — the DO UPDATE does not assign every column", *got.ConfirmedAt)
	}
	if got.LastStep != nil {
		t.Fatalf("re-enrolment left LastStep = %d, want NULL — the new secret's first genuine code would be refused as a replay", *got.LastStep)
	}
	if !got.CreatedAt.Equal(reEnrolled.CreatedAt) {
		t.Fatalf("CreatedAt = %v, want the re-enrolment's %v", got.CreatedAt, reEnrolled.CreatedAt)
	}
}
