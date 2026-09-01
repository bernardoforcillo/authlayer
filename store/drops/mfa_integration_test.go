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
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/auth/authtest"
	"github.com/bernardoforcillo/authlayer/internal/totp"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/password"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
	"github.com/bernardoforcillo/authlayer/token"
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
	for _, tbl := range []*pg.Table{s.TrustedDevices, s.RecoveryCodes, s.Factors} {
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
	truncate := fmt.Sprintf("TRUNCATE %s, %s, %s", s.Factors.Name(), s.RecoveryCodes.Name(), s.TrustedDevices.Name())
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

// --- service-level MFA against a real server ---
//
// Everything above this line is store behaviour. What follows drives
// auth.Service's own second-factor flow — enrol, confirm, a login that
// returns a challenge, CompleteMFA — against live PostgreSQL, and it exists
// for the reason this file's own header gives: memory-backend evidence says
// nothing about the SQL that actually runs.
//
// Two of the service-level mutations behind this feature have a
// storage-level counterpart, and these are the tests that carry them:
//
//   - Skipping auth.MFAStore.AdvanceStep. In store/memory the replay guard
//     is a map write under a mutex; here it is an UPDATE whose predicate
//     compares the presented step against the stored last_step, and only a
//     server can show that the predicate is really in the statement.
//   - Burning the challenge after minting the session. In store/memory the
//     claim is a map delete; here it is a DELETE whose rows-affected count
//     is what makes exactly one of two concurrent callers win, under real
//     row locks rather than a mutex.

// liveCipher is the drops lane's auth.Cipher: the same deliberately trivial
// round trip auth's own suite uses, restated here because a _test.go type
// is never part of another package's importable surface. It refuses a value
// it did not produce, which is auth.Cipher's one contractual obligation.
type liveCipher struct{}

const liveCipherPrefix = "enc:"

func (liveCipher) Encrypt(plaintext string) (string, error) {
	return liveCipherPrefix + plaintext, nil
}

func (liveCipher) Decrypt(ciphertext string) (string, error) {
	rest, ok := strings.CutPrefix(ciphertext, liveCipherPrefix)
	if !ok {
		return "", errors.New("liveCipher: not a ciphertext this cipher produced")
	}
	return rest, nil
}

// liveClock is a movable clock shared by the Service and the test, so a
// TOTP code can be placed in a chosen step and then stepped past.
type liveClock struct {
	mu sync.Mutex
	t  time.Time
}

func newLiveClock() *liveClock {
	return &liveClock{t: time.Date(2026, 3, 4, 10, 15, 15, 0, time.UTC)}
}

func (c *liveClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *liveClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// liveMFAFixture is a Service wired over BOTH live stores, plus the handles
// a test needs to assert on stored state, move time, and rebuild the same
// Service over a wrapped Store.
type liveMFAFixture struct {
	sqlDB *sql.DB
	auth  *dropsstore.AuthStore
	mfa   *dropsstore.MFAStore
	svc   *auth.Service
	clock *liveClock
	opts  []auth.Option
}

// newLiveMFAService builds that fixture over AUTHLAYER_TEST_DSN, recreating
// both schemas so each test starts empty. Cleanup ordering follows
// openLiveDB's own doc.
func newLiveMFAService(t *testing.T) liveMFAFixture {
	t.Helper()
	sqlDB, db := openLiveDB(t)
	ctx := context.Background()

	authSt := dropsstore.NewAuthStore(db)
	dropAuthTables(t, db, authSt)
	if err := authSt.CreateSchema(ctx); err != nil {
		t.Fatalf("AuthStore.CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, authSt) })

	mfaSt := dropsstore.NewMFAStore(db)
	dropMFATables(t, db, mfaSt)
	if err := mfaSt.CreateSchema(ctx); err != nil {
		t.Fatalf("MFAStore.CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropMFATables(t, db, mfaSt) })

	clk := newLiveClock()
	opts := []auth.Option{
		auth.WithHasher(password.Bcrypt(bcrypt.MinCost)),
		auth.WithJWT([][]byte{bytes.Repeat([]byte("k"), 32)}, 15*time.Minute),
		auth.WithMFAStore(mfaSt),
		auth.WithMFASecretCipher(liveCipher{}),
		auth.WithClock(clk.now),
	}
	return liveMFAFixture{
		sqlDB: sqlDB,
		auth:  authSt,
		mfa:   mfaSt,
		svc:   auth.New(authSt, opts...),
		clock: clk,
		opts:  opts,
	}
}

const liveMFAPassword = "Correct-Horse-Battery-9!"

// enrolLive takes an account all the way through enrolment against the live
// stores, returning the user, the plaintext secret and the recovery codes.
func enrolLive(t *testing.T, f liveMFAFixture, email string) (auth.UserBase, string, []string) {
	t.Helper()
	ctx := context.Background()

	up, err := f.svc.SignUp(ctx, email, liveMFAPassword)
	if err != nil {
		t.Fatalf("SignUp(%q): %v", email, err)
	}
	secret, uri, err := f.svc.BeginMFAEnrolment(ctx, up.User.ID)
	if err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}
	if uri == "" {
		t.Fatal("BeginMFAEnrolment returned an empty provisioning URI")
	}
	codes, err := f.svc.ConfirmMFAEnrolment(ctx, up.User.ID, liveTOTPCode(t, secret, f.clock.now()))
	if err != nil {
		t.Fatalf("ConfirmMFAEnrolment: %v", err)
	}
	return up.User, secret, codes
}

func liveTOTPCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.Code(secret, at, 6, 30*time.Second, totp.SHA1)
	if err != nil {
		t.Fatalf("totp.Code: %v", err)
	}
	return code
}

func liveLoginOwingMFA(t *testing.T, f liveMFAFixture, email string) auth.LoginResult {
	t.Helper()
	res, err := f.svc.Login(context.Background(), email, liveMFAPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login(%q): %v", email, err)
	}
	if res.MFA == nil {
		t.Fatalf("Login(%q) returned no MFA challenge for a confirmed factor", email)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("Login(%q) handed back tokens (%q/%q) on the MFA-owed path", email, res.AccessToken, res.RefreshToken)
	}
	return res
}

// TestMFAServiceEnrolsAndCompletesLive is the end-to-end shape: the secret
// really round-trips through a text column as ciphertext, the confirmation
// really stamps confirmed_at, the challenge really persists as a
// verification row, and the exchange really produces a rotatable session.
func TestMFAServiceEnrolsAndCompletesLive(t *testing.T) {
	f := newLiveMFAService(t)
	ctx := context.Background()
	u, secret, codes := enrolLive(t, f, "live-mfa-basic@example.com")

	stored, err := f.mfa.FindFactor(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if stored.ConfirmedAt == nil {
		t.Fatal("confirmed_at was not stamped by the live confirmation")
	}
	if stored.SecretEnc == secret || !strings.HasPrefix(stored.SecretEnc, liveCipherPrefix) {
		t.Fatalf("secret_enc = %q, want ciphertext — a plaintext column here is a second-factor bypass for every user", stored.SecretEnc)
	}
	if len(codes) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(codes))
	}

	f.clock.advance(30 * time.Second)
	pending := liveLoginOwingMFA(t, f, "live-mfa-basic@example.com")

	res, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, liveTOTPCode(t, secret, f.clock.now()), "198.51.100.4", "live-agent")
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("CompleteMFA produced no session")
	}
	if _, rerr := f.svc.Refresh(ctx, res.RefreshToken); rerr != nil {
		t.Fatalf("Refresh on the completed session: %v", rerr)
	}
	// The challenge row is really gone from the verifications table.
	if _, verr := f.auth.FindVerificationByHash(ctx, token.HashOpaque(pending.MFA.Token)); !errors.Is(verr, auth.ErrVerificationNotFound) {
		t.Fatalf("challenge row after completion = %v, want it burned", verr)
	}
}

// TestMFAServiceRefusesAReplayedTOTPCodeLive is the storage-level
// counterpart of the "skip AdvanceStep" mutation. The refusal it pins is
// produced by store/drops' AdvanceStep UPDATE predicate, not by anything in
// the service — remove either half and a shoulder-surfed code stays valid
// for its whole skew window.
func TestMFAServiceRefusesAReplayedTOTPCodeLive(t *testing.T) {
	f := newLiveMFAService(t)
	ctx := context.Background()
	u, secret, _ := enrolLive(t, f, "live-mfa-replay@example.com")

	f.clock.advance(30 * time.Second)
	code := liveTOTPCode(t, secret, f.clock.now())

	first := liveLoginOwingMFA(t, f, "live-mfa-replay@example.com")
	if _, err := f.svc.CompleteMFA(ctx, first.MFA.Token, code, "1.2.3.4", "agent"); err != nil {
		t.Fatalf("first CompleteMFA: %v", err)
	}

	second := liveLoginOwingMFA(t, f, "live-mfa-replay@example.com")
	if _, err := f.svc.CompleteMFA(ctx, second.MFA.Token, code, "5.6.7.8", "attacker"); !errors.Is(err, auth.ErrMFACodeInvalid) {
		t.Fatalf("replayed code = %v, want ErrMFACodeInvalid", err)
	}

	// last_step really moved in the database, and the next step still works.
	stored, err := f.mfa.FindFactor(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if stored.LastStep == nil {
		t.Fatal("last_step is NULL after a completion; the replay guard has no state")
	}
	f.clock.advance(30 * time.Second)
	if _, err := f.svc.CompleteMFA(ctx, second.MFA.Token, liveTOTPCode(t, secret, f.clock.now()), "1.2.3.4", "agent"); err != nil {
		t.Fatalf("next-step code after a refused replay: %v, want success", err)
	}
}

// parkOnChallengeLookupStore parks the FIRST caller to look a verification
// up, immediately after the real (successful) read, and holds it until the
// test releases it — auth/magiclink_test.go's own parking store, restated
// here for the same reason liveCipher is, and pointed at CompleteMFA.
//
// It makes the two-party race deterministic BY CONSTRUCTION rather than by
// scheduler luck: caller #2 is only ever started once caller #1 holds a
// live, unburned challenge and cannot proceed, so caller #2 is guaranteed
// to reach DeleteVerification first. sessionInserts counts the sessions
// that were actually persisted, which is what distinguishes "one session
// was ever minted" from "one caller succeeded".
type parkOnChallengeLookupStore struct {
	auth.Store
	calls          atomic.Int32
	parked         chan struct{}
	release        chan struct{}
	sessionInserts atomic.Int32
}

func newParkOnChallengeLookupStore(inner auth.Store) *parkOnChallengeLookupStore {
	return &parkOnChallengeLookupStore{
		Store:   inner,
		parked:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (s *parkOnChallengeLookupStore) FindVerificationByHash(ctx context.Context, hash string) (auth.Verification, error) {
	v, err := s.Store.FindVerificationByHash(ctx, hash)
	if s.calls.Add(1) == 1 {
		close(s.parked)
		<-s.release
	}
	return v, err
}

func (s *parkOnChallengeLookupStore) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	got, err := s.Store.CreateSession(ctx, sess)
	if err == nil {
		s.sessionInserts.Add(1)
	}
	return got, err
}

// TestMFAServiceChallengeAdmitsExactlyOneSessionLive is the storage-level
// counterpart of the "burn the challenge after minting" mutation: the claim
// that decides this race is store/drops' DeleteVerification and its
// rows-affected gate, against real row locks. Move the burn after the mint
// and both callers get in.
//
// The two callers present DIFFERENT recovery codes on purpose. With the
// same TOTP code, AdvanceStep would decide the race and the challenge's own
// burn would never be tested; with two valid, unspent recovery codes the
// burn is the only thing that can make one of them lose.
func TestMFAServiceChallengeAdmitsExactlyOneSessionLive(t *testing.T) {
	f := newLiveMFAService(t)
	ctx := context.Background()
	u, _, codes := enrolLive(t, f, "live-mfa-race@example.com")
	pending := liveLoginOwingMFA(t, f, "live-mfa-race@example.com")

	// Several connections, so the parked caller genuinely holds one while
	// the second runs: a single-connection pool would deadlock rather than
	// race. Warmed for the reason TestMFAStoreSatisfiesTheContractLive
	// warms its own.
	f.sqlDB.SetMaxOpenConns(4)
	f.sqlDB.SetMaxIdleConns(4)
	warmPool(t, f.sqlDB, 4)

	parking := newParkOnChallengeLookupStore(f.auth)
	svc := auth.New(parking, f.opts...)

	type result struct {
		res auth.LoginResult
		err error
	}
	firstDone := make(chan result, 1)
	go func() {
		res, err := svc.CompleteMFA(ctx, pending.MFA.Token, codes[0], "1.1.1.1", "first")
		firstDone <- result{res, err}
	}()

	<-parking.parked // caller #1 holds the live challenge and cannot proceed

	secondRes, secondErr := svc.CompleteMFA(ctx, pending.MFA.Token, codes[1], "2.2.2.2", "second")

	close(parking.release)
	first := <-firstDone

	if secondErr != nil {
		t.Fatalf("winner (second, unparked caller) err = %v, want nil", secondErr)
	}
	if secondRes.AccessToken == "" || secondRes.RefreshToken == "" {
		t.Fatal("winner got no usable session")
	}
	if !errors.Is(first.err, auth.ErrVerificationNotFound) {
		t.Fatalf("loser (first, parked caller) err = %v, want ErrVerificationNotFound", first.err)
	}
	if first.res.AccessToken != "" || first.res.RefreshToken != "" {
		t.Fatalf("loser got tokens (%q/%q); the challenge was already claimed", first.res.AccessToken, first.res.RefreshToken)
	}
	if n := parking.sessionInserts.Load(); n != 1 {
		t.Fatalf("CreateSession succeeded %d time(s), want exactly 1 — one challenge must never become two sessions", n)
	}
	sessions, err := f.auth.ListSessionsByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want exactly 1", len(sessions))
	}
}

// liveTrustedDevice builds one unexpired trusted device for userID.
func liveTrustedDevice(userID string, at time.Time) auth.TrustedDevice {
	return auth.TrustedDevice{
		ID:        uid.NewV7(),
		UserID:    userID,
		TokenHash: "td-" + uid.NewV7(),
		Label:     "live device",
		CreatedAt: at,
		ExpiresAt: at.Add(30 * 24 * time.Hour),
	}
}

// TestMFAStoreTrustedDeviceTokenHashIsUniqueLive proves the constraint
// exists in the DATABASE rather than only in the reference store's scan.
//
// auth.TrustedDevice.TokenHash's MUST is discharged here by UNIQUE
// (token_hash), which [MFASchema] registers through AddUnique and
// CreateSchema emits as a guarded ALTER TABLE — a path the unit tests cannot
// exercise at all, and the one that decides whether two rows can share a
// token. If they could, FindTrustedDeviceByHash would return whichever the
// server reached first, so WHICH ACCOUNT a token skips the second factor for
// would be decided by row order.
func TestMFAStoreTrustedDeviceTokenHashIsUniqueLive(t *testing.T) {
	_, st := newLiveMFAStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)

	first := liveTrustedDevice(uid.NewV7(), at)
	if _, err := st.CreateTrustedDevice(ctx, first); err != nil {
		t.Fatalf("CreateTrustedDevice: %v", err)
	}

	clash := liveTrustedDevice(uid.NewV7(), at)
	clash.TokenHash = first.TokenHash
	if _, err := st.CreateTrustedDevice(ctx, clash); err == nil {
		t.Fatalf("a second device with the same token_hash was accepted — CreateSchema did not emit UNIQUE (token_hash), so one token now resolves to whichever row the server reaches first")
	}

	got, err := st.FindTrustedDeviceByHash(ctx, first.TokenHash)
	if err != nil {
		t.Fatalf("FindTrustedDeviceByHash: %v", err)
	}
	if got.ID != first.ID {
		t.Fatalf("the hash resolves to %s, want the original %s", got.ID, first.ID)
	}
}

// TestMFAStoreTrustedDeviceLookupsUseTheIndexLive proves the planner
// actually picks trusted_devices' user_id index, with a control that drops
// it and requires the plan to degrade. It is the index behind every "your
// trusted devices" screen, every RevokeTrustedDevice ownership scan, and
// every sweep in auth.Service.ChangePassword's matrix.
//
// enable_seqscan is left alone deliberately, exactly as in
// TestMFAStoreRecoveryCodeLookupsUseTheIndexLive: forcing the planner would
// prove only that the index CAN be used.
func TestMFAStoreTrustedDeviceLookupsUseTheIndexLive(t *testing.T) {
	sqlDB, st := newLiveMFAStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	tbl := st.Schema().TrustedDevices.Name()

	target := uid.NewV7()
	for range 2 {
		if _, err := st.CreateTrustedDevice(ctx, liveTrustedDevice(target, at)); err != nil {
			t.Fatalf("CreateTrustedDevice: %v", err)
		}
	}
	for range 400 {
		if _, err := st.CreateTrustedDevice(ctx, liveTrustedDevice(uid.NewV7(), at)); err != nil {
			t.Fatalf("CreateTrustedDevice: %v", err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx, "ANALYZE "+tbl); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	byUser := fmt.Sprintf("SELECT id FROM %s WHERE user_id = $1", tbl)
	if plan := explain(t, sqlDB, byUser, target); !strings.Contains(plan, "Index") {
		t.Fatalf("ListTrustedDevices' filter does not use an index:\n%s", plan)
	}

	if _, err := sqlDB.ExecContext(ctx, "DROP INDEX "+tbl+"_user_id_idx"); err != nil {
		t.Fatalf("dropping the index: %v", err)
	}
	if plan := explain(t, sqlDB, byUser, target); !strings.Contains(plan, "Seq Scan") {
		t.Fatalf("with the index dropped the plan did not degrade to a sequential scan, so the earlier plan proves nothing:\n%s", plan)
	}
}
