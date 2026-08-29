//go:build integration

// Live end-to-end tests for the auth store against a real PostgreSQL. Run
// with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...`
// stays database-free.
//
// markRotatedContract (store/memory/auth_test.go) is NOT reused here: it is
// unexported and lives in a _test.go file (package memory_test), and Go
// test files are never part of a package's importable surface regardless of
// export — nothing outside store/memory can reach it by any name, exported
// or not. TestMarkRotatedConcurrencyExactlyOneWinnerLive below is therefore
// an independent implementation, deliberately shaped like
// raceMarkRotated/markRotatedContract and like this file's own
// TestConsumeLinkConcurrencyExactlyOneWinnerLive counterpart in
// invite_integration_test.go, rather than a re-derived approximation of a
// different contract.
package dropsstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/password"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// liveTestPassword satisfies password.DefaultRules() and is shared by the
// service-level live tests below.
const liveTestPassword = "Correct-Horse-Battery-9!"

// newLiveAuthService wires a real auth.Service over a live AuthStore. A few
// tests in this file exercise SERVICE behaviour (session revocation
// semantics) rather than store behaviour, because the defects they pin were
// reproduced against a real server and a memory-store-only regression test
// would not prove the fix holds there. bcrypt runs at MinCost so the suite
// stays fast; the default UUIDv7 id generator is left in place because the
// drops schema types every id column as uuid.
func newLiveAuthService(st *dropsstore.AuthStore) *auth.Service {
	return auth.New(st,
		auth.WithHasher(password.Bcrypt(bcrypt.MinCost)),
		auth.WithJWT([][]byte{bytes.Repeat([]byte("k"), 32)}, 15*time.Minute),
	)
}

// openLiveDB opens AUTHLAYER_TEST_DSN and wraps it in *pg.DB, skipping the
// test if the DSN is unset. It registers sqlDB.Close() as a cleanup BEFORE
// any table-dropping cleanup the caller registers afterward: t.Cleanup
// callbacks run after a test function's defers, in LIFO order, so
// registering Close here (first) means it runs LAST — a later
// table-dropping cleanup still has a live connection when it runs. See
// store/drops/integration_test.go's dropAll and
// invite_integration_test.go's newLiveInviteStore for the same pattern.
// Returns the raw *sql.DB too, since a handful of tests need it directly —
// connection-pool tuning ([newLiveAuthStoreWarmed]) or issuing DDL/queries
// drops has no builder for.
func openLiveDB(t *testing.T) (*sql.DB, *pg.DB) {
	t.Helper()
	dsn := os.Getenv("AUTHLAYER_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUTHLAYER_TEST_DSN to run the drops auth store integration test")
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return sqlDB, pg.New(stdlib.New(sqlDB))
}

// newLiveAuthStore builds a fresh AuthStore over a connection from
// AUTHLAYER_TEST_DSN, and drops/recreates all three tables so each test
// starts from an empty schema.
func newLiveAuthStore(t *testing.T) *dropsstore.AuthStore {
	t.Helper()
	_, db := openLiveDB(t)
	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()

	dropAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, st) })

	return st
}

func dropAuthTables(t *testing.T, db *pg.DB, st *dropsstore.AuthStore) {
	t.Helper()
	s := st.Schema()
	for _, tbl := range []*pg.Table{s.Sessions, s.Verifications, s.Users} {
		if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
			t.Fatalf("drop %s: %v", tbl.Name(), err)
		}
	}
}

// TestAuthStoreUserLifecycleLive exercises CreateUser, FindUserByID,
// FindUserByEmail, MarkEmailVerified, UpdateUserPassword and
// UpdateUserEmail against a real server, and proves UNIQUE(email) actually
// reached the database rather than living only in the in-memory Table
// registry.
func TestAuthStoreUserLifecycleLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	u := auth.UserBase{
		ID: uid.NewV7(), Email: "  Bob@Example.com  ", PasswordHash: "hash1",
		CreatedAt: now, UpdatedAt: now,
	}
	created, err := st.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.Email != "bob@example.com" {
		t.Fatalf("CreateUser returned Email = %q, want normalized", created.Email)
	}

	got, err := st.FindUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.Email != "bob@example.com" || got.EmailVerifiedAt != nil {
		t.Fatalf("FindUserByID = %+v", got)
	}
	if _, err := st.FindUserByID(ctx, uid.NewV7()); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByID(unknown) err = %v, want ErrUserNotFound", err)
	}

	if got, err := st.FindUserByEmail(ctx, "  BOB@example.COM "); err != nil || got.ID != u.ID {
		t.Fatalf("FindUserByEmail(variant) = %+v, %v", got, err)
	}

	// UNIQUE(email) must reach the database: a second user with the same
	// normalized address, different case/whitespace, must collide.
	dup := auth.UserBase{ID: uid.NewV7(), Email: "bob@example.com", CreatedAt: now, UpdatedAt: now}
	if _, err := st.CreateUser(ctx, dup); !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("duplicate-email CreateUser err = %v, want ErrEmailTaken", err)
	}
	// A second user under the same id must also be refused, and classified
	// as ErrIDTaken, not folded into ErrEmailTaken.
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: u.ID, Email: "someone-else@example.com"}); !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("duplicate-id CreateUser err = %v, want ErrIDTaken", err)
	}

	// MarkEmailVerified: wrong address is refused (ErrEmailMismatch), then
	// the actual current address succeeds.
	if err := st.MarkEmailVerified(ctx, u.ID, "someone-else@example.com", now); !errors.Is(err, auth.ErrEmailMismatch) {
		t.Fatalf("MarkEmailVerified(wrong address) err = %v, want ErrEmailMismatch", err)
	}
	verifiedAt := now.Add(time.Minute)
	if err := st.MarkEmailVerified(ctx, u.ID, "bob@example.com", verifiedAt); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	got, err = st.FindUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.EmailVerifiedAt == nil || !got.EmailVerifiedAt.Equal(verifiedAt) {
		t.Fatalf("EmailVerifiedAt = %v, want %v", got.EmailVerifiedAt, verifiedAt)
	}
	if !got.UpdatedAt.Equal(verifiedAt) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, verifiedAt)
	}
	if err := st.MarkEmailVerified(ctx, uid.NewV7(), "bob@example.com", now); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("MarkEmailVerified(unknown user) err = %v, want ErrUserNotFound", err)
	}

	// UpdateUserPassword.
	if err := st.UpdateUserPassword(ctx, u.ID, "new-hash", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	got, err = st.FindUserByID(ctx, u.ID)
	if err != nil || got.PasswordHash != "new-hash" {
		t.Fatalf("FindUserByID after UpdateUserPassword = %+v, %v", got, err)
	}
	if err := st.UpdateUserPassword(ctx, uid.NewV7(), "h", now); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("UpdateUserPassword(unknown) err = %v, want ErrUserNotFound", err)
	}

	// UpdateUserEmail: clears EmailVerifiedAt, normalizes, and re-checks
	// UNIQUE(email) against the OTHER live user (dup's write above failed,
	// so create a second, distinct user to collide with here).
	other := auth.UserBase{ID: uid.NewV7(), Email: "carol@example.com", CreatedAt: now, UpdatedAt: now}
	if _, err := st.CreateUser(ctx, other); err != nil {
		t.Fatalf("CreateUser(other): %v", err)
	}
	if err := st.UpdateUserEmail(ctx, u.ID, "  Carol@Example.com  ", now.Add(3*time.Minute)); !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("UpdateUserEmail(taken) err = %v, want ErrEmailTaken", err)
	}
	updateAt := now.Add(4 * time.Minute)
	if err := st.UpdateUserEmail(ctx, u.ID, "  New@Example.com  ", updateAt); err != nil {
		t.Fatalf("UpdateUserEmail: %v", err)
	}
	got, err = st.FindUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.Email != "new@example.com" {
		t.Fatalf("Email = %q, want new@example.com", got.Email)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil — UpdateUserEmail must clear it", got.EmailVerifiedAt)
	}
	if !got.UpdatedAt.Equal(updateAt) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, updateAt)
	}
	// Updating a user to the address it already holds is not a self-conflict.
	if err := st.UpdateUserEmail(ctx, u.ID, "new@example.com", now.Add(5*time.Minute)); err != nil {
		t.Fatalf("UpdateUserEmail(own address) err = %v, want nil", err)
	}
	if err := st.UpdateUserEmail(ctx, uid.NewV7(), "x@example.com", now); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("UpdateUserEmail(unknown) err = %v, want ErrUserNotFound", err)
	}
}

// TestCreateUserDuplicateEmailInsideTxReturnsErrEmailTakenLive is FIX 1's
// regression test: a duplicate-email CreateUser composed into a CALLER'S
// OWN transaction (via pg.DB.InTx, the same composition [Store.WithTx] and
// [InviteStore] callers use) must still return auth.ErrEmailTaken. An
// earlier version of CreateUser classified a unique violation by
// re-querying the table for the colliding id AFTER the INSERT had already
// failed — safe standalone, but PostgreSQL aborts a transaction the
// instant one statement inside it fails, so that follow-up read (itself
// just another statement on the same, now-doomed transaction) always came
// back as SQLSTATE 25P02 ("current transaction is aborted") instead of an
// answer — and 25P02 satisfied none of ErrEmailTaken, ErrIDTaken, or even
// the original pg.ErrUniqueViolation. See [isPrimaryKeyViolation]'s doc for
// the fix: classification now reads the failed statement's own error
// directly, issuing no further statement at all, so it cannot be affected
// by the transaction's aborted state.
func TestCreateUserDuplicateEmailInsideTxReturnsErrEmailTakenLive(t *testing.T) {
	_, db := openLiveDB(t)
	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()
	dropAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, st) })

	now := time.Now().UTC().Truncate(time.Microsecond)
	first := auth.UserBase{ID: uid.NewV7(), Email: "intx@example.com", CreatedAt: now, UpdatedAt: now}
	if _, err := st.CreateUser(ctx, first); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	dup := auth.UserBase{ID: uid.NewV7(), Email: "  InTx@Example.com  ", CreatedAt: now, UpdatedAt: now}
	txErr := db.InTx(ctx, func(txdb *pg.DB) error {
		txSt := dropsstore.NewAuthStore(txdb)
		_, err := txSt.CreateUser(ctx, dup)
		return err
	})
	if !errors.Is(txErr, auth.ErrEmailTaken) {
		t.Fatalf("CreateUser(duplicate email) inside InTx err = %v, want auth.ErrEmailTaken", txErr)
	}

	// InTx rolls back on a non-nil return, so the failed write must not
	// have landed at all.
	if _, err := st.FindUserByID(ctx, dup.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("dup user found after a rolled-back InTx: err = %v, want ErrUserNotFound", err)
	}
}

// TestCreateUserDuplicateIDInsideTxReturnsErrIDTakenLive is
// TestCreateUserDuplicateEmailInsideTxReturnsErrEmailTakenLive's
// counterpart for the OTHER branch of [isPrimaryKeyViolation]: a duplicate
// id, not a duplicate email, composed into the same caller-owned
// transaction.
func TestCreateUserDuplicateIDInsideTxReturnsErrIDTakenLive(t *testing.T) {
	_, db := openLiveDB(t)
	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()
	dropAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, st) })

	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uid.NewV7()
	first := auth.UserBase{ID: id, Email: "id-intx-1@example.com", CreatedAt: now, UpdatedAt: now}
	if _, err := st.CreateUser(ctx, first); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	dup := auth.UserBase{ID: id, Email: "id-intx-2@example.com", CreatedAt: now, UpdatedAt: now}
	txErr := db.InTx(ctx, func(txdb *pg.DB) error {
		txSt := dropsstore.NewAuthStore(txdb)
		_, err := txSt.CreateUser(ctx, dup)
		return err
	})
	if !errors.Is(txErr, auth.ErrIDTaken) {
		t.Fatalf("CreateUser(duplicate id) inside InTx err = %v, want auth.ErrIDTaken", txErr)
	}

	got, err := st.FindUserByID(ctx, id)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.Email != "id-intx-1@example.com" {
		t.Fatalf("original row's Email = %q after a rolled-back duplicate-id InTx, want it unchanged", got.Email)
	}
}

// TestAuthStoreCreateSchemaSelfHealsMissingEmailUniqueLive is FIX 2's
// regression test. UNIQUE(email) is declared inline on a fresh table's own
// CREATE TABLE, but CreateSchema's CREATE TABLE IF NOT EXISTS is a no-op
// against a users table that already exists — one created by an older
// version of this code, or by hand, before the constraint existed. Without
// email ALSO registered as a self-healing ALTER TABLE (see [AuthSchema]'s
// doc), such a table would silently accept duplicate addresses forever.
// This test builds exactly that pre-existing, deliberately-incomplete
// table by hand, runs CreateSchema, and proves the constraint landed.
func TestAuthStoreCreateSchemaSelfHealsMissingEmailUniqueLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	ctx := context.Background()

	if _, err := sqlDB.ExecContext(ctx, `DROP TABLE IF EXISTS sessions, verifications, users CASCADE`); err != nil {
		t.Fatal(err)
	}
	// A hand-built users table with every column CreateSchema expects, but
	// deliberately missing UNIQUE(email) — simulating a table that predates
	// the constraint.
	if _, err := sqlDB.ExecContext(ctx, `CREATE TABLE users (
		id uuid NOT NULL PRIMARY KEY,
		email text NOT NULL,
		email_verified_at timestamptz,
		password_hash text NOT NULL,
		created_at timestamptz NOT NULL,
		updated_at timestamptz NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DROP TABLE IF EXISTS sessions, verifications, users CASCADE`)
	})

	st := dropsstore.NewAuthStore(db)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: uid.NewV7(), Email: "heal@example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, err := st.CreateUser(ctx, auth.UserBase{ID: uid.NewV7(), Email: "heal@example.com", CreatedAt: now, UpdatedAt: now})
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("second CreateUser with the same email err = %v, want ErrEmailTaken — UNIQUE(email) did not self-heal onto the pre-existing table", err)
	}
}

// TestAuthStoreSessionLifecycleLive exercises CreateSession,
// FindSessionByHash, ListSessionsByUser, DeleteSession and
// DeleteSessionsByFamily, and proves UNIQUE(token_hash) on sessions
// actually reached the database.
func TestAuthStoreSessionLifecycleLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()

	sess := auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "sess-hash-1", FamilyID: uid.NewV7(),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UserAgent: "ua", IP: "1.2.3.4",
	}
	created, err := st.CreateSession(ctx, sess)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if created != sess {
		t.Fatalf("CreateSession returned %+v, want %+v unchanged", created, sess)
	}

	got, err := st.FindSessionByHash(ctx, "sess-hash-1")
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if got.ID != sess.ID || got.RotatedAt != nil {
		t.Fatalf("FindSessionByHash = %+v", got)
	}
	if _, err := st.FindSessionByHash(ctx, "nope"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(unknown) err = %v, want ErrSessionNotFound", err)
	}

	// UNIQUE(token_hash) must reach the database.
	dup := auth.Session{ID: uid.NewV7(), UserID: userID, TokenHash: "sess-hash-1", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if _, err := st.CreateSession(ctx, dup); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate token_hash CreateSession err = %v, want pg.ErrUniqueViolation", err)
	}
	if _, err := st.CreateSession(ctx, auth.Session{ID: sess.ID, UserID: userID, TokenHash: "sess-hash-other"}); !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("duplicate id CreateSession err = %v, want ErrIDTaken", err)
	}

	second := auth.Session{ID: uid.NewV7(), UserID: userID, TokenHash: "sess-hash-2", FamilyID: sess.FamilyID, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if _, err := st.CreateSession(ctx, second); err != nil {
		t.Fatalf("CreateSession(second): %v", err)
	}
	otherUserSess := auth.Session{ID: uid.NewV7(), UserID: uid.NewV7(), TokenHash: "sess-hash-3", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if _, err := st.CreateSession(ctx, otherUserSess); err != nil {
		t.Fatalf("CreateSession(other user): %v", err)
	}

	list, err := st.ListSessionsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListSessionsByUser = %d, want 2: %+v", len(list), list)
	}
	empty, err := st.ListSessionsByUser(ctx, uid.NewV7())
	if err != nil || len(empty) != 0 {
		t.Fatalf("ListSessionsByUser(unknown user) = %v, %v", empty, err)
	}

	if err := st.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := st.FindSessionByHash(ctx, "sess-hash-1"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash after delete: err = %v, want ErrSessionNotFound", err)
	}
	if err := st.DeleteSession(ctx, sess.ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("second DeleteSession err = %v, want ErrSessionNotFound", err)
	}

	if err := st.DeleteSessionsByFamily(ctx, sess.FamilyID); err != nil {
		t.Fatalf("DeleteSessionsByFamily: %v", err)
	}
	if _, err := st.FindSessionByHash(ctx, "sess-hash-2"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("family member survived DeleteSessionsByFamily")
	}
	if _, err := st.FindSessionByHash(ctx, "sess-hash-3"); err != nil {
		t.Fatalf("other family's session should have survived, got err = %v", err)
	}
	if err := st.DeleteSessionsByFamily(ctx, uid.NewV7()); err != nil {
		t.Fatalf("DeleteSessionsByFamily(no matches): %v", err)
	}
}

// TestAuthStoreVerificationLifecycleLive exercises CreateVerification,
// FindVerificationByHash, DeleteVerification and
// DeleteVerificationsByUserAndPurpose, and proves UNIQUE(token_hash) on
// verifications actually reached the database.
func TestAuthStoreVerificationLifecycleLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()

	v := auth.Verification{
		ID: uid.NewV7(), UserID: userID, TokenHash: "ver-hash-1", Purpose: "signup",
		Email: "  Bob@Example.com  ", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	created, err := st.CreateVerification(ctx, v)
	if err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}
	if created.Email != "bob@example.com" {
		t.Fatalf("CreateVerification returned Email = %q, want normalized", created.Email)
	}

	got, err := st.FindVerificationByHash(ctx, "ver-hash-1")
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if got.ID != v.ID || got.Purpose != "signup" || got.Email != "bob@example.com" {
		t.Fatalf("FindVerificationByHash = %+v", got)
	}
	if _, err := st.FindVerificationByHash(ctx, "nope"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(unknown) err = %v, want ErrVerificationNotFound", err)
	}

	// UNIQUE(token_hash) must reach the database.
	dup := auth.Verification{ID: uid.NewV7(), UserID: userID, TokenHash: "ver-hash-1", Purpose: "signup", Email: "x@example.com", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if _, err := st.CreateVerification(ctx, dup); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate token_hash CreateVerification err = %v, want pg.ErrUniqueViolation", err)
	}
	if _, err := st.CreateVerification(ctx, auth.Verification{ID: v.ID, UserID: userID, TokenHash: "ver-hash-other"}); !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("duplicate id CreateVerification err = %v, want ErrIDTaken", err)
	}

	v2 := auth.Verification{ID: uid.NewV7(), UserID: userID, TokenHash: "ver-hash-2", Purpose: "password_reset", Email: "bob@example.com", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	v3 := auth.Verification{ID: uid.NewV7(), UserID: userID, TokenHash: "ver-hash-3", Purpose: "email_change", Email: "new@example.com", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	v4 := auth.Verification{ID: uid.NewV7(), UserID: uid.NewV7(), TokenHash: "ver-hash-4", Purpose: "password_reset", Email: "other@example.com", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	for _, x := range []auth.Verification{v2, v3, v4} {
		if _, err := st.CreateVerification(ctx, x); err != nil {
			t.Fatalf("CreateVerification(%s): %v", x.ID, err)
		}
	}

	if err := st.DeleteVerification(ctx, v.ID); err != nil {
		t.Fatalf("DeleteVerification: %v", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "ver-hash-1"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash after delete: err = %v, want ErrVerificationNotFound", err)
	}
	if err := st.DeleteVerification(ctx, v.ID); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("second DeleteVerification err = %v, want ErrVerificationNotFound", err)
	}

	// DeleteVerificationsByUserAndPurpose removes only (userID,
	// password_reset) — v2, not v3 (different purpose) or v4 (different
	// user).
	if err := st.DeleteVerificationsByUserAndPurpose(ctx, userID, "password_reset"); err != nil {
		t.Fatalf("DeleteVerificationsByUserAndPurpose: %v", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "ver-hash-2"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("v2 survived DeleteVerificationsByUserAndPurpose")
	}
	if _, err := st.FindVerificationByHash(ctx, "ver-hash-3"); err != nil {
		t.Fatalf("v3 (different purpose) should have survived, got err = %v", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "ver-hash-4"); err != nil {
		t.Fatalf("v4 (different user) should have survived, got err = %v", err)
	}
	if err := st.DeleteVerificationsByUserAndPurpose(ctx, uid.NewV7(), "signup"); err != nil {
		t.Fatalf("DeleteVerificationsByUserAndPurpose(no matches): %v", err)
	}
}

// TestMarkRotatedLive is MarkRotated's sequential counterpart to
// store/memory/auth_test.go's TestMarkRotatedFirstCallerWins /
// TestMarkRotatedSecondCallFails / TestMarkRotatedNotFound /
// TestMarkRotatedIgnoresExpiry, run against a real server: the single
// UPDATE...RETURNING statement's shape (see [dropsstore.AuthStore.MarkRotated])
// only matters if it produces these exact outcomes against PostgreSQL
// itself, not just against the fake driver.
func TestMarkRotatedLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	sess, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: uid.NewV7(), TokenHash: "rot-hash-1", FamilyID: uid.NewV7(),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	rotatedAt := now.Add(time.Minute)
	got, ok, err := st.MarkRotated(ctx, "rot-hash-1", rotatedAt)
	if err != nil {
		t.Fatalf("MarkRotated (first): %v", err)
	}
	if !ok {
		t.Fatal("MarkRotated (first) ok = false, want true for a fresh session")
	}
	if got.RotatedAt == nil || !got.RotatedAt.Equal(rotatedAt) {
		t.Fatalf("MarkRotated (first) RotatedAt = %v, want %v", got.RotatedAt, rotatedAt)
	}
	if got.ID != sess.ID || got.TokenHash != sess.TokenHash {
		t.Fatalf("MarkRotated (first) returned session %+v, want the same row as %+v", got, sess)
	}

	// Replay: the same token presented again must lose, and must return the
	// FIRST rotation's stamp, not overwrite it.
	second := rotatedAt.Add(time.Minute)
	got2, ok2, err := st.MarkRotated(ctx, "rot-hash-1", second)
	if err != nil {
		t.Fatalf("MarkRotated (replay) err = %v, want nil (a lost race is not an error)", err)
	}
	if ok2 {
		t.Fatal("MarkRotated (replay) ok = true against an already-rotated session, want false")
	}
	if got2.RotatedAt == nil || !got2.RotatedAt.Equal(rotatedAt) {
		t.Fatalf("MarkRotated (replay) RotatedAt = %v, want the FIRST rotation's stamp %v", got2.RotatedAt, rotatedAt)
	}

	if _, ok, err := st.MarkRotated(ctx, "no-such-hash", now); !errors.Is(err, auth.ErrSessionNotFound) || ok {
		t.Fatalf("MarkRotated(unknown hash) = ok=%v err=%v, want ok=false err=ErrSessionNotFound", ok, err)
	}

	// Expiry must not gate rotation.
	expired, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: uid.NewV7(), TokenHash: "rot-hash-expired",
		ExpiresAt: now.Add(-time.Hour), CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateSession(expired): %v", err)
	}
	if _, ok, err := st.MarkRotated(ctx, expired.TokenHash, now); err != nil || !ok {
		t.Fatalf("MarkRotated(expired-but-unrotated) = ok=%v err=%v, want ok=true err=nil", ok, err)
	}
}

// TestCreateSuccessorSessionSucceedsWhenPredecessorExistsLive is the
// ordinary path: the predecessor is still there, so the successor is
// inserted and ok is true.
func TestCreateSuccessorSessionSucceedsWhenPredecessorExistsLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()
	familyID := uid.NewV7()

	rotatedAt := now
	pred, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "csx-pred-1", FamilyID: familyID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, RotatedAt: &rotatedAt,
	})
	if err != nil {
		t.Fatalf("CreateSession(predecessor): %v", err)
	}

	succ := auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "csx-succ-1", FamilyID: familyID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	got, ok, err := st.CreateSuccessorSession(ctx, pred.ID, succ)
	if err != nil {
		t.Fatalf("CreateSuccessorSession: %v", err)
	}
	if !ok {
		t.Fatal("CreateSuccessorSession ok = false, want true — the predecessor exists")
	}
	if got.ID != succ.ID {
		t.Fatalf("CreateSuccessorSession returned id %q, want %q", got.ID, succ.ID)
	}

	stored, err := st.FindSessionByHash(ctx, "csx-succ-1")
	if err != nil {
		t.Fatalf("FindSessionByHash(successor): %v", err)
	}
	if stored.ID != succ.ID || stored.RotatedAt != nil {
		t.Fatalf("stored successor = %+v, want ID=%q RotatedAt=nil", stored, succ.ID)
	}
}

// TestCreateSuccessorSessionRefusesResurrectionAfterFamilyRevokedLive is the
// live reproduction of FIX 1's Critical directly: DeleteSessionsByFamily is
// run to COMPLETE COMPLETION first — exactly the sequencing the review
// reproduced against the unconditional CreateSession this method replaced
// ("family revoked down to zero sessions, the winner's insert then lands,
// leaving one live session") — and only THEN is CreateSuccessorSession
// attempted against the now-gone predecessor. Against the fixed
// implementation this must refuse: ok=false, no error, and the row count
// stays at zero — no resurrection.
func TestCreateSuccessorSessionRefusesResurrectionAfterFamilyRevokedLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()
	familyID := uid.NewV7()

	rotatedAt := now
	pred, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "csx-pred-2", FamilyID: familyID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, RotatedAt: &rotatedAt,
	})
	if err != nil {
		t.Fatalf("CreateSession(predecessor): %v", err)
	}

	// The reuse-detection response, run to completion BEFORE the winner's
	// own successor insert is attempted — the exact sequencing the review
	// reproduced.
	if err := st.DeleteSessionsByFamily(ctx, familyID); err != nil {
		t.Fatalf("DeleteSessionsByFamily: %v", err)
	}
	if _, err := st.FindSessionByHash(ctx, "csx-pred-2"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("predecessor still present after DeleteSessionsByFamily: err = %v", err)
	}

	succ := auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "csx-succ-2", FamilyID: familyID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	got, ok, err := st.CreateSuccessorSession(ctx, pred.ID, succ)
	if err != nil {
		t.Fatalf("CreateSuccessorSession err = %v, want nil (a lost race is not a failure)", err)
	}
	if ok {
		t.Fatal("CreateSuccessorSession ok = true against an already-revoked family — this is the resurrection bug FIX 1 closes")
	}
	if got != (auth.Session{}) {
		t.Fatalf("CreateSuccessorSession returned %+v, want the zero value", got)
	}

	// The critical assertion: the successor must NOT be findable — no
	// resurrection, the family stays exactly as revoked as
	// DeleteSessionsByFamily left it.
	if _, err := st.FindSessionByHash(ctx, "csx-succ-2"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(successor) err = %v, want ErrSessionNotFound — the family was resurrected with a live session", err)
	}
	list, err := st.ListSessionsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after a revoked family's rotation was attempted; want 0", len(list))
	}
}

// TestCreateSuccessorSessionDuplicateIDFailsLive pins that s.ID's own
// uniqueness is still enforced against a real server, independent of
// predecessorID's existence — the live counterpart to
// store/memory/auth_test.go's TestCreateSuccessorSessionDuplicateIDFails.
func TestCreateSuccessorSessionDuplicateIDFailsLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()
	familyID := uid.NewV7()

	rotatedAt := now
	pred, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "csx-pred-3", FamilyID: familyID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, RotatedAt: &rotatedAt,
	})
	if err != nil {
		t.Fatalf("CreateSession(predecessor): %v", err)
	}
	existing, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "csx-existing-3",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateSession(existing): %v", err)
	}

	_, ok, err := st.CreateSuccessorSession(ctx, pred.ID, auth.Session{
		ID: existing.ID, UserID: userID, TokenHash: "csx-new-3",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("CreateSuccessorSession(duplicate id) err = %v, want ErrIDTaken", err)
	}
	if ok {
		t.Fatal("CreateSuccessorSession ok = true despite ErrIDTaken")
	}

	// The original row must be untouched, AND the predecessor must NOT have
	// been consumed by the rolled-back transaction — it is still there for
	// a genuine successor to be minted against later.
	got, err := st.FindSessionByHash(ctx, "csx-existing-3")
	if err != nil || got.ID != existing.ID {
		t.Fatalf("original row disturbed: got=%+v err=%v", got, err)
	}
	if _, err := st.FindSessionByHash(ctx, "csx-pred-3"); err != nil {
		t.Fatalf("predecessor missing after a rolled-back duplicate-id CreateSuccessorSession: %v", err)
	}
}

// TestCreateSuccessorSessionIDTakenCheckedEvenWhenPredecessorGoneLive is
// FIX 4's live regression test: auth.Store's own contract on
// CreateSuccessorSession requires s.ID's uniqueness to be "checked as part
// of the same atomic step, independent of predecessorID's own existence" —
// store/memory's TestCreateSuccessorSessionIDTakenCheckedEvenWhenPredecessorGone
// pins this already; this is the live counterpart against a real server.
// Unlike TestCreateSuccessorSessionDuplicateIDFailsLive above (whose
// predecessor DOES exist, so the id collision is caught by the real
// server's own PRIMARY KEY constraint on the INSERT attempt), this test
// deliberately has NO predecessor row at all: before this fix, that made
// AuthStore's SELECT ... FOR UPDATE return pg.ErrNoRows and short-circuit
// straight to (zero, false, nil) — masking the id collision entirely rather
// than reporting auth.ErrIDTaken.
func TestCreateSuccessorSessionIDTakenCheckedEvenWhenPredecessorGoneLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()

	existing, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "csx-idtaken-existing",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateSession(existing): %v", err)
	}

	_, ok, err := st.CreateSuccessorSession(ctx, uid.NewV7() /* no such predecessor */, auth.Session{
		ID: existing.ID, UserID: userID, TokenHash: "csx-idtaken-new",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("CreateSuccessorSession err = %v, want ErrIDTaken — the id collision must be reported even though the predecessor never existed at all", err)
	}
	if ok {
		t.Fatal("CreateSuccessorSession ok = true despite ErrIDTaken")
	}

	// The original row must be untouched by the rolled-back transaction.
	got, err := st.FindSessionByHash(ctx, "csx-idtaken-existing")
	if err != nil || got.ID != existing.ID {
		t.Fatalf("original row disturbed: got=%+v err=%v", got, err)
	}
}

// TestCreateSuccessorSessionForUpdateBlocksUncommittedDeleteLive is FIX 1's
// mandatory regression test: it pins that .ForUpdate() on
// CreateSuccessorSession's own predecessor SELECT is load-bearing, not
// decorative. In the InTx-then-SELECT-then-INSERT shape this method uses,
// FOR UPDATE is the ONLY thing that makes the check-then-insert behave
// correctly against a concurrently in-flight (uncommitted) DELETE targeting
// the same predecessor row: without it, a plain SELECT answers from its own
// statement snapshot under READ COMMITTED and cannot see an uncommitted
// DELETE at all — it reports the predecessor present and the INSERT
// proceeds, resurrecting a family a concurrent revocation is in the middle
// of removing, even though that revocation ultimately commits and wins.
//
// This is driven against raw SQL on a second, dedicated connection — not
// through [dropsstore.AuthStore.DeleteSessionsByFamily] itself, which,
// after FIX 2, takes its own SELECT ... FOR UPDATE lock and would therefore
// block trying to acquire the very same row this test's own held
// transaction already locks, rather than staying simply "in flight,
// uncommitted" the way this test needs to stage. BEGIN; DELETE FROM
// sessions WHERE family_id = $1, held open without COMMIT, is exactly "a
// DELETE that has not yet committed" — the scenario FOR UPDATE exists to
// make CreateSuccessorSession wait for.
func TestCreateSuccessorSessionForUpdateBlocksUncommittedDeleteLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()
	dropAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, st) })

	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()
	familyID := uid.NewV7()
	rotatedAt := now
	pred, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "fu-pred-1", FamilyID: familyID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, RotatedAt: &rotatedAt,
	})
	if err != nil {
		t.Fatalf("CreateSession(predecessor): %v", err)
	}

	// A second, dedicated raw connection: BEGIN a transaction and DELETE the
	// family, but never commit it yet — an uncommitted delete in flight.
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		t.Fatalf("sqlDB.Conn: %v", err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	// Rollback is a safe no-op once Commit has already succeeded below (it
	// returns sql.ErrTxDone, discarded here) — this guarantees the raw
	// transaction never lingers open if a t.Fatal[f] on any path between
	// here and the real Commit call below short-circuits this goroutine via
	// runtime.Goexit, which would otherwise leave an uncommitted
	// transaction holding a lock that t.Cleanup's own DROP TABLE (a
	// DIFFERENT connection) would then block on indefinitely.
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE family_id = $1", familyID); err != nil {
		t.Fatalf("raw DELETE: %v", err)
	}

	succ := auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "fu-succ-1", FamilyID: familyID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	type result struct {
		sess auth.Session
		ok   bool
		err  error
	}
	done := make(chan result, 1)
	go func() {
		s, ok, cerr := st.CreateSuccessorSession(ctx, pred.ID, succ)
		done <- result{s, ok, cerr}
	}()

	select {
	case <-done:
		t.Fatal("CreateSuccessorSession returned before the concurrent, uncommitted DELETE was committed — .ForUpdate() is not blocking on the locked predecessor row")
	case <-time.After(200 * time.Millisecond):
		// Still blocked, as expected — the predecessor row is locked by the
		// uncommitted raw DELETE above.
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit raw DELETE: %v", err)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("CreateSuccessorSession err = %v, want nil (a lost race is not a failure)", r.err)
	}
	if r.ok {
		t.Fatal("CreateSuccessorSession ok = true after the family was deleted out from under it — this is the resurrection FIX 1 exists to prevent")
	}
	if r.sess != (auth.Session{}) {
		t.Fatalf("CreateSuccessorSession returned %+v, want the zero value", r.sess)
	}

	if _, err := st.FindSessionByHash(ctx, "fu-succ-1"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(successor) err = %v, want ErrSessionNotFound — no resurrection", err)
	}
}

// TestDeleteSessionsByFamilyRemovesConcurrentlyMintedSuccessorLive is FIX
// 2's mandatory live regression test — the CRITICAL closed this round. It
// reproduces the exact lock ordering the review measured directly:
// CreateSuccessorSession wins the predecessor's FOR UPDATE lock FIRST and,
// while holding it (about to insert but not yet committed), a concurrent
// DeleteSessionsByFamily call blocks trying to acquire that same row's
// lock. Once the lock holder commits (inserting the successor and
// releasing the lock), the review measured DeleteSessionsByFamily's PRIOR,
// single-autocommit-DELETE implementation removing exactly one row — the
// predecessor — and leaving the freshly-minted successor as the family's
// sole survivor: no SERIAL ordering of the two calls produces that outcome
// (either DeleteSessionsByFamily's DELETE runs entirely before the SELECT
// that finds the predecessor — nothing to insert against — or entirely
// after the INSERT commits — both rows exist for the DELETE to remove), so
// this is a genuine concurrency anomaly, not a benign reordering.
//
// Against the fixed, lock-then-delete DeleteSessionsByFamily this must
// instead remove BOTH rows: its own DELETE statement re-snapshots only
// AFTER its SELECT ... FOR UPDATE has finished waiting on the row lock, by
// which point the successor is already committed and visible.
//
// Driven the same way as the FIX 1 test above: a second, dedicated raw
// connection stands in for "CreateSuccessorSession has won the lock and is
// about to insert, but has not committed yet" by taking the SELECT ... FOR
// UPDATE and the successor's own INSERT directly, with the commit withheld
// until after this test has confirmed the real DeleteSessionsByFamily call
// is genuinely blocked on the still-held lock.
func TestDeleteSessionsByFamilyRemovesConcurrentlyMintedSuccessorLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()
	dropAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, st) })

	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()
	familyID := uid.NewV7()
	rotatedAt := now
	pred, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: userID, TokenHash: "lo-pred-1", FamilyID: familyID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, RotatedAt: &rotatedAt,
	})
	if err != nil {
		t.Fatalf("CreateSession(predecessor): %v", err)
	}

	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		t.Fatalf("sqlDB.Conn: %v", err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	// Same reasoning as TestCreateSuccessorSessionForUpdateBlocksUncommittedDeleteLive's
	// own identical defer: guarantees this raw transaction never lingers
	// open (holding the predecessor's row lock) across a t.Fatal[f] on any
	// path below, which would otherwise deadlock t.Cleanup's own DROP TABLE.
	defer func() { _ = tx.Rollback() }()
	var lockedID string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM sessions WHERE id = $1 FOR UPDATE", pred.ID).Scan(&lockedID); err != nil {
		t.Fatalf("raw SELECT ... FOR UPDATE: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- st.DeleteSessionsByFamily(ctx, familyID) }()

	select {
	case derr := <-done:
		t.Fatalf("DeleteSessionsByFamily returned (err=%v) before the concurrent, uncommitted successor insert was committed — its own SELECT ... FOR UPDATE is not blocking on the locked predecessor row", derr)
	case <-time.After(200 * time.Millisecond):
		// Still blocked, as expected.
	}

	// Insert the successor — exactly what CreateSuccessorSession's own
	// insertSession would do — and commit, releasing the predecessor lock.
	succHash := "lo-succ-1"
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, token_hash, family_id, expires_at, created_at, rotated_at, user_agent, ip)
		 VALUES ($1,$2,$3,$4,$5,$6,NULL,'','')`,
		uid.NewV7(), userID, succHash, familyID, now.Add(time.Hour), now); err != nil {
		t.Fatalf("raw INSERT(successor): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit raw tx: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("DeleteSessionsByFamily: %v", err)
	}

	if _, err := st.FindSessionByHash(ctx, pred.TokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("predecessor survived DeleteSessionsByFamily: err = %v, want ErrSessionNotFound", err)
	}
	if _, err := st.FindSessionByHash(ctx, succHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("concurrently-minted successor survived DeleteSessionsByFamily: err = %v, want ErrSessionNotFound — this is the resurrection FIX 2 closes", err)
	}
}

// TestDeleteSessionsByFamilyConcurrentSameFamilyBothSucceedLive is round
// 3's FIX 1 positive-path regression test: two GENUINELY concurrent calls
// to the real, exported DeleteSessionsByFamily, targeting the SAME family,
// must both succeed and leave zero survivors — the ordinary, non-hostile
// case (two browser tabs both triggering LogoutAll, or a reuse-detection
// revocation racing an explicit logout) that the revocation-versus-
// revocation fix below must not turn into a false-positive failure.
//
// This test alone cannot demonstrate the deadlock the fix closes: two
// textually identical, unordered SELECT ... FOR UPDATE queries against a
// small, static row set deterministically visit rows in the SAME physical
// order in this environment — confirmed directly, not assumed: 1960
// rounds of exactly this scenario (rows/family between 20 and 500, run
// against the PRE-advisory-lock code) produced 0 deadlocks. The mechanism
// itself, and the fix, are proven instead by
// TestDeleteSessionsByFamilyOppositeLockOrderRequiresAdvisoryLockLive
// below, which deliberately constructs the opposite-order condition this
// test cannot organically reach at this scale. See this package's own task
// report for the measurement.
func TestDeleteSessionsByFamilyConcurrentSameFamilyBothSucceedLive(t *testing.T) {
	const rows = 20
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()
	familyID := uid.NewV7()

	for i := 0; i < rows; i++ {
		rotated := now
		if _, err := st.CreateSession(ctx, auth.Session{
			ID: uid.NewV7(), UserID: userID, TokenHash: uid.NewV7(), FamilyID: familyID,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now, RotatedAt: &rotated,
		}); err != nil {
			t.Fatalf("seed CreateSession %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			errs[i] = st.DeleteSessionsByFamily(ctx, familyID)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("DeleteSessionsByFamily call %d: %v", i, err)
		}
	}

	left, err := st.ListSessionsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after both concurrent deletes, want 0", len(left))
	}
}

// TestDeleteSessionsByFamilyOppositeLockOrderRequiresAdvisoryLockLive is
// the mandatory mutation-check target for round 3's FIX 1: it deliberately
// constructs the exact lock-order inversion
// [AuthStore.DeleteSessionsByFamily]'s "Revocation-versus-revocation" doc
// section describes, since two REAL concurrent calls cannot be relied on
// to reach it organically in every environment — see
// TestDeleteSessionsByFamilyConcurrentSameFamilyBothSucceedLive's own doc
// for the 1960-round measurement that found no natural divergence here.
// SELECT ... FOR UPDATE with no ORDER BY gives PostgreSQL no obligation to
// lock a family's rows in any particular order — the planner is free to
// choose sequential-scan physical order, an index-scan order via
// sessions_family_id_idx, or (at production scale, under
// synchronize_seqscans or genuine concurrent write load) something that
// varies run to run. This test does not wait for that variance to appear
// on its own; it forces it, by racing the real DeleteSessionsByFamily
// (call A, natural/unordered — confirmed directly, via EXPLAIN and by
// reading back the row order, to be ascending id order against this exact
// schema and seed) against a second, raw connection (call B) that locks
// the SAME family's rows in the OPPOSITE, explicit order (highest id to
// lowest) — a worst-case-equivalent stand-in for whatever order a second
// concurrent caller's own unordered scan could legally choose.
//
// Call B locks one row per statement — seedRows separate round trips,
// walking ids high to low — rather than issuing its own single combined
// "ORDER BY id DESC ... FOR UPDATE". That combined form was tried first
// and never once produced a deadlock: call A's single, fast, entirely
// server-side statement (no per-row network round trip) reliably locks,
// deletes and commits all seedRows rows before a second combined
// statement even returns from the network, so the two never actually hold
// conflicting locks at the same instant. Pacing call B's own locking out
// over real wall-clock time — one ordinary network + parse/plan/execute
// round trip per row — gives call A's fast sweep something to
// meaningfully overlap with. Confirmed empirically at seedRows=300: call A
// reliably blocks part-way through its scan, call B reliably blocks
// part-way through its own reverse walk, PostgreSQL's deadlock detector
// reliably fires after its default ~1s deadlock_timeout, and call A —
// never call B — is reliably the aborted victim, matching what the
// coordinator's own measurement against the real store reported ("the
// victim always being DeleteSessionsByFamily").
//
// Call B is not a black box standing in for "some other client": it
// reissues the IDENTICAL first statement DeleteSessionsByFamily itself
// does — the same
// pg_advisory_xact_lock(hashtext('authlayer:sessions:family'), hashtext($1))
// call, with the same two arguments — before its own row-locking loop, so
// this test exercises the real serialization mechanism, not an
// approximation of it: pg_advisory_xact_lock is keyed globally by its two
// integer arguments, identical across any session or connection that
// calls it with the same key, so call A's real advisory-lock acquisition
// (when the fix is in place) genuinely blocks call B here, and vice versa.
// If a future change to DeleteSessionsByFamily's own advisory-lock
// statement text or key derivation drifts from what is hardcoded here,
// this test's own assumption (that B contends for THE SAME lock A takes)
// silently stops holding — keep the two in sync.
//
// With the fix in place, this is deterministic, not merely likely:
// whichever of A/B acquires the advisory lock first runs to completion
// (deleting every row) before the other is even unblocked — the lock is
// held for the acquiring transaction's full duration — so the second one's
// own row-locking (in either order) finds nothing left to lock: both
// succeed, zero survivors, no deadlock possible by construction, and both
// finish in well under a second (confirmed: ~100-125ms each). Mutation-
// checked by removing the production pg_advisory_xact_lock call: call A
// then proceeds directly to its unordered scan with no gate at all, racing
// call B's explicit reverse-order walk for real — SQLSTATE 40P01 after
// PostgreSQL's own ~1s deadlock_timeout, reliably against call A.
//
// "The second one's own row-locking finds nothing left to lock" is not
// just prose above — it is call B's OWN outcome whenever A wins the
// advisory lock first, and it is the CORRECT, fix-working outcome, not a
// failure: call B's per-row loop then receives sql.ErrNoRows on the very
// first id it tries (A, having exclusively held the family since before
// B's own advisory-lock call unblocked, has already deleted everything).
// An earlier version of this test treated ANY error from that loop —
// including this one — as a test failure, which made the test itself
// flaky in proportion to how often call A happened to win: reproduced
// directly, roughly 10% of runs (2/25 cold-pool, 7/30 warm-pool) failed
// with "want nil" on exactly this legitimate sql.ErrNoRows. The loop below
// treats sql.ErrNoRows specially — stop walking, let call B's own
// zero-row DELETE/COMMIT run harmlessly, fall through to the shared
// zero-survivors assertion — while any OTHER error (in particular a
// genuine "deadlock detected", SQLSTATE 40P01, which is what the mutation
// check above actually produces) still fails the test exactly as before.
// This keeps the test's mutation-detection bite intact while removing the
// false failure on the fix's own intended behavior.
func TestDeleteSessionsByFamilyOppositeLockOrderRequiresAdvisoryLockLive(t *testing.T) {
	const seedRows = 300
	sqlDB, db := openLiveDB(t)
	// Warm the pool to at least 2 live connections before the race, the
	// same reasoning as [newLiveAuthStoreWarmed]'s own doc: call A's pool
	// checkout (inside DeleteSessionsByFamily's InTx) and call B's own
	// sqlDB.Conn below must both be satisfied from an already-open
	// connection, not a fresh TCP + auth round trip — an unwarmed pool lets
	// one side's connection-setup latency dwarf the other's, so they never
	// actually race for the same rows at the same time.
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)
	{
		var warm sync.WaitGroup
		warm.Add(4)
		for i := 0; i < 4; i++ {
			go func() {
				defer warm.Done()
				var one int
				if err := sqlDB.QueryRowContext(context.Background(), "SELECT 1").Scan(&one); err != nil {
					t.Errorf("pool warm-up query: %v", err)
				}
			}()
		}
		warm.Wait()
	}

	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()
	dropAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, st) })

	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uid.NewV7()
	familyID := uid.NewV7()
	ids := make([]string, 0, seedRows)
	for i := 0; i < seedRows; i++ {
		id := uid.NewV7()
		rotated := now
		if _, err := st.CreateSession(ctx, auth.Session{
			ID: id, UserID: userID, TokenHash: uid.NewV7(), FamilyID: familyID,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now, RotatedAt: &rotated,
		}); err != nil {
			t.Fatalf("seed CreateSession %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	// uid.NewV7 is time-ordered, so ids is already ascending — the same
	// order DeleteSessionsByFamily's own unordered SELECT ... FOR UPDATE
	// naturally produces here (confirmed directly against this exact
	// query+schema: a Bitmap Heap Scan over sessions_family_id_idx that
	// returns rows in ascending id order for a freshly-seeded family, on
	// this PostgreSQL version and configuration — see this package's own
	// task report for the probe). Call B below walks ids in the OPPOSITE
	// direction, one row at a time, to force a genuine opposite-order
	// interleaving against call A's single combined, fast statement.

	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		t.Fatalf("sqlDB.Conn: %v", err)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	var aErr, bErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		aStart := time.Now()
		aErr = st.DeleteSessionsByFamily(ctx, familyID)
		t.Logf("call A (real DeleteSessionsByFamily) finished in %v, err=%v", time.Since(aStart), aErr)
	}()
	go func() {
		defer wg.Done()
		tx, txErr := conn.BeginTx(ctx, nil)
		if txErr != nil {
			bErr = txErr
			return
		}
		// Safe no-op once Commit has already succeeded — same reasoning as
		// this file's other raw-connection tests: guarantees this raw
		// transaction never lingers open (holding a row or advisory lock)
		// if this goroutine returns early on any path below.
		defer func() { _ = tx.Rollback() }()

		if _, err := tx.ExecContext(ctx,
			"SELECT pg_advisory_xact_lock(hashtext('authlayer:sessions:family'), hashtext($1))",
			familyID); err != nil {
			bErr = err
			return
		}
		// Lock every row individually, walking ids HIGH to LOW — the
		// opposite of call A's ascending order — as seedRows separate
		// round trips rather than one combined statement. Call A's own
		// combined SELECT ... FOR UPDATE locks all of its rows within a
		// single, fast, server-side statement; without deliberately
		// drawing call B's own locking out over real wall-clock time the
		// same way, one side reliably finishes (and commits) before the
		// other even starts, and the two never actually contend for the
		// same row at the same time — confirmed directly: a single
		// combined ORDER BY id DESC statement here never once produced a
		// deadlock (see the task report). One row per statement is slow
		// enough, purely from ordinary network + parse/plan/execute
		// overhead per round trip, to reliably overlap with call A's own
		// (much faster) sweep from the other end.
		raceStart := time.Now()
		aWonRace := false
		for i := len(ids) - 1; i >= 0; i-- {
			var locked string
			if err := tx.QueryRowContext(ctx, "SELECT id FROM sessions WHERE id = $1 FOR UPDATE", ids[i]).Scan(&locked); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					// Call A won the advisory lock ahead of call B — exactly
					// what the fix is SUPPOSED to allow — and has already
					// deleted this row, and by construction (DELETE FROM
					// sessions WHERE family_id = $1 removes the WHOLE
					// family in one statement) every other row in the
					// family too. This is not a failure: stop walking and
					// fall through to the DELETE/COMMIT below (which will
					// correctly affect zero rows) and the final
					// zero-survivors assertion. Only a genuine deadlock
					// (SQLSTATE 40P01, NOT sql.ErrNoRows) means the mutual
					// lock failed to serialize the two calls — that still
					// falls through to the bErr branch below unchanged.
					aWonRace = true
					break
				}
				t.Logf("call B (raw, reverse order) failed after locking %d/%d rows in %v: %v", len(ids)-1-i, len(ids), time.Since(raceStart), err)
				bErr = err
				return
			}
		}
		if aWonRace {
			t.Logf("call B (raw, reverse order) found call A had already won and deleted the family, after %v", time.Since(raceStart))
		} else {
			t.Logf("call B (raw, reverse order) locked all %d rows in %v", len(ids), time.Since(raceStart))
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE family_id = $1", familyID); err != nil {
			bErr = err
			return
		}
		bErr = tx.Commit()
	}()
	wg.Wait()

	left, lerr := st.ListSessionsByUser(ctx, userID)
	if lerr != nil {
		t.Fatalf("ListSessionsByUser: %v", lerr)
	}
	t.Logf("survivors = %d", len(left))

	if aErr != nil {
		t.Fatalf("DeleteSessionsByFamily (call A): %v — want nil (a lock-order deadlock here means the advisory lock this round added is missing or broken)", aErr)
	}
	if bErr != nil {
		t.Fatalf("raw reverse-order peer (call B): %v — want nil", bErr)
	}
	if len(left) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after both concurrent deletes, want 0", len(left))
	}
}

// newLiveAuthStoreWarmed is newLiveAuthStore's counterpart for a
// concurrency test that needs the connection pool already holding n live
// connections before the race starts — see
// TestMarkRotatedConcurrencyExactlyOneWinnerLive's doc for why an unwarmed
// pool badly undercounts how often a broken, split-lock MarkRotated gets
// caught. database/sql's default MaxIdleConns is 2, so SetMaxOpenConns /
// SetMaxIdleConns must both be raised to n BEFORE warming — otherwise
// opening n connections and returning them idle would just have the pool
// close all but 2 of them again immediately.
func newLiveAuthStoreWarmed(t *testing.T, n int) *dropsstore.AuthStore {
	t.Helper()
	sqlDB, db := openLiveDB(t)
	sqlDB.SetMaxOpenConns(n)
	sqlDB.SetMaxIdleConns(n)

	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()
	dropAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, db, st) })

	// Prime the pool: n goroutines each force database/sql to hand them a
	// connection (opening one if the pool doesn't already have an idle
	// one), then return it to the now-larger idle pool. Once this
	// completes, the actual race's first real query per goroutine is a
	// pool checkout that is already satisfied, not a fresh TCP + auth
	// round trip — see the concurrency test's own doc for why that
	// distinction is what makes the difference.
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			var one int
			if err := sqlDB.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
				t.Errorf("pool warm-up query: %v", err)
			}
		}()
	}
	wg.Wait()

	return st
}

// TestMarkRotatedConcurrencyExactlyOneWinnerLive is the live-Postgres proof
// the task exists to produce: a fake driver has no lock contention or wire
// round trips to interleave, so it cannot demonstrate atomicity — only a
// real server's row lock can. N goroutines race MarkRotated against one
// fresh, unrotated session; PostgreSQL's row-level lock under the single
// "UPDATE ... WHERE token_hash = $1 AND rotated_at IS NULL RETURNING ..."
// statement must admit exactly one of them. Shaped like
// invite_integration_test.go's TestConsumeLinkConcurrencyExactlyOneWinnerLive
// and store/memory/auth_test.go's raceMarkRotated — see this file's own
// top-of-file doc for why that function itself could not be reused
// directly.
//
// The pool is pre-warmed to N connections before the race starts (see
// [newLiveAuthStoreWarmed]) rather than left to grow on demand. Measured
// over 45 runs at N=100 against an UNWARMED pool, a deliberately broken
// read-then-write MarkRotated (SELECT the session, decide, then a separate
// UPDATE by id with no compare-and-set guard) was caught only ~40-70% of
// the time: opening a fresh connection is comparatively slow and uneven,
// so goroutines trickle into the actual UPDATE across a wide window instead
// of arriving together, which sharply reduces how often two of them
// genuinely race for the same row. Pre-warming closes that gap: 10/10 runs
// caught the same mutation, and 10/10 runs passed clean against the real,
// atomic implementation (see the task report for the exact mutation and
// counts). This project has already learned twice — Plan 4's ConsumeLink,
// and this exact MarkRotated contract's own store/memory concurrency test
// — that a probabilistic detector on a single-winner invariant is not
// trustworthy as a regression net; an occasional green run on a broken
// implementation is worse than a slower test.
//
// shared is computed ONCE, before any goroutine starts, and every
// goroutine's MarkRotated call races with that identical instant rather
// than each computing its own time.Now(). The final assertion checks the
// winning row's RotatedAt against this exact known value, not merely that
// it is non-nil — pinning that the winner's write actually persisted the
// instant it was asked to, not some other value a subtler bug might have
// substituted while still leaving "successes == 1" true.
func TestMarkRotatedConcurrencyExactlyOneWinnerLive(t *testing.T) {
	const n = 100
	st := newLiveAuthStoreWarmed(t, n)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	sess, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: uid.NewV7(), TokenHash: "race-hash", FamilyID: uid.NewV7(),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	shared := now.Add(time.Minute)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, errs := 0, 0

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, ok, err := st.MarkRotated(ctx, sess.TokenHash, shared)
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
		t.Fatalf("got %d unexpected errors from MarkRotated", errs)
	}
	if successes != 1 {
		t.Fatalf("got %d successful MarkRotated calls against one session, want exactly 1 — MarkRotated is not atomic", successes)
	}

	got, err := st.FindSessionByHash(ctx, sess.TokenHash)
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if got.RotatedAt == nil || !got.RotatedAt.Equal(shared) {
		t.Fatalf("final RotatedAt = %v, want the shared instant every goroutine raced with, %v", got.RotatedAt, shared)
	}
}

// TestAuthStoreCreateSchemaLandsConstraintsOnRealPostgres proves all three
// UNIQUE constraints — users.email (inline), sessions.token_hash and
// verifications.token_hash (both via CreateSchema's ALTER TABLE) — actually
// reach the database, by reading them back out of pg_constraint, rather
// than inferring their existence indirectly from a duplicate-insert error
// (which the lifecycle tests above already do separately). Mirrors
// schema_integration_test.go's TestCreateSchemaLandsConstraintsOnRealPostgres
// and invite_integration_test.go's
// TestInviteStoreCreateSchemaLandsConstraintsOnRealPostgres. Also re-runs
// CreateSchema to confirm it stays idempotent against a real server.
//
// It also confirms sessions_family_id_idx — a plain (non-unique) index, so
// it does not appear in pg_constraint at all — by reading pg_indexes
// instead, the same way the constraint assertions below read pg_constraint.
// See [NewAuthSchema]'s own comment on why this index is load-bearing now
// that [AuthStore.DeleteSessionsByFamily] costs a transaction per family
// rather than one autocommit statement.
func TestAuthStoreCreateSchemaLandsConstraintsOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("AUTHLAYER_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUTHLAYER_TEST_DSN to run the drops auth store integration test")
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	db := pg.New(stdlib.New(sqlDB))
	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()

	for _, tbl := range []string{"sessions", "verifications", "users"} {
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
		for _, tbl := range []string{"sessions", "verifications", "users"} {
			_, _ = sqlDB.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+tbl+" CASCADE")
		}
	})

	rows, err := sqlDB.QueryContext(ctx, `
		SELECT c.conname, c.contype, pg_get_constraintdef(c.oid)
		FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname IN ('users','sessions','verifications')
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
		t.Logf("%-30s %s  %s", name, typ, def)
		found[name] = def
	}

	for _, want := range []struct{ name, def string }{
		{"users_email_key", "UNIQUE (email)"},
		{"users_pkey", "PRIMARY KEY (id)"},
		{"sessions_token_hash", "UNIQUE (token_hash)"},
		{"sessions_pkey", "PRIMARY KEY (id)"},
		{"verifications_token_hash", "UNIQUE (token_hash)"},
		{"verifications_pkey", "PRIMARY KEY (id)"},
	} {
		def, ok := found[want.name]
		if !ok {
			t.Errorf("MISSING: %s on the auth tables", want.name)
			continue
		}
		if def != want.def {
			t.Errorf("%s definition = %q, want %q", want.name, def, want.def)
		}
	}

	var idxDef string
	err = sqlDB.QueryRowContext(ctx,
		`SELECT indexdef FROM pg_indexes WHERE tablename = 'sessions' AND indexname = $1`,
		"sessions_family_id_idx").Scan(&idxDef)
	if err != nil {
		t.Fatalf("sessions_family_id_idx: %v", err)
	}
	if !strings.Contains(idxDef, "(family_id)") {
		t.Fatalf("sessions_family_id_idx definition = %q, want it to index (family_id)", idxDef)
	}
	t.Logf("sessions_family_id_idx           i  %s", idxDef)

	err = sqlDB.QueryRowContext(ctx,
		`SELECT indexdef FROM pg_indexes WHERE tablename = 'verifications' AND indexname = $1`,
		"verifications_user_id_purpose_idx").Scan(&idxDef)
	if err != nil {
		t.Fatalf("verifications_user_id_purpose_idx: %v", err)
	}
	// Column ORDER is asserted, not just membership: (purpose, user_id)
	// would be a different, far less selective index for the same query.
	if !strings.Contains(idxDef, "(user_id, purpose)") {
		t.Fatalf("verifications_user_id_purpose_idx definition = %q, want it to index (user_id, purpose) in that order", idxDef)
	}
	t.Logf("verifications_user_id_purpose_idx i  %s", idxDef)
}

// TestAuthPurgeExpiredLive mirrors invite_integration_test.go's
// TestPurgeExpiredLive: it removes rows expired strictly before the cutoff
// from both sessions and verifications, sums the count across both, and
// leaves users (never purged) and live rows untouched.
func TestAuthPurgeExpiredLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	userID := uid.NewV7()

	sess1 := auth.Session{ID: uid.NewV7(), UserID: userID, TokenHash: "purge-sess-1", ExpiresAt: past, CreatedAt: now}
	sess2 := auth.Session{ID: uid.NewV7(), UserID: userID, TokenHash: "purge-sess-2", ExpiresAt: future, CreatedAt: now}
	for _, s := range []auth.Session{sess1, sess2} {
		if _, err := st.CreateSession(ctx, s); err != nil {
			t.Fatalf("CreateSession(%s): %v", s.ID, err)
		}
	}

	ver1 := auth.Verification{ID: uid.NewV7(), UserID: userID, TokenHash: "purge-ver-1", ExpiresAt: past, CreatedAt: now}
	ver2 := auth.Verification{ID: uid.NewV7(), UserID: userID, TokenHash: "purge-ver-2", ExpiresAt: future, CreatedAt: now}
	for _, v := range []auth.Verification{ver1, ver2} {
		if _, err := st.CreateVerification(ctx, v); err != nil {
			t.Fatalf("CreateVerification(%s): %v", v.ID, err)
		}
	}

	n, err := st.PurgeExpired(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 2 {
		t.Fatalf("PurgeExpired removed %d rows, want 2 (sess1, ver1)", n)
	}

	if _, err := st.FindSessionByHash(ctx, "purge-sess-1"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("sess1 err = %v, want ErrSessionNotFound (should be purged)", err)
	}
	if _, err := st.FindSessionByHash(ctx, "purge-sess-2"); err != nil {
		t.Fatalf("sess2 err = %v, want it to survive", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "purge-ver-1"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("ver1 err = %v, want ErrVerificationNotFound (should be purged)", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "purge-ver-2"); err != nil {
		t.Fatalf("ver2 err = %v, want it to survive", err)
	}
}

// TestLogoutOfRotatedTokenRevokesFamilyLive is the live-PostgreSQL half of
// auth's TestLogoutOfRotatedTokenRevokesFamily. The defect it pins — Logout
// deleting the retained rotated row that reuse detection trips over, so a
// thief who rotates a stolen token and then logs the SAME stolen token out
// disarms the tripwire and keeps a rotating successor — was confirmed
// against a real server before the fix, so the fix is confirmed there too
// rather than only against the in-memory store's semantics.
func TestLogoutOfRotatedTokenRevokesFamilyLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	svc := newLiveAuthService(st)

	res, err := svc.SignUp(ctx, "live-logout-family@example.com", liveTestPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	login, err := svc.Login(ctx, "live-logout-family@example.com", liveTestPassword, "203.0.113.9", "thief")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	stolen := login.RefreshToken

	attacker, err := svc.Refresh(ctx, stolen)
	if err != nil {
		t.Fatalf("Refresh(stolen): %v", err)
	}
	if err := svc.Logout(ctx, stolen); err != nil {
		t.Fatalf("Logout(rotated token) err = %v, want nil", err)
	}

	sessions, err := st.ListSessionsByUser(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("ListSessionsByUser returned %d row(s) after Logout of a rotated token; want 0 — the family must be revoked", len(sessions))
	}
	if _, err := svc.Refresh(ctx, attacker.RefreshToken); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Refresh(successor) err = %v, want ErrTokenInvalid — the attacker's successor must not outlive the family", err)
	}
}

// TestRevokeSessionRevokesWholeFamilyLive is the live-PostgreSQL half of
// auth's TestRevokeSessionRevokesWholeFamilyNotOneRow: a "your devices"
// screen is built from ListSessions, which returns rotation history, so
// revoking whichever row the user picked must sign the whole login out —
// and must not spill into another family.
func TestRevokeSessionRevokesWholeFamilyLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	svc := newLiveAuthService(st)

	res, err := svc.SignUp(ctx, "live-revoke-family@example.com", liveTestPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	loginA, err := svc.Login(ctx, "live-revoke-family@example.com", liveTestPassword, "203.0.113.9", "device-a")
	if err != nil {
		t.Fatalf("Login(device A): %v", err)
	}
	loginB, err := svc.Login(ctx, "live-revoke-family@example.com", liveTestPassword, "198.51.100.7", "device-b")
	if err != nil {
		t.Fatalf("Login(device B): %v", err)
	}
	deviceA, deviceB := loginA.RefreshToken, loginB.RefreshToken

	rotatedA, err := svc.Refresh(ctx, deviceA)
	if err != nil {
		t.Fatalf("Refresh(device A): %v", err)
	}

	listed, err := svc.ListSessions(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("ListSessions returned %d rows, want 3 (A's predecessor, A's successor, B)", len(listed))
	}
	var supersededA string
	for _, sess := range listed {
		if sess.RotatedAt != nil {
			supersededA = sess.ID
		}
	}
	if supersededA == "" {
		t.Fatal("no superseded row found in the listing")
	}

	if err := svc.RevokeSession(ctx, res.User.ID, supersededA); err != nil {
		t.Fatalf("RevokeSession(superseded row): %v", err)
	}
	if _, err := svc.Refresh(ctx, rotatedA.RefreshToken); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Refresh(device A's current token) err = %v, want ErrTokenInvalid — the device must actually be signed out", err)
	}
	remaining, err := st.ListSessionsByUser(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("ListSessionsByUser returned %d row(s), want 1 — device B's family must be untouched", len(remaining))
	}
	if _, err := svc.Refresh(ctx, deviceB); err != nil {
		t.Fatalf("Refresh(device B): %v — revocation must not spill across families", err)
	}
}

// TestResetPasswordStampsEmailVerifiedLive confirms against a real server
// that a completed reset certifies the address its token was delivered to,
// closing the WithRequireVerifiedEmail lockout. The service-level unit test
// (auth's TestResetPasswordStampsEmailVerifiedClosingTheLockout) proves the
// logic; this proves the two Store calls it now makes — FindUserByID and
// the conditional MarkEmailVerified — behave the same over PostgreSQL,
// where MarkEmailVerified's address check is a WHERE clause rather than a
// map comparison.
func TestResetPasswordStampsEmailVerifiedLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	svc := auth.New(st,
		auth.WithHasher(password.Bcrypt(bcrypt.MinCost)),
		auth.WithJWT([][]byte{bytes.Repeat([]byte("k"), 32)}, 15*time.Minute),
		auth.WithRequireVerifiedEmail(true),
	)

	res, err := svc.SignUp(ctx, "live-locked@example.com", liveTestPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := svc.Login(ctx, "live-locked@example.com", liveTestPassword, "203.0.113.9", "agent"); !errors.Is(err, auth.ErrEmailNotVerified) {
		t.Fatalf("Login before the reset err = %v, want ErrEmailNotVerified", err)
	}

	tok, ok, err := svc.RequestPasswordReset(ctx, "live-locked@example.com", "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}
	const recovered = "Recovered-Valid-Pass22!"
	if err := svc.ResetPassword(ctx, tok, recovered); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	stored, err := st.FindUserByID(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is still nil after a completed reset")
	}
	if _, err := svc.Login(ctx, "live-locked@example.com", recovered, "203.0.113.9", "agent"); err != nil {
		t.Fatalf("Login after the reset: %v", err)
	}
}

// TestLogoutAllSweepsPendingVerificationsLive is the live-PostgreSQL
// regression for the takeover that survived "sign out everywhere". The
// vulnerability was demonstrated against this store, so the fix is pinned
// against it too rather than only against store/memory: an attacker's
// pending email_change outlived LogoutAll and VerifyEmail redeemed it
// afterwards with no authentication at all, moving the account to an
// address Login and RequestPasswordReset can no longer reach the victim at.
func TestLogoutAllSweepsPendingVerificationsLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	svc := newLiveAuthService(st)

	res, err := svc.SignUp(ctx, "live-sweep@example.com", liveTestPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	changeTok, err := svc.RequestEmailChange(ctx, res.User.ID, liveTestPassword, "attacker@evil.example")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	resetTok, ok, err := svc.RequestPasswordReset(ctx, "live-sweep@example.com", "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	if err := svc.LogoutAll(ctx, res.User.ID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}

	if _, err := svc.VerifyEmail(ctx, changeTok); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("VerifyEmail(email_change) after LogoutAll err = %v, want ErrVerificationNotFound", err)
	}
	if err := svc.ResetPassword(ctx, resetTok, "Attacker-Chosen-Pass24!"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("ResetPassword after LogoutAll err = %v, want ErrVerificationNotFound", err)
	}
	stored, err := st.FindUserByID(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.Email != "live-sweep@example.com" {
		t.Fatalf("stored email = %q, want the original — the account was moved after a sign-out-everywhere", stored.Email)
	}
}

// TestVerifyEmailChangeSweepsResetTokensLive is the live regression for the
// mirror gap: an address rotation that swept no reset token left a link in
// the mailbox the user was fleeing able to reset the password of the
// account at its NEW address for the rest of the reset TTL. Verified
// against this store before the fix; pinned against it now.
func TestVerifyEmailChangeSweepsResetTokensLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	svc := newLiveAuthService(st)

	res, err := svc.SignUp(ctx, "live-old@example.com", liveTestPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	// A reset link is issued to the address the user is about to leave.
	resetTok, ok, err := svc.RequestPasswordReset(ctx, "live-old@example.com", "203.0.113.9")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	changeTok, err := svc.RequestEmailChange(ctx, res.User.ID, liveTestPassword, "live-new@example.com")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	moved, err := svc.VerifyEmail(ctx, changeTok)
	if err != nil {
		t.Fatalf("VerifyEmail(email_change): %v", err)
	}
	if moved.Email != "live-new@example.com" {
		t.Fatalf("email after redemption = %q, want %q", moved.Email, "live-new@example.com")
	}

	if err := svc.ResetPassword(ctx, resetTok, "Old-Mailbox-Pass25!"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("ResetPassword(token delivered to the OLD address) err = %v, want ErrVerificationNotFound", err)
	}
	if _, err := svc.Login(ctx, "live-new@example.com", liveTestPassword, "203.0.113.9", "agent"); err != nil {
		t.Fatalf("Login with the ORIGINAL password after the refused reset: %v, want success", err)
	}
}

// recordingDriver wraps a real drops driver and keeps every statement it
// executes, so a test can recover the EXACT SQL a store method issued and
// then EXPLAIN that same string. Writing the DELETE out by hand in the test
// instead would EXPLAIN a query the store does not actually run, and would
// keep passing if the store's predicate ever changed.
type recordingDriver struct {
	drops.Driver
	execs []string
}

func (d *recordingDriver) Exec(ctx context.Context, query string, args ...any) (drops.Result, error) {
	d.execs = append(d.execs, query)
	return d.Driver.Exec(ctx, query, args...)
}

func (d *recordingDriver) last() string {
	if len(d.execs) == 0 {
		return ""
	}
	return d.execs[len(d.execs)-1]
}

// explain returns the plan for query with args bound, as one newline-joined
// string.
func explain(t *testing.T, sqlDB *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := sqlDB.QueryContext(context.Background(), "EXPLAIN "+query, args...)
	if err != nil {
		t.Fatalf("EXPLAIN %s: %v", query, err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("EXPLAIN rows: %v", err)
	}
	return strings.Join(lines, "\n")
}

// TestDeleteVerificationsByUserAndPurposeUsesTheIndexLive proves the
// verifications (user_id, purpose) index registered by NewAuthSchema is one
// the PLANNER ACTUALLY PICKS, not merely one that exists. An index the
// planner ignores is not a fix, and this is the one index in the schema
// whose absence is a documented SECURITY cost rather than only a
// performance one: DeleteVerificationsByUserAndPurpose runs on every
// auth.Service.RequestPasswordReset, so a sequential scan there makes the
// residual enumeration timing channel that method's doc (point 5) discloses
// grow with the number of pending tokens held for ALL users.
//
// The test carries its own CONTROL: it drops the index, re-EXPLAINs, and
// requires the plan to become a sequential scan. Without that step a
// planner that had chosen a seq scan anyway — or an assertion matching
// something that appears in every plan — would pass silently, and the test
// would prove nothing about the index. CreateSchema then puts the index
// back, which also re-exercises its self-healing property against a real
// server.
func TestDeleteVerificationsByUserAndPurposeUsesTheIndexLive(t *testing.T) {
	sqlDB, rawDB := openLiveDB(t)
	rec := &recordingDriver{Driver: stdlib.New(sqlDB)}
	db := pg.New(rec)
	st := dropsstore.NewAuthStore(db)
	ctx := context.Background()

	dropAuthTables(t, rawDB, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAuthTables(t, rawDB, st) })

	// Seed enough rows, spread over enough distinct users, that an index
	// scan is the cheaper plan. On a table of a handful of rows PostgreSQL
	// correctly prefers a sequential scan whatever indexes exist, so a
	// near-empty table cannot answer the question this test asks.
	const users, perUser = 300, 4
	purposes := []string{"signup", "email_change", "password_reset", "password_reset"}
	now := time.Now().UTC().Truncate(time.Microsecond)
	var probeUser string
	for i := 0; i < users; i++ {
		userID := uid.NewV7()
		if i == users/2 {
			probeUser = userID
		}
		for j := 0; j < perUser; j++ {
			_, err := st.CreateVerification(ctx, auth.Verification{
				ID: uid.NewV7(), UserID: userID,
				TokenHash: uid.NewV7() + uid.NewV7(),
				Purpose:   purposes[j],
				Email:     "explain-" + uid.NewV7() + "@example.com",
				ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			})
			if err != nil {
				t.Fatalf("CreateVerification: %v", err)
			}
		}
	}
	if _, err := sqlDB.ExecContext(ctx, "ANALYZE "+st.Schema().Verifications.Name()); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	// Recover the store's own DELETE by running it against a user id that
	// owns no rows: the statement is issued and recorded, and the table's
	// contents and statistics are left exactly as ANALYZE saw them.
	if err := st.DeleteVerificationsByUserAndPurpose(ctx, uid.NewV7(), "password_reset"); err != nil {
		t.Fatalf("DeleteVerificationsByUserAndPurpose: %v", err)
	}
	stmt := rec.last()
	if !strings.Contains(stmt, "DELETE") || !strings.Contains(stmt, "user_id") || !strings.Contains(stmt, "purpose") {
		t.Fatalf("recorded statement is not the delete under test: %q", stmt)
	}
	t.Logf("STATEMENT %s", stmt)

	withIndex := explain(t, sqlDB, stmt, probeUser, "password_reset")
	t.Logf("PLAN with the index:\n%s", withIndex)
	idx := st.Schema().Verifications.Name() + "_user_id_purpose_idx"
	if !strings.Contains(withIndex, idx) {
		t.Fatalf("the planner did not use %s — an index it ignores is not a fix. Plan:\n%s", idx, withIndex)
	}
	if strings.Contains(withIndex, "Seq Scan on "+st.Schema().Verifications.Name()) {
		t.Fatalf("plan still contains a sequential scan of the verifications table:\n%s", withIndex)
	}

	// The control: without the index the same statement on the same data
	// must fall back to a sequential scan. If it does not, the assertion
	// above was not measuring the index.
	if _, err := sqlDB.ExecContext(ctx, "DROP INDEX "+idx); err != nil {
		t.Fatalf("DROP INDEX %s: %v", idx, err)
	}
	withoutIndex := explain(t, sqlDB, stmt, probeUser, "password_reset")
	t.Logf("PLAN without the index (control):\n%s", withoutIndex)
	if !strings.Contains(withoutIndex, "Seq Scan on "+st.Schema().Verifications.Name()) {
		t.Fatalf("control failed: dropping %s did not produce a sequential scan, so the plan above proves nothing about the index. Plan:\n%s",
			idx, withoutIndex)
	}

	// CreateSchema self-heals the index back onto the existing table, the
	// same way it self-heals a missing UNIQUE constraint.
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (self-heal after DROP INDEX): %v", err)
	}
	var def string
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT indexdef FROM pg_indexes WHERE tablename = $1 AND indexname = $2`,
		st.Schema().Verifications.Name(), idx).Scan(&def); err != nil {
		t.Fatalf("index %s did not come back after CreateSchema: %v", idx, err)
	}
	t.Logf("SELF-HEAL %s", def)
}

// TestUpdateUserEmailConcurrentSameAddressExactlyOneWinnerLive is the live
// counterpart of store/memory's
// TestUpdateUserEmailConcurrentSameAddressExactlyOneWinner, and pins the
// same atomicity MUST on auth.Store.UpdateUserEmail against a real server —
// where "atomic" means something the memory store's single mutex cannot
// demonstrate: many connections, no shared lock, and the UNIQUE (email)
// constraint as the only arbiter.
//
// It is written independently rather than shared with the memory test for
// the reason recorded at the top of this file about markRotatedContract:
// that helper is unexported and lives in package memory_test, so nothing
// outside store/memory can reach it.
func TestUpdateUserEmailConcurrentSameAddressExactlyOneWinnerLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	const n = 24
	target := "contested-" + uid.NewV7() + "@example.com"
	ids := make([]string, n)
	for i := range ids {
		ids[i] = uid.NewV7()
		if _, err := st.CreateUser(ctx, auth.UserBase{
			ID: ids[i], Email: "start-" + uid.NewV7() + "@example.com",
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}

	var mu sync.Mutex
	var successes, taken int
	var others []error
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			err := st.UpdateUserEmail(ctx, id, target, now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, auth.ErrEmailTaken):
				taken++
			default:
				others = append(others, err)
			}
		}(id)
	}
	close(start)
	wg.Wait()

	if len(others) > 0 {
		t.Fatalf("unexpected errors from UpdateUserEmail: %v", others)
	}
	if successes != 1 {
		t.Fatalf("UpdateUserEmail succeeded for %d callers, want exactly 1", successes)
	}
	if taken != n-1 {
		t.Fatalf("UpdateUserEmail returned ErrEmailTaken to %d callers, want %d", taken, n-1)
	}

	// Read the final state back from the server rather than inferring it
	// from the counts: exactly one row holds the contested address.
	holders := 0
	for _, id := range ids {
		u, err := st.FindUserByID(ctx, id)
		if err != nil {
			t.Fatalf("FindUserByID: %v", err)
		}
		if u.Email == target {
			holders++
		}
	}
	if holders != 1 {
		t.Fatalf("%d users hold %q after the race, want exactly 1", holders, target)
	}
}

// TestNonUUIDIDGeneratorFailsAgainstDropsLive pins the backend constraint
// auth.WithIDGenerator and scope.WithIDGenerator both document: an id
// generator whose output PostgreSQL's uuid parser rejects fails against this
// store, at the STORE and on the FIRST write, not at construction.
//
// It asserts the SQLSTATE rather than merely "an error", because the exact
// code is what the two doc comments name and what a reader hitting it in
// production will search for. And it asserts the failing VALUE is in the
// message, since that is what tells a reader which knob produced it.
//
// Its counterpart in the auth package,
// TestNonUUIDIDGeneratorIsAcceptedByTheMemoryStore, shows the same generator
// working end to end against store/memory. Together they pin the shape of
// the trap: it is invisible until deployment.
//
// The auth half is asserted here rather than the scope half only because
// this file already has the auth fixtures; the cause is common to both, and
// is that store/drops types every id this library mints for itself as uuid
// unconditionally. WithTextUserIDs does not reach those columns — it types
// user ids supplied from OUTSIDE the library.
func TestNonUUIDIDGeneratorFailsAgainstDropsLive(t *testing.T) {
	st := newLiveAuthStore(t)
	n := 0
	svc := auth.New(st,
		auth.WithHasher(password.Bcrypt(bcrypt.MinCost)),
		auth.WithJWT([][]byte{bytes.Repeat([]byte("k"), 32)}, 15*time.Minute),
		auth.WithIDGenerator(func() string {
			n++
			return fmt.Sprintf("usr_readable_%03d", n)
		}),
	)

	_, err := svc.SignUp(context.Background(), "readable@example.com", liveTestPassword)
	if err == nil {
		t.Fatal("SignUp succeeded with a non-UUID id generator — store/drops types users.id as uuid, so if this now works the constraint documented on auth.WithIDGenerator and scope.WithIDGenerator is stale and must be revisited")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("SignUp err = %v (%T), want a *pgconn.PgError", err, err)
	}
	if pgErr.Code != "22P02" {
		t.Fatalf("SignUp err SQLSTATE = %s, want 22P02 (invalid_text_representation): %v", pgErr.Code, err)
	}
	if !strings.Contains(err.Error(), "usr_readable_") {
		t.Fatalf("SignUp err does not name the rejected id, so a reader cannot tell which knob produced it: %v", err)
	}
	t.Logf("SQLSTATE %s: %v", pgErr.Code, err)
}
