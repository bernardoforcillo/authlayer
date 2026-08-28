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
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// newLiveAuthStore opens a connection from AUTHLAYER_TEST_DSN, builds a
// fresh AuthStore, and drops/recreates all three tables so each test starts
// from an empty schema. It registers sqlDB.Close() as a cleanup BEFORE the
// table-dropping cleanup: t.Cleanup callbacks run after a test function's
// defers, in LIFO order, so registering Close first means it runs LAST —
// the drop-tables cleanup still has a live connection when it runs. See
// store/drops/integration_test.go's dropAll and
// invite_integration_test.go's newLiveInviteStore for the same pattern.
func newLiveAuthStore(t *testing.T) *dropsstore.AuthStore {
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

	db := pg.New(stdlib.New(sqlDB))
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
func TestMarkRotatedConcurrencyExactlyOneWinnerLive(t *testing.T) {
	st := newLiveAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	sess, err := st.CreateSession(ctx, auth.Session{
		ID: uid.NewV7(), UserID: uid.NewV7(), TokenHash: "race-hash", FamilyID: uid.NewV7(),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
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
			_, ok, err := st.MarkRotated(ctx, sess.TokenHash, time.Now().UTC())
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
	if got.RotatedAt == nil {
		t.Fatal("final RotatedAt = nil, want the winner's stamp")
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
