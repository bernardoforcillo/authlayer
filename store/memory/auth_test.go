package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Compile-time proof the memory store satisfies auth.Store.
var _ auth.Store = (*memory.AuthStore)(nil)

func newAuthStore() *memory.AuthStore {
	return memory.NewAuthStore()
}

// --- NormalizeEmail ---

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"bob@example.com", "bob@example.com"},
		{"Bob@Example.com", "bob@example.com"},
		{"  bob@example.com  ", "bob@example.com"},
		{"\tBOB@EXAMPLE.COM\n", "bob@example.com"},
		{"", ""},
	}
	for _, c := range cases {
		if got := auth.NormalizeEmail(c.in); got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- Users ---

func TestCreateAndFindUserByID(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()

	u := auth.UserBase{
		ID:           "user1",
		Email:        "bob@example.com",
		PasswordHash: "hash1",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	created, err := st.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created != u {
		t.Fatalf("CreateUser returned %+v, want %+v", created, u)
	}

	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got != u {
		t.Fatalf("FindUserByID = %+v, want %+v", got, u)
	}
}

func TestFindUserByIDNotFound(t *testing.T) {
	st := newAuthStore()
	_, err := st.FindUserByID(context.Background(), "nonesuch")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByID err = %v, want ErrUserNotFound", err)
	}
}

func TestCreateUserNormalizesEmailOnWrite(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()

	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "  Bob@Example.com\t"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Fatalf("stored Email = %q, want normalized %q", got.Email, "bob@example.com")
	}
}

func TestFindUserByEmailNormalizesOnRead(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	for _, variant := range []string{"bob@example.com", "Bob@Example.com", "  bob@example.com  ", "BOB@EXAMPLE.COM"} {
		got, err := st.FindUserByEmail(ctx, variant)
		if err != nil {
			t.Fatalf("FindUserByEmail(%q): %v", variant, err)
		}
		if got.ID != "user1" {
			t.Fatalf("FindUserByEmail(%q) returned id %q, want user1", variant, got.ID)
		}
	}
}

func TestFindUserByEmailNotFound(t *testing.T) {
	st := newAuthStore()
	_, err := st.FindUserByEmail(context.Background(), "nonesuch@example.com")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail err = %v, want ErrUserNotFound", err)
	}
}

// TestCreateUserDuplicateEmailFails pins the uniqueness check
// [auth.NormalizeEmail]'s doc promises: a case/whitespace variant of an
// already-registered address must not be able to create a second account.
func TestCreateUserDuplicateEmailFails(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err := st.CreateUser(ctx, auth.UserBase{ID: "user2", Email: "  Bob@Example.com  "})
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("second CreateUser err = %v, want ErrEmailTaken", err)
	}

	// The rejected write must not have landed.
	if _, err := st.FindUserByID(ctx, "user2"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByID(user2) err = %v, want ErrUserNotFound — the conflicting write must not persist", err)
	}
}

// --- Sessions ---

func TestCreateAndFindSessionByHash(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()

	sess := auth.Session{
		ID:        "sess1",
		UserID:    "user1",
		TokenHash: "hash1",
		FamilyID:  "fam1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	created, err := st.CreateSession(ctx, sess)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if created != sess {
		t.Fatalf("CreateSession returned %+v, want %+v", created, sess)
	}

	got, err := st.FindSessionByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if got != sess {
		t.Fatalf("FindSessionByHash = %+v, want %+v", got, sess)
	}
}

func TestFindSessionByHashNotFound(t *testing.T) {
	st := newAuthStore()
	_, err := st.FindSessionByHash(context.Background(), "nonesuch")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash err = %v, want ErrSessionNotFound", err)
	}
}

func TestListSessionsByUserScopesToUser(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	for _, sess := range []auth.Session{
		{ID: "sess1", UserID: "user1", TokenHash: "hash1"},
		{ID: "sess2", UserID: "user1", TokenHash: "hash2"},
		{ID: "sess3", UserID: "user2", TokenHash: "hash3"},
	} {
		if _, err := st.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession(%s): %v", sess.ID, err)
		}
	}

	got, err := st.ListSessionsByUser(ctx, "user1")
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListSessionsByUser returned %d sessions, want 2", len(got))
	}
	for _, sess := range got {
		if sess.UserID != "user1" {
			t.Fatalf("ListSessionsByUser leaked session %+v belonging to a different user", sess)
		}
	}
}

func TestListSessionsByUserEmptyIsEmptyNotError(t *testing.T) {
	st := newAuthStore()
	got, err := st.ListSessionsByUser(context.Background(), "nonesuch")
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListSessionsByUser returned %d sessions, want 0", len(got))
	}
}

func TestDeleteSession(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash1"}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := st.DeleteSession(ctx, "sess1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := st.FindSessionByHash(ctx, "hash1"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash after delete: err = %v, want ErrSessionNotFound", err)
	}
}

func TestDeleteSessionNotFound(t *testing.T) {
	st := newAuthStore()
	err := st.DeleteSession(context.Background(), "nonesuch")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("DeleteSession err = %v, want ErrSessionNotFound", err)
	}
}

func TestDeleteSessionsByFamilyRemovesOnlyMatchingRows(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	for _, sess := range []auth.Session{
		{ID: "sess1", FamilyID: "fam1", TokenHash: "hash1"},
		{ID: "sess2", FamilyID: "fam1", TokenHash: "hash2"},
		{ID: "sess3", FamilyID: "fam2", TokenHash: "hash3"},
	} {
		if _, err := st.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession(%s): %v", sess.ID, err)
		}
	}

	if err := st.DeleteSessionsByFamily(ctx, "fam1"); err != nil {
		t.Fatalf("DeleteSessionsByFamily: %v", err)
	}

	if _, err := st.FindSessionByHash(ctx, "hash1"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("fam1 session hash1 survived DeleteSessionsByFamily")
	}
	if _, err := st.FindSessionByHash(ctx, "hash2"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("fam1 session hash2 survived DeleteSessionsByFamily")
	}
	if _, err := st.FindSessionByHash(ctx, "hash3"); err != nil {
		t.Fatalf("fam2 session hash3 should have survived, got err = %v", err)
	}
}

func TestDeleteSessionsByFamilyNoMatchesIsNotError(t *testing.T) {
	st := newAuthStore()
	if err := st.DeleteSessionsByFamily(context.Background(), "nonesuch"); err != nil {
		t.Fatalf("DeleteSessionsByFamily: %v", err)
	}
}

// --- MarkRotated ---

func TestMarkRotatedFirstCallerWins(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash1"}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	now := time.Now()
	got, ok, err := st.MarkRotated(ctx, "hash1", now)
	if err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	if !ok {
		t.Fatal("MarkRotated ok = false for a fresh, unrotated session")
	}
	if got.RotatedAt == nil || !got.RotatedAt.Equal(now) {
		t.Fatalf("MarkRotated returned RotatedAt = %v, want %v", got.RotatedAt, now)
	}

	// The mark must be visible to a subsequent read through the ordinary path.
	reread, err := st.FindSessionByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("FindSessionByHash after MarkRotated: %v", err)
	}
	if reread.RotatedAt == nil || !reread.RotatedAt.Equal(now) {
		t.Fatalf("FindSessionByHash RotatedAt = %v, want %v", reread.RotatedAt, now)
	}
}

func TestMarkRotatedSecondCallFails(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash1"}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	first := time.Now()
	if _, ok, err := st.MarkRotated(ctx, "hash1", first); err != nil || !ok {
		t.Fatalf("first MarkRotated: ok=%v err=%v, want ok=true err=nil", ok, err)
	}

	second := first.Add(time.Minute)
	got, ok, err := st.MarkRotated(ctx, "hash1", second)
	if err != nil {
		t.Fatalf("second MarkRotated returned an error: %v, want nil (this is a replay, not a failure)", err)
	}
	if ok {
		t.Fatal("second MarkRotated ok = true against an already-rotated session, want false")
	}
	// The already-rotated session is returned so the caller can inspect
	// RotatedAt to decide this was a replay.
	if got.RotatedAt == nil || !got.RotatedAt.Equal(first) {
		t.Fatalf("second MarkRotated returned RotatedAt = %v, want the FIRST rotation's stamp %v — the replay must not overwrite it", got.RotatedAt, first)
	}
}

func TestMarkRotatedNotFound(t *testing.T) {
	st := newAuthStore()
	_, ok, err := st.MarkRotated(context.Background(), "nonesuch", time.Now())
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("MarkRotated err = %v, want ErrSessionNotFound", err)
	}
	if ok {
		t.Fatal("MarkRotated ok = true for a nonexistent session")
	}
}

// TestMarkRotatedIgnoresExpiry pins the contract's most easily "fixed" bug:
// expiry is deliberately NOT part of MarkRotated's predicate (see its doc on
// auth.Store). A session already past ExpiresAt but never rotated must still
// be markable — the caller, not this method, decides what an
// expired-but-successfully-rotated result means.
func TestMarkRotatedIgnoresExpiry(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{
		ID: "sess1", TokenHash: "hash1", ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	_, ok, err := st.MarkRotated(ctx, "hash1", time.Now())
	if err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	if !ok {
		t.Fatal("MarkRotated ok = false for an expired-but-unrotated session; expiry must not gate rotation")
	}
}

// TestMarkRotatedConcurrencyExactlyOneWinner pins the observable contract: N
// goroutines race to rotate one session's token, and exactly one of them must
// observe ok=true, the rest ok=false with no error, and the session's final
// RotatedAt must be the shared instant every goroutine raced with. Every N
// goroutine is started ahead of time and blocked on a channel so they all
// enter MarkRotated at effectively the same instant once it closes,
// maximizing contention — the same construction as
// store/memory/invite_test.go's TestConsumeLinkConcurrencyExactlyOneWinner.
//
// What this test does NOT reliably do is catch a broken, split-lock
// (read-then-write) MarkRotated — read the session under one lock
// acquisition, decide, then write under a second. This was measured directly
// against a mutated copy of MarkRotated built exactly that way (read under
// mu, unlock, decide, then a second mu.Lock to write): N=500 goroutines
// behind the same channel barrier, this same test rerun with `go test
// -count`.
//
//   - Naive window (nothing inserted between the unlocked read and the
//     second Lock): 70 runs total (20 + 50, in two separate invocations), 3
//     failures — a 3/70 (~4%) catch rate. Not flaky-clean the way
//     TestConsumeLinkConcurrencyExactlyOneWinner's doc reports for
//     ConsumeLink (0 failures in 20 runs, even at 2000 goroutines), but
//     still far too unreliable to trust as a regression net: a CI run that
//     happens to land in the ~96% of green runs certifies a broken
//     implementation as correct. The failures that did occur reported 2 and
//     3 successful callers, consistent with the sub-microsecond window
//     TestConsumeLinkConcurrencyExactlyOneWinner's doc describes — most
//     interleavings still resolve before a second goroutine's Lock() call
//     can land in the gap, they just do so less consistently here than in
//     ConsumeLink's simpler map lookup.
//   - Widened window (a temporary time.Millisecond sleep inserted between
//     the unlocked read and the second Lock(), in the mutated copy only —
//     never shipped): 20/20 runs failed, every single time. Per-run success
//     counts ranged from 318 to 500 (out of 500 goroutines), overwhelmingly
//     clustered at 500 — i.e. essentially every goroutine won, not merely
//     more than one.
//
// Both mutation runs were done by hand against a scratch copy of
// AuthStore.MarkRotated and are not part of this test file — see the task
// report for the exact diff used and the raw counts. A fully deterministic
// catch (100% on the naive window, no sleep needed) was not pursued for the
// in-memory store: unlike store/drops' live-Postgres tests, an in-process
// mutex has no independent contention source (no row lock, no wire round
// trip) to interleave against from outside the method, so forcing the
// interleaving without a timing-based delay would require adding a
// test-only blocking hook into AuthStore.MarkRotated itself — instrumenting
// production code purely to make a test of its ABSENCE of a bug more
// reliable. That trade was judged not worth it here, for the same reason
// Plan 4 ultimately answered this by adding a *_Live test against real
// PostgreSQL (store/drops/invite_integration_test.go's
// TestConsumeLinkConcurrencyExactlyOneWinnerLive) rather than instrumenting
// the in-memory store: the deterministic version belongs against the real
// contention source, in this package's store/drops counterpart, in a later
// task. The real guarantee that MarkRotated is atomic is the implementation
// holding one lock across the entire check-and-mark (see its doc comment in
// auth.go), not this test — this test pins the contract and catches a
// grossly broken implementation reliably (100% once the window is widened)
// and a subtly broken one occasionally (~4% at the naive window), per the
// same caveats TestConsumeLinkConcurrencyExactlyOneWinner's doc states.
//
// It is also a logical (check-then-act) race, not a memory race: every
// individual map read and write in the broken variant is still separately
// mutex-protected, so `go test -race` sees nothing unsynchronized and will
// not flag it either. Run -race anyway — it catches a different class of
// mutation, such as dropping the locking altogether — just not this one.
func TestMarkRotatedConcurrencyExactlyOneWinner(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash1"}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	const n = 500
	now := time.Now()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	errs := 0

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, ok, err := st.MarkRotated(ctx, "hash1", now)
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
		t.Fatalf("got %d successful MarkRotated calls against one session, want exactly 1", successes)
	}

	got, err := st.FindSessionByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if got.RotatedAt == nil || !got.RotatedAt.Equal(now) {
		t.Fatalf("final RotatedAt = %v, want %v", got.RotatedAt, now)
	}
}

// --- Verifications ---

func TestCreateAndFindVerificationByHash(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()

	v := auth.Verification{
		ID:        "ver1",
		UserID:    "user1",
		TokenHash: "hash1",
		Purpose:   "signup",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	created, err := st.CreateVerification(ctx, v)
	if err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}
	if created != v {
		t.Fatalf("CreateVerification returned %+v, want %+v", created, v)
	}

	got, err := st.FindVerificationByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if got != v {
		t.Fatalf("FindVerificationByHash = %+v, want %+v", got, v)
	}
}

func TestFindVerificationByHashNotFound(t *testing.T) {
	st := newAuthStore()
	_, err := st.FindVerificationByHash(context.Background(), "nonesuch")
	if !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash err = %v, want ErrVerificationNotFound", err)
	}
}

func TestDeleteVerification(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateVerification(ctx, auth.Verification{ID: "ver1", TokenHash: "hash1"}); err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}
	if err := st.DeleteVerification(ctx, "ver1"); err != nil {
		t.Fatalf("DeleteVerification: %v", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "hash1"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash after delete: err = %v, want ErrVerificationNotFound", err)
	}
}

func TestDeleteVerificationNotFound(t *testing.T) {
	st := newAuthStore()
	err := st.DeleteVerification(context.Background(), "nonesuch")
	if !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("DeleteVerification err = %v, want ErrVerificationNotFound", err)
	}
}

func TestDeleteVerificationsByUserAndPurposeRemovesOnlyMatchingRows(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	for _, v := range []auth.Verification{
		{ID: "ver1", UserID: "user1", Purpose: "password_reset", TokenHash: "hash1"},
		{ID: "ver2", UserID: "user1", Purpose: "password_reset", TokenHash: "hash2"},
		{ID: "ver3", UserID: "user1", Purpose: "email_change", TokenHash: "hash3"},
		{ID: "ver4", UserID: "user2", Purpose: "password_reset", TokenHash: "hash4"},
	} {
		if _, err := st.CreateVerification(ctx, v); err != nil {
			t.Fatalf("CreateVerification(%s): %v", v.ID, err)
		}
	}

	if err := st.DeleteVerificationsByUserAndPurpose(ctx, "user1", "password_reset"); err != nil {
		t.Fatalf("DeleteVerificationsByUserAndPurpose: %v", err)
	}

	if _, err := st.FindVerificationByHash(ctx, "hash1"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("ver1 survived DeleteVerificationsByUserAndPurpose")
	}
	if _, err := st.FindVerificationByHash(ctx, "hash2"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("ver2 survived DeleteVerificationsByUserAndPurpose")
	}
	if _, err := st.FindVerificationByHash(ctx, "hash3"); err != nil {
		t.Fatalf("ver3 (different purpose) should have survived, got err = %v", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "hash4"); err != nil {
		t.Fatalf("ver4 (different user) should have survived, got err = %v", err)
	}
}

func TestDeleteVerificationsByUserAndPurposeNoMatchesIsNotError(t *testing.T) {
	st := newAuthStore()
	if err := st.DeleteVerificationsByUserAndPurpose(context.Background(), "nonesuch", "signup"); err != nil {
		t.Fatalf("DeleteVerificationsByUserAndPurpose: %v", err)
	}
}

// --- PurgeExpired ---

func TestPurgeExpiredRemovesExpiredSessionsAndVerifications(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	cutoff := time.Now()

	if _, err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash1", ExpiresAt: cutoff.Add(-time.Hour)}); err != nil {
		t.Fatalf("CreateSession(expired): %v", err)
	}
	if _, err := st.CreateSession(ctx, auth.Session{ID: "sess2", TokenHash: "hash2", ExpiresAt: cutoff.Add(time.Hour)}); err != nil {
		t.Fatalf("CreateSession(live): %v", err)
	}
	if _, err := st.CreateVerification(ctx, auth.Verification{ID: "ver1", TokenHash: "vhash1", ExpiresAt: cutoff.Add(-time.Hour)}); err != nil {
		t.Fatalf("CreateVerification(expired): %v", err)
	}
	if _, err := st.CreateVerification(ctx, auth.Verification{ID: "ver2", TokenHash: "vhash2", ExpiresAt: cutoff.Add(time.Hour)}); err != nil {
		t.Fatalf("CreateVerification(live): %v", err)
	}

	n, err := st.PurgeExpired(ctx, cutoff)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 2 {
		t.Fatalf("PurgeExpired removed %d rows, want 2", n)
	}

	if _, err := st.FindSessionByHash(ctx, "hash1"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expired session survived PurgeExpired")
	}
	if _, err := st.FindSessionByHash(ctx, "hash2"); err != nil {
		t.Fatalf("live session should have survived, got err = %v", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "vhash1"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("expired verification survived PurgeExpired")
	}
	if _, err := st.FindVerificationByHash(ctx, "vhash2"); err != nil {
		t.Fatalf("live verification should have survived, got err = %v", err)
	}
}

func TestPurgeExpiredNothingToPurgeAuth(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	n, err := st.PurgeExpired(ctx, time.Now())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 0 {
		t.Fatalf("PurgeExpired removed %d rows, want 0", n)
	}
}
