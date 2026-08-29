package memory_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/auth/authtest"
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

// TestCreateUserDuplicateIDFails pins the exact scenario the review's I-4
// finding named: creating a second user under an ID that already identifies
// a different row must be refused, not silently replace it. Before this fix
// CreateUser(ctx, UserBase{ID: "user1", Email: "eve@evil.com"}) against an
// existing user1 holding bob@example.com would pass the email scan (no other
// row holds eve@evil.com) and overwrite Bob's row wholesale — different
// email, same ID, no error, every Session/Verification still keyed to user1
// now silently belonging to "Eve".
func TestCreateUserDuplicateIDFails(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "eve@evil.com"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("second CreateUser (same id, different email) err = %v, want ErrIDTaken", err)
	}

	// Bob's row must be completely untouched by the rejected write.
	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Fatalf("user1's Email = %q after a rejected duplicate-id CreateUser, want it unchanged at %q", got.Email, "bob@example.com")
	}
}

// --- User mutation: MarkEmailVerified, UpdateUserPassword, UpdateUserEmail ---

func TestMarkEmailVerified(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Now()
	if err := st.MarkEmailVerified(ctx, "user1", "bob@example.com", now); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.EmailVerifiedAt == nil || !got.EmailVerifiedAt.Equal(now) {
		t.Fatalf("EmailVerifiedAt = %v, want %v", got.EmailVerifiedAt, now)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}
}

// TestMarkEmailVerifiedNormalizesEmail confirms the comparison between the
// passed email and the row's current Email goes through NormalizeEmail on
// the argument side too, so a case/whitespace variant of the current
// address still succeeds — matching the same normalize-on-every-touch
// discipline as CreateUser/FindUserByEmail/UpdateUserEmail, not a stricter
// byte-exact check.
func TestMarkEmailVerifiedNormalizesEmail(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := st.MarkEmailVerified(ctx, "user1", "  Bob@Example.com  ", time.Now()); err != nil {
		t.Fatalf("MarkEmailVerified(case/whitespace variant of the current address): %v", err)
	}
}

func TestMarkEmailVerifiedNotFound(t *testing.T) {
	st := newAuthStore()
	err := st.MarkEmailVerified(context.Background(), "nonesuch", "bob@example.com", time.Now())
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("MarkEmailVerified err = %v, want ErrUserNotFound", err)
	}
}

// TestMarkEmailVerifiedRefusesStaleAddress is the fix's central regression
// test, pinning the exact scenario the review named: a verification token is
// effectively minted for one address (the caller obtains proof of control
// for it), but before that proof is redeemed, a *different* flow changes the
// user's address via UpdateUserEmail. Redeeming the stale proof must be
// refused — the store must not silently certify whatever address the row
// now holds using proof that was only ever for the old one. Without the
// email parameter and this check, MarkEmailVerified(ctx, userID, now) would
// have stamped EmailVerifiedAt regardless, certifying carol@example.com on
// proof of control of bob@example.com — a false verification.
func TestMarkEmailVerifiedRefusesStaleAddress(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// A verification token is (conceptually) minted for bob@example.com.
	// Before it is redeemed, a concurrent/different flow changes the
	// address — UpdateUserEmail itself already clears EmailVerifiedAt (see
	// TestUpdateUserEmailNormalizesAndClearsVerification), but the point of
	// this test is the *next* step: redeeming the now-stale proof.
	if err := st.UpdateUserEmail(ctx, "user1", "carol@example.com", time.Now()); err != nil {
		t.Fatalf("UpdateUserEmail: %v", err)
	}

	err := st.MarkEmailVerified(ctx, "user1", "bob@example.com", time.Now())
	if !errors.Is(err, auth.ErrEmailMismatch) {
		t.Fatalf("MarkEmailVerified(stale address) err = %v, want ErrEmailMismatch", err)
	}

	// The refused call must not have landed at all.
	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil — a refused, mismatched verification must not certify anything", got.EmailVerifiedAt)
	}
	if got.Email != "carol@example.com" {
		t.Fatalf("Email = %q, want it unchanged at %q — the refused call must not touch the row at all", got.Email, "carol@example.com")
	}
}

// TestMarkEmailVerifiedRefusesStaleAddressForSignup is round 3's central
// regression test. Round 2 closed the race for "email_change" but left it
// open for "signup": Verification.Email (then NewEmail) was documented empty
// for every Purpose but email_change, so a signup redemption handler had
// nothing to read except the row's own *current* Email — which is exactly
// what MarkEmailVerified's check compares against, making the comparison
// compare the current address to itself and always pass. This test mints a
// real "signup" Verification (via CreateVerification, exercising the actual
// persisted-and-retrieved Email field rather than a hand-constructed value),
// changes the user's address before redemption, and redeems using the
// Verification's own recorded Email — which must now be refused.
func TestMarkEmailVerifiedRefusesStaleAddressForSignup(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// A "signup" verification is minted for bob@example.com — the address
	// on the row at signup time.
	v, err := st.CreateVerification(ctx, auth.Verification{
		ID: "ver1", UserID: "user1", TokenHash: "hash1", Purpose: "signup",
		Email: "bob@example.com", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}

	// Before the token is redeemed, a different flow changes the address.
	if err := st.UpdateUserEmail(ctx, "user1", "carol@example.com", time.Now()); err != nil {
		t.Fatalf("UpdateUserEmail: %v", err)
	}

	// Redeeming the stale signup token, using the address it actually
	// recorded, must be refused — not silently certify carol@example.com on
	// proof of control of bob@example.com.
	err = st.MarkEmailVerified(ctx, "user1", v.Email, time.Now())
	if !errors.Is(err, auth.ErrEmailMismatch) {
		t.Fatalf("MarkEmailVerified(stale signup token) err = %v, want ErrEmailMismatch", err)
	}

	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil — a refused signup verification must not certify anything", got.EmailVerifiedAt)
	}
}

func TestUpdateUserPassword(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com", PasswordHash: "old-hash"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Now()
	if err := st.UpdateUserPassword(ctx, "user1", "new-hash", now); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}

	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.PasswordHash != "new-hash" {
		t.Fatalf("PasswordHash = %q, want %q", got.PasswordHash, "new-hash")
	}
	if !got.UpdatedAt.Equal(now) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}
}

func TestUpdateUserPasswordEmptyRemovesCredential(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com", PasswordHash: "old-hash"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := st.UpdateUserPassword(ctx, "user1", "", time.Now()); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.PasswordHash != "" {
		t.Fatalf("PasswordHash = %q, want empty (no password credential)", got.PasswordHash)
	}
}

func TestUpdateUserPasswordNotFound(t *testing.T) {
	st := newAuthStore()
	err := st.UpdateUserPassword(context.Background(), "nonesuch", "hash", time.Now())
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("UpdateUserPassword err = %v, want ErrUserNotFound", err)
	}
}

// TestUpdateUserEmailNormalizesAndClearsVerification pins the two contested
// behaviours the review named for UpdateUserEmail: the new address is
// normalized on write (I-1), and EmailVerifiedAt is unconditionally cleared
// back to nil rather than left alone — the store has no independent proof
// the new address was ever confirmed, only the caller's say-so.
func TestUpdateUserEmailNormalizesAndClearsVerification(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	verifiedAt := time.Now().Add(-time.Hour)
	if _, err := st.CreateUser(ctx, auth.UserBase{
		ID: "user1", Email: "bob@example.com", EmailVerifiedAt: &verifiedAt,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Now()
	if err := st.UpdateUserEmail(ctx, "user1", "  New@Example.com  ", now); err != nil {
		t.Fatalf("UpdateUserEmail: %v", err)
	}

	got, err := st.FindUserByID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.Email != "new@example.com" {
		t.Fatalf("Email = %q, want normalized %q", got.Email, "new@example.com")
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil — changing the address must clear verification", got.EmailVerifiedAt)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}

	// The user must still be findable by the new address, and no longer by
	// the old one.
	if _, err := st.FindUserByEmail(ctx, "new@example.com"); err != nil {
		t.Fatalf("FindUserByEmail(new@example.com): %v", err)
	}
	if _, err := st.FindUserByEmail(ctx, "bob@example.com"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail(bob@example.com) err = %v, want ErrUserNotFound", err)
	}
}

func TestUpdateUserEmailDuplicateFails(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser(user1): %v", err)
	}
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user2", Email: "carol@example.com"}); err != nil {
		t.Fatalf("CreateUser(user2): %v", err)
	}

	err := st.UpdateUserEmail(ctx, "user2", "  Bob@Example.com  ", time.Now())
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("UpdateUserEmail err = %v, want ErrEmailTaken", err)
	}

	// The rejected write must not have landed.
	got, err := st.FindUserByID(ctx, "user2")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.Email != "carol@example.com" {
		t.Fatalf("user2's Email = %q after a rejected UpdateUserEmail, want it unchanged at %q", got.Email, "carol@example.com")
	}
}

// TestUpdateUserEmailToOwnAddressIsNotSelfConflict proves the uniqueness scan
// excludes the row being updated: setting a user's email to the address it
// already holds must not be treated as a conflict with itself.
func TestUpdateUserEmailToOwnAddressIsNotSelfConflict(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, auth.UserBase{ID: "user1", Email: "bob@example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := st.UpdateUserEmail(ctx, "user1", "bob@example.com", time.Now()); err != nil {
		t.Fatalf("UpdateUserEmail(own address) err = %v, want nil", err)
	}
}

func TestUpdateUserEmailNotFound(t *testing.T) {
	st := newAuthStore()
	err := st.UpdateUserEmail(context.Background(), "nonesuch", "new@example.com", time.Now())
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("UpdateUserEmail err = %v, want ErrUserNotFound", err)
	}
}

// TestUpdateUserEmailConcurrentSameAddressExactlyOneWinner pins the
// atomicity MUST on auth.Store.UpdateUserEmail: of many callers moving
// DIFFERENT users to the SAME address at once, exactly one may succeed and
// every other must get ErrEmailTaken.
//
// This is the MUST with the least above it. auth.Service.RequestEmailChange
// deliberately performs no pre-check of the new address — a pre-check there
// would be an un-rate-limited "is this address registered?" oracle for any
// authenticated caller — so UpdateUserEmail at redemption is the only place
// the two-callers-racing-one-address race is decided. A read-then-write
// implementation lets every caller find the address free and every caller
// write it, leaving several users sharing one normalized address and every
// address-keyed lookup in the package (Login, RequestPasswordReset) reading
// whichever row it happens to reach first.
//
// The final-state assertion is the load-bearing one: counting winners alone
// would pass against a store that returned ErrEmailTaken to everybody and
// wrote nothing.
func TestUpdateUserEmailConcurrentSameAddressExactlyOneWinner(t *testing.T) {
	const n = 50
	const target = "contested@example.com"

	st := newAuthStore()
	ctx := context.Background()
	now := time.Now().UTC()

	ids := make([]string, n)
	for i := range ids {
		ids[i] = "user" + strconv.Itoa(i)
		if _, err := st.CreateUser(ctx, auth.UserBase{
			ID: ids[i], Email: "start" + strconv.Itoa(i) + "@example.com",
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("CreateUser %s: %v", ids[i], err)
		}
	}

	var successes, taken, other atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			switch err := st.UpdateUserEmail(ctx, id, target, now); {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, auth.ErrEmailTaken):
				taken.Add(1)
			default:
				other.Add(1)
			}
		}(id)
	}
	close(start)
	wg.Wait()

	if got := other.Load(); got != 0 {
		t.Fatalf("%d callers got an unexpected error from UpdateUserEmail", got)
	}
	if got := successes.Load(); got != 1 {
		t.Fatalf("UpdateUserEmail succeeded for %d callers, want exactly 1 — a read-then-write implementation lets several racing callers all find %q free and all write it",
			got, target)
	}
	if got := taken.Load(); got != n-1 {
		t.Fatalf("UpdateUserEmail returned ErrEmailTaken to %d callers, want %d", got, n-1)
	}

	// Final state, read back rather than inferred from the counts: exactly
	// one row holds the contested address.
	holders := 0
	for _, id := range ids {
		u, err := st.FindUserByID(ctx, id)
		if err != nil {
			t.Fatalf("FindUserByID %s: %v", id, err)
		}
		if u.Email == target {
			holders++
		}
	}
	if holders != 1 {
		t.Fatalf("%d users hold %q after the race, want exactly 1 — UserBase.Email's uniqueness requirement is broken and every address-keyed lookup is now order-dependent",
			holders, target)
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

func TestCreateSessionDuplicateIDFails(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash1"}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	_, err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash2"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("second CreateSession (same id) err = %v, want ErrIDTaken", err)
	}

	// The original row must be completely untouched by the rejected write.
	got, err := st.FindSessionByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("FindSessionByHash(hash1): %v", err)
	}
	if got.ID != "sess1" {
		t.Fatalf("original session's ID = %q, want sess1", got.ID)
	}
	if _, err := st.FindSessionByHash(ctx, "hash2"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(hash2) err = %v, want ErrSessionNotFound — the rejected write must not persist", err)
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

// --- CreateSuccessorSession ---

// TestCreateSuccessorSessionSucceedsWhenPredecessorExists pins the ordinary
// path: predecessorID still identifies a row, so the successor is inserted
// and ok is true.
func TestCreateSuccessorSessionSucceedsWhenPredecessorExists(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	now := time.Now()
	rotatedAt := now
	if _, err := st.CreateSession(ctx, auth.Session{
		ID: "pred1", FamilyID: "fam1", TokenHash: "hash-pred", RotatedAt: &rotatedAt,
	}); err != nil {
		t.Fatalf("CreateSession(predecessor): %v", err)
	}

	succ := auth.Session{ID: "succ1", FamilyID: "fam1", TokenHash: "hash-succ", UserID: "user1"}
	got, ok, err := st.CreateSuccessorSession(ctx, "pred1", succ)
	if err != nil {
		t.Fatalf("CreateSuccessorSession: %v", err)
	}
	if !ok {
		t.Fatal("CreateSuccessorSession ok = false, want true — the predecessor exists")
	}
	if got != succ {
		t.Fatalf("CreateSuccessorSession returned %+v, want %+v unchanged", got, succ)
	}

	stored, err := st.FindSessionByHash(ctx, "hash-succ")
	if err != nil {
		t.Fatalf("FindSessionByHash(successor): %v", err)
	}
	if stored.ID != "succ1" {
		t.Fatalf("stored successor ID = %q, want succ1", stored.ID)
	}
}

// TestCreateSuccessorSessionFailsWhenPredecessorGone pins the whole reason
// this method exists: if predecessorID no longer identifies a row — the
// family was already revoked — the successor must NOT be inserted, ok must
// be false, and this must NOT be reported as an error (it's an expected
// outcome of a real race, matching MarkRotated's own ok=false stance).
func TestCreateSuccessorSessionFailsWhenPredecessorGone(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()

	succ := auth.Session{ID: "succ1", FamilyID: "fam1", TokenHash: "hash-succ"}
	got, ok, err := st.CreateSuccessorSession(ctx, "nonexistent-predecessor", succ)
	if err != nil {
		t.Fatalf("CreateSuccessorSession err = %v, want nil (a lost race is not a failure)", err)
	}
	if ok {
		t.Fatal("CreateSuccessorSession ok = true despite a nonexistent predecessor")
	}
	if got != (auth.Session{}) {
		t.Fatalf("CreateSuccessorSession returned %+v, want the zero value", got)
	}

	// The critical assertion: nothing was inserted at all.
	if _, err := st.FindSessionByHash(ctx, "hash-succ"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(successor) err = %v, want ErrSessionNotFound — CreateSuccessorSession must not have inserted anything", err)
	}
}

// TestCreateSuccessorSessionDuplicateIDFails pins that s.ID's own uniqueness
// is still enforced, matching CreateSession's own contract, independent of
// predecessorID's existence.
func TestCreateSuccessorSessionDuplicateIDFails(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{ID: "pred1", TokenHash: "hash-pred"}); err != nil {
		t.Fatalf("CreateSession(predecessor): %v", err)
	}
	if _, err := st.CreateSession(ctx, auth.Session{ID: "already-taken", TokenHash: "hash-existing"}); err != nil {
		t.Fatalf("CreateSession(existing): %v", err)
	}

	_, ok, err := st.CreateSuccessorSession(ctx, "pred1", auth.Session{ID: "already-taken", TokenHash: "hash-new"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("CreateSuccessorSession(duplicate id) err = %v, want ErrIDTaken", err)
	}
	if ok {
		t.Fatal("CreateSuccessorSession ok = true despite ErrIDTaken")
	}

	// The original row must be untouched.
	got, err := st.FindSessionByHash(ctx, "hash-existing")
	if err != nil || got.ID != "already-taken" {
		t.Fatalf("original row disturbed: got=%+v err=%v", got, err)
	}
}

// TestCreateSuccessorSessionIDTakenCheckedEvenWhenPredecessorGone pins the
// precedence between the two failure conditions this method can report: an
// id collision is reported (ErrIDTaken) even when the predecessor is ALSO
// already gone, rather than the predecessor-gone case masking it with a
// bare ok=false. Either failure alone is enough to refuse the insert; this
// confirms which one the store surfaces when both are true.
func TestCreateSuccessorSessionIDTakenCheckedEvenWhenPredecessorGone(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateSession(ctx, auth.Session{ID: "already-taken", TokenHash: "hash-existing"}); err != nil {
		t.Fatalf("CreateSession(existing): %v", err)
	}

	_, ok, err := st.CreateSuccessorSession(ctx, "no-such-predecessor", auth.Session{ID: "already-taken", TokenHash: "hash-new"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("CreateSuccessorSession err = %v, want ErrIDTaken", err)
	}
	if ok {
		t.Fatal("CreateSuccessorSession ok = true despite ErrIDTaken")
	}
}

// oneWinner reports whether (successes, errs) — a tally of MarkRotated
// outcomes from some race — satisfies "exactly one winner, no errors". It is
// a plain boolean predicate, not a t.Fatalf-calling assertion, specifically
// so it can be reused with opposite polarity: it is the same condition
// authtest's own MarkRotated race asserts of a real auth.Store (its PASS
// condition is "one winner"), while TestSplitLockStoreProducesTwoWinners
// below asserts oneWinner is false of splitLockStore's results (its PASS
// condition is "the one-winner predicate correctly rejects two winners").
// Stating it once, here, is what makes that control genuine evidence about
// the shared suite's assertion rather than a parallel test that merely
// resembles it.
func oneWinner(successes, errs int) bool {
	return errs == 0 && successes == 1
}

// TestAuthStoreSatisfiesTheStoreContract runs the exported
// [github.com/bernardoforcillo/authlayer/auth/authtest] suite against this
// package's store: every documented obligation of auth.Store, including the
// MarkRotated race this test used to drive from a local copy of the driver.
// That copy is gone — the suite is the one implementation of the contract
// now, shared with store/drops' live-PostgreSQL lane, which previously had
// to reimplement it because an unexported helper in a _test.go file is
// reachable from nowhere else.
//
// The suite's MarkRotated check pins the same observable contract the local
// copy did: N goroutines started ahead of time and blocked on a channel so
// they all enter MarkRotated at effectively the same instant once it closes
// (the same construction as store/memory/invite_test.go's
// TestConsumeLinkConcurrencyExactlyOneWinner), exactly one observing
// ok=true, the rest ok=false with no error, and a final RotatedAt equal to
// the shared instant every goroutine raced with.
//
// [authtest.RunTokenHashUniquenessContract] is deliberately NOT run here:
// this store does not enforce Session.TokenHash or Verification.TokenHash
// uniqueness, on purpose and as its own package doc says, deferring it to
// store/drops. That is why the uniqueness obligation is a separate entry
// point in authtest rather than part of RunStoreContract.
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
//     ConsumeLink's simpler map lookup. An independent reviewer reproduced
//     this on different hardware and measured 1 failure in 160 runs
//     (~0.6%) — a different number, same conclusion: naive-window detection
//     is real but far too unreliable to trust, and the lower rate makes
//     refusing to call 3/70 "confirmation" look more justified, not less —
//     a reviewer re-running the same experiment could easily have seen 0
//     failures and called the mutation flaky-clean, exactly as happened to
//     Plan 4's ConsumeLink.
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
// catch on memory.AuthStore itself (100% on the naive window, no sleep
// needed) was not pursued: unlike store/drops' live-Postgres tests, an
// in-process mutex has no independent contention source (no row lock, no
// wire round trip) to interleave against from outside the method — the
// split-lock window lies inside one method's own body, between its own
// Unlock and its next Lock, and no wrapper or double placed around
// AuthStore.MarkRotated has a seam to park at that point. Forcing it really
// would require a test-only blocking hook compiled into AuthStore.MarkRotated
// itself — instrumenting production code purely to make a test of its
// ABSENCE of a bug more reliable. That trade is still not taken here, for
// the same reason Plan 4 ultimately answered the equivalent question
// (ConsumeLink) with a live-Postgres test rather than instrumenting
// store/memory: the deterministic version against memory.AuthStore itself
// belongs against a real contention source, i.e. this package's store/drops
// counterpart, in a later task.
//
// What IS pursued here, and requires no production instrumentation at all,
// is a deterministic negative control: TestSplitLockStoreProducesTwoWinners
// below drives a small, standalone, deliberately-broken double that
// implements exactly the split-lock shape, with a gate channel guaranteeing
// — not merely risking — that a second caller completes its full cycle while
// the first is parked mid-method, then applies the identical oneWinner
// predicate the shared suite's own MarkRotated race asserts (see that
// function's doc) and asserts it is false. That control does NOT reuse the
// suite's N-goroutine channel-barrier driver: that driver has no hook to
// release a parked goroutine only after the others have finished, so driving
// it verbatim here would either deadlock (nothing would ever close the gate)
// or require releasing on a timer, reintroducing exactly the
// timing-dependence this control exists to eliminate. It uses its own
// minimal, two-goroutine, explicitly-sequenced driver instead — see its own
// doc for the construction — and shares the assertion, not the driver. That
// control passes 100% of the time, every run, with no sleep anywhere. It
// does not prove memory.AuthStore is atomic — nothing outside the method can
// force that interleaving on it — but it does prove oneWinner itself is a
// real detector of this exact bug shape (false when fed a genuinely broken
// store's results), not a tautology that happens to always report success.
// The real guarantee that MarkRotated is atomic is the implementation
// holding one lock across the entire check-and-mark (see its doc comment in
// auth.go) plus that negative control, not this hand-run mutation
// experiment — this test pins the contract and catches a grossly broken
// implementation reliably (100% once the window is widened) and a subtly
// broken one occasionally (~1-4% at the naive window), per the same caveats
// TestConsumeLinkConcurrencyExactlyOneWinner's doc states.
//
// It is also a logical (check-then-act) race, not a memory race: every
// individual map read and write in the broken variant is still separately
// mutex-protected, so `go test -race` sees nothing unsynchronized and will
// not flag it either. Run -race anyway — it catches a different class of
// mutation, such as dropping the locking altogether — just not this one.
func TestAuthStoreSatisfiesTheStoreContract(t *testing.T) {
	authtest.RunStoreContract(t, func(*testing.T) auth.Store { return newAuthStore() })
}

// splitLockStore is a small, standalone, test-only auth.Store double that
// deliberately implements MarkRotated with the exact broken shape the
// mutation experiment above describes by hand: read the session under mu,
// unlock, decide, then a second mu.Lock to write. It exists to turn that
// hand-run, timing-dependent experiment into a committed, deterministic
// check — see TestSplitLockStoreProducesTwoWinners. It only implements
// CreateSession and MarkRotated; it is never asserted to satisfy auth.Store
// and is never handed to the shared contract suite, which requires a real,
// correct implementation.
type splitLockStore struct {
	mu       sync.Mutex
	sessions map[string]auth.Session

	// parked is CompareAndSwap'd by whichever caller reaches the gap first,
	// so exactly one caller — not "the first Nth of them" and not
	// "whichever wins a data race on a plain bool" — ever blocks on gate.
	// This is deliberately NOT a sync.Once: Once.Do serializes every
	// concurrent caller behind the first call until that first call
	// returns, so if the chosen goroutine's body blocks on gate (as this
	// one must, to create the window), every other caller would block on
	// Once.Do too, and the second caller could never reach MarkRotated to
	// complete its cycle — deadlocking the whole test instead of letting it
	// through. atomic.Bool.CompareAndSwap elects a winner without blocking
	// the losers at the point of election; only the winner blocks, and only
	// on gate.
	parked   atomic.Bool
	parkedCh chan struct{} // closed once the first caller has parked
	gate     chan struct{} // closed by the test to release the parked caller
}

func newSplitLockStore() *splitLockStore {
	return &splitLockStore{
		sessions: map[string]auth.Session{},
		parkedCh: make(chan struct{}),
		gate:     make(chan struct{}),
	}
}

// CreateSession stores the session under its ID, mirroring
// AuthStore.CreateSession's happy path (no id-collision guard — this double
// exists to test MarkRotated, not Create semantics).
func (s *splitLockStore) CreateSession(_ context.Context, sess auth.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

// MarkRotated is the deliberately broken shape: the find, under mu, is
// unlocked before the RotatedAt decision and the write, which take a second,
// independent acquisition. The first caller to reach the gap parks on gate
// until the test releases it; every other caller sails through untouched, so
// whichever of them observes the still-unrotated sess also decides ok=true
// and also writes.
func (s *splitLockStore) MarkRotated(_ context.Context, tokenHash string, now time.Time) (auth.Session, bool, error) {
	s.mu.Lock()
	var id string
	var sess auth.Session
	found := false
	for i, sv := range s.sessions {
		if sv.TokenHash == tokenHash {
			id, sess, found = i, sv, true
			break
		}
	}
	s.mu.Unlock()

	if !found {
		return auth.Session{}, false, auth.ErrSessionNotFound
	}
	if sess.RotatedAt != nil {
		return sess, false, nil
	}

	if s.parked.CompareAndSwap(false, true) {
		close(s.parkedCh)
		<-s.gate
	}

	s.mu.Lock()
	sess.RotatedAt = &now
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, true, nil
}

// TestSplitLockStoreProducesTwoWinners is the deterministic negative control
// TestAuthStoreSatisfiesTheStoreContract's doc comment describes: it
// proves oneWinner (the predicate the shared suite's MarkRotated race
// asserts) actually rejects the check-then-act bug shape, with no timing
// dependency and no sleep anywhere — unlike the hand-run mutation experiment
// (3/70 or 1/160 naive, 20/20 only once widened with a sleep), this test
// gets the intended, correct verdict 100% of the time, by construction,
// every run.
//
// It does NOT drive splitLockStore through the shared suite's N-goroutine
// channel-barrier driver — splitLockStore implements only CreateSession and
// MarkRotated (with a CreateSession signature that doesn't even match
// auth.Store's), it is never asserted to satisfy auth.Store, and is never
// handed to the shared contract suite, which requires a real, correct
// implementation. It also could not be, even if it did satisfy the
// interface: that driver has no way to release the one parked
// goroutine only after every other goroutine has already finished, so
// launching splitLockStore's two callers through it would either deadlock
// (nothing would ever close gate) or force releasing on a timer, which is
// exactly the timing-dependence this control exists to eliminate. What is
// genuinely shared with the suite is the assertion, via oneWinner:
// this test computes its own (successes, errs) from a minimal, two-goroutine,
// explicitly-sequenced driver below, then evaluates the identical oneWinner
// function and asserts it is false — proving that function is a real
// detector, not a tautology that happens to always report success.
//
// It does not exercise memory.AuthStore at all and does not prove that type
// is atomic — nothing outside MarkRotated's body can force this interleaving
// on it, since the split lies inside one method between its own Unlock and
// its next Lock, with no seam for a wrapper to park at. That absence of a
// seam is exactly why splitLockStore is a standalone double rather than a
// wrapper around AuthStore.
//
// Construction: caller A starts and races into MarkRotated, wins the park
// (asserted by waiting on parkedCh rather than sleeping), and blocks on
// gate. Caller B then starts and is driven all the way to completion —
// wg.Wait() proves it, not a timeout — while A is still parked, so B
// necessarily also observes the unrotated session and also writes. Only
// then is A released. Both must report ok=true, and both must go on to
// report no error — a nil-error MarkRotated call with ok=false is a
// legitimate "someone else won" outcome, not a bug, but it would mean this
// double failed to reproduce the shape it exists to reproduce, so it is
// checked, not assumed.
func TestSplitLockStoreProducesTwoWinners(t *testing.T) {
	st := newSplitLockStore()
	ctx := context.Background()
	if err := st.CreateSession(ctx, auth.Session{ID: "sess1", TokenHash: "hash1"}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	now := time.Now()
	var wgA sync.WaitGroup
	var okA bool
	var errA error

	wgA.Add(1)
	go func() {
		defer wgA.Done()
		_, ok, err := st.MarkRotated(ctx, "hash1", now)
		okA, errA = ok, err
	}()

	<-st.parkedCh // block until A has claimed the gap and parked — no spin, no sleep

	var wgB sync.WaitGroup
	var okB bool
	var errB error
	wgB.Add(1)
	go func() {
		defer wgB.Done()
		_, ok, err := st.MarkRotated(ctx, "hash1", now)
		okB, errB = ok, err
	}()
	wgB.Wait() // B has now run its entire read-decide-write cycle to completion

	close(st.gate) // release A
	wgA.Wait()

	successes, errs := 0, 0
	for _, ok := range []bool{okA, okB} {
		if ok {
			successes++
		}
	}
	for _, err := range []error{errA, errB} {
		if err != nil {
			errs++
		}
	}

	if errs != 0 {
		t.Fatalf("got %d unexpected errors from MarkRotated (errA=%v, errB=%v)", errs, errA, errB)
	}
	if successes != 2 {
		t.Fatalf("got successes=%d, want exactly 2 — splitLockStore's broken shape must let both callers win, or it isn't reproducing the bug shape this control exists to demonstrate", successes)
	}
	// The genuine warrant: apply the identical predicate the shared suite's
	// MarkRotated race depends on, to this double's results, and confirm it
	// correctly says no.
	if oneWinner(successes, errs) {
		t.Fatalf("oneWinner(successes=%d, errs=%d) = true, want false — this predicate must reject a check-then-act MarkRotated's results, and it did not", successes, errs)
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

// TestCreateVerificationNormalizesEmailOnWrite pins I-1: Verification.Email
// — the address the token was minted for — must be normalized on write, the
// same as UserBase.Email itself, so it can never land a non-canonical
// address in the users table once redeemed (via UpdateUserEmail).
func TestCreateVerificationNormalizesEmailOnWrite(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()

	if _, err := st.CreateVerification(ctx, auth.Verification{
		ID: "ver1", TokenHash: "hash1", Purpose: "email_change", Email: "  New@Example.com  ",
	}); err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}

	got, err := st.FindVerificationByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if got.Email != "new@example.com" {
		t.Fatalf("stored Email = %q, want normalized %q", got.Email, "new@example.com")
	}
}

// TestCreateVerificationNormalizesEmailOnWriteForSignup is
// TestCreateVerificationNormalizesEmailOnWrite's sibling for "signup" —
// pinning round 3's fix directly: Email must be populated and normalized
// for EVERY Purpose, not only "email_change". Before this fix the field
// (then named NewEmail) was documented empty for every Purpose but
// email_change, which is what made MarkEmailVerified's email-match check
// vacuous for signup (see TestMarkEmailVerifiedRefusesStaleAddressForSignup).
func TestCreateVerificationNormalizesEmailOnWriteForSignup(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()

	if _, err := st.CreateVerification(ctx, auth.Verification{
		ID: "ver1", TokenHash: "hash1", Purpose: "signup", Email: "  Bob@Example.com  ",
	}); err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}

	got, err := st.FindVerificationByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Fatalf("stored Email = %q, want normalized %q — a signup verification must carry its address too, not just email_change", got.Email, "bob@example.com")
	}
}

func TestCreateVerificationDuplicateIDFails(t *testing.T) {
	st := newAuthStore()
	ctx := context.Background()
	if _, err := st.CreateVerification(ctx, auth.Verification{ID: "ver1", TokenHash: "hash1"}); err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}

	_, err := st.CreateVerification(ctx, auth.Verification{ID: "ver1", TokenHash: "hash2"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("second CreateVerification (same id) err = %v, want ErrIDTaken", err)
	}

	// The original row must be completely untouched by the rejected write.
	if _, err := st.FindVerificationByHash(ctx, "hash1"); err != nil {
		t.Fatalf("FindVerificationByHash(hash1): %v", err)
	}
	if _, err := st.FindVerificationByHash(ctx, "hash2"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(hash2) err = %v, want ErrVerificationNotFound — the rejected write must not persist", err)
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
