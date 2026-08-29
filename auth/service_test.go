package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// testCost is bcrypt's minimum valid cost, used throughout instead of the
// library default so this suite runs quickly — bcrypt is deliberately slow,
// and DefaultCost-strength hashing on every test would make the suite slow
// for no correctness benefit. Matches password_test.go's own testCost.
const testCost = bcrypt.MinCost

// testSigningKey is a 32-byte (the token package's own minimum) HMAC key
// used across this suite's Services.
var testSigningKey = bytes.Repeat([]byte("k"), 32)

// testUser is an application's own user type: it embeds auth.UserBase and
// adds one extra field, DisplayName, satisfying auth.MutableUser entirely
// through promoted methods (see UserBase.Base / UserBase.SetBase) — no
// method of its own is written, which is itself the property this type
// exists to demonstrate.
type testUser struct {
	auth.UserBase
	DisplayName string
}

// newTestService builds a Service[testUser] over a fresh in-memory store, a
// fast (testCost) Hasher, and a fixed signing key, plus whatever additional
// options a test needs.
func newTestService(t *testing.T, opts ...auth.Option) (*auth.Service[testUser, *testUser], *memory.AuthStore) {
	t.Helper()
	store := memory.NewAuthStore()
	base := []auth.Option{
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	}
	svc := auth.New[testUser](store, append(base, opts...)...)
	return svc, store
}

// --- spyHasher: records which method was called with what, and how many
// times, while still delegating to a real (fast-cost) bcrypt Hasher so
// Verify/Dummy results stay honest. ---

type spyHasher struct {
	inner password.Hasher

	mu          sync.Mutex
	hashCalls   []string
	verifyCalls []string
	dummyCalls  []string
}

func newSpyHasher() *spyHasher { return &spyHasher{inner: password.Bcrypt(testCost)} }

func (s *spyHasher) Hash(plain string) (string, error) {
	s.mu.Lock()
	s.hashCalls = append(s.hashCalls, plain)
	s.mu.Unlock()
	return s.inner.Hash(plain)
}

func (s *spyHasher) Verify(plain, hash string) bool {
	s.mu.Lock()
	s.verifyCalls = append(s.verifyCalls, plain)
	s.mu.Unlock()
	return s.inner.Verify(plain, hash)
}

func (s *spyHasher) Dummy(plain string) {
	s.mu.Lock()
	s.dummyCalls = append(s.dummyCalls, plain)
	s.mu.Unlock()
	s.inner.Dummy(plain)
}

func (s *spyHasher) counts() (hash, verify, dummy int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hashCalls), len(s.verifyCalls), len(s.dummyCalls)
}

// --- fakeLimiter: a scriptable auth.RateLimiter that records every key it
// was asked about. ---

type fakeLimiter struct {
	allow bool
	err   error

	mu   sync.Mutex
	keys []string
}

func (l *fakeLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.mu.Lock()
	l.keys = append(l.keys, key)
	l.mu.Unlock()
	return l.allow, l.err
}

func (l *fakeLimiter) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

// --- countingStore: wraps memory.AuthStore, counting calls to
// FindUserByEmail and CreateUser — the two operations SignUp could reach
// before deciding new-vs-duplicate — used to prove SignUp never touches the
// Store at all on a rejected (weak) password. ---

type countingStore struct {
	*memory.AuthStore
	mu               sync.Mutex
	findByEmailCalls int
	createUserCalls  int
}

func newCountingStore() *countingStore {
	return &countingStore{AuthStore: memory.NewAuthStore()}
}

func (s *countingStore) FindUserByEmail(ctx context.Context, email string) (auth.UserBase, error) {
	s.mu.Lock()
	s.findByEmailCalls++
	s.mu.Unlock()
	return s.AuthStore.FindUserByEmail(ctx, email)
}

func (s *countingStore) CreateUser(ctx context.Context, u auth.UserBase) (auth.UserBase, error) {
	s.mu.Lock()
	s.createUserCalls++
	s.mu.Unlock()
	return s.AuthStore.CreateUser(ctx, u)
}

// calls returns the total number of FindUserByEmail + CreateUser calls —
// the two operations SignUp could reach before password validation, if
// that check were ever moved after them.
func (s *countingStore) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findByEmailCalls + s.createUserCalls
}

func (s *countingStore) reset() {
	s.mu.Lock()
	s.findByEmailCalls, s.createUserCalls = 0, 0
	s.mu.Unlock()
}

// --- orderStore: wraps memory.AuthStore, recording the exact sequence of
// calls to the three methods VerifyEmail's ordering contract is about. ---

type orderStore struct {
	*memory.AuthStore
	mu    sync.Mutex
	order []string
}

func newOrderStore() *orderStore { return &orderStore{AuthStore: memory.NewAuthStore()} }

func (s *orderStore) record(name string) {
	s.mu.Lock()
	s.order = append(s.order, name)
	s.mu.Unlock()
}

func (s *orderStore) DeleteVerification(ctx context.Context, id string) error {
	s.record("DeleteVerification")
	return s.AuthStore.DeleteVerification(ctx, id)
}

func (s *orderStore) MarkEmailVerified(ctx context.Context, userID, email string, now time.Time) error {
	s.record("MarkEmailVerified")
	return s.AuthStore.MarkEmailVerified(ctx, userID, email, now)
}

func (s *orderStore) UpdateUserEmail(ctx context.Context, userID, email string, now time.Time) error {
	s.record("UpdateUserEmail")
	return s.AuthStore.UpdateUserEmail(ctx, userID, email, now)
}

// UpdateUserPassword records its own call — used by
// TestResetPasswordClaimsBeforeApplyOrdering, [ResetPassword]'s ordering
// analogue of TestVerifyEmailClaimsBeforeApplyOrderingSignup above.
func (s *orderStore) UpdateUserPassword(ctx context.Context, userID, passwordHash string, now time.Time) error {
	s.record("UpdateUserPassword")
	return s.AuthStore.UpdateUserPassword(ctx, userID, passwordHash, now)
}

func (s *orderStore) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// --- errStore: wraps memory.AuthStore, forcing FindUserByEmail (and
// optionally FindVerificationByHash) to fail with an arbitrary, non-sentinel
// error — used to prove SignUp/Login/VerifyEmail fail closed on a Store
// error they cannot interpret as "not found". ---

var errStoreBoom = errors.New("boom: simulated store outage")

type errStore struct {
	*memory.AuthStore
	failFindUserByEmail        bool
	failFindVerificationByHash bool
	failCreateUser             bool
}

func (s *errStore) FindUserByEmail(ctx context.Context, email string) (auth.UserBase, error) {
	if s.failFindUserByEmail {
		return auth.UserBase{}, errStoreBoom
	}
	return s.AuthStore.FindUserByEmail(ctx, email)
}

func (s *errStore) FindVerificationByHash(ctx context.Context, hash string) (auth.Verification, error) {
	if s.failFindVerificationByHash {
		return auth.Verification{}, errStoreBoom
	}
	return s.AuthStore.FindVerificationByHash(ctx, hash)
}

func (s *errStore) CreateUser(ctx context.Context, u auth.UserBase) (auth.UserBase, error) {
	if s.failCreateUser {
		return auth.UserBase{}, errStoreBoom
	}
	return s.AuthStore.CreateUser(ctx, u)
}

// --- write-outage doubles for FIX 1: both wrap a real, healthy
// memory.AuthStore for reads (so ErrEmailTaken/not-found decisions stay
// correct) while making some subset of writes fail identically for every
// caller, regardless of which address is involved. SignUp no longer calls
// DeleteVerificationsByUserAndPurpose at all (see FIX 2, round 2: deleting
// an existing account's pending verification on an unauthenticated probe
// was itself the bug), so these doubles fail only the writes SignUp still
// performs: CreateUser and CreateVerification. ---

var errWriteBoom = errors.New("boom: simulated write-path outage")

// allWritesFailStore fails every write SignUp could reach (CreateUser,
// CreateVerification) — the broadest outage: e.g. a full disk affecting
// the whole database.
type allWritesFailStore struct {
	*memory.AuthStore
}

func (s *allWritesFailStore) CreateUser(context.Context, auth.UserBase) (auth.UserBase, error) {
	return auth.UserBase{}, errWriteBoom
}

func (s *allWritesFailStore) CreateVerification(context.Context, auth.Verification) (auth.Verification, error) {
	return auth.Verification{}, errWriteBoom
}

// deleteVerificationsFailStore fails ONLY DeleteVerificationsByUserAndPurpose
// (every read and every other write healthy) — used to prove SignUp never
// calls it at all, not merely that it survives the call failing.
type deleteVerificationsFailStore struct {
	*memory.AuthStore
}

func (s *deleteVerificationsFailStore) DeleteVerificationsByUserAndPurpose(context.Context, string, string) error {
	return errWriteBoom
}

// verificationWriteFailStore leaves CreateUser and every read fully
// healthy (delegated to the real store, so ErrEmailTaken is still reported
// correctly) but fails CreateVerification — a narrower, more realistic
// outage affecting only the verifications table's writes.
type verificationWriteFailStore struct {
	*memory.AuthStore
}

func (s *verificationWriteFailStore) CreateVerification(context.Context, auth.Verification) (auth.Verification, error) {
	return auth.Verification{}, errWriteBoom
}

// usersTableWritesFailStore fails ONLY CreateUser, leaving reads and every
// verification-related write healthy — a narrower outage than
// allWritesFailStore, isolating whether new-vs-duplicate detection itself
// (CreateUser, not a preliminary FindUserByEmail) is what makes this
// specific write's failure surface reachable on both branches.
type usersTableWritesFailStore struct {
	*memory.AuthStore
}

func (s *usersTableWritesFailStore) CreateUser(context.Context, auth.UserBase) (auth.UserBase, error) {
	return auth.UserBase{}, errWriteBoom
}

// purposeSweepFailStore fails DeleteVerificationsByUserAndPurpose for ONE
// nominated purpose and delegates every other call — including a sweep of
// any other purpose — to a healthy store. Unlike deleteVerificationsFailStore
// (which fails the method wholesale, so a test using it cannot tell WHICH
// sweep propagated), this isolates a single sweep: pointing it at
// "email_change" leaves the long-standing "password_reset" sweep succeeding,
// so a failure reaching the caller can only have come from the email_change
// sweep the credential-rotation fix added.
type purposeSweepFailStore struct {
	*memory.AuthStore
	failPurpose string
}

func (s *purposeSweepFailStore) DeleteVerificationsByUserAndPurpose(ctx context.Context, userID, purpose string) error {
	if purpose == s.failPurpose {
		return errWriteBoom
	}
	return s.AuthStore.DeleteVerificationsByUserAndPurpose(ctx, userID, purpose)
}

const validPassword = "Correct-Horse-Battery-9!"

// ============================================================
// SignUp
// ============================================================

// TestSignUpValidatesPasswordBeforeLookup pins the required ordering: a weak
// password must be rejected WITHOUT the Store ever being consulted. This is
// the test the brief's first mandatory mutation targets: move the
// password.Validate call to after the lookup, and this must fail.
func TestSignUpValidatesPasswordBeforeLookup(t *testing.T) {
	store := newCountingStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	_, err := svc.SignUp(context.Background(), "someone@example.com", "weak")
	if !errors.Is(err, auth.ErrWeakPassword) {
		t.Fatalf("SignUp(weak password) err = %v, want ErrWeakPassword", err)
	}
	if got := store.calls(); got != 0 {
		t.Fatalf("Store was touched %d times for a password that should have been rejected before any lookup or write; want 0", got)
	}
}

// TestSignUpWeakPasswordIdenticalForNewAndExistingAddress restates the same
// property from the enumeration angle: an already-registered address and a
// brand new one must reject a weak password identically — same error, and
// crucially the Store's FindUserByEmail is never reached for either, so
// there is no lookup result to leak a timing or behavioural difference
// through.
func TestSignUpWeakPasswordIdenticalForNewAndExistingAddress(t *testing.T) {
	store := newCountingStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	// Register one real account first.
	if _, err := svc.SignUp(context.Background(), "existing@example.com", validPassword); err != nil {
		t.Fatalf("seeding SignUp: %v", err)
	}
	store.reset() // reset the counters after the seed signup

	_, err1 := svc.SignUp(context.Background(), "existing@example.com", "weak")
	_, err2 := svc.SignUp(context.Background(), "brand-new@example.com", "weak")

	if !errors.Is(err1, auth.ErrWeakPassword) || !errors.Is(err2, auth.ErrWeakPassword) {
		t.Fatalf("errs = %v, %v, want both ErrWeakPassword", err1, err2)
	}
	if got := store.calls(); got != 0 {
		t.Fatalf("Store touched %d times across two weak-password sign-ups; want 0 for both", got)
	}
}

// TestSignUpEnumerationSafeOnDuplicate pins the core property: SignUp for an
// address that is already registered returns Created:false, the EXISTING
// user, an empty VerifyToken, and a NIL error. This is the test the brief's
// second mandatory mutation targets: make SignUp return an error on a
// duplicate, and this must fail.
func TestSignUpEnumerationSafeOnDuplicate(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	first, err := svc.SignUp(ctx, "dup@example.com", validPassword)
	if err != nil {
		t.Fatalf("seeding SignUp: %v", err)
	}

	second, err := svc.SignUp(ctx, "DUP@Example.com  ", "A-Different-Valid-Pass1!")
	if err != nil {
		t.Fatalf("SignUp(duplicate) err = %v, want nil", err)
	}
	if second.Created {
		t.Fatalf("SignUp(duplicate).Created = true, want false")
	}
	if second.VerifyToken != "" {
		t.Fatalf("SignUp(duplicate).VerifyToken = %q, want empty", second.VerifyToken)
	}
	if second.User.ID != first.User.ID {
		t.Fatalf("SignUp(duplicate).User.ID = %q, want the existing user's id %q", second.User.ID, first.User.ID)
	}
}

// TestSignUpCreatesUserAndSignupVerification pins the success shape: a real
// new address gets Created:true, a populated user, a non-empty VerifyToken
// that resolves to a "signup" Verification bound to the same address and
// user.
func TestSignUpCreatesUserAndSignupVerification(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	res, err := svc.SignUp(ctx, "  Alice@Example.COM ", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if !res.Created {
		t.Fatalf("Created = false, want true")
	}
	if res.User.ID == "" {
		t.Fatal("User.ID is empty")
	}
	if res.User.Email != "alice@example.com" {
		t.Fatalf("User.Email = %q, want normalized \"alice@example.com\"", res.User.Email)
	}
	if res.VerifyToken == "" {
		t.Fatal("VerifyToken is empty for a newly created account")
	}

	v, err := store.FindVerificationByHash(ctx, token.HashOpaque(res.VerifyToken))
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if v.Purpose != auth.PurposeSignup {
		t.Fatalf("Verification.Purpose = %q, want %q", v.Purpose, auth.PurposeSignup)
	}
	if v.UserID != res.User.ID {
		t.Fatalf("Verification.UserID = %q, want %q", v.UserID, res.User.ID)
	}
	if v.Email != "alice@example.com" {
		t.Fatalf("Verification.Email = %q, want \"alice@example.com\"", v.Email)
	}
	if !v.ExpiresAt.After(time.Now()) {
		t.Fatalf("Verification.ExpiresAt = %v, want in the future", v.ExpiresAt)
	}
}

// TestSignUpHashesPasswordForNewAccount pins that a real sign-up's stored
// credential is produced by Hasher.Hash, and verifies against the plaintext
// via the same Hasher.
func TestSignUpHashesPasswordForNewAccount(t *testing.T) {
	spy := newSpyHasher()
	svc, store := newTestService(t, auth.WithHasher(spy))
	ctx := context.Background()

	res, err := svc.SignUp(ctx, "bob@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	hashN, verifyN, dummyN := spy.counts()
	if hashN != 1 || verifyN != 0 || dummyN != 0 {
		t.Fatalf("hasher calls (hash,verify,dummy) = (%d,%d,%d), want (1,0,0)", hashN, verifyN, dummyN)
	}

	u, err := store.FindUserByID(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if !spy.inner.Verify(validPassword, u.PasswordHash) {
		t.Fatal("stored PasswordHash does not verify against the plaintext SignUp was given")
	}
}

// TestSignUpHashesOnBothBranchesSymmetrically is the behavioural pin for
// FIX 1's redesign: the duplicate branch must ALSO call Hash (never Dummy,
// which cannot fail by design and so cannot close the write-failure-surface
// gap FIX 1 is about — see SignUp's "Fail closed, symmetrically" doc). This
// replaces the original round's Dummy-based pin, which described a design
// this method no longer uses.
func TestSignUpHashesOnBothBranchesSymmetrically(t *testing.T) {
	spy := newSpyHasher()
	svc, _ := newTestService(t, auth.WithHasher(spy))
	ctx := context.Background()

	if _, err := svc.SignUp(ctx, "carol@example.com", validPassword); err != nil {
		t.Fatalf("seeding SignUp: %v", err)
	}
	spy.mu.Lock()
	spy.hashCalls, spy.verifyCalls, spy.dummyCalls = nil, nil, nil
	spy.mu.Unlock()

	res, err := svc.SignUp(ctx, "carol@example.com", "Another-Valid-Pass2!")
	if err != nil {
		t.Fatalf("SignUp(duplicate): %v", err)
	}
	if res.Created {
		t.Fatal("Created = true on a duplicate address")
	}

	hashN, verifyN, dummyN := spy.counts()
	if hashN != 1 || verifyN != 0 || dummyN != 0 {
		t.Fatalf("hasher calls (hash,verify,dummy) = (%d,%d,%d), want (1,0,0) — the duplicate branch must hash too (and discard the result), never Dummy", hashN, verifyN, dummyN)
	}
}

// TestSignUpFailsClosedOnCreateUserError proves a Store failure on the
// PRIMARY write (CreateUser, now attempted on every call — see SignUp's
// doc) is surfaced as an error rather than silently folded into a duplicate
// result.
func TestSignUpFailsClosedOnCreateUserError(t *testing.T) {
	store := &errStore{AuthStore: memory.NewAuthStore(), failCreateUser: true}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	res, err := svc.SignUp(context.Background(), "dana@example.com", validPassword)
	if !errors.Is(err, errStoreBoom) {
		t.Fatalf("SignUp err = %v, want errStoreBoom", err)
	}
	if res.Created {
		t.Fatal("Created = true despite CreateUser failing")
	}
}

// TestSignUpReadFailureIndistinguishableAcrossBranches is round 2's
// CRITICAL fix, pinned directly: FindUserByEmail now runs unconditionally
// on every SignUp call (see the method doc's "Fail closed, by
// construction"), so a read-path outage must fail the new-address and
// already-registered branches identically. This is the exact gap round 1
// reopened, mirrored: with only the delete failing, and separately with
// only the read failing, a NEW address returned nil while a REGISTERED
// one errored — reachable by ordinary conditions (a DB role with INSERT
// but not DELETE, replica lag, row-lock contention), not just a total
// outage.
//
// The prior version of this test (TestSignUpFailsClosedOnDuplicateFollowUpReadError)
// only exercised the duplicate branch and, by construction of the OLD
// code, could not have caught this: FindUserByEmail was called on that
// branch alone. This version drives the identical read failure against
// BOTH a brand-new address and an already-registered one from the SAME
// store and asserts both fail with the SAME error.
func TestSignUpReadFailureIndistinguishableAcrossBranches(t *testing.T) {
	store := &errStore{AuthStore: memory.NewAuthStore(), failFindUserByEmail: true}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	// Seed directly on the underlying store, bypassing the wrapper (which
	// only fails FindUserByEmail; CreateUser is untouched).
	now := time.Now().UTC()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	if _, err := store.AuthStore.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-1", Email: "eve@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	_, errNew := svc.SignUp(context.Background(), "frankie@example.com", validPassword)
	_, errDup := svc.SignUp(context.Background(), "eve@example.com", validPassword)

	if errNew == nil {
		t.Fatal("SignUp(new address) succeeded despite the read path being broken")
	}
	if errDup == nil {
		t.Fatal("SignUp(existing address) succeeded despite the read path being broken — registered addresses must not sail through a read outage that fails new ones")
	}
	if !errors.Is(errNew, errStoreBoom) || !errors.Is(errDup, errStoreBoom) {
		t.Fatalf("errNew=%v errDup=%v, want both to wrap errStoreBoom — the caller must not be able to tell the branches apart by error identity either", errNew, errDup)
	}
}

// TestSignUpWriteFailureIndistinguishableAcrossBranches is the test FIX 1
// specifically asked for: drive a store write failure and confirm the
// new-address and already-registered branches are indistinguishable to the
// caller. Both must fail, and fail with the SAME error, under a store whose
// every write method fails identically regardless of which address is
// used — proving error-presence alone can no longer serve as an
// enumeration oracle.
func TestSignUpWriteFailureIndistinguishableAcrossBranches(t *testing.T) {
	inner := memory.NewAuthStore()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	now := time.Now().UTC()
	if _, err := inner.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-1", Email: "existing@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	store := &allWritesFailStore{AuthStore: inner}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	_, errNew := svc.SignUp(context.Background(), "brandnew@example.com", validPassword)
	_, errDup := svc.SignUp(context.Background(), "existing@example.com", validPassword)

	if errNew == nil {
		t.Fatal("SignUp(new address) succeeded despite a total write outage")
	}
	if errDup == nil {
		t.Fatal("SignUp(existing address) succeeded despite a total write outage — this is exactly the enumeration oracle FIX 1 closes: a registered address must not sail through untouched while an unregistered one fails")
	}
	if !errors.Is(errNew, errWriteBoom) || !errors.Is(errDup, errWriteBoom) {
		t.Fatalf("errNew=%v errDup=%v, want both to wrap errWriteBoom — the caller must not be able to tell the branches apart by error identity either", errNew, errDup)
	}
}

// TestSignUpVerificationWriteFailureIndistinguishable isolates the mint
// step specifically: even when CreateUser and every read behave perfectly
// normally (as they would if only the verifications table's writes were
// broken), minting the "signup" Verification must fail identically on
// both branches — it is the literal same CreateVerification call on
// either branch (see SignUp's doc), not an "equivalent" one, so there is
// nothing branch-specific left for a partial outage to distinguish.
func TestSignUpVerificationWriteFailureIndistinguishable(t *testing.T) {
	inner := memory.NewAuthStore()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	now := time.Now().UTC()
	if _, err := inner.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-1", Email: "existing@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	store := &verificationWriteFailStore{AuthStore: inner}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	_, errNew := svc.SignUp(context.Background(), "brandnew2@example.com", validPassword)
	_, errDup := svc.SignUp(context.Background(), "existing@example.com", validPassword)

	if errNew == nil {
		t.Fatal("SignUp(new address) succeeded despite verification writes being broken")
	}
	if errDup == nil {
		t.Fatal("SignUp(existing address) succeeded despite verification writes being broken")
	}
	if !errors.Is(errNew, errWriteBoom) || !errors.Is(errDup, errWriteBoom) {
		t.Fatalf("errNew=%v errDup=%v, want both to wrap errWriteBoom", errNew, errDup)
	}
}

// TestSignUpUsersTableWriteFailureIndistinguishable isolates the FIRST half
// of FIX 1: even with reads and every verification-related write healthy,
// a broken CreateUser (e.g. only the users table's writes are down) must
// fail BOTH branches identically. This is what specifically depends on
// CreateUser being the SOLE new-vs-duplicate signal (see SignUp's doc) —
// reverting to a preliminary FindUserByEmail lookup, with CreateUser only
// attempted on the new-address branch, would let an existing address route
// around this broken call entirely and succeed.
func TestSignUpUsersTableWriteFailureIndistinguishable(t *testing.T) {
	inner := memory.NewAuthStore()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	now := time.Now().UTC()
	if _, err := inner.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-2", Email: "existing2@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	store := &usersTableWritesFailStore{AuthStore: inner}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	_, errNew := svc.SignUp(context.Background(), "brandnew3@example.com", validPassword)
	_, errDup := svc.SignUp(context.Background(), "existing2@example.com", validPassword)

	if errNew == nil {
		t.Fatal("SignUp(new address) succeeded despite the users table's writes being broken")
	}
	if errDup == nil {
		t.Fatal("SignUp(existing address) succeeded despite the users table's writes being broken — a preliminary read-only lookup let it route around CreateUser entirely")
	}
	if !errors.Is(errNew, errWriteBoom) || !errors.Is(errDup, errWriteBoom) {
		t.Fatalf("errNew=%v errDup=%v, want both to wrap errWriteBoom", errNew, errDup)
	}
}

// TestSignUpNeverReturnsPasswordHash pins FIX 2: SignUpResult.User never
// carries a live, usable PasswordHash, on EITHER branch — even though the
// Store itself does hold a real bcrypt digest for both users.
func TestSignUpNeverReturnsPasswordHash(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	created, err := svc.SignUp(ctx, "frank2@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp(new): %v", err)
	}
	if created.User.PasswordHash != "" {
		t.Fatalf("Created branch: User.PasswordHash = %q, want empty", created.User.PasswordHash)
	}
	stored, err := store.FindUserByID(ctx, created.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.PasswordHash == "" {
		t.Fatal("the STORE's own copy has no PasswordHash at all — seeding is broken, not just the return value")
	}

	dup, err := svc.SignUp(ctx, "frank2@example.com", "Another-Valid-Pass3!")
	if err != nil {
		t.Fatalf("SignUp(duplicate): %v", err)
	}
	if dup.Created {
		t.Fatal("Created = true on a duplicate address")
	}
	if dup.User.PasswordHash != "" {
		t.Fatalf("Duplicate branch: User.PasswordHash = %q, want empty — this would leak another account's live credential digest", dup.User.PasswordHash)
	}
}

// TestSignUpProbeDoesNotDestroyVictimsVerification pins FIX 2 directly: an
// unauthenticated probe of an already-registered, not-yet-verified address
// must NOT invalidate that account's real, already-issued "signup"
// verification. An earlier version deleted it first (mirroring
// invite.Service.InviteByEmail's replace-on-reinvite stance), which let
// anyone destroy a stranger's verification link merely by "signing up"
// with their address — a denial-of-service reachable by a single
// unauthenticated request, worse under WithRequireVerifiedEmail since this
// package exposes no resend path.
func TestSignUpProbeDoesNotDestroyVictimsVerification(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	victim, err := svc.SignUp(ctx, "victim@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp(victim): %v", err)
	}
	if victim.VerifyToken == "" {
		t.Fatal("victim's own VerifyToken is empty")
	}

	// The attacker probes the same address, learning nothing (Created is
	// false, VerifyToken is empty — the enumeration contract holds) but,
	// under the bug, also destroying the victim's real token as a side
	// effect.
	probe, err := svc.SignUp(ctx, "victim@example.com", "Attacker-Chosen-Pass1!")
	if err != nil {
		t.Fatalf("SignUp(probe): %v", err)
	}
	if probe.Created {
		t.Fatal("probe reported Created = true for an already-registered address")
	}
	if probe.VerifyToken != "" {
		t.Fatal("probe's VerifyToken is non-empty — the attacker must never receive a redeemable token")
	}

	// The victim's ORIGINAL token must still redeem successfully.
	user, err := svc.VerifyEmail(ctx, victim.VerifyToken)
	if err != nil {
		t.Fatalf("VerifyEmail(victim's original token) after a probe: %v — the probe destroyed the victim's real verification", err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is nil after redeeming the victim's original token")
	}
}

// TestSignUpNeverCallsDeleteVerifications is a lower-level companion:
// probing an existing address must not call DeleteVerificationsByUserAndPurpose
// at all (not merely "not destructively" — not at all), confirmed via a
// store double that fails that one method while leaving everything else,
// including CreateVerification, healthy. If SignUp still called it, this
// would fail; it does not.
func TestSignUpNeverCallsDeleteVerifications(t *testing.T) {
	store := &deleteVerificationsFailStore{AuthStore: memory.NewAuthStore()}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()

	if _, err := svc.SignUp(ctx, "gina2@example.com", validPassword); err != nil {
		t.Fatalf("SignUp(new): %v", err)
	}
	probe, err := svc.SignUp(ctx, "gina2@example.com", "Another-Valid-Pass4!")
	if err != nil {
		t.Fatalf("SignUp(probe): %v — DeleteVerificationsByUserAndPurpose must never be called", err)
	}
	if probe.Created {
		t.Fatal("Created = true on a duplicate address")
	}
}

// TestNewUserBaseDirectlyUsable confirms an application with no extra
// profile fields can instantiate Service[UserBase] directly — UserBase
// satisfies MutableUser via its own promoted Base/SetBase methods.
func TestNewUserBaseDirectlyUsable(t *testing.T) {
	store := memory.NewAuthStore()
	svc := auth.New[auth.UserBase](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	res, err := svc.SignUp(context.Background(), "erin@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if res.User.Email != "erin@example.com" {
		t.Fatalf("User.Email = %q, want \"erin@example.com\"", res.User.Email)
	}
}

// TestSignUpDoesNotConsultRateLimiter documents and pins that SignUp never
// calls the configured RateLimiter — rate limiting is scoped to Login only
// (see WithRateLimiter's doc).
func TestSignUpDoesNotConsultRateLimiter(t *testing.T) {
	limiter := &fakeLimiter{allow: false} // would deny everything, if consulted
	svc, _ := newTestService(t, auth.WithRateLimiter(limiter))

	if _, err := svc.SignUp(context.Background(), "frank@example.com", validPassword); err != nil {
		t.Fatalf("SignUp: %v (a denying limiter must not affect SignUp)", err)
	}
	if got := limiter.callCount(); got != 0 {
		t.Fatalf("RateLimiter.Allow called %d times by SignUp; want 0", got)
	}
}

// ============================================================
// Login
// ============================================================

func mustSignUp(t *testing.T, svc *auth.Service[testUser, *testUser], email, plain string) testUser {
	t.Helper()
	res, err := svc.SignUp(context.Background(), email, plain)
	if err != nil {
		t.Fatalf("SignUp(%q): %v", email, err)
	}
	return res.User
}

// mustLogin signs the given (already-registered) email/plain in with a
// fixed IP/UserAgent and fails the test on any error. Used throughout the
// Refresh/Logout/session-management suite below, which cares about the
// resulting user and refresh token, not about Login's own behaviour
// (already pinned above).
func mustLogin(t *testing.T, svc *auth.Service[testUser, *testUser], email, plain string) (user testUser, access, refresh string) {
	t.Helper()
	user, access, refresh, err := svc.Login(context.Background(), email, plain, "203.0.113.9", "test-agent")
	if err != nil {
		t.Fatalf("Login(%q): %v", email, err)
	}
	return user, access, refresh
}

func TestLoginSuccess(t *testing.T) {
	svc, store := newTestService(t)
	mustSignUp(t, svc, "gina@example.com", validPassword)

	user, access, refresh, err := svc.Login(context.Background(), "Gina@Example.com", validPassword, "203.0.113.5", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if user.Email != "gina@example.com" {
		t.Fatalf("Email = %q, want \"gina@example.com\"", user.Email)
	}
	if access == "" || refresh == "" {
		t.Fatalf("access=%q refresh=%q, want both non-empty", access, refresh)
	}

	claims, err := token.Parse(access, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse(access): %v", err)
	}
	if claims.Subject != user.ID {
		t.Fatalf("claims.Subject = %q, want %q", claims.Subject, user.ID)
	}
	if claims.Email != "gina@example.com" {
		t.Fatalf("claims.Email = %q, want \"gina@example.com\"", claims.Email)
	}

	sess, err := store.FindSessionByHash(context.Background(), token.HashOpaque(refresh))
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if sess.ID != claims.SessionID {
		t.Fatalf("session.ID = %q, want claims.SessionID = %q", sess.ID, claims.SessionID)
	}
	if sess.UserID != user.ID {
		t.Fatalf("session.UserID = %q, want %q", sess.UserID, user.ID)
	}
	if sess.IP != "203.0.113.5" || sess.UserAgent != "test-agent" {
		t.Fatalf("session IP/UserAgent = %q/%q, want the values Login was given", sess.IP, sess.UserAgent)
	}
	if sess.FamilyID != sess.ID {
		t.Fatalf("session.FamilyID = %q, want it to equal its own ID at login (root of the chain)", sess.FamilyID)
	}
}

// TestLoginUnknownUserFailsWithDummy is the behavioural pin for the brief's
// third mandatory mutation on Login: remove the Dummy call on the user-miss
// path and this must fail.
func TestLoginUnknownUserFailsWithDummy(t *testing.T) {
	spy := newSpyHasher()
	svc, _ := newTestService(t, auth.WithHasher(spy))

	_, _, _, err := svc.Login(context.Background(), "nobody@example.com", "whatever", "1.2.3.4", "")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	hashN, verifyN, dummyN := spy.counts()
	if hashN != 0 || verifyN != 0 || dummyN != 1 {
		t.Fatalf("hasher calls (hash,verify,dummy) = (%d,%d,%d), want (0,0,1)", hashN, verifyN, dummyN)
	}
}

func TestLoginWrongPasswordFailsWithVerify(t *testing.T) {
	spy := newSpyHasher()
	svc, _ := newTestService(t, auth.WithHasher(spy))
	mustSignUp(t, svc, "henry@example.com", validPassword)
	spy.mu.Lock()
	spy.hashCalls, spy.verifyCalls, spy.dummyCalls = nil, nil, nil
	spy.mu.Unlock()

	_, _, _, err := svc.Login(context.Background(), "henry@example.com", "wrong-password", "1.2.3.4", "")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	hashN, verifyN, dummyN := spy.counts()
	if hashN != 0 || verifyN != 1 || dummyN != 0 {
		t.Fatalf("hasher calls (hash,verify,dummy) = (%d,%d,%d), want (0,1,0)", hashN, verifyN, dummyN)
	}
}

// TestLoginUnknownUserAndWrongPasswordReturnSameError pins that the two
// failure causes are indistinguishable to the caller.
func TestLoginUnknownUserAndWrongPasswordReturnSameError(t *testing.T) {
	svc, _ := newTestService(t)
	mustSignUp(t, svc, "ivy@example.com", validPassword)

	_, _, _, errUnknown := svc.Login(context.Background(), "nobody@example.com", "x", "1.2.3.4", "")
	_, _, _, errWrong := svc.Login(context.Background(), "ivy@example.com", "wrong", "1.2.3.4", "")

	if !errors.Is(errUnknown, auth.ErrInvalidCredentials) || !errors.Is(errWrong, auth.ErrInvalidCredentials) {
		t.Fatalf("errs = %v, %v, want both ErrInvalidCredentials", errUnknown, errWrong)
	}
}

// TestLoginNoPasswordCredentialTreatedAsInvalid covers UserBase's documented
// contract: an account with an empty PasswordHash (an OAuth-only user, say)
// must fail a password login exactly like a wrong password — Dummy, not
// Verify, and the same sentinel.
func TestLoginNoPasswordCredentialTreatedAsInvalid(t *testing.T) {
	spy := newSpyHasher()
	svc, store := newTestService(t, auth.WithHasher(spy))
	now := time.Now().UTC()
	if _, err := store.CreateUser(context.Background(), auth.UserBase{
		ID:        "oauth-user-1",
		Email:     "oauth@example.com",
		CreatedAt: now,
		UpdatedAt: now,
		// PasswordHash intentionally left empty.
	}); err != nil {
		t.Fatalf("seeding CreateUser: %v", err)
	}

	_, _, _, err := svc.Login(context.Background(), "oauth@example.com", "anything", "1.2.3.4", "")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	hashN, verifyN, dummyN := spy.counts()
	if hashN != 0 || verifyN != 0 || dummyN != 1 {
		t.Fatalf("hasher calls (hash,verify,dummy) = (%d,%d,%d), want (0,0,1) — Verify must never run against an empty hash", hashN, verifyN, dummyN)
	}
}

func TestLoginRateLimitedDeniesBeforeStoreAccess(t *testing.T) {
	limiter := &fakeLimiter{allow: false}
	store := newCountingStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithRateLimiter(limiter),
	)

	_, _, _, err := svc.Login(context.Background(), "anyone@example.com", "whatever", "9.9.9.9", "")
	if !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if got := store.calls(); got != 0 {
		t.Fatalf("FindUserByEmail called %d times despite the rate limiter denying; want 0", got)
	}
}

// TestLoginRateLimitKeyedByIPNotEmail pins the brief's explicit requirement:
// the limiter is keyed by IP, never by the attempted email — otherwise an
// attacker could lock a victim out merely by exhausting a bucket keyed on
// the victim's address.
func TestLoginRateLimitKeyedByIPNotEmail(t *testing.T) {
	limiter := &fakeLimiter{allow: true}
	svc, _ := newTestService(t, auth.WithRateLimiter(limiter))

	svc.Login(context.Background(), "victim@example.com", "x", "198.51.100.7", "")
	svc.Login(context.Background(), "someone-else@example.com", "x", "198.51.100.7", "")

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.keys) != 2 {
		t.Fatalf("limiter was consulted %d times, want 2", len(limiter.keys))
	}
	for i, k := range limiter.keys {
		if k != "198.51.100.7" {
			t.Fatalf("limiter key[%d] = %q, want the caller's IP \"198.51.100.7\" (never the email)", i, k)
		}
	}
}

func TestLoginFailsClosedOnRateLimiterError(t *testing.T) {
	limiter := &fakeLimiter{err: errStoreBoom}
	svc, _ := newTestService(t, auth.WithRateLimiter(limiter))

	_, _, _, err := svc.Login(context.Background(), "anyone@example.com", "x", "1.2.3.4", "")
	if !errors.Is(err, errStoreBoom) {
		t.Fatalf("err = %v, want errStoreBoom (rate limiter errors must fail closed, not be swallowed)", err)
	}
	if errors.Is(err, auth.ErrRateLimited) {
		t.Fatal("a rate limiter ERROR must not be reported as ErrRateLimited — those are different failure causes")
	}
}

func TestLoginFailsClosedOnStoreLookupError(t *testing.T) {
	store := &errStore{AuthStore: memory.NewAuthStore(), failFindUserByEmail: true}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	_, _, _, err := svc.Login(context.Background(), "anyone@example.com", "x", "1.2.3.4", "")
	if !errors.Is(err, errStoreBoom) {
		t.Fatalf("err = %v, want errStoreBoom", err)
	}
	if errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("a Store failure must not be reported as ErrInvalidCredentials — that would hide an outage as a bad password")
	}
}

func TestLoginRequireVerifiedEmailBlocksUnverified(t *testing.T) {
	svc, _ := newTestService(t, auth.WithRequireVerifiedEmail(true))
	mustSignUp(t, svc, "jack@example.com", validPassword)

	_, _, _, err := svc.Login(context.Background(), "jack@example.com", validPassword, "1.2.3.4", "")
	if !errors.Is(err, auth.ErrEmailNotVerified) {
		t.Fatalf("err = %v, want ErrEmailNotVerified", err)
	}
}

func TestLoginRequireVerifiedEmailAllowsVerified(t *testing.T) {
	svc, _ := newTestService(t, auth.WithRequireVerifiedEmail(true))
	res, err := svc.SignUp(context.Background(), "kate@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := svc.VerifyEmail(context.Background(), res.VerifyToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	user, _, _, err := svc.Login(context.Background(), "kate@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is nil on the returned user after verification")
	}
}

func TestLoginDefaultAllowsUnverified(t *testing.T) {
	svc, _ := newTestService(t) // WithRequireVerifiedEmail not set
	mustSignUp(t, svc, "leo@example.com", validPassword)

	if _, _, _, err := svc.Login(context.Background(), "leo@example.com", validPassword, "1.2.3.4", ""); err != nil {
		t.Fatalf("Login: %v, want success (default does not require verification)", err)
	}
}

// TestLoginIssuesAccessTokenWithExtraClaims is FIX 3's corrected pin. The
// original version discarded the loaded user with `_ = u` and only checked
// key-presence, so it could not have detected the extender receiving an
// empty/wrong user at all. This version instead simulates exactly what a
// real application does per WithClaimsExtender's corrected doc: look up its
// OWN profile data keyed by the real, authenticated user's id
// (u.Base().ID) — which requires Login to hand the extender the actual
// user it just authenticated, not a separately (and differently)
// constructed one — and asserts the CLAIM VALUE that lookup produced, not
// merely that some key exists.
func TestLoginIssuesAccessTokenWithExtraClaims(t *testing.T) {
	// A stand-in for the application's OWN store of profile data, keyed by
	// the real user id — exactly the pattern WithClaimsExtender's doc now
	// recommends, since this package's own Store never persists it.
	plans := map[string]string{}

	store := memory.NewAuthStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithClaimsExtender(func(u testUser) map[string]any {
			return map[string]any{"plan": plans[u.Base().ID]}
		}),
	)

	res, err := svc.SignUp(context.Background(), "mona@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if res.User.ID == "" {
		t.Fatal("SignUp returned an empty user id")
	}
	plans[res.User.ID] = "gold-plan"

	loggedIn, access, _, err := svc.Login(context.Background(), "mona@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loggedIn.ID != res.User.ID {
		t.Fatalf("Login returned user id %q, want the signed-up user's id %q", loggedIn.ID, res.User.ID)
	}

	claims, err := token.Parse(access, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse: %v", err)
	}
	if claims.Extra == nil {
		t.Fatal("claims.Extra is nil, want the extender's map")
	}
	got, ok := claims.Extra["plan"]
	if !ok {
		t.Fatalf("claims.Extra = %#v, want a \"plan\" key", claims.Extra)
	}
	if got != "gold-plan" {
		t.Fatalf("claims.Extra[\"plan\"] = %#v, want \"gold-plan\" — the extender must have received the real, authenticated user's id to look this up, not an empty/zero one", got)
	}
}

// TestLoginRejectsEmptyIP pins the availability-hazard fix: an empty ip
// must never silently become a shared rate-limit bucket key.
func TestLoginRejectsEmptyIP(t *testing.T) {
	svc, _ := newTestService(t)
	mustSignUp(t, svc, "pia@example.com", validPassword)

	_, _, _, err := svc.Login(context.Background(), "pia@example.com", validPassword, "", "")
	if !errors.Is(err, auth.ErrMissingIP) {
		t.Fatalf("err = %v, want ErrMissingIP", err)
	}
}

// TestLoginNoSigningKeyFailsClosed also pins the orphaned-session-row
// minor fix: a misconfigured signing key must fail BEFORE any Session row
// is persisted, not leave one behind that no refresh token can ever
// reach — visible to Store.ListSessionsByUser regardless.
func TestLoginNoSigningKeyFailsClosed(t *testing.T) {
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store, auth.WithHasher(password.Bcrypt(testCost))) // no WithJWT
	user := mustSignUp(t, svc, "nora@example.com", validPassword)

	_, _, _, err := svc.Login(context.Background(), "nora@example.com", validPassword, "1.2.3.4", "")
	if !errors.Is(err, token.ErrKeyTooShort) {
		t.Fatalf("err = %v, want token.ErrKeyTooShort", err)
	}

	sessions, err := store.ListSessionsByUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s), want 0 — a failed token issuance must not leave an orphaned session row", len(sessions))
	}
}

func TestLoginNormalizesEmail(t *testing.T) {
	svc, _ := newTestService(t)
	mustSignUp(t, svc, "oscar@example.com", validPassword)

	if _, _, _, err := svc.Login(context.Background(), "  Oscar@EXAMPLE.com", validPassword, "1.2.3.4", ""); err != nil {
		t.Fatalf("Login with a case/whitespace variant: %v, want success", err)
	}
}

// ============================================================
// VerifyEmail
// ============================================================

func TestVerifyEmailSignupMarksVerified(t *testing.T) {
	svc, _ := newTestService(t)
	res, err := svc.SignUp(context.Background(), "pat@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	user, err := svc.VerifyEmail(context.Background(), res.VerifyToken)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is nil after VerifyEmail")
	}
	if user.Email != "pat@example.com" {
		t.Fatalf("Email = %q, want \"pat@example.com\"", user.Email)
	}
}

func TestVerifyEmailTokenNotReusable(t *testing.T) {
	svc, _ := newTestService(t)
	res, err := svc.SignUp(context.Background(), "quinn@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := svc.VerifyEmail(context.Background(), res.VerifyToken); err != nil {
		t.Fatalf("first VerifyEmail: %v", err)
	}
	if _, err := svc.VerifyEmail(context.Background(), res.VerifyToken); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("second VerifyEmail err = %v, want ErrVerificationNotFound", err)
	}
}

func TestVerifyEmailUnknownToken(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.VerifyEmail(context.Background(), "this-token-was-never-issued")
	if !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("err = %v, want ErrVerificationNotFound", err)
	}
}

func TestVerifyEmailExpiredTokenNotClaimed(t *testing.T) {
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithClock(func() time.Time { return fixedNow }),
	)

	res, err := svc.SignUp(context.Background(), "rex@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	// The clock is fixed, so the freshly-minted token has not expired yet —
	// move the clock forward past its ExpiresAt (defaultVerificationTTL is
	// 24h) by rebuilding the Service with a later fixed clock instead of
	// mutating the closure, then verifying against the SAME store.
	later := fixedNow.Add(25 * time.Hour)
	svcLater := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithClock(func() time.Time { return later }),
	)

	_, err = svcLater.VerifyEmail(context.Background(), res.VerifyToken)
	if !errors.Is(err, auth.ErrVerificationExpired) {
		t.Fatalf("err = %v, want ErrVerificationExpired", err)
	}

	// Not burned: the row must still be findable by hash.
	if _, ferr := store.FindVerificationByHash(context.Background(), token.HashOpaque(res.VerifyToken)); ferr != nil {
		t.Fatalf("verification was deleted despite being expired-not-claimed: FindVerificationByHash: %v", ferr)
	}
}

func TestVerifyEmailPasswordResetPurposeRejected(t *testing.T) {
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	res, err := svc.SignUp(context.Background(), "sam@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		t.Fatalf("GenerateOpaque: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.CreateVerification(context.Background(), auth.Verification{
		ID:        "verif-reset-1",
		UserID:    res.User.ID,
		TokenHash: hash,
		Purpose:   auth.PurposePasswordReset,
		Email:     "sam@example.com",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}

	if _, err := svc.VerifyEmail(context.Background(), plain); !errors.Is(err, auth.ErrVerificationPurpose) {
		t.Fatalf("err = %v, want ErrVerificationPurpose", err)
	}
	if _, ferr := store.FindVerificationByHash(context.Background(), hash); ferr != nil {
		t.Fatalf("password_reset verification was burned by VerifyEmail: %v", ferr)
	}
}

func TestVerifyEmailChangeUpdatesAddressAndVerifies(t *testing.T) {
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	res, err := svc.SignUp(context.Background(), "tina@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := svc.VerifyEmail(context.Background(), res.VerifyToken); err != nil {
		t.Fatalf("initial VerifyEmail: %v", err)
	}

	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		t.Fatalf("GenerateOpaque: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.CreateVerification(context.Background(), auth.Verification{
		ID:        "verif-change-1",
		UserID:    res.User.ID,
		TokenHash: hash,
		Purpose:   auth.PurposeEmailChange,
		Email:     "tina-new@example.com",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}

	user, err := svc.VerifyEmail(context.Background(), plain)
	if err != nil {
		t.Fatalf("VerifyEmail(email_change): %v", err)
	}
	if user.Email != "tina-new@example.com" {
		t.Fatalf("Email = %q, want \"tina-new@example.com\"", user.Email)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is nil after redeeming an email_change token")
	}
}

// TestVerifyEmailClaimsBeforeApplyOrderingSignup is the direct, structural
// pin for the brief's fourth mandatory mutation: reverse the claim/apply
// order inside VerifyEmail (apply — MarkEmailVerified/UpdateUserEmail —
// before the claim, DeleteVerification) and this must fail. It records the
// exact sequence of Store calls via orderStore rather than trying to infer
// the reordering from an outcome, which is the one technique guaranteed to
// catch a literal statement-order swap.
func TestVerifyEmailClaimsBeforeApplyOrderingSignup(t *testing.T) {
	store := newOrderStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	res, err := svc.SignUp(context.Background(), "uma@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	store.mu.Lock()
	store.order = nil
	store.mu.Unlock()

	if _, err := svc.VerifyEmail(context.Background(), res.VerifyToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	got := store.snapshot()
	want := []string{"DeleteVerification", "MarkEmailVerified"}
	if !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v (claim must happen before apply)", got, want)
	}
}

// TestVerifyEmailClaimsBeforeApplyOrderingEmailChange is the email_change
// analogue of the above: DeleteVerification must precede BOTH
// UpdateUserEmail and MarkEmailVerified.
func TestVerifyEmailClaimsBeforeApplyOrderingEmailChange(t *testing.T) {
	store := newOrderStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	res, err := svc.SignUp(context.Background(), "vince@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		t.Fatalf("GenerateOpaque: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.CreateVerification(context.Background(), auth.Verification{
		ID:        "verif-change-order-1",
		UserID:    res.User.ID,
		TokenHash: hash,
		Purpose:   auth.PurposeEmailChange,
		Email:     "vince-new@example.com",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}
	store.mu.Lock()
	store.order = nil
	store.mu.Unlock()

	if _, err := svc.VerifyEmail(context.Background(), plain); err != nil {
		t.Fatalf("VerifyEmail(email_change): %v", err)
	}

	got := store.snapshot()
	want := []string{"DeleteVerification", "UpdateUserEmail", "MarkEmailVerified"}
	if !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v (claim must happen before either apply step)", got, want)
	}
}

// TestVerifyEmailConcurrentSameTokenExactlyOneWinner races N goroutines
// against the same token on the real, concurrency-safe in-memory store, and
// asserts exactly one gets a successful redemption. This is a real-world
// confirmation alongside the structural ordering tests above — see this
// task's report for why the structural test, not this one, is the reliable
// discriminator for a reversed claim/apply order specifically.
func TestVerifyEmailConcurrentSameTokenExactlyOneWinner(t *testing.T) {
	svc, _ := newTestService(t)
	res, err := svc.SignUp(context.Background(), "wendy@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, notFound, other := 0, 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.VerifyEmail(context.Background(), res.VerifyToken)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, auth.ErrVerificationNotFound):
				notFound++
			default:
				other++
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1 (got notFound=%d other=%d)", successes, notFound, other)
	}
	if notFound != n-1 {
		t.Fatalf("notFound = %d, want %d", notFound, n-1)
	}
	if other != 0 {
		t.Fatalf("other = %d, want 0", other)
	}
}

func TestVerifyEmailFailsClosedOnLookupStoreError(t *testing.T) {
	store := &errStore{AuthStore: memory.NewAuthStore(), failFindVerificationByHash: true}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	_, err := svc.VerifyEmail(context.Background(), "some-token")
	if !errors.Is(err, errStoreBoom) {
		t.Fatalf("err = %v, want errStoreBoom", err)
	}
}

// equalStrings reports whether a and b hold the same strings in the same
// order.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ============================================================
// FIX 3 (round 2): UserBase.PasswordHash json:"-"
// ============================================================

// TestUserBasePasswordHashExcludedFromJSON pins the type-level fix
// directly at the JSON layer, independent of which Service method
// produced the value: json.Marshal of a type embedding UserBase (exactly
// the shape SignUp/Login/VerifyEmail hand back) must never include the
// credential digest, under its Go field name OR its lowercase JSON
// convention, even though the field is populated and non-empty in memory.
func TestUserBasePasswordHashExcludedFromJSON(t *testing.T) {
	u := testUser{
		UserBase: auth.UserBase{
			ID:           "user-1",
			Email:        "jill@example.com",
			PasswordHash: "$2a$04$thisIsALiveBcryptDigestDoNotLeakMe",
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		},
		DisplayName: "Jill",
	}

	out, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "thisIsALiveBcryptDigest") {
		t.Fatalf("marshaled JSON contains the live hash value: %s", s)
	}
	if strings.Contains(strings.ToLower(s), "passwordhash") || strings.Contains(s, "password_hash") {
		t.Fatalf("marshaled JSON contains a PasswordHash key at all (should be fully omitted via json:\"-\"): %s", s)
	}

	// Sanity: the OTHER fields are still there — this isn't accidentally
	// stripping the whole embedded struct.
	if !strings.Contains(s, "jill@example.com") {
		t.Fatalf("marshaled JSON is missing Email entirely, want it present: %s", s)
	}
}

// TestLoginNeverReturnsPasswordHash extends FIX 2's SignUp-only coverage
// to Login, closing the gap round 1's report disclosed and left open.
func TestLoginNeverReturnsPasswordHash(t *testing.T) {
	svc, _ := newTestService(t)
	mustSignUp(t, svc, "karl@example.com", validPassword)

	user, _, _, err := svc.Login(context.Background(), "karl@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if user.PasswordHash != "" {
		t.Fatalf("Login returned User.PasswordHash = %q, want empty", user.PasswordHash)
	}
}

// TestVerifyEmailNeverReturnsPasswordHash is VerifyEmail's counterpart.
func TestVerifyEmailNeverReturnsPasswordHash(t *testing.T) {
	svc, _ := newTestService(t)
	res, err := svc.SignUp(context.Background(), "lena@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	user, err := svc.VerifyEmail(context.Background(), res.VerifyToken)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if user.PasswordHash != "" {
		t.Fatalf("VerifyEmail returned User.PasswordHash = %q, want empty", user.PasswordHash)
	}
}

// ============================================================
// Refresh, Logout, LogoutAll, ListSessions, RevokeSession
// ============================================================

// TestRefreshMintsWorkingSuccessorAndOldTokenThenReuse pins the required
// property that a rotation returns a working successor, and that the OLD
// (now-rotated) token subsequently fails with ErrTokenReuse.
func TestRefreshMintsWorkingSuccessorAndOldTokenThenReuse(t *testing.T) {
	svc, store := newTestService(t)
	mustSignUp(t, svc, "amy@example.com", validPassword)
	user, _, refresh1 := mustLogin(t, svc, "amy@example.com", validPassword)
	ctx := context.Background()

	res, err := svc.Refresh(ctx, refresh1)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.User.ID != user.ID {
		t.Fatalf("LoginResult.User.ID = %q, want %q", res.User.ID, user.ID)
	}
	if res.AccessToken == "" {
		t.Fatal("LoginResult.AccessToken is empty")
	}
	if res.RefreshToken == "" || res.RefreshToken == refresh1 {
		t.Fatalf("LoginResult.RefreshToken = %q, want a non-empty value different from the original %q", res.RefreshToken, refresh1)
	}

	// The successor genuinely works: its own access token parses, and its
	// session is present, current (RotatedAt nil), and in the SAME family
	// as the original.
	claims, err := token.Parse(res.AccessToken, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse(successor access token): %v", err)
	}
	if claims.Subject != user.ID {
		t.Fatalf("claims.Subject = %q, want %q", claims.Subject, user.ID)
	}

	succSess, err := store.FindSessionByHash(ctx, token.HashOpaque(res.RefreshToken))
	if err != nil {
		t.Fatalf("FindSessionByHash(successor): %v", err)
	}
	if succSess.RotatedAt != nil {
		t.Fatal("successor session's RotatedAt is non-nil, want nil (current)")
	}
	origSess, err := store.FindSessionByHash(ctx, token.HashOpaque(refresh1))
	if err != nil {
		t.Fatalf("FindSessionByHash(original, now rotated): %v", err)
	}
	if succSess.FamilyID != origSess.FamilyID {
		t.Fatalf("successor FamilyID = %q, want the original's %q", succSess.FamilyID, origSess.FamilyID)
	}
	if origSess.RotatedAt == nil {
		t.Fatal("original session's RotatedAt is nil after a successful rotation, want non-nil")
	}

	// The old token, presented again, is a genuine replay.
	if _, err := svc.Refresh(ctx, refresh1); !errors.Is(err, auth.ErrTokenReuse) {
		t.Fatalf("second Refresh(original token) err = %v, want ErrTokenReuse", err)
	}
}

// TestRefreshReuseRevokesWholeFamilyNotJustPresentedSession pins the
// required property that reuse revokes the WHOLE family, not merely the
// session whose hash was presented. It builds a 3-session chain
// (original -> successor2 -> successor3, the only currently-live one), then
// replays the long-superseded ORIGINAL token and confirms every row in the
// family — including the currently-live successor3, which was never itself
// presented — is gone afterward.
func TestRefreshReuseRevokesWholeFamilyNotJustPresentedSession(t *testing.T) {
	svc, store := newTestService(t)
	mustSignUp(t, svc, "beth@example.com", validPassword)
	user, _, refresh1 := mustLogin(t, svc, "beth@example.com", validPassword)
	ctx := context.Background()

	res2, err := svc.Refresh(ctx, refresh1)
	if err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	res3, err := svc.Refresh(ctx, res2.RefreshToken)
	if err != nil {
		t.Fatalf("second Refresh: %v", err)
	}

	// Replay the ORIGINAL, long-superseded token — not the current one.
	if _, err := svc.Refresh(ctx, refresh1); !errors.Is(err, auth.ErrTokenReuse) {
		t.Fatalf("replay err = %v, want ErrTokenReuse", err)
	}

	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after reuse; want 0 — the whole family, not just the presented session, must be revoked", len(sessions))
	}

	// The currently-live successor (res3), never itself presented, must
	// also now be unusable — direct proof the revocation was family-wide.
	if _, err := svc.Refresh(ctx, res3.RefreshToken); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Refresh(the never-presented, currently-live successor) after family revocation err = %v, want ErrTokenInvalid (its session no longer exists)", err)
	}
}

// TestRefreshExpiredTokenInvalidAndFamilyIntact pins that an expired token
// is ErrTokenInvalid, and — critically — does NOT revoke the family:
// ordinary end-of-life is not evidence of theft.
func TestRefreshExpiredTokenInvalidAndFamilyIntact(t *testing.T) {
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithRefreshTTL(time.Hour),
		auth.WithClock(func() time.Time { return fixedNow }),
	)
	ctx := context.Background()
	if _, err := svc.SignUp(ctx, "cara@example.com", validPassword); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	user, _, refresh1, err := svc.Login(ctx, "cara@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// A second Service sharing the same Store, with the clock moved past
	// the 1-hour refresh TTL.
	later := fixedNow.Add(2 * time.Hour)
	svcLater := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithRefreshTTL(time.Hour),
		auth.WithClock(func() time.Time { return later }),
	)

	if _, err := svcLater.Refresh(ctx, refresh1); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Refresh(expired) err = %v, want ErrTokenInvalid", err)
	}

	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after an expired Refresh; want 1 (family untouched)", len(sessions))
	}
	if sessions[0].RotatedAt != nil {
		t.Fatalf("the expired session's RotatedAt = %v, want nil — an expired-but-unpresented-for-rotation session must not become marked rotated either", sessions[0].RotatedAt)
	}
}

// TestLogoutUnknownTokenReturnsNil pins Logout's idempotency contract for a
// token this Store has never issued.
func TestLogoutUnknownTokenReturnsNil(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.Logout(context.Background(), "this-token-was-never-issued"); err != nil {
		t.Fatalf("Logout(unknown token) err = %v, want nil", err)
	}
}

// TestLogoutRevokesSessionAndIsIdempotent pins the ordinary case: Logout
// deletes exactly the presented session, and calling it again with the same
// (now-already-deleted) token is still nil, not an error.
func TestLogoutRevokesSessionAndIsIdempotent(t *testing.T) {
	svc, store := newTestService(t)
	mustSignUp(t, svc, "dee@example.com", validPassword)
	user, _, refresh := mustLogin(t, svc, "dee@example.com", validPassword)
	ctx := context.Background()

	if err := svc.Logout(ctx, refresh); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after Logout; want 0", len(sessions))
	}

	if err := svc.Logout(ctx, refresh); err != nil {
		t.Fatalf("second Logout(same, now-deleted token) err = %v, want nil", err)
	}
}

// TestLogoutAllRevokesEveryFamilyIncludingRotatedPredecessors pins
// LogoutAll: every session across every family for the user is gone
// afterward, including a rotated-but-unexpired predecessor row a
// per-row-id approach could miss.
func TestLogoutAllRevokesEveryFamilyIncludingRotatedPredecessors(t *testing.T) {
	svc, store := newTestService(t)
	mustSignUp(t, svc, "flynn@example.com", validPassword)
	user, _, refreshDeviceA := mustLogin(t, svc, "flynn@example.com", validPassword)
	ctx := context.Background()

	// A second, independent login — a second device/family.
	_, _, refreshDeviceB, err := svc.Login(ctx, "flynn@example.com", validPassword, "198.51.100.2", "device-b")
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}

	// Rotate device A once, so its family has a rotated-but-unexpired
	// predecessor plus a current successor.
	if _, err := svc.Refresh(ctx, refreshDeviceA); err != nil {
		t.Fatalf("Refresh(device A): %v", err)
	}
	_ = refreshDeviceB

	if err := svc.LogoutAll(ctx, user.ID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}

	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after LogoutAll; want 0 (every family, every row)", len(sessions))
	}
}

// TestListSessionsShowsOnlyOwn pins that ListSessions for one user never
// returns another user's sessions.
func TestListSessionsShowsOnlyOwn(t *testing.T) {
	svc, _ := newTestService(t)
	userA := mustSignUp(t, svc, "eddie@example.com", validPassword)
	mustSignUp(t, svc, "fiona@example.com", validPassword)
	ctx := context.Background()
	mustLogin(t, svc, "eddie@example.com", validPassword)
	mustLogin(t, svc, "fiona@example.com", validPassword)

	sessions, err := svc.ListSessions(ctx, userA.ID)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}
	if sessions[0].UserID != userA.ID {
		t.Fatalf("session.UserID = %q, want %q (a different user's session leaked)", sessions[0].UserID, userA.ID)
	}
}

// TestRevokeSessionRequiresOwnership pins RevokeSession's authorization
// contract: a session id belonging to a DIFFERENT user is refused
// (ErrSessionNotFound, identical to a nonexistent id — never leaking that
// the id belongs to someone else), while the true owner can revoke it.
func TestRevokeSessionRequiresOwnership(t *testing.T) {
	svc, store := newTestService(t)
	userA := mustSignUp(t, svc, "gale@example.com", validPassword)
	userB := mustSignUp(t, svc, "hollis@example.com", validPassword)
	ctx := context.Background()
	mustLogin(t, svc, "gale@example.com", validPassword)
	mustLogin(t, svc, "hollis@example.com", validPassword)

	bSessions, err := store.ListSessionsByUser(ctx, userB.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser(B): %v", err)
	}
	if len(bSessions) != 1 {
		t.Fatalf("len(bSessions) = %d, want 1", len(bSessions))
	}

	// A tries to revoke B's session.
	if err := svc.RevokeSession(ctx, userA.ID, bSessions[0].ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("RevokeSession(A, B's session id) err = %v, want ErrSessionNotFound", err)
	}
	// B's session must still exist.
	stillThere, err := store.ListSessionsByUser(ctx, userB.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser(B) after A's attempt: %v", err)
	}
	if len(stillThere) != 1 {
		t.Fatalf("len(stillThere) = %d, want 1 — B's session must survive A's unauthorized attempt", len(stillThere))
	}

	// B revokes their own session.
	if err := svc.RevokeSession(ctx, userB.ID, bSessions[0].ID); err != nil {
		t.Fatalf("RevokeSession(B, B's own session id): %v", err)
	}
	gone, err := store.ListSessionsByUser(ctx, userB.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser(B) after B's own revoke: %v", err)
	}
	if len(gone) != 0 {
		t.Fatalf("len(gone) = %d, want 0", len(gone))
	}
}

// TestRefreshRotatedRowRetainedUntilPurgeExpired pins that a
// rotated-but-unexpired session row is NOT deleted at rotation time — it is
// retained (that is what makes reuse detection possible at all — see
// auth.go's package doc) — and is swept only once PurgeExpired is called
// past its ExpiresAt, alongside its successor.
func TestRefreshRotatedRowRetainedUntilPurgeExpired(t *testing.T) {
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithRefreshTTL(24*time.Hour),
		auth.WithClock(func() time.Time { return fixedNow }),
	)
	ctx := context.Background()
	if _, err := svc.SignUp(ctx, "ivan@example.com", validPassword); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	user, _, refresh1, err := svc.Login(ctx, "ivan@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	res, err := svc.Refresh(ctx, refresh1)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Both rows — the rotated predecessor and its successor — are retained
	// immediately after rotation.
	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("len(sessions) right after rotation = %d, want 2 (rotated predecessor retained + successor)", len(sessions))
	}

	// Neither has expired yet: PurgeExpired at "now" removes neither
	// session row (SignUp's own 24h "signup" Verification is also not
	// expired yet at this point, so this call removes nothing at all).
	n, err := store.PurgeExpired(ctx, fixedNow)
	if err != nil {
		t.Fatalf("PurgeExpired(now): %v", err)
	}
	if n != 0 {
		t.Fatalf("PurgeExpired(now) removed %d row(s) before anything expired; want 0", n)
	}

	// Past both rows' ExpiresAt (refreshTTL is 24h): both are swept. This
	// call also sweeps SignUp's own unrelated 24h "signup" Verification
	// (which has now separately expired too), so rather than assert an
	// exact total, check the two SESSION rows specifically: both must now
	// be unfindable.
	if _, err := store.PurgeExpired(ctx, fixedNow.Add(25*time.Hour)); err != nil {
		t.Fatalf("PurgeExpired(+25h): %v", err)
	}
	if _, err := store.FindSessionByHash(ctx, token.HashOpaque(refresh1)); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(predecessor) after PurgeExpired err = %v, want ErrSessionNotFound", err)
	}
	if _, err := store.FindSessionByHash(ctx, token.HashOpaque(res.RefreshToken)); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(successor) after PurgeExpired err = %v, want ErrSessionNotFound", err)
	}
}

// --- parkingStore: wraps a real auth.Store, embedding it so every method
// besides the one overridden below is genuine, un-faked behaviour. It
// overrides FindSessionByHash to park the FIRST caller only — after it has
// already performed the real read — until release is closed, building a
// deterministic (not scheduler-dependent) interleaving for
// TestRefreshConcurrentSameTokenExactlyOneWinnerFamilyRevoked.
//
// An atomic counter decides which call is "first", not sync.Once:
// Once.Do would block a SECOND concurrent caller reaching the same Once
// until the first call's Do function returns — which never happens while
// that first call is deliberately parked inside it, a guaranteed deadlock
// rather than a controlled interleaving. ---

type parkingStore struct {
	auth.Store
	calls   atomic.Int32
	parked  chan struct{}
	release chan struct{}

	// successorInserts counts CreateSuccessorSession calls that actually
	// won (ok=true) — see TestRefreshConcurrentSameTokenExactlyOneWinnerFamilyRevoked's
	// direct "exactly one successor" assertion, which reads this rather
	// than inferring the count from the final session total (a final count
	// of zero is also what a double-mint-then-both-get-revoked bug would
	// produce, so it cannot tell the two apart on its own).
	successorInserts atomic.Int32
}

func newParkingStore(inner auth.Store) *parkingStore {
	return &parkingStore{
		Store:   inner,
		parked:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

// FindSessionByHash delegates to the real store FIRST — read first, then
// park — so the parked caller holds a genuine, freshly-read (unrotated)
// session, exactly as an unparked caller would. Only THEN, if this is the
// very first call this store has ever seen, it closes parked (signalling
// the test driver it is safe to run the second caller to completion) and
// blocks until release is closed.
func (s *parkingStore) FindSessionByHash(ctx context.Context, tokenHash string) (auth.Session, error) {
	sess, err := s.Store.FindSessionByHash(ctx, tokenHash)
	if s.calls.Add(1) == 1 {
		close(s.parked)
		<-s.release
	}
	return sess, err
}

// CreateSuccessorSession delegates unchanged, counting only the calls that
// actually won (ok=true) — see successorInserts' own doc.
func (s *parkingStore) CreateSuccessorSession(ctx context.Context, predecessorID string, sess auth.Session) (auth.Session, bool, error) {
	got, ok, err := s.Store.CreateSuccessorSession(ctx, predecessorID, sess)
	if ok {
		s.successorInserts.Add(1)
	}
	return got, ok, err
}

// TestRefreshConcurrentSameTokenExactlyOneWinnerFamilyRevoked is the
// mandatory deterministic concurrency test: two concurrent Refresh calls
// presenting the SAME token must yield exactly one winner. Determinism
// comes from parkingStore, not from scheduler luck: the second (unparked)
// caller is only ever invoked after the first has already read its session
// and parked, so the second is GUARANTEED to reach Store.MarkRotated first
// and win the compare-and-set — every run takes the identical path.
func TestRefreshConcurrentSameTokenExactlyOneWinnerFamilyRevoked(t *testing.T) {
	store := memory.NewAuthStore()
	seed := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	user := mustSignUp(t, seed, "hank@example.com", validPassword)
	_, _, refresh1, err := seed.Login(ctx, "hank@example.com", validPassword, "1.2.3.4", "seed-agent")
	if err != nil {
		t.Fatalf("seeding Login: %v", err)
	}

	parking := newParkingStore(store)
	svc := auth.New[testUser](parking,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	type result struct {
		res auth.LoginResult[testUser]
		err error
	}
	firstDone := make(chan result, 1)
	go func() {
		res, err := svc.Refresh(ctx, refresh1)
		firstDone <- result{res, err}
	}()

	<-parking.parked // caller #1 has read the (unrotated) session and is now parked

	// Caller #2 runs to completion, entirely unparked (this is the second
	// call this store has seen, so parkingStore's counter != 1).
	secondRes, secondErr := svc.Refresh(ctx, refresh1)

	close(parking.release) // release caller #1 to resume past its parked read
	first := <-firstDone

	// Deterministic, not probabilistic: caller #2 ran to completion while
	// caller #1 was still parked before ever reaching Store.MarkRotated, so
	// caller #2 MUST be the CAS winner and caller #1 MUST be the loser —
	// guaranteed by construction, not by scheduler timing.
	if secondErr != nil {
		t.Fatalf("winner (second, unparked caller) err = %v, want nil", secondErr)
	}
	if secondRes.RefreshToken == "" || secondRes.AccessToken == "" {
		t.Fatal("winner's LoginResult has an empty token")
	}
	if !errors.Is(first.err, auth.ErrTokenReuse) {
		t.Fatalf("loser (first, parked caller) err = %v, want ErrTokenReuse", first.err)
	}
	if first.res.RefreshToken != "" {
		t.Fatalf("loser's LoginResult.RefreshToken = %q, want empty (zero value) on error", first.res.RefreshToken)
	}

	// Direct assertion, not inferred from the final session count below: a
	// double-mint bug would ALSO leave zero live sessions once both are
	// revoked, so counting successful CreateSuccessorSession calls directly
	// is what actually distinguishes "exactly one successor was ever
	// minted" from "two were minted and both got swept up".
	if n := parking.successorInserts.Load(); n != 1 {
		t.Fatalf("CreateSuccessorSession won %d time(s), want exactly 1", n)
	}

	// Exactly one winner ever minted a successor. The loser's ErrTokenReuse
	// additionally revokes the WHOLE family — including the successor the
	// winner just minted moments earlier.
	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after the concurrent reuse was detected; want 0", len(sessions))
	}
}

// --- parkAfterMarkRotatedStore: wraps a real auth.Store, embedding it so
// every method besides MarkRotated is genuine. It parks the WINNING caller
// (the one whose own MarkRotated call returns ok=true) immediately after
// MarkRotated returns, before Refresh can go on to call
// CreateSuccessorSession — the exact window
// TestRefreshFamilyRevokedBetweenMarkRotatedAndSuccessorFailsClosed and
// TestLogoutAllReliableAgainstConcurrentRefresh both drive a full,
// completed revocation through, deterministically, before ever releasing
// the parked winner. Unlike parkingStore above, there is only ever one
// caller to park here (no second racing Refresh call), so a plain "park on
// ok=true" guard is enough — no atomic counter needed to pick "the first"
// among several. ---

type parkAfterMarkRotatedStore struct {
	auth.Store
	parked  chan struct{}
	release chan struct{}
}

func newParkAfterMarkRotatedStore(inner auth.Store) *parkAfterMarkRotatedStore {
	return &parkAfterMarkRotatedStore{
		Store:   inner,
		parked:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

// MarkRotated delegates to the real store FIRST — so the winning caller's
// predecessor session is genuinely, atomically rotated before anything
// parks — then, only for the call that actually won (ok=true), parks until
// release is closed.
func (s *parkAfterMarkRotatedStore) MarkRotated(ctx context.Context, tokenHash string, now time.Time) (auth.Session, bool, error) {
	sess, ok, err := s.Store.MarkRotated(ctx, tokenHash, now)
	if ok {
		close(s.parked)
		<-s.release
	}
	return sess, ok, err
}

// TestRefreshFamilyRevokedBetweenMarkRotatedAndSuccessorFailsClosed is the
// mandatory FIX 2 deterministic test: it parks the winner strictly between
// Store.MarkRotated and Store.CreateSuccessorSession, drives a full,
// completed family revocation through the real store in that window (via
// DeleteSessionsByFamily directly — exactly what a concurrent caller's own
// reuse-detection response does, see
// TestRefreshReuseRevokesWholeFamilyNotJustPresentedSession), and only then
// releases the parked winner. Before FIX 1 this reproduced the resurrection
// bug: the winner's unconditional CreateSession landed anyway, leaving one
// live, fully-functional session behind despite the family having already
// been revoked to zero. Against the fixed CreateSuccessorSession-gated
// path, the winner's own attempt to persist its successor must see the
// predecessor gone and fail closed with ErrSessionRevoked, minting nothing.
func TestRefreshFamilyRevokedBetweenMarkRotatedAndSuccessorFailsClosed(t *testing.T) {
	store := memory.NewAuthStore()
	seed := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	user := mustSignUp(t, seed, "iris@example.com", validPassword)
	_, _, refresh1, err := seed.Login(ctx, "iris@example.com", validPassword, "1.2.3.4", "seed-agent")
	if err != nil {
		t.Fatalf("seeding Login: %v", err)
	}

	parking := newParkAfterMarkRotatedStore(store)
	svc := auth.New[testUser](parking,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	type result struct {
		res auth.LoginResult[testUser]
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := svc.Refresh(ctx, refresh1)
		done <- result{res, err}
	}()

	<-parking.parked // the winner has rotated its predecessor and is now parked

	// Drive a full revocation to COMPLETION, directly against the real
	// store, in the exact window the winner is parked inside — the family
	// must be gone before the winner is ever released.
	sessionsBefore, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessionsBefore) != 1 {
		t.Fatalf("len(sessionsBefore) = %d, want 1 (the rotated predecessor, not yet a successor)", len(sessionsBefore))
	}
	familyID := sessionsBefore[0].FamilyID
	if err := store.DeleteSessionsByFamily(ctx, familyID); err != nil {
		t.Fatalf("DeleteSessionsByFamily: %v", err)
	}
	confirmGone, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(confirmGone) != 0 {
		t.Fatalf("len(confirmGone) = %d, want 0 — the revocation must be COMPLETE before releasing the winner", len(confirmGone))
	}

	close(parking.release) // only NOW does the winner resume
	r := <-done

	if !errors.Is(r.err, auth.ErrSessionRevoked) {
		t.Fatalf("err = %v, want ErrSessionRevoked", r.err)
	}
	if r.res.RefreshToken != "" || r.res.AccessToken != "" {
		t.Fatalf("LoginResult = %+v, want the zero value on ErrSessionRevoked", r.res)
	}

	remaining, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after the resurrection attempt; want 0 — the family must stay revoked", len(remaining))
	}
}

// TestLogoutAllReliableAgainstConcurrentRefresh is FIX 3's test: it proves
// LogoutAll specifically (not a raw DeleteSessionsByFamily call) is
// reliable against an in-flight Refresh that already won MarkRotated
// before LogoutAll ran. Same parking technique as the test above; the
// revoker here is svc.LogoutAll's own real code path end to end, exercising
// the exact scenario the review named as understated: "an ALREADY-LISTED
// family is resurrected by a concurrent Refresh" — LogoutAll's list-then-
// delete-per-family loop has already observed and is in the middle of
// revoking this exact family when the parked winner is released.
func TestLogoutAllReliableAgainstConcurrentRefresh(t *testing.T) {
	store := memory.NewAuthStore()
	seed := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	user := mustSignUp(t, seed, "jonas@example.com", validPassword)
	_, _, refresh1, err := seed.Login(ctx, "jonas@example.com", validPassword, "1.2.3.4", "seed-agent")
	if err != nil {
		t.Fatalf("seeding Login: %v", err)
	}

	parking := newParkAfterMarkRotatedStore(store)
	svc := auth.New[testUser](parking,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	type result struct {
		res auth.LoginResult[testUser]
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := svc.Refresh(ctx, refresh1)
		done <- result{res, err}
	}()

	<-parking.parked // the winner has rotated its predecessor and is now parked

	// LogoutAll's own real code path — list, then DeleteSessionsByFamily
	// per distinct family — run to full completion against the real store
	// while the winner is parked.
	if err := svc.LogoutAll(ctx, user.ID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	confirmGone, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(confirmGone) != 0 {
		t.Fatalf("len(confirmGone) = %d, want 0 — LogoutAll must have completed before releasing the winner", len(confirmGone))
	}

	close(parking.release)
	r := <-done

	if !errors.Is(r.err, auth.ErrSessionRevoked) {
		t.Fatalf("err = %v, want ErrSessionRevoked", r.err)
	}

	remaining, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) after LogoutAll raced a concurrent Refresh; want 0 — \"sign out everywhere\" must be reliable", len(remaining))
	}
}

// --- deleteFamilyFailsStore: wraps a real auth.Store, forcing
// DeleteSessionsByFamily to fail with an arbitrary, non-sentinel error —
// used to prove Refresh's replay branch never loses the "a replay was
// detected" signal merely because the housekeeping response to it also
// failed. ---

var errDeleteFamilyBoom = errors.New("boom: simulated DeleteSessionsByFamily outage")

type deleteFamilyFailsStore struct {
	auth.Store
}

func (s *deleteFamilyFailsStore) DeleteSessionsByFamily(context.Context, string) error {
	return errDeleteFamilyBoom
}

// TestRefreshReplayErrorPreservesReuseSignalEvenWhenFamilyDeleteFails pins
// the "also take" fix: a DeleteSessionsByFamily failure while responding to
// a detected replay must not mask that a replay WAS detected. The returned
// error must satisfy errors.Is against BOTH ErrTokenReuse (the signal) and
// the Store's own underlying error (the operational failure) — losing
// either one is worse than a slightly noisier error.
func TestRefreshReplayErrorPreservesReuseSignalEvenWhenFamilyDeleteFails(t *testing.T) {
	store := memory.NewAuthStore()
	seed := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	mustSignUp(t, seed, "kara@example.com", validPassword)
	_, _, refresh1, err := seed.Login(ctx, "kara@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("seeding Login: %v", err)
	}

	failing := &deleteFamilyFailsStore{Store: store}
	svc := auth.New[testUser](failing,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	// Rotate once for real (through the healthy underlying store, via seed)
	// so refresh1 is genuinely superseded — the next Refresh(refresh1) is a
	// real replay, not a fabricated one.
	if _, err := seed.Refresh(ctx, refresh1); err != nil {
		t.Fatalf("seeding rotation: %v", err)
	}

	_, err = svc.Refresh(ctx, refresh1)
	if !errors.Is(err, auth.ErrTokenReuse) {
		t.Fatalf("err = %v, want it to satisfy errors.Is(err, ErrTokenReuse) even though DeleteSessionsByFamily failed", err)
	}
	if !errors.Is(err, errDeleteFamilyBoom) {
		t.Fatalf("err = %v, want it to ALSO satisfy errors.Is(err, errDeleteFamilyBoom) — the operational failure must not be hidden either", err)
	}
}

// ============================================================
// ChangePassword
// ============================================================

// TestChangePasswordRequiresCurrentPassword is the mandatory mutation-anchor
// test: remove the current-password check and this must fail.
func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "olga@example.com", validPassword)

	err := svc.ChangePassword(ctx, user.ID, "", "wrong-current-password", "A-New-Valid-Pass1!")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}

	// The stored hash must be untouched: the ORIGINAL password still works.
	stored, ferr := store.FindUserByID(ctx, user.ID)
	if ferr != nil {
		t.Fatalf("FindUserByID: %v", ferr)
	}
	if !password.Bcrypt(testCost).Verify(validPassword, stored.PasswordHash) {
		t.Fatal("PasswordHash was changed despite a wrong current password being supplied")
	}
}

func TestChangePasswordWeakNextRejected(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "pete@example.com", validPassword)

	err := svc.ChangePassword(ctx, user.ID, "", validPassword, "weak")
	if !errors.Is(err, auth.ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}

	stored, ferr := store.FindUserByID(ctx, user.ID)
	if ferr != nil {
		t.Fatalf("FindUserByID: %v", ferr)
	}
	if !password.Bcrypt(testCost).Verify(validPassword, stored.PasswordHash) {
		t.Fatal("PasswordHash was changed despite next failing the configured password rules")
	}
}

func TestChangePasswordSuccessUpdatesHashAndAllowsNewLogin(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "quincy@example.com", validPassword)

	const newPass = "Brand-New-Valid-Pass2!"
	if err := svc.ChangePassword(ctx, user.ID, "", validPassword, newPass); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, _, _, err := svc.Login(ctx, "quincy@example.com", validPassword, "1.2.3.4", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login(old password) err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, _, err := svc.Login(ctx, "quincy@example.com", newPass, "1.2.3.4", ""); err != nil {
		t.Fatalf("Login(new password): %v, want success", err)
	}
}

// TestChangePasswordRevokesOtherSessionsKeepsCurrentAlive pins the "every
// OTHER session, but not the caller's own" contract, and the
// currentSessionID mechanism this task's implementation chose to identify
// it: device A's session (whose id is passed as currentSessionID) survives,
// device B's is revoked.
func TestChangePasswordRevokesOtherSessionsKeepsCurrentAlive(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "rita@example.com", validPassword)

	_, accessA, refreshA, err := svc.Login(ctx, "rita@example.com", validPassword, "1.2.3.4", "device-a")
	if err != nil {
		t.Fatalf("Login(device A): %v", err)
	}
	_, _, refreshB, err := svc.Login(ctx, "rita@example.com", validPassword, "5.6.7.8", "device-b")
	if err != nil {
		t.Fatalf("Login(device B): %v", err)
	}

	claimsA, err := token.Parse(accessA, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse(accessA): %v", err)
	}

	const newPass = "Rotated-Valid-Pass3!"
	if err := svc.ChangePassword(ctx, user.ID, claimsA.SessionID, validPassword, newPass); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) after ChangePassword = %d, want 1 (only the caller's own session survives)", len(sessions))
	}
	if sessions[0].ID != claimsA.SessionID {
		t.Fatalf("surviving session id = %q, want the caller's own %q", sessions[0].ID, claimsA.SessionID)
	}

	if _, err := svc.Refresh(ctx, refreshA); err != nil {
		t.Fatalf("Refresh(device A, the spared session) after ChangePassword: %v, want success", err)
	}
	if _, err := svc.Refresh(ctx, refreshB); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Refresh(device B, revoked) err = %v, want ErrTokenInvalid", err)
	}
}

// TestChangePasswordNoCurrentSessionRevokesAll pins the documented
// fail-closed default: an empty (or unrecognised) currentSessionID protects
// nothing — every session is revoked, matching LogoutAll.
func TestChangePasswordNoCurrentSessionRevokesAll(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "sam2@example.com", validPassword)
	mustLogin(t, svc, "sam2@example.com", validPassword)

	if err := svc.ChangePassword(ctx, user.ID, "", validPassword, "Another-Valid-Pass4!"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("len(sessions) = %d, want 0 — an empty currentSessionID must protect nothing", len(sessions))
	}
}

func TestChangePasswordUnknownUserPropagatesNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	err := svc.ChangePassword(context.Background(), "no-such-user-id", "", validPassword, "Another-Valid-Pass5!")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

// TestChangePasswordInvalidatesOutstandingResetToken is the mandatory
// mutation-anchor test for review FIX 1 (ChangePassword side): a
// still-valid "password_reset" token requested BEFORE a credentialed
// ChangePassword call must not survive it. Before the fix, this was
// demonstrated by execution: the pre-existing token still redeemed
// successfully after ChangePassword, letting an attacker who merely holds
// an old reset link take the account right back even after the legitimate
// owner changed their password specifically because they suspected
// compromise.
func TestChangePasswordInvalidatesOutstandingResetToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "iris2@example.com", validPassword)

	resetTok, ok, err := svc.RequestPasswordReset(ctx, "iris2@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	if err := svc.ChangePassword(ctx, user.ID, "", validPassword, "Changed-Valid-Pass13!"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(resetTok)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(reset token) after ChangePassword err = %v, want ErrVerificationNotFound", ferr)
	}
	if err := svc.ResetPassword(ctx, resetTok, "Attacker-Chosen-Pass14!"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("ResetPassword(pre-existing token) after ChangePassword err = %v, want ErrVerificationNotFound — the reset token must not survive a credentialed password change", err)
	}
}

// TestChangePasswordInvalidatesOutstandingEmailChangeToken pins the OTHER
// half of the same side door. An "email_change" verification is a stronger
// primitive than a reset token, not a weaker one: it lives 24h rather than
// 1h, [Service.RequestEmailChange] needs no current password to mint one
// (a briefly-stolen access token is enough), and [Service.VerifyEmail]
// redeems it with NO authentication at all, moving the account to the
// attacker's address. After that the victim cannot recover — [Service.Login]
// and [Service.RequestPasswordReset] both look accounts up BY email — so a
// pending email_change surviving the one action a user takes on suspecting
// compromise is a full, unrecoverable takeover held open for a day.
func TestChangePasswordInvalidatesOutstandingEmailChangeToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "iris3@example.com", validPassword)

	// The attacker, holding a stolen session, arms the takeover.
	changeTok, err := svc.RequestEmailChange(ctx, user.ID, "attacker@evil.example")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}

	// The victim responds to the suspected compromise.
	if err := svc.ChangePassword(ctx, user.ID, "", validPassword, "Changed-Valid-Pass17!"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(changeTok)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(email_change token) after ChangePassword err = %v, want ErrVerificationNotFound", ferr)
	}
	if _, err := svc.VerifyEmail(ctx, changeTok); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("VerifyEmail(pre-existing email_change token) after ChangePassword err = %v, want ErrVerificationNotFound — the address takeover must not survive a credentialed password change", err)
	}

	// The account must still be reachable at its original address.
	stored, err := store.FindUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.Email != "iris3@example.com" {
		t.Fatalf("stored email = %q, want %q — the account was moved to the attacker's address", stored.Email, "iris3@example.com")
	}
}

// TestChangePasswordFailsClosedWhenEmailChangeSweepFails proves the new
// sweep is not fire-and-forget: it fails closed exactly as the
// password_reset sweep beside it does. The double fails ONLY the
// email_change purpose, so the reset sweep still succeeds and this error
// can only be the new one propagating.
func TestChangePasswordFailsClosedWhenEmailChangeSweepFails(t *testing.T) {
	store := &purposeSweepFailStore{AuthStore: memory.NewAuthStore(), failPurpose: auth.PurposeEmailChange}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	user := mustSignUp(t, svc, "iris4@example.com", validPassword)

	if err := svc.ChangePassword(ctx, user.ID, "", validPassword, "Changed-Valid-Pass18!"); !errors.Is(err, errWriteBoom) {
		t.Fatalf("ChangePassword err = %v, want the store's own error — a failed email_change sweep must not be swallowed", err)
	}
}

// ============================================================
// RequestPasswordReset
// ============================================================

func TestRequestPasswordResetKnownAddressReturnsRedeemableToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "tara@example.com", validPassword)

	tok, ok, err := svc.RequestPasswordReset(ctx, "Tara@Example.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if !ok {
		t.Fatal("ok = false, want true for a known address")
	}
	if tok == "" {
		t.Fatal("token is empty for a known address")
	}

	v, err := store.FindVerificationByHash(ctx, token.HashOpaque(tok))
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if v.Purpose != auth.PurposePasswordReset {
		t.Fatalf("Purpose = %q, want %q", v.Purpose, auth.PurposePasswordReset)
	}
	if v.UserID != user.ID {
		t.Fatalf("UserID = %q, want %q", v.UserID, user.ID)
	}
	if v.Email != "tara@example.com" {
		t.Fatalf("Email = %q, want \"tara@example.com\"", v.Email)
	}
}

// TestRequestPasswordResetUnknownAddressReturnsFalseNilError is the
// mandatory mutation-anchor test: make RequestPasswordReset return an error
// for an unknown address, and this must fail.
func TestRequestPasswordResetUnknownAddressReturnsFalseNilError(t *testing.T) {
	svc, _ := newTestService(t)

	tok, ok, err := svc.RequestPasswordReset(context.Background(), "nobody-here@example.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("err = %v, want nil — never an error purely because the address is unknown", err)
	}
	if ok {
		t.Fatal("ok = true, want false for an unknown address")
	}
	if tok != "" {
		t.Fatalf("token = %q, want empty for an unknown address", tok)
	}
}

func TestRequestPasswordResetRequiresIP(t *testing.T) {
	svc, _ := newTestService(t)
	_, _, err := svc.RequestPasswordReset(context.Background(), "anyone@example.com", "")
	if !errors.Is(err, auth.ErrMissingIP) {
		t.Fatalf("err = %v, want ErrMissingIP", err)
	}
}

func TestRequestPasswordResetIPRateLimitedDeniesBeforeStoreAccess(t *testing.T) {
	limiter := &fakeLimiter{allow: false}
	store := newCountingStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithRateLimiter(limiter),
	)

	tok, ok, err := svc.RequestPasswordReset(context.Background(), "anyone@example.com", "9.9.9.9")
	if !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if ok || tok != "" {
		t.Fatalf("ok=%v tok=%q despite the IP rate limiter denying; want false/empty", ok, tok)
	}
	if got := store.calls(); got != 0 {
		t.Fatalf("Store touched %d times despite the IP limiter denying; want 0", got)
	}
}

// TestRequestPasswordResetAddressRateLimitSameShapeAsUnknown pins the
// brief's point 2: a per-ADDRESS rate-limit denial for a KNOWN address must
// return the exact same shape as an unknown address — ("", false, nil) —
// never ErrRateLimited, which would itself become an oracle.
func TestRequestPasswordResetAddressRateLimitSameShapeAsUnknown(t *testing.T) {
	addressLimiter := &fakeLimiter{allow: false}
	svc, _ := newTestService(t, auth.WithPasswordResetRateLimiter(addressLimiter))
	ctx := context.Background()
	mustSignUp(t, svc, "uma2@example.com", validPassword)

	tok, ok, err := svc.RequestPasswordReset(ctx, "uma2@example.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("err = %v, want nil (never ErrRateLimited for the address-keyed limiter)", err)
	}
	if ok {
		t.Fatal("ok = true despite the address rate limiter denying")
	}
	if tok != "" {
		t.Fatalf("token = %q, want empty", tok)
	}

	addressLimiter.mu.Lock()
	defer addressLimiter.mu.Unlock()
	if len(addressLimiter.keys) != 1 || addressLimiter.keys[0] != "uma2@example.com" {
		t.Fatalf("address limiter keys = %v, want [\"uma2@example.com\"] (keyed by the normalized address)", addressLimiter.keys)
	}
}

// TestRequestPasswordResetReadFailureIndistinguishableAcrossBranches proves
// a FindUserByEmail outage — a call that runs on EVERY invocation — fails
// the known and unknown branches identically, mirroring
// TestSignUpReadFailureIndistinguishableAcrossBranches.
func TestRequestPasswordResetReadFailureIndistinguishableAcrossBranches(t *testing.T) {
	store := &errStore{AuthStore: memory.NewAuthStore(), failFindUserByEmail: true}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	now := time.Now().UTC()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	if _, err := store.AuthStore.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-reset-1", Email: "vince2@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	_, _, errKnown := svc.RequestPasswordReset(context.Background(), "vince2@example.com", "1.2.3.4")
	_, _, errUnknown := svc.RequestPasswordReset(context.Background(), "never-registered@example.com", "1.2.3.4")

	if errKnown == nil {
		t.Fatal("RequestPasswordReset(known address) succeeded despite the read path being broken")
	}
	if errUnknown == nil {
		t.Fatal("RequestPasswordReset(unknown address) succeeded despite the read path being broken")
	}
	if !errors.Is(errKnown, errStoreBoom) || !errors.Is(errUnknown, errStoreBoom) {
		t.Fatalf("errKnown=%v errUnknown=%v, want both to wrap errStoreBoom", errKnown, errUnknown)
	}
}

// TestRequestPasswordResetCreateVerificationFailureNotDistinguishable pins
// point 3 of "The enumeration property, again": a failure reachable ONLY on
// the known-address branch (CreateVerification) must not surface as an
// error at all — it must return the exact same shape an unknown address
// gets.
func TestRequestPasswordResetCreateVerificationFailureNotDistinguishable(t *testing.T) {
	inner := memory.NewAuthStore()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	now := time.Now().UTC()
	if _, err := inner.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-reset-2", Email: "wade@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	store := &verificationWriteFailStore{AuthStore: inner}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	tokKnown, okKnown, errKnown := svc.RequestPasswordReset(context.Background(), "wade@example.com", "1.2.3.4")
	tokUnknown, okUnknown, errUnknown := svc.RequestPasswordReset(context.Background(), "never-registered2@example.com", "1.2.3.4")

	if errKnown != nil {
		t.Fatalf("errKnown = %v, want nil — CreateVerification's failure must not surface as an error", errKnown)
	}
	if errUnknown != nil {
		t.Fatalf("errUnknown = %v, want nil", errUnknown)
	}
	if okKnown != okUnknown || okKnown != false {
		t.Fatalf("okKnown=%v okUnknown=%v, want both false — identical to the unknown-address shape", okKnown, okUnknown)
	}
	if tokKnown != tokUnknown || tokKnown != "" {
		t.Fatalf("tokKnown=%q tokUnknown=%q, want both empty", tokKnown, tokUnknown)
	}
}

// TestRequestPasswordResetInvalidatesEarlierToken is the coverage for
// review FIX 2: requesting a second password-reset token for the same
// address must invalidate the FIRST one — honouring
// [auth.Store.DeleteVerificationsByUserAndPurpose]'s own documented
// contract ("so requesting a new password-reset email invalidates any
// earlier one instead of leaving both redeemable"), which
// RequestPasswordReset did not call at all before this fix.
func TestRequestPasswordResetInvalidatesEarlierToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	mustSignUp(t, svc, "kian@example.com", validPassword)

	tok1, ok1, err := svc.RequestPasswordReset(ctx, "kian@example.com", "1.2.3.4")
	if err != nil || !ok1 {
		t.Fatalf("first RequestPasswordReset: ok=%v err=%v", ok1, err)
	}
	tok2, ok2, err := svc.RequestPasswordReset(ctx, "kian@example.com", "1.2.3.4")
	if err != nil || !ok2 {
		t.Fatalf("second RequestPasswordReset: ok=%v err=%v", ok2, err)
	}
	if tok1 == tok2 {
		t.Fatal("both RequestPasswordReset calls returned the SAME token")
	}

	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok1)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(tok1) after re-requesting err = %v, want ErrVerificationNotFound — the earlier token must be invalidated", ferr)
	}
	if err := svc.ResetPassword(ctx, tok2, "Second-Valid-Pass17!"); err != nil {
		t.Fatalf("ResetPassword(tok2, the current one): %v, want success", err)
	}
}

// ============================================================
// ResetPassword
// ============================================================

func TestResetPasswordSuccessChangesPasswordAndBurnsToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	mustSignUp(t, svc, "xena@example.com", validPassword)

	tok, ok, err := svc.RequestPasswordReset(ctx, "xena@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	const newPass = "Reset-Valid-Pass6!"
	if err := svc.ResetPassword(ctx, tok, newPass); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if _, _, _, err := svc.Login(ctx, "xena@example.com", validPassword, "1.2.3.4", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login(old password) err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, _, err := svc.Login(ctx, "xena@example.com", newPass, "1.2.3.4", ""); err != nil {
		t.Fatalf("Login(new password): %v, want success", err)
	}

	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(redeemed token) err = %v, want ErrVerificationNotFound", ferr)
	}
	if err := svc.ResetPassword(ctx, tok, "Another-Valid-Pass7!"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("second ResetPassword(same token) err = %v, want ErrVerificationNotFound", err)
	}
}

// TestResetPasswordRevokesAllSessions is the mandatory mutation-anchor test:
// remove the session-revocation step and this must fail. Unlike
// ChangePassword, ResetPassword spares NOTHING — both of the account's
// devices, logged in BEFORE the reset, must be revoked.
func TestResetPasswordRevokesAllSessions(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "yara@example.com", validPassword)
	_, _, refreshA, err := svc.Login(ctx, "yara@example.com", validPassword, "1.2.3.4", "device-a")
	if err != nil {
		t.Fatalf("Login(device A): %v", err)
	}
	_, _, refreshB, err := svc.Login(ctx, "yara@example.com", validPassword, "5.6.7.8", "device-b")
	if err != nil {
		t.Fatalf("Login(device B): %v", err)
	}

	tok, ok, err := svc.RequestPasswordReset(ctx, "yara@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}
	if err := svc.ResetPassword(ctx, tok, "Reset-Valid-Pass8!"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("len(sessions) after ResetPassword = %d, want 0 (every session, every device, must be revoked)", len(sessions))
	}
	if _, err := svc.Refresh(ctx, refreshA); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Refresh(device A) after ResetPassword err = %v, want ErrTokenInvalid", err)
	}
	if _, err := svc.Refresh(ctx, refreshB); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Refresh(device B) after ResetPassword err = %v, want ErrTokenInvalid", err)
	}
}

// TestResetPasswordClaimsBeforeApplyOrdering is the mandatory
// mutation-anchor test for ordering: reverse ResetPassword's claim/apply
// order and this must fail. Mirrors
// TestVerifyEmailClaimsBeforeApplyOrderingSignup's technique exactly, via
// orderStore's UpdateUserPassword override.
func TestResetPasswordClaimsBeforeApplyOrdering(t *testing.T) {
	store := newOrderStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	mustSignUp(t, svc, "zack@example.com", validPassword)

	tok, ok, err := svc.RequestPasswordReset(ctx, "zack@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}
	store.mu.Lock()
	store.order = nil
	store.mu.Unlock()

	if err := svc.ResetPassword(ctx, tok, "Ordered-Valid-Pass9!"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	got := store.snapshot()
	want := []string{"DeleteVerification", "UpdateUserPassword"}
	if !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v (claim must happen before apply)", got, want)
	}
}

func TestResetPasswordUnknownToken(t *testing.T) {
	svc, _ := newTestService(t)
	err := svc.ResetPassword(context.Background(), "this-token-was-never-issued", "Some-Valid-Pass10!")
	if !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("err = %v, want ErrVerificationNotFound", err)
	}
}

func TestResetPasswordExpiredTokenNotClaimed(t *testing.T) {
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithClock(func() time.Time { return fixedNow }),
	)
	ctx := context.Background()
	mustSignUp(t, svc, "abby@example.com", validPassword)

	tok, ok, err := svc.RequestPasswordReset(ctx, "abby@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	later := fixedNow.Add(2 * time.Hour) // past the 1h password-reset TTL
	svcLater := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithClock(func() time.Time { return later }),
	)

	if err := svcLater.ResetPassword(ctx, tok, "Expired-Valid-Pass11!"); !errors.Is(err, auth.ErrVerificationExpired) {
		t.Fatalf("err = %v, want ErrVerificationExpired", err)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok)); ferr != nil {
		t.Fatalf("verification was deleted despite being expired-not-claimed: %v", ferr)
	}
}

func TestResetPasswordWrongPurposeRejectedNotClaimed(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	res, err := svc.SignUp(ctx, "cody@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	// res.VerifyToken is a "signup"-purpose token; present it to
	// ResetPassword, which only redeems "password_reset".
	if err := svc.ResetPassword(ctx, res.VerifyToken, "Wrong-Purpose-Pass12!"); !errors.Is(err, auth.ErrVerificationPurpose) {
		t.Fatalf("err = %v, want ErrVerificationPurpose", err)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(res.VerifyToken)); ferr != nil {
		t.Fatalf("signup verification was burned by ResetPassword: %v", ferr)
	}
}

func TestResetPasswordWeakNextPasswordNotClaimed(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	mustSignUp(t, svc, "dana2@example.com", validPassword)

	tok, ok, err := svc.RequestPasswordReset(ctx, "dana2@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	if err := svc.ResetPassword(ctx, tok, "weak"); !errors.Is(err, auth.ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok)); ferr != nil {
		t.Fatalf("token was burned despite next failing password rules: %v", ferr)
	}
}

// TestResetPasswordInvalidatesSiblingResetToken is the mandatory
// mutation-anchor test for review FIX 1 (ResetPassword side): a SECOND,
// independently-existing "password_reset" token for the same account must
// not survive a completed reset performed with a DIFFERENT token. Before
// the fix, this was demonstrated by execution: a sibling token still reset
// the account again after the first reset had already completed.
//
// The sibling is seeded directly on the store (not via a second
// RequestPasswordReset call) so this test isolates ResetPassword's OWN
// cleanup specifically from RequestPasswordReset's separate reissue-time
// cleanup — see TestRequestPasswordResetInvalidatesEarlierToken for that
// one, which a call-request-twice version of this test would have
// conflated: the second RequestPasswordReset call would itself invalidate
// the first token before ResetPassword ever ran, which is a different
// mechanism than the one this test targets.
func TestResetPasswordInvalidatesSiblingResetToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "jonah@example.com", validPassword)

	tok1, ok1, err := svc.RequestPasswordReset(ctx, "jonah@example.com", "1.2.3.4")
	if err != nil || !ok1 {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok1, err)
	}

	tok2Plain, tok2Hash, err := token.GenerateOpaque()
	if err != nil {
		t.Fatalf("GenerateOpaque: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.CreateVerification(ctx, auth.Verification{
		ID:        "verif-sibling-reset-1",
		UserID:    user.ID,
		TokenHash: tok2Hash,
		Purpose:   auth.PurposePasswordReset,
		Email:     "jonah@example.com",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateVerification: %v", err)
	}

	if err := svc.ResetPassword(ctx, tok1, "First-Valid-Pass15!"); err != nil {
		t.Fatalf("ResetPassword(tok1): %v", err)
	}

	if _, ferr := store.FindVerificationByHash(ctx, tok2Hash); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(sibling) after redeeming tok1 err = %v, want ErrVerificationNotFound", ferr)
	}
	if err := svc.ResetPassword(ctx, tok2Plain, "Second-Valid-Pass16!"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("ResetPassword(sibling token) err = %v, want ErrVerificationNotFound — a sibling reset token must not survive a completed reset", err)
	}
}

// TestResetPasswordInvalidatesOutstandingEmailChangeToken is the
// ResetPassword half of the same door TestChangePasswordInvalidatesOutstandingEmailChangeToken
// closes for ChangePassword — see that test for why an outstanding
// email_change token is the stronger of the two primitives a credential
// rotation must sweep.
func TestResetPasswordInvalidatesOutstandingEmailChangeToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "jonah2@example.com", validPassword)

	changeTok, err := svc.RequestEmailChange(ctx, user.ID, "attacker2@evil.example")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}

	resetTok, ok, err := svc.RequestPasswordReset(ctx, "jonah2@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}
	if err := svc.ResetPassword(ctx, resetTok, "Recovered-Valid-Pass19!"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(changeTok)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(email_change token) after ResetPassword err = %v, want ErrVerificationNotFound", ferr)
	}
	if _, err := svc.VerifyEmail(ctx, changeTok); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("VerifyEmail(pre-existing email_change token) after ResetPassword err = %v, want ErrVerificationNotFound — the address takeover must not survive a completed reset", err)
	}

	stored, err := store.FindUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.Email != "jonah2@example.com" {
		t.Fatalf("stored email = %q, want %q — the account was moved to the attacker's address", stored.Email, "jonah2@example.com")
	}
}

// TestResetPasswordFailsClosedWhenEmailChangeSweepFails is the ResetPassword
// counterpart of TestChangePasswordFailsClosedWhenEmailChangeSweepFails: the
// double fails only the email_change purpose, so the password_reset sweep
// still succeeds and a propagated error can only be the new sweep's.
func TestResetPasswordFailsClosedWhenEmailChangeSweepFails(t *testing.T) {
	store := &purposeSweepFailStore{AuthStore: memory.NewAuthStore(), failPurpose: auth.PurposeEmailChange}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	mustSignUp(t, svc, "jonah3@example.com", validPassword)

	resetTok, ok, err := svc.RequestPasswordReset(ctx, "jonah3@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}
	if err := svc.ResetPassword(ctx, resetTok, "Changed-Valid-Pass20!"); !errors.Is(err, errWriteBoom) {
		t.Fatalf("ResetPassword err = %v, want the store's own error — a failed email_change sweep must not be swallowed", err)
	}
}

// ============================================================
// RequestEmailChange
// ============================================================

func TestRequestEmailChangeMintsRedeemableToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "erin2@example.com", validPassword)

	tok, err := svc.RequestEmailChange(ctx, user.ID, "  Erin-New@Example.COM ")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if tok == "" {
		t.Fatal("token is empty")
	}

	v, err := store.FindVerificationByHash(ctx, token.HashOpaque(tok))
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if v.Purpose != auth.PurposeEmailChange {
		t.Fatalf("Purpose = %q, want %q", v.Purpose, auth.PurposeEmailChange)
	}
	if v.Email != "erin-new@example.com" {
		t.Fatalf("Email = %q, want normalized \"erin-new@example.com\"", v.Email)
	}
	if v.UserID != user.ID {
		t.Fatalf("UserID = %q, want %q", v.UserID, user.ID)
	}

	got, err := svc.VerifyEmail(ctx, tok)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if got.Email != "erin-new@example.com" {
		t.Fatalf("Email after redemption = %q, want \"erin-new@example.com\"", got.Email)
	}
	if got.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is nil after redeeming an email_change token")
	}
}

// TestRequestEmailChangeTakenEmailDeferredToRedemption pins FIX 3 from the
// review: the early ErrEmailTaken pre-check was removed (it was an
// un-rate-limited registered-address oracle available to any authenticated
// caller — one signup bought unlimited "is this address registered?"
// queries). Requesting a change to an address already taken by a DIFFERENT
// user now succeeds at mint time exactly like any other request; the
// conflict only surfaces at VerifyEmail redemption time via
// Store.UpdateUserEmail's own atomic check, burning the token in the
// process — the same cost VerifyEmail's "claims before applies" ordering
// already imposes for every other doomed redemption.
func TestRequestEmailChangeTakenEmailDeferredToRedemption(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	userA := mustSignUp(t, svc, "finn@example.com", validPassword)
	mustSignUp(t, svc, "gwen@example.com", validPassword)

	tok, err := svc.RequestEmailChange(ctx, userA.ID, "gwen@example.com")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v, want success — the taken-email check is deferred to redemption", err)
	}
	if tok == "" {
		t.Fatal("token is empty, want a real mint even for an address already taken by someone else")
	}

	if _, err := svc.VerifyEmail(ctx, tok); !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("VerifyEmail(taken-email token) err = %v, want ErrEmailTaken", err)
	}
	// The token is burned regardless of the failure, matching VerifyEmail's
	// documented ordering — it must not be redeemable a second time.
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(after a failed redemption) err = %v, want ErrVerificationNotFound", ferr)
	}

	// userA's own address must be untouched by the failed redemption.
	stillOwn, err := store.FindUserByID(ctx, userA.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stillOwn.Email != "finn@example.com" {
		t.Fatalf("userA.Email = %q after a failed redemption, want unchanged \"finn@example.com\"", stillOwn.Email)
	}
}

func TestRequestEmailChangeUnknownUserPropagatesNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.RequestEmailChange(context.Background(), "no-such-user-id", "someone@example.com")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestRequestEmailChangeSameEmailAllowed(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "holly@example.com", validPassword)

	tok, err := svc.RequestEmailChange(ctx, user.ID, "Holly@Example.com")
	if err != nil {
		t.Fatalf("RequestEmailChange(own current address): %v, want success", err)
	}
	if tok == "" {
		t.Fatal("token is empty")
	}
}

// TestRequestEmailChangeRejectsEmptyEmail is the mandatory mutation-anchor
// test for review round 2's FIX 3: an empty (or whitespace-only, once
// normalized) newEmail must be rejected with ErrEmailRequired before
// anything is minted. Reproduced at both HEAD and base before this guard
// existed: an empty newEmail minted a real token, VerifyEmail redeemed it
// successfully, the stored address became "", and the account was
// permanently unreachable by email afterward — this test also confirms
// that specific bricking scenario cannot occur once the guard is in place,
// not merely that the immediate call errors.
func TestRequestEmailChangeRejectsEmptyEmail(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "ivy2@example.com", validPassword)

	if _, err := svc.RequestEmailChange(ctx, user.ID, ""); !errors.Is(err, auth.ErrEmailRequired) {
		t.Fatalf("RequestEmailChange(\"\") err = %v, want ErrEmailRequired", err)
	}
	if _, err := svc.RequestEmailChange(ctx, user.ID, "   "); !errors.Is(err, auth.ErrEmailRequired) {
		t.Fatalf("RequestEmailChange(whitespace-only) err = %v, want ErrEmailRequired", err)
	}

	// No verification of any kind was minted for either rejected call —
	// confirmed by checking the account is untouched and still reachable at
	// its real address, the property an empty newEmail would have destroyed.
	stillThere, err := store.FindUserByEmail(ctx, "ivy2@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail(original address) after rejected requests: %v, want success — the account must still be reachable", err)
	}
	if stillThere.ID != user.ID {
		t.Fatalf("FindUserByEmail returned a different user: got %q, want %q", stillThere.ID, user.ID)
	}
}
