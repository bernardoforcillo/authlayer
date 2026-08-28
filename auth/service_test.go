package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
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
