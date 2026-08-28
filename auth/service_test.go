package auth_test

import (
	"bytes"
	"context"
	"errors"
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
// FindUserByEmail — used to prove SignUp never reaches the Store on a
// rejected (weak) password. ---

type countingStore struct {
	*memory.AuthStore
	mu               sync.Mutex
	findByEmailCalls int
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

func (s *countingStore) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findByEmailCalls
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
}

func (s *errStore) FindUserByEmail(_ context.Context, _ string) (auth.UserBase, error) {
	if s.failFindUserByEmail {
		return auth.UserBase{}, errStoreBoom
	}
	return s.AuthStore.FindUserByEmail(context.Background(), "")
}

func (s *errStore) FindVerificationByHash(ctx context.Context, hash string) (auth.Verification, error) {
	if s.failFindVerificationByHash {
		return auth.Verification{}, errStoreBoom
	}
	return s.AuthStore.FindVerificationByHash(ctx, hash)
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
		t.Fatalf("FindUserByEmail was called %d times for a password that should have been rejected before any lookup; want 0", got)
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
	store.mu.Lock()
	store.findByEmailCalls = 0 // reset the counter after the seed signup
	store.mu.Unlock()

	_, err1 := svc.SignUp(context.Background(), "existing@example.com", "weak")
	_, err2 := svc.SignUp(context.Background(), "brand-new@example.com", "weak")

	if !errors.Is(err1, auth.ErrWeakPassword) || !errors.Is(err2, auth.ErrWeakPassword) {
		t.Fatalf("errs = %v, %v, want both ErrWeakPassword", err1, err2)
	}
	if got := store.calls(); got != 0 {
		t.Fatalf("FindUserByEmail called %d times across two weak-password sign-ups; want 0 for both", got)
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

// TestSignUpDummyCalledOnDuplicateNotHash is the behavioural pin for the
// brief's third mandatory mutation on this method: remove the Dummy call on
// the duplicate branch and this must fail. Unlike a wall-clock timing
// assertion (which the brief warns is inherently flaky), this observes a
// plain, deterministic fact — which Hasher method was invoked — through a
// spy double, which is possible here (unlike token's hmac.Equal-vs-==
// case) precisely because Hasher is an interface parameter Service already
// takes by injection, not a language operator.
func TestSignUpDummyCalledOnDuplicateNotHash(t *testing.T) {
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
	if hashN != 0 || verifyN != 0 || dummyN != 1 {
		t.Fatalf("hasher calls (hash,verify,dummy) = (%d,%d,%d), want (0,0,1) — the duplicate branch must call Dummy, not Hash", hashN, verifyN, dummyN)
	}
}

// TestSignUpFailsClosedOnLookupStoreError proves a Store failure while
// checking for an existing address is surfaced as an error — never silently
// folded into either a successful create or a duplicate result.
func TestSignUpFailsClosedOnLookupStoreError(t *testing.T) {
	store := &errStore{AuthStore: memory.NewAuthStore(), failFindUserByEmail: true}
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	res, err := svc.SignUp(context.Background(), "dana@example.com", validPassword)
	if !errors.Is(err, errStoreBoom) {
		t.Fatalf("SignUp err = %v, want errStoreBoom", err)
	}
	if res.Created {
		t.Fatal("Created = true despite the lookup failing")
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

func TestLoginIssuesAccessTokenWithExtraClaims(t *testing.T) {
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithClaimsExtender(func(u testUser) map[string]any {
			return map[string]any{"display_name": u.DisplayName}
		}),
	)

	res, err := svc.SignUp(context.Background(), "mona@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	// Give the stored user a DisplayName directly, bypassing SignUp (which
	// this task does not extend with profile fields), so the extender has
	// something non-zero to surface.
	u, err := store.FindUserByID(context.Background(), res.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	_ = u

	_, access, _, err := svc.Login(context.Background(), "mona@example.com", validPassword, "1.2.3.4", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	claims, err := token.Parse(access, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse: %v", err)
	}
	if claims.Extra == nil {
		t.Fatal("claims.Extra is nil, want the extender's map")
	}
	if _, ok := claims.Extra["display_name"]; !ok {
		t.Fatalf("claims.Extra = %#v, want a \"display_name\" key", claims.Extra)
	}
}

func TestLoginNoSigningKeyFailsClosed(t *testing.T) {
	store := memory.NewAuthStore()
	svc := auth.New[testUser](store, auth.WithHasher(password.Bcrypt(testCost))) // no WithJWT
	mustSignUp(t, svc, "nora@example.com", validPassword)

	_, _, _, err := svc.Login(context.Background(), "nora@example.com", validPassword, "1.2.3.4", "")
	if !errors.Is(err, token.ErrKeyTooShort) {
		t.Fatalf("err = %v, want token.ErrKeyTooShort", err)
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
