package auth_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// ============================================================
// Doubles used only by the magic-link suite
// ============================================================

// magicLinkSequenceStore wraps a real memory.AuthStore and records the
// exact sequence of the four calls RequestMagicLink can reach, so the
// known and unknown branches' call sequences can be compared directly
// rather than inferred. DeleteVerificationsByUserAndPurpose records the
// purpose it was given too: the re-issue sweep is purpose-scoped, and a
// sweep that quietly widened to another purpose would otherwise look
// identical here.
type magicLinkSequenceStore struct {
	*memory.AuthStore
	mu    sync.Mutex
	order []string
}

func newMagicLinkSequenceStore() *magicLinkSequenceStore {
	return &magicLinkSequenceStore{AuthStore: memory.NewAuthStore()}
}

func (s *magicLinkSequenceStore) record(name string) {
	s.mu.Lock()
	s.order = append(s.order, name)
	s.mu.Unlock()
}

func (s *magicLinkSequenceStore) FindUserByEmail(ctx context.Context, email string) (auth.UserBase, error) {
	s.record("FindUserByEmail")
	return s.AuthStore.FindUserByEmail(ctx, email)
}

func (s *magicLinkSequenceStore) CreateUser(ctx context.Context, u auth.UserBase) (auth.UserBase, error) {
	s.record("CreateUser")
	return s.AuthStore.CreateUser(ctx, u)
}

func (s *magicLinkSequenceStore) DeleteVerificationsByUserAndPurpose(ctx context.Context, userID, purpose string) error {
	s.record("DeleteVerificationsByUserAndPurpose:" + purpose)
	return s.AuthStore.DeleteVerificationsByUserAndPurpose(ctx, userID, purpose)
}

func (s *magicLinkSequenceStore) CreateVerification(ctx context.Context, v auth.Verification) (auth.Verification, error) {
	s.record("CreateVerification")
	return s.AuthStore.CreateVerification(ctx, v)
}

func (s *magicLinkSequenceStore) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

func (s *magicLinkSequenceStore) reset() {
	s.mu.Lock()
	s.order = nil
	s.mu.Unlock()
}

// ============================================================
// RequestMagicLink
// ============================================================

func TestRequestMagicLinkKnownAddressMintsAMagicLinkVerification(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	svc, store := newTestService(t, auth.WithClock(func() time.Time { return now }))
	ctx := context.Background()
	user := mustSignUp(t, svc, "mira@example.com", validPassword)

	tok, ok, err := svc.RequestMagicLink(ctx, "Mira@Example.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
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
	if v.Purpose != auth.PurposeMagicLink {
		t.Fatalf("Purpose = %q, want %q", v.Purpose, auth.PurposeMagicLink)
	}
	if v.UserID != user.ID {
		t.Fatalf("UserID = %q, want %q", v.UserID, user.ID)
	}
	if v.Email != "mira@example.com" {
		t.Fatalf("Email = %q, want the normalized address", v.Email)
	}
	if want := now.Add(15 * time.Minute); !v.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want the 15-minute default %v", v.ExpiresAt, want)
	}
}

// TestRequestMagicLinkUnknownAddressReturnsFalseNilError is this task's
// mutation anchor: make the unknown branch return a distinguishable error
// instead of ("", false, nil) and this must fail.
func TestRequestMagicLinkUnknownAddressReturnsFalseNilError(t *testing.T) {
	svc, _ := newTestService(t)

	tok, ok, err := svc.RequestMagicLink(context.Background(), "nobody-magic@example.com", "1.2.3.4")
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

func TestRequestMagicLinkRequiresIP(t *testing.T) {
	svc, _ := newTestService(t)
	_, _, err := svc.RequestMagicLink(context.Background(), "anyone-magic@example.com", "")
	if !errors.Is(err, auth.ErrMissingIP) {
		t.Fatalf("err = %v, want ErrMissingIP", err)
	}
}

func TestRequestMagicLinkIPRateLimitedDeniesBeforeStoreAccess(t *testing.T) {
	limiter := &fakeLimiter{allow: false}
	store := newCountingStore()
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithRateLimiter(limiter),
		// Provisioning ON, so a leak past the IP limiter would also be a
		// free account creation, not merely a lookup.
		auth.WithMagicLinkProvisioning(true),
	)

	tok, ok, err := svc.RequestMagicLink(context.Background(), "anyone-magic@example.com", "9.9.9.9")
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

// TestRequestMagicLinkAddressRateLimitSameShapeAsUnknown is the magic-link
// twin of TestRequestPasswordResetAddressRateLimitSameShapeAsUnknown: an
// address-keyed denial for a KNOWN address must return the exact shape an
// unknown address gets — ("", false, nil) — never ErrRateLimited, which
// would itself be the existence oracle this method's design exists to
// close.
func TestRequestMagicLinkAddressRateLimitSameShapeAsUnknown(t *testing.T) {
	addressLimiter := &fakeLimiter{allow: false}
	svc, _ := newTestService(t, auth.WithMagicLinkRateLimiter(addressLimiter))
	ctx := context.Background()
	mustSignUp(t, svc, "nadia@example.com", validPassword)

	tok, ok, err := svc.RequestMagicLink(ctx, "nadia@example.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("err = %v, want nil (never ErrRateLimited for the address-keyed limiter)", err)
	}
	if ok {
		t.Fatal("ok = true despite the address rate limiter denying")
	}
	if tok != "" {
		t.Fatalf("token = %q, want empty", tok)
	}

	// And byte-identical to what an unknown address returns on the same
	// Service, which is what "indistinguishable" has to mean here.
	unknownTok, unknownOK, unknownErr := svc.RequestMagicLink(ctx, "never-registered-magic@example.com", "1.2.3.4")
	if unknownTok != tok || unknownOK != ok || unknownErr != err {
		t.Fatalf("denied-known=(%q,%v,%v) unknown=(%q,%v,%v), want identical",
			tok, ok, err, unknownTok, unknownOK, unknownErr)
	}

	addressLimiter.mu.Lock()
	defer addressLimiter.mu.Unlock()
	if len(addressLimiter.keys) != 2 {
		t.Fatalf("address limiter keys = %v, want two calls (one per request)", addressLimiter.keys)
	}
	if addressLimiter.keys[0] != "nadia@example.com" {
		t.Fatalf("address limiter key[0] = %q, want the normalized address", addressLimiter.keys[0])
	}
	if addressLimiter.keys[1] != "never-registered-magic@example.com" {
		t.Fatalf("address limiter key[1] = %q — the limiter must be consulted for an UNKNOWN address too, or its own call pattern becomes the oracle", addressLimiter.keys[1])
	}
}

// TestRequestMagicLinkCallSequenceDiffersOnlyByTheBranchExclusiveWrites
// records the real call sequence on each branch. They necessarily differ —
// the known branch has a user row to write against and the unknown branch
// does not — so this pins exactly WHICH calls are branch-exclusive, which
// is what the error-set tests below then have to neutralize.
func TestRequestMagicLinkCallSequenceDiffersOnlyByTheBranchExclusiveWrites(t *testing.T) {
	store := newMagicLinkSequenceStore()
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	mustSignUp(t, svc, "orla@example.com", validPassword)

	store.reset()
	if _, _, err := svc.RequestMagicLink(ctx, "orla@example.com", "1.2.3.4"); err != nil {
		t.Fatalf("RequestMagicLink(known): %v", err)
	}
	known := store.snapshot()

	store.reset()
	if _, _, err := svc.RequestMagicLink(ctx, "not-orla@example.com", "1.2.3.4"); err != nil {
		t.Fatalf("RequestMagicLink(unknown): %v", err)
	}
	unknown := store.snapshot()

	wantKnown := []string{"FindUserByEmail", "DeleteVerificationsByUserAndPurpose:magic_link", "CreateVerification"}
	wantUnknown := []string{"FindUserByEmail"}
	if !equalStrings(known, wantKnown) {
		t.Fatalf("known-branch calls = %v, want %v", known, wantKnown)
	}
	if !equalStrings(unknown, wantUnknown) {
		t.Fatalf("unknown-branch calls = %v, want %v", unknown, wantUnknown)
	}
}

func TestRequestMagicLinkProvisioningCallSequence(t *testing.T) {
	store := newMagicLinkSequenceStore()
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithMagicLinkProvisioning(true),
	)
	ctx := context.Background()

	store.reset()
	if _, _, err := svc.RequestMagicLink(ctx, "provisioned@example.com", "1.2.3.4"); err != nil {
		t.Fatalf("RequestMagicLink(unknown, provisioning on): %v", err)
	}
	got := store.snapshot()
	want := []string{"FindUserByEmail", "CreateUser", "DeleteVerificationsByUserAndPurpose:magic_link", "CreateVerification"}
	if !equalStrings(got, want) {
		t.Fatalf("provisioning-branch calls = %v, want %v", got, want)
	}
}

// TestRequestMagicLinkReadFailureIndistinguishableAcrossBranches: a
// FindUserByEmail outage runs on EVERY call, so it must fail both branches
// identically.
func TestRequestMagicLinkReadFailureIndistinguishableAcrossBranches(t *testing.T) {
	store := &errStore{AuthStore: memory.NewAuthStore(), failFindUserByEmail: true}
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	now := time.Now().UTC()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	if _, err := store.AuthStore.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-magic-1", Email: "pia@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	_, _, errKnown := svc.RequestMagicLink(context.Background(), "pia@example.com", "1.2.3.4")
	_, _, errUnknown := svc.RequestMagicLink(context.Background(), "never-registered-magic2@example.com", "1.2.3.4")

	if !errors.Is(errKnown, errStoreBoom) || !errors.Is(errUnknown, errStoreBoom) {
		t.Fatalf("errKnown=%v errUnknown=%v, want both to wrap errStoreBoom", errKnown, errUnknown)
	}
}

// TestRequestMagicLinkCreateVerificationFailureNotDistinguishable: a
// failure reachable ONLY on the known-address branch must not surface as an
// error at all.
func TestRequestMagicLinkCreateVerificationFailureNotDistinguishable(t *testing.T) {
	inner := memory.NewAuthStore()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	now := time.Now().UTC()
	if _, err := inner.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-magic-2", Email: "quinn@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	store := &verificationWriteFailStore{AuthStore: inner}
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	tokKnown, okKnown, errKnown := svc.RequestMagicLink(context.Background(), "quinn@example.com", "1.2.3.4")
	tokUnknown, okUnknown, errUnknown := svc.RequestMagicLink(context.Background(), "never-registered-magic3@example.com", "1.2.3.4")

	if errKnown != nil || errUnknown != nil {
		t.Fatalf("errKnown=%v errUnknown=%v, want both nil — CreateVerification's failure must not surface", errKnown, errUnknown)
	}
	if okKnown != okUnknown || okKnown {
		t.Fatalf("okKnown=%v okUnknown=%v, want both false", okKnown, okUnknown)
	}
	if tokKnown != tokUnknown || tokKnown != "" {
		t.Fatalf("tokKnown=%q tokUnknown=%q, want both empty", tokKnown, tokUnknown)
	}
}

// TestRequestMagicLinkSweepFailureNotDistinguishable is the same argument
// for the OTHER branch-exclusive write: the re-issue sweep. It uses
// purposeSweepFailStore pointed at "magic_link" so only THIS sweep fails —
// a wholesale DeleteVerificationsByUserAndPurpose outage could not tell
// which sweep the folded result came from.
func TestRequestMagicLinkSweepFailureNotDistinguishable(t *testing.T) {
	inner := memory.NewAuthStore()
	seedHash, err := password.Bcrypt(testCost).Hash(validPassword)
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	now := time.Now().UTC()
	if _, err := inner.CreateUser(context.Background(), auth.UserBase{
		ID: "seed-magic-3", Email: "rex@example.com", PasswordHash: seedHash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}

	store := &purposeSweepFailStore{AuthStore: inner, failPurpose: auth.PurposeMagicLink}
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	tokKnown, okKnown, errKnown := svc.RequestMagicLink(context.Background(), "rex@example.com", "1.2.3.4")
	tokUnknown, okUnknown, errUnknown := svc.RequestMagicLink(context.Background(), "never-registered-magic4@example.com", "1.2.3.4")

	if errKnown != nil || errUnknown != nil {
		t.Fatalf("errKnown=%v errUnknown=%v, want both nil — the sweep's failure must not surface", errKnown, errUnknown)
	}
	if okKnown != okUnknown || okKnown {
		t.Fatalf("okKnown=%v okUnknown=%v, want both false", okKnown, okUnknown)
	}
	if tokKnown != tokUnknown || tokKnown != "" {
		t.Fatalf("tokKnown=%q tokUnknown=%q, want both empty", tokKnown, tokUnknown)
	}
}

// TestRequestMagicLinkInvalidatesEarlierLink pins the re-issue contract:
// a second request for the same address kills the first link.
func TestRequestMagicLinkInvalidatesEarlierLink(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	mustSignUp(t, svc, "sana@example.com", validPassword)

	tok1, ok1, err := svc.RequestMagicLink(ctx, "sana@example.com", "1.2.3.4")
	if err != nil || !ok1 {
		t.Fatalf("first RequestMagicLink: ok=%v err=%v", ok1, err)
	}
	tok2, ok2, err := svc.RequestMagicLink(ctx, "sana@example.com", "1.2.3.4")
	if err != nil || !ok2 {
		t.Fatalf("second RequestMagicLink: ok=%v err=%v", ok2, err)
	}
	if tok1 == tok2 {
		t.Fatal("both RequestMagicLink calls returned the SAME token")
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok1)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(tok1) = %v, want ErrVerificationNotFound — the earlier link must be invalidated", ferr)
	}
}

// TestRequestMagicLinkReIssueLeavesOtherPurposesAlone pins that the
// re-issue sweep is purpose-scoped: requesting a magic link must not
// destroy a pending signup or password-reset token.
func TestRequestMagicLinkReIssueLeavesOtherPurposesAlone(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	res, err := svc.SignUp(ctx, "tomas@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	resetTok, ok, err := svc.RequestPasswordReset(ctx, "tomas@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	if _, _, err := svc.RequestMagicLink(ctx, "tomas@example.com", "1.2.3.4"); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(res.VerifyToken)); ferr != nil {
		t.Fatalf("signup verification after RequestMagicLink: %v, want it untouched", ferr)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(resetTok)); ferr != nil {
		t.Fatalf("password_reset verification after RequestMagicLink: %v, want it untouched", ferr)
	}
}

// TestRequestMagicLinkProvisioningOffCreatesNoUser is the default posture:
// an unknown address mints nothing and creates nobody.
func TestRequestMagicLinkProvisioningOffCreatesNoUser(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	tok, ok, err := svc.RequestMagicLink(ctx, "ghost@example.com", "1.2.3.4")
	if err != nil || ok || tok != "" {
		t.Fatalf("RequestMagicLink = (%q, %v, %v), want an empty token, false, nil", tok, ok, err)
	}
	if _, ferr := store.FindUserByEmail(ctx, "ghost@example.com"); !errors.Is(ferr, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail after a provisioning-off request = %v, want ErrUserNotFound — no account may be created", ferr)
	}
}

// TestRequestMagicLinkProvisioningOnCreatesPasswordlessUnverifiedAccount
// pins the opt-in branch: the account exists, holds NO password credential
// (so [Service.Login] can never authenticate it — see UserBase's doc), and
// is NOT treated as address-verified merely because someone asked for a
// link.
func TestRequestMagicLinkProvisioningOnCreatesPasswordlessUnverifiedAccount(t *testing.T) {
	svc, store := newTestService(t, auth.WithMagicLinkProvisioning(true))
	ctx := context.Background()

	tok, ok, err := svc.RequestMagicLink(ctx, "Ines@Example.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	if !ok || tok == "" {
		t.Fatalf("ok=%v tok=%q, want a minted link for a provisioned address", ok, tok)
	}

	u, err := store.FindUserByEmail(ctx, "ines@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v, want the provisioned account", err)
	}
	if u.PasswordHash != "" {
		t.Fatalf("PasswordHash = %q, want empty — a provisioned account holds no password credential", u.PasswordHash)
	}
	if u.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil — requesting a link proves nothing; redeeming one does", u.EmailVerifiedAt)
	}
	if u.Email != "ines@example.com" {
		t.Fatalf("Email = %q, want the normalized address", u.Email)
	}

	v, err := store.FindVerificationByHash(ctx, token.HashOpaque(tok))
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if v.UserID != u.ID || v.Purpose != auth.PurposeMagicLink || v.Email != u.Email {
		t.Fatalf("verification = %+v, want it bound to the provisioned account with purpose magic_link", v)
	}

	// A provisioned account is not a login: no password can reach it.
	if _, lerr := svc.Login(ctx, "ines@example.com", validPassword, "1.2.3.4", "agent"); !errors.Is(lerr, auth.ErrInvalidCredentials) {
		t.Fatalf("Login against a provisioned account = %v, want ErrInvalidCredentials", lerr)
	}
}

// TestRequestMagicLinkProvisioningOnAddressRateLimitCreatesNoUser pins
// that the address-keyed limiter gates PROVISIONING, not merely minting:
// otherwise the limiter that is documented as provisioning's control would
// not actually control it.
func TestRequestMagicLinkProvisioningOnAddressRateLimitCreatesNoUser(t *testing.T) {
	addressLimiter := &fakeLimiter{allow: false}
	svc, store := newTestService(t,
		auth.WithMagicLinkProvisioning(true),
		auth.WithMagicLinkRateLimiter(addressLimiter),
	)
	ctx := context.Background()

	tok, ok, err := svc.RequestMagicLink(ctx, "denied@example.com", "1.2.3.4")
	if err != nil || ok || tok != "" {
		t.Fatalf("RequestMagicLink = (%q, %v, %v), want an empty token, false, nil", tok, ok, err)
	}
	if _, ferr := store.FindUserByEmail(ctx, "denied@example.com"); !errors.Is(ferr, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail = %v, want ErrUserNotFound — a denied request must not provision", ferr)
	}
}

// TestRequestMagicLinkProvisioningOnCreateUserFailureIsFolded pins that
// CreateUser's failure — reachable only on the provisioning branch — is
// folded into the same ("", false, nil) every other deny path uses, rather
// than surfacing as an error.
func TestRequestMagicLinkProvisioningOnCreateUserFailureIsFolded(t *testing.T) {
	store := &usersTableWritesFailStore{AuthStore: memory.NewAuthStore()}
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithMagicLinkProvisioning(true),
	)

	tok, ok, err := svc.RequestMagicLink(context.Background(), "doomed@example.com", "1.2.3.4")
	if err != nil {
		t.Fatalf("err = %v, want nil — CreateUser's failure must not surface as an error", err)
	}
	if ok || tok != "" {
		t.Fatalf("ok=%v tok=%q, want an empty token and false", ok, tok)
	}
}

// TestWithMagicLinkTTLOverridesDefault pins that the magic-link lifetime is
// independent of the other two verification lifetimes.
func TestWithMagicLinkTTLOverridesDefault(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	svc, store := newTestService(t,
		auth.WithClock(func() time.Time { return now }),
		auth.WithMagicLinkTTL(5*time.Minute),
	)
	ctx := context.Background()
	res, err := svc.SignUp(ctx, "ugo@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	signup, err := store.FindVerificationByHash(ctx, token.HashOpaque(res.VerifyToken))
	if err != nil {
		t.Fatalf("FindVerificationByHash(signup): %v", err)
	}
	if want := now.Add(24 * time.Hour); !signup.ExpiresAt.Equal(want) {
		t.Fatalf("signup ExpiresAt = %v, want the untouched 24h default %v", signup.ExpiresAt, want)
	}

	tok, ok, err := svc.RequestMagicLink(ctx, "ugo@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink: ok=%v err=%v", ok, err)
	}
	v, err := store.FindVerificationByHash(ctx, token.HashOpaque(tok))
	if err != nil {
		t.Fatalf("FindVerificationByHash(magic_link): %v", err)
	}
	if want := now.Add(5 * time.Minute); !v.ExpiresAt.Equal(want) {
		t.Fatalf("magic_link ExpiresAt = %v, want %v", v.ExpiresAt, want)
	}
}

func TestWithMagicLinkTTLIgnoresNonPositiveDurations(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	svc, store := newTestService(t,
		auth.WithClock(func() time.Time { return now }),
		auth.WithMagicLinkTTL(0),
		auth.WithMagicLinkTTL(-time.Hour),
	)
	ctx := context.Background()
	mustSignUp(t, svc, "vera@example.com", validPassword)

	tok, ok, err := svc.RequestMagicLink(ctx, "vera@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink: ok=%v err=%v", ok, err)
	}
	v, err := store.FindVerificationByHash(ctx, token.HashOpaque(tok))
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if want := now.Add(15 * time.Minute); !v.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want the 15-minute default %v", v.ExpiresAt, want)
	}
}

// TestMagicLinkTokenIsNotRedeemableThroughVerifyEmail pins that the new
// purpose does not quietly widen VerifyEmail's closed set: a magic link is
// a login credential, not an address attestation, and VerifyEmail must
// refuse it without burning it.
func TestMagicLinkTokenIsNotRedeemableThroughVerifyEmail(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	mustSignUp(t, svc, "wilma@example.com", validPassword)

	tok, ok, err := svc.RequestMagicLink(ctx, "wilma@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink: ok=%v err=%v", ok, err)
	}
	if _, verr := svc.VerifyEmail(ctx, tok); !errors.Is(verr, auth.ErrVerificationPurpose) {
		t.Fatalf("VerifyEmail(magic link) = %v, want ErrVerificationPurpose", verr)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok)); ferr != nil {
		t.Fatalf("magic link after a refused VerifyEmail: %v, want it un-burned", ferr)
	}
}

// ============================================================
// RedeemMagicLink
// ============================================================

// redeemOrderStore records the order of the four calls RedeemMagicLink's
// claim-before-apply contract is about. CreateSession is the one that
// matters most: the burn MUST precede it, or two people clicking the same
// link both get a session.
type redeemOrderStore struct {
	*memory.AuthStore
	mu    sync.Mutex
	order []string
}

func newRedeemOrderStore() *redeemOrderStore {
	return &redeemOrderStore{AuthStore: memory.NewAuthStore()}
}

func (s *redeemOrderStore) record(name string) {
	s.mu.Lock()
	s.order = append(s.order, name)
	s.mu.Unlock()
}

func (s *redeemOrderStore) DeleteVerification(ctx context.Context, id string) error {
	s.record("DeleteVerification")
	return s.AuthStore.DeleteVerification(ctx, id)
}

func (s *redeemOrderStore) FindUserByID(ctx context.Context, id string) (auth.UserBase, error) {
	s.record("FindUserByID")
	return s.AuthStore.FindUserByID(ctx, id)
}

func (s *redeemOrderStore) MarkEmailVerified(ctx context.Context, userID, email string, now time.Time) error {
	s.record("MarkEmailVerified")
	return s.AuthStore.MarkEmailVerified(ctx, userID, email, now)
}

func (s *redeemOrderStore) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	s.record("CreateSession")
	return s.AuthStore.CreateSession(ctx, sess)
}

func (s *redeemOrderStore) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// userGoneStore answers FindUserByID with ErrUserNotFound while leaving
// every other call genuine — the account vanishing between mint and
// redeem. The core auth.Store has no DeleteUser (it arrives with account
// deletion, a later plan), so this double is how that window is reached at
// all.
type userGoneStore struct {
	*memory.AuthStore
}

func (s *userGoneStore) FindUserByID(context.Context, string) (auth.UserBase, error) {
	return auth.UserBase{}, auth.ErrUserNotFound
}

// parkOnVerificationLookupStore parks the FIRST caller to look a
// verification up, immediately AFTER the real (successful) read, and holds
// it until the test releases it. That makes the two-party race
// deterministic by construction rather than by scheduler luck: caller #2
// is only ever started once caller #1 holds a genuine, still-live
// Verification and is blocked before it can burn it, so caller #2 is
// GUARANTEED to reach Store.DeleteVerification first. It is
// service_test.go's parkingStore, pointed at a different call.
//
// sessionInserts counts sessions that were actually persisted. Counting
// them directly is what distinguishes "exactly one session was ever
// minted" from "two were minted": the returned LoginResults alone cannot,
// since a caller can fail after its own CreateSession succeeded.
type parkOnVerificationLookupStore struct {
	auth.Store
	calls          atomic.Int32
	parked         chan struct{}
	release        chan struct{}
	sessionInserts atomic.Int32
}

func newParkOnVerificationLookupStore(inner auth.Store) *parkOnVerificationLookupStore {
	return &parkOnVerificationLookupStore{
		Store:   inner,
		parked:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (s *parkOnVerificationLookupStore) FindVerificationByHash(ctx context.Context, hash string) (auth.Verification, error) {
	v, err := s.Store.FindVerificationByHash(ctx, hash)
	if s.calls.Add(1) == 1 {
		close(s.parked)
		<-s.release
	}
	return v, err
}

func (s *parkOnVerificationLookupStore) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	got, err := s.Store.CreateSession(ctx, sess)
	if err == nil {
		s.sessionInserts.Add(1)
	}
	return got, err
}

// mustRequestMagicLink requests a link for a KNOWN address and fails the
// test if one is not issued.
func mustRequestMagicLink(t *testing.T, svc *auth.Service, email string) string {
	t.Helper()
	tok, ok, err := svc.RequestMagicLink(context.Background(), email, "1.2.3.4")
	if err != nil {
		t.Fatalf("RequestMagicLink(%q): %v", email, err)
	}
	if !ok || tok == "" {
		t.Fatalf("RequestMagicLink(%q): ok=%v tok=%q, want an issued link", email, ok, tok)
	}
	return tok
}

func TestRedeemMagicLinkIssuesAWorkingSessionAndScrubsPasswordHash(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "abel@example.com", validPassword)
	tok := mustRequestMagicLink(t, svc, "abel@example.com")

	res, err := svc.RedeemMagicLink(ctx, tok, "203.0.113.9", "magic-agent")
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("access=%q refresh=%q, want both non-empty", res.AccessToken, res.RefreshToken)
	}
	if res.User.PasswordHash != "" {
		t.Fatalf("User.PasswordHash = %q, want it scrubbed", res.User.PasswordHash)
	}
	if res.User.ID != user.ID {
		t.Fatalf("User.ID = %q, want %q", res.User.ID, user.ID)
	}

	claims, err := token.Parse(res.AccessToken, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse(access): %v", err)
	}
	if claims.Subject != user.ID || claims.Email != "abel@example.com" {
		t.Fatalf("claims = %+v, want subject %q and email %q", claims, user.ID, "abel@example.com")
	}

	sess, err := store.FindSessionByHash(ctx, token.HashOpaque(res.RefreshToken))
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if sess.ID != claims.SessionID {
		t.Fatalf("session.ID = %q, want claims.SessionID %q", sess.ID, claims.SessionID)
	}
	if sess.UserID != user.ID {
		t.Fatalf("session.UserID = %q, want %q", sess.UserID, user.ID)
	}
	if sess.IP != "203.0.113.9" || sess.UserAgent != "magic-agent" {
		t.Fatalf("session IP/UserAgent = %q/%q, want the values RedeemMagicLink was given", sess.IP, sess.UserAgent)
	}
	if sess.FamilyID != sess.ID {
		t.Fatalf("session.FamilyID = %q, want it to equal its own ID (root of a new chain)", sess.FamilyID)
	}

	// The session genuinely works: it rotates.
	if _, rerr := svc.Refresh(ctx, res.RefreshToken); rerr != nil {
		t.Fatalf("Refresh on the magic-link session: %v, want success", rerr)
	}
}

// TestRedeemMagicLinkTokenIsSingleUse is half of this task's first mutation
// anchor: move the burn after the session mint and this must fail.
func TestRedeemMagicLinkTokenIsSingleUse(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	mustSignUp(t, svc, "bela@example.com", validPassword)
	tok := mustRequestMagicLink(t, svc, "bela@example.com")

	if _, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent"); err != nil {
		t.Fatalf("first RedeemMagicLink: %v", err)
	}
	res, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent")
	if !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("second RedeemMagicLink err = %v, want ErrVerificationNotFound — a magic link is single-use", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("second redemption handed back tokens (%q/%q); want none", res.AccessToken, res.RefreshToken)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("verification after redemption = %v, want it burned", ferr)
	}
}

// TestRedeemMagicLinkClaimsBeforeApplyOrdering pins the ordering directly:
// the burn must be recorded BEFORE the session insert. This is the other
// half of mutation (a) — reordering those two lines must be visible here
// as well as through the concurrency tests.
func TestRedeemMagicLinkClaimsBeforeApplyOrdering(t *testing.T) {
	store := newRedeemOrderStore()
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	mustSignUp(t, svc, "cora@example.com", validPassword)
	tok := mustRequestMagicLink(t, svc, "cora@example.com")

	if _, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent"); err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	got := store.snapshot()
	want := []string{"DeleteVerification", "FindUserByID", "MarkEmailVerified", "CreateSession"}
	if !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v — the claim must precede every effect", got, want)
	}
}

// TestRedeemMagicLinkConcurrentSameTokenExactlyOneWinner runs N symmetric
// goroutines against ONE link. There are no fixed roles here — every
// goroutine runs the identical code — so the "closing a channel readies
// waiters LIFO" hazard that makes a two-party start-gate explore a single
// interleaving does not arise; the deterministic park/gate test below
// covers the ordered case.
func TestRedeemMagicLinkConcurrentSameTokenExactlyOneWinner(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "dara@example.com", validPassword)
	tok := mustRequestMagicLink(t, svc, "dara@example.com")

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	withTokens, notFound, other := 0, 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && res.AccessToken != "" && res.RefreshToken != "":
				withTokens++
			case errors.Is(err, auth.ErrVerificationNotFound):
				notFound++
			default:
				other++
			}
		}()
	}
	wg.Wait()

	if withTokens != 1 {
		t.Fatalf("redemptions yielding a usable session = %d, want exactly 1 (notFound=%d other=%d)", withTokens, notFound, other)
	}
	if notFound != n-1 {
		t.Fatalf("notFound = %d, want %d", notFound, n-1)
	}
	if other != 0 {
		t.Fatalf("other = %d, want 0", other)
	}

	sessions, err := store.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions after %d concurrent redemptions = %d, want exactly 1", n, len(sessions))
	}
}

// TestRedeemMagicLinkDeterministicRaceAdmitsExactlyOneWinner drives the
// same property through a fixed, guaranteed interleaving instead of
// hoping the scheduler produces one: caller #1 holds a live, unburned
// verification and is parked; caller #2 then runs start to finish. Every
// run takes the identical path, so a failure here is a real defect rather
// than a flake, and a passing run is not scheduler luck.
func TestRedeemMagicLinkDeterministicRaceAdmitsExactlyOneWinner(t *testing.T) {
	inner := memory.NewAuthStore()
	seed := auth.New(inner,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	user := mustSignUp(t, seed, "elio@example.com", validPassword)
	tok := mustRequestMagicLink(t, seed, "elio@example.com")

	parking := newParkOnVerificationLookupStore(inner)
	svc := auth.New(parking,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)

	type result struct {
		res auth.LoginResult
		err error
	}
	firstDone := make(chan result, 1)
	go func() {
		res, err := svc.RedeemMagicLink(ctx, tok, "1.1.1.1", "first")
		firstDone <- result{res, err}
	}()

	<-parking.parked // caller #1 has read the live verification and is parked

	secondRes, secondErr := svc.RedeemMagicLink(ctx, tok, "2.2.2.2", "second")

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
		t.Fatalf("loser got tokens (%q/%q); want none — the link was already claimed", first.res.AccessToken, first.res.RefreshToken)
	}

	// Direct, not inferred: exactly one session row was ever persisted.
	if n := parking.sessionInserts.Load(); n != 1 {
		t.Fatalf("CreateSession succeeded %d time(s), want exactly 1 — two people clicking one link must not both get in", n)
	}
	sessions, err := inner.ListSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want exactly 1", len(sessions))
	}
}

// TestRedeemMagicLinkRefusesAPasswordResetTokenWithoutBurningIt is this
// task's second mutation anchor. Removing the purpose check would let a
// "password_reset" token — a LOWER-privileged credential, redeemable only
// into a password-set form — be exchanged directly for a live session:
// a full account takeover from a token that was never meant to grant one.
// The token must also SURVIVE the refusal, exactly as ResetPassword and
// VerifyEmail leave a wrongly-presented token alone.
func TestRedeemMagicLinkRefusesAPasswordResetTokenWithoutBurningIt(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	mustSignUp(t, svc, "fina@example.com", validPassword)

	resetTok, ok, err := svc.RequestPasswordReset(ctx, "fina@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	res, rerr := svc.RedeemMagicLink(ctx, resetTok, "1.2.3.4", "agent")
	if !errors.Is(rerr, auth.ErrVerificationPurpose) {
		t.Fatalf("RedeemMagicLink(password_reset token) = %v, want ErrVerificationPurpose — redeeming one into a session is a full account takeover from a lower-privileged token", rerr)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("a password_reset token yielded a session (%q/%q); that is an account takeover", res.AccessToken, res.RefreshToken)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(resetTok)); ferr != nil {
		t.Fatalf("password_reset verification after the refusal: %v, want it un-burned", ferr)
	}
	// And it still does the job it was actually minted for.
	if perr := svc.ResetPassword(ctx, resetTok, "Another-Valid-Pass21!"); perr != nil {
		t.Fatalf("ResetPassword after the refused redemption: %v, want success", perr)
	}
}

// TestRedeemMagicLinkRefusesASignupTokenWithoutBurningIt is the same
// argument for the other direction: a "signup" token is an address
// attestation and grants nothing over the credential, so it must not
// become a login either.
func TestRedeemMagicLinkRefusesASignupTokenWithoutBurningIt(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	res, err := svc.SignUp(ctx, "gus@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	got, rerr := svc.RedeemMagicLink(ctx, res.VerifyToken, "1.2.3.4", "agent")
	if !errors.Is(rerr, auth.ErrVerificationPurpose) {
		t.Fatalf("RedeemMagicLink(signup token) = %v, want ErrVerificationPurpose", rerr)
	}
	if got.AccessToken != "" || got.RefreshToken != "" {
		t.Fatalf("a signup token yielded a session (%q/%q)", got.AccessToken, got.RefreshToken)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(res.VerifyToken)); ferr != nil {
		t.Fatalf("signup verification after the refusal: %v, want it un-burned", ferr)
	}
}

func TestRedeemMagicLinkUnknownToken(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.RedeemMagicLink(context.Background(), "not-a-real-token", "1.2.3.4", "agent")
	if !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("err = %v, want ErrVerificationNotFound", err)
	}
}

// TestRedeemMagicLinkExpiredLinkNotClaimed pins that an expired link is
// refused AND left alone: it ages out through PurgeExpired like any other
// row, so a user who clicks late loses nothing but the click.
func TestRedeemMagicLinkExpiredLinkNotClaimed(t *testing.T) {
	minted := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := minted
	svc, store := newTestService(t, auth.WithClock(func() time.Time { return clock }))
	ctx := context.Background()
	mustSignUp(t, svc, "hana@example.com", validPassword)
	tok := mustRequestMagicLink(t, svc, "hana@example.com")

	clock = minted.Add(15*time.Minute + time.Nanosecond)
	res, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent")
	if !errors.Is(err, auth.ErrVerificationExpired) {
		t.Fatalf("err = %v, want ErrVerificationExpired", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("an expired link yielded a session (%q/%q)", res.AccessToken, res.RefreshToken)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(tok)); ferr != nil {
		t.Fatalf("verification after an expired redemption: %v, want it un-burned", ferr)
	}
}

// TestRedeemMagicLinkStampsEmailVerifiedOnANeverVerifiedAccount: receiving
// mail at an address is proof of control of it, the same argument that
// made ResetPassword stamp.
func TestRedeemMagicLinkStampsEmailVerifiedOnANeverVerifiedAccount(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	svc, store := newTestService(t, auth.WithClock(func() time.Time { return now }))
	ctx := context.Background()
	user := mustSignUp(t, svc, "iris@example.com", validPassword)
	if user.EmailVerifiedAt != nil {
		t.Fatal("precondition: a fresh signup must be unverified")
	}
	tok := mustRequestMagicLink(t, svc, "iris@example.com")

	res, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent")
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	stored, err := store.FindUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is still nil — redeeming a link delivered to the address is proof of control")
	}
	if !stored.EmailVerifiedAt.Equal(now) {
		t.Fatalf("EmailVerifiedAt = %v, want %v", stored.EmailVerifiedAt, now)
	}
	// The returned record must not lie about it either.
	if res.User.EmailVerifiedAt == nil || !res.User.EmailVerifiedAt.Equal(now) {
		t.Fatalf("returned User.EmailVerifiedAt = %v, want %v — the value handed back must match what was just written", res.User.EmailVerifiedAt, now)
	}
}

// TestRedeemMagicLinkDoesNotRestampAnAlreadyVerifiedAddress: EmailVerifiedAt
// records WHEN control was first proven, so an unrelated sign-in must not
// move it forward.
func TestRedeemMagicLinkDoesNotRestampAnAlreadyVerifiedAddress(t *testing.T) {
	signupAt := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := signupAt
	svc, store := newTestService(t, auth.WithClock(func() time.Time { return clock }))
	ctx := context.Background()
	res, err := svc.SignUp(ctx, "jonah@example.com", validPassword)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, verr := svc.VerifyEmail(ctx, res.VerifyToken); verr != nil {
		t.Fatalf("VerifyEmail: %v", verr)
	}
	before, err := store.FindUserByID(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if before.EmailVerifiedAt == nil {
		t.Fatal("precondition: the address must already be verified")
	}

	clock = signupAt.Add(48 * time.Hour)
	tok := mustRequestMagicLink(t, svc, "jonah@example.com")
	if _, rerr := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent"); rerr != nil {
		t.Fatalf("RedeemMagicLink: %v", rerr)
	}

	after, err := store.FindUserByID(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if !after.EmailVerifiedAt.Equal(*before.EmailVerifiedAt) {
		t.Fatalf("EmailVerifiedAt moved from %v to %v — a sign-in must not re-stamp an audit value", before.EmailVerifiedAt, after.EmailVerifiedAt)
	}
}

// TestRedeemMagicLinkDoesNotVerifyAnAddressTheLinkWasNotSentTo pins the
// second guard: the proof is about the address the link was DELIVERED to,
// not whatever the row happens to hold at redemption time.
func TestRedeemMagicLinkDoesNotVerifyAnAddressTheLinkWasNotSentTo(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	store := memory.NewAuthStore()
	svc := auth.New(store,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithClock(func() time.Time { return now }),
	)
	ctx := context.Background()
	user := mustSignUp(t, svc, "kaya@example.com", validPassword)
	tok := mustRequestMagicLink(t, svc, "kaya@example.com")

	// The account's address moves out from under the pending link, and is
	// left unverified exactly as UpdateUserEmail leaves it.
	if err := store.UpdateUserEmail(ctx, user.ID, "kaya-new@example.com", now); err != nil {
		t.Fatalf("UpdateUserEmail: %v", err)
	}

	if _, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent"); err != nil {
		t.Fatalf("RedeemMagicLink: %v, want the sign-in to still succeed", err)
	}
	stored, err := store.FindUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil — nobody proved control of %q", stored.EmailVerifiedAt, stored.Email)
	}
}

// TestRedeemMagicLinkUserGoneBetweenMintAndRedeem pins the fail-closed
// answer for an account that disappears after its link was issued, and
// that the claim already happened: the token is burned either way, which
// is under-granting rather than leaving a claimed token redeemable.
func TestRedeemMagicLinkUserGoneBetweenMintAndRedeem(t *testing.T) {
	inner := memory.NewAuthStore()
	seed := auth.New(inner,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	ctx := context.Background()
	mustSignUp(t, seed, "liam@example.com", validPassword)
	tok := mustRequestMagicLink(t, seed, "liam@example.com")

	svc := auth.New(&userGoneStore{AuthStore: inner},
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
	)
	res, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("a vanished account yielded a session (%q/%q)", res.AccessToken, res.RefreshToken)
	}
	if _, ferr := inner.FindVerificationByHash(ctx, token.HashOpaque(tok)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("verification = %v, want it burned — the claim runs before the user is loaded", ferr)
	}
}

// TestRedeemMagicLinkBurnsOnlyItsOwnToken is the sweep matrix's last row:
// redemption claims the link it was given and sweeps nothing else.
func TestRedeemMagicLinkBurnsOnlyItsOwnToken(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()
	user := mustSignUp(t, svc, "maja@example.com", validPassword)
	resetTok, ok, err := svc.RequestPasswordReset(ctx, "maja@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}
	changeTok, err := svc.RequestEmailChange(ctx, user.ID, validPassword, "maja-new@example.com")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	tok := mustRequestMagicLink(t, svc, "maja@example.com")

	if _, rerr := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent"); rerr != nil {
		t.Fatalf("RedeemMagicLink: %v", rerr)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(resetTok)); ferr != nil {
		t.Fatalf("password_reset verification after redemption: %v, want it untouched", ferr)
	}
	if _, ferr := store.FindVerificationByHash(ctx, token.HashOpaque(changeTok)); ferr != nil {
		t.Fatalf("email_change verification after redemption: %v, want it untouched", ferr)
	}
}

// TestRedeemMagicLinkLeavesExistingSessionsAlone: signing in on a new
// device is not a revocation event.
func TestRedeemMagicLinkLeavesExistingSessionsAlone(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	mustSignUp(t, svc, "nils@example.com", validPassword)
	_, _, refresh := mustLogin(t, svc, "nils@example.com", validPassword)
	tok := mustRequestMagicLink(t, svc, "nils@example.com")

	if _, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent"); err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if _, err := svc.Refresh(ctx, refresh); err != nil {
		t.Fatalf("Refresh on the pre-existing session: %v, want it still alive", err)
	}
}

// TestRedeemMagicLinkSignsInAProvisionedPasswordlessAccount closes the
// provisioning loop end to end: an account created by RequestMagicLink has
// no password, so redemption is the ONLY way it can ever be signed in, and
// it must work.
func TestRedeemMagicLinkSignsInAProvisionedPasswordlessAccount(t *testing.T) {
	svc, store := newTestService(t, auth.WithMagicLinkProvisioning(true))
	ctx := context.Background()

	tok, ok, err := svc.RequestMagicLink(ctx, "opal@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink: ok=%v err=%v", ok, err)
	}
	res, err := svc.RedeemMagicLink(ctx, tok, "1.2.3.4", "agent")
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("a provisioned account got no usable session")
	}
	stored, err := store.FindUserByEmail(ctx, "opal@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if stored.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is nil after redemption — the click is what proves control")
	}
	if stored.PasswordHash != "" {
		t.Fatalf("PasswordHash = %q, want it still empty — redemption sets no password", stored.PasswordHash)
	}
}
