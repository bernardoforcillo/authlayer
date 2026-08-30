package auth_test

import (
	"context"
	"errors"
	"sync"
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
