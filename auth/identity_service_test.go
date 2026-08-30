package auth_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// --- fixtures shared by the SignInWith suite -------------------------------

// newOAuthService builds a Service over fresh in-memory auth AND identity
// stores. Everything else matches newTestService (fast hasher, fixed signing
// key); opts are applied after the identity store is wired, so a test may
// still override it with a double of its own.
func newOAuthService(t *testing.T, opts ...auth.Option) (*auth.Service, *memory.AuthStore, *memory.IdentityStore) {
	t.Helper()
	ids := memory.NewIdentityStore()
	svc, store := newTestService(t, append([]auth.Option{auth.WithIdentityStore(ids)}, opts...)...)
	return svc, store, ids
}

// googleExt is the assertion a provider hands the application after a
// successful dance. Tests vary one field at a time from this shape.
func googleExt(email string, verified bool) auth.ExternalIdentity {
	return auth.ExternalIdentity{
		Provider:      "google",
		Subject:       "google-subject-1",
		Email:         email,
		EmailVerified: verified,
	}
}

// signInReq wraps an assertion with the two audit fields every session row
// carries, so tests that do not care about them stay short.
func signInReq(ext auth.ExternalIdentity) auth.SignInRequest {
	return auth.SignInRequest{Identity: ext, IP: "198.51.100.7", UserAgent: "oauth-agent"}
}

// signUpVerified registers an account by password AND redeems its signup
// verification, producing the "local account is itself verified" half that
// LinkVerified requires. mustSignUp alone leaves EmailVerifiedAt nil.
func signUpVerified(t *testing.T, svc *auth.Service, email, plain string) auth.UserBase {
	t.Helper()
	res, err := svc.SignUp(context.Background(), email, plain)
	if err != nil || !res.Created {
		t.Fatalf("SignUp(%q): created=%v err=%v", email, res.Created, err)
	}
	if _, err := svc.VerifyEmail(context.Background(), res.VerifyToken); err != nil {
		t.Fatalf("VerifyEmail(%q): %v", email, err)
	}
	user, err := svc.User(context.Background(), res.User.ID)
	if err != nil {
		t.Fatalf("User(%q): %v", res.User.ID, err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatalf("signUpVerified(%q): EmailVerifiedAt still nil", email)
	}
	return user
}

// sessionCount reports how many session rows exist for userID. Every refusal
// test asserts this is zero: an error return that still minted a session
// would be an authentication bypass wearing an error's clothes.
func sessionCount(t *testing.T, store *memory.AuthStore, userID string) int {
	t.Helper()
	sessions, err := store.ListSessionsByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListSessionsByUser(%q): %v", userID, err)
	}
	return len(sessions)
}

// identitiesOf returns userID's identity rows.
func identitiesOf(t *testing.T, ids auth.IdentityStore, userID string) []auth.Identity {
	t.Helper()
	list, err := ids.ListIdentitiesByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListIdentitiesByUser(%q): %v", userID, err)
	}
	return list
}

// assertNoIdentityRow fails unless (provider, subject) is unknown to the
// store. This is the strongest form of "nothing was written": it holds even
// if a buggy implementation attached the identity to some OTHER user than
// the one a test was watching.
func assertNoIdentityRow(t *testing.T, ids auth.IdentityStore, provider, subject string) {
	t.Helper()
	got, err := ids.FindIdentityByProviderSubject(context.Background(), provider, subject)
	if !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("FindIdentityByProviderSubject(%q,%q) = %+v, err = %v; want ErrIdentityNotFound — the refusal must write nothing",
			provider, subject, got, err)
	}
}

// assertNoTokens fails unless the result carries neither token. A refusal
// that returned a populated SignInResult alongside its error would hand a
// caller who forgot to check err a working session.
func assertNoTokens(t *testing.T, res auth.SignInResult) {
	t.Helper()
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("refused SignInWith returned tokens: access=%q refresh=%q", res.AccessToken, res.RefreshToken)
	}
	if res.Created {
		t.Fatalf("refused SignInWith reported Created = true")
	}
	if res.User.ID != "" {
		t.Fatalf("refused SignInWith returned a user: %+v", res.User)
	}
}

// --- test doubles ----------------------------------------------------------

var errIdentityBoom = errors.New("boom: simulated identity-store outage")

// touchFailIdentityStore is a real store whose TouchIdentity always fails.
// It exists for the fail-closed test: a sign-in that cannot record the use
// of an identity must not proceed to mint a session.
type touchFailIdentityStore struct {
	auth.IdentityStore
}

func (s touchFailIdentityStore) TouchIdentity(context.Context, string, time.Time) error {
	return errIdentityBoom
}

// findFailIdentityStore fails every (provider, subject) lookup. A store that
// cannot answer must never be read as a store that answered "no such
// identity": that would push every sign-in down the email rung.
type findFailIdentityStore struct {
	auth.IdentityStore
}

func (s findFailIdentityStore) FindIdentityByProviderSubject(context.Context, string, string) (auth.Identity, error) {
	return auth.Identity{}, errIdentityBoom
}

// emailTakenStore is an AuthStore whose CreateUser always reports the
// address as already registered — what a genuinely concurrent provisioning
// of the same address produces.
type emailTakenStore struct {
	*memory.AuthStore
}

func (s emailTakenStore) CreateUser(context.Context, auth.UserBase) (auth.UserBase, error) {
	return auth.UserBase{}, auth.ErrEmailTaken
}

// gatedIdentityStore delegates to a real IdentityStore but parks the FIRST
// FindIdentityByProviderSubject call AFTER it has computed its answer and
// BEFORE that answer is returned. That is precisely the check-then-act
// window in SignInWith's first rung, held open on demand: the test drives
// the exact interleaving through two channels, with no sleeps and no
// repeated rounds, so the outcome is deterministic rather than a 1-in-N
// chance of catching a race.
//
// A counter rather than sync.Once is deliberate: Once.Do blocks every other
// caller until the first invocation returns, which would deadlock the very
// second sign-in the test needs to run while the first is parked.
type gatedIdentityStore struct {
	auth.IdentityStore

	finds   atomic.Int64
	parked  chan struct{}
	release chan struct{}
}

func newGatedIdentityStore(inner auth.IdentityStore) *gatedIdentityStore {
	return &gatedIdentityStore{
		IdentityStore: inner,
		parked:        make(chan struct{}),
		release:       make(chan struct{}),
	}
}

func (s *gatedIdentityStore) FindIdentityByProviderSubject(ctx context.Context, provider, subject string) (auth.Identity, error) {
	i, err := s.IdentityStore.FindIdentityByProviderSubject(ctx, provider, subject)
	if s.finds.Add(1) == 1 {
		close(s.parked)
		<-s.release
	}
	return i, err
}

// --- the port must be configured -------------------------------------------

// TestSignInWithRefusesWithoutAnIdentityStore pins that the optional port
// being absent is an ordinary typed refusal at the entry point, not a nil
// dereference somewhere down the ladder.
func TestSignInWithRefusesWithoutAnIdentityStore(t *testing.T) {
	svc, _ := newTestService(t) // no WithIdentityStore

	res, err := svc.SignInWith(context.Background(), signInReq(googleExt("nia@example.com", true)))
	if !errors.Is(err, auth.ErrOAuthNotConfigured) {
		t.Fatalf("SignInWith err = %v, want ErrOAuthNotConfigured", err)
	}
	assertNoTokens(t, res)
}

// --- rung 1: the (provider, subject) pair ----------------------------------

// TestSignInWithProvisionsThenResolvesBySubject walks the ordinary happy
// path twice: the first call provisions, the second resolves the same
// external account back to the same local user and stamps LastUsedAt.
func TestSignInWithProvisionsThenResolvesBySubject(t *testing.T) {
	created := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	used := created.Add(48 * time.Hour)
	now := created
	svc, store, ids := newOAuthService(t, auth.WithClock(func() time.Time { return now }))
	ctx := context.Background()

	first, err := svc.SignInWith(ctx, signInReq(googleExt("Owen@Example.com", true)))
	if err != nil {
		t.Fatalf("first SignInWith: %v", err)
	}
	if !first.Created {
		t.Fatalf("first SignInWith Created = false, want true for an unknown subject and unknown address")
	}

	now = used
	second, err := svc.SignInWith(ctx, signInReq(googleExt("owen@example.com", true)))
	if err != nil {
		t.Fatalf("second SignInWith: %v", err)
	}
	if second.Created {
		t.Fatalf("second SignInWith Created = true, want false — the subject was already linked")
	}
	if second.User.ID != first.User.ID {
		t.Fatalf("second SignInWith user = %q, want the first call's user %q", second.User.ID, first.User.ID)
	}

	list := identitiesOf(t, ids, first.User.ID)
	if len(list) != 1 {
		t.Fatalf("identity rows = %d, want exactly 1 — the second sign-in must reuse the link, not add one", len(list))
	}
	if list[0].LastUsedAt == nil || !list[0].LastUsedAt.Equal(used) {
		t.Fatalf("LastUsedAt = %v, want the second sign-in's clock %v", list[0].LastUsedAt, used)
	}
	if sessionCount(t, store, first.User.ID) != 2 {
		t.Fatalf("sessions = %d, want 2 — each sign-in mints its own", sessionCount(t, store, first.User.ID))
	}
}

// TestSignInWithResolvesBySubjectEvenWhenTheProviderChangesTheEmail is the
// first of the two tests pinning the LADDER'S ORDER, and the reason
// (provider, subject) is consulted before the address.
//
// A user changing their address at the provider must land on the same local
// account. Consulting the email first would instead see an address nobody
// holds locally and provision a SECOND account, silently splitting the user
// in two — and, worse, would make the provider's mutable email field the
// thing that decides which local account an established link resolves to.
//
// Mutation check: move the email rung ahead of the subject rung and this
// fails.
func TestSignInWithResolvesBySubjectEvenWhenTheProviderChangesTheEmail(t *testing.T) {
	svc, store, ids := newOAuthService(t)
	ctx := context.Background()

	first, err := svc.SignInWith(ctx, signInReq(googleExt("pia.old@example.com", true)))
	if err != nil {
		t.Fatalf("first SignInWith: %v", err)
	}

	// Same subject, brand-new address that belongs to nobody here.
	second, err := svc.SignInWith(ctx, signInReq(googleExt("pia.new@example.com", true)))
	if err != nil {
		t.Fatalf("second SignInWith: %v", err)
	}
	if second.Created {
		t.Fatalf("Created = true: a changed provider email provisioned a second account")
	}
	if second.User.ID != first.User.ID {
		t.Fatalf("user = %q, want the linked account %q — the subject identifies the account, not the address",
			second.User.ID, first.User.ID)
	}

	// users.email is untouched: this package never rewrites a local address
	// from a provider's assertion.
	if second.User.Email != "pia.old@example.com" {
		t.Fatalf("User.Email = %q, want \"pia.old@example.com\" — a provider assertion must not rewrite the local address",
			second.User.Email)
	}
	if _, err := store.FindUserByEmail(ctx, "pia.new@example.com"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail(new address) err = %v, want ErrUserNotFound — no second account may exist", err)
	}
	if list := identitiesOf(t, ids, first.User.ID); len(list) != 1 {
		t.Fatalf("identity rows = %d, want exactly 1", len(list))
	}
}

// TestSignInWithDoesNotRerouteALinkedIdentityToAnotherAccount is the second
// ladder-order test, and the one with teeth: the address the provider now
// reports belongs to a DIFFERENT, fully verified local account.
//
// With the email consulted first, the linking policy would be satisfied
// (provider verified, target account verified) and the sign-in would resolve
// to that other account — one external identity signing in as whichever
// local user its mutable email field currently names. The subject rung
// exists to make that unreachable.
//
// Mutation check: move the email rung ahead of the subject rung and this
// fails.
func TestSignInWithDoesNotRerouteALinkedIdentityToAnotherAccount(t *testing.T) {
	svc, store, ids := newOAuthService(t)
	ctx := context.Background()

	linked, err := svc.SignInWith(ctx, signInReq(googleExt("quinn@example.com", true)))
	if err != nil {
		t.Fatalf("SignInWith(initial link): %v", err)
	}
	victim := signUpVerified(t, svc, "rhea@example.com", validPassword)

	// The provider now reports the victim's verified address for the SAME
	// subject.
	res, err := svc.SignInWith(ctx, signInReq(googleExt("rhea@example.com", true)))
	if err != nil {
		t.Fatalf("SignInWith(changed email): %v", err)
	}
	if res.User.ID != linked.User.ID {
		t.Fatalf("user = %q, want the already-linked account %q — an established link must never be re-routed by the provider's email",
			res.User.ID, linked.User.ID)
	}
	if res.User.ID == victim.ID {
		t.Fatalf("the external identity signed in as the victim %q", victim.ID)
	}
	if got := identitiesOf(t, ids, victim.ID); len(got) != 0 {
		t.Fatalf("victim identity rows = %d, want 0", len(got))
	}
	if got := sessionCount(t, store, victim.ID); got != 0 {
		t.Fatalf("victim sessions = %d, want 0", got)
	}
}

// TestSignInWithFailsClosedWhenTheIdentityLookupFails pins that a store
// outage on the first rung is propagated rather than read as "no such
// identity". Folding an error into a miss would silently demote every
// sign-in to the email rung for the duration of the outage, where a
// permissive policy or a fresh provisioning decides the account instead of
// the link that actually exists.
func TestSignInWithFailsClosedWhenTheIdentityLookupFails(t *testing.T) {
	svc, store, _ := newOAuthService(t, auth.WithIdentityStore(findFailIdentityStore{memory.NewIdentityStore()}))
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, signInReq(googleExt("sam@example.com", true)))
	if !errors.Is(err, errIdentityBoom) {
		t.Fatalf("SignInWith err = %v, want the store's own error", err)
	}
	assertNoTokens(t, res)
	if _, err := store.FindUserByEmail(ctx, "sam@example.com"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail err = %v, want ErrUserNotFound — a failed lookup must not fall through to provisioning", err)
	}
}

// TestSignInWithFailsClosedWhenTouchIdentityFails pins the package's
// fail-closed constraint on the one write the resolved-by-subject path
// performs before minting: if the use cannot be recorded, no session is
// issued. Swallowing the error would trade an audit field for a silent
// divergence between what the store believes and what the caller was given.
func TestSignInWithFailsClosedWhenTouchIdentityFails(t *testing.T) {
	inner := memory.NewIdentityStore()
	svc, store, _ := newOAuthService(t, auth.WithIdentityStore(touchFailIdentityStore{inner}))
	ctx := context.Background()

	first, err := svc.SignInWith(ctx, signInReq(googleExt("tess@example.com", true)))
	if err != nil {
		t.Fatalf("first SignInWith: %v", err)
	}
	before := sessionCount(t, store, first.User.ID)

	res, err := svc.SignInWith(ctx, signInReq(googleExt("tess@example.com", true)))
	if !errors.Is(err, errIdentityBoom) {
		t.Fatalf("second SignInWith err = %v, want the TouchIdentity error propagated", err)
	}
	assertNoTokens(t, res)
	if got := sessionCount(t, store, first.User.ID); got != before {
		t.Fatalf("sessions = %d, want %d — a failed touch must not mint a session", got, before)
	}
}

// TestSignInWithFailsClosedOnADanglingIdentity pins what happens when an
// identity row names a user that no longer exists. There is no honest
// account to sign in as, so the sign-in fails rather than provisioning a
// replacement from the provider's asserted address — which would let a
// deleted account be resurrected, with its old id gone and its old data
// unreachable, by whoever still holds the external account.
func TestSignInWithFailsClosedOnADanglingIdentity(t *testing.T) {
	svc, _, ids := newOAuthService(t)
	ctx := context.Background()

	if _, err := ids.CreateIdentity(ctx, auth.Identity{
		ID:       "identity-dangling",
		UserID:   "user-that-does-not-exist",
		Provider: "google",
		Subject:  "google-subject-1",
		Email:    "una@example.com",
	}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	res, err := svc.SignInWith(ctx, signInReq(googleExt("una@example.com", true)))
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("SignInWith err = %v, want ErrUserNotFound", err)
	}
	assertNoTokens(t, res)
}

// --- rung 2: provisioning --------------------------------------------------

// TestSignInWithProvisionsAnUnknownAddress pins every field of a
// freshly-provisioned account: no password credential in the store (not
// merely scrubbed on the way out), the address normalized, the verification
// timestamp taken from the provider's claim, and an identity row carrying
// the provider's asserted address.
func TestSignInWithProvisionsAnUnknownAddress(t *testing.T) {
	now := time.Date(2026, 4, 2, 9, 30, 0, 0, time.UTC)
	svc, store, ids := newOAuthService(t, auth.WithClock(func() time.Time { return now }))
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, signInReq(googleExt("  Vera@Example.COM ", true)))
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if !res.Created {
		t.Fatalf("Created = false, want true")
	}
	if res.User.Email != "vera@example.com" {
		t.Fatalf("User.Email = %q, want the normalized address", res.User.Email)
	}
	if res.User.PasswordHash != "" {
		t.Fatalf("User.PasswordHash = %q, want it scrubbed", res.User.PasswordHash)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("access=%q refresh=%q, want both non-empty", res.AccessToken, res.RefreshToken)
	}

	stored, err := store.FindUserByEmail(ctx, "vera@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if stored.PasswordHash != "" {
		t.Fatalf("stored PasswordHash = %q, want empty — an OAuth-provisioned account holds no password credential at all", stored.PasswordHash)
	}
	if stored.EmailVerifiedAt == nil || !stored.EmailVerifiedAt.Equal(now) {
		t.Fatalf("stored EmailVerifiedAt = %v, want %v — the provider asserted the address verified", stored.EmailVerifiedAt, now)
	}

	list := identitiesOf(t, ids, res.User.ID)
	if len(list) != 1 {
		t.Fatalf("identity rows = %d, want 1", len(list))
	}
	if list[0].Provider != "google" || list[0].Subject != "google-subject-1" {
		t.Fatalf("identity (provider,subject) = (%q,%q), want (google, google-subject-1)", list[0].Provider, list[0].Subject)
	}
	if list[0].Email != "vera@example.com" {
		t.Fatalf("identity Email = %q, want the provider's asserted address, normalized", list[0].Email)
	}
	if !list[0].CreatedAt.Equal(now) {
		t.Fatalf("identity CreatedAt = %v, want %v", list[0].CreatedAt, now)
	}
	if list[0].LastUsedAt == nil || !list[0].LastUsedAt.Equal(now) {
		t.Fatalf("identity LastUsedAt = %v, want %v — this link was created BY a sign-in, so it has been used",
			list[0].LastUsedAt, now)
	}

	// The minted session and access token are the same shape Login's are.
	claims, err := token.Parse(res.AccessToken, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse: %v", err)
	}
	if claims.Subject != res.User.ID || claims.Email != "vera@example.com" {
		t.Fatalf("claims = %+v, want subject %q and the normalized email", claims, res.User.ID)
	}
	sess, err := store.FindSessionByHash(ctx, token.HashOpaque(res.RefreshToken))
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if sess.ID != claims.SessionID || sess.UserID != res.User.ID {
		t.Fatalf("session = %+v, want it to name the token's session and the provisioned user", sess)
	}
	if sess.FamilyID != sess.ID {
		t.Fatalf("session.FamilyID = %q, want it to root its own chain", sess.FamilyID)
	}
	if sess.IP != "198.51.100.7" || sess.UserAgent != "oauth-agent" {
		t.Fatalf("session IP/UserAgent = %q/%q, want the request's values", sess.IP, sess.UserAgent)
	}
}

// TestSignInWithProvisionsUnverifiedWhenTheProviderDoesNot pins the other
// half of the provisioning rule: EmailVerifiedAt is set iff the provider
// asserted the address verified. A provider that does not report
// verification maps to false, and the account it provisions must not come
// out marked as though someone had proven control of the address.
func TestSignInWithProvisionsUnverifiedWhenTheProviderDoesNot(t *testing.T) {
	svc, store, _ := newOAuthService(t)
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, signInReq(googleExt("wes@example.com", false)))
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if !res.Created {
		t.Fatalf("Created = false, want true")
	}
	stored, err := store.FindUserByEmail(ctx, "wes@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if stored.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil — the provider did not assert the address verified", stored.EmailVerifiedAt)
	}
}

// TestSignInWithPropagatesAConcurrentProvisioning pins that losing the
// provisioning race is reported, not papered over. Falling back to "then it
// must already exist, link to it" would skip the linking policy entirely for
// exactly the caller who lost the race.
func TestSignInWithPropagatesAConcurrentProvisioning(t *testing.T) {
	ids := memory.NewIdentityStore()
	svc := auth.New(emailTakenStore{memory.NewAuthStore()},
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithIdentityStore(ids),
	)
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, signInReq(googleExt("xan@example.com", true)))
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("SignInWith err = %v, want ErrEmailTaken propagated", err)
	}
	assertNoTokens(t, res)
	assertNoIdentityRow(t, ids, "google", "google-subject-1")
}

// TestSignInWithClosesTheSubjectLookupWindowInTheStore is the deterministic
// control for the one check-then-act SignInWith cannot avoid: the gap
// between "no identity for this (provider, subject)" and the CreateIdentity
// that acts on it. Two sign-ins for the same external account can both pass
// the check.
//
// It is driven through the exact interleaving with a park/gate channel pair
// and no sleeps: goroutine A's lookup answers "not found", then parks
// holding that answer while B runs to completion and creates the row. A then
// resumes into a world its own answer no longer describes.
//
// What must happen: the STORE refuses A's write on its (provider, subject)
// uniqueness constraint, and SignInWith propagates that refusal rather than
// re-pointing B's link or minting a second session. There is no lock in the
// service layer for this and there cannot be one — the users table and the
// identities table may be different backends — so the constraint is the
// whole defence, and this test is what says so out loud.
func TestSignInWithClosesTheSubjectLookupWindowInTheStore(t *testing.T) {
	gated := newGatedIdentityStore(memory.NewIdentityStore())
	svc, store := newTestService(t, auth.WithIdentityStore(gated))
	ctx := context.Background()
	req := signInReq(googleExt("yuki@example.com", true))

	var (
		wg   sync.WaitGroup
		resA auth.SignInResult
		errA error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resA, errA = svc.SignInWith(ctx, req)
	}()

	<-gated.parked // A has read "not found" and is holding it.

	resB, errB := svc.SignInWith(ctx, req)
	if errB != nil {
		t.Fatalf("B SignInWith: %v", errB)
	}
	if !resB.Created {
		t.Fatalf("B Created = false, want true — B ran to completion first")
	}

	close(gated.release)
	wg.Wait()

	if !errors.Is(errA, auth.ErrIdentityLinked) {
		t.Fatalf("A SignInWith err = %v, want ErrIdentityLinked from the store's uniqueness constraint", errA)
	}
	assertNoTokens(t, resA)

	linked, err := gated.FindIdentityByProviderSubject(ctx, "google", "google-subject-1")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if linked.UserID != resB.User.ID {
		t.Fatalf("identity UserID = %q, want B's user %q — A must never re-point an existing link", linked.UserID, resB.User.ID)
	}
	if got := len(identitiesOf(t, gated, resB.User.ID)); got != 1 {
		t.Fatalf("identity rows = %d, want exactly 1", got)
	}
	if got := sessionCount(t, store, resB.User.ID); got != 1 {
		t.Fatalf("sessions = %d, want exactly 1 — only B authenticated", got)
	}
}

// --- rung 2: the linking policy --------------------------------------------

// TestSignInWithLinksWhenBothSidesAreVerified is the positive control for
// the two attack tests below: with the provider asserting a verified address
// AND the local account already verified, LinkVerified links and signs in.
// Without this, a SignInWith that refused everything would pass both attack
// tests while being useless.
func TestSignInWithLinksWhenBothSidesAreVerified(t *testing.T) {
	svc, store, ids := newOAuthService(t)
	ctx := context.Background()
	user := signUpVerified(t, svc, "zara@example.com", validPassword)

	res, err := svc.SignInWith(ctx, signInReq(googleExt("zara@example.com", true)))
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if res.Created {
		t.Fatalf("Created = true, want false — the account already existed")
	}
	if res.User.ID != user.ID {
		t.Fatalf("user = %q, want the existing account %q", res.User.ID, user.ID)
	}
	if res.User.PasswordHash != "" {
		t.Fatalf("User.PasswordHash = %q, want it scrubbed", res.User.PasswordHash)
	}
	if got := len(identitiesOf(t, ids, user.ID)); got != 1 {
		t.Fatalf("identity rows = %d, want 1", got)
	}
	if got := sessionCount(t, store, user.ID); got != 1 {
		t.Fatalf("sessions = %d, want 1", got)
	}
}

// TestSignInWithRefusesAnUnverifiedProviderClaimingAVerifiedAccount IS the
// attack, written as a test.
//
// The attacker registers the victim's address at a provider that does not
// verify addresses (or at one that does but reports the address unverified)
// and signs in. Under a naive "the addresses match, so sign them in" the
// victim's account is handed over without the password ever being involved.
// LinkVerified requires the provider's own assertion of verification as one
// of its two halves, and this is that half.
//
// Mutation check: drop `providerVerified` from mayLink's LinkVerified case
// and this must fail.
func TestSignInWithRefusesAnUnverifiedProviderClaimingAVerifiedAccount(t *testing.T) {
	svc, store, ids := newOAuthService(t)
	ctx := context.Background()
	victim := signUpVerified(t, svc, "ada@example.com", validPassword)

	res, err := svc.SignInWith(ctx, signInReq(googleExt("ada@example.com", false)))
	if !errors.Is(err, auth.ErrLinkRequiresVerification) {
		t.Fatalf("SignInWith err = %v, want ErrLinkRequiresVerification — an unverified provider assertion must never take over a verified account", err)
	}
	assertNoTokens(t, res)
	assertNoIdentityRow(t, ids, "google", "google-subject-1")
	if got := len(identitiesOf(t, ids, victim.ID)); got != 0 {
		t.Fatalf("victim identity rows = %d, want 0 — the refusal must write nothing", got)
	}
	if got := sessionCount(t, store, victim.ID); got != 0 {
		t.Fatalf("victim sessions = %d, want 0 — the refusal must issue no session", got)
	}
}

// TestSignInWithRefusesWhenTheLocalAccountIsUnverified is the same attack
// from the other side, and the reason LinkVerified needs BOTH halves.
//
// The attacker signs up locally with the victim's address (nobody has proven
// control of it — that is what unverified means) and waits. When the real
// owner later signs in with a provider that genuinely verified the address,
// a one-sided policy would attach that identity to the ATTACKER's account:
// the real owner's provider login now lands in an account the attacker also
// holds the password to.
//
// Mutation check: drop the `u.EmailVerifiedAt != nil` half of mayLink's
// LinkVerified case and this must fail.
func TestSignInWithRefusesWhenTheLocalAccountIsUnverified(t *testing.T) {
	svc, store, ids := newOAuthService(t)
	ctx := context.Background()
	squatted := mustSignUp(t, svc, "bee@example.com", validPassword) // never verified

	res, err := svc.SignInWith(ctx, signInReq(googleExt("bee@example.com", true)))
	if !errors.Is(err, auth.ErrLinkRequiresVerification) {
		t.Fatalf("SignInWith err = %v, want ErrLinkRequiresVerification — an unverified local account must not absorb a verified identity", err)
	}
	assertNoTokens(t, res)
	assertNoIdentityRow(t, ids, "google", "google-subject-1")
	if got := len(identitiesOf(t, ids, squatted.ID)); got != 0 {
		t.Fatalf("identity rows = %d, want 0 — the refusal must write nothing", got)
	}
	if got := sessionCount(t, store, squatted.ID); got != 0 {
		t.Fatalf("sessions = %d, want 0 — the refusal must issue no session", got)
	}
}

// TestSignInWithLinkNeverRefusesEvenWhenBothAreVerified pins that LinkNever
// is a policy about the IMPLICIT link and refuses it unconditionally — the
// exact input TestSignInWithLinksWhenBothSidesAreVerified accepts under the
// default policy.
func TestSignInWithLinkNeverRefusesEvenWhenBothAreVerified(t *testing.T) {
	svc, store, ids := newOAuthService(t, auth.WithLinking(auth.LinkNever))
	ctx := context.Background()
	user := signUpVerified(t, svc, "cleo@example.com", validPassword)

	res, err := svc.SignInWith(ctx, signInReq(googleExt("cleo@example.com", true)))
	if !errors.Is(err, auth.ErrLinkRequiresVerification) {
		t.Fatalf("SignInWith err = %v, want ErrLinkRequiresVerification under LinkNever", err)
	}
	assertNoTokens(t, res)
	assertNoIdentityRow(t, ids, "google", "google-subject-1")
	if got := sessionCount(t, store, user.ID); got != 0 {
		t.Fatalf("sessions = %d, want 0", got)
	}
}

// TestSignInWithLinkNeverStillProvisions pins that LinkNever governs only
// the implicit LINK. An address nobody holds locally is not a link at all,
// so it still provisions — otherwise LinkNever would silently mean "no
// external sign-in at all", which is what WithIdentityStore's absence means.
func TestSignInWithLinkNeverStillProvisions(t *testing.T) {
	svc, _, _ := newOAuthService(t, auth.WithLinking(auth.LinkNever))
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, signInReq(googleExt("dot@example.com", true)))
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if !res.Created {
		t.Fatalf("Created = false, want true — LinkNever refuses links, not provisioning")
	}
}

// TestSignInWithLinkAlwaysLinksWhenNeitherIsVerified pins the documented
// (and documented-as-unsafe) behaviour of LinkAlways: the same input both
// attack tests refuse is accepted, on the email match alone.
func TestSignInWithLinkAlwaysLinksWhenNeitherIsVerified(t *testing.T) {
	svc, store, ids := newOAuthService(t, auth.WithLinking(auth.LinkAlways))
	ctx := context.Background()
	user := mustSignUp(t, svc, "eve@example.com", validPassword) // unverified

	res, err := svc.SignInWith(ctx, signInReq(googleExt("eve@example.com", false)))
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if res.Created {
		t.Fatalf("Created = true, want false — the account already existed")
	}
	if res.User.ID != user.ID {
		t.Fatalf("user = %q, want %q", res.User.ID, user.ID)
	}
	if got := len(identitiesOf(t, ids, user.ID)); got != 1 {
		t.Fatalf("identity rows = %d, want 1", got)
	}
	if got := sessionCount(t, store, user.ID); got != 1 {
		t.Fatalf("sessions = %d, want 1", got)
	}
}

// TestSignInWithLinkAlwaysDoesNotVerifyTheLocalAccount pins that linking is
// not verification: LinkAlways attaches the identity but must not stamp
// EmailVerifiedAt on an account nobody proved control of. Otherwise the
// unsafe policy would additionally launder an unverified account into a
// verified one, which every other check in this package then trusts.
func TestSignInWithLinkAlwaysDoesNotVerifyTheLocalAccount(t *testing.T) {
	svc, store, _ := newOAuthService(t, auth.WithLinking(auth.LinkAlways))
	ctx := context.Background()
	user := mustSignUp(t, svc, "fay@example.com", validPassword)

	if _, err := svc.SignInWith(ctx, signInReq(googleExt("fay@example.com", true))); err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	stored, err := store.FindUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v, want nil — linking an identity certifies nothing about the local address", stored.EmailVerifiedAt)
	}
}

// --- rung 2: resolving the address -----------------------------------------

// TestSignInWithRequiresAnEmail pins ErrEmailRequired and, more importantly,
// that the refusal writes nothing. users.email is unique, so provisioning on
// an empty address would create one account that every later address-less
// provider then collides with — or, worse, signs in as.
func TestSignInWithRequiresAnEmail(t *testing.T) {
	cases := []struct {
		name          string
		email         string
		fallbackEmail string
	}{
		{"both empty", "", ""},
		{"both whitespace", "   ", "\t\n "},
		{"provider empty, fallback whitespace", "", "  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, store, ids := newOAuthService(t)
			ctx := context.Background()

			res, err := svc.SignInWith(ctx, auth.SignInRequest{
				Identity:      googleExt(tc.email, true),
				FallbackEmail: tc.fallbackEmail,
				IP:            "198.51.100.7",
			})
			if !errors.Is(err, auth.ErrEmailRequired) {
				t.Fatalf("SignInWith err = %v, want ErrEmailRequired", err)
			}
			assertNoTokens(t, res)
			assertNoIdentityRow(t, ids, "google", "google-subject-1")
			if _, err := store.FindUserByEmail(ctx, ""); !errors.Is(err, auth.ErrUserNotFound) {
				t.Fatalf("FindUserByEmail(\"\") err = %v, want ErrUserNotFound — nothing may be provisioned on an empty address", err)
			}
		})
	}
}

// TestSignInWithUsesTheFallbackEmail pins the GitHub-with-a-private-address
// case: the provider returns no address, the application supplies one, and
// provisioning proceeds on it.
func TestSignInWithUsesTheFallbackEmail(t *testing.T) {
	svc, store, ids := newOAuthService(t)
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, auth.SignInRequest{
		Identity:      auth.ExternalIdentity{Provider: "github", Subject: "gh-42"},
		FallbackEmail: " Gus@Example.com ",
		IP:            "198.51.100.7",
	})
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if !res.Created || res.User.Email != "gus@example.com" {
		t.Fatalf("res = %+v, want a provisioned account at the normalized fallback address", res)
	}
	if _, err := store.FindUserByEmail(ctx, "gus@example.com"); err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}

	list := identitiesOf(t, ids, res.User.ID)
	if len(list) != 1 {
		t.Fatalf("identity rows = %d, want 1", len(list))
	}
	if list[0].Email != "" {
		t.Fatalf("identity Email = %q, want empty — Identity.Email records what the PROVIDER asserted, and it asserted nothing", list[0].Email)
	}
}

// TestSignInWithNeverTreatsAFallbackEmailAsVerified pins the security half
// of FallbackEmail: it is the application's own value, unverified by
// construction, and EmailVerified is a claim about the address the provider
// RETURNED — which here is no address at all.
//
// Carrying EmailVerified over to a fallback address would reopen the whole
// attack this ladder exists to stop, with one extra step: the attacker
// registers any account at a verifying provider, supplies the victim's
// address as the fallback, and the provider's verification of a completely
// different address is credited to it.
func TestSignInWithNeverTreatsAFallbackEmailAsVerified(t *testing.T) {
	t.Run("provisioning leaves the account unverified", func(t *testing.T) {
		svc, store, _ := newOAuthService(t)
		ctx := context.Background()

		res, err := svc.SignInWith(ctx, auth.SignInRequest{
			Identity:      auth.ExternalIdentity{Provider: "github", Subject: "gh-43", EmailVerified: true},
			FallbackEmail: "hana@example.com",
			IP:            "198.51.100.7",
		})
		if err != nil {
			t.Fatalf("SignInWith: %v", err)
		}
		stored, err := store.FindUserByID(ctx, res.User.ID)
		if err != nil {
			t.Fatalf("FindUserByID: %v", err)
		}
		if stored.EmailVerifiedAt != nil {
			t.Fatalf("EmailVerifiedAt = %v, want nil — the provider verified no address here", stored.EmailVerifiedAt)
		}
	})

	t.Run("linking to an existing verified account is refused", func(t *testing.T) {
		svc, store, ids := newOAuthService(t)
		ctx := context.Background()
		victim := signUpVerified(t, svc, "iris@example.com", validPassword)

		res, err := svc.SignInWith(ctx, auth.SignInRequest{
			Identity:      auth.ExternalIdentity{Provider: "github", Subject: "gh-44", EmailVerified: true},
			FallbackEmail: "iris@example.com",
			IP:            "198.51.100.7",
		})
		if !errors.Is(err, auth.ErrLinkRequiresVerification) {
			t.Fatalf("SignInWith err = %v, want ErrLinkRequiresVerification", err)
		}
		assertNoTokens(t, res)
		assertNoIdentityRow(t, ids, "github", "gh-44")
		if got := sessionCount(t, store, victim.ID); got != 0 {
			t.Fatalf("victim sessions = %d, want 0", got)
		}
	})
}

// TestSignInWithPrefersTheProviderAddressOverTheFallback pins that the
// fallback is a fallback: when the provider DID return an address, that is
// the one the ladder resolves on, and the application's value is ignored
// rather than silently overriding it.
func TestSignInWithPrefersTheProviderAddressOverTheFallback(t *testing.T) {
	svc, store, _ := newOAuthService(t)
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, auth.SignInRequest{
		Identity:      googleExt("jo@example.com", true),
		FallbackEmail: "not-jo@example.com",
		IP:            "198.51.100.7",
	})
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if res.User.Email != "jo@example.com" {
		t.Fatalf("User.Email = %q, want the provider's address", res.User.Email)
	}
	if _, err := store.FindUserByEmail(ctx, "not-jo@example.com"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail(fallback) err = %v, want ErrUserNotFound", err)
	}
}

// --- what SignInWith deliberately does NOT do ------------------------------

// TestSignInWithDoesNotConsultTheLoginRateLimiter pins a deliberate
// difference from Login, so it cannot be mistaken for an oversight: the
// [RateLimiter] exists to slow password GUESSING, and SignInWith accepts no
// guessable secret. A limiter set to deny everything does not affect it, and
// is not even consulted.
func TestSignInWithDoesNotConsultTheLoginRateLimiter(t *testing.T) {
	limiter := &fakeLimiter{allow: false}
	svc, _, _ := newOAuthService(t, auth.WithRateLimiter(limiter))
	ctx := context.Background()

	if _, err := svc.SignInWith(ctx, signInReq(googleExt("kim@example.com", true))); err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	if got := limiter.callCount(); got != 0 {
		t.Fatalf("limiter consulted %d times, want 0", got)
	}
}

// TestSignInWithAcceptsAnEmptyIP pins the second deliberate difference from
// Login, which rejects an empty ip with ErrMissingIP because a blank one
// would make every such caller share a single rate-limit bucket. SignInWith
// consults no limiter, so ip is purely the audit field SignInRequest says it
// is, and an application behind a proxy that cannot supply one still works.
func TestSignInWithAcceptsAnEmptyIP(t *testing.T) {
	svc, store, _ := newOAuthService(t)
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, auth.SignInRequest{Identity: googleExt("lena@example.com", true)})
	if err != nil {
		t.Fatalf("SignInWith err = %v, want success with no ip", err)
	}
	sess, err := store.FindSessionByHash(ctx, token.HashOpaque(res.RefreshToken))
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if sess.IP != "" {
		t.Fatalf("session.IP = %q, want the empty value it was given", sess.IP)
	}
}

// TestSignInWithIgnoresRequireVerifiedEmail pins a KNOWN, deliberate
// consequence rather than a desirable one, so that changing it is a decision
// someone makes on purpose.
//
// WithRequireVerifiedEmail is documented as a check on Service.Login, and
// SignInWith does not apply it. On the LINK path that costs nothing —
// LinkVerified already demands the local account be verified, which is
// strictly stronger. On the PROVISIONING path it means a deployment that set
// the flag can still end up with a session for an account whose address
// nobody proved control of, when the provider reports the address
// unverified. Nobody else holds that address (the lookup missed), so it is
// not a takeover; it is an inconsistency between two policies, and the
// remedy available today is to configure only providers that report
// verification honestly.
func TestSignInWithIgnoresRequireVerifiedEmail(t *testing.T) {
	svc, _, _ := newOAuthService(t, auth.WithRequireVerifiedEmail(true))
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, signInReq(googleExt("mo@example.com", false)))
	if err != nil {
		t.Fatalf("SignInWith err = %v, want success — WithRequireVerifiedEmail is Login's check, not this one's", err)
	}
	if !res.Created || res.AccessToken == "" {
		t.Fatalf("res = %+v, want a provisioned account with a session", res)
	}
	// ... and the same account cannot log in with a password, which is the
	// asymmetry this test exists to make visible.
	if _, err := svc.Login(ctx, "mo@example.com", validPassword, "198.51.100.7", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login err = %v, want ErrInvalidCredentials", err)
	}
}

// TestSignInWithNeverRewritesTheIdentityEmail pins that a later sign-in does
// not update the stored Identity.Email to whatever the provider now asserts.
// The port offers no such write (TouchIdentity is its only mutation), and
// the field records what was asserted AT LINK TIME — an audit value, not a
// mirror of the provider's current state.
func TestSignInWithNeverRewritesTheIdentityEmail(t *testing.T) {
	svc, _, ids := newOAuthService(t)
	ctx := context.Background()

	first, err := svc.SignInWith(ctx, signInReq(googleExt("nell.old@example.com", true)))
	if err != nil {
		t.Fatalf("first SignInWith: %v", err)
	}
	if _, err := svc.SignInWith(ctx, signInReq(googleExt("nell.new@example.com", true))); err != nil {
		t.Fatalf("second SignInWith: %v", err)
	}

	list := identitiesOf(t, ids, first.User.ID)
	if len(list) != 1 {
		t.Fatalf("identity rows = %d, want 1", len(list))
	}
	if list[0].Email != "nell.old@example.com" {
		t.Fatalf("identity Email = %q, want the address asserted at link time", list[0].Email)
	}
}

// --- the password-less account -------------------------------------------

// TestOAuthProvisionedUserCannotLoginWithAnEmptyPassword pins the edge the
// plan calls out by name. An account provisioned by SignInWith holds
// PasswordHash == "", and "" must not be a password that opens it — the
// difference between "this account has no password" and "this account's
// password is the empty string" is the whole of its security.
func TestOAuthProvisionedUserCannotLoginWithAnEmptyPassword(t *testing.T) {
	svc, _, _ := newOAuthService(t)
	ctx := context.Background()

	if _, err := svc.SignInWith(ctx, signInReq(googleExt("opal@example.com", true))); err != nil {
		t.Fatalf("SignInWith: %v", err)
	}

	for _, attempt := range []string{"", " ", validPassword} {
		if _, err := svc.Login(ctx, "opal@example.com", attempt, "198.51.100.7", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("Login(%q) err = %v, want ErrInvalidCredentials", attempt, err)
		}
	}
}

// TestOAuthProvisionedUserCannotChangePassword pins WHY the reset flow below
// is the only route: ChangePassword requires the CURRENT password, and there
// is none to present. Every attempt — including the empty string, which is
// literally what the column holds — is refused.
func TestOAuthProvisionedUserCannotChangePassword(t *testing.T) {
	svc, _, _ := newOAuthService(t)
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, signInReq(googleExt("pearl@example.com", true)))
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}
	claims, err := token.Parse(res.AccessToken, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse: %v", err)
	}

	for _, current := range []string{"", validPassword} {
		err := svc.ChangePassword(ctx, res.User.ID, claims.SessionID, current, "Brand-New-Pass-9!")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("ChangePassword(current=%q) err = %v, want ErrInvalidCredentials", current, err)
		}
	}
}

// TestOAuthProvisionedUserGetsAPasswordThroughTheResetFlow pins the recovery
// path an OAuth-provisioned account depends on, end to end:
// RequestPasswordReset -> ResetPassword -> Login. It is the ONLY route to a
// first password today (see the test above), so a regression here would
// strand every such account on the provider forever, with no way to log in
// if that provider is lost — and nothing else in the suite would notice.
func TestOAuthProvisionedUserGetsAPasswordThroughTheResetFlow(t *testing.T) {
	svc, store, _ := newOAuthService(t)
	ctx := context.Background()

	res, err := svc.SignInWith(ctx, signInReq(googleExt("rae@example.com", true)))
	if err != nil {
		t.Fatalf("SignInWith: %v", err)
	}

	tok, ok, err := svc.RequestPasswordReset(ctx, "rae@example.com", "198.51.100.7")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v — a password-less account must still be able to request one", ok, err)
	}

	const firstPassword = "First-Password-Ever-4!"
	if err := svc.ResetPassword(ctx, tok, firstPassword); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	login, err := svc.Login(ctx, "rae@example.com", firstPassword, "198.51.100.7", "after-reset")
	if err != nil {
		t.Fatalf("Login after reset: %v", err)
	}
	if login.User.ID != res.User.ID {
		t.Fatalf("Login user = %q, want the OAuth-provisioned account %q", login.User.ID, res.User.ID)
	}

	stored, err := store.FindUserByID(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if stored.PasswordHash == "" {
		t.Fatalf("PasswordHash still empty after a completed reset")
	}

	// And the external identity still works: acquiring a password does not
	// unlink anything.
	again, err := svc.SignInWith(ctx, signInReq(googleExt("rae@example.com", true)))
	if err != nil {
		t.Fatalf("SignInWith after reset: %v", err)
	}
	if again.User.ID != res.User.ID || again.Created {
		t.Fatalf("SignInWith after reset = %+v, want the same account and Created false", again)
	}
}
