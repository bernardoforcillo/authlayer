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

// hashOf is how a test looks a challenge row up directly, mirroring what the
// service stores: the challenge itself is not a secret, but it is persisted
// only as its sha256 — see auth.Challenge.Hash.
func hashOf(plainChallenge string) string { return token.HashOpaque(plainChallenge) }

// --- fixtures shared by the passkey suite ----------------------------------

// newPasskeyService builds a Service over fresh in-memory auth AND credential
// stores. Everything else matches newTestService (fast hasher, fixed signing
// key); opts are applied after the credential store is wired, so a test may
// still override it with a double of its own.
func newPasskeyService(t *testing.T, opts ...auth.Option) (*auth.Service, *memory.AuthStore, *memory.CredentialStore) {
	t.Helper()
	creds := memory.NewCredentialStore()
	svc, store := newTestService(t, append([]auth.Option{auth.WithCredentialStore(creds)}, opts...)...)
	return svc, store, creds
}

// credID returns credential-id bytes distinct per label, including a byte
// outside the printable range so a test that accidentally round-trips them
// through a string conversion is caught here rather than in store/drops.
func credID(label byte) []byte { return []byte{0x00, 0xff, label, 0x7f} }

// pubKey stands in for the COSE_Key bytes a real verifier would extract. This
// package never parses it, which is exactly why an arbitrary blob is a
// faithful fixture.
func pubKey(label byte) []byte { return []byte{0xa5, 0x01, 0x02, label} }

// registerPasskey runs a whole registration ceremony for userID — begin, then
// finish with the challenge just minted — and returns the stored credential.
// It is the "the application's verifier said yes" path every login test needs
// to have happened first.
//
// It passes an EMPTY currentSessionID, which is correct for an account with
// no confirmed second factor: [auth.Service.RequireFreshMFA] is a documented
// no-op there. An account that HAS one needs registerPasskeyFrom and a
// session that has freshly proved the factor — see
// [auth.Service.FinishPasskeyRegistration], "It is step-up gated".
func registerPasskey(t *testing.T, svc *auth.Service, userID string, c auth.NewCredential) auth.Credential {
	t.Helper()
	return registerPasskeyFrom(t, svc, userID, "", c)
}

// registerPasskeyFrom is registerPasskey with the caller's own session id,
// for the accounts step-up actually gates.
func registerPasskeyFrom(t *testing.T, svc *auth.Service, userID, sessionID string, c auth.NewCredential) auth.Credential {
	t.Helper()
	ctx := context.Background()
	challenge, err := svc.BeginPasskeyRegistration(ctx, userID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration(%q): %v", userID, err)
	}
	c.Challenge = challenge
	stored, err := svc.FinishPasskeyRegistration(ctx, userID, sessionID, c)
	if err != nil {
		t.Fatalf("FinishPasskeyRegistration(%q): %v", userID, err)
	}
	return stored
}

// newCred is the ordinary NewCredential a verifier produces: a distinct
// credential id and key, and a zero baseline counter, which is what most
// platform authenticators actually report.
func newCred(label byte) auth.NewCredential {
	return auth.NewCredential{
		CredentialID: credID(label),
		PublicKey:    pubKey(label),
		Transports:   "internal,hybrid",
		Label:        "test authenticator",
	}
}

// mustBeginLogin mints a login challenge and fails the test if it cannot.
func mustBeginLogin(t *testing.T, svc *auth.Service) string {
	t.Helper()
	challenge, err := svc.BeginPasskeyLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginPasskeyLogin: %v", err)
	}
	return challenge
}

// assertNoLoginResult pins that a REFUSED FinishPasskeyLogin handed back
// nothing at all. An error return that still carried tokens would be an
// authentication bypass wearing an error's clothes, and every refusal test
// below asserts it.
func assertNoLoginResult(t *testing.T, res auth.LoginResult) {
	t.Helper()
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("refused FinishPasskeyLogin returned tokens: access=%q refresh=%q", res.AccessToken, res.RefreshToken)
	}
	if res.User.ID != "" {
		t.Fatalf("refused FinishPasskeyLogin returned a user: %+v", res.User)
	}
}

// credentialsOf returns userID's stored credential rows.
func credentialsOf(t *testing.T, creds auth.CredentialStore, userID string) []auth.Credential {
	t.Helper()
	rows, err := creds.ListCredentialsByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListCredentialsByUser(%q): %v", userID, err)
	}
	return rows
}

// --- the port must be configured -------------------------------------------

// TestPasskeyEntryPointsRefuseWithoutACredentialStore pins that the optional
// port being absent is an ordinary typed refusal at every entry point, not a
// nil dereference somewhere down the ladder. It is the same guarantee
// TestSignInWithRefusesWithoutAnIdentityStore makes for the identity port.
func TestPasskeyEntryPointsRefuseWithoutACredentialStore(t *testing.T) {
	svc, _ := newTestService(t) // no WithCredentialStore
	u := mustSignUp(t, svc, "nils@example.com", validPassword)
	ctx := context.Background()

	if _, err := svc.BeginPasskeyRegistration(ctx, u.ID); !errors.Is(err, auth.ErrPasskeysNotConfigured) {
		t.Errorf("BeginPasskeyRegistration err = %v, want ErrPasskeysNotConfigured", err)
	}
	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", newCred('a')); !errors.Is(err, auth.ErrPasskeysNotConfigured) {
		t.Errorf("FinishPasskeyRegistration err = %v, want ErrPasskeysNotConfigured", err)
	}
	if _, err := svc.BeginPasskeyLogin(ctx); !errors.Is(err, auth.ErrPasskeysNotConfigured) {
		t.Errorf("BeginPasskeyLogin err = %v, want ErrPasskeysNotConfigured", err)
	}
	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{CredentialID: credID('a')}, "203.0.113.4", "agent")
	if !errors.Is(err, auth.ErrPasskeysNotConfigured) {
		t.Errorf("FinishPasskeyLogin err = %v, want ErrPasskeysNotConfigured", err)
	}
	assertNoLoginResult(t, res)
	if _, err := svc.ListPasskeys(ctx, u.ID); !errors.Is(err, auth.ErrPasskeysNotConfigured) {
		t.Errorf("ListPasskeys err = %v, want ErrPasskeysNotConfigured", err)
	}
	if err := svc.DeletePasskey(ctx, u.ID, "some-row"); !errors.Is(err, auth.ErrPasskeysNotConfigured) {
		t.Errorf("DeletePasskey err = %v, want ErrPasskeysNotConfigured", err)
	}
}

// --- registration ----------------------------------------------------------

// TestRegisterThenLoginWithAPasskey is the positive control for every refusal
// test below: a full ceremony pair produces a stored credential and then a
// live session. Without it, an implementation that refused everything would
// pass the whole rest of this file.
func TestRegisterThenLoginWithAPasskey(t *testing.T) {
	svc, store, creds := newPasskeyService(t)
	u := mustSignUp(t, svc, "aiko@example.com", validPassword)
	ctx := context.Background()

	stored := registerPasskey(t, svc, u.ID, newCred('a'))
	if stored.ID == "" {
		t.Fatalf("stored credential has no surrogate ID")
	}
	if stored.UserID != u.ID {
		t.Fatalf("stored.UserID = %q, want %q", stored.UserID, u.ID)
	}
	if string(stored.PublicKey) != string(pubKey('a')) {
		t.Fatalf("stored.PublicKey = %x, want %x — the key is stored verbatim and unparsed", stored.PublicKey, pubKey('a'))
	}
	if stored.LastUsedAt != nil {
		t.Fatalf("stored.LastUsedAt = %v, want nil — registering is not using", stored.LastUsedAt)
	}

	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    mustBeginLogin(t, svc),
		CredentialID: credID('a'),
		SignCount:    1,
	}, "203.0.113.7", "passkey-agent")
	if err != nil {
		t.Fatalf("FinishPasskeyLogin: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("FinishPasskeyLogin returned no tokens: %+v", res)
	}
	if res.User.ID != u.ID {
		t.Fatalf("logged in as %q, want %q — the credential row IS the resolution path", res.User.ID, u.ID)
	}
	if res.User.PasswordHash != "" {
		t.Fatalf("LoginResult.User carries a live PasswordHash")
	}
	if got := sessionCount(t, store, u.ID); got != 1 {
		t.Fatalf("sessions = %d, want exactly 1", got)
	}

	after := credentialsOf(t, creds, u.ID)
	if len(after) != 1 {
		t.Fatalf("credential rows = %d, want 1", len(after))
	}
	if after[0].SignCount != 1 {
		t.Fatalf("SignCount = %d, want 1 — the assertion's counter must be recorded", after[0].SignCount)
	}
	if after[0].LastUsedAt == nil {
		t.Fatalf("LastUsedAt still nil after a login")
	}
}

// TestFinishPasskeyRegistrationRefusesEmptyFields pins that a NewCredential
// missing either half is refused BEFORE any store is touched. An empty
// credential id is not a harmless miss — it is a key every empty-id row
// collides on, and the first one written is what every later empty-id login
// resolves to.
func TestFinishPasskeyRegistrationRefusesEmptyFields(t *testing.T) {
	svc, _, creds := newPasskeyService(t)
	u := mustSignUp(t, svc, "bram@example.com", validPassword)
	ctx := context.Background()
	challenge, err := svc.BeginPasskeyRegistration(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}

	noID := newCred('a')
	noID.Challenge = challenge
	noID.CredentialID = nil
	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", noID); !errors.Is(err, auth.ErrCredentialIDRequired) {
		t.Errorf("empty CredentialID err = %v, want ErrCredentialIDRequired", err)
	}

	noKey := newCred('a')
	noKey.Challenge = challenge
	noKey.PublicKey = nil
	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", noKey); !errors.Is(err, auth.ErrPublicKeyRequired) {
		t.Errorf("empty PublicKey err = %v, want ErrPublicKeyRequired", err)
	}

	if got := len(credentialsOf(t, creds, u.ID)); got != 0 {
		t.Fatalf("credential rows = %d, want 0 — a refused registration must store nothing", got)
	}
	// Neither refusal may have burned the ceremony: both were decided before
	// the claim, so the user's live challenge is still there to complete.
	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", auth.NewCredential{
		Challenge:    challenge,
		CredentialID: credID('a'),
		PublicKey:    pubKey('a'),
	}); err != nil {
		t.Fatalf("FinishPasskeyRegistration after two malformed attempts: %v — the challenge must survive them", err)
	}
}

// TestFinishPasskeyRegistrationRefusesACredentialAlreadyRegistered pins the
// uniqueness MUST at the service boundary: one authenticator credential maps
// to exactly one account, forever. Without it a login resolving that
// credential id lands on whichever row the backend returns first — one
// passkey signing in as either of two people, decided by row order.
func TestFinishPasskeyRegistrationRefusesACredentialAlreadyRegistered(t *testing.T) {
	svc, _, creds := newPasskeyService(t)
	owner := mustSignUp(t, svc, "cleo@example.com", validPassword)
	attacker := mustSignUp(t, svc, "dax@example.com", validPassword)
	ctx := context.Background()

	registerPasskey(t, svc, owner.ID, newCred('a'))

	// The attacker names the SAME authenticator credential id, on their own
	// account, with their own ceremony and their own key.
	stolen := newCred('a')
	stolen.PublicKey = pubKey('z')
	challenge, err := svc.BeginPasskeyRegistration(ctx, attacker.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	stolen.Challenge = challenge
	if _, err := svc.FinishPasskeyRegistration(ctx, attacker.ID, "", stolen); !errors.Is(err, auth.ErrCredentialRegistered) {
		t.Fatalf("second registration of the same credential id = %v, want ErrCredentialRegistered", err)
	}

	if got := len(credentialsOf(t, creds, attacker.ID)); got != 0 {
		t.Fatalf("attacker credential rows = %d, want 0", got)
	}
	held, err := creds.FindCredentialByCredentialID(ctx, credID('a'))
	if err != nil {
		t.Fatalf("FindCredentialByCredentialID: %v", err)
	}
	if held.UserID != owner.ID {
		t.Fatalf("credential now belongs to %q, want the original owner %q — a row is never re-pointed", held.UserID, owner.ID)
	}
	if string(held.PublicKey) != string(pubKey('a')) {
		t.Fatalf("PublicKey was overwritten: %x", held.PublicKey)
	}
}

// TestFinishPasskeyRegistrationRefusesAnotherAccountsChallenge pins
// ErrChallengeUser. Reaching it means the application mixed two ceremonies
// up, and the safe reading of that is not "register it against the account
// the caller named": that would attach a credential to an account whose
// ceremony never happened.
func TestFinishPasskeyRegistrationRefusesAnotherAccountsChallenge(t *testing.T) {
	svc, _, creds := newPasskeyService(t)
	victim := mustSignUp(t, svc, "eun@example.com", validPassword)
	other := mustSignUp(t, svc, "finn@example.com", validPassword)
	ctx := context.Background()

	challenge, err := svc.BeginPasskeyRegistration(ctx, victim.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	c := newCred('a')
	c.Challenge = challenge

	if _, err := svc.FinishPasskeyRegistration(ctx, other.ID, "", c); !errors.Is(err, auth.ErrChallengeUser) {
		t.Fatalf("finishing with another account's challenge = %v, want ErrChallengeUser", err)
	}
	if got := len(credentialsOf(t, creds, other.ID)); got != 0 {
		t.Fatalf("other account credential rows = %d, want 0", got)
	}
	// Refused before the claim, so the victim's own ceremony still completes.
	if _, err := svc.FinishPasskeyRegistration(ctx, victim.ID, "", c); err != nil {
		t.Fatalf("victim's own FinishPasskeyRegistration: %v — their challenge must not have been burned", err)
	}
}

// --- the ceremony-type binding ---------------------------------------------

// TestARegistrationChallengeCannotCompleteALogin is the check that keeps the
// two ceremonies separable, and it is the reason [auth.Challenge] carries a
// Ceremony at all.
//
// Any authenticated user can obtain a registration challenge for their OWN
// account, freely and repeatedly. Without this binding that challenge
// completes a LOGIN, and the only remaining question is whose credential id
// the caller names — and credential ids are not secret. So this is not a
// tidiness check on an enum; it is the difference between "a passkey signs
// its owner in" and "anyone who can start a registration signs in as anyone".
func TestARegistrationChallengeCannotCompleteALogin(t *testing.T) {
	svc, store, _ := newPasskeyService(t)
	victim := mustSignUp(t, svc, "gwen@example.com", validPassword)
	attacker := mustSignUp(t, svc, "hugo@example.com", validPassword)
	ctx := context.Background()

	registerPasskey(t, svc, victim.ID, newCred('a'))

	// The attacker begins a registration on their OWN account — a thing they
	// are entitled to do — and presents that challenge to a login naming the
	// victim's credential id.
	registration, err := svc.BeginPasskeyRegistration(ctx, attacker.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}

	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    registration,
		CredentialID: credID('a'),
		SignCount:    1,
	}, "203.0.113.66", "attacker-agent")
	if !errors.Is(err, auth.ErrChallengeCeremony) {
		t.Fatalf("login with a registration challenge = %v, want ErrChallengeCeremony", err)
	}
	assertNoLoginResult(t, res)
	if got := sessionCount(t, store, victim.ID); got != 0 {
		t.Fatalf("victim sessions = %d, want 0", got)
	}
	if got := sessionCount(t, store, attacker.ID); got != 0 {
		t.Fatalf("attacker sessions = %d, want 0", got)
	}
}

// TestALoginChallengeCannotCompleteARegistration is the same binding read in
// the other direction. A login challenge is obtainable by ANYONE — the
// endpoint is unauthenticated — so if it completed a registration, the only
// thing standing between an unauthenticated caller and a credential on
// somebody's account would be the userID argument.
func TestALoginChallengeCannotCompleteARegistration(t *testing.T) {
	svc, _, creds := newPasskeyService(t)
	u := mustSignUp(t, svc, "iris@example.com", validPassword)
	ctx := context.Background()

	c := newCred('a')
	c.Challenge = mustBeginLogin(t, svc)

	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", c); !errors.Is(err, auth.ErrChallengeCeremony) {
		t.Fatalf("registration with a login challenge = %v, want ErrChallengeCeremony", err)
	}
	if got := len(credentialsOf(t, creds, u.ID)); got != 0 {
		t.Fatalf("credential rows = %d, want 0", got)
	}
}

// --- single use, expiry, and the burn ---------------------------------------

// TestPasskeyChallengesAreSingleUse pins that a challenge is claimed exactly
// once, in both ceremonies. For a zero-counter authenticator this burn is the
// ONLY replay protection that exists — the signature counter cannot help — so
// a second presentation of the same assertion must find nothing to claim.
func TestPasskeyChallengesAreSingleUse(t *testing.T) {
	svc, store, creds := newPasskeyService(t)
	u := mustSignUp(t, svc, "jonas@example.com", validPassword)
	ctx := context.Background()

	// Registration.
	regChallenge, err := svc.BeginPasskeyRegistration(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	first := newCred('a')
	first.Challenge = regChallenge
	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", first); err != nil {
		t.Fatalf("first FinishPasskeyRegistration: %v", err)
	}
	second := newCred('b')
	second.Challenge = regChallenge
	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", second); !errors.Is(err, auth.ErrChallengeNotFound) {
		t.Fatalf("reusing a registration challenge = %v, want ErrChallengeNotFound", err)
	}
	if got := len(credentialsOf(t, creds, u.ID)); got != 1 {
		t.Fatalf("credential rows = %d, want 1 — one ceremony, one credential", got)
	}

	// Login.
	loginChallenge := mustBeginLogin(t, svc)
	assertion := auth.VerifiedAssertion{Challenge: loginChallenge, CredentialID: credID('a'), SignCount: 1}
	if _, err := svc.FinishPasskeyLogin(ctx, assertion, "203.0.113.8", "agent"); err != nil {
		t.Fatalf("first FinishPasskeyLogin: %v", err)
	}
	replay := assertion
	replay.SignCount = 2 // even with an honest, increasing counter
	res, err := svc.FinishPasskeyLogin(ctx, replay, "203.0.113.8", "agent")
	if !errors.Is(err, auth.ErrChallengeNotFound) {
		t.Fatalf("reusing a login challenge = %v, want ErrChallengeNotFound", err)
	}
	assertNoLoginResult(t, res)
	if got := sessionCount(t, store, u.ID); got != 1 {
		t.Fatalf("sessions = %d, want exactly 1", got)
	}
}

// failingSessionStore delegates to a real AuthStore but fails every
// CreateSession. It stands in for the store outage that can strike between
// the challenge burn and the session write, which is the one window that
// tells claim-before-apply apart from apply-before-claim on a SEQUENTIAL
// path — see TestFinishPasskeyLoginBurnsTheChallengeEvenWhenTheMintFails.
type failingSessionStore struct {
	*memory.AuthStore
	fail atomic.Bool
}

var errSessionOutage = errors.New("session store is down")

func (s *failingSessionStore) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	if s.fail.Load() {
		return auth.Session{}, errSessionOutage
	}
	return s.AuthStore.CreateSession(ctx, sess)
}

// TestFinishPasskeyLoginBurnsTheChallengeEvenWhenTheMintFails is the
// single-use property in the case that actually distinguishes the two
// orderings on a sequential path.
//
// The challenge is claimed BEFORE anything is issued, so a failure in the
// session mint that follows leaves the challenge burned and no session
// issued: the ceremony is not retryable and the application must begin
// another. That is the deliberate direction — under-granting rather than
// leaving a claimed one-time value live for a second presentation.
//
// An implementation that minted first and burned afterwards returns the same
// error from the first call, but leaves the challenge claimable, so the
// retry below SUCCEEDS. That is the whole point of this test.
func TestFinishPasskeyLoginBurnsTheChallengeEvenWhenTheMintFails(t *testing.T) {
	inner := memory.NewAuthStore()
	store := &failingSessionStore{AuthStore: inner}
	creds := memory.NewCredentialStore()
	svc := auth.New(store, auth.WithHasher(newSpyHasher()), auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute), auth.WithCredentialStore(creds))
	ctx := context.Background()

	u := mustSignUp(t, svc, "kai@example.com", validPassword)
	registerPasskey(t, svc, u.ID, newCred('a'))

	challenge := mustBeginLogin(t, svc)
	store.fail.Store(true)
	assertion := auth.VerifiedAssertion{Challenge: challenge, CredentialID: credID('a'), SignCount: 1}
	if _, err := svc.FinishPasskeyLogin(ctx, assertion, "203.0.113.9", "agent"); !errors.Is(err, errSessionOutage) {
		t.Fatalf("FinishPasskeyLogin during a session outage = %v, want the store error propagated", err)
	}

	// The outage clears. The same challenge must be gone regardless.
	store.fail.Store(false)
	retry := assertion
	retry.SignCount = 2
	res, err := svc.FinishPasskeyLogin(ctx, retry, "203.0.113.9", "agent")
	if !errors.Is(err, auth.ErrChallengeNotFound) {
		t.Fatalf("retrying the same challenge = %v, want ErrChallengeNotFound — the claim ran before the mint", err)
	}
	assertNoLoginResult(t, res)
	if got := sessionCount(t, inner, u.ID); got != 0 {
		t.Fatalf("sessions = %d, want 0", got)
	}
}

// TestPasskeyChallengesExpire pins that a challenge past its TTL is refused,
// in both ceremonies, and that the refusal happens BEFORE the claim — an
// expired challenge is already unusable, and the row is the PurgeExpired
// janitor's business rather than something an attempt should burn.
func TestPasskeyChallengesExpire(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc, _, creds := newPasskeyService(t,
		auth.WithClock(func() time.Time { return clock() }),
		auth.WithPasskeyChallengeTTL(5*time.Minute),
	)
	u := mustSignUp(t, svc, "lena@example.com", validPassword)
	ctx := context.Background()

	// A registered credential, so the login below reaches the challenge check
	// rather than stopping at credential resolution — which runs first, so a
	// stale credential id cannot burn a live ceremony.
	registerPasskey(t, svc, u.ID, newCred('a'))

	regChallenge, err := svc.BeginPasskeyRegistration(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	loginChallenge := mustBeginLogin(t, svc)

	// Exactly at ExpiresAt: not before it, so already unusable.
	now = now.Add(5 * time.Minute)

	c := newCred('b')
	c.Challenge = regChallenge
	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", c); !errors.Is(err, auth.ErrChallengeExpired) {
		t.Fatalf("expired registration challenge = %v, want ErrChallengeExpired", err)
	}
	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    loginChallenge,
		CredentialID: credID('a'),
		SignCount:    1,
	}, "203.0.113.10", "agent")
	if !errors.Is(err, auth.ErrChallengeExpired) {
		t.Fatalf("expired login challenge = %v, want ErrChallengeExpired", err)
	}
	assertNoLoginResult(t, res)

	// Neither attempt burned its row: the janitor is what removes them.
	if _, err := creds.FindChallengeByHash(ctx, hashOf(regChallenge)); err != nil {
		t.Fatalf("registration challenge row is gone: %v — an expired challenge must not be burned by the attempt", err)
	}
	if _, err := creds.FindChallengeByHash(ctx, hashOf(loginChallenge)); err != nil {
		t.Fatalf("login challenge row is gone: %v", err)
	}
}

// TestPurgeExpiredRemovesCeremonyChallenges pins the janitor that bounds the
// challenge table. BeginPasskeyLogin is unauthenticated and writes a row per
// call with no limiter of its own, so this is the only thing keeping that
// table finite.
func TestPurgeExpiredRemovesCeremonyChallenges(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc, _, creds := newPasskeyService(t,
		auth.WithClock(func() time.Time { return clock() }),
		auth.WithPasskeyChallengeTTL(5*time.Minute),
	)
	ctx := context.Background()

	stale := mustBeginLogin(t, svc)
	now = now.Add(10 * time.Minute)
	live := mustBeginLogin(t, svc)

	n, err := svc.PurgeExpired(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("PurgeExpired removed %d rows, want 1 — the expired challenge and nothing else", n)
	}
	if _, err := creds.FindChallengeByHash(ctx, hashOf(stale)); !errors.Is(err, auth.ErrChallengeNotFound) {
		t.Fatalf("expired challenge survived the purge: %v", err)
	}
	if _, err := creds.FindChallengeByHash(ctx, hashOf(live)); err != nil {
		t.Fatalf("live challenge was purged: %v", err)
	}
}

// --- the signature counter, the only clone detection ------------------------

// TestFinishPasskeyLoginRefusesANonIncreasingSignCount is the clone check,
// and it is the one behaviour in this file that no other layer can supply.
//
// An authenticator that maintains a counter increments it on every assertion,
// so a value at or below the stored one means the assertion came from
// something that is not the authenticator's current state: WebAuthn defines
// that as the signal for a CLONED authenticator, and it is also what a
// replayed assertion produces. A refused counter must refuse the LOGIN, with
// its own sentinel — recording the counter and signing the user in anyway
// would be a control that is documented and not there.
func TestFinishPasskeyLoginRefusesANonIncreasingSignCount(t *testing.T) {
	svc, store, creds := newPasskeyService(t)
	u := mustSignUp(t, svc, "mira@example.com", validPassword)
	ctx := context.Background()

	c := newCred('a')
	c.SignCount = 10 // a real, counter-maintaining authenticator
	registerPasskey(t, svc, u.ID, c)

	for _, tc := range []struct {
		name      string
		signCount uint32
	}{
		{"lower than the stored counter — the clone has fallen behind", 9},
		{"equal to the stored counter — a replay, or a clone in lockstep", 10},
		{"zero against a non-zero stored counter — a decrease, not a counter-less authenticator", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
				Challenge:    mustBeginLogin(t, svc),
				CredentialID: credID('a'),
				SignCount:    tc.signCount,
			}, "203.0.113.11", "agent")
			if !errors.Is(err, auth.ErrClonedAuthenticator) {
				t.Fatalf("FinishPasskeyLogin(count=%d) err = %v, want ErrClonedAuthenticator", tc.signCount, err)
			}
			assertNoLoginResult(t, res)
			if got := sessionCount(t, store, u.ID); got != 0 {
				t.Fatalf("sessions = %d, want 0 — a suspected clone must be issued nothing", got)
			}
			rows := credentialsOf(t, creds, u.ID)
			if rows[0].SignCount != 10 {
				t.Fatalf("stored SignCount = %d, want 10 — a refused counter must not be written", rows[0].SignCount)
			}
			if rows[0].LastUsedAt != nil {
				t.Fatalf("LastUsedAt was stamped by a refused login")
			}
		})
	}

	// The positive control: an honest increase still works, so the test above
	// is not passing because logins are broken outright.
	if _, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    mustBeginLogin(t, svc),
		CredentialID: credID('a'),
		SignCount:    11,
	}, "203.0.113.11", "agent"); err != nil {
		t.Fatalf("FinishPasskeyLogin(count=11): %v — an increasing counter must be accepted", err)
	}
	if got := credentialsOf(t, creds, u.ID)[0].SignCount; got != 11 {
		t.Fatalf("stored SignCount = %d, want 11", got)
	}
}

// TestFinishPasskeyLoginAcceptsACounterLessAuthenticator pins the one
// documented exception, which is a WebAuthn rule rather than a convenience:
// an authenticator reporting zero against a stored zero does not maintain a
// counter at all. Most platform passkeys, and everything synced through a
// credential manager, are in this category. Applying the compare-and-set to
// them would refuse every login after the first — locking out most of the
// world's passkeys — so the service calls TouchCredential instead.
func TestFinishPasskeyLoginAcceptsACounterLessAuthenticator(t *testing.T) {
	svc, store, creds := newPasskeyService(t)
	u := mustSignUp(t, svc, "noor@example.com", validPassword)
	ctx := context.Background()

	registerPasskey(t, svc, u.ID, newCred('a')) // SignCount 0

	for i := range 3 {
		if _, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
			Challenge:    mustBeginLogin(t, svc),
			CredentialID: credID('a'),
			SignCount:    0,
		}, "203.0.113.12", "agent"); err != nil {
			t.Fatalf("login %d with a zero counter: %v — a counter-less authenticator must not be read as a clone", i+1, err)
		}
	}
	if got := sessionCount(t, store, u.ID); got != 3 {
		t.Fatalf("sessions = %d, want 3", got)
	}
	rows := credentialsOf(t, creds, u.ID)
	if rows[0].SignCount != 0 {
		t.Fatalf("SignCount = %d, want 0 — TouchCredential must not move the counter", rows[0].SignCount)
	}
	if rows[0].LastUsedAt == nil {
		t.Fatalf("LastUsedAt still nil — a counter-less login must still record a use")
	}
}

// TestFinishPasskeyLoginHoldsAZeroCounterCredentialToItOnceItMoves pins how
// narrow the exception is. A credential that starts at zero and then asserts
// a real counter is held to that counter from then on: the exception is
// "both are zero", not "zero is always fine".
func TestFinishPasskeyLoginHoldsAZeroCounterCredentialToItOnceItMoves(t *testing.T) {
	svc, _, _ := newPasskeyService(t)
	u := mustSignUp(t, svc, "otto@example.com", validPassword)
	ctx := context.Background()

	registerPasskey(t, svc, u.ID, newCred('a')) // stored 0

	if _, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    mustBeginLogin(t, svc),
		CredentialID: credID('a'),
		SignCount:    5,
	}, "203.0.113.13", "agent"); err != nil {
		t.Fatalf("0 -> 5 is an increase and must be applied: %v", err)
	}

	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    mustBeginLogin(t, svc),
		CredentialID: credID('a'),
		SignCount:    0,
	}, "203.0.113.13", "agent")
	if !errors.Is(err, auth.ErrClonedAuthenticator) {
		t.Fatalf("5 -> 0 = %v, want ErrClonedAuthenticator — a decrease is a decrease", err)
	}
	assertNoLoginResult(t, res)
}

// --- resolution and the anonymized account ----------------------------------

// TestFinishPasskeyLoginRefusesAnUnknownCredential pins that an unregistered
// credential id resolves to nothing, before any challenge is claimed — a
// caller probing credential ids must not be able to burn other people's live
// ceremonies as a side effect.
func TestFinishPasskeyLoginRefusesAnUnknownCredential(t *testing.T) {
	svc, _, creds := newPasskeyService(t)
	ctx := context.Background()

	challenge := mustBeginLogin(t, svc)
	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    challenge,
		CredentialID: credID('q'),
		SignCount:    1,
	}, "203.0.113.14", "agent")
	if !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("unknown credential id = %v, want ErrCredentialNotFound", err)
	}
	assertNoLoginResult(t, res)
	if _, err := creds.FindChallengeByHash(ctx, hashOf(challenge)); err != nil {
		t.Fatalf("challenge was burned by an unknown-credential attempt: %v", err)
	}

	// An empty credential id is refused before any store is touched at all.
	if _, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{Challenge: challenge}, "203.0.113.14", "agent"); !errors.Is(err, auth.ErrCredentialIDRequired) {
		t.Fatalf("empty credential id = %v, want ErrCredentialIDRequired", err)
	}
}

// TestPasskeyCeremoniesRefuseAnAnonymizedAccount pins the DeletedAt check on
// BOTH Finish methods, and on Begin. A non-nil DeletedAt means "no one may
// authenticate as this account, by any route": a credential row surviving
// anonymization is a fact about foreign keys, not about whether the account
// exists, and a passkey is a way in that needs no password at all.
func TestPasskeyCeremoniesRefuseAnAnonymizedAccount(t *testing.T) {
	svc, store, _ := newPasskeyService(t)
	u := mustSignUp(t, svc, "pia@example.com", validPassword)
	ctx := context.Background()

	registerPasskey(t, svc, u.ID, newCred('a'))
	// Ceremonies armed while the account was live, then the account closes.
	regChallenge, err := svc.BeginPasskeyRegistration(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	loginChallenge := mustBeginLogin(t, svc)

	if err := svc.AnonymizeAccount(ctx, u.ID, "", validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}

	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    loginChallenge,
		CredentialID: credID('a'),
		SignCount:    1,
	}, "203.0.113.15", "agent")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FinishPasskeyLogin on an anonymized account = %v, want ErrUserNotFound", err)
	}
	assertNoLoginResult(t, res)
	if got := sessionCount(t, store, u.ID); got != 0 {
		t.Fatalf("sessions = %d, want 0", got)
	}

	c := newCred('b')
	c.Challenge = regChallenge
	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", c); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FinishPasskeyRegistration on an anonymized account = %v, want ErrUserNotFound", err)
	}
	if _, err := svc.BeginPasskeyRegistration(ctx, u.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("BeginPasskeyRegistration on an anonymized account = %v, want ErrUserNotFound", err)
	}
}

// --- the deterministic concurrency control ----------------------------------

// gatedCredentialStore delegates to a real CredentialStore but parks the
// FIRST FindChallengeByHash call AFTER it has computed its answer and BEFORE
// that answer is returned. That is precisely the check-then-act window in
// both Finish methods, held open on demand: the test drives the exact
// interleaving through two channels, with no sleeps and no repeated rounds,
// so the outcome is deterministic rather than a 1-in-N chance.
//
// The shape is deliberate and this project has learned it the hard way. A
// 20-goroutine race here once PASSED against a deliberately broken
// challenge-burn ordering — closing a channel readies its waiters LIFO, and a
// fixed-role race explores essentially one interleaving. Only a park/gate
// pair proves the ordering.
//
// A counter rather than sync.Once: Once.Do blocks every other caller until
// the first invocation returns, which would deadlock the very second login
// the test needs to run while the first is parked.
//
// The gate is ARMED explicitly, because these tests must register a
// credential before they can exercise a login and that setup runs its own
// ceremonies through this same store. An always-on gate parks the setup and
// the test deadlocks with nobody left to release it.
type gatedCredentialStore struct {
	auth.CredentialStore

	armed   atomic.Bool
	finds   atomic.Int64
	parked  chan struct{}
	release chan struct{}
}

func newGatedCredentialStore(inner auth.CredentialStore) *gatedCredentialStore {
	return &gatedCredentialStore{
		CredentialStore: inner,
		parked:          make(chan struct{}),
		release:         make(chan struct{}),
	}
}

// arm makes the NEXT FindChallengeByHash the one that parks. Call it once
// setup is done and the interleaving under test is about to begin.
func (s *gatedCredentialStore) arm() { s.armed.Store(true) }

func (s *gatedCredentialStore) FindChallengeByHash(ctx context.Context, hash string) (auth.Challenge, error) {
	c, err := s.CredentialStore.FindChallengeByHash(ctx, hash)
	if s.armed.Load() && s.finds.Add(1) == 1 {
		close(s.parked)
		<-s.release
	}
	return c, err
}

// TestFinishPasskeyLoginConcurrentClaimsAdmitExactlyOneWinner is the
// deterministic control for the check-then-act window neither Finish method
// can avoid: the gap between "this challenge is live" and the claim that acts
// on it. Two callers presenting the SAME challenge can both pass the check.
//
// It is driven through the exact interleaving with a park/gate channel pair
// and no sleeps: goroutine A's lookup answers "live", then parks holding that
// answer while B runs to completion and burns the row. A then resumes into a
// world its own answer no longer describes.
//
// What must happen: the STORE refuses A's claim on DeleteChallenge's
// rows-affected gate, and FinishPasskeyLogin propagates that refusal rather
// than minting a second session. There is no lock in the service layer for
// this and there cannot be one, so the claim's atomicity is the whole
// defence, and this test is what says so out loud.
//
// The authenticator here reports a ZERO counter, deliberately, and that is
// what makes the test decisive rather than merely suggestive. A
// counter-maintaining credential has a second line of defence: the
// compare-and-set would refuse the loser even if the claim did not, so the
// test would pass for the wrong reason. A zero-counter authenticator — most
// platform passkeys, everything synced through a credential manager — has NO
// counter to fall back on, so the challenge burn is the only thing between
// one assertion and two sessions. That is precisely the claim
// FinishPasskeyLogin's "The zero counter" makes, and this is where it is
// held to it.
func TestFinishPasskeyLoginConcurrentClaimsAdmitExactlyOneWinner(t *testing.T) {
	inner := memory.NewCredentialStore()
	gated := newGatedCredentialStore(inner)
	svc, store := newTestService(t, auth.WithCredentialStore(gated))
	ctx := context.Background()

	u := mustSignUp(t, svc, "quinn@example.com", validPassword)
	registerPasskey(t, svc, u.ID, newCred('a')) // SignCount 0, and it stays 0

	// One challenge, presented twice — a forwarded assertion, a retried
	// request, a double-clicked button.
	challenge := mustBeginLogin(t, svc)
	assertion := auth.VerifiedAssertion{Challenge: challenge, CredentialID: credID('a'), SignCount: 0}

	gated.arm() // setup is done; the next lookup is the one held open

	var (
		wg   sync.WaitGroup
		resA auth.LoginResult
		errA error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resA, errA = svc.FinishPasskeyLogin(ctx, assertion, "203.0.113.16", "agent-a")
	}()

	<-gated.parked // A has read a LIVE challenge and is holding that answer.

	resB, errB := svc.FinishPasskeyLogin(ctx, assertion, "203.0.113.17", "agent-b")
	if errB != nil {
		t.Fatalf("B FinishPasskeyLogin: %v", errB)
	}
	if resB.AccessToken == "" {
		t.Fatalf("B got no tokens — B ran to completion first and must be the winner")
	}

	close(gated.release)
	wg.Wait()

	if !errors.Is(errA, auth.ErrChallengeNotFound) {
		t.Fatalf("A FinishPasskeyLogin err = %v, want ErrChallengeNotFound from the claim it lost", errA)
	}
	assertNoLoginResult(t, resA)
	if got := sessionCount(t, store, u.ID); got != 1 {
		t.Fatalf("sessions = %d, want exactly 1 — one challenge admits one login", got)
	}
}

// TestFinishPasskeyRegistrationConcurrentClaimsAdmitExactlyOneWinner is the
// same control for the registration ceremony: one challenge must produce one
// credential, not two.
func TestFinishPasskeyRegistrationConcurrentClaimsAdmitExactlyOneWinner(t *testing.T) {
	inner := memory.NewCredentialStore()
	gated := newGatedCredentialStore(inner)
	svc, _ := newTestService(t, auth.WithCredentialStore(gated))
	ctx := context.Background()

	u := mustSignUp(t, svc, "rhea@example.com", validPassword)
	challenge, err := svc.BeginPasskeyRegistration(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}

	credA := newCred('a')
	credA.Challenge = challenge
	credB := newCred('b')
	credB.Challenge = challenge

	gated.arm() // setup is done; the next lookup is the one held open

	var (
		wg   sync.WaitGroup
		errA error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, errA = svc.FinishPasskeyRegistration(ctx, u.ID, "", credA)
	}()

	<-gated.parked

	if _, err := svc.FinishPasskeyRegistration(ctx, u.ID, "", credB); err != nil {
		t.Fatalf("B FinishPasskeyRegistration: %v", err)
	}

	close(gated.release)
	wg.Wait()

	if !errors.Is(errA, auth.ErrChallengeNotFound) {
		t.Fatalf("A FinishPasskeyRegistration err = %v, want ErrChallengeNotFound", errA)
	}
	rows := credentialsOf(t, gated, u.ID)
	if len(rows) != 1 {
		t.Fatalf("credential rows = %d, want exactly 1 — one ceremony admits one credential", len(rows))
	}
	if string(rows[0].CredentialID) != string(credID('b')) {
		t.Fatalf("stored credential is %x, want B's %x", rows[0].CredentialID, credID('b'))
	}
}

// --- listing and removal ----------------------------------------------------

// TestListPasskeysIsScopedToTheUser pins that the listing is a scoped
// pass-through and never a listing of anyone else's rows, and that an account
// with none — or one that does not exist at all — is an empty answer rather
// than an error or an existence oracle.
func TestListPasskeysIsScopedToTheUser(t *testing.T) {
	svc, _, _ := newPasskeyService(t)
	mine := mustSignUp(t, svc, "sami@example.com", validPassword)
	theirs := mustSignUp(t, svc, "tova@example.com", validPassword)
	ctx := context.Background()

	registerPasskey(t, svc, mine.ID, newCred('a'))
	registerPasskey(t, svc, mine.ID, newCred('b'))
	registerPasskey(t, svc, theirs.ID, newCred('c'))

	rows, err := svc.ListPasskeys(ctx, mine.ID)
	if err != nil {
		t.Fatalf("ListPasskeys: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ListPasskeys returned %d rows, want 2", len(rows))
	}
	for _, r := range rows {
		if r.UserID != mine.ID {
			t.Fatalf("ListPasskeys returned another user's row: %+v", r)
		}
	}

	none, err := svc.ListPasskeys(ctx, "no-such-user")
	if err != nil {
		t.Fatalf("ListPasskeys(unknown user): %v — an unknown id must not be an existence oracle", err)
	}
	if len(none) != 0 {
		t.Fatalf("ListPasskeys(unknown user) returned %d rows, want 0", len(none))
	}
}

// TestDeletePasskeyRefusesTheAccountsLastWayIn is ErrLastCredential's passkey
// arm. An account with one passkey, no working password and no linked
// identity has exactly one way in, and removing it would be a permanent,
// silent lockout — nothing in this package could sign that user in again.
func TestDeletePasskeyRefusesTheAccountsLastWayIn(t *testing.T) {
	svc, store, creds := newPasskeyService(t)
	ctx := context.Background()

	// An account with NO password at all: the shape magic-link provisioning
	// and passkey-first sign-up produce.
	u, err := store.CreateUser(ctx, auth.UserBase{
		ID:        "11111111-1111-4111-8111-111111111111",
		Email:     "uma@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	only := registerPasskey(t, svc, u.ID, newCred('a'))

	if err := svc.DeletePasskey(ctx, u.ID, only.ID); !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("DeletePasskey on the only way in = %v, want ErrLastCredential", err)
	}
	if got := len(credentialsOf(t, creds, u.ID)); got != 1 {
		t.Fatalf("credential rows = %d, want 1 — a refusal must remove nothing", got)
	}

	// A second passkey makes the first removable, and then the second is the
	// last way in and is refused in its turn.
	second := registerPasskey(t, svc, u.ID, newCred('b'))
	if err := svc.DeletePasskey(ctx, u.ID, only.ID); err != nil {
		t.Fatalf("DeletePasskey with a sibling surviving: %v", err)
	}
	if err := svc.DeletePasskey(ctx, u.ID, second.ID); !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("DeletePasskey(second) = %v, want ErrLastCredential — it is now the last way in", err)
	}
}

// TestDeletePasskeyCountsTheOtherCredentialKinds pins the shared arithmetic
// from the passkey side: a working password OR a linked identity is another
// way in, so the last passkey may go.
func TestDeletePasskeyCountsTheOtherCredentialKinds(t *testing.T) {
	t.Run("a working password", func(t *testing.T) {
		svc, _, _ := newPasskeyService(t)
		u := mustSignUp(t, svc, "vera@example.com", validPassword)
		only := registerPasskey(t, svc, u.ID, newCred('a'))
		if err := svc.DeletePasskey(context.Background(), u.ID, only.ID); err != nil {
			t.Fatalf("DeletePasskey with a working password: %v — the password is another way in", err)
		}
	})

	t.Run("a password the configured policy refuses is NOT a way in", func(t *testing.T) {
		// Under WithRequireVerifiedEmail, Login refuses an unverified
		// account outright, so its stored hash opens nothing. Counting it
		// would let this remove the only door that does open.
		svc, _, _ := newPasskeyService(t, auth.WithRequireVerifiedEmail(true))
		u := mustSignUp(t, svc, "wren@example.com", validPassword) // unverified
		only := registerPasskey(t, svc, u.ID, newCred('a'))
		if err := svc.DeletePasskey(context.Background(), u.ID, only.ID); !errors.Is(err, auth.ErrLastCredential) {
			t.Fatalf("DeletePasskey = %v, want ErrLastCredential — an unverified account's password is not a way in", err)
		}
	})

	t.Run("a linked identity", func(t *testing.T) {
		ids := memory.NewIdentityStore()
		creds := memory.NewCredentialStore()
		svc, store := newTestService(t, auth.WithIdentityStore(ids), auth.WithCredentialStore(creds))
		ctx := context.Background()

		u, err := store.CreateUser(ctx, auth.UserBase{
			ID:        "22222222-2222-4222-8222-222222222222",
			Email:     "xan@example.com",
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		only := registerPasskey(t, svc, u.ID, newCred('a'))

		// No identity yet: the passkey is the only way in.
		if err := svc.DeletePasskey(ctx, u.ID, only.ID); !errors.Is(err, auth.ErrLastCredential) {
			t.Fatalf("DeletePasskey before linking = %v, want ErrLastCredential", err)
		}
		if _, err := svc.LinkIdentity(ctx, u.ID, googleExt("xan@example.com", true)); err != nil {
			t.Fatalf("LinkIdentity: %v", err)
		}
		if err := svc.DeletePasskey(ctx, u.ID, only.ID); err != nil {
			t.Fatalf("DeletePasskey after linking: %v — the identity is another way in", err)
		}
	})
}

// TestDeletePasskeyRefusesAnotherUsersCredential pins that one account cannot
// remove another's way in by naming its row id. A credential belonging to
// somebody else is not found here, ever, whether or not the id exists.
func TestDeletePasskeyRefusesAnotherUsersCredential(t *testing.T) {
	svc, _, creds := newPasskeyService(t)
	mine := mustSignUp(t, svc, "yuki@example.com", validPassword)
	theirs := mustSignUp(t, svc, "zane@example.com", validPassword)
	ctx := context.Background()

	victimRow := registerPasskey(t, svc, theirs.ID, newCred('c'))

	if err := svc.DeletePasskey(ctx, mine.ID, victimRow.ID); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("DeletePasskey naming another user's row = %v, want ErrCredentialNotFound", err)
	}
	if got := len(credentialsOf(t, creds, theirs.ID)); got != 1 {
		t.Fatalf("victim credential rows = %d, want 1 — nothing of theirs may be removed", got)
	}
	if err := svc.DeletePasskey(ctx, mine.ID, "no-such-row"); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("DeletePasskey(unknown row) = %v, want ErrCredentialNotFound", err)
	}
}

// TestDeletePasskeyDoesNotRevokeSessions pins the one place this method
// deliberately differs from UnlinkIdentity. Removing ONE credential from a
// set whose other members are, by the guard above, still working is not the
// categorical "this account is not mine any more" an unlink is, and a Session
// records no credential provenance, so a sweep here could only be
// all-or-nothing. "Removing a passkey signs you out everywhere" composes from
// LogoutAll, and the application keeps that choice.
func TestDeletePasskeyDoesNotRevokeSessions(t *testing.T) {
	svc, store, _ := newPasskeyService(t)
	u := mustSignUp(t, svc, "abel@example.com", validPassword)
	ctx := context.Background()

	doomed := registerPasskey(t, svc, u.ID, newCred('a'))
	registerPasskey(t, svc, u.ID, newCred('b'))
	mustLogin(t, svc, "abel@example.com", validPassword)
	if got := sessionCount(t, store, u.ID); got != 1 {
		t.Fatalf("sessions before = %d, want 1", got)
	}

	if err := svc.DeletePasskey(ctx, u.ID, doomed.ID); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	if got := sessionCount(t, store, u.ID); got != 1 {
		t.Fatalf("sessions after = %d, want 1 — DeletePasskey revokes nothing", got)
	}
}

// TestARemovedPasskeyCanNoLongerSignIn pins the obvious consequence, which is
// worth a test because it is the whole point of the method: the credential is
// gone from the resolution path.
func TestARemovedPasskeyCanNoLongerSignIn(t *testing.T) {
	svc, _, _ := newPasskeyService(t)
	u := mustSignUp(t, svc, "bo@example.com", validPassword)
	ctx := context.Background()

	doomed := registerPasskey(t, svc, u.ID, newCred('a'))
	if err := svc.DeletePasskey(ctx, u.ID, doomed.ID); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}

	res, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{
		Challenge:    mustBeginLogin(t, svc),
		CredentialID: credID('a'),
		SignCount:    1,
	}, "203.0.113.18", "agent")
	if !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("login with a removed passkey = %v, want ErrCredentialNotFound", err)
	}
	assertNoLoginResult(t, res)
}

// --- the arithmetic, read from the identity side ----------------------------

// TestUnlinkIdentityCountsAPasskeyAsAWayIn pins the OTHER half of the shared
// arithmetic, and it is a behaviour change: an account holding one identity
// and one passkey but no password used to be refused this unlink, because the
// computation only knew about passwords. The passkey is a genuine way in and
// refusing was simply wrong.
//
// The two removers read the same function, which is what keeps them from
// drifting into disagreeing about what a way in is.
func TestUnlinkIdentityCountsAPasskeyAsAWayIn(t *testing.T) {
	ids := memory.NewIdentityStore()
	creds := memory.NewCredentialStore()
	svc, store := newTestService(t, auth.WithIdentityStore(ids), auth.WithCredentialStore(creds))
	ctx := context.Background()

	u, err := store.CreateUser(ctx, auth.UserBase{
		ID:        "33333333-3333-4333-8333-333333333333",
		Email:     "cyd@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := svc.LinkIdentity(ctx, u.ID, googleExt("cyd@example.com", true)); err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}

	// No password, no passkey: the identity is the only way in.
	if err := svc.UnlinkIdentity(ctx, u.ID, "google"); !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("UnlinkIdentity with no other credential = %v, want ErrLastCredential", err)
	}

	registerPasskey(t, svc, u.ID, newCred('a'))
	if err := svc.UnlinkIdentity(ctx, u.ID, "google"); err != nil {
		t.Fatalf("UnlinkIdentity with a passkey registered: %v — the passkey is a way in", err)
	}
	if got := len(identitiesOf(t, ids, u.ID)); got != 0 {
		t.Fatalf("identity rows = %d, want 0", got)
	}
}

// TestUnlinkIdentityIgnoresPasskeysWhenThePortIsNotWired pins the fail-closed
// reading of an absent optional port: a way in this Service cannot reach is
// not a way in it can offer, so a Service without WithCredentialStore behaves
// exactly as it did before passkeys existed.
func TestUnlinkIdentityIgnoresPasskeysWhenThePortIsNotWired(t *testing.T) {
	ids := memory.NewIdentityStore()
	svc, store := newTestService(t, auth.WithIdentityStore(ids)) // no credential store
	ctx := context.Background()

	u, err := store.CreateUser(ctx, auth.UserBase{
		ID:        "44444444-4444-4444-8444-444444444444",
		Email:     "dee@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := svc.LinkIdentity(ctx, u.ID, googleExt("dee@example.com", true)); err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}
	if err := svc.UnlinkIdentity(ctx, u.ID, "google"); !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("UnlinkIdentity = %v, want ErrLastCredential", err)
	}
}
