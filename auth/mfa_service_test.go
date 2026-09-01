package auth_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/internal/totp"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// --- fixtures ---

// testCipher is a deliberately trivial auth.Cipher: enough to prove the
// service encrypts before storing and decrypts before validating, and
// nothing else. It is NOT an example — see auth.WithMFASecretCipher for why
// this package ships no real implementation.
//
// It refuses a value it did not produce, which is the one contractual
// obligation auth.Cipher places on Decrypt and the one this suite leans on:
// a service that stored a plaintext secret would fail to decrypt it here
// rather than quietly working.
type testCipher struct{}

const testCipherPrefix = "enc:"

func (testCipher) Encrypt(plaintext string) (string, error) {
	return testCipherPrefix + plaintext, nil
}

func (testCipher) Decrypt(ciphertext string) (string, error) {
	rest, ok := strings.CutPrefix(ciphertext, testCipherPrefix)
	if !ok {
		return "", errors.New("testCipher: not a ciphertext this cipher produced")
	}
	return rest, nil
}

// mfaClock is a movable clock shared by a Service and the test driving it,
// so a test can put a TOTP code in a chosen step and then step past it.
// Guarded by a mutex because the concurrency tests below read it from
// several goroutines at once.
type mfaClock struct {
	mu sync.Mutex
	t  time.Time
}

func newMFAClock() *mfaClock {
	// A fixed instant, so a failing run is reproducible. Chosen mid-step
	// rather than on a step boundary so that "advance by one period" moves
	// exactly one step rather than sometimes two.
	return &mfaClock{t: time.Date(2026, 3, 4, 10, 15, 15, 0, time.UTC)}
}

func (c *mfaClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *mfaClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// mfaFixture is everything an MFA test needs: the Service, the two stores
// behind it (so a test can assert on stored state directly), and the clock
// both the Service and the test read.
type mfaFixture struct {
	svc   *auth.Service
	store *memory.AuthStore
	mfa   *memory.MFAStore
	clock *mfaClock
}

func newMFAService(t *testing.T, opts ...auth.Option) mfaFixture {
	t.Helper()
	clk := newMFAClock()
	mfaStore := memory.NewMFAStore()
	base := []auth.Option{
		auth.WithMFAStore(mfaStore),
		auth.WithMFASecretCipher(testCipher{}),
		auth.WithMFAIssuer("Acme"),
		auth.WithClock(clk.now),
	}
	svc, store := newTestService(t, append(base, opts...)...)
	return mfaFixture{svc: svc, store: store, mfa: mfaStore, clock: clk}
}

// totpCodeAt computes the code the user's authenticator would show at at.
func totpCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.Code(secret, at, 6, 30*time.Second, totp.SHA1)
	if err != nil {
		t.Fatalf("totp.Code: %v", err)
	}
	return code
}

// enrolled is one account with a CONFIRMED factor: its user record, the
// plaintext TOTP secret, and the recovery codes confirmation handed back.
type enrolled struct {
	user     auth.UserBase
	secret   string
	recovery []string
}

// enrolConfirmed signs an account up and takes it all the way through
// enrolment, leaving the fixture's clock where it started.
func enrolConfirmed(t *testing.T, f mfaFixture, email string) enrolled {
	t.Helper()
	ctx := context.Background()
	u := mustSignUp(t, f.svc, email, validPassword)

	secret, uri, err := f.svc.BeginMFAEnrolment(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginMFAEnrolment(%q): %v", email, err)
	}
	if secret == "" || uri == "" {
		t.Fatalf("BeginMFAEnrolment(%q): secret=%q uri=%q, want both non-empty", email, secret, uri)
	}

	codes, err := f.svc.ConfirmMFAEnrolment(ctx, u.ID, totpCodeAt(t, secret, f.clock.now()))
	if err != nil {
		t.Fatalf("ConfirmMFAEnrolment(%q): %v", email, err)
	}
	return enrolled{user: u, secret: secret, recovery: codes}
}

// loginOwingMFA logs in and fails the test unless the result is a pending,
// second-factor-owed login.
func loginOwingMFA(t *testing.T, f mfaFixture, email string) auth.LoginResult {
	t.Helper()
	res, err := f.svc.Login(context.Background(), email, validPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login(%q): %v", email, err)
	}
	if res.MFA == nil {
		t.Fatalf("Login(%q) returned no MFA challenge; the account has a confirmed factor", email)
	}
	return res
}

// --- the property this plan must not break ---

// TestLoginOwingMFAHandsBackNothingUsableThroughAnyField is the single most
// important assertion in this task, and it is written from the point of
// view of a caller compiled against v0.1.0: one that reads AccessToken,
// has never heard of LoginResult.MFA, and would happily install a session
// from whatever it is given.
//
// Such a caller must get the EMPTY STRING — which token.Parse refuses —
// and not merely from AccessToken: the assertion walks every string field
// of LoginResult by reflection, so a future field that leaked a usable
// credential onto this path would fail here too. It also proves the
// negative at the store: no Session row exists, so there is nothing for a
// leaked value to name.
//
// Mutation anchor (a): populate the tokens on the MFA-owed path and this
// must fail.
func TestLoginOwingMFAHandsBackNothingUsableThroughAnyField(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "nadia@example.com")

	res, err := f.svc.Login(ctx, "nadia@example.com", validPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login: %v, want a nil error — the password was correct", err)
	}

	// The v0.1.0 caller's own view: every string this struct hands back.
	rv := reflect.ValueOf(res)
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Type.Kind() != reflect.String {
			continue
		}
		if got := rv.Field(i).String(); got != "" {
			t.Fatalf("LoginResult.%s = %q on the MFA-owed path, want empty — a caller that ignores MFA must get nothing usable", rt.Field(i).Name, got)
		}
	}

	// And empty is refused, rather than being a token nobody checked.
	if _, perr := token.Parse(res.AccessToken, testSigningKey); perr == nil {
		t.Fatal("token.Parse accepted the access token from an MFA-owed login; it must refuse it")
	}
	if _, rerr := f.svc.Refresh(ctx, res.RefreshToken); rerr == nil {
		t.Fatal("Refresh accepted the refresh token from an MFA-owed login; it must refuse it")
	}

	// The challenge itself is present and is not a session.
	if res.MFA == nil {
		t.Fatal("LoginResult.MFA = nil, want a challenge")
	}
	if res.MFA.Token == "" {
		t.Fatal("MFAChallenge.Token is empty")
	}
	if _, perr := token.Parse(res.MFA.Token, testSigningKey); perr == nil {
		t.Fatal("the challenge token parsed as an access token; it is an opaque handle, not a credential")
	}
	if !res.MFA.ExpiresAt.After(f.clock.now()) {
		t.Fatalf("MFAChallenge.ExpiresAt = %v, want after now (%v)", res.MFA.ExpiresAt, f.clock.now())
	}

	// Nothing was minted: there is no session for a leaked value to name.
	sessions, err := f.store.ListSessionsByUser(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("sessions after an MFA-owed login = %d, want 0 — Login must not mint one", len(sessions))
	}

	if res.User.PasswordHash != "" {
		t.Fatalf("User.PasswordHash = %q on the MFA-owed path, want it scrubbed", res.User.PasswordHash)
	}
	if res.User.ID != e.user.ID {
		t.Fatalf("User.ID = %q, want %q", res.User.ID, e.user.ID)
	}
}

// --- Login's own behaviour around the factor ---

// TestLoginIgnoresAnUnconfirmedFactor is the lockout guard: enrolment that
// was begun and never finished must not gate anything, or a user who
// scanned nothing is locked out of an account whose password they know.
func TestLoginIgnoresAnUnconfirmedFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	u := mustSignUp(t, f.svc, "olen@example.com", validPassword)

	if _, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID); err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}

	res, err := f.svc.Login(ctx, "olen@example.com", validPassword, "1.2.3.4", "agent")
	if err != nil {
		t.Fatalf("Login with an unconfirmed factor: %v, want success", err)
	}
	if res.MFA != nil {
		t.Fatal("an UNCONFIRMED factor gated the login; a user who scanned nothing would be locked out")
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("access=%q refresh=%q, want a full session", res.AccessToken, res.RefreshToken)
	}
}

func TestLoginWithNoFactorIsUnchanged(t *testing.T) {
	f := newMFAService(t)
	mustSignUp(t, f.svc, "pila@example.com", validPassword)

	res, err := f.svc.Login(context.Background(), "pila@example.com", validPassword, "1.2.3.4", "agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.MFA != nil || res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("mfa=%v access=%q refresh=%q, want an ordinary session", res.MFA, res.AccessToken, res.RefreshToken)
	}
}

// TestEnforcementRequiredRefusesAnUnenrolledAccountWithItsOwnSentinel pins
// that the refusal is distinguishable: an application must be able to route
// the user into enrolment rather than telling them their password was
// wrong when it was right.
func TestEnforcementRequiredRefusesAnUnenrolledAccountWithItsOwnSentinel(t *testing.T) {
	f := newMFAService(t, auth.WithMFAEnforcement(auth.EnforcementRequired))
	ctx := context.Background()
	mustSignUp(t, f.svc, "quin@example.com", validPassword)

	res, err := f.svc.Login(ctx, "quin@example.com", validPassword, "1.2.3.4", "agent")
	if !errors.Is(err, auth.ErrMFARequired) {
		t.Fatalf("Login err = %v, want ErrMFARequired", err)
	}
	if errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("ErrMFARequired must not also satisfy ErrInvalidCredentials; the password was correct")
	}
	if res.AccessToken != "" || res.RefreshToken != "" || res.MFA != nil {
		t.Fatalf("a refused login handed back %+v, want the zero LoginResult", res)
	}

	// And a WRONG password still says wrong password — the enforcement
	// check is after the credential check, never before it, so it cannot
	// become an "is this account enrolled?" oracle.
	if _, werr := f.svc.Login(ctx, "quin@example.com", "not-the-password", "1.2.3.4", "agent"); !errors.Is(werr, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong-password err = %v, want ErrInvalidCredentials", werr)
	}
	if _, uerr := f.svc.Login(ctx, "nobody@example.com", validPassword, "1.2.3.4", "agent"); !errors.Is(uerr, auth.ErrInvalidCredentials) {
		t.Fatalf("unknown-address err = %v, want ErrInvalidCredentials", uerr)
	}
}

// TestEnforcementRequiredRefusesAnUnconfirmedFactorToo: begun-but-abandoned
// enrolment is not enrolment.
func TestEnforcementRequiredRefusesAnUnconfirmedFactorToo(t *testing.T) {
	f := newMFAService(t, auth.WithMFAEnforcement(auth.EnforcementRequired))
	ctx := context.Background()
	u := mustSignUp(t, f.svc, "rosa@example.com", validPassword)
	if _, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID); err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}

	if _, err := f.svc.Login(ctx, "rosa@example.com", validPassword, "1.2.3.4", "agent"); !errors.Is(err, auth.ErrMFARequired) {
		t.Fatalf("Login err = %v, want ErrMFARequired", err)
	}
}

// TestEnforcementRequiredWithNoStoreIsAWiringError: refusing every user
// with "enrol a factor" when no factor CAN be enrolled would send a whole
// deployment somewhere that cannot work. The honest answer names the
// missing piece.
func TestEnforcementRequiredWithNoStoreIsAWiringError(t *testing.T) {
	svc, _ := newTestService(t, auth.WithMFAEnforcement(auth.EnforcementRequired))
	ctx := context.Background()
	mustSignUp(t, svc, "sena@example.com", validPassword)

	_, err := svc.Login(ctx, "sena@example.com", validPassword, "1.2.3.4", "agent")
	if !errors.Is(err, auth.ErrMFANotConfigured) {
		t.Fatalf("Login err = %v, want ErrMFANotConfigured", err)
	}
}

func TestEnforcementOptionalIsTheZeroValue(t *testing.T) {
	if auth.EnforcementOptional != 0 {
		t.Fatalf("EnforcementOptional = %d, want 0 — the safe policy must be what a caller who says nothing gets", auth.EnforcementOptional)
	}
}

func TestWithMFAEnforcementPanicsOnAnUnknownMode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("WithMFAEnforcement(99) did not panic; a Service holding a mode no branch handles is worse than a construction failure")
		}
	}()
	_ = auth.New(memory.NewAuthStore(), auth.WithMFAEnforcement(auth.Enforcement(99)))
}

// --- enrolment ---

func TestBeginMFAEnrolmentStoresAnUnconfirmedEncryptedFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	u := mustSignUp(t, f.svc, "tara@example.com", validPassword)

	secret, uri, err := f.svc.BeginMFAEnrolment(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}

	stored, err := f.mfa.FindFactor(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if stored.ConfirmedAt != nil {
		t.Fatal("a factor was stored already confirmed; nothing has been proven yet")
	}
	if stored.LastStep != nil {
		t.Fatal("a fresh factor carries a LastStep; its owner's first genuine code would be refused")
	}
	if stored.SecretEnc == secret {
		t.Fatal("the TOTP secret was stored in the clear; a dump of this column is a second-factor bypass for every user")
	}
	if !strings.HasPrefix(stored.SecretEnc, testCipherPrefix) {
		t.Fatalf("SecretEnc = %q, want it to have gone through the configured Cipher", stored.SecretEnc)
	}
	if !strings.Contains(uri, "otpauth://totp/") || !strings.Contains(uri, "issuer=Acme") {
		t.Fatalf("provisioning URI = %q, want an otpauth URI carrying the configured issuer", uri)
	}
	if !strings.Contains(uri, secret) {
		t.Fatalf("provisioning URI = %q, want it to carry the secret it just minted", uri)
	}
}

func TestBeginMFAEnrolmentRefusesWithoutAStoreOrACipher(t *testing.T) {
	ctx := context.Background()

	noStore, _ := newTestService(t, auth.WithMFASecretCipher(testCipher{}))
	u := mustSignUp(t, noStore, "ubah@example.com", validPassword)
	if _, _, err := noStore.BeginMFAEnrolment(ctx, u.ID); !errors.Is(err, auth.ErrMFANotConfigured) {
		t.Fatalf("BeginMFAEnrolment with no store = %v, want ErrMFANotConfigured", err)
	}

	mfaStore := memory.NewMFAStore()
	noCipher, _ := newTestService(t, auth.WithMFAStore(mfaStore))
	v := mustSignUp(t, noCipher, "vito@example.com", validPassword)
	if _, _, err := noCipher.BeginMFAEnrolment(ctx, v.ID); !errors.Is(err, auth.ErrMFACipherNotConfigured) {
		t.Fatalf("BeginMFAEnrolment with no cipher = %v, want ErrMFACipherNotConfigured", err)
	}
	if _, ferr := mfaStore.FindFactor(ctx, v.ID); !errors.Is(ferr, auth.ErrFactorNotFound) {
		t.Fatalf("a factor was written despite the refusal: %v — a Service with no key must hold no secret", ferr)
	}
}

// TestBeginMFAEnrolmentRefusesToOverwriteAConfirmedFactor: this method asks
// for no password, so overwriting a confirmed factor with an unconfirmed
// one would be a password-free way to switch a victim's second factor off
// from a stolen session.
func TestBeginMFAEnrolmentRefusesToOverwriteAConfirmedFactor(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "wren@example.com")

	before, err := f.mfa.FindFactor(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}

	if _, _, err := f.svc.BeginMFAEnrolment(ctx, e.user.ID); !errors.Is(err, auth.ErrMFAAlreadyEnrolled) {
		t.Fatalf("BeginMFAEnrolment on a confirmed account = %v, want ErrMFAAlreadyEnrolled", err)
	}

	after, err := f.mfa.FindFactor(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if after.SecretEnc != before.SecretEnc || after.ConfirmedAt == nil {
		t.Fatal("the confirmed factor was replaced by the refused call; MFA would be silently off")
	}

	// And the account is still gated.
	if _, err := f.svc.Login(ctx, "wren@example.com", validPassword, "1.2.3.4", "agent"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	loginOwingMFA(t, f, "wren@example.com")
}

// TestBeginMFAEnrolmentReplacesAnUnconfirmedFactorWholesale: the retry path
// a user takes when their app rejected the first URI.
func TestBeginMFAEnrolmentReplacesAnUnconfirmedFactorWholesale(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	u := mustSignUp(t, f.svc, "xena@example.com", validPassword)

	first, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID)
	if err != nil {
		t.Fatalf("first BeginMFAEnrolment: %v", err)
	}
	second, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID)
	if err != nil {
		t.Fatalf("second BeginMFAEnrolment: %v", err)
	}
	if first == second {
		t.Fatal("a second enrolment reused the first secret; it must mint a fresh one")
	}

	// The FIRST secret is dead: only the stored one confirms.
	if _, err := f.svc.ConfirmMFAEnrolment(ctx, u.ID, totpCodeAt(t, first, f.clock.now())); !errors.Is(err, auth.ErrMFACodeInvalid) {
		t.Fatalf("confirming with the superseded secret = %v, want ErrMFACodeInvalid", err)
	}
	if _, err := f.svc.ConfirmMFAEnrolment(ctx, u.ID, totpCodeAt(t, second, f.clock.now())); err != nil {
		t.Fatalf("confirming with the current secret: %v", err)
	}
}

func TestConfirmMFAEnrolmentRequiresAValidCode(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	u := mustSignUp(t, f.svc, "yara@example.com", validPassword)
	secret, _, err := f.svc.BeginMFAEnrolment(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}

	for _, bad := range []string{"", "000000", "12345", "not-a-code", totpCodeAt(t, secret, f.clock.now().Add(10*time.Minute))} {
		if _, cerr := f.svc.ConfirmMFAEnrolment(ctx, u.ID, bad); !errors.Is(cerr, auth.ErrMFACodeInvalid) {
			t.Fatalf("ConfirmMFAEnrolment(%q) = %v, want ErrMFACodeInvalid", bad, cerr)
		}
	}

	stored, err := f.mfa.FindFactor(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if stored.ConfirmedAt != nil {
		t.Fatal("a refused confirmation stamped ConfirmedAt anyway")
	}
}

func TestConfirmMFAEnrolmentStampsAndIssuesHashedRecoveryCodes(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "zoya@example.com")

	stored, err := f.mfa.FindFactor(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if stored.ConfirmedAt == nil {
		t.Fatal("ConfirmedAt was not stamped")
	}
	if !stored.ConfirmedAt.Equal(f.clock.now()) {
		t.Fatalf("ConfirmedAt = %v, want the service clock's %v", stored.ConfirmedAt, f.clock.now())
	}
	if stored.LastStep == nil {
		t.Fatal("LastStep is nil after a confirmation; the code that confirmed the factor is still replayable")
	}

	if len(e.recovery) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(e.recovery))
	}
	seen := map[string]bool{}
	for _, c := range e.recovery {
		if c == "" || seen[c] {
			t.Fatalf("recovery codes are not unique/non-empty: %q", e.recovery)
		}
		seen[c] = true
	}

	rows, err := f.mfa.ListRecoveryCodes(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListRecoveryCodes: %v", err)
	}
	if len(rows) != len(e.recovery) {
		t.Fatalf("stored codes = %d, want %d", len(rows), len(e.recovery))
	}
	hasher := password.Bcrypt(testCost)
	for _, r := range rows {
		if seen[r.CodeHash] {
			t.Fatal("a recovery code was stored in plaintext; a dump of this column bypasses the second factor for every user")
		}
		if r.UsedAt != nil {
			t.Fatal("a freshly issued recovery code is already marked used")
		}
		matches := 0
		for _, plain := range e.recovery {
			if hasher.Verify(plain, r.CodeHash) {
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("stored hash matched %d of the returned plaintexts, want exactly 1", matches)
		}
	}
}

func TestConfirmMFAEnrolmentIsNotRepeatable(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "abby@example.com")

	f.clock.advance(30 * time.Second)
	if _, err := f.svc.ConfirmMFAEnrolment(ctx, e.user.ID, totpCodeAt(t, e.secret, f.clock.now())); !errors.Is(err, auth.ErrMFAAlreadyEnrolled) {
		t.Fatalf("second ConfirmMFAEnrolment = %v, want ErrMFAAlreadyEnrolled — a second set of codes would silently invalidate the first", err)
	}

	rows, err := f.mfa.ListRecoveryCodes(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListRecoveryCodes: %v", err)
	}
	hasher := password.Bcrypt(testCost)
	for _, r := range rows {
		matched := false
		for _, plain := range e.recovery {
			if hasher.Verify(plain, r.CodeHash) {
				matched = true
			}
		}
		if !matched {
			t.Fatal("the stored recovery set was replaced; the codes the user wrote down are dead")
		}
	}
}

func TestConfirmMFAEnrolmentWithoutBeginningIsFactorNotFound(t *testing.T) {
	f := newMFAService(t)
	u := mustSignUp(t, f.svc, "bram@example.com", validPassword)
	if _, err := f.svc.ConfirmMFAEnrolment(context.Background(), u.ID, "123456"); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("ConfirmMFAEnrolment with no enrolment = %v, want ErrFactorNotFound", err)
	}
}

// --- CompleteMFA ---

func TestCompleteMFAWithATOTPCodeMintsTheSession(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "cleo@example.com")

	// One step past the confirmation, so the code differs from the one
	// that stamped the factor.
	f.clock.advance(30 * time.Second)
	pending := loginOwingMFA(t, f, "cleo@example.com")

	res, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, totpCodeAt(t, e.secret, f.clock.now()), "198.51.100.4", "totp-agent")
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.MFA != nil {
		t.Fatal("CompleteMFA returned another challenge; there is nothing left to owe")
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("access=%q refresh=%q, want a full session", res.AccessToken, res.RefreshToken)
	}
	if res.User.PasswordHash != "" {
		t.Fatalf("User.PasswordHash = %q, want it scrubbed", res.User.PasswordHash)
	}

	claims, err := token.Parse(res.AccessToken, testSigningKey)
	if err != nil {
		t.Fatalf("token.Parse: %v", err)
	}
	if claims.Subject != e.user.ID {
		t.Fatalf("claims.Subject = %q, want %q", claims.Subject, e.user.ID)
	}
	sess, err := f.store.FindSessionByHash(ctx, token.HashOpaque(res.RefreshToken))
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if sess.IP != "198.51.100.4" || sess.UserAgent != "totp-agent" {
		t.Fatalf("session IP/UA = %q/%q, want CompleteMFA's own arguments", sess.IP, sess.UserAgent)
	}
	if _, rerr := f.svc.Refresh(ctx, res.RefreshToken); rerr != nil {
		t.Fatalf("Refresh on the completed session: %v, want it to work", rerr)
	}
}

func TestCompleteMFAWithARecoveryCodeMintsTheSession(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "dita@example.com")
	pending := loginOwingMFA(t, f, "dita@example.com")

	res, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[0], "1.2.3.4", "agent")
	if err != nil {
		t.Fatalf("CompleteMFA with a recovery code: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("a recovery code did not produce a session")
	}
}

// TestCompleteMFARefusesAReplayedTOTPCode is mutation anchor (b): remove
// the AdvanceStep compare-and-set and this must fail. A code read over a
// shoulder, off a screen share, or out of a phishing page stays valid for
// its whole skew window without it.
func TestCompleteMFARefusesAReplayedTOTPCode(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "elke@example.com")

	f.clock.advance(30 * time.Second)
	code := totpCodeAt(t, e.secret, f.clock.now())

	first := loginOwingMFA(t, f, "elke@example.com")
	if _, err := f.svc.CompleteMFA(ctx, first.MFA.Token, code, "1.2.3.4", "agent"); err != nil {
		t.Fatalf("first CompleteMFA: %v", err)
	}

	// Same step, same code, a fresh challenge: exactly the shape of a
	// replay by whoever was watching.
	second := loginOwingMFA(t, f, "elke@example.com")
	res, err := f.svc.CompleteMFA(ctx, second.MFA.Token, code, "5.6.7.8", "attacker")
	if !errors.Is(err, auth.ErrMFACodeInvalid) {
		t.Fatalf("replayed code = %v, want ErrMFACodeInvalid — a code stays usable for its whole window without the replay guard", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("a replayed code produced a session (%q/%q)", res.AccessToken, res.RefreshToken)
	}

	// Still inside the same skew window, an EARLIER step is refused too.
	earlier := totpCodeAt(t, e.secret, f.clock.now().Add(-30*time.Second))
	if _, err := f.svc.CompleteMFA(ctx, second.MFA.Token, earlier, "5.6.7.8", "attacker"); !errors.Is(err, auth.ErrMFACodeInvalid) {
		t.Fatalf("earlier-step code = %v, want ErrMFACodeInvalid", err)
	}

	// And the legitimate user is not locked out: the next step works.
	f.clock.advance(30 * time.Second)
	if _, err := f.svc.CompleteMFA(ctx, second.MFA.Token, totpCodeAt(t, e.secret, f.clock.now()), "1.2.3.4", "agent"); err != nil {
		t.Fatalf("next-step code after a refused replay: %v, want success", err)
	}
}

// TestCompleteMFARecoveryCodeIsSingleUse: the property recovery codes have.
func TestCompleteMFARecoveryCodeIsSingleUse(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "fern@example.com")

	first := loginOwingMFA(t, f, "fern@example.com")
	if _, err := f.svc.CompleteMFA(ctx, first.MFA.Token, e.recovery[0], "1.2.3.4", "agent"); err != nil {
		t.Fatalf("first use: %v", err)
	}

	second := loginOwingMFA(t, f, "fern@example.com")
	if _, err := f.svc.CompleteMFA(ctx, second.MFA.Token, e.recovery[0], "1.2.3.4", "agent"); !errors.Is(err, auth.ErrMFACodeInvalid) {
		t.Fatalf("second use of one recovery code = %v, want ErrMFACodeInvalid", err)
	}
	// A different, unspent code still works.
	if _, err := f.svc.CompleteMFA(ctx, second.MFA.Token, e.recovery[1], "1.2.3.4", "agent"); err != nil {
		t.Fatalf("an unspent recovery code: %v, want success", err)
	}
}

// TestCompleteMFAChallengeIsSingleUse: one challenge, one session.
func TestCompleteMFAChallengeIsSingleUse(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "gwen@example.com")
	pending := loginOwingMFA(t, f, "gwen@example.com")

	if _, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[0], "1.2.3.4", "agent"); err != nil {
		t.Fatalf("first CompleteMFA: %v", err)
	}

	res, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[1], "1.2.3.4", "agent")
	if !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("second CompleteMFA = %v, want ErrVerificationNotFound", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("a spent challenge produced a session (%q/%q)", res.AccessToken, res.RefreshToken)
	}
	if _, ferr := f.store.FindVerificationByHash(ctx, token.HashOpaque(pending.MFA.Token)); !errors.Is(ferr, auth.ErrVerificationNotFound) {
		t.Fatalf("challenge row after completion = %v, want it burned", ferr)
	}
	sessions, err := f.store.ListSessionsByUser(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want exactly 1", len(sessions))
	}
}

// TestCompleteMFAWrongCodeDoesNotBurnTheChallenge: a mistyped code is the
// commonest event on this screen. Burning the challenge for it would send
// the user back to the password form every time their thumb slipped.
func TestCompleteMFAWrongCodeDoesNotBurnTheChallenge(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "hana@example.com")
	f.clock.advance(30 * time.Second)
	pending := loginOwingMFA(t, f, "hana@example.com")

	for _, bad := range []string{"000000", "", "nonsense", "999999"} {
		if _, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, bad, "1.2.3.4", "agent"); !errors.Is(err, auth.ErrMFACodeInvalid) {
			t.Fatalf("CompleteMFA(%q) = %v, want ErrMFACodeInvalid", bad, err)
		}
		if _, ferr := f.store.FindVerificationByHash(ctx, token.HashOpaque(pending.MFA.Token)); ferr != nil {
			t.Fatalf("the challenge was burned by a wrong code (%q): %v", bad, ferr)
		}
	}

	// And the same challenge still completes with a right code.
	if _, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, totpCodeAt(t, e.secret, f.clock.now()), "1.2.3.4", "agent"); err != nil {
		t.Fatalf("CompleteMFA after four wrong codes: %v, want success", err)
	}
}

func TestCompleteMFAExpiredChallengeIsRefusedAndNotBurned(t *testing.T) {
	f := newMFAService(t, auth.WithMFAChallengeTTL(2*time.Minute))
	ctx := context.Background()
	e := enrolConfirmed(t, f, "ilsa@example.com")
	pending := loginOwingMFA(t, f, "ilsa@example.com")

	f.clock.advance(2 * time.Minute)
	res, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[0], "1.2.3.4", "agent")
	if !errors.Is(err, auth.ErrVerificationExpired) {
		t.Fatalf("expired challenge = %v, want ErrVerificationExpired", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatal("an expired challenge produced a session")
	}
	// Not burned: it ages out through PurgeExpired like any other row, and
	// the recovery code the caller offered was not spent either.
	if _, ferr := f.store.FindVerificationByHash(ctx, token.HashOpaque(pending.MFA.Token)); ferr != nil {
		t.Fatalf("the expired challenge was burned: %v", ferr)
	}
	rows, err := f.mfa.ListRecoveryCodes(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListRecoveryCodes: %v", err)
	}
	for _, r := range rows {
		if r.UsedAt != nil {
			t.Fatal("a recovery code was burned by a call that refused on expiry")
		}
	}
}

func TestCompleteMFAUsesTheConfiguredChallengeTTL(t *testing.T) {
	f := newMFAService(t, auth.WithMFAChallengeTTL(90*time.Second))
	enrolConfirmed(t, f, "jane@example.com")
	pending := loginOwingMFA(t, f, "jane@example.com")

	if want := f.clock.now().Add(90 * time.Second); !pending.MFA.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", pending.MFA.ExpiresAt, want)
	}
}

// TestCompleteMFARefusesEveryOtherPurpose: a magic link or a reset token
// exchanged here would be a session issued without any second factor at
// all — the exact thing withholding the session was for.
func TestCompleteMFARefusesEveryOtherPurpose(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "kira@example.com")

	magic, ok, err := f.svc.RequestMagicLink(ctx, "kira@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink: ok=%v err=%v", ok, err)
	}
	reset, ok, err := f.svc.RequestPasswordReset(ctx, "kira@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}

	for name, tok := range map[string]string{"magic_link": magic, "password_reset": reset} {
		res, cerr := f.svc.CompleteMFA(ctx, tok, e.recovery[0], "1.2.3.4", "agent")
		if !errors.Is(cerr, auth.ErrVerificationPurpose) {
			t.Fatalf("CompleteMFA(%s token) = %v, want ErrVerificationPurpose", name, cerr)
		}
		if res.AccessToken != "" || res.RefreshToken != "" {
			t.Fatalf("a %s token produced a session through CompleteMFA", name)
		}
		if _, ferr := f.store.FindVerificationByHash(ctx, token.HashOpaque(tok)); ferr != nil {
			t.Fatalf("the %s token was burned by the refusal: %v", name, ferr)
		}
	}

	// And the reverse: an mfa_challenge is redeemable nowhere else.
	pending := loginOwingMFA(t, f, "kira@example.com")
	if _, verr := f.svc.VerifyEmail(ctx, pending.MFA.Token); !errors.Is(verr, auth.ErrVerificationPurpose) {
		t.Fatalf("VerifyEmail(challenge) = %v, want ErrVerificationPurpose", verr)
	}
	if _, merr := f.svc.RedeemMagicLink(ctx, pending.MFA.Token, "1.2.3.4", "agent"); !errors.Is(merr, auth.ErrVerificationPurpose) {
		t.Fatalf("RedeemMagicLink(challenge) = %v, want ErrVerificationPurpose", merr)
	}
	if perr := f.svc.ResetPassword(ctx, pending.MFA.Token, "Another-Valid-Pass21!"); !errors.Is(perr, auth.ErrVerificationPurpose) {
		t.Fatalf("ResetPassword(challenge) = %v, want ErrVerificationPurpose", perr)
	}
	if _, ferr := f.store.FindVerificationByHash(ctx, token.HashOpaque(pending.MFA.Token)); ferr != nil {
		t.Fatalf("the challenge was burned by one of those refusals: %v", ferr)
	}
}

func TestCompleteMFAAfterDisableMFAFailsClosed(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "lena@example.com")
	pending := loginOwingMFA(t, f, "lena@example.com")

	if err := f.svc.DisableMFA(ctx, e.user.ID, validPassword); err != nil {
		t.Fatalf("DisableMFA: %v", err)
	}
	if _, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[0], "1.2.3.4", "agent"); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("CompleteMFA after DisableMFA = %v, want ErrFactorNotFound — an outstanding challenge must die with the factor", err)
	}
}

// TestCompleteMFARefusesAnAnonymizedAccount pins CompleteMFA's OWN guard,
// by stamping the row directly rather than through Service.AnonymizeAccount
// — that method deletes every verification the account holds, so a
// challenge minted before it never survives to reach this check. The guard
// still has to exist: it is the one that holds if a future sweep is
// narrowed, and it is the same defence-in-depth stance Service.VerifyEmail
// takes for its own anonymized-account refusal.
func TestCompleteMFARefusesAnAnonymizedAccount(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "mira@example.com")
	pending := loginOwingMFA(t, f, "mira@example.com")

	if err := f.store.MarkUserDeleted(ctx, e.user.ID, "deleted-mira@example.invalid", f.clock.now()); err != nil {
		t.Fatalf("MarkUserDeleted: %v", err)
	}
	if _, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[0], "1.2.3.4", "agent"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("CompleteMFA on an anonymized account = %v, want ErrUserNotFound", err)
	}
	sessions, err := f.store.ListSessionsByUser(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("sessions = %d, want 0", len(sessions))
	}
}

// TestAnonymizeAccountSweepsOutstandingChallenges is the other half: the
// existing whole-account verification sweep already takes challenges with
// it, so the guard above is defence in depth rather than the only thing
// standing there.
func TestAnonymizeAccountSweepsOutstandingChallenges(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "nuri@example.com")
	pending := loginOwingMFA(t, f, "nuri@example.com")

	if err := f.svc.AnonymizeAccount(ctx, e.user.ID, validPassword); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}
	if _, err := f.store.FindVerificationByHash(ctx, token.HashOpaque(pending.MFA.Token)); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("challenge after AnonymizeAccount = %v, want it swept", err)
	}
	if _, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[0], "1.2.3.4", "agent"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("CompleteMFA after AnonymizeAccount = %v, want ErrVerificationNotFound", err)
	}
}

func TestMFAChallengeMethodsAreNotShared(t *testing.T) {
	f := newMFAService(t)
	enrolConfirmed(t, f, "nita@example.com")

	first := loginOwingMFA(t, f, "nita@example.com")
	if !equalStrings(first.MFA.Methods, []string{"totp", "recovery_code"}) {
		t.Fatalf("Methods = %v, want [totp recovery_code]", first.MFA.Methods)
	}
	first.MFA.Methods[0] = "clobbered"

	second := loginOwingMFA(t, f, "nita@example.com")
	if !equalStrings(second.MFA.Methods, []string{"totp", "recovery_code"}) {
		t.Fatalf("Methods = %v after another challenge's slice was written to; each challenge must own its own", second.MFA.Methods)
	}
}

// --- the challenge's user binding ---

// unscopedMFAStore answers FindFactor and/or ListRecoveryCodes with ANOTHER
// user's rows, whoever is asked for. It is a deliberately non-compliant
// auth.MFAStore — both methods are contracted to return only the named
// user's rows — in the same spirit as auth/authtest's negative doubles: it
// proves the SERVICE refuses to trust a backend that mis-scopes, rather
// than assuming no backend ever will.
//
// What it stands in for is not exotic. A missing WHERE clause, a query
// keyed on a stale variable, or a cache keyed on the wrong id all produce
// exactly this, and the consequence is that one account's authenticator
// satisfies another account's challenge.
type unscopedMFAStore struct {
	*memory.MFAStore
	lend          string // whose rows come back regardless of who is asked for
	unscopeFactor bool
	unscopeCodes  bool
}

func (s *unscopedMFAStore) FindFactor(ctx context.Context, userID string) (auth.MFAFactor, error) {
	if s.unscopeFactor {
		userID = s.lend
	}
	return s.MFAStore.FindFactor(ctx, userID)
}

func (s *unscopedMFAStore) ListRecoveryCodes(ctx context.Context, userID string) ([]auth.RecoveryCode, error) {
	if s.unscopeCodes {
		userID = s.lend
	}
	return s.MFAStore.ListRecoveryCodes(ctx, userID)
}

func (s *unscopedMFAStore) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string, now time.Time) (bool, error) {
	if s.unscopeCodes {
		userID = s.lend
	}
	return s.MFAStore.ConsumeRecoveryCode(ctx, userID, codeHash, now)
}

// TestCompleteMFARefusesAnotherAccountsFactorAndCodes is mutation anchor
// (d): drop the challenge's user binding — the f.UserID check in
// CompleteMFA and the c.UserID check in spendRecoveryCode — and this must
// fail. The challenge names the account; every credential checked against
// it must belong to that same account, and the service does not take the
// store's word for it.
func TestCompleteMFARefusesAnotherAccountsFactorAndCodes(t *testing.T) {
	ctx := context.Background()

	// Seed both accounts through an ordinary, correctly-scoping service.
	seed := newMFAService(t)
	alice := enrolConfirmed(t, seed, "alice@example.com")
	bob := enrolConfirmed(t, seed, "bob@example.com")

	build := func(unscopeFactor, unscopeCodes bool) mfaFixture {
		wrapped := &unscopedMFAStore{
			MFAStore:      seed.mfa,
			lend:          bob.user.ID,
			unscopeFactor: unscopeFactor,
			unscopeCodes:  unscopeCodes,
		}
		svc := auth.New(seed.store,
			auth.WithHasher(password.Bcrypt(testCost)),
			auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
			auth.WithMFAStore(wrapped),
			auth.WithMFASecretCipher(testCipher{}),
			auth.WithClock(seed.clock.now),
		)
		return mfaFixture{svc: svc, store: seed.store, mfa: seed.mfa, clock: seed.clock}
	}

	t.Run("factor", func(t *testing.T) {
		f := build(true, false)
		f.clock.advance(30 * time.Second)
		pending := loginOwingMFA(t, f, "alice@example.com")

		// Bob's authenticator, against Alice's challenge.
		_, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, totpCodeAt(t, bob.secret, f.clock.now()), "1.2.3.4", "agent")
		if err == nil {
			t.Fatal("Bob's TOTP code completed Alice's challenge; the second factor is not bound to the account")
		}
		if !errors.Is(err, auth.ErrStoreContract) {
			t.Fatalf("err = %v, want ErrStoreContract — the factor handed back was not the challenge's user's", err)
		}
		if _, ferr := f.store.FindVerificationByHash(ctx, token.HashOpaque(pending.MFA.Token)); ferr != nil {
			t.Fatalf("the challenge was burned by the refusal: %v", ferr)
		}
		sessions, serr := f.store.ListSessionsByUser(ctx, alice.user.ID)
		if serr != nil {
			t.Fatalf("ListSessionsByUser: %v", serr)
		}
		if len(sessions) != 0 {
			t.Fatalf("sessions for Alice = %d, want 0", len(sessions))
		}
	})

	t.Run("recovery codes", func(t *testing.T) {
		f := build(false, true)
		pending := loginOwingMFA(t, f, "alice@example.com")

		// Bob's recovery code, against Alice's challenge.
		_, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, bob.recovery[0], "1.2.3.4", "agent")
		if err == nil {
			t.Fatal("Bob's recovery code completed Alice's challenge; the second factor is not bound to the account")
		}
		if !errors.Is(err, auth.ErrMFACodeInvalid) {
			t.Fatalf("err = %v, want ErrMFACodeInvalid", err)
		}
		// Bob's code survives: a refusal must not spend someone else's
		// credential.
		rows, lerr := f.mfa.ListRecoveryCodes(ctx, bob.user.ID)
		if lerr != nil {
			t.Fatalf("ListRecoveryCodes: %v", lerr)
		}
		for _, r := range rows {
			if r.UsedAt != nil {
				t.Fatal("Bob's recovery code was burned by a refused completion of Alice's challenge")
			}
		}
	})
}

// TestCompleteMFACrossUserCodesAreRefusedEndToEnd is the same property
// through the real, correctly-scoping store: no doubles, nothing staged.
func TestCompleteMFACrossUserCodesAreRefusedEndToEnd(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	alice := enrolConfirmed(t, f, "orla@example.com")
	bob := enrolConfirmed(t, f, "pavel@example.com")

	f.clock.advance(30 * time.Second)
	pending := loginOwingMFA(t, f, "orla@example.com")

	for name, code := range map[string]string{
		"bob's TOTP code":     totpCodeAt(t, bob.secret, f.clock.now()),
		"bob's recovery code": bob.recovery[0],
	} {
		if _, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, code, "1.2.3.4", "agent"); !errors.Is(err, auth.ErrMFACodeInvalid) {
			t.Fatalf("CompleteMFA(alice's challenge, %s) = %v, want ErrMFACodeInvalid", name, err)
		}
	}

	for _, id := range []string{alice.user.ID, bob.user.ID} {
		sessions, err := f.store.ListSessionsByUser(ctx, id)
		if err != nil {
			t.Fatalf("ListSessionsByUser: %v", err)
		}
		if len(sessions) != 0 {
			t.Fatalf("sessions for %q = %d, want 0", id, len(sessions))
		}
	}

	// Alice's own code still finishes Alice's login.
	if _, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, totpCodeAt(t, alice.secret, f.clock.now()), "1.2.3.4", "agent"); err != nil {
		t.Fatalf("CompleteMFA with Alice's own code: %v", err)
	}
}

// --- claim before apply ---

// mfaOrderStore records the two calls whose ORDER is the property: the
// challenge's burn and the session's insert.
type mfaOrderStore struct {
	*memory.AuthStore
	mu    sync.Mutex
	order []string
}

func newMFAOrderStore() *mfaOrderStore {
	return &mfaOrderStore{AuthStore: memory.NewAuthStore()}
}

func (s *mfaOrderStore) record(name string) {
	s.mu.Lock()
	s.order = append(s.order, name)
	s.mu.Unlock()
}

func (s *mfaOrderStore) DeleteVerification(ctx context.Context, id string) error {
	s.record("DeleteVerification")
	return s.AuthStore.DeleteVerification(ctx, id)
}

func (s *mfaOrderStore) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	s.record("CreateSession")
	return s.AuthStore.CreateSession(ctx, sess)
}

func (s *mfaOrderStore) reset() {
	s.mu.Lock()
	s.order = nil
	s.mu.Unlock()
}

func (s *mfaOrderStore) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// TestCompleteMFAClaimsTheChallengeBeforeMinting is half of mutation anchor
// (c): move the burn after the mint and this must fail. It pins the
// ordering directly rather than inferring it from an outcome, the way
// TestRedeemMagicLinkClaimsBeforeApplyOrdering does for its own flow.
func TestCompleteMFAClaimsTheChallengeBeforeMinting(t *testing.T) {
	ordering := newMFAOrderStore()
	clk := newMFAClock()
	mfaStore := memory.NewMFAStore()
	svc := auth.New(ordering,
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithMFAStore(mfaStore),
		auth.WithMFASecretCipher(testCipher{}),
		auth.WithClock(clk.now),
	)
	f := mfaFixture{svc: svc, store: ordering.AuthStore, mfa: mfaStore, clock: clk}
	e := enrolConfirmed(t, f, "quill@example.com")
	pending := loginOwingMFA(t, f, "quill@example.com")

	ordering.reset()
	if _, err := svc.CompleteMFA(context.Background(), pending.MFA.Token, e.recovery[0], "1.2.3.4", "agent"); err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}

	got := ordering.snapshot()
	want := []string{"DeleteVerification", "CreateSession"}
	if !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v — the claim must precede the session it authorizes", got, want)
	}
}

// TestCompleteMFADeterministicRaceAdmitsExactlyOneSession is the other half
// of mutation anchor (c), and it is deterministic by construction rather
// than by scheduler luck: caller #1 is parked holding a live, unburned
// challenge, and caller #2 then runs start to finish. Every run takes the
// identical path.
//
// The two callers present DIFFERENT recovery codes on purpose. With the
// same TOTP code, MFAStore.AdvanceStep would decide the race and the
// challenge's own burn would never be tested; with two valid, unspent
// recovery codes the burn is the only thing that can make one of them lose.
func TestCompleteMFADeterministicRaceAdmitsExactlyOneSession(t *testing.T) {
	inner := memory.NewAuthStore()
	clk := newMFAClock()
	mfaStore := memory.NewMFAStore()
	opts := []auth.Option{
		auth.WithHasher(password.Bcrypt(testCost)),
		auth.WithJWT([][]byte{testSigningKey}, 15*time.Minute),
		auth.WithMFAStore(mfaStore),
		auth.WithMFASecretCipher(testCipher{}),
		auth.WithClock(clk.now),
	}
	seed := mfaFixture{svc: auth.New(inner, opts...), store: inner, mfa: mfaStore, clock: clk}
	e := enrolConfirmed(t, seed, "rhea@example.com")
	pending := loginOwingMFA(t, seed, "rhea@example.com")

	parking := newParkOnVerificationLookupStore(inner)
	svc := auth.New(parking, opts...)
	ctx := context.Background()

	type result struct {
		res auth.LoginResult
		err error
	}
	firstDone := make(chan result, 1)
	go func() {
		res, err := svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[0], "1.1.1.1", "first")
		firstDone <- result{res, err}
	}()

	<-parking.parked // caller #1 holds the live challenge and cannot proceed

	secondRes, secondErr := svc.CompleteMFA(ctx, pending.MFA.Token, e.recovery[1], "2.2.2.2", "second")

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
		t.Fatalf("loser got tokens (%q/%q); the challenge was already claimed", first.res.AccessToken, first.res.RefreshToken)
	}

	// Direct, not inferred: exactly one session row was ever persisted.
	if n := parking.sessionInserts.Load(); n != 1 {
		t.Fatalf("CreateSession succeeded %d time(s), want exactly 1 — one challenge must never become two sessions", n)
	}
	sessions, err := inner.ListSessionsByUser(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want exactly 1", len(sessions))
	}
}

// TestCompleteMFAConcurrentSameChallengeExactlyOneWinner is the symmetric
// mass race beside the deterministic one: every goroutine runs the
// identical call with its own unspent recovery code, so the assertion is
// independent of the order they run in.
func TestCompleteMFAConcurrentSameChallengeExactlyOneWinner(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "sion@example.com")
	pending := loginOwingMFA(t, f, "sion@example.com")

	n := len(e.recovery)
	var wg sync.WaitGroup
	var mu sync.Mutex
	withTokens, notFound, other := 0, 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(code string) {
			defer wg.Done()
			res, err := f.svc.CompleteMFA(ctx, pending.MFA.Token, code, "1.2.3.4", "agent")
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
		}(e.recovery[i])
	}
	wg.Wait()

	if withTokens != 1 {
		t.Fatalf("completions yielding a session = %d, want exactly 1 (notFound=%d other=%d)", withTokens, notFound, other)
	}
	sessions, err := f.store.ListSessionsByUser(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions after %d concurrent completions = %d, want exactly 1", n, len(sessions))
	}
}

// TestCompleteMFAConcurrentSameTOTPCodeAdvancesOnce drives the replay guard
// under contention: N goroutines present the SAME code against N distinct
// challenges, which is an attacker submitting a captured code alongside the
// user's own. Exactly one may get in.
func TestCompleteMFAConcurrentSameTOTPCodeAdvancesOnce(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "tova@example.com")
	f.clock.advance(30 * time.Second)
	code := totpCodeAt(t, e.secret, f.clock.now())

	const n = 8
	challenges := make([]string, n)
	for i := range challenges {
		challenges[i] = loginOwingMFA(t, f, "tova@example.com").MFA.Token
	}

	var wg sync.WaitGroup
	var winners atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(tok string) {
			defer wg.Done()
			res, err := f.svc.CompleteMFA(ctx, tok, code, "1.2.3.4", "agent")
			if err == nil && res.AccessToken != "" {
				winners.Add(1)
			}
		}(challenges[i])
	}
	wg.Wait()

	if got := winners.Load(); got != 1 {
		t.Fatalf("concurrent presentations of one TOTP code that succeeded = %d, want exactly 1", got)
	}
	sessions, err := f.store.ListSessionsByUser(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want exactly 1", len(sessions))
	}
}

// --- DisableMFA ---

func TestDisableMFARequiresTheCurrentPassword(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	e := enrolConfirmed(t, f, "ulla@example.com")

	if err := f.svc.DisableMFA(ctx, e.user.ID, "not-the-password"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("DisableMFA with a wrong password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := f.mfa.FindFactor(ctx, e.user.ID); err != nil {
		t.Fatalf("the factor was removed by a refused DisableMFA: %v", err)
	}
	rows, err := f.mfa.ListRecoveryCodes(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListRecoveryCodes: %v", err)
	}
	if len(rows) != len(e.recovery) {
		t.Fatalf("recovery codes after a refused DisableMFA = %d, want %d", len(rows), len(e.recovery))
	}
	// Still gated.
	loginOwingMFA(t, f, "ulla@example.com")

	if err := f.svc.DisableMFA(ctx, e.user.ID, validPassword); err != nil {
		t.Fatalf("DisableMFA with the right password: %v", err)
	}
	if _, err := f.mfa.FindFactor(ctx, e.user.ID); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("FindFactor after DisableMFA = %v, want ErrFactorNotFound", err)
	}
	rows, err = f.mfa.ListRecoveryCodes(ctx, e.user.ID)
	if err != nil {
		t.Fatalf("ListRecoveryCodes: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("recovery codes after DisableMFA = %d, want 0 — they are live credentials on their own", len(rows))
	}

	res, err := f.svc.Login(ctx, "ulla@example.com", validPassword, "1.2.3.4", "agent")
	if err != nil {
		t.Fatalf("Login after DisableMFA: %v", err)
	}
	if res.MFA != nil || res.AccessToken == "" {
		t.Fatal("the account is still gated after DisableMFA")
	}
}

func TestDisableMFARefusesAnAccountWithNoPassword(t *testing.T) {
	f := newMFAService(t)
	ctx := context.Background()
	u, err := f.store.CreateUser(ctx, auth.UserBase{ID: "3f1a0d2e-0000-7000-8000-000000000001", Email: "vega@example.com", CreatedAt: f.clock.now(), UpdatedAt: f.clock.now()})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := f.svc.DisableMFA(ctx, u.ID, ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("DisableMFA on a passwordless account = %v, want ErrInvalidCredentials", err)
	}
}

func TestDisableMFAWithoutAFactorIsFactorNotFound(t *testing.T) {
	f := newMFAService(t)
	u := mustSignUp(t, f.svc, "wilf@example.com", validPassword)
	if err := f.svc.DisableMFA(context.Background(), u.ID, validPassword); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("DisableMFA with nothing enrolled = %v, want ErrFactorNotFound", err)
	}
}

func TestMFAEntryPointsRefuseWithoutAStore(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	u := mustSignUp(t, svc, "xander@example.com", validPassword)

	if _, _, err := svc.BeginMFAEnrolment(ctx, u.ID); !errors.Is(err, auth.ErrMFANotConfigured) {
		t.Fatalf("BeginMFAEnrolment = %v, want ErrMFANotConfigured", err)
	}
	if _, err := svc.ConfirmMFAEnrolment(ctx, u.ID, "123456"); !errors.Is(err, auth.ErrMFANotConfigured) {
		t.Fatalf("ConfirmMFAEnrolment = %v, want ErrMFANotConfigured", err)
	}
	if err := svc.DisableMFA(ctx, u.ID, validPassword); !errors.Is(err, auth.ErrMFANotConfigured) {
		t.Fatalf("DisableMFA = %v, want ErrMFANotConfigured", err)
	}
}
