package auth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// recordingHook is an auth.Hook that keeps every Event it sees, for tests
// to take and assert on. It returns nil, as the docs recommend a
// best-effort hook does.
type recordingHook struct {
	mu     sync.Mutex
	events []auth.Event
}

func (r *recordingHook) On(_ context.Context, e auth.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

// take returns everything recorded since the last take, and clears it.
func (r *recordingHook) take() []auth.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.events
	r.events = nil
	return out
}

// anySession is the SessionID a want-Event carries to mean "non-empty, any
// value" — for the paths that mint a session whose id the test cannot know
// in advance.
const anySession = "*"

// wantEvents asserts got is exactly want, in order, comparing Kind, UserID,
// SessionID (with the anySession wildcard), IP, UserAgent and Detail, and
// that every At is set.
func wantEvents(t *testing.T, got []auth.Event, want ...auth.Event) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d event(s) %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Kind != w.Kind || g.UserID != w.UserID || g.IP != w.IP || g.UserAgent != w.UserAgent || g.Detail != w.Detail {
			t.Fatalf("event %d = %+v, want %+v", i, g, w)
		}
		switch {
		case w.SessionID == anySession && g.SessionID == "":
			t.Fatalf("event %d = %+v, want a non-empty SessionID", i, g)
		case w.SessionID != anySession && g.SessionID != w.SessionID:
			t.Fatalf("event %d SessionID = %q, want %q", i, g.SessionID, w.SessionID)
		}
		if g.At.IsZero() {
			t.Fatalf("event %d = %+v has a zero At; the Service clock must stamp it", i, g)
		}
	}
}

// assertNoAddress pins the enumeration rule on the Event itself: no field
// of any recorded event carries an email address.
func assertNoAddress(t *testing.T, events []auth.Event) {
	t.Helper()
	for _, e := range events {
		for _, field := range []string{e.UserID, e.SessionID, e.IP, e.UserAgent, e.Detail} {
			if strings.Contains(field, "@") {
				t.Fatalf("event %+v carries an address in one of its fields", e)
			}
		}
	}
}

// TestHooksEmitEveryKind drives every entry point that emits, on one Service
// with every optional port wired, and asserts the kind and fields of each
// event — and, between the emitting steps, that the enumeration-hardened
// request paths emit nothing. The hook returns nil throughout, so this also
// proves the Service's own results and errors are exactly what they are
// without hooks.
func TestHooksEmitEveryKind(t *testing.T) {
	rec := &recordingHook{}
	ids := memory.NewIdentityStore()
	creds := memory.NewCredentialStore()
	f := newMFAService(t, auth.WithHooks(rec), auth.WithIdentityStore(ids), auth.WithCredentialStore(creds))
	svc := f.svc
	ctx := context.Background()
	const ip, ua = "203.0.113.9", "hooks-agent"
	password := validPassword

	// -- SignUp: the created branch emits, the duplicate branch does not --
	res, err := svc.SignUp(ctx, "hooks@example.com", password)
	if err != nil || !res.Created {
		t.Fatalf("SignUp: created=%v err=%v", res.Created, err)
	}
	u := res.User
	wantEvents(t, rec.take(), auth.Event{Kind: auth.SignedUp, UserID: u.ID, Detail: auth.DetailPassword})

	dup, err := svc.SignUp(ctx, "hooks@example.com", password)
	if err != nil || dup.Created {
		t.Fatalf("duplicate SignUp: created=%v err=%v", dup.Created, err)
	}
	wantEvents(t, rec.take())

	// -- VerifyEmail (signup) --
	if _, err := svc.VerifyEmail(ctx, res.VerifyToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.EmailVerified, UserID: u.ID})

	// -- Login failures: every detail, never the address --
	if _, err := svc.Login(ctx, "hooks@example.com", "Wrong-Password-Entirely-1!", ip, ua); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login(wrong password) = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.Login(ctx, "nobody@example.com", password, ip, ua); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login(unknown) = %v, want ErrInvalidCredentials", err)
	}
	failures := rec.take()
	wantEvents(t, failures,
		auth.Event{Kind: auth.LoginFailed, UserID: u.ID, IP: ip, UserAgent: ua, Detail: auth.DetailWrongPassword},
		auth.Event{Kind: auth.LoginFailed, UserID: "", IP: ip, UserAgent: ua, Detail: auth.DetailUnknownUser},
	)
	assertNoAddress(t, failures)

	// -- Login, Refresh, reuse --
	login, err := svc.Login(ctx, "hooks@example.com", password, ip, ua)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	sid := sessionIDOf(t, svc, login.AccessToken)
	wantEvents(t, rec.take(), auth.Event{Kind: auth.LoggedIn, UserID: u.ID, SessionID: sid, IP: ip, UserAgent: ua, Detail: auth.DetailPassword})

	next, err := svc.Refresh(ctx, login.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	nextSID := sessionIDOf(t, svc, next.AccessToken)
	wantEvents(t, rec.take(), auth.Event{Kind: auth.SessionRefreshed, UserID: u.ID, SessionID: nextSID, IP: ip, UserAgent: ua})

	if _, err := svc.Refresh(ctx, login.RefreshToken); !errors.Is(err, auth.ErrTokenReuse) {
		t.Fatalf("Refresh(replayed) = %v, want ErrTokenReuse", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.TokenReuseDetected, UserID: u.ID, SessionID: sid, IP: ip, UserAgent: ua, Detail: auth.DetailReuse})

	// -- Logout of a current token; Logout of a superseded one --
	login2, err := svc.Login(ctx, "hooks@example.com", password, ip, ua)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	sid2 := sessionIDOf(t, svc, login2.AccessToken)
	rec.take()
	if err := svc.Logout(ctx, login2.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.LoggedOut, UserID: u.ID, SessionID: sid2, IP: ip, UserAgent: ua})
	if err := svc.Logout(ctx, login2.RefreshToken); err != nil {
		t.Fatalf("Logout(again): %v", err)
	}
	wantEvents(t, rec.take()) // idempotent no-op: nothing changed, nothing emitted

	login3, err := svc.Login(ctx, "hooks@example.com", password, ip, ua)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	sid3 := sessionIDOf(t, svc, login3.AccessToken)
	if _, err := svc.Refresh(ctx, login3.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	rec.take()
	if err := svc.Logout(ctx, login3.RefreshToken); err != nil { // superseded token
		t.Fatalf("Logout(superseded): %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.TokenReuseDetected, UserID: u.ID, SessionID: sid3, IP: ip, UserAgent: ua, Detail: auth.DetailReuse})

	// -- RevokeSession, LogoutAll --
	login4, err := svc.Login(ctx, "hooks@example.com", password, ip, ua)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	sid4 := sessionIDOf(t, svc, login4.AccessToken)
	rec.take()
	if err := svc.RevokeSession(ctx, u.ID, sid4); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.SessionRevoked, UserID: u.ID, SessionID: sid4, IP: ip, UserAgent: ua})

	if _, err := svc.Login(ctx, "hooks@example.com", password, ip, ua); err != nil {
		t.Fatalf("Login: %v", err)
	}
	rec.take()
	if err := svc.LogoutAll(ctx, u.ID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.LoggedOutAll, UserID: u.ID})

	// -- ChangePassword --
	login5, err := svc.Login(ctx, "hooks@example.com", password, ip, ua)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	sid5 := sessionIDOf(t, svc, login5.AccessToken)
	rec.take()
	password = "Another-Valid-Pass22!"
	if err := svc.ChangePassword(ctx, u.ID, sid5, validPassword, password); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.PasswordChanged, UserID: u.ID, SessionID: sid5})

	// -- RequestPasswordReset emits nothing; ResetPassword emits --
	resetTok, ok, err := svc.RequestPasswordReset(ctx, "hooks@example.com", ip)
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset: ok=%v err=%v", ok, err)
	}
	if _, _, err := svc.RequestPasswordReset(ctx, "nobody@example.com", ip); err != nil {
		t.Fatalf("RequestPasswordReset(unknown): %v", err)
	}
	wantEvents(t, rec.take())
	password = "Third-Valid-Password-33!"
	if err := svc.ResetPassword(ctx, resetTok, password); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.PasswordReset, UserID: u.ID})

	// -- RequestEmailChange emits nothing; its redemption emits two --
	changeTok, err := svc.RequestEmailChange(ctx, u.ID, "", password, "moved@example.com")
	if err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	wantEvents(t, rec.take())
	if _, err := svc.VerifyEmail(ctx, changeTok); err != nil {
		t.Fatalf("VerifyEmail(email_change): %v", err)
	}
	wantEvents(t, rec.take(),
		auth.Event{Kind: auth.EmailChanged, UserID: u.ID},
		auth.Event{Kind: auth.EmailVerified, UserID: u.ID},
	)
	email := "moved@example.com"

	// -- RequestMagicLink emits nothing; RedeemMagicLink emits, then LoggedIn --
	linkTok, ok, err := svc.RequestMagicLink(ctx, email, ip)
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink: ok=%v err=%v", ok, err)
	}
	if _, _, err := svc.RequestMagicLink(ctx, "nobody@example.com", ip); err != nil {
		t.Fatalf("RequestMagicLink(unknown): %v", err)
	}
	wantEvents(t, rec.take())
	redeemed, err := svc.RedeemMagicLink(ctx, linkTok, ip, ua)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	wantEvents(t, rec.take(),
		auth.Event{Kind: auth.MagicLinkRedeemed, UserID: u.ID, IP: ip, UserAgent: ua},
		auth.Event{Kind: auth.LoggedIn, UserID: u.ID, SessionID: sessionIDOf(t, svc, redeemed.AccessToken), IP: ip, UserAgent: ua, Detail: auth.DetailMagicLink},
	)

	// -- LinkIdentity, UnlinkIdentity --
	if _, err := svc.LinkIdentity(ctx, u.ID, googleExt(email, true)); err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.IdentityLinked, UserID: u.ID})
	if err := svc.UnlinkIdentity(ctx, u.ID, "google"); err != nil {
		t.Fatalf("UnlinkIdentity: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.IdentityUnlinked, UserID: u.ID})

	// -- SignInWith provisioning: SignedUp, IdentityLinked, LoggedIn --
	ext := auth.ExternalIdentity{Provider: "github", Subject: "gh-42", Email: "new-via-github@example.com", EmailVerified: true}
	signed, err := svc.SignInWith(ctx, auth.SignInRequest{Identity: ext, IP: ip, UserAgent: ua})
	if err != nil || !signed.Created {
		t.Fatalf("SignInWith: created=%v err=%v", signed.Created, err)
	}
	wantEvents(t, rec.take(),
		auth.Event{Kind: auth.SignedUp, UserID: signed.User.ID, IP: ip, UserAgent: ua, Detail: auth.DetailExternalIdentity},
		auth.Event{Kind: auth.IdentityLinked, UserID: signed.User.ID, IP: ip, UserAgent: ua},
		auth.Event{Kind: auth.LoggedIn, UserID: signed.User.ID, SessionID: anySession, IP: ip, UserAgent: ua, Detail: auth.DetailExternalIdentity},
	)
	// A second sign-in through the linked identity: LoggedIn only.
	if _, err := svc.SignInWith(ctx, auth.SignInRequest{Identity: ext, IP: ip, UserAgent: ua}); err != nil {
		t.Fatalf("SignInWith(again): %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.LoggedIn, UserID: signed.User.ID, SessionID: anySession, IP: ip, UserAgent: ua, Detail: auth.DetailExternalIdentity})

	// -- Passkeys: register, log in, fail, delete --
	if _, err := svc.BeginPasskeyRegistration(ctx, u.ID); err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	wantEvents(t, rec.take())
	cred := registerPasskey(t, svc, u.ID, newCred('h'))
	wantEvents(t, rec.take(), auth.Event{Kind: auth.PasskeyRegistered, UserID: u.ID})

	challenge := mustBeginLogin(t, svc)
	wantEvents(t, rec.take())
	pk, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{Challenge: challenge, CredentialID: credID('h'), SignCount: 1}, ip, ua)
	if err != nil {
		t.Fatalf("FinishPasskeyLogin: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.LoggedIn, UserID: u.ID, SessionID: sessionIDOf(t, svc, pk.AccessToken), IP: ip, UserAgent: ua, Detail: auth.DetailPasskey})

	if _, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{Challenge: mustBeginLogin(t, svc), CredentialID: credID('z'), SignCount: 1}, ip, ua); !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("FinishPasskeyLogin(unknown credential) = %v, want ErrCredentialNotFound", err)
	}
	if _, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{Challenge: "never-issued", CredentialID: credID('h'), SignCount: 2}, ip, ua); !errors.Is(err, auth.ErrChallengeNotFound) {
		t.Fatalf("FinishPasskeyLogin(bad challenge) = %v, want ErrChallengeNotFound", err)
	}
	if _, err := svc.FinishPasskeyLogin(ctx, auth.VerifiedAssertion{Challenge: mustBeginLogin(t, svc), CredentialID: credID('h'), SignCount: 1}, ip, ua); !errors.Is(err, auth.ErrClonedAuthenticator) {
		t.Fatalf("FinishPasskeyLogin(stale counter) = %v, want ErrClonedAuthenticator", err)
	}
	wantEvents(t, rec.take(),
		auth.Event{Kind: auth.LoginFailed, UserID: "", IP: ip, UserAgent: ua, Detail: auth.DetailPasskeyUnknown},
		auth.Event{Kind: auth.LoginFailed, UserID: u.ID, IP: ip, UserAgent: ua, Detail: auth.DetailPasskeyChallengeInvalid},
		auth.Event{Kind: auth.LoginFailed, UserID: u.ID, IP: ip, UserAgent: ua, Detail: auth.DetailClonedAuthenticator},
	)

	if err := svc.DeletePasskey(ctx, u.ID, cred.ID); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.PasskeyDeleted, UserID: u.ID})

	// -- MFA: enrol, challenge, wrong code, complete, trust, revoke, disable --
	secret, _, err := svc.BeginMFAEnrolment(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginMFAEnrolment: %v", err)
	}
	wantEvents(t, rec.take())
	if _, err := svc.ConfirmMFAEnrolment(ctx, u.ID, totpCodeAt(t, secret, f.clock.now())); err != nil {
		t.Fatalf("ConfirmMFAEnrolment: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.MFAEnrolled, UserID: u.ID})

	f.clock.advance(30 * time.Second)
	pending, err := svc.Login(ctx, email, password, ip, ua)
	if err != nil || pending.MFA == nil {
		t.Fatalf("Login owing MFA: mfa=%v err=%v", pending.MFA, err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.MFAChallenged, UserID: u.ID, IP: ip, UserAgent: ua})

	if _, err := svc.CompleteMFA(ctx, pending.MFA.Token, "000000", ip, ua); !errors.Is(err, auth.ErrMFACodeInvalid) {
		t.Fatalf("CompleteMFA(wrong code) = %v, want ErrMFACodeInvalid", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.LoginFailed, UserID: u.ID, IP: ip, UserAgent: ua, Detail: auth.DetailMFACodeInvalid})

	done, err := svc.CompleteMFA(ctx, pending.MFA.Token, totpCodeAt(t, secret, f.clock.now()), ip, ua)
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	fresh := sessionIDOf(t, svc, done.AccessToken)
	wantEvents(t, rec.take(), auth.Event{Kind: auth.LoggedIn, UserID: u.ID, SessionID: fresh, IP: ip, UserAgent: ua, Detail: auth.DetailMFA})

	device, err := svc.TrustThisDevice(ctx, u.ID, fresh, "laptop")
	if err != nil {
		t.Fatalf("TrustThisDevice: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.DeviceTrusted, UserID: u.ID, SessionID: fresh})

	trusted, err := svc.LoginWithTrustedDevice(ctx, email, password, ip, ua, device)
	if err != nil || trusted.MFA != nil {
		t.Fatalf("LoginWithTrustedDevice: mfa=%v err=%v", trusted.MFA, err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.LoggedIn, UserID: u.ID, SessionID: sessionIDOf(t, svc, trusted.AccessToken), IP: ip, UserAgent: ua, Detail: auth.DetailTrustedDevice})

	devices := devicesOf(t, f, u.ID)
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}
	if err := svc.RevokeTrustedDevice(ctx, u.ID, devices[0].ID); err != nil {
		t.Fatalf("RevokeTrustedDevice: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.TrustedDeviceRevoked, UserID: u.ID})

	if err := svc.DisableMFA(ctx, u.ID, fresh, password); err != nil {
		t.Fatalf("DisableMFA: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.MFADisabled, UserID: u.ID, SessionID: fresh})

	// -- The two endings --
	if err := svc.AnonymizeAccount(ctx, signed.User.ID, "", ""); err != nil {
		t.Fatalf("AnonymizeAccount: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.AccountAnonymized, UserID: signed.User.ID})

	if err := svc.DeleteAccount(ctx, u.ID, fresh, password); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	wantEvents(t, rec.take(), auth.Event{Kind: auth.AccountDeleted, UserID: u.ID, SessionID: fresh})
}

// TestLoginFailedUnderEnforcementAndUnverified covers the two LoginFailed
// details the sequence above cannot reach on one Service: an unverified
// address under WithRequireVerifiedEmail, and a missing factor under
// EnforcementRequired. Neither event carries the address.
func TestLoginFailedUnderEnforcementAndUnverified(t *testing.T) {
	ctx := context.Background()

	rec := &recordingHook{}
	svc, _ := newTestService(t, auth.WithHooks(rec), auth.WithRequireVerifiedEmail(true))
	u := mustSignUp(t, svc, "unverified@example.com", validPassword)
	rec.take()
	if _, err := svc.Login(ctx, "unverified@example.com", validPassword, "1.2.3.4", "ua"); !errors.Is(err, auth.ErrEmailNotVerified) {
		t.Fatalf("Login = %v, want ErrEmailNotVerified", err)
	}
	got := rec.take()
	wantEvents(t, got, auth.Event{Kind: auth.LoginFailed, UserID: u.ID, IP: "1.2.3.4", UserAgent: "ua", Detail: auth.DetailEmailNotVerified})
	assertNoAddress(t, got)

	rec2 := &recordingHook{}
	f := newMFAService(t, auth.WithHooks(rec2), auth.WithMFAEnforcement(auth.EnforcementRequired))
	u2 := mustSignUp(t, f.svc, "nofactor@example.com", validPassword)
	rec2.take()
	if _, err := f.svc.Login(ctx, "nofactor@example.com", validPassword, "1.2.3.4", "ua"); !errors.Is(err, auth.ErrMFARequired) {
		t.Fatalf("Login = %v, want ErrMFARequired", err)
	}
	got = rec2.take()
	wantEvents(t, got, auth.Event{Kind: auth.LoginFailed, UserID: u2.ID, IP: "1.2.3.4", UserAgent: "ua", Detail: auth.DetailMFARequired})
	assertNoAddress(t, got)

	// An anonymized account is a distinct detail to the hook and the same
	// ErrInvalidCredentials to the caller. AnonymizeAccount itself scrubs
	// the address, so a login by the old one is an ordinary unknown user;
	// the stamped-row branch is defence in depth, reached only when a row
	// is stamped by another route — so this stamps it directly, keeping the
	// address findable, exactly as such a route would.
	rec3 := &recordingHook{}
	svc3, store3 := newTestService(t, auth.WithHooks(rec3))
	u3 := mustSignUp(t, svc3, "gone@example.com", validPassword)
	if err := store3.MarkUserDeleted(ctx, u3.ID, "gone@example.com", time.Now().UTC()); err != nil {
		t.Fatalf("MarkUserDeleted: %v", err)
	}
	rec3.take()
	if _, err := svc3.Login(ctx, "gone@example.com", validPassword, "1.2.3.4", "ua"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login(anonymized) = %v, want ErrInvalidCredentials", err)
	}
	wantEvents(t, rec3.take(), auth.Event{Kind: auth.LoginFailed, UserID: u3.ID, IP: "1.2.3.4", UserAgent: "ua", Detail: auth.DetailAccountAnonymized})
}

// TestHardenedRequestPathsEmitNothing pins the enumeration note as a
// property of its own: RequestPasswordReset, RequestMagicLink (with and
// without provisioning) and RequestEmailChange emit nothing on any branch,
// and SignUp's duplicate branch emits nothing — so a hook cannot become the
// oracle those methods are built to deny.
func TestHardenedRequestPathsEmitNothing(t *testing.T) {
	ctx := context.Background()
	rec := &recordingHook{}
	svc, _ := newTestService(t, auth.WithHooks(rec), auth.WithMagicLinkProvisioning(true))
	u := mustSignUp(t, svc, "quiet@example.com", validPassword)
	rec.take()

	if _, err := svc.SignUp(ctx, "quiet@example.com", validPassword); err != nil {
		t.Fatalf("duplicate SignUp: %v", err)
	}
	for _, email := range []string{"quiet@example.com", "unknown@example.com"} {
		if _, _, err := svc.RequestPasswordReset(ctx, email, "1.2.3.4"); err != nil {
			t.Fatalf("RequestPasswordReset(%q): %v", email, err)
		}
	}
	// With provisioning on, the unknown branch CREATES an account — and
	// still emits nothing, not even SignedUp.
	for _, email := range []string{"quiet@example.com", "provisioned@example.com"} {
		if _, _, err := svc.RequestMagicLink(ctx, email, "1.2.3.4"); err != nil {
			t.Fatalf("RequestMagicLink(%q): %v", email, err)
		}
	}
	if _, err := svc.RequestEmailChange(ctx, u.ID, "", validPassword, "elsewhere@example.com"); err != nil {
		t.Fatalf("RequestEmailChange: %v", err)
	}
	if _, err := svc.RequestEmailChange(ctx, u.ID, "", "Wrong-Password-Entirely-1!", "elsewhere@example.com"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("RequestEmailChange(wrong password) = %v, want ErrInvalidCredentials", err)
	}

	if got := rec.take(); len(got) != 0 {
		t.Fatalf("the hardened request paths emitted %d event(s): %+v; want none", len(got), got)
	}
	if _, err := svc.User(ctx, u.ID); err != nil {
		t.Fatalf("User: %v", err)
	}
}

// TestLoginHookErrorPropagatesWithTheSessionLive documents the consequence
// the Hook doc states: the session row is persisted BEFORE the LoggedIn hook
// runs, so a hook that fails leaves a live session the caller never received
// a token for, and Login returns the hook's error.
func TestLoginHookErrorPropagatesWithTheSessionLive(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("audit sink is down")
	failing := auth.HookFunc(func(_ context.Context, e auth.Event) error {
		if e.Kind == auth.LoggedIn {
			return boom
		}
		return nil
	})
	svc, store := newTestService(t, auth.WithHooks(failing))
	u := mustSignUp(t, svc, "live@example.com", validPassword)

	res, err := svc.Login(ctx, "live@example.com", validPassword, "1.2.3.4", "ua")
	if !errors.Is(err, boom) {
		t.Fatalf("Login = %v, want the hook's error", err)
	}
	if res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("Login returned tokens alongside the error: %+v", res)
	}
	sessions, err := store.ListSessionsByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions after a failed LoggedIn hook = %d, want 1: the row is persisted before the hook runs, and that is the documented cost", len(sessions))
	}
}

// TestFailureHookErrorIsJoinedToTheRefusal pins the rule for failure
// events: a hook error on LoginFailed does not replace ErrInvalidCredentials
// — the caller sees both — and a nil-returning hook leaves the error exactly
// as it was.
func TestFailureHookErrorIsJoinedToTheRefusal(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("audit sink is down")
	svc, _ := newTestService(t, auth.WithHooks(auth.HookFunc(func(_ context.Context, e auth.Event) error {
		if e.Kind == auth.LoginFailed {
			return boom
		}
		return nil
	})))
	mustSignUp(t, svc, "joined@example.com", validPassword)

	_, err := svc.Login(ctx, "joined@example.com", "Wrong-Password-Entirely-1!", "1.2.3.4", "ua")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login = %v, want it to still be ErrInvalidCredentials", err)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("Login = %v, want the hook's error joined", err)
	}

	quiet, _ := newTestService(t, auth.WithHooks(auth.HookFunc(func(context.Context, auth.Event) error { return nil })))
	mustSignUp(t, quiet, "quiet2@example.com", validPassword)
	_, err = quiet.Login(ctx, "quiet2@example.com", "Wrong-Password-Entirely-1!", "1.2.3.4", "ua")
	if err != auth.ErrInvalidCredentials { //nolint:errorlint // the point is identity: a nil hook must leave the sentinel unwrapped
		t.Fatalf("Login with a nil-returning hook = %#v, want the bare ErrInvalidCredentials", err)
	}
}

// TestWithHooksAccumulatesSkipsNilAndStampsAt pins the option's shape: it
// appends across calls in order, ignores nil, and At comes from the Service
// clock.
func TestWithHooksAccumulatesSkipsNilAndStampsAt(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	var order []string
	first := auth.HookFunc(func(_ context.Context, e auth.Event) error {
		order = append(order, "first")
		if !e.At.Equal(fixed) {
			t.Fatalf("At = %v, want the Service clock's %v", e.At, fixed)
		}
		return nil
	})
	second := auth.HookFunc(func(context.Context, auth.Event) error { order = append(order, "second"); return nil })
	svc, _ := newTestService(t,
		auth.WithHooks(first, nil),
		auth.WithHooks(second),
		auth.WithClock(func() time.Time { return fixed }),
	)
	if _, err := svc.SignUp(ctx, "order@example.com", validPassword); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("hook order = %v, want [first second]", order)
	}
}
