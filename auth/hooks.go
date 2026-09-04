package auth

import (
	"context"
	"errors"
	"time"
)

// EventKind identifies a lifecycle event this package emits to the [Hook]s
// registered with [WithHooks]. The shape mirrors
// [github.com/bernardoforcillo/authlayer/scope.EventKind] exactly, so one
// audit sink can consume both packages' events with the same plumbing.
type EventKind int

// The lifecycle events Service emits. Each constant's comment names the
// entry points that emit it and which optional [Event] fields carry a value.
// Every kind is emitted AFTER the mutation it describes has succeeded and
// BEFORE the method returns — see [Hook] for what that means when a hook
// fails — and no kind is emitted from an entry point that is
// enumeration-hardened; see [WithHooks], "What deliberately emits nothing".
const (
	// SignedUp is emitted by [Service.SignUp] on the Created==true branch
	// ONLY — the duplicate-address branch emits nothing, deliberately (see
	// [WithHooks]) — and by [Service.SignInWith] when it PROVISIONS an
	// account for an external identity nobody held. UserID is the new
	// account; Detail is [DetailPassword] or [DetailExternalIdentity], which
	// door created it. Not emitted for an account [Service.RequestMagicLink]
	// provisions under [WithMagicLinkProvisioning]: that method is
	// enumeration-hardened and emits nothing on either branch, so such an
	// account's first event is the [MagicLinkRedeemed] that signs it in.
	SignedUp EventKind = iota
	// EmailVerified is emitted by [Service.VerifyEmail] for both purposes
	// it redeems — the address was certified either way — after
	// [EmailChanged] on the email_change branch. UserID only.
	EmailVerified
	// LoggedIn is emitted by every path that MINTS a session: [Service.Login]
	// and [Service.LoginWithTrustedDevice] (completed, no challenge
	// outstanding), [Service.CompleteMFA], [Service.RedeemMagicLink],
	// [Service.SignInWith] and [Service.FinishPasskeyLogin]. UserID,
	// SessionID (the new root session), IP and UserAgent are all set; Detail
	// names the door — [DetailPassword], [DetailTrustedDevice], [DetailMFA],
	// [DetailMagicLink], [DetailExternalIdentity] or [DetailPasskey]. Not
	// emitted by [Service.Refresh], which rotates rather than signs in — see
	// [SessionRefreshed].
	LoggedIn
	// LoginFailed is emitted when an authentication attempt is refused on
	// its credentials: [Service.Login] / [Service.LoginWithTrustedDevice] for
	// an unknown address ([DetailUnknownUser], with UserID ""), an anonymized
	// account ([DetailAccountAnonymized]), an account with no password
	// credential ([DetailNoPassword]), a wrong password ([DetailWrongPassword]),
	// an unverified address under [WithRequireVerifiedEmail]
	// ([DetailEmailNotVerified]) or a missing factor under
	// [EnforcementRequired] ([DetailMFARequired]); [Service.CompleteMFA] for
	// a code that does not authenticate ([DetailMFACodeInvalid]);
	// [Service.FinishPasskeyLogin] for an unknown credential
	// ([DetailPasskeyUnknown], UserID ""), a challenge that would not claim
	// ([DetailPasskeyChallengeInvalid]) or a counter that did not advance
	// ([DetailClonedAuthenticator]). IP and UserAgent are set where the
	// entry point had them. The attempted email address is NEVER on the
	// Event — not in Detail, not anywhere — see [WithHooks]. Not emitted for
	// [ErrMissingIP] or [ErrRateLimited]: those refusals happen before any
	// credential is looked at, and a per-attempt hook there would be a hook
	// the limiter exists to spare the deployment from.
	LoginFailed
	// MFAChallenged is emitted when a sign-in stops at a second-factor
	// challenge instead of a session: [Service.Login],
	// [Service.RedeemMagicLink] and [Service.SignInWith]. UserID, IP and
	// UserAgent where the entry point had them; no SessionID, because no
	// session exists.
	MFAChallenged
	// SessionRefreshed is emitted by [Service.Refresh] once the successor
	// session is persisted. UserID; SessionID is the NEW session; IP and
	// UserAgent are the ones the successor inherited from its predecessor —
	// the login that started the family, not the device that just rotated
	// (see Refresh's own note on those fields).
	SessionRefreshed
	// TokenReuseDetected is emitted by [Service.Refresh] when a rotated-away
	// token was presented again and the family has been revoked — after
	// [Store.DeleteSessionsByFamily] succeeded, so a revocation that failed
	// emits nothing and the caller's error says why — and by [Service.Logout]
	// presented a superseded token, which carries the same signal and takes
	// the same action. UserID; SessionID is the superseded session that was
	// replayed; IP and UserAgent are that session's; Detail is [DetailReuse].
	TokenReuseDetected
	// LoggedOut is emitted by [Service.Logout] when it removed a current
	// session's row. UserID and SessionID. An unknown or already-removed
	// token emits nothing, since nothing changed.
	LoggedOut
	// LoggedOutAll is emitted by [Service.LogoutAll] after every family and
	// every swept verification and trusted device is gone. UserID only.
	LoggedOutAll
	// SessionRevoked is emitted by [Service.RevokeSession] once the named
	// session's family is revoked. UserID; SessionID is the session the
	// caller named, not every row of the family.
	SessionRevoked
	// PasswordChanged is emitted by [Service.ChangePassword] after the
	// credential is written and every other family revoked. UserID;
	// SessionID is the caller's own, spared session.
	PasswordChanged
	// PasswordReset is emitted by [Service.ResetPassword] when a reset
	// completes. UserID only — the flow has no session of its own.
	PasswordReset
	// EmailChanged is emitted by [Service.VerifyEmail] when an email_change
	// token is redeemed and the address has moved, before the
	// [EmailVerified] the same redemption emits. UserID only; neither address
	// is on the Event.
	EmailChanged
	// MagicLinkRedeemed is emitted by [Service.RedeemMagicLink] once the link
	// is burned and the account has passed its checks, BEFORE the second
	// factor is consulted — so it is followed by either [MFAChallenged] or
	// [LoggedIn]. UserID, IP and UserAgent.
	MagicLinkRedeemed
	// IdentityLinked is emitted whenever an external identity row is
	// created: [Service.LinkIdentity], and [Service.SignInWith] on both the
	// provisioning and the implicit-link rung. UserID only; the provider is
	// not on the Event (see [Event.Detail]) — a hook that needs it lists
	// the account's identities.
	IdentityLinked
	// IdentityUnlinked is emitted by [Service.UnlinkIdentity] after the
	// identity is removed and every session revoked. UserID only.
	IdentityUnlinked
	// MFAEnrolled is emitted by [Service.ConfirmMFAEnrolment] once the
	// factor is confirmed and its recovery codes stored. UserID only.
	// [Service.BeginMFAEnrolment] emits nothing: an unconfirmed factor is,
	// for every purpose, no factor.
	MFAEnrolled
	// MFADisabled is emitted by [Service.DisableMFA] after the factor and
	// its codes are gone. UserID; SessionID is the caller's own.
	MFADisabled
	// PasskeyRegistered is emitted by [Service.FinishPasskeyRegistration].
	// UserID; SessionID is the caller's own.
	PasskeyRegistered
	// PasskeyDeleted is emitted by [Service.DeletePasskey] once the row is
	// gone. UserID only.
	PasskeyDeleted
	// DeviceTrusted is emitted by [Service.TrustThisDevice]. UserID;
	// SessionID is the session that vouched.
	DeviceTrusted
	// TrustedDeviceRevoked is emitted by [Service.RevokeTrustedDevice].
	// UserID only.
	TrustedDeviceRevoked
	// AccountDeleted is emitted by [Service.DeleteAccount] after the user row
	// is gone — the LAST thing that method does, so the hook sees an id
	// nothing in this package can resolve any more. UserID; SessionID is the
	// caller's own, already revoked.
	AccountDeleted
	// AccountAnonymized is emitted by [Service.AnonymizeAccount] after the
	// row is scrubbed and stamped. UserID; SessionID is the caller's own,
	// already revoked.
	AccountAnonymized
)

// The closed vocabulary [Event.Detail] draws from. It is exported so a hook
// can switch on it, and it is the ONLY thing that field ever carries — never
// an address, never a token, never caller input.
const (
	// DetailPassword: the door was a password ([Service.Login] with no
	// trusted device standing in for a factor; [Service.SignUp]).
	DetailPassword = "password"
	// DetailTrustedDevice: [Service.LoginWithTrustedDevice] let a trusted
	// device stand in for the second factor.
	DetailTrustedDevice = "trusted_device"
	// DetailMFA: [Service.CompleteMFA] finished a challenged login.
	DetailMFA = "mfa"
	// DetailMagicLink: [Service.RedeemMagicLink].
	DetailMagicLink = "magic_link"
	// DetailExternalIdentity: [Service.SignInWith].
	DetailExternalIdentity = "external_identity"
	// DetailPasskey: [Service.FinishPasskeyLogin].
	DetailPasskey = "passkey"

	// DetailUnknownUser: the address named no account. UserID is "".
	DetailUnknownUser = "unknown_user"
	// DetailAccountAnonymized: the account is stamped [UserBase.DeletedAt];
	// the caller was told [ErrInvalidCredentials], exactly as for an
	// unknown address.
	DetailAccountAnonymized = "account_anonymized"
	// DetailNoPassword: the account holds no password credential — an
	// external-identity-only or magic-link-only account was asked for one.
	DetailNoPassword = "no_password"
	// DetailWrongPassword: the password did not verify.
	DetailWrongPassword = "wrong_password"
	// DetailEmailNotVerified: the password verified but
	// [WithRequireVerifiedEmail] refused an unconfirmed address.
	DetailEmailNotVerified = "email_not_verified"
	// DetailMFARequired: the password verified but [EnforcementRequired]
	// found no confirmed factor.
	DetailMFARequired = "mfa_required"
	// DetailMFACodeInvalid: the TOTP or recovery code did not authenticate.
	DetailMFACodeInvalid = "mfa_code_invalid"
	// DetailPasskeyUnknown: the assertion named a credential id this
	// deployment does not hold. UserID is "".
	DetailPasskeyUnknown = "passkey_unknown_credential"
	// DetailPasskeyChallengeInvalid: the ceremony's challenge was unknown,
	// expired, for the other ceremony, or already claimed.
	DetailPasskeyChallengeInvalid = "passkey_challenge_invalid"
	// DetailClonedAuthenticator: the signature counter did not advance —
	// [ErrClonedAuthenticator].
	DetailClonedAuthenticator = "cloned_authenticator"
	// DetailReuse: a rotated-away refresh token was presented again.
	DetailReuse = "reuse"
)

// Event describes a lifecycle mutation for hooks (audit, webhooks, cache
// invalidation, outbox). Which optional fields carry a value depends on the
// kind — see each [EventKind] constant. It deliberately carries no email
// address and no token: every field is either an id, an audit stamp, or a
// word from the closed [Detail] vocabulary.
type Event struct {
	// Kind is which mutation occurred.
	Kind EventKind
	// UserID is the account the event concerns. Empty on exactly two
	// [LoginFailed] details, [DetailUnknownUser] and [DetailPasskeyUnknown],
	// where there was no account to name.
	UserID string
	// SessionID is set when a session is involved: the one minted, rotated
	// to, removed, replayed, or — on a step-up-gated method — the caller's
	// own.
	SessionID string
	// IP is the caller's address, when the entry point had one. Never the
	// key of a rate-limit decision — no event is emitted for those.
	IP string
	// UserAgent is the caller's user agent, when the entry point had one.
	UserAgent string
	// Detail is a word from the closed vocabulary above — the door a login
	// came through, or why an attempt failed. Never free text, and never an
	// email address: a [LoginFailed] for an unknown address says
	// "unknown_user" and nothing about which address was tried.
	Detail string
	// At is the event time, stamped from the Service clock if left zero —
	// so a hook can rely on it being set.
	At time.Time
}

// Hook observes lifecycle events.
//
// Hooks fire AFTER the mutation has been applied to the store and BEFORE the
// method returns, and a hook that returns an error aborts the method: the
// error is propagated to the caller. Nothing in this package runs in a
// transaction a hook could roll back, so the store change is ALREADY IN
// PLACE while the caller sees an error. For [Service.Login] that means a
// hook failure leaves a live [Session] row whose refresh token the caller
// never received — it ages out with the refresh TTL or falls to
// [Service.LogoutAll] — and for [Service.SignUp] a real account whose
// verification token was never handed back. So keep side effects that must
// not be retried out of hooks, and return nil for best-effort work such as
// logging; a hook is the right place for an audit write, an outbox row or a
// cache drop, and the wrong place for anything whose failure should undo the
// mutation, because it cannot.
//
// On a FAILURE event — [LoginFailed], [TokenReuseDetected] — the method was
// already returning an error, and a hook error does not replace it: the
// caller gets both, joined, so [errors.Is] matches the original sentinel and
// the hook's error alike. An [ErrInvalidCredentials] stays an
// ErrInvalidCredentials whatever the audit sink did.
//
// Hooks run in the order they were registered with [WithHooks]; the first
// error stops the chain. They are called on the caller's goroutine and share
// its context, so a slow hook slows the request — and, for [LoginFailed], a
// hook whose cost DIFFERS by [Event.Detail] reopens the timing channel
// [password.Hasher.Dummy] exists to close between "unknown address" and
// "wrong password". Keep a LoginFailed hook constant-shape: write the event
// and return.
type Hook interface {
	On(ctx context.Context, e Event) error
}

// HookFunc adapts a function to the [Hook] interface.
type HookFunc func(ctx context.Context, e Event) error

// On implements [Hook].
func (f HookFunc) On(ctx context.Context, e Event) error { return f(ctx, e) }

// WithHooks appends lifecycle hooks fired after successful mutations. It
// appends rather than replaces, so several calls accumulate and hooks run in
// registration order — matching
// [github.com/bernardoforcillo/authlayer/scope.WithHooks]. nil hooks are
// skipped.
//
// # What deliberately emits nothing
//
// The enumeration-hardened request paths emit NO event, on EITHER branch:
// [Service.SignUp]'s duplicate-address branch, [Service.RequestPasswordReset],
// [Service.RequestMagicLink], and [Service.RequestEmailChange]. Each of
// those methods is built so that its Store calls, its error set and its
// returned shape are identical whether or not the address is registered —
// and a hook is a caller-visible side effect whose cost is whatever the
// application put in it. Firing one on the known branch only would reopen
// the oracle by timing; firing one on both branches would hand the
// application a Created/known flag it must then be trusted never to act on
// differently. Neither is this package's to risk, so those methods stay
// silent, and this is a documented gap rather than an oversight: an
// application that wants a record of reset or magic-link REQUESTS logs them
// at its own handler, where it already knows it must answer uniformly.
// Redemptions are not hardened and do emit — [PasswordReset],
// [MagicLinkRedeemed], [EmailChanged].
//
// [LoginFailed] is emitted with the attempted IP and NEVER the attempted
// address — not in [Event.Detail], not anywhere. A failed-login log keyed by
// address is a list of which addresses exist, and this package will not
// build one; key yours by IP or by the UserID a wrong-password event
// carries, which names an account the attacker already knew existed.
//
// Emission changes no Store-call sequence and no error: a Service with no
// hooks behaves exactly as it did before hooks existed, and one whose hooks
// all return nil is observably identical to it.
func WithHooks(h ...Hook) Option {
	return func(c *config) {
		for _, hook := range h {
			if hook != nil {
				c.hooks = append(c.hooks, hook)
			}
		}
	}
}

// emit stamps e.At from the Service clock if unset and runs every hook in
// order, stopping at the first error. It is called AFTER the mutation the
// event describes and is the last thing before a successful return.
func (s *Service) emit(ctx context.Context, e Event) error {
	if len(s.cfg.hooks) == 0 {
		return nil
	}
	if e.At.IsZero() {
		e.At = s.cfg.clock()
	}
	for _, h := range s.cfg.hooks {
		if err := h.On(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// emitFailure is emit for the events that accompany an error the method is
// already returning — [LoginFailed], [TokenReuseDetected]. It returns err
// unchanged when every hook succeeds, so a Service without hooks (or with
// well-behaved ones) returns exactly the sentinel it always did; when a hook
// fails, it returns both joined, so neither the original refusal nor the
// hook's failure is lost to the other — see [Hook].
func (s *Service) emitFailure(ctx context.Context, e Event, err error) error {
	if herr := s.emit(ctx, e); herr != nil {
		return errors.Join(err, herr)
	}
	return err
}
