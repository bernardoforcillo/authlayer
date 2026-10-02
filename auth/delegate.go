package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bernardoforcillo/authlayer/password"
)

// This file is the Service's set of delegation seams. Service keeps every
// security-critical invariant (enumeration safety, sweeps, step-up) to
// itself and hands the DECISIONS that vary between deployments to small
// interfaces the application supplies:
//
//   - which sign-in methods exist at all — [WithMethods]
//   - who may register — [SignUpPolicy]
//   - what a password must look like — [PasswordPolicy]
//   - whether an authenticated account may open a session — [SessionGate]
//   - a sign-in method of your own — [Authenticator]
//
// Every one is optional, and the default of each reproduces the behaviour
// the Service had before the seam existed.

// Method names a way of proving who you are. The built-in ones are the
// constants below; an [Authenticator] adds its own.
type Method string

const (
	// MethodPassword is [Service.Login] and its trusted-device variant.
	MethodPassword Method = "password"
	// MethodMagicLink is [Service.RequestMagicLink] and
	// [Service.RedeemMagicLink].
	MethodMagicLink Method = "magic_link"
	// MethodPasskey is [Service.BeginPasskeyLogin] and
	// [Service.FinishPasskeyLogin].
	MethodPasskey Method = "passkey"
	// MethodExternalIdentity is [Service.SignInWith].
	MethodExternalIdentity Method = "external_identity"
)

// ErrMethodDisabled: the method was switched off by [WithMethods], or no
// [Authenticator] is registered under that name. It reflects static
// configuration, never the state of any account, so it leaks nothing about
// who is registered.
var ErrMethodDisabled = errors.New("authlayer/auth: sign-in method is not enabled")

// SignUpPolicy decides whether an address may register. It is consulted by
// [Service.SignUp] with the NORMALIZED address, before the store is touched.
// A non-nil error is returned from SignUp unchanged.
//
// Decide from the address alone — a domain allowlist or deny-list. A
// decision that depends on whether the address is already registered
// (including a lookup in your own users table) would answer "is this
// address known" through SignUp's response and break its enumeration
// safety; see that method's doc.
type SignUpPolicy interface {
	AllowSignUp(ctx context.Context, email string) error
}

// SignUpPolicyFunc adapts a function to [SignUpPolicy].
type SignUpPolicyFunc func(ctx context.Context, email string) error

// AllowSignUp implements [SignUpPolicy].
func (f SignUpPolicyFunc) AllowSignUp(ctx context.Context, email string) error {
	return f(ctx, email)
}

// PasswordPolicy decides whether a plaintext password is acceptable and
// returns the names of the rules it fails, empty when it passes. It is
// consulted wherever a password is chosen: SignUp, ChangePassword,
// SetPassword and ResetPassword. [password.Rules] is the built-in one; see
// [RulesPolicy].
type PasswordPolicy interface {
	Check(plain string) (failed []string)
}

// RulesPolicy adapts [password.Rules] to [PasswordPolicy].
type RulesPolicy password.Rules

// Check implements [PasswordPolicy].
func (r RulesPolicy) Check(plain string) []string {
	return password.Validate(plain, password.Rules(r))
}

// SessionGate is the last word before any session is minted, whichever
// door the account came through: it receives the authenticated account (its
// PasswordHash is cleared) and the door, the same string [Event.Detail]
// carries on [LoggedIn]. A non-nil error refuses the session and is
// returned to the caller; use it for bans, suspensions, tenant checks or
// "only after the contract is signed" rules.
//
// It runs after the credential has been verified, so a refusal is visible
// only to someone who already proved the account — it cannot be used to
// probe for accounts.
type SessionGate interface {
	AllowSession(ctx context.Context, u UserBase, door string) error
}

// SessionGateFunc adapts a function to [SessionGate].
type SessionGateFunc func(ctx context.Context, u UserBase, door string) error

// AllowSession implements [SessionGate].
func (f SessionGateFunc) AllowSession(ctx context.Context, u UserBase, door string) error {
	return f(ctx, u, door)
}

// AuthRequest is what [Service.Authenticate] hands an [Authenticator]:
// the transport-level facts plus whatever fields its method needs.
type AuthRequest struct {
	// IP and UserAgent are the caller's; IP must be non-empty.
	IP        string
	UserAgent string
	// Fields carries the method's own inputs (an OTP, an assertion, a
	// signed SAML response — whatever the Authenticator documents).
	Fields map[string]string
}

// Authenticator is a sign-in method supplied by the application — SMS
// OTP, SAML, a hardware token, an SSO bridge. It verifies a credential and
// names the account; the Service does everything after that exactly as it
// does for a built-in door: rate limit, deleted-account refusal,
// [SessionGate], the second factor, session minting and the audit events.
//
// Authenticate returns the id of the account the credential belongs to. On
// failure return [ErrInvalidCredentials] (or any error); it is reported
// as a [LoginFailed] event and returned to the caller. An Authenticator
// owns its own enumeration safety: return the same error for "no such
// account" and "wrong credential".
type Authenticator interface {
	Name() Method
	Authenticate(ctx context.Context, req AuthRequest) (userID string, err error)
}

// WithMethods enables exactly the listed built-in methods and any
// [Authenticator] registered under a listed name. Everything else is
// refused with [ErrMethodDisabled] before it touches an account. The
// default (no call) enables every built-in method.
//
// Leaving [MethodPassword] out also lets [Service.SignUp] register an
// account from an email alone, as [WithPasswordRequired](false) does, and
// refuses a SignUp that supplies a password.
func WithMethods(methods ...Method) Option {
	return func(c *config) {
		c.methods = make(map[Method]bool, len(methods))
		for _, m := range methods {
			c.methods[m] = true
		}
	}
}

// WithSignUpPolicy installs a [SignUpPolicy]. nil restores the default
// (anyone may register).
func WithSignUpPolicy(p SignUpPolicy) Option {
	return func(c *config) { c.signUpPolicy = p }
}

// WithPasswordPolicy installs a [PasswordPolicy], replacing [WithRules].
// nil restores the rules-based default.
func WithPasswordPolicy(p PasswordPolicy) Option {
	return func(c *config) { c.passwordPolicy = p }
}

// WithSessionGate installs a [SessionGate]. nil restores the default (no
// gate).
func WithSessionGate(g SessionGate) Option {
	return func(c *config) { c.sessionGate = g }
}

// WithAuthenticators registers custom sign-in methods for
// [Service.Authenticate]. A later registration under the same name replaces
// an earlier one; names colliding with a built-in [Method] are ignored so a
// custom method cannot masquerade as a built-in one in audit events.
func WithAuthenticators(as ...Authenticator) Option {
	return func(c *config) {
		if c.authenticators == nil {
			c.authenticators = map[Method]Authenticator{}
		}
		for _, a := range as {
			if a == nil || isBuiltinMethod(a.Name()) || a.Name() == "" {
				continue
			}
			c.authenticators[a.Name()] = a
		}
	}
}

func isBuiltinMethod(m Method) bool {
	switch m {
	case MethodPassword, MethodMagicLink, MethodPasskey, MethodExternalIdentity:
		return true
	}
	return false
}

// methodEnabled reports whether m may be used. A nil set means "all
// built-ins"; a registered Authenticator still needs its name listed when a
// set is given.
func (s *Service) methodEnabled(m Method) bool {
	if s.cfg.methods == nil {
		return true
	}
	return s.cfg.methods[m]
}

func (s *Service) requireMethod(m Method) error {
	if !s.methodEnabled(m) {
		return ErrMethodDisabled
	}
	return nil
}

// passwordOptionalNow reports whether SignUp may omit the password.
func (s *Service) passwordOptionalNow() bool {
	return s.cfg.passwordOptional || !s.methodEnabled(MethodPassword)
}

// checkPassword runs the configured [PasswordPolicy] (or the rules) and
// wraps failures in [ErrWeakPassword].
func (s *Service) checkPassword(plain string) error {
	var failed []string
	if s.cfg.passwordPolicy != nil {
		failed = s.cfg.passwordPolicy.Check(plain)
	} else {
		failed = password.Validate(plain, s.cfg.rules)
	}
	if len(failed) > 0 {
		return fmt.Errorf("%w: %s", ErrWeakPassword, strings.Join(failed, ","))
	}
	return nil
}

// gateSession consults the [SessionGate], if any.
func (s *Service) gateSession(ctx context.Context, u UserBase, door string) error {
	if s.cfg.sessionGate == nil {
		return nil
	}
	u.PasswordHash = ""
	return s.cfg.sessionGate.AllowSession(ctx, u, door)
}

// Authenticate signs an account in through a registered [Authenticator].
// It is the generic counterpart of [Service.Login]: the method proves the
// credential, the Service does the rest. The result has the same shape as
// Login's — tokens, or an MFA challenge when the account has a confirmed
// second factor.
func (s *Service) Authenticate(ctx context.Context, method Method, req AuthRequest) (LoginResult, error) {
	var zero LoginResult

	a, ok := s.cfg.authenticators[method]
	if !ok || !s.methodEnabled(method) {
		return zero, ErrMethodDisabled
	}
	if req.IP == "" {
		return zero, ErrMissingIP
	}
	if s.cfg.limiter != nil {
		allowed, err := s.cfg.limiter.Allow(ctx, req.IP)
		if err != nil {
			return zero, err
		}
		if !allowed {
			return zero, ErrRateLimited
		}
	}

	failed := func(userID string, err error) error {
		return s.emitFailure(ctx, Event{Kind: LoginFailed, UserID: userID, IP: req.IP, UserAgent: req.UserAgent, Detail: string(method)}, err)
	}

	userID, err := a.Authenticate(ctx, req)
	if err != nil {
		return zero, failed("", err)
	}
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return zero, failed("", ErrInvalidCredentials)
		}
		return zero, err
	}
	if u.DeletedAt != nil {
		return zero, failed(u.ID, ErrInvalidCredentials)
	}
	if s.cfg.requireVerifiedEmail && u.EmailVerifiedAt == nil {
		return zero, failed(u.ID, ErrEmailNotVerified)
	}

	challenge, err := s.mfaAtSignIn(ctx, u)
	if err != nil {
		return zero, err
	}
	if challenge != nil {
		u.PasswordHash = ""
		if err := s.emit(ctx, Event{Kind: MFAChallenged, UserID: u.ID, IP: req.IP, UserAgent: req.UserAgent}); err != nil {
			return zero, err
		}
		return LoginResult{User: u, MFA: challenge}, nil
	}
	return s.mintSession(ctx, u, req.IP, req.UserAgent, nil, string(method))
}
