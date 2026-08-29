// Package auth (this file) is the service layer built on top of [Store]:
// sign-up, login, and email verification. Where auth.go defines the
// persistence shape and performs no hashing or token minting of its own (see
// that file's package doc), Service wires together
// [github.com/bernardoforcillo/authlayer/password]'s Hasher/Validate,
// [github.com/bernardoforcillo/authlayer/token]'s opaque-token and JWT
// primitives, and a Store to produce the three flows an application
// actually calls.
//
// Like [github.com/bernardoforcillo/authlayer/scope.Service], Service is
// generic over the application's own user type U: embed [UserBase] in your
// own struct to add whatever profile fields you like, and Service reads and
// writes the embedded identity/credential fields through the [User] /
// [MutableUser] interfaces, which [UserBase] itself satisfies via promoted
// methods — see those types' docs. An application with no extra fields uses
// [UserBase] itself as U.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/token"
)

// User is the read side of an application-supplied user type: whatever
// extra fields it embeds, it must give back the [UserBase] this Service
// manages. [UserBase] itself implements this (Base returns the receiver
// unchanged), so any type that embeds UserBase satisfies User automatically
// through method promotion, with no code of its own.
type User interface {
	// Base returns the embedded UserBase.
	Base() UserBase
}

// MutableUser is the write side: the pointer receiver Service uses to stamp
// what it creates and to load what a Store returns back onto U. Embedding
// [UserBase] is enough to satisfy this too, for the same promotion reason
// as [User].
type MutableUser interface {
	User
	// SetBase overwrites the embedded UserBase wholesale.
	SetBase(UserBase)
}

// Base implements [User]. Embedding UserBase in an application's own user
// type promotes this method for free.
func (u UserBase) Base() UserBase { return u }

// SetBase implements [MutableUser]. Embedding UserBase in an application's
// own user type promotes this method for free.
func (u *UserBase) SetBase(b UserBase) { *u = b }

// The three closed values [Verification.Purpose] takes — see that field's
// doc and [Store]'s sentinel-error doc for why the closed set lives here,
// in the service layer, rather than on the Store port.
const (
	// PurposeSignup marks a Verification minted by [Service.SignUp] to
	// confirm a newly registered address. Redeemed by [Service.VerifyEmail].
	PurposeSignup = "signup"
	// PurposeEmailChange marks a Verification minted for an in-place email
	// change, bound to the NEW address (see [Verification.Email]).
	// Redeemed by [Service.VerifyEmail], which additionally calls
	// [Store.UpdateUserEmail] before marking it verified.
	PurposeEmailChange = "email_change"
	// PurposePasswordReset marks a Verification minted for a password-reset
	// flow. Not redeemable through [Service.VerifyEmail] —
	// [Service.ResetPassword] owns this purpose's redemption, and
	// VerifyEmail refuses it with [ErrVerificationPurpose] rather than
	// silently accepting it and burning the token for nothing.
	PurposePasswordReset = "password_reset"
)

// defaultVerificationTTL is how long a [Service.SignUp]-minted "signup"
// verification stays redeemable. Not exposed as an Option (see [New] for the
// full option surface), but chosen generously (a day) since
// an email that never arrives, or arrives late, must not force a whole new
// sign-up.
const defaultVerificationTTL = 24 * time.Hour

// defaultPasswordResetTTL is how long a [Service.RequestPasswordReset]-minted
// "password_reset" [Verification] stays redeemable. Deliberately shorter
// than defaultVerificationTTL's 24 hours: a password-reset link is a more
// security-sensitive bearer credential than a signup-confirmation link (it
// grants a full credential change, not merely a "yes, I own this address"
// attestation), and a short window is the conventional stance this class of
// flow takes elsewhere.
const defaultPasswordResetTTL = time.Hour

// Sentinel errors returned by Service, layered on top of the ones [Store]
// already defines (ErrUserNotFound and friends propagate through verbatim
// on a store miss that isn't one of the cases below — see the "Fail
// closed" note on each method for what that means).
var (
	// ErrWeakPassword: the plaintext given to [Service.SignUp] fails one or
	// more of the configured [password.Rules]. Checked BEFORE any store
	// lookup — see SignUp's doc for why the ordering is load-bearing, not
	// cosmetic.
	ErrWeakPassword = errors.New("authlayer/auth: password does not meet the configured rules")
	// ErrInvalidCredentials: [Service.Login] could not authenticate the
	// given email/password pair. Returned identically whether the address
	// is unregistered, the account has no password credential at all, or
	// the password is simply wrong — see Login's doc for why those three
	// cases must be indistinguishable to the caller.
	ErrInvalidCredentials = errors.New("authlayer/auth: invalid email or password")
	// ErrEmailNotVerified: [Service.Login] refused a login that would
	// otherwise have succeeded, because [WithRequireVerifiedEmail] is
	// enabled and the account's address is not yet verified.
	ErrEmailNotVerified = errors.New("authlayer/auth: email address is not verified")
	// ErrRateLimited: [Service.Login] refused an attempt because the
	// configured [RateLimiter] denied the caller's IP. Store and Hasher are
	// never touched when this fires.
	ErrRateLimited = errors.New("authlayer/auth: rate limit exceeded")
	// ErrMissingIP: [Service.Login] was called with an empty ip. Refused
	// unconditionally, whether or not a [RateLimiter] is configured — an
	// empty ip would otherwise become one shared rate-limit bucket across
	// every caller that omits it, an availability hazard, not a merely
	// missing audit field. See Login's own doc.
	ErrMissingIP = errors.New("authlayer/auth: ip must not be empty")
	// ErrVerificationExpired: [Service.VerifyEmail] was presented a token
	// whose ExpiresAt has passed. Checked before the token is claimed, so
	// an expired token is never burned — it simply ages out via
	// [Store.PurgeExpired] like any other expired row.
	ErrVerificationExpired = errors.New("authlayer/auth: verification token has expired")
	// ErrVerificationPurpose: [Service.VerifyEmail] was presented a token
	// whose Purpose it does not redeem — currently only
	// [PurposePasswordReset], which [Service.ResetPassword] redeems
	// instead. Checked before the claim, so a wrongly-presented token is
	// not burned either.
	ErrVerificationPurpose = errors.New("authlayer/auth: verification token is not valid for this operation")
	// ErrTokenInvalid: [Service.Refresh] was presented a refresh token this
	// Store has never heard of ([Store.FindSessionByHash] returning
	// [ErrSessionNotFound]), or whose session has expired
	// (Session.ExpiresAt <= now). Both cases are reported identically —
	// see Refresh's doc for why an expired token does not, on its own,
	// distinguish itself from an unknown one, and critically, why NEITHER
	// case revokes the session's family: ordinary end-of-life is not
	// evidence of theft.
	ErrTokenInvalid = errors.New("authlayer/auth: refresh token is invalid or expired")
	// ErrTokenReuse: [Service.Refresh] was presented a refresh token whose
	// session was already rotated away — [Store.MarkRotated] returning
	// ok=false. This package cannot distinguish a genuine attacker replaying
	// a stolen token from a legitimate client retrying a raced request with
	// a now-stale one, so it treats every occurrence as compromise: by the
	// time this error is returned, every session in the token's family has
	// already been revoked via [Store.DeleteSessionsByFamily]. See Refresh's
	// doc, "Why the whole family, not just the presented session".
	//
	// A caller inspecting an error returned by Refresh with [errors.Is]
	// MUST check ErrTokenReuse before checking whether the error wraps a
	// [Store] error of its own: when [Store.DeleteSessionsByFamily] itself
	// fails while responding to a detected replay, Refresh wraps BOTH — the
	// returned error satisfies errors.Is against ErrTokenReuse (a replay
	// WAS detected; that fact must never be lost merely because the
	// housekeeping response to it also failed) and against whatever the
	// Store's own error is (so the operational failure is not hidden
	// either). See Refresh's doc, "Fail closed".
	ErrTokenReuse = errors.New("authlayer/auth: refresh token reuse detected; session family revoked")
	// ErrSessionRevoked: [Service.Refresh] won [Store.MarkRotated] — this
	// caller's presented token was genuinely current and unrotated, and
	// nobody replayed it — but by the time it went to persist the
	// successor, [Store.CreateSuccessorSession] reported that the
	// predecessor session no longer existed: something else (most likely a
	// DIFFERENT, concurrently-replayed token in the same family triggering
	// [Store.DeleteSessionsByFamily], or an explicit [Service.LogoutAll] /
	// [Service.RevokeSession] / [Service.Logout] racing this exact call)
	// revoked the family out from under this rotation between those two
	// steps. This is deliberately a THIRD, distinct outcome from
	// ErrTokenInvalid (the presented token itself was never bad — it won
	// the compare-and-set fair and square) and from ErrTokenReuse (nobody
	// replayed THIS caller's token; nothing about this call was itself a
	// replay). The presented token is already rotated away regardless — see
	// Refresh's doc, "Fail closed" — so the caller genuinely has nothing:
	// no successor was minted, and the old token is already superseded.
	// Treat it the same as any other authentication failure: the caller
	// must sign in again.
	ErrSessionRevoked = errors.New("authlayer/auth: session family was revoked before rotation could complete")
	// ErrEmailRequired: [Service.RequestEmailChange] was given a newEmail
	// that is empty once normalized (see [NormalizeEmail] — this also
	// catches a whitespace-only value, not just a literal ""). Checked
	// before anything else, including the [Store.FindUserByID] existence
	// check, so a malformed request never reaches the Store at all. Without
	// this guard, an empty newEmail minted a redeemable token exactly like
	// any other, and successful redemption via [Service.VerifyEmail] set
	// [UserBase.Email] to "" — a self-inflicted account lockout with no
	// recovery path this package exposes, since [Service.Login] and
	// [Service.RequestPasswordReset] both look accounts up BY email.
	ErrEmailRequired = errors.New("authlayer/auth: email must not be empty")
)

// RateLimiter throttles [Service.Login] attempts by a caller-supplied key.
// Login calls Allow with the caller's IP address — never with the attempted
// email — so a malicious caller cannot lock a victim out of their own
// account merely by exhausting a bucket keyed on the victim's address; only
// the attacker's own IP bucket is ever spent. See [WithRateLimiter].
type RateLimiter interface {
	// Allow reports whether an attempt keyed by key may proceed right now.
	//
	// A false, nil result means Login refuses immediately with
	// [ErrRateLimited], without calling the Store or the Hasher at all. A
	// non-nil error means the limiter itself could not answer — Login
	// treats that as "deny" too (propagating the error, not ErrRateLimited)
	// rather than guessing "allow": an authentication decision that cannot
	// be made must deny, the same fail-closed discipline every store error
	// elsewhere in this package already follows.
	Allow(ctx context.Context, key string) (bool, error)
}

// config is the resolved Service configuration, built from the defaults and
// mutated via Option at construction — immutable once New returns, matching
// [github.com/bernardoforcillo/authlayer/scope.Option]'s own stance.
type config struct {
	hasher     password.Hasher
	rules      password.Rules
	signingKey [][]byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	clock      func() time.Time
	idGen      func() string
	limiter    RateLimiter
	// resetLimiter is the address-keyed [RateLimiter] [Service.RequestPasswordReset]
	// additionally consults — see [WithPasswordResetRateLimiter]'s doc for
	// why it is a second, independent config slot rather than reusing
	// limiter (which stays IP-keyed everywhere it is used).
	resetLimiter RateLimiter
	// claimsExtender holds a func(U) map[string]any, type-erased to `any`
	// because config itself is not generic over U (see the codebase note
	// on WithClaimsExtender for why). New asserts it back to the concrete
	// function type exactly once, at construction — see New's doc.
	claimsExtender       any
	requireVerifiedEmail bool
}

func defaultConfig() config {
	return config{
		hasher:     password.Bcrypt(0),
		rules:      password.DefaultRules(),
		accessTTL:  15 * time.Minute,
		refreshTTL: 30 * 24 * time.Hour,
		clock:      func() time.Time { return time.Now().UTC() },
		idGen:      uid.NewV7,
	}
}

// Option customizes a Service. Options are applied in order at construction
// and never afterwards, matching every other Option type in this codebase
// (scope.Option, invite.Option).
type Option func(*config)

// WithHasher overrides the [password.Hasher] used to hash, verify, and
// dummy-compare passwords. The default is [password.Bcrypt] at bcrypt's own
// library default cost. A nil h is ignored, leaving the default (or a prior
// option) in place.
func WithHasher(h password.Hasher) Option {
	return func(c *config) {
		if h != nil {
			c.hasher = h
		}
	}
}

// WithRules sets the [password.Rules] [Service.SignUp] validates a new
// password against. The default is [password.DefaultRules] — authlayer's
// baseline policy (minimum 12 characters, all four character classes) —
// not the permissive zero value; a caller that wants no policy at all must
// pass password.Rules{} explicitly.
func WithRules(r password.Rules) Option {
	return func(c *config) { c.rules = r }
}

// WithJWT sets the HMAC signing keys and access-token lifetime
// [Service.Login] issues with. keys[0] is the key every new access token is
// signed with; any keys after it are accepted on tokens presented for
// verification but never used to sign — the same rotation convention
// [token.Issue]/[token.Parse] document. A nil or empty keys leaves the
// signing key unset, in which case Login fails closed the first time it
// tries to issue a token: [token.Issue] itself refuses a key shorter than
// 32 bytes with token.ErrKeyTooShort, and a missing key is indistinguishable
// from a zero-length one for that check. ttl <= 0 is ignored, leaving the
// default (15 minutes) or a prior option in place.
//
// There is no default signing key — an application MUST call this before
// any successful Login, by design: silently minting tokens under a
// zero-value or generated-on-the-fly key would be the exact "alg: none
// reached through the key parameter" failure mode [token]'s own package doc
// warns about.
func WithJWT(keys [][]byte, ttl time.Duration) Option {
	return func(c *config) {
		if len(keys) > 0 {
			c.signingKey = keys
		}
		if ttl > 0 {
			c.accessTTL = ttl
		}
	}
}

// WithRefreshTTL sets how long a session minted by [Service.Login] remains
// presentable before it expires — [Session.ExpiresAt] is stamped as
// CreatedAt+d. The default is 30 days. d <= 0 is ignored, leaving the
// default (or a prior option) in place.
func WithRefreshTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.refreshTTL = d
		}
	}
}

// WithClock sets the clock Service stamps CreatedAt/UpdatedAt/ExpiresAt
// and checks expiry against. The default is time.Now().UTC(). A nil clock
// is ignored.
//
// Injecting a fixed clock makes assertions on stamped timestamps
// deterministic, matching [github.com/bernardoforcillo/authlayer/scope.WithClock]'s
// own stance.
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.clock = now
		}
	}
}

// WithIDGenerator sets the id generator used for users, sessions, and
// verifications. The default is UUIDv7 ([uid.NewV7]) — matching
// [github.com/bernardoforcillo/authlayer/scope.WithIDGenerator]'s own
// rationale. A nil generator is ignored, leaving the default (or a prior
// option) in place.
func WithIDGenerator(gen func() string) Option {
	return func(c *config) {
		if gen != nil {
			c.idGen = gen
		}
	}
}

// WithRateLimiter wires a [RateLimiter] that [Service.Login] and
// [Service.RequestPasswordReset] both consult, keyed by IP, before touching
// the Store or the Hasher — see that interface's doc for why IP and never
// email. The default is nil, meaning neither method imposes a rate limit at
// all. [Service.SignUp] never consults it — rate limiting is scoped to the
// two methods named above, and no other method in this package consults a
// limiter of any kind.
func WithRateLimiter(l RateLimiter) Option {
	return func(c *config) { c.limiter = l }
}

// WithPasswordResetRateLimiter wires a second, independent [RateLimiter]
// that [Service.RequestPasswordReset] consults, keyed by the NORMALIZED
// email address rather than by IP — see [NormalizeEmail]. The default is
// nil, meaning RequestPasswordReset imposes no address-keyed limit at all;
// [WithRateLimiter]'s IP-keyed limit, if configured, still applies on its
// own.
//
// A denial from this limiter is never surfaced as [ErrRateLimited] the way
// WithRateLimiter's IP-keyed denial is — see
// [Service.RequestPasswordReset]'s doc, "The enumeration property, again",
// point 2, for why: an address-keyed rate limit that surfaced as a
// distinguishable error would itself become the exact existence oracle this
// method's whole design exists to close.
//
// This limiter is also what this method's own re-issue behaviour depends
// on for protection, not merely enumeration timing: [Service.RequestPasswordReset]
// invalidates an address's earlier "password_reset" token every time a new
// one is minted (see that method's doc, point 1, and [Store]'s own
// documented contract on [Store.DeleteVerificationsByUserAndPurpose]).
// Without an address-keyed limit, ANYONE who merely knows an address — no
// credential, no prior relationship to the account required — can kill a
// victim's genuine, still-unredeemed reset link at will simply by looping
// calls to RequestPasswordReset for that address, since each call
// invalidates whatever the account's most recent token was. That is
// inherent to the re-issue contract [Store] documents, not a bug this
// method can avoid while still honouring it, and this package does not
// configure a default here for exactly the reason [WithRateLimiter]'s own
// default is nil: the right bucket size is an operator decision. Setting
// this limiter is what bounds how often that griefing can happen, not just
// how many timing samples an attacker can collect.
func WithPasswordResetRateLimiter(l RateLimiter) Option {
	return func(c *config) { c.resetLimiter = l }
}

// WithRequireVerifiedEmail controls whether [Service.Login] refuses an
// otherwise-successful login for an account whose email is not yet
// verified, with [ErrEmailNotVerified]. The default is false: an unverified
// account may still log in. See Login's doc for exactly when this check
// runs relative to the password check.
func WithRequireVerifiedEmail(require bool) Option {
	return func(c *config) { c.requireVerifiedEmail = require }
}

// WithClaimsExtender registers a callback that computes additional claims
// from the just-authenticated user. Its result is NESTED under
// [token.Claims].Extra as one sub-object, not merged into the token's
// top-level fields — an extender that returns {"sub": "victim"} produces
// {"sub":"real-subject", ..., "ext":{"sub":"victim"}} on the wire, so it
// can never shadow Subject, SessionID, Email, or the timestamps. That
// nesting is structural, not a denylist: there is no way for an
// extender's map to reach the reserved keys at all. The default is nil:
// Login issues tokens with Extra unset.
//
// u carries the real, freshly-loaded identity: whatever [UserBase] fields
// this package itself manages (ID, Email, EmailVerifiedAt, ...) are
// genuinely populated — see [Service.wrap]. Anything your own type embeds
// BEYOND UserBase is not: [Store] only ever persists the UserBase-shaped
// portion (see that interface's own doc), so this package has no way to
// recover a field like Plan from storage on your behalf. Look such fields
// up yourself, inside the callback, keyed by the real u.Base().ID:
//
//	auth.New[MyUser](store, auth.WithClaimsExtender(func(u MyUser) map[string]any {
//		profile := myApp.Profiles.Lookup(u.Base().ID) // your own store, not this package's
//		return map[string]any{"plan": profile.Plan}
//	}))
//
// U here MUST be exactly the same type argument given to [New] — Go cannot
// enforce that statically, because config (and therefore this Option) is
// not itself generic over U (see config's own doc for why: making Option
// generic would force every OTHER option, none of which mention U in their
// own arguments, to be called with an explicit type argument at every call
// site, e.g. auth.WithHasher[MyUser](h), which is worse ergonomics than the
// one narrow risk this trades for). New asserts the callback back to
// func(U) map[string]any exactly once, immediately after applying every
// Option — so a mismatched type argument here panics loudly at
// construction time, not silently or deep inside a later Login call.
func WithClaimsExtender[U any](f func(U) map[string]any) Option {
	return func(c *config) {
		if f != nil {
			c.claimsExtender = f
		}
	}
}

// SignUpResult is the outcome of [Service.SignUp]. Both branches return a
// nil error; Created and VerifyToken are what differ, and User is populated
// only on the new-account branch.
//
// # The caller's obligation
//
// A public sign-up handler MUST emit a FIXED response — same status code,
// same body shape, same rough latency — regardless of the outcome. That is
// the actual requirement, and it is stronger than "do not branch on
// Created": nothing in this struct is safe to reflect back to an
// unauthenticated caller merely because it is not the Created bool.
// VerifyToken's presence, the shape of User, and how long the call took are
// all observable, and any of them differing between outcomes answers "is
// this address registered?" just as well. Use VerifyToken (non-empty only
// when Created is true) to decide whether to SEND MAIL — never to decide
// what to tell the HTTP caller. The property is enforced up to the boundary
// of this function and no further; see [Service.SignUp]'s doc for what this
// package does hold, and for the timing residual it does not.
type SignUpResult[U any] struct {
	// Created is true for a genuinely new account, false when the address
	// was already registered. See the type doc for what a caller may do
	// with that: decide whether to send mail, not what to answer.
	Created bool
	// User is the newly created user when Created is true, and the ZERO
	// value of U when Created is false — never the account that was found.
	// SignUp's duplicate branch does load that account (unconditionally,
	// on both branches, which is what keeps its Store-call sequence
	// identical — see [Service.SignUp]), but it is not handed out: its ID,
	// CreatedAt and EmailVerifiedAt each answer "is this address
	// registered?" on their own, in one request, to a caller who has
	// proven nothing about the address. Populating this field only when
	// Created is true mirrors VerifyToken's own rule for the same reason.
	//
	// PasswordHash is cleared to "" on the branch that DOES populate this
	// field: the caller already knows the plaintext it submitted, so that
	// specific hash is not new information, but it is not this package's
	// to hand back either — see [UserBase.PasswordHash]'s own doc.
	User U
	// VerifyToken is the plain "signup" verification token, present only
	// when Created is true. Empty when Created is false — SignUp DOES
	// mint a "signup" Verification for the existing account too, on every
	// call regardless of Created (see [Service.SignUp]'s "Fail closed, by
	// construction"), but that token is discarded rather than surfaced
	// here: nothing about calling SignUp again for an address you do not
	// control should ever hand you something to redeem, or touch the
	// verification the real accountholder already has.
	VerifyToken string
}

// LoginResult is the outcome of a successful [Service.Refresh]: the account
// the redeemed refresh token belongs to, a freshly issued access token, and
// the plaintext of the new refresh token minted as this rotation's
// successor. See Refresh's own doc for the full ladder that produces one.
type LoginResult[U any] struct {
	// User is the account the rotated session belongs to, freshly loaded
	// from the Store — never a cached or stale copy carried over from
	// whatever session lookup happened earlier in the ladder. PasswordHash
	// is always cleared to "" here, matching every other Service method
	// that hands back U — see [UserBase.PasswordHash]'s own doc.
	User U
	// AccessToken is a fresh, short-lived HS256 JWT — see [WithJWT] — bound
	// to the NEW session (its SessionID claim is the successor's, not the
	// rotated-away predecessor's).
	AccessToken string
	// RefreshToken is the plaintext of the newly minted successor session's
	// refresh token. Present this on the NEXT call to Refresh; the token
	// just redeemed to produce this result is now rotated away and will
	// fail with [ErrTokenReuse], revoking the whole family, if presented
	// again.
	RefreshToken string
}

// Service mints, authenticates, and verifies accounts for one application.
// U is the application's own user type; see the package doc for the
// [User]/[MutableUser] embedding convention that lets Service read and
// write it. A Service performs no authorization of its own — there is
// nothing to authorize yet at sign-up or login, unlike
// [github.com/bernardoforcillo/authlayer/scope.Service] — and is safe for
// concurrent use if its Store, Hasher, and RateLimiter are; it caches
// nothing.
type Service[U any, PU interface {
	*U
	MutableUser
}] struct {
	store    Store
	cfg      config
	extender func(U) map[string]any
}

// New wires a [Store] and options into a Service. The pointer type
// parameter PU is inferred, so callers write New[U](store, opts...) —
// matching [github.com/bernardoforcillo/authlayer/scope.New]'s own
// pointer-type-parameter convention. An application with no extra profile
// fields can instantiate New[UserBase](store, opts...) directly, since
// UserBase satisfies MutableUser itself (see [UserBase.Base] /
// [UserBase.SetBase]).
//
// If [WithClaimsExtender] was used, its callback is asserted back to its
// concrete func(U) map[string]any type here — see that Option's doc for why
// this is the one place a type mismatch between it and U surfaces, and why
// that surfacing is a panic rather than a returned error: New has no error
// return, matching every other constructor in this codebase
// (scope.New, invite.New), because misconfiguration here is a wiring bug
// caught once at startup, not a runtime condition a caller is expected to
// handle per call.
func New[U any, PU interface {
	*U
	MutableUser
}](store Store, opts ...Option) *Service[U, PU] {
	cfg := defaultConfig()
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	svc := &Service[U, PU]{store: store, cfg: cfg}
	if cfg.claimsExtender != nil {
		svc.extender = cfg.claimsExtender.(func(U) map[string]any)
	}
	return svc
}

// wrap loads b into a freshly zeroed U via the [MutableUser] write side —
// the inverse of U.Base(), used everywhere this Service hands a UserBase
// loaded from or returned by the Store back to its own caller as U.
func (s *Service[U, PU]) wrap(b UserBase) U {
	var u U
	PU(&u).SetBase(b)
	return u
}

// SignUp registers a new account, or reports that the address is already
// registered — without ever returning an error for the latter. See
// [SignUpResult] and the section below for why, and for what this means
// for whoever calls SignUp.
//
// # Enumeration safety
//
// A library that mints tokens cannot fake "we emailed the address that's
// already on file" the way a real mail send can, so SignUp does not try:
// instead, EVERY code path — new address or already-registered — returns
// (SignUpResult, nil) whenever the underlying operations succeed. Several
// things hold, deliberately, and each is load-bearing on its own:
//
//  1. plainPassword is validated against the configured [password.Rules]
//     BEFORE anything else — before the address is even normalized, let
//     alone looked up. A weak password is rejected with [ErrWeakPassword]
//     identically whether the address exists or not, because the decision
//     to reject it is made before SignUp has learned which case it's in.
//  2. Every SignUp call attempts the SAME sequence of operations,
//     regardless of how it turns out — see "Fail closed, symmetrically"
//     below for why this is not merely tidy but load-bearing.
//  3. Once an outcome IS determined, the already-registered branch returns
//     a nil error, never one of this package's sentinels or the Store's.
//     An error return is itself an observable signal a caller could branch
//     on, so "duplicate" is encoded in the returned [SignUpResult], not in
//     the error.
//  4. The already-registered branch hands back the ZERO
//     [SignUpResult.User], never the account it found — see that field's
//     doc. That account's ID, CreatedAt and EmailVerifiedAt would each
//     answer "is this address registered?" on their own, in a single
//     request, to a caller who has proven nothing about the address.
//
// None of this survives contact with an HTTP handler that lets the two
// outcomes look different from outside. Whatever calls SignUp MUST return
// a FIXED response — same status, same body shape, same rough latency —
// regardless of the outcome. That obligation is strictly stronger than
// "do not branch on Created": Created, whether VerifyToken is present,
// whether User is populated, and the wall clock are all observable, and
// any one of them reaching an unauthenticated caller answers the question
// this method exists not to answer. Use VerifyToken (non-empty only when
// Created is true) to decide whether to SEND AN EMAIL, never to decide
// what to tell the HTTP caller. The property is enforced up to the
// boundary of this function and no further.
//
// # Fail closed, by construction
//
// A "look the address up, then branch" implementation — an earlier version
// of this method — closes the timing channel (both branches pay
// comparable [password.Hasher] cost) and the error-VALUE channel (the
// duplicate branch never returns a sentinel), but leaves a louder, simpler
// channel wide open: every operation beyond the single [Store.CreateUser]
// call used to run on only ONE branch. A first attempt at THAT gap made
// the duplicate branch call [Store.FindUserByEmail] and mint a
// verification too — but only on the duplicate branch, which does not
// close the asymmetry, it relocates it: under a read outage, or a Store
// role with INSERT but not DELETE, a NEW address (which never reached
// either call) now sailed through while a REGISTERED one failed. Pointing
// two single-branch operations at each other does not cancel them out.
//
// So every operation SignUp performs after CreateUser runs on BOTH
// branches, unconditionally, as the literal same call — not "the new
// branch does X, the duplicate branch does an equivalent Y":
//
//  1. Hash the password — never [password.Hasher.Dummy]. Dummy cannot
//     fail, by design (see its own doc): closing the write-failure gap
//     needs an operation that CAN fail the same way regardless of branch,
//     and only a real Hash call is that operation.
//  2. Attempt [Store.CreateUser], with that hash — the ONLY signal this
//     method uses to decide new-vs-duplicate. Success or [ErrEmailTaken]
//     both fall through to step 3; anything else returns immediately.
//  3. [Store.FindUserByEmail] the normalized address. On the new branch
//     this reads back the row CreateUser just wrote — a real read that
//     can genuinely fail under a read-path outage, which is the point: a
//     read failure now fails BOTH branches the same way, not just the one
//     that used to perform it.
//  4. Mint a fresh "signup" [Verification] for whichever user step 3
//     returned. On the new branch this is the token
//     [SignUpResult.VerifyToken] returns. On the duplicate branch the
//     SAME call runs against the EXISTING account and its result is
//     discarded — VerifyToken stays empty regardless (see
//     [SignUpResult]) — so this write's failure surface is reachable on
//     both branches too. This step does not delete anything — see "What
//     this does NOT do" below.
//
// The Store calls SignUp performs are therefore identical on every
// invocation, branch-independent through step 4. The only place the two
// branches diverge is the FINAL, in-process decision of what to put in
// the return value — Created, VerifyToken, and whether User is populated
// at all. The enumeration property holds by CONSTRUCTION — there is no
// Store call either branch can reach that the other cannot — not by an
// argument about how comparable two different code paths happen to be.
// What construction does NOT make indistinguishable is the returned
// VALUE: keeping that from leaking is the caller's obligation, stated
// above and on [SignUpResult].
//
// # What this does NOT do to an already-registered account
//
// Step 4 never deletes an existing verification before minting the
// discarded one. An earlier version did, reasoning by analogy to
// [github.com/bernardoforcillo/authlayer/invite.Service.InviteByEmail]'s
// replace-not-accumulate stance on re-invitation — but that analogy does
// not hold here: an email invite's replace runs because the SAME inviter
// is re-inviting an address they already have standing to invite, while
// SignUp's caller has proven nothing about the address at all. Deleting
// on that basis meant an anonymous, unauthenticated prober — the entire
// audience this method exists to give nothing to — could permanently
// invalidate a real accountholder's already-delivered verification link
// merely by "signing up" with their address, shutting them out of their
// own account under [WithRequireVerifiedEmail] — this package still
// exposes no verification resend path, so the only way back would be the
// password-reset detour [Service.ResetPassword] provides (see "Why a
// completed reset verifies the address" there), which a user who never
// lost their password has no reason to look for. So step 4's mint is
// purely additive: an account's real
// pending verification, if it has one, is left exactly as it was: an
// extra, never-returned row that ages out on its own via
// defaultVerificationTTL, same as any other unredeemed token, and never
// interferes with the real one being redeemed.
//
// A Store failure at any step is returned as-is — SignUp cannot honestly
// report Created when it does not know, and guessing would risk exactly
// the silent-degrade "no credential" failure mode this whole package
// refuses to produce.
//
// # Enumeration safety depends on the Store
//
// Everything above proves the SEQUENCE of calls SignUp issues is
// identical regardless of outcome — by construction, not by argument,
// there is no `if`/`else` here that sends one outcome down a call the
// other skips. But identical calls only guarantee identical OUTCOMES if
// the Store answers them consistently, and two of [Store]'s own methods
// carry an obligation this method's safety leans on:
//
//   - [Store.CreateUser] MUST decide ErrEmailTaken from the SAME attempt
//     that performs the write, never from a cheaper, separately-authorized
//     read performed first. Otherwise a condition that blocks writes but
//     not reads makes CreateUser fail only for a genuinely new address —
//     the one that needs the write to succeed — while a duplicate
//     short-circuits to ErrEmailTaken from the read alone.
//   - [Store.FindUserByEmail] MUST read-your-writes with CreateUser: the
//     row CreateUser just returned MUST be visible to the FindUserByEmail
//     call two lines below it. A Store answering from a lagging replica
//     makes that immediate read fail for a brand-new address specifically
//     — its write has not replicated yet — while a genuinely duplicate
//     address's long-since-replicated row is unaffected.
//
// Either violation reopens the exact enumeration oracle this method's own
// doc spends several sections closing, from inside the Store rather than
// from here — see each method's own doc on [Store] for why, in detail.
// This is a joint property: SignUp cannot single-handedly guarantee
// enumeration safety against a Store that does not honor these two
// obligations, no matter how carefully it is written. store/memory and
// store/drops both honor them today (documented on their own CreateUser
// implementations); a third-party Store implementation must too.
//
// SignUpResult.User is populated only when Created is true, and never
// carries a live PasswordHash even then — see that field's own doc and
// [UserBase.PasswordHash]'s.
func (s *Service[U, PU]) SignUp(ctx context.Context, email, plainPassword string) (SignUpResult[U], error) {
	if failed := password.Validate(plainPassword, s.cfg.rules); len(failed) > 0 {
		return SignUpResult[U]{}, fmt.Errorf("%w: %s", ErrWeakPassword, strings.Join(failed, ","))
	}

	normalized := NormalizeEmail(email)
	now := s.cfg.clock()

	hash, err := s.cfg.hasher.Hash(plainPassword)
	if err != nil {
		return SignUpResult[U]{}, err
	}

	_, err = s.store.CreateUser(ctx, UserBase{
		ID:           s.cfg.idGen(),
		Email:        normalized,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	created := err == nil
	if err != nil && !errors.Is(err, ErrEmailTaken) {
		return SignUpResult[U]{}, err
	}

	// From here on, EVERY call is identical regardless of branch — see
	// "Fail closed, by construction" above. created is the only thing
	// that determines the shape of the final return.
	user, ferr := s.store.FindUserByEmail(ctx, normalized)
	if ferr != nil {
		return SignUpResult[U]{}, ferr
	}

	plainToken, verr := s.mintSignupVerification(ctx, user.ID, user.Email, now)
	if verr != nil {
		return SignUpResult[U]{}, verr
	}
	user.PasswordHash = ""

	if !created {
		// The zero U, not the account that was found — see
		// [SignUpResult.User]. The caller attempted to register an address
		// they have proven nothing about; handing them that account's id,
		// CreatedAt and EmailVerifiedAt would answer "is this address
		// registered?" outright.
		return SignUpResult[U]{Created: false}, nil
	}
	return SignUpResult[U]{Created: true, User: s.wrap(user), VerifyToken: plainToken}, nil
}

// mintSignupVerification mints and persists a fresh "signup" [Verification]
// for (userID, email) and returns its plaintext token. Called by
// [Service.SignUp] on every invocation regardless of branch — see that
// method's "Fail closed, by construction" section — and never preceded by
// deleting any prior verification; see "What this does NOT do" there for
// why that would be a mistake.
func (s *Service[U, PU]) mintSignupVerification(ctx context.Context, userID, email string, now time.Time) (string, error) {
	plainToken, tokenHash, err := token.GenerateOpaque()
	if err != nil {
		return "", err
	}
	if _, err := s.store.CreateVerification(ctx, Verification{
		ID:        s.cfg.idGen(),
		UserID:    userID,
		TokenHash: tokenHash,
		Purpose:   PurposeSignup,
		Email:     email,
		ExpiresAt: now.Add(defaultVerificationTTL),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return plainToken, nil
}

// Login authenticates email/plainPassword and, on success, mints a new
// session: an access token (a short-lived, HS256-signed JWT — see
// [WithJWT]) and a refresh token (a long-lived opaque bearer token, whose
// hash becomes the minted [Session]'s TokenHash). ip and userAgent are
// stamped onto that Session as audit fields (see [Session.IP] /
// [Session.UserAgent]) and ip additionally keys the rate limiter, if one is
// configured — see [RateLimiter]'s doc for why never email.
//
// ip must be non-empty — [ErrMissingIP] otherwise, checked before the rate
// limiter is even consulted. A blank ip is not a harmless "unknown": every
// caller that omits it would share ONE rate-limit bucket, so one client
// that forgets to pass its caller's address (or an attacker who realizes
// omitting it is accepted) can exhaust that shared bucket and lock out
// every other client that also omits it — an availability hazard hiding
// behind what looks like a missing-but-optional field.
//
// # Order of checks, and why
//
//  1. ip is non-empty ([ErrMissingIP]) and, if a [RateLimiter] is
//     configured, allows this ip ([ErrRateLimited]) — both checked before
//     the Store or the Hasher are touched at all.
//  2. Look up email (normalized). A miss calls [password.Hasher.Dummy]
//     with plainPassword — spending comparable bcrypt work to the
//     wrong-password case below — and returns [ErrInvalidCredentials].
//  3. An account with no password credential (PasswordHash == "" — see
//     [UserBase]'s doc for why that is a real, supported state, an
//     OAuth-only account being the obvious example) is treated exactly
//     like a lookup miss: Dummy, then ErrInvalidCredentials. Falling
//     through to Verify against an empty hash would return false safely
//     (see [password.Hasher.Verify]'s own doc), but it would also do so
//     near-instantly rather than paying bcrypt's cost — reopening the
//     exact timing gap Dummy exists to close, this time distinguishing
//     "exists, no password" from "exists, wrong password" instead of
//     "exists" from "doesn't".
//  4. Verify the password. A mismatch is [ErrInvalidCredentials] — the
//     same sentinel as cases 2 and 3, deliberately: a caller cannot tell
//     "no such account", "account has no password", and "wrong password"
//     apart from the error alone.
//  5. Only once credentials are proven does this check
//     [WithRequireVerifiedEmail]: an unverified account fails with
//     [ErrEmailNotVerified] here, never earlier, so a caller who does not
//     already know the password cannot use the verified-or-not distinction
//     as its own enumeration channel.
//  6. Only once every check above has passed does this touch the Store
//     with a write ([Store.CreateSession]) — and even that is ordered
//     LAST, after [token.Issue] has already succeeded (see the body): a
//     misconfigured signing key ([WithJWT] never called, or too short)
//     fails before any Session row is persisted, rather than leaving an
//     orphaned, unreachable-by-refresh-token row behind that
//     [Store.ListSessionsByUser] would still report.
//
// # Fail closed
//
// Any Store or RateLimiter error not covered by a case above is returned
// as-is, never folded into ErrInvalidCredentials or a silent success — see
// the package-level "Fail closed" constraint this method, like every other
// one in this file, is held to.
func (s *Service[U, PU]) Login(ctx context.Context, email, plainPassword, ip, userAgent string) (U, string, string, error) {
	var zero U

	if ip == "" {
		return zero, "", "", ErrMissingIP
	}
	if s.cfg.limiter != nil {
		allowed, err := s.cfg.limiter.Allow(ctx, ip)
		if err != nil {
			return zero, "", "", err
		}
		if !allowed {
			return zero, "", "", ErrRateLimited
		}
	}

	normalized := NormalizeEmail(email)
	u, err := s.store.FindUserByEmail(ctx, normalized)
	switch {
	case errors.Is(err, ErrUserNotFound):
		s.cfg.hasher.Dummy(plainPassword)
		return zero, "", "", ErrInvalidCredentials
	case err != nil:
		return zero, "", "", err
	}

	if u.PasswordHash == "" {
		s.cfg.hasher.Dummy(plainPassword)
		return zero, "", "", ErrInvalidCredentials
	}
	if !s.cfg.hasher.Verify(plainPassword, u.PasswordHash) {
		return zero, "", "", ErrInvalidCredentials
	}

	if s.cfg.requireVerifiedEmail && u.EmailVerifiedAt == nil {
		return zero, "", "", ErrEmailNotVerified
	}

	now := s.cfg.clock()
	sessionID := s.cfg.idGen()
	refreshPlain, refreshHash, err := token.GenerateOpaque()
	if err != nil {
		return zero, "", "", err
	}

	// Cleared before wrap, not after: this way neither the claims extender
	// (an application-supplied callback that could otherwise embed it
	// into a JWT claim without realizing) nor this method's own return
	// value ever sees a live credential digest — see
	// [UserBase.PasswordHash]'s own doc for why that field carries json:"-"
	// but is additionally cleared here rather than relying on that alone.
	u.PasswordHash = ""

	// wrapped is the ONE user value both the claims extender and this
	// method's own return statement use — see [WithClaimsExtender]'s doc
	// for why the extender must see the real, just-authenticated identity
	// rather than a separately (and identically) reconstructed one.
	wrapped := s.wrap(u)
	var extra map[string]any
	if s.extender != nil {
		extra = s.extender(wrapped)
	}
	// Issued BEFORE CreateSession, deliberately — see "Order of checks"
	// point 6 above: a bad signing key must fail before any Session row
	// exists to be orphaned.
	accessToken, err := token.Issue(token.Claims{
		Subject:   u.ID,
		SessionID: sessionID,
		Email:     u.Email,
		Extra:     extra,
	}, s.signingKey(), s.cfg.accessTTL)
	if err != nil {
		return zero, "", "", err
	}

	if _, err := s.store.CreateSession(ctx, Session{
		ID:        sessionID,
		UserID:    u.ID,
		TokenHash: refreshHash,
		// FamilyID: this session is the root of its own rotation chain —
		// nothing to inherit from at login — so it names itself. A
		// successor minted by a future refresh carries this same value
		// forward (see auth.go's package doc, "Sessions, families, and
		// rotation").
		FamilyID:  sessionID,
		ExpiresAt: now.Add(s.cfg.refreshTTL),
		CreatedAt: now,
		UserAgent: userAgent,
		IP:        ip,
	}); err != nil {
		return zero, "", "", err
	}

	return wrapped, accessToken, refreshPlain, nil
}

// signingKey returns the current signing key ([WithJWT]'s keys[0]), or nil
// if none was configured. Returning nil rather than indexing an empty slice
// (which would panic) lets [token.Issue]'s own key-length check —
// token.ErrKeyTooShort for anything under 32 bytes, nil included — be what
// fails a misconfigured Service closed, with a clear, existing sentinel,
// instead of this package inventing a second one or panicking itself.
func (s *Service[U, PU]) signingKey() []byte {
	if len(s.cfg.signingKey) == 0 {
		return nil
	}
	return s.cfg.signingKey[0]
}

// VerifyEmail redeems plainToken: a "signup" token marks the account's
// current email verified; an "email_change" token overwrites the account's
// email to the address the token was minted for (see
// [Verification.Email]'s doc — it is that address for every Purpose, not
// only email_change) and then marks THAT address verified. It returns the
// user as it stands after redemption.
//
// An unknown token is whatever [Store.FindVerificationByHash] reports
// (ErrVerificationNotFound). A known but expired token is
// [ErrVerificationExpired] — checked before anything else, so an expired
// token is never claimed; it simply ages out via [Store.PurgeExpired] like
// any other expired row, matching
// [github.com/bernardoforcillo/authlayer/invite.Service.AcceptInvite]'s
// identical stance on an expired EmailInvite. A token minted for
// [PurposePasswordReset] is [ErrVerificationPurpose] — this method does not
// redeem that purpose ([Service.ResetPassword] does) — checked
// before the claim too, so presenting the wrong kind of token here does not
// burn it.
//
// # Ordering, and why it is not negotiable
//
// This method claims the verification FIRST — [Store.DeleteVerification],
// whose contract is rows-affected gated, so of any two callers racing to
// delete the same id (including the SAME token presented twice
// concurrently) at most one ever sees a nil error — and only THEN applies
// its effect (MarkEmailVerified, or UpdateUserEmail followed by
// MarkEmailVerified for an email_change). Only the caller that wins the
// claim proceeds to apply; the other gets ErrVerificationNotFound and
// applies nothing.
//
// The reverse order — apply first, claim second — is what an earlier
// version of this exact pattern did elsewhere in this codebase: see
// [github.com/bernardoforcillo/authlayer/invite.Service.AcceptInvite]'s doc,
// "Ordering, and why", for the incident this method is deliberately built
// not to repeat ("Plan 4 shipped the reverse and admitted two subjects from
// one invitation"). Applying first would let every caller racing on the
// same token reach MarkEmailVerified/UpdateUserEmail — both idempotent
// writes to the SAME target user and address, so a race does not escalate
// to a different account the way AcceptInvite's did — but it would still
// leave the verification row claimable by a concurrent caller for the
// entire duration of the apply step, which is exactly the window
// claim-then-apply exists to close to zero.
//
// One consequence worth stating plainly, matching AcceptInvite's own: this
// is NOT safe to retry with the same token. A failure after the claim
// succeeds (MarkEmailVerified or UpdateUserEmail returning an error) burns
// the verification anyway — the row is already gone. That is the safe
// direction: under-verifying (the caller must request a fresh token) rather
// than leaving a claimed-but-not-yet-applied token redeemable by a second
// presentation.
func (s *Service[U, PU]) VerifyEmail(ctx context.Context, plainToken string) (U, error) {
	var zero U

	v, err := s.store.FindVerificationByHash(ctx, token.HashOpaque(plainToken))
	if err != nil {
		return zero, err
	}

	now := s.cfg.clock()
	if !now.Before(v.ExpiresAt) {
		return zero, ErrVerificationExpired
	}
	switch v.Purpose {
	case PurposeSignup, PurposeEmailChange:
		// Redeemable here; fall through.
	default:
		return zero, ErrVerificationPurpose
	}

	// The claim: exactly one caller ever sees a nil error for this id — see
	// the method doc's "Ordering, and why" section.
	if err := s.store.DeleteVerification(ctx, v.ID); err != nil {
		return zero, err
	}

	// The apply: the verification is burned from here on, whatever happens
	// below.
	if v.Purpose == PurposeEmailChange {
		if err := s.store.UpdateUserEmail(ctx, v.UserID, v.Email, now); err != nil {
			return zero, err
		}
	}
	if err := s.store.MarkEmailVerified(ctx, v.UserID, v.Email, now); err != nil {
		return zero, err
	}

	u, err := s.store.FindUserByID(ctx, v.UserID)
	if err != nil {
		return zero, err
	}
	u.PasswordHash = ""
	return s.wrap(u), nil
}

// Refresh redeems refreshPlain — the opaque refresh token plaintext handed
// to a caller by [Service.Login] or a prior call to Refresh — for a new
// access token and a new refresh token, exchanging (rotating) the presented
// [Session] for a freshly minted successor that shares its FamilyID. See
// auth.go's package doc, "Sessions, families, and rotation", for the model
// this method implements; this doc comment is about the ladder specifically.
//
// # The rotation ladder
//
//  1. tokenHash := [token.HashOpaque](refreshPlain); look the session up by
//     hash. A miss ([Store.FindSessionByHash] returning
//     [Store]'s ErrSessionNotFound) is [ErrTokenInvalid] — a refresh token
//     this Store has never issued, or one it has already forgotten (see
//     [Store.PurgeExpired]).
//  2. ExpiresAt <= now is ALSO ErrTokenInvalid, but — deliberately — does
//     NOT revoke the family: ordinary end-of-life is not evidence of theft,
//     and revoking a family merely because one device's refresh token aged
//     out would needlessly sign out every OTHER device sharing that login.
//     This mirrors why [Store.MarkRotated]'s own predicate excludes expiry
//     — see that method's doc.
//  3. [Store.MarkRotated] atomically attempts to claim this session:
//     ok=true means this caller — and, by MarkRotated's own single-winner
//     contract, ONLY this caller among however many concurrently present
//     the same token — won the transition from current to superseded.
//     ok=false means the row was ALREADY superseded: a genuine replay,
//     indistinguishable (see auth.go's package doc) from a legitimate
//     request racing its own retry, so this method does not try to tell
//     them apart. It revokes EVERY session sharing FamilyID via
//     [Store.DeleteSessionsByFamily] — not merely the presented one — and
//     returns [ErrTokenReuse]. See "Why the whole family" below. A
//     tokenHash that MarkRotated itself can no longer find (the row was
//     deleted between step 1 and here — PurgeExpired, LogoutAll, or another
//     reuse revocation racing this one) is also reported as ErrTokenInvalid,
//     matching step 1's miss case, not surfaced as the raw Store sentinel.
//  4. Only a true ok from step 3 goes on to mint a successor: a fresh
//     opaque refresh token (in the SAME FamilyID as the rotated session, so
//     the chain still traces back to one login) and a fresh access token.
//     THIS IS THE PROPERTY THE WHOLE METHOD EXISTS TO ENFORCE — see the
//     next section for why.
//  5. [Store.CreateSuccessorSession] persists the new Session row — but
//     ONLY if the predecessor rotated in step 3 still exists AT THIS
//     INSTANT. ok=false here means a DIFFERENT caller's own reuse response
//     (or an explicit LogoutAll/RevokeSession/Logout) revoked this
//     session's whole family in the window between step 3 and here: this
//     caller's token was genuine and really did win step 3, but there is no
//     family left to join. Minting nothing and returning [ErrSessionRevoked]
//     is what step 5 exists to guarantee instead of the alternative — an
//     unconditional insert here would silently resurrect an already-revoked
//     family with exactly one live session. See "Why step 5 exists" below.
//
// # Why step 3's result, not step 1's, authorizes minting
//
// The session loaded in step 1 is a stale read the instant this method
// yields the CPU to any concurrent caller — and under Go's scheduler, it
// can. Two callers racing the SAME refresh token can both load a session
// with RotatedAt == nil at step 1: reading RotatedAt THERE and branching on
// it to decide whether to mint would let both callers conclude "not yet
// rotated, safe to mint" and both succeed, after which the original refresh
// token is never actually replayed against a superseded row — a stolen
// token becomes an undetectable second, parallel session, exactly the
// failure [Store.MarkRotated]'s own doc describes. MarkRotated's ok is the
// ONLY value this method treats as authoritative for "did I win", because
// it is the one value computed inside the same atomic compare-and-set that
// performs the mark — see that method's doc for why the check and the mark
// must be one atomic step, not two.
// TestRefreshConcurrentSameTokenExactlyOneWinnerFamilyRevoked, in this
// package's test suite, builds a deterministic (not scheduler-dependent)
// interleaving to pin exactly this.
//
// # Why the whole family, not just the presented session
//
// See auth.go's package doc for the policy this implements: this package
// cannot distinguish an attacker replaying a stolen token from a client
// retrying a raced request with a now-stale one, so it treats every replay
// as compromise. Revoking only the ONE session whose hash was presented
// would leave every successor already minted from this family — including,
// worst case, one an attacker themselves rotated into moments before this
// call — untouched and still live. Revoking the family forces every device
// sharing this login to sign in again: a deliberate, security-first
// tradeoff, not an oversight.
//
// With one bound, and it is sharpest exactly here. "Sign in again" means
// every [Session] row is gone, so no REFRESH token in this family works. It
// does NOT invalidate an ACCESS token already issued for any of them: a
// short-lived HS256 JWT (see [WithJWT] — 15 minutes by default) is
// stateless, and this package never looks a presented one up in the [Store]
// (see [token.Parse]). In the worst case just described — an attacker who
// rotated into a successor moments before this revocation — that attacker
// holds a freshly-minted access token and keeps whatever access it alone
// authorizes for up to its full TTL AFTER the alarm has fired and the
// family is gone. Reuse detection contains the compromise at the refresh
// boundary, not instantly. See [Service.LogoutAll]'s doc, "What this does
// not revoke", for the same bound stated in full and for the SessionID
// ("sid") claim that is the hook for closing it.
//
// # Why step 5 exists
//
// Winning step 3 proves the predecessor row existed and was unrotated at
// THAT instant — it proves nothing about whether it still exists by the
// time this method reaches its own insert. A different caller, replaying a
// DIFFERENT, already-superseded token from this SAME family, loses ITS OWN
// step 3 and responds — per "Why the whole family" above — by calling
// Store.DeleteSessionsByFamily, which can complete in the gap between this
// caller's step 3 and step 5. An earlier version of this method called the
// unconditional [Store.CreateSession] in that gap: the reuse alarm fired,
// correctly revoked the entire family, and this call then silently undid
// it, leaving one live, fully rotating session behind — the compromise the
// alarm exists to stop survives the alarm. [Store.CreateSuccessorSession]
// closes that window the same way step 3 closes ITS window: as one atomic
// check-and-insert, this time gated on "does the family this session
// belongs to still exist" rather than "did I win the compare-and-set" —
// see that method's own doc on [Store] for the exact contract, including
// the atomicity it requires of a backend, the shapes that satisfy that
// requirement, and why a read-then-write implementation leaves open the
// very window the method exists to close. Like every other atomicity MUST
// on [Store], this window is closed only insofar as the backend in use
// honours it.
//
// # Fail closed
//
// Any Store error not itself translated into one of the sentinels above —
// a lookup failure that is not ErrSessionNotFound, a MarkRotated failure, a
// FindUserByID failure for the winning caller, a CreateSuccessorSession
// failure — is returned as-is. In particular, a Store error AFTER step 3
// has already returned ok=true (loading the user, issuing the access
// token, persisting the successor) is surfaced as a plain error, never
// silently downgraded to "no session" or a fabricated success: this method
// never hands back a [LoginResult] it cannot back with every one of those
// steps having genuinely succeeded. A DeleteSessionsByFamily failure at
// step 3's replay branch does NOT mask that a replay was detected: the
// returned error satisfies errors.Is against both [ErrTokenReuse] and the
// Store's own error — see ErrTokenReuse's own doc for why losing that
// signal would be worse than a slightly noisier one.
//
// One accepted, disclosed trade-off: once step 3 has returned ok=true, the
// presented token IS already rotated away — [Store.MarkRotated] performed
// an irreversible write. If [token.Issue] subsequently fails (a
// misconfigured signing key) or step 5 reports ok=false ([ErrSessionRevoked])
// or its own Store error, this method returns that error, but the
// predecessor session cannot be "un-rotated": the caller is left with
// neither a working old token (it is rotated) nor a working new one (it
// was never persisted, or never returned). This mirrors [Service.Login]'s
// own disclosed orphaned-session-row trade-off, and for a related reason:
// this method issues the access token BEFORE reaching step 5 specifically
// so a bad signing key fails before step 5 is even attempted — but it
// cannot avoid the token-loss window itself, since step 3 must run, and
// commit, before this method is even allowed to decide whether it may mint
// at all.
func (s *Service[U, PU]) Refresh(ctx context.Context, refreshPlain string) (LoginResult[U], error) {
	var zero LoginResult[U]
	now := s.cfg.clock()
	tokenHash := token.HashOpaque(refreshPlain)

	// Step 1: find the session. A miss is ErrTokenInvalid.
	sess, err := s.store.FindSessionByHash(ctx, tokenHash)
	switch {
	case errors.Is(err, ErrSessionNotFound):
		return zero, ErrTokenInvalid
	case err != nil:
		return zero, err
	}

	// Step 2: expiry is checked here, against the step-1 read, and — unlike
	// step 3's replay case — never revokes the family.
	if !sess.ExpiresAt.After(now) {
		return zero, ErrTokenInvalid
	}

	// Step 3: the compare-and-set. rotated.RotatedAt is now guaranteed
	// non-nil regardless of ok — either this call just set it (ok=true) or
	// an earlier winner already had (ok=false) — but this method reads only
	// ok, never rotated.RotatedAt, to decide what happens next. See the
	// method doc's "Why step 3's result, not step 1's" section: that
	// distinction is the entire point of this method.
	rotated, ok, err := s.store.MarkRotated(ctx, tokenHash, now)
	switch {
	case errors.Is(err, ErrSessionNotFound):
		return zero, ErrTokenInvalid
	case err != nil:
		return zero, err
	}
	if !ok {
		// A genuine replay. Revoke the whole family, not just this session.
		//
		// A DeleteSessionsByFamily failure here must not swallow the fact
		// that a replay WAS detected — see ErrTokenReuse's own doc for why
		// both are wrapped rather than just derr alone.
		if derr := s.store.DeleteSessionsByFamily(ctx, rotated.FamilyID); derr != nil {
			return zero, fmt.Errorf("%w: %w", ErrTokenReuse, derr)
		}
		return zero, ErrTokenReuse
	}

	// Step 4: this caller won. Mint the successor.
	u, err := s.store.FindUserByID(ctx, rotated.UserID)
	if err != nil {
		return zero, err
	}
	u.PasswordHash = ""
	wrapped := s.wrap(u)

	successorID := s.cfg.idGen()
	refreshPlainNew, refreshHashNew, err := token.GenerateOpaque()
	if err != nil {
		return zero, err
	}

	var extra map[string]any
	if s.extender != nil {
		extra = s.extender(wrapped)
	}
	// Issued BEFORE step 5, deliberately, matching Login's own ordering and
	// for the same reason: a bad signing key must fail before step 5 is
	// even attempted, rather than leaving a successor Session row persisted
	// that no refresh token can ever reach.
	accessToken, err := token.Issue(token.Claims{
		Subject:   rotated.UserID,
		SessionID: successorID,
		Email:     u.Email,
		Extra:     extra,
	}, s.signingKey(), s.cfg.accessTTL)
	if err != nil {
		return zero, err
	}

	// Step 5: persist the successor, but ONLY if the predecessor rotated in
	// step 3 still exists — see the method doc's "Why step 5 exists"
	// section. ok=false here means this family was revoked in the window
	// between step 3 and here; this caller's own token was never replayed,
	// but there is nothing left to join, so this method mints nothing and
	// fails closed with ErrSessionRevoked rather than silently resurrecting
	// an already-revoked family.
	_, ok, err = s.store.CreateSuccessorSession(ctx, rotated.ID, Session{
		ID:        successorID,
		UserID:    rotated.UserID,
		TokenHash: refreshHashNew,
		// FamilyID: inherited from the rotated predecessor, not
		// self-named — this is what keeps the whole chain traceable to
		// one login. See auth.go's package doc.
		FamilyID:  rotated.FamilyID,
		ExpiresAt: now.Add(s.cfg.refreshTTL),
		CreatedAt: now,
		// UserAgent/IP: inherited from the predecessor. Refresh takes no
		// ip/userAgent parameters of its own — the ladder in this method's
		// doc has no step for updating them — so the successor's audit
		// fields describe the login that started this family, not
		// necessarily the device that just rotated it.
		UserAgent: rotated.UserAgent,
		IP:        rotated.IP,
	})
	if err != nil {
		return zero, err
	}
	if !ok {
		return zero, ErrSessionRevoked
	}

	return LoginResult[U]{User: wrapped, AccessToken: accessToken, RefreshToken: refreshPlainNew}, nil
}

// Logout revokes the session identified by refreshPlain. It is idempotent:
// a refreshPlain this Store has never issued, or one whose session has
// already been removed (by a prior Logout, [Service.LogoutAll],
// [Service.RevokeSession], reuse-triggered family revocation, or
// [Store.PurgeExpired]), returns nil rather than an error — a caller
// logging out is asking "make sure this session does not exist", and both
// of those starting states already satisfy that, so there is nothing to
// report as a failure.
//
// Presenting a CURRENT (unrotated) token is an ordinary single-session
// logout: exactly that [Session] row is removed, and the rest of its family
// — in particular its rotated-but-unexpired predecessors, the rows reuse
// detection needs — is left alone. Nothing has been presented that would
// justify sweeping them, and see [Service.LogoutAll] for the deliberate
// "everything, everywhere" call. ExpiresAt is not checked either way: an
// expired token still identifies a row, and removing it is what the caller
// asked for.
//
// # A superseded token revokes the family
//
// If the located session is already rotated (RotatedAt != nil), Logout
// revokes its WHOLE family via [Store.DeleteSessionsByFamily] and returns
// nil — the caller asked to be logged out and they are, more thoroughly.
// Presenting a superseded token carries the identical signal it carries at
// [Service.Refresh], and the two paths must not disagree about what it
// means.
//
// Deleting that single row instead was a complete bypass of reuse
// detection, and it needed no race. Reuse detection works precisely BECAUSE
// the rotated predecessor row is retained: a replay of it loses
// [Store.MarkRotated], and that ok=false is what fires
// [Store.DeleteSessionsByFamily]. So a thief holding a stolen refresh token
// R could call [Service.Refresh](R) to win the rotation and take successor
// S_a, then call Logout(R) with the SAME stolen token to delete the row the
// victim's replay would have tripped over. The victim's client then
// presents R, receives [ErrTokenInvalid] rather than [ErrTokenReuse], the
// family is never revoked, S_a rotates indefinitely, and the victim sees a
// benign "session expired". Confirmed against live PostgreSQL as well as
// the in-memory store.
//
// # What this does not revoke
//
// Either way — one row or the whole family — "revoked" means the [Session]
// row is gone, so the REFRESH token cannot be presented again. It does NOT
// invalidate an ACCESS token already issued for that session: a short-lived
// HS256 JWT (see [WithJWT] — 15 minutes by default) is stateless, and this
// package never looks a presented one up in the [Store] (see [token.Parse]).
// A device holding one keeps working, on whatever its access token alone
// authorizes, for up to the remainder of that token's own TTL after this
// call. The family case is the one to watch: it now signs out MORE than the
// caller presented, and every one of those devices keeps its current access
// token for up to a full TTL. See [Service.LogoutAll]'s doc, "What this does
// not revoke", for the same bound in full and for the SessionID ("sid")
// claim that is the hook for closing it.
//
// A non-sentinel Store error is returned as-is; see the package's "Fail
// closed" constraint.
func (s *Service[U, PU]) Logout(ctx context.Context, refreshPlain string) error {
	sess, err := s.store.FindSessionByHash(ctx, token.HashOpaque(refreshPlain))
	switch {
	case errors.Is(err, ErrSessionNotFound):
		return nil
	case err != nil:
		return err
	}
	if sess.RotatedAt != nil {
		// A superseded token was presented. That is the SAME signal
		// [Service.Refresh] treats as a replay, and the two paths must not
		// disagree about what it means — see the method doc's "A
		// superseded token" section. Revoke the whole family rather than
		// deleting the tripwire row this session is.
		if err := s.store.DeleteSessionsByFamily(ctx, sess.FamilyID); err != nil {
			return err
		}
		return nil
	}
	if err := s.store.DeleteSession(ctx, sess.ID); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			// Raced with something else that deleted it first (another
			// Logout call for the same token, a family revocation, ...) —
			// still idempotent from this caller's point of view.
			return nil
		}
		return err
	}
	return nil
}

// LogoutAll revokes every session belonging to userID, across every
// family — every device and browser this user is currently signed in on,
// bounded by "What this does not revoke" below. A user with none is not an
// error.
//
// This is implemented as one [Store.DeleteSessionsByFamily] call per
// DISTINCT family among the user's sessions, rather than one
// [Store.DeleteSession] call per row returned by
// [Store.ListSessionsByUser]: DeleteSessionsByFamily also removes that
// family's rotated-but-unexpired predecessors (see auth.go's package doc
// for why those rows are retained rather than deleted at rotation time),
// not merely whichever rows happened to still exist at the instant the
// list was read.
//
// # What this does not revoke
//
// "Every device" above means every [Session] row — every REFRESH token — is
// gone: [Service.Refresh] on any of them now fails, and
// [Service.ListSessions] returns nothing. It does NOT invalidate an ACCESS
// token already issued for any of those sessions. A short-lived HS256 JWT
// (see [WithJWT] — 15 minutes by default) is stateless by design, and this
// package never looks a presented one up in the [Store], only verifies its
// signature and expiry (see [token.Parse]). A device holding one keeps
// working, on every request its access token alone authorizes, for up to
// the remainder of that token's own TTL after this call has removed every
// session it had. So the refresh side is revoked INSTANTLY and the access
// side WITHIN ONE ACCESS TTL — read the "every device and browser" sentence
// above with that bound attached.
//
// This is inherent to a stateless access token, not a defect of this
// method, and every other revocation path in this package
// ([Service.Logout], [Service.RevokeSession], [Service.ChangePassword],
// [Service.ResetPassword], and [Service.Refresh]'s own reuse response)
// carries it identically. An application that needs another device's access
// to stop being honoured sooner than that TTL must check the SessionID
// ("sid") claim (see [token.Claims.SessionID], stamped by [Service.Login]
// and [Service.Refresh] at mint time) against the [Store] on every request
// — the same per-request lookup [Service.Refresh] and
// [Service.RevokeSession] already perform — rather than trusting a parsed,
// still-unexpired JWT alone. Shortening the access TTL through [WithJWT]
// narrows the window without closing it.
func (s *Service[U, PU]) LogoutAll(ctx context.Context, userID string) error {
	sessions, err := s.store.ListSessionsByUser(ctx, userID)
	if err != nil {
		return err
	}
	done := make(map[string]bool, len(sessions))
	for _, sess := range sessions {
		if done[sess.FamilyID] {
			continue
		}
		done[sess.FamilyID] = true
		if err := s.store.DeleteSessionsByFamily(ctx, sess.FamilyID); err != nil {
			return err
		}
	}
	return nil
}

// ListSessions returns every session belonging to userID — rotated or not,
// expired or not, exactly as [Store.ListSessionsByUser] reports them — and
// nothing belonging to any other user: it is a thin, scoped pass-through,
// not a place this package adds cross-user visibility.
//
// # This is rotation history, not a device list
//
// Because rotated rows are retained until [Store.PurgeExpired] (they are
// what makes replay detectable — see auth.go's package doc), one device
// refreshing at the 15-minute default TTL accumulates about 97 rows in a
// day, 96 of them superseded, none purgeable until the refresh TTL passes.
// A "your devices" screen is therefore NOT this slice: a caller wanting
// only the currently-presentable sessions filters on RotatedAt == nil and
// ExpiresAt.After(now) itself, and a caller wanting one entry per LOGIN
// groups by FamilyID — every row sharing a FamilyID descends from the same
// login on the same device.
//
// [Service.RevokeSession] takes a Session.ID but revokes that session's
// whole FAMILY, precisely so a handler built from this listing signs the
// device out whichever of its rows the user happened to pick — see that
// method's doc.
func (s *Service[U, PU]) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	return s.store.ListSessionsByUser(ctx, userID)
}

// RevokeSession signs out the login that sessionID belongs to: it resolves
// sessionID to its [Session] FamilyID and revokes that whole family via
// [Store.DeleteSessionsByFamily] — but ONLY if sessionID belongs to userID,
// never by sessionID alone. A sessionID that exists but belongs to a
// DIFFERENT user is reported identically to a sessionID that does not exist
// at all ([Store]'s ErrSessionNotFound): this method authorizes the
// revocation itself, by the id's membership in userID's own
// [Store.ListSessionsByUser] results, rather than trusting a
// caller-supplied (userID, sessionID) pair to already be consistent. An
// application handler that reads userID from an authenticated caller's own
// access token and sessionID from request input cannot use this method to
// revoke a different user's session — or, now, a different user's family —
// by guessing or enumerating ids. Revoking a family that has already been
// revoked is not an error: DeleteSessionsByFamily deleting zero rows
// succeeds, so this method is idempotent for as long as the id remains
// resolvable, and reports ErrSessionNotFound once the rows are gone.
//
// # Why a family, not a row
//
// A family is one login on one device — every row sharing a FamilyID
// descends from it by rotation — so "revoke the family" is exactly what a
// "sign this device out" control means, and every other revocation path in
// this package ([Service.LogoutAll], [Service.ChangePassword],
// [Service.ResetPassword], and [Service.Refresh]'s own reuse response)
// already works per family.
//
// Deleting the single named row instead silently failed to sign anything
// out, in the most common way this method is called.
// [Service.ListSessions] returns rotation HISTORY (see its doc), so a "your
// devices" screen built from it lists a family's superseded rows alongside
// its current one — about 97 rows per device per day at the default TTL,
// 96 of them superseded. Revoking whichever row the user picked deleted a
// superseded entry, returned nil, and left the device refreshing from its
// current successor: a revocation UI that reports success and signs nobody
// out.
//
// # What this does not revoke
//
// "Sign this device out" is a claim about [Session] rows, which is to say
// about the family's REFRESH tokens: they are gone, and [Service.Refresh]
// on any of them fails immediately. It does NOT invalidate an ACCESS token
// the device was already issued. That token is a stateless HS256 JWT (see
// [WithJWT] — 15 minutes by default) this package never looks up in the
// [Store], only verifies (see [token.Parse]), so the revoked device keeps
// whatever its access token alone authorizes for up to the remainder of
// that token's own TTL after this call returns nil. A "your devices" screen
// that reports "signed out" immediately is therefore accurate about the
// refresh side and up to one access TTL early about the rest — worth saying
// in the UI if the distinction matters to the operator. See
// [Service.LogoutAll]'s doc, "What this does not revoke", for the same
// bound in full and for the SessionID ("sid") claim that closes it.
func (s *Service[U, PU]) RevokeSession(ctx context.Context, userID, sessionID string) error {
	sessions, err := s.store.ListSessionsByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if sess.ID == sessionID {
			// Resolve the named session to its FAMILY and revoke that —
			// see the method doc's "Why a family, not a row" section.
			return s.store.DeleteSessionsByFamily(ctx, sess.FamilyID)
		}
	}
	return ErrSessionNotFound
}

// ChangePassword changes userID's password from current to next, requiring
// current to verify against the account's existing credential before
// anything is written — this is what makes it safe for an application to
// expose without re-authenticating the caller through a full login first.
// next is validated against the configured [password.Rules]
// ([ErrWeakPassword] on failure) before it is hashed and persisted.
//
// # Identifying the caller's own session
//
// On success, ChangePassword revokes every OTHER session belonging to
// userID — every other device/browser this account is currently signed in
// on (see "What revocation does not revoke" below for what that guarantee
// does NOT include) — while leaving the caller's OWN, currently-in-use
// session alive, so the very request that changed the password does not
// itself get logged out. That requires knowing WHICH of userID's sessions
// belongs to the caller, and a signature of just (ctx, userID, current,
// next) gives this method nothing to distinguish "the session this request
// is using" from any of the account's other sessions — so this method's
// signature adds a fifth parameter, currentSessionID, to close that gap;
// see the parameter list below.
//
// currentSessionID is the [Session.ID] of the caller's own, currently
// presented session — ordinarily the SessionID claim off the access token
// an application already validated to authenticate this very request (see
// [token.Claims.SessionID], stamped by [Service.Login] and [Service.Refresh]
// at mint time). Passing an empty string, or an id that does not belong to
// userID at all, protects nothing: every session is revoked, the same as
// [Service.LogoutAll] — a deliberately fail-closed default for a
// security-sensitive action, not a silent no-op. A caller that cannot
// supply its own session id (a service account changing another user's
// password out-of-band, say) gets exactly that "everywhere" behaviour,
// which is the safe direction to default to.
//
// # What revocation does not revoke
//
// "Revoked" above means the [Session] row — the refresh token — is gone:
// [Service.Refresh] on it now fails, and [Service.ListSessions] stops
// listing it. It does NOT invalidate an access token ALREADY ISSUED for
// that session: a short-lived HS256 JWT (see [WithJWT] — 15 minutes by
// default) is stateless by design, and this package never looks a
// presented one up in the [Store] to check it is still current, only
// verifies its signature and expiry (see [token.Parse]). A device holding
// one keeps working for up to the remainder of its own TTL after this call
// revokes the [Session] that minted it. This is the same limitation
// [Service.LogoutAll] already has — inherent to a stateless access token,
// not a defect specific to this method, but stated here explicitly rather
// than left for the prose above to imply otherwise. An application that
// needs another device's access to stop being honoured sooner than that
// TTL must check the SessionID ("sid") claim (see [token.Claims.SessionID])
// against the [Store] on every request, the same per-request lookup this
// package's own [Service.Refresh] and [Service.RevokeSession] already
// perform, rather than trusting a parsed, still-unexpired JWT alone.
//
// # Ordering
//
//  1. [Store.FindUserByID] loads the account; ErrUserNotFound propagates
//     as-is.
//  2. An account with no password credential (PasswordHash == "" — see
//     [UserBase]'s doc) is treated like a lookup miss: [password.Hasher.Dummy]
//     runs (comparable-cost hygiene, mirroring [Service.Login]'s identical
//     stance on its own no-credential case — see that method's doc), then
//     [ErrInvalidCredentials].
//  3. current is checked against the stored hash via [password.Hasher.Verify].
//     A mismatch is ErrInvalidCredentials — nothing is written, and next is
//     never even validated, so a caller who does not know the current
//     password learns nothing about next's own validity either.
//  4. next is validated against the configured [password.Rules];
//     [ErrWeakPassword] on failure.
//  5. next is hashed and persisted via [Store.UpdateUserPassword].
//  6. Every outstanding "password_reset" AND "email_change" [Verification]
//     for this account is invalidated, via two
//     [Store.DeleteVerificationsByUserAndPurpose] calls — one per purpose,
//     both fail-closed. See "Why both purposes, and what the sweep does
//     not cover" below.
//  7. Every session NOT sharing currentSessionID's family is revoked via
//     [Store.DeleteSessionsByFamily], one call per distinct OTHER family —
//     the same "list, then delete per distinct family" shape
//     [Service.LogoutAll] uses, so a rotated-but-unexpired predecessor row
//     in another family is swept too, not just the currently-live session
//     in that family.
//
// # Why both purposes, and what the sweep does not cover
//
// A password change is the one action a user takes when they suspect
// compromise, so it must leave nothing armed that can quietly undo it.
// Two verification purposes can:
//
// A still-valid reset link — one whose [Service.RequestPasswordReset] call
// ran and returned BEFORE this call started — would otherwise stay
// redeemable AFTER the owner changed their password, taking the account
// right back for the remainder of the reset token's TTL.
//
// A still-valid "email_change" token is the STRONGER of the two, and
// sweeping only the reset one left the stronger door open: it lives
// defaultVerificationTTL (24h) rather than the reset token's 1h,
// [Service.RequestEmailChange] mints one with no current password at all
// (so a briefly-stolen access token — which, per "What revocation does not
// revoke" above, outlives even [Service.LogoutAll] for up to its own TTL —
// suffices to arm it), and [Service.VerifyEmail] redeems it with NO
// authentication whatsoever, moving the address to the attacker's via
// [Store.UpdateUserEmail]. After that the victim cannot recover:
// [Service.Login] and [Service.RequestPasswordReset] both look accounts up
// BY email. Purpose-scoping the sweep is still right — an "email_change"
// token is not a "password_reset" token, and this method deliberately does
// not touch "signup" tokens, which grant nothing over the credential — but
// purpose-scoping was never a reason to leave a credential-rotation bypass
// armed.
//
// Both sweeps carry the SAME guarantee, and it is SEQUENTIAL ONLY: nothing
// orders either against a concurrently-running [Service.RequestPasswordReset]
// or [Service.RequestEmailChange] call. If that other call's own
// [Store.CreateVerification] has not yet committed at the instant the sweep
// runs, the sweep finds nothing, the concurrent mint proceeds moments
// later, and the resulting token survives — demonstrated deterministically
// by parking an in-flight RequestPasswordReset at CreateVerification,
// running ChangePassword to completion (the sweep finds nothing), then
// releasing the mint: the token redeems, and the attacker's password logs
// in. Closing that window for real would need a transaction spanning both
// the sweep and the mint, which [Store] does not offer today — this method
// does not claim to close it, only the strictly-sequential case.
// [Service.ResetPassword] closes the same two side doors, with the same
// sequential-only scope, for its own, differently-triggered path; see that
// method's doc.
//
// A Store or Hasher error at any step is returned as-is — see the
// package's "Fail closed" constraint.
func (s *Service[U, PU]) ChangePassword(ctx context.Context, userID, currentSessionID, current, next string) error {
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if u.PasswordHash == "" {
		s.cfg.hasher.Dummy(current)
		return ErrInvalidCredentials
	}
	if !s.cfg.hasher.Verify(current, u.PasswordHash) {
		return ErrInvalidCredentials
	}

	if failed := password.Validate(next, s.cfg.rules); len(failed) > 0 {
		return fmt.Errorf("%w: %s", ErrWeakPassword, strings.Join(failed, ","))
	}
	hash, err := s.cfg.hasher.Hash(next)
	if err != nil {
		return err
	}

	now := s.cfg.clock()
	if err := s.store.UpdateUserPassword(ctx, userID, hash, now); err != nil {
		return err
	}

	// Close BOTH token side doors — see the method doc's point 6. The
	// email_change sweep is not a tidier variant of the reset one; it is
	// the stronger of the two doors.
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, userID, PurposePasswordReset); err != nil {
		return err
	}
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, userID, PurposeEmailChange); err != nil {
		return err
	}

	sessions, err := s.store.ListSessionsByUser(ctx, userID)
	if err != nil {
		return err
	}
	var currentFamilyID string
	for _, sess := range sessions {
		if sess.ID == currentSessionID {
			currentFamilyID = sess.FamilyID
			break
		}
	}
	done := make(map[string]bool, len(sessions))
	if currentFamilyID != "" {
		done[currentFamilyID] = true
	}
	for _, sess := range sessions {
		if done[sess.FamilyID] {
			continue
		}
		done[sess.FamilyID] = true
		if err := s.store.DeleteSessionsByFamily(ctx, sess.FamilyID); err != nil {
			return err
		}
	}
	return nil
}

// RequestPasswordReset begins a password-reset flow for email: for a known,
// registered address it mints a "password_reset" [Verification] and returns
// (token, true, nil); for an unknown address it returns ("", false, nil) —
// deliberately never an error purely because the address is unregistered.
// The CALLER carries the same obligation [Service.SignUp] places on its
// own caller — see that method's doc, "Enumeration safety": whatever wraps
// this method MUST return a FIXED response, same status and body shape and
// rough latency, regardless of the outcome. ok exists to decide whether to
// actually send a reset email, never to shape an HTTP response, and
// neither does the returned token's presence.
//
// ip must be non-empty ([ErrMissingIP]) and, if a [RateLimiter] is
// configured via [WithRateLimiter], allows this ip ([ErrRateLimited]) —
// both checked before anything address-specific happens at all, the same
// ordering [Service.Login] uses and for the same reason (see that method's
// doc). If [WithPasswordResetRateLimiter] is also configured, this method
// additionally consults it keyed by the normalized address — see "The
// enumeration property, again" below for why a denial from THAT limiter
// looks nothing like ErrRateLimited.
//
// # The enumeration property, again
//
// This method has the same shape as [Service.SignUp] and is held to the
// same standard — see that method's doc for the full discipline. This
// section states how each of its points lands here specifically, corrected
// against actual measurement rather than assumption (see point 5 — an
// earlier version of this doc understated this method's residual timing
// channel and overstated why a symmetric alternative wasn't available;
// both are corrected below rather than softened).
//
//  1. Identical calls, identical order — with two necessary, disclosed
//     exceptions. The ip check, the IP [RateLimiter], email normalization,
//     the address [RateLimiter] (keyed by the normalized address whether or
//     not it identifies anyone — the limiter is never told which), and
//     [Store.FindUserByEmail] all run in the SAME order on every call,
//     regardless of outcome. [token.GenerateOpaque] runs unconditionally
//     too, right after the lookup, on every call, whether or not its result
//     is ever used.
//
//     Two Store writes are branch-exclusive:
//     [Store.DeleteVerificationsByUserAndPurpose] (invalidating any earlier
//     "password_reset" token for this user — honouring that method's own
//     documented contract on [Store] — before minting a new one) and
//     [Store.CreateVerification] itself. Both require a real UserID, so
//     unlike SignUp — where [Store.CreateUser]'s own attempt IS the
//     new-vs-duplicate signal and leaves a real [UserBase] row on BOTH
//     branches for every later step to run against — this method has no
//     row on the unknown branch to run either write against. [s.cfg.clock]
//     and [s.cfg.idGen] are pulled in by those same two writes and so are
//     branch-exclusive too; neither can fail, so neither adds anything to
//     point 3's error-set argument, but a caller-injected [WithIDGenerator]
//     with an observable side effect or its own cost (a shared counter, an
//     external ID service) would run only on the known branch — the
//     default, [github.com/bernardoforcillo/authlayer/internal/uid.NewV7],
//     is a pure local computation and carries no such risk.
//
//     This does NOT mean no symmetric alternative exists — an earlier
//     version of this doc claimed exactly that, and it was wrong. Neither
//     [github.com/bernardoforcillo/authlayer/store/drops] nor
//     [github.com/bernardoforcillo/authlayer/store/memory] declares a
//     foreign key between verifications and users, so an unconditional
//     [Store.CreateVerification] (and, for the delete, an unconditional
//     [Store.DeleteVerificationsByUserAndPurpose]) keyed on a reserved,
//     synthetic UserID on the unknown branch too WOULD run an identical
//     call on both branches, closing point 5's timing gap entirely. This
//     implementation deliberately does not do that: the trade is letting an
//     unauthenticated caller grow the verifications table at will — bounded
//     by the IP limiter, and self-cleaning via [Store.PurgeExpired] against
//     this method's own TTL — in exchange for closing the gap. That is
//     genuinely defensible either way; this implementation keeps the
//     asymmetric shape and documents its real cost (point 5) rather than
//     claiming the symmetric option doesn't exist.
//
//  2. Rate limiting by IP is a plain [ErrRateLimited], exactly like Login,
//     because it is decided before any address-specific behaviour runs at
//     all. Rate limiting by ADDRESS is NOT: a denial there returns ("",
//     false, nil) — the exact shape an unknown address gets — never
//     ErrRateLimited. Returning ErrRateLimited for the address-keyed case
//     would itself be an oracle, reachable only once enough requests for
//     THAT address have run — folding it into the success-shaped "no" the
//     unknown branch already uses closes that regardless of how many
//     requests are sent.
//
//  3. The error sets are identical too, by different means for different
//     calls. The ip check, the IP limiter, the address limiter, and
//     [Store.FindUserByEmail] itself all run on EVERY call, so a real
//     failure from any of them is symmetric by construction and returned
//     as-is — [Service.SignUp]'s stance on its own branch-independent
//     calls. Both branch-exclusive writes from point 1 —
//     [Store.DeleteVerificationsByUserAndPurpose] and
//     [Store.CreateVerification] — are handled the same way ON PURPOSE:
//     neither failure is returned as an error. Both are folded into the
//     same ("", false, nil) an unknown address gets. Surfacing either as a
//     real error would be reachable ONLY on the known-address branch by
//     construction — exactly the "any store failure reachable on one
//     branch only is a binary oracle" trap, reached this time through a
//     write's FAILURE rather than a write's presence. Masking them costs
//     the caller a clean signal that the verifications table specifically
//     is unhealthy — a real, disclosed trade-off — but the alternative
//     hands back exactly the address oracle this method exists to deny.
//
//  4. Never an error purely for an unknown address: confirmed structurally
//     above — the ErrUserNotFound branch falls straight through to the
//     same return every other "deny" path in this method uses, ("", false,
//     nil), never propagated as ErrUserNotFound or anything else.
//
//  5. Timing is the channel that remains, and it is measured, not merely
//     theoretical. Against a live PostgreSQL-backed [Store]
//     ([github.com/bernardoforcillo/authlayer/store/drops]), 400 samples
//     per branch first measured a known-address median of 1510µs against
//     an unknown-address median of 308µs — Δ≈1.2ms, roughly 5×, with the
//     two distributions nearly disjoint under low-jitter, same-host
//     measurement. Point 1's second branch-exclusive write (added to honour
//     [Store]'s DeleteVerificationsByUserAndPurpose contract) widened it:
//     re-measured after that write, the known-address median ran 2276-3453µs
//     against an unknown-address 556-576µs — Δ≈1.7-2.9ms, roughly 4-6×,
//     disjoint at the known branch's 5th percentile against the unknown
//     branch's 95th. The channel got wider, not narrower, and the number
//     here is the post-write one. Over realistic WAN jitter this needs on the order of 10² to 10³
//     samples against the SAME address to resolve reliably — practical for
//     a targeted check against one suspected address, not for bulk
//     enumeration across many candidates, but real, and this doc will not
//     call it "far weaker, noisier" without a number behind that claim.
//     [WithPasswordResetRateLimiter] is the control that bounds it: it caps
//     how many samples an attacker can collect against any ONE address,
//     which is the resource this timing channel actually needs. An
//     operator who wants the channel closed rather than merely bounded
//     should set a tight per-address limit, or take the symmetric
//     synthetic-row alternative point 1 describes and this implementation
//     does not; this package does not close it structurally on its own.
//
// The response-SHAPE duty stated above the numbered list — that whatever
// wraps this method must return the same status/body regardless of ok —
// extends to TIMING too, after point 5: a caller that awaits this method's
// return and then performs address-dependent work before responding (a real
// email send, say) can reopen point 5's channel at the transport layer even
// though this method's own two possible outcomes already take measurably
// different time to produce internally. A caller that cares should either
// accept point 5's channel as documented and bounded by
// [WithPasswordResetRateLimiter], or normalize its OWN response timing
// independently (a fixed delay, a queued/async send) — this package does
// not attempt that on a caller's behalf.
//
// [Service.SignUp]'s two Store obligations (CreateUser deciding
// ErrEmailTaken from the write itself, FindUserByEmail reading its own
// writes) are not load-bearing here — this method never calls CreateUser at
// all — but a [Store.FindUserByEmail] answering from a stale replica would
// still be a problem of its own kind: a very recently registered address
// could read back as unknown right after signing up. That is an ordinary
// staleness bug, not the specific enumeration oracle SignUp's doc
// describes (there is no "attempt a write, then immediately read it back"
// pairing here for replica lag to exploit asymmetrically), so it is called
// out here as a general caveat rather than inherited as the same numbered
// obligation.
func (s *Service[U, PU]) RequestPasswordReset(ctx context.Context, email, ip string) (string, bool, error) {
	if ip == "" {
		return "", false, ErrMissingIP
	}
	if s.cfg.limiter != nil {
		allowed, err := s.cfg.limiter.Allow(ctx, ip)
		if err != nil {
			return "", false, err
		}
		if !allowed {
			return "", false, ErrRateLimited
		}
	}

	normalized := NormalizeEmail(email)

	addressAllowed := true
	if s.cfg.resetLimiter != nil {
		allowed, err := s.cfg.resetLimiter.Allow(ctx, normalized)
		if err != nil {
			return "", false, err
		}
		addressAllowed = allowed
	}

	u, err := s.store.FindUserByEmail(ctx, normalized)
	switch {
	case errors.Is(err, ErrUserNotFound):
		// known stays false; fall through to the identical calls below.
	case err != nil:
		return "", false, err
	}
	known := err == nil

	// Identical on every call, whether or not its result is ever used — see
	// the method doc's "The enumeration property, again", point 1.
	plainToken, tokenHash, gerr := token.GenerateOpaque()
	if gerr != nil {
		return "", false, gerr
	}

	if !known || !addressAllowed {
		return "", false, nil
	}

	now := s.cfg.clock()

	// Invalidate any earlier "password_reset" token for this user before
	// minting the new one — honouring [Store.DeleteVerificationsByUserAndPurpose]'s
	// own documented contract. Branch-exclusive, like CreateVerification
	// below — see the method doc's "The enumeration property, again",
	// points 1 and 3.
	if derr := s.store.DeleteVerificationsByUserAndPurpose(ctx, u.ID, PurposePasswordReset); derr != nil {
		// See point 3: a failure reachable ONLY on this branch must not be
		// surfaced as a distinguishable error.
		return "", false, nil
	}

	if _, cerr := s.store.CreateVerification(ctx, Verification{
		ID:        s.cfg.idGen(),
		UserID:    u.ID,
		TokenHash: tokenHash,
		Purpose:   PurposePasswordReset,
		Email:     u.Email,
		ExpiresAt: now.Add(defaultPasswordResetTTL),
		CreatedAt: now,
	}); cerr != nil {
		// See the method doc, point 3: a failure reachable ONLY on this
		// branch must not be surfaced as a distinguishable error.
		return "", false, nil
	}

	return plainToken, true, nil
}

// ResetPassword redeems plainToken — a "password_reset" [Verification]
// minted by [Service.RequestPasswordReset] — setting the account's password
// to next, certifying the address the token was delivered to if it is not
// already certified (see "Why a completed reset verifies the address"
// below), and revoking EVERY session the account has, on every device (see
// [Service.ChangePassword]'s doc, "What revocation does not revoke", for
// what that guarantee does NOT include — the same limitation applies here):
// unlike [Service.ChangePassword], there is no "caller's own session" to spare
// here, because presenting a valid reset token is not proof the caller is
// using any of the account's existing sessions at all — it may be reached
// from a device that was never signed in, precisely the scenario this flow
// exists for ("I lost access and can't use my old sessions"). Revoking
// everything is the safe assumption: whoever redeemed the token now holds
// the only credential that matters, and every session minted under the OLD
// password is treated the way [Service.Refresh] treats a detected token
// theft — revoked outright, not trusted to still be the same legitimate
// user.
//
// An unknown token is whatever [Store.FindVerificationByHash] reports
// (ErrVerificationNotFound). A known but expired token is
// [ErrVerificationExpired]. A token minted for any purpose OTHER than
// [PurposePasswordReset] is [ErrVerificationPurpose] — both checked before
// the token is claimed, matching [Service.VerifyEmail]'s identical stance,
// so neither burns the token. next is validated against the configured
// [password.Rules] ([ErrWeakPassword]) and hashed BEFORE the claim too: a
// weak or otherwise-doomed next must not cost the caller their one-time
// token — the same reasoning VerifyEmail applies to its own pre-claim
// checks, extended one step further because this method, unlike
// VerifyEmail, has a "the new value might itself be invalid" step at all.
//
// # Ordering, and why it is not negotiable
//
// Exactly like [Service.VerifyEmail] — see that method's doc, "Ordering,
// and why it is not negotiable", for the incident ("Plan 4 shipped the
// reverse and admitted two subjects from one invitation") this ordering is
// deliberately built not to repeat — this method claims the verification
// FIRST ([Store.DeleteVerification], rows-affected gated so at most one of
// any two callers racing the SAME token ever sees a nil error) and only
// THEN applies its effect ([Store.UpdateUserPassword], then the session
// revocation below). A failure after the claim succeeds burns the
// verification anyway — under-resetting (the caller must request a fresh
// token) rather than leaving a claimed-but-not-yet-applied token redeemable
// by a second presentation. This is why every step that CAN be checked or
// prepared before commitment — expiry, purpose, [password.Validate], and
// the hash itself — happens before the claim: the only work left to run
// AFTER the token is irrevocably burned is a write already known to hold
// valid input.
//
// After [Store.UpdateUserPassword] succeeds, two
// [Store.DeleteVerificationsByUserAndPurpose] calls — one per purpose, both
// fail-closed — invalidate every OTHER outstanding "password_reset" token
// AND every outstanding "email_change" token for the same user.
//
// The reset sweep: the token THIS call redeemed is already gone via the
// claim above, but a second, still-live token from an earlier
// [Service.RequestPasswordReset] call that already ran and returned BEFORE
// this call started is not, and would otherwise still grant a full password
// reset after this one already completed.
//
// The email_change sweep closes the stronger of the two doors, and sweeping
// only the reset one left it open: an "email_change" token lives
// defaultVerificationTTL (24h) rather than this token's 1h, is minted with
// no current password at all by [Service.RequestEmailChange], and is
// redeemed by [Service.VerifyEmail] with NO authentication whatsoever —
// moving the account to the attacker's address, after which the victim
// cannot recover, since [Service.Login] and [Service.RequestPasswordReset]
// both look accounts up BY email. A reset is a credential rotation, most
// often performed precisely because the account may be compromised, so it
// must not leave that armed.
//
// These are the same two side doors [Service.ChangePassword] closes for its
// own, differently-triggered path, with the identical SEQUENTIAL-ONLY scope
// that method's doc discloses: nothing orders either sweep against a
// [Service.RequestPasswordReset] or [Service.RequestEmailChange] call whose
// own [Store.CreateVerification] is genuinely concurrent with this one, and
// a token minted by such a call can still survive and later redeem — see
// [Service.ChangePassword]'s doc, point 6, for the deterministic
// demonstration and why closing that window would need a transaction
// [Store] does not offer.
//
// # Why a completed reset verifies the address
//
// A reset token is only ever deliverable to the address it was minted for,
// so redeeming one IS proof of control of that address — the same proof a
// "signup" token carries, arriving through a different door. A successful
// reset therefore stamps [UserBase.EmailVerifiedAt] via
// [Store.MarkEmailVerified] when it is not already set.
//
// Without this, [WithRequireVerifiedEmail](true) — which the readme's own
// quick start enables — had no way out, because this package exposes no
// verification resend path: an attacker who signed up with an address they
// did not own permanently denied the real owner that address (the owner
// could prove control through a reset and STILL could not log in), and any
// user whose signup email was lost was locked out for good.
//
// Two guards keep the stamp honest, and both are why this reads the user
// row rather than stamping unconditionally:
//
//   - Already verified: EmailVerifiedAt is left exactly as it was.
//     [Store.MarkEmailVerified] is idempotent and would happily re-stamp
//     it to now, but that field records WHEN control was first proven, and
//     moving it forward on every unrelated password reset would falsify an
//     audit value for no gain.
//   - A different address: the proof is about [Verification.Email], the
//     address this token was DELIVERED to, not whatever the row happens to
//     hold at redemption time. If the account's address changed in between
//     (and was left unverified, as [Store.UpdateUserEmail] leaves it),
//     nothing is stamped — the reset still resets the password and
//     certifies nothing.
//
// The read and the stamp are two calls, not one atomic step, and that is
// safe HERE specifically: a concurrent [Store.UpdateUserEmail] landing
// between them cannot produce a false verification, because
// MarkEmailVerified re-checks the address against the row's CURRENT value
// as one atomic step of its own (see its doc) and returns ErrEmailMismatch
// rather than certifying an address nobody proved control of. The two
// guards above are therefore an optimization of intent, not the
// enforcement point; the enforcement point is in the Store.
//
// Only THEN is every session belonging to the verification's UserID
// revoked — one [Store.DeleteSessionsByFamily] call per distinct family,
// the same "list, then delete per distinct family" shape
// [Service.LogoutAll] uses, so rotated-but-unexpired predecessor rows are
// swept too, not just each family's currently-live session.
//
// A Store or Hasher error at any step is returned as-is — see the
// package's "Fail closed" constraint. In particular, a
// [Store.DeleteSessionsByFamily] failure partway through the revocation
// loop is returned immediately, leaving whichever families were already
// revoked revoked and the rest untouched — the caller sees a non-nil error
// either way and must not assume the reset "mostly worked".
func (s *Service[U, PU]) ResetPassword(ctx context.Context, plainToken, next string) error {
	v, err := s.store.FindVerificationByHash(ctx, token.HashOpaque(plainToken))
	if err != nil {
		return err
	}

	now := s.cfg.clock()
	if !now.Before(v.ExpiresAt) {
		return ErrVerificationExpired
	}
	if v.Purpose != PurposePasswordReset {
		return ErrVerificationPurpose
	}

	if failed := password.Validate(next, s.cfg.rules); len(failed) > 0 {
		return fmt.Errorf("%w: %s", ErrWeakPassword, strings.Join(failed, ","))
	}
	hash, err := s.cfg.hasher.Hash(next)
	if err != nil {
		return err
	}

	// The claim: exactly one caller ever sees a nil error for this id — see
	// the method doc's "Ordering, and why it is not negotiable" section.
	if err := s.store.DeleteVerification(ctx, v.ID); err != nil {
		return err
	}

	// The apply: the verification is burned from here on, whatever happens
	// below.
	if err := s.store.UpdateUserPassword(ctx, v.UserID, hash, now); err != nil {
		return err
	}

	// Close BOTH token side doors — see the method doc above. The
	// email_change sweep is not a tidier variant of the reset one; it is
	// the stronger of the two doors.
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, v.UserID, PurposePasswordReset); err != nil {
		return err
	}
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, v.UserID, PurposeEmailChange); err != nil {
		return err
	}

	// Redeeming this token proved control of the address it was delivered
	// to — see the method doc's "Why a completed reset verifies the
	// address" section. Stamp it if, and only if, it is not already
	// stamped and the account still holds that same address. Both fields
	// are normalized by the Store on the way in (see [Store.CreateUser],
	// [Store.UpdateUserEmail] and [Store.CreateVerification]), so this
	// compares like with like.
	u, err := s.store.FindUserByID(ctx, v.UserID)
	if err != nil {
		return err
	}
	if u.EmailVerifiedAt == nil && u.Email == v.Email {
		if err := s.store.MarkEmailVerified(ctx, v.UserID, v.Email, now); err != nil {
			return err
		}
	}

	sessions, err := s.store.ListSessionsByUser(ctx, v.UserID)
	if err != nil {
		return err
	}
	done := make(map[string]bool, len(sessions))
	for _, sess := range sessions {
		if done[sess.FamilyID] {
			continue
		}
		done[sess.FamilyID] = true
		if err := s.store.DeleteSessionsByFamily(ctx, sess.FamilyID); err != nil {
			return err
		}
	}
	return nil
}

// RequestEmailChange mints an "email_change" [Verification] bound to
// newEmail for the already-authenticated user identified by userID, and
// returns its plaintext token. Redeeming it — via [Service.VerifyEmail],
// which recognises [PurposeEmailChange] — overwrites the account's email to
// newEmail and marks that address verified; see VerifyEmail's own doc for
// the redemption side.
//
// Unlike [Service.SignUp] and [Service.RequestPasswordReset], this method
// is not held to an enumeration-safety discipline: userID identifies an
// ALREADY-authenticated caller (an application calls this with the id from
// a caller's own validated access token, not with an id an anonymous
// prober supplies), so there is no unauthenticated audience this method
// needs to give nothing to. Accordingly it fails loudly and early rather
// than uniformly:
//
//  1. newEmail is normalized (see [NormalizeEmail]) and, if that leaves it
//     empty — a literal "", or whitespace-only input — this returns
//     [ErrEmailRequired] before touching the [Store] at all. Without this,
//     an empty newEmail minted a token exactly like any other, and a
//     successful redemption via [Service.VerifyEmail] set [UserBase.Email]
//     to "": reproduced directly, this bricks the account — [Service.Login]
//     and [Service.RequestPasswordReset] both look accounts up BY email, so
//     an account with no email cannot be reached by either again. This was
//     this method's only input check before this guard was added; removing
//     it (see the ErrEmailTaken discussion below, which removed the OTHER
//     check) would have left newEmail entirely unvalidated.
//  2. [Store.FindUserByID] loads userID; ErrUserNotFound propagates as-is
//     rather than being folded into some enumeration-safe shape — an
//     invalid userID here is a caller bug (a stale or forged id), not an
//     anonymous probe.
//  3. A fresh [Verification] is minted with Purpose [PurposeEmailChange]
//     and Email set to newEmail (never the account's OLD address — see
//     [Verification.Email]'s doc for why this field always carries the NEW
//     address for this purpose specifically), using the same
//     defaultVerificationTTL as a signup token.
//
// This method does NOT pre-check whether newEmail already belongs to a
// DIFFERENT user before minting — an earlier version did, returning
// [ErrEmailTaken] immediately. That check was removed: it turned this
// method into an un-rate-limited "is this address registered?" oracle for
// ANY authenticated caller — one signup buys unlimited queries against
// arbitrary addresses, with no [RateLimiter] of any kind gating it, unlike
// [Service.RequestPasswordReset]'s carefully-bounded equivalent. The
// pre-check was never the actual enforcement point: [Store.UpdateUserEmail]
// re-checks the identical condition atomically at REDEMPTION time
// regardless (see that method's doc), which is what genuinely closes the
// two-callers-racing-the-same-address race. Removing the pre-check costs a
// caller nothing but the timing of discovery: a request for an
// already-taken address still mints a token exactly like any other, and
// [Service.VerifyEmail] surfaces [ErrEmailTaken] at redemption instead —
// the one-time token is burned for nothing in that case, the same
// already-accepted cost [Service.VerifyEmail]'s "claims before applies"
// ordering imposes for every other doomed redemption. Requesting a change
// to the account's OWN current address is not an error either way: at
// redemption, [Store.UpdateUserEmail]'s uniqueness check excludes the
// caller's own row.
//
// A Store or [token.GenerateOpaque] error at any step is returned as-is.
func (s *Service[U, PU]) RequestEmailChange(ctx context.Context, userID, newEmail string) (string, error) {
	normalized := NormalizeEmail(newEmail)
	if normalized == "" {
		return "", ErrEmailRequired
	}

	if _, err := s.store.FindUserByID(ctx, userID); err != nil {
		return "", err
	}

	now := s.cfg.clock()
	plainToken, tokenHash, err := token.GenerateOpaque()
	if err != nil {
		return "", err
	}
	if _, err := s.store.CreateVerification(ctx, Verification{
		ID:        s.cfg.idGen(),
		UserID:    userID,
		TokenHash: tokenHash,
		Purpose:   PurposeEmailChange,
		Email:     normalized,
		ExpiresAt: now.Add(defaultVerificationTTL),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return plainToken, nil
}
