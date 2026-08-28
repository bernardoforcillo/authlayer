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
	// flow. Not redeemable through [Service.VerifyEmail] — a later task's
	// password-reset method owns this purpose's redemption, and
	// VerifyEmail refuses it with [ErrVerificationPurpose] rather than
	// silently accepting it and burning the token for nothing.
	PurposePasswordReset = "password_reset"
)

// defaultVerificationTTL is how long a [Service.SignUp]-minted "signup"
// verification stays redeemable. Not exposed as an Option — this task's
// option surface is fixed (see [New]) — but chosen generously (a day) since
// an email that never arrives, or arrives late, must not force a whole new
// sign-up.
const defaultVerificationTTL = 24 * time.Hour

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
	// [PurposePasswordReset], reserved for a later task's dedicated
	// password-reset method. Checked before the claim, so a
	// wrongly-presented token is not burned either.
	ErrVerificationPurpose = errors.New("authlayer/auth: verification token is not valid for this operation")
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

// WithRateLimiter wires a [RateLimiter] that [Service.Login] consults,
// keyed by IP, before touching the Store or the Hasher — see that
// interface's doc for why IP and never email. The default is nil, meaning
// Login imposes no rate limit at all. [Service.SignUp] never consults it:
// this task's brief scopes rate limiting to Login only.
func WithRateLimiter(l RateLimiter) Option {
	return func(c *config) { c.limiter = l }
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

// SignUpResult is the outcome of [Service.SignUp]. See that method's doc
// for the full enumeration-safety contract; the short version: Created is
// the ONLY field that tells the two branches apart, both branches return a
// nil error, and it is the CALLER's responsibility to not let that
// difference leak — a caller that returns Created literally, or a
// differently-shaped/differently-timed HTTP response depending on it,
// destroys the property no code in this package can protect once control
// leaves it. See SignUp's doc for the details.
type SignUpResult[U any] struct {
	// Created is true for a genuinely new account, false when the address
	// was already registered. This is the only field a caller may treat
	// differently between branches — see the type doc.
	Created bool
	// User is the newly created user when Created is true, or the existing
	// account (loaded fresh from the Store) when Created is false.
	// PasswordHash is always cleared to "" on this field, on BOTH branches
	// — never the live bcrypt digest, whether it is one this call just
	// produced (the caller already knows the plaintext it submitted, so
	// that specific hash is not new information) or, on the duplicate
	// branch, an existing account's real, active credential, which a
	// caller who merely attempted to sign up with that address has no
	// business ever seeing. If a caller genuinely needs the existing
	// account's credential material for some other purpose, load it
	// directly from the Store — SignUp does not hand it out.
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
// (SignUpResult, nil) whenever the underlying operations succeed. Created
// is the only field that distinguishes them. Several things hold,
// deliberately, and each is load-bearing on its own:
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
//     on, so "duplicate" is encoded ONLY in SignUpResult.Created, a plain
//     bool inside an otherwise-identical success value.
//
// None of this survives contact with an HTTP handler that inspects
// Created and returns a different status code, a different body, or does
// so measurably faster or slower for one branch than the other. Whatever
// calls SignUp MUST return a byte-identical response — same status, same
// body shape, same rough latency — regardless of Created; use
// VerifyToken (non-empty only when Created is true) to decide whether to
// send an email, never to decide what to tell the HTTP caller. The
// property is enforced up to the boundary of this function and no
// further.
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
// the return value — Created and VerifyToken, exactly the one difference
// [SignUpResult] documents as legitimate. The enumeration property holds
// by CONSTRUCTION — there is no Store call either branch can reach that
// the other cannot — not by an argument about how comparable two
// different code paths happen to be.
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
// merely by "signing up" with their address, locking them out of their
// own account under [WithRequireVerifiedEmail] with no resend path this
// package exposes. So step 4's mint is purely additive: an account's real
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
// SignUpResult.User never carries a live PasswordHash on either branch —
// see that field's own doc and [UserBase.PasswordHash]'s.
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
		return SignUpResult[U]{Created: false, User: s.wrap(user)}, nil
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
// redeem that purpose (a later task's dedicated method does) — checked
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
