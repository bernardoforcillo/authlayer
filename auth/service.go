// Package auth (this file) is the service layer built on top of [Store]:
// sign-up, login, and email verification. Where auth.go defines the
// persistence shape and performs no hashing or token minting of its own (see
// that file's package doc), Service wires together
// [github.com/bernardoforcillo/authlayer/password]'s Hasher/Validate,
// [github.com/bernardoforcillo/authlayer/token]'s opaque-token and JWT
// primitives, and a Store to produce the three flows an application
// actually calls.
//
// # Why Service is not generic over your user type
//
// [github.com/bernardoforcillo/authlayer/scope.Service] IS generic over the
// application's container and member types, and a reader arriving from that
// package will notice this one is not. The difference is deliberate, and it
// is about what each package owns rather than about consistency for its own
// sake.
//
// A container is genuinely application-shaped. scope has no opinion about
// what a workspace, project or tenant IS: the application declares the
// struct, embeds scope.ContainerBase in it, passes ITS OWN value in to
// CreateContainer, and [github.com/bernardoforcillo/authlayer/store/drops]
// derives the table from that type — so the extra fields are persisted,
// round-tripped, and handed back. The type parameter carries real weight
// there.
//
// A credential record is not application-shaped. This package needs exactly
// one fixed set of columns to do its job — an id, a normalized email, a
// verification stamp, a password hash, timestamps — and every one of them is
// load-bearing for a flow it implements. [UserBase] is that record, and it is
// the whole record: Service reads and writes UserBase, [Store] persists
// UserBase, and store/drops derives the users table from UserBase. Profile
// data — a display name, a plan, a locale — belongs in your own tables, which
// is also what keeps this library's migrations from ever owning a column your
// product's shape decides. Look those fields up yourself, keyed by
// UserBase.ID; [WithClaimsExtender]'s doc has the worked example.
//
// An earlier version of this package DID carry a Service[U, PU] type
// parameter, presented as the ContainerBase analogy above. It was inert: no
// method accepted a U, the value handed back was reconstructed from a zero U
// with the loaded UserBase written onto it, and store/drops derived its table
// from UserBase regardless — so an application's extra fields were
// unreachable in both directions, and a claims extender always saw them zero.
// Removing it is what this doc section replaces the analogy with, rather than
// leaving a claim the code never honoured.
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

// The five closed values [Verification.Purpose] takes — see that field's
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
	// PurposeMagicLink marks a Verification minted by
	// [Service.RequestMagicLink] for a passwordless sign-in. Not redeemable
	// through [Service.VerifyEmail] — [Service.RedeemMagicLink] owns this
	// purpose's redemption, and VerifyEmail refuses it with
	// [ErrVerificationPurpose] without burning it, the same stance it takes
	// on PurposePasswordReset.
	//
	// This is the only purpose whose redemption issues a SESSION, which is
	// why it is swept by every credential-rotation and remediation path
	// that already sweeps the other two redeemable-by-mail purposes — see
	// [Service.ChangePassword]'s doc, "The sweep matrix".
	PurposeMagicLink = "magic_link"
	// PurposeMFAChallenge marks a Verification minted by [Service.Login]
	// when the account owes a second factor: the short-lived, single-use
	// handle [Service.CompleteMFA] exchanges, together with a TOTP or
	// recovery code, for the session Login deliberately did not mint. See
	// [MFAChallenge] and auth/mfa_service.go's package doc for why the
	// pending state is a Verification rather than a fifth table.
	//
	// It is redeemable through [Service.CompleteMFA] and NOWHERE else.
	// [Service.VerifyEmail] whitelists the two purposes it redeems and so
	// refuses this one already; [Service.ResetPassword] and
	// [Service.RedeemMagicLink] each refuse anything but their own. Those
	// refusals are not bookkeeping: a challenge is a HALF-authenticated
	// login — its holder has proven a password and nothing else — and
	// redeeming one anywhere that issues a session or sets a credential
	// without the second factor would hand back exactly what withholding
	// the session was for.
	//
	// Unlike the other four, this purpose is never mailed anywhere. Its
	// [Verification.Email] is populated (the field's contract is
	// unconditional) but proves nothing and certifies nothing: completing
	// a challenge does not stamp [UserBase.EmailVerifiedAt], because
	// nothing about the address was demonstrated by holding the handle
	// Login just returned over an already-authenticated channel.
	PurposeMFAChallenge = "mfa_challenge"
)

// defaultVerificationTTL is the default for [WithVerificationTTL]: how long
// a "signup" or "email_change" [Verification] stays redeemable. Chosen
// generously (a day) since an email that never arrives, or arrives late,
// must not force a whole new sign-up.
const defaultVerificationTTL = 24 * time.Hour

// defaultPasswordResetTTL is the default for [WithPasswordResetTTL]: how
// long a "password_reset" [Verification] stays redeemable. Deliberately
// shorter than defaultVerificationTTL's 24 hours: a password-reset link is a
// more security-sensitive bearer credential than a signup-confirmation link
// (it grants a full credential change, not merely a "yes, I own this
// address" attestation), and a short window is the conventional stance this
// class of flow takes elsewhere.
const defaultPasswordResetTTL = time.Hour

// defaultMagicLinkTTL is the default for [WithMagicLinkTTL]: how long a
// "magic_link" [Verification] stays redeemable. Shorter still than
// defaultPasswordResetTTL's hour, because redeeming one does not merely
// let its holder SET a credential — it IS the credential: [Service.RedeemMagicLink]
// exchanges it directly for a session, with no password step in between.
const defaultMagicLinkTTL = 15 * time.Minute

// defaultMFAChallengeTTL is the default for [WithMFAChallengeTTL]: how long
// a "mfa_challenge" [Verification] minted by [Service.Login] stays
// exchangeable through [Service.CompleteMFA]. The shortest of the five, and
// for a reason none of the others share: it is not a link that has to
// survive a mail queue and a distracted human, it is the gap between two
// steps of one sitting — read the code off an authenticator and type it in.
// Minutes are generous for that; hours would only widen the window in which
// a challenge stolen from a browser's memory, a proxy log or a shared
// terminal is still worth something to whoever took it.
const defaultMFAChallengeTTL = 5 * time.Minute

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
	// a now-stale one, so it treats every occurrence as compromise: when
	// this error is returned ALONE — wrapping nothing else — every session
	// in the token's family has already been revoked via
	// [Store.DeleteSessionsByFamily]. See Refresh's doc, "Why the whole
	// family, not just the presented session".
	//
	// Exactly two cases return it wrapped around a SECOND error, and in
	// both a replay was detected while the family may still be live:
	// [Store.DeleteSessionsByFamily] itself failing, and [ErrStoreContract]
	// — MarkRotated reporting the replay but handing back a [Session] with
	// no FamilyID, leaving nothing to revoke.
	//
	// A caller inspecting an error returned by Refresh with [errors.Is]
	// MUST therefore check ErrTokenReuse before checking whether the error
	// wraps anything else: in both cases the returned error satisfies
	// errors.Is against ErrTokenReuse (a replay WAS detected; that fact
	// must never be lost merely because the response to it also failed) and
	// against the second error too (so the operational failure is not
	// hidden either). See Refresh's doc, "Fail closed".
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
	// after that method's [Store.FindUserByID] lookup and its
	// current-password check, and before anything is minted: a caller who
	// fails the credential check is told only [ErrInvalidCredentials],
	// never that the address they proposed was also malformed. Without
	// this guard, an empty newEmail minted a redeemable token exactly like
	// any other, and successful redemption via [Service.VerifyEmail] set
	// [UserBase.Email] to "" — a self-inflicted account lockout with no
	// recovery path this package exposes, since [Service.Login] and
	// [Service.RequestPasswordReset] both look accounts up BY email.
	ErrEmailRequired = errors.New("authlayer/auth: email must not be empty")
	// ErrStoreContract: a [Store] returned a value its own documented
	// contract forbids, at a point where continuing would silently degrade
	// a security control rather than merely produce a wrong answer. This
	// package cannot validate every Store response — most of the port's
	// obligations (the atomicity MUSTs, the enumeration obligations) are
	// unobservable from here — so this sentinel is deliberately narrow, not
	// a general "the Store misbehaved" channel. Every trigger it has today
	// is the same one condition, reached from each of the three methods
	// that revoke a whole session family: a [Session] handed back with an
	// empty FamilyID, which leaves nothing to revoke.
	//
	//   - [Service.Refresh] detecting a replay ([Store.MarkRotated]
	//     returning ok=false) and being handed a Session with no FamilyID.
	//     See Refresh's doc, "Why the whole family, not just the presented
	//     session", for why proceeding there would fire the alarm while
	//     containment did nothing.
	//   - [Service.Logout] presented a SUPERSEDED token — the same signal,
	//     reached through a different door — and finding no FamilyID on it.
	//   - [Service.RevokeSession] resolving the caller's chosen session id
	//     to a Session with no FamilyID.
	//
	// In all three, DeleteSessionsByFamily(ctx, "") would match no rows and
	// return nil: the method would report success having revoked nothing,
	// which is the one outcome a revocation primitive must never produce.
	// Neither proceeding with a meaningless key nor silently skipping the
	// revocation is acceptable, so each fails closed and says which
	// contract was broken.
	//
	// Where the caller's own request has an outcome worth preserving, this
	// is wrapped ALONGSIDE the sentinel that names it — ErrTokenReuse in
	// Refresh's case, because a replay was still detected and that fact
	// must not be lost — so a caller matching on the request-level outcome
	// keeps working and an operator still gets the diagnosis. Logout and
	// RevokeSession have no such second signal: the request simply could
	// not be carried out, and they return this alone.
	ErrStoreContract = errors.New("authlayer/auth: store violated its documented contract")
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
	// verificationTTL, passwordResetTTL and magicLinkTTL are the three
	// [Verification] lifetimes — see [WithVerificationTTL],
	// [WithPasswordResetTTL] and [WithMagicLinkTTL].
	verificationTTL  time.Duration
	passwordResetTTL time.Duration
	magicLinkTTL     time.Duration
	clock            func() time.Time
	idGen            func() string
	limiter          RateLimiter
	// resetLimiter is the address-keyed [RateLimiter] [Service.RequestPasswordReset]
	// additionally consults — see [WithPasswordResetRateLimiter]'s doc for
	// why it is a second, independent config slot rather than reusing
	// limiter (which stays IP-keyed everywhere it is used).
	resetLimiter RateLimiter
	// magicLinkLimiter is the address-keyed [RateLimiter]
	// [Service.RequestMagicLink] additionally consults — a third,
	// independent slot for the same reason resetLimiter is a second one:
	// limiter stays IP-keyed everywhere it is used, and a deployment may
	// want a tighter bucket on magic links than on password resets (a
	// magic link is a login, not a credential-set form). See
	// [WithMagicLinkRateLimiter].
	magicLinkLimiter RateLimiter
	// magicLinkProvisioning is [WithMagicLinkProvisioning]: whether
	// [Service.RequestMagicLink] creates an account for an address it does
	// not recognise. Defaults to false.
	magicLinkProvisioning bool
	claimsExtender        func(UserBase) map[string]any
	requireVerifiedEmail  bool
	// identityStore is the OPTIONAL external-identity port — see
	// [WithIdentityStore]. nil means no external sign-in is configured, and
	// every entry point needing it fails with [ErrOAuthNotConfigured]
	// rather than dereferencing this.
	identityStore IdentityStore
	// linking is the implicit-link policy for external sign-in — see
	// [Linking] and [WithLinking]. It is deliberately left at its ZERO
	// VALUE by defaultConfig rather than assigned there: [LinkVerified] is
	// that zero value, so a config built by any route at all — including
	// one a future refactor forgets to run through defaultConfig — carries
	// the safe policy. See [LinkVerified]'s own doc.
	linking Linking
	// accountDeletionHook is the application's own pre-delete cleanup —
	// see [WithAccountDeletionHook] and [Service.DeleteAccount], both in
	// deletion.go. nil means no hook, which is the default.
	accountDeletionHook func(ctx context.Context, userID string) error
	// mfaStore is the OPTIONAL second-factor port — see [WithMFAStore] and
	// [MFAStore]. nil means no MFA is configured, and every entry point
	// needing it fails with [ErrMFANotConfigured] rather than
	// dereferencing this.
	mfaStore MFAStore
	// mfaCipher encrypts TOTP secrets at rest — see [WithMFASecretCipher].
	// nil means enrolment is REFUSED with [ErrMFACipherNotConfigured]
	// rather than falling back to storing a plaintext bearer credential;
	// auth/mfa.go's package doc carries that argument.
	mfaCipher Cipher
	// mfaEnforcement is whether a second factor is optional or mandatory —
	// see [Enforcement] and [WithMFAEnforcement]. Left at its ZERO VALUE by
	// defaultConfig rather than assigned there, exactly as linking is:
	// [EnforcementOptional] is that zero value, so a config built by any
	// route at all carries the policy that cannot lock anybody out.
	mfaEnforcement Enforcement
	// mfaChallengeTTL is how long a "mfa_challenge" [Verification] stays
	// exchangeable — see [WithMFAChallengeTTL].
	mfaChallengeTTL time.Duration
	// mfaIssuer is the label an authenticator app shows beside the account —
	// see [WithMFAIssuer]. Empty is valid and renders a URI with no issuer.
	mfaIssuer string
}

func defaultConfig() config {
	return config{
		hasher:           password.Bcrypt(0),
		rules:            password.DefaultRules(),
		accessTTL:        15 * time.Minute,
		refreshTTL:       30 * 24 * time.Hour,
		verificationTTL:  defaultVerificationTTL,
		passwordResetTTL: defaultPasswordResetTTL,
		magicLinkTTL:     defaultMagicLinkTTL,
		mfaChallengeTTL:  defaultMFAChallengeTTL,
		clock:            func() time.Time { return time.Now().UTC() },
		idGen:            uid.NewV7,
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
// # The whole list is checked, not just the signing key
//
// A keys where ANY entry is unusable is ignored in full, exactly like a nil
// or empty one, leaving the signing key unset.
//
// This is not tidiness. [token.Issue] validates only the key it signs with,
// while [token.Parse] refuses the ENTIRE call if any key in the list is
// under the floor — so a list whose first key is fine and whose second is
// not used to build a Service that minted access tokens it could never
// verify: every login succeeded, every subsequent request failed
// token.ErrKeyTooShort, and nothing pointed at the misconfiguration. Fail
// closed, but a total, self-inflicted auth outage discovered by users
// rather than by the operator. Rejecting the list here moves that to the
// operator's first Login, where the "no signing key configured" path
// already reports it.
//
// "Unusable" is not defined here: each key is checked by asking
// [token.Issue] to mint a throwaway token with it, so the floor lives in
// exactly one place — the token package — and this option cannot drift from
// it or miss a constraint added there later.
//
// There is no default signing key — an application MUST call this before
// any successful Login, by design: silently minting tokens under a
// zero-value or generated-on-the-fly key would be the exact "alg: none
// reached through the key parameter" failure mode [token]'s own package doc
// warns about.
func WithJWT(keys [][]byte, ttl time.Duration) Option {
	return func(c *config) {
		if len(keys) > 0 && keysUsable(keys) {
			c.signingKey = keys
		}
		if ttl > 0 {
			c.accessTTL = ttl
		}
	}
}

// keysUsable reports whether every key in keys is one [token.Issue] will
// sign with and [token.Parse] will accept. It asks the token package rather
// than re-stating its rules: a throwaway Issue exercises exactly the checks
// a real mint would, so there is no second copy of the HS256 key floor to
// fall out of step. Claims{} and a positive ttl leave the key as the only
// thing that can fail.
func keysUsable(keys [][]byte) bool {
	for _, k := range keys {
		if _, err := token.Issue(token.Claims{}, k, time.Minute); err != nil {
			return false
		}
	}
	return true
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

// WithVerificationTTL sets how long a "signup" or "email_change"
// [Verification] stays redeemable: [Service.SignUp] and
// [Service.RequestEmailChange] both stamp ExpiresAt as CreatedAt+d. The
// default is 24 hours, deliberately generous — an email that never arrives,
// or arrives late, must not force a whole new sign-up. d <= 0 is ignored,
// leaving the default (or a prior option) in place, rather than minting a
// token that is already expired — matching [WithRefreshTTL] and
// [github.com/bernardoforcillo/authlayer/invite.WithInviteExpiry].
//
// It has no effect on password-reset tokens, which carry their own,
// deliberately shorter lifetime — see [WithPasswordResetTTL].
//
// Shortening this shortens the window in which an "email_change" token —
// the strongest of the three, since [Service.VerifyEmail] redeems it with
// no authentication at all — remains armed; see [Service.ChangePassword]'s
// doc, "Why both purposes", for why that window matters.
func WithVerificationTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.verificationTTL = d
		}
	}
}

// WithPasswordResetTTL sets how long a "password_reset" [Verification]
// minted by [Service.RequestPasswordReset] stays redeemable: ExpiresAt is
// stamped as CreatedAt+d. The default is one hour — shorter than
// [WithVerificationTTL]'s 24, because a reset link grants a full credential
// change rather than a "yes, I own this address" attestation. d <= 0 is
// ignored, leaving the default (or a prior option) in place.
//
// A shorter window here is a real hardening, and a deployment that delivers
// mail promptly can afford one (fifteen minutes is a common choice); the
// cost is that a user who opens the link late must request another. An
// expired token is [ErrVerificationExpired] and is never burned by the
// attempt — see [Service.ResetPassword] — so requesting another is the only
// consequence.
func WithPasswordResetTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.passwordResetTTL = d
		}
	}
}

// WithMagicLinkTTL sets how long a "magic_link" [Verification] minted by
// [Service.RequestMagicLink] stays redeemable: ExpiresAt is stamped as
// CreatedAt+d. The default is fifteen minutes — shorter than
// [WithPasswordResetTTL]'s hour, and far shorter than
// [WithVerificationTTL]'s day, because this token is not a step towards a
// credential, it IS one: [Service.RedeemMagicLink] exchanges it for a live
// session with nothing else asked of its holder. d <= 0 is ignored,
// leaving the default (or a prior option) in place.
//
// This is the whole of the window in which a link sitting unread in a
// mailbox is a working login, so it is the one knob that bounds the
// "mailbox compromised later" case. It is not the only control: the link
// is single-use ([Service.RedeemMagicLink] burns it), re-issuing invalidates
// the previous one ([Service.RequestMagicLink]), and every credential
// rotation sweeps it (see [Service.ChangePassword]'s doc, "The sweep
// matrix"). Lengthening it past the default trades directly against all
// three; the cost of a short window is only that a user who opens the mail
// late must ask for another link, since an expired token is
// [ErrVerificationExpired] and is never burned by the attempt.
func WithMagicLinkTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.magicLinkTTL = d
		}
	}
}

// WithMagicLinkProvisioning controls whether [Service.RequestMagicLink]
// CREATES an account for an address it does not recognise, rather than
// silently minting nothing. The default is false: magic links sign existing
// accounts in and register nobody.
//
// # What enabling this exposes, stated plainly
//
// With it on, anyone who can receive mail at an address can bring an
// account for that address into existence, unauthenticated, by asking for a
// link and clicking it. That is exactly the exposure an open
// [Service.SignUp] endpoint already has — which is why a deployment that
// already offers open self-service registration gives up nothing new here —
// but it is a real change for a deployment that does not, and it is not
// free. [WithMagicLinkRateLimiter] is the control, and it gates
// provisioning itself, not merely the minting that follows it: a denial
// from that limiter creates no account. [WithRateLimiter]'s IP-keyed limit
// applies first and bounds the same thing per source.
//
// The account created holds no password credential at all
// (PasswordHash "", so [Service.Login] can never authenticate it — see
// [UserBase]'s doc) and an unset EmailVerifiedAt: ASKING for a link proves
// nothing about the address, and only [Service.RedeemMagicLink] — which
// requires actually receiving the mail — stamps it.
//
// One consequence worth planning for: a probe of an unregistered address
// leaves a real, permanent row behind. Unlike the verifications a magic
// link also creates, that row never expires and [Store.PurgeExpired] does
// not remove it, so a deployment enabling this should expect its users
// table to accumulate addresses nobody ever signed in with.
func WithMagicLinkProvisioning(enabled bool) Option {
	return func(c *config) { c.magicLinkProvisioning = enabled }
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
// verifications. The default is UUIDv7 (internal/uid.NewV7, not importable
// from outside this module): time-ordered, so ids minted later sort later
// and a b-tree index on a primary key stays dense. A nil generator is
// ignored, leaving the default (or a prior option) in place.
//
// # A non-UUID generator needs WithAuthTextLibraryIDs on store/drops
//
// The shipped PostgreSQL backend has to declare a column type.
// [github.com/bernardoforcillo/authlayer/store/drops] types users.id,
// sessions.id and verifications.id — and the sessions/verifications user_id
// columns referencing users.id — as PostgreSQL uuid BY DEFAULT, which is
// correct for the default generator and wrong for any other. Override this
// option and you must pass
// [github.com/bernardoforcillo/authlayer/store/drops.WithAuthTextLibraryIDs]
// as well, which types all five columns text instead:
//
//	st := dropsstore.NewAuthStore(db, dropsstore.WithAuthTextLibraryIDs())
//	svc := auth.New(st, auth.WithIDGenerator(ulid.Make))
//
// If the same deployment uses the RBAC or invitation halves, pass
// [github.com/bernardoforcillo/authlayer/store/drops.WithTextLibraryIDs] and
// [github.com/bernardoforcillo/authlayer/store/drops.WithInviteTextLibraryIDs]
// to those stores, and
// [github.com/bernardoforcillo/authlayer/store/drops.WithTextUserIDs] /
// [github.com/bernardoforcillo/authlayer/store/drops.WithInviteTextUserIDs]
// too, since their user-id columns then hold ids minted by this generator.
// Note that WithTextUserIDs is a different option from the library-id ones
// and covers only those externally supplied columns; this store offers no
// equivalent, because it owns the users table its user_id columns reference.
//
// Without the option, a generator returning anything PostgreSQL's uuid parser
// rejects — a ULID, a database sequence, a readable "usr_a1b2c3" — fails the
// very first [Service.SignUp] with SQLSTATE 22P02
// (invalid_text_representation). It fails at the Store, not at construction,
// and [github.com/bernardoforcillo/authlayer/store/memory] accepts any string
// happily: a service developed and tested entirely against the memory store
// with such a generator passes every test and breaks on its first real
// sign-up. All three of those are pinned by test —
// TestNonUUIDIDGeneratorIsAcceptedByTheMemoryStore in this package,
// TestNonUUIDIDGeneratorFailsAgainstDropsLive in store/drops's integration
// lane, which asserts the 22P02 specifically, and
// TestTextLibraryIDsRoundTripANonUUIDGeneratorLive in the same lane, which
// round-trips a ULID generator end to end with the option on.
//
// Against a Store of your own the only requirement is that ids are unique
// and stable; use whatever that schema accepts.
// [github.com/bernardoforcillo/authlayer/scope.WithIDGenerator] carries the
// identical requirement, for the identical reason.
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

// WithMagicLinkRateLimiter wires a third, independent [RateLimiter] that
// [Service.RequestMagicLink] consults, keyed by the NORMALIZED email
// address rather than by IP — see [NormalizeEmail]. The default is nil,
// meaning RequestMagicLink imposes no address-keyed limit at all;
// [WithRateLimiter]'s IP-keyed limit, if configured, still applies on its
// own. It is deliberately NOT the same slot as
// [WithPasswordResetRateLimiter]: the two flows have different costs and a
// deployment may want different buckets for them.
//
// A denial from this limiter is never surfaced as [ErrRateLimited] the way
// WithRateLimiter's IP-keyed denial is — see [Service.RequestMagicLink]'s
// doc, "The enumeration property", point 2, for why: an address-keyed rate
// limit that surfaced as a distinguishable error would itself become the
// existence oracle that method's whole design exists to close.
//
// This limiter is the control for three separate things, and only the
// first is about enumeration:
//
//   - It bounds how many timing samples an attacker can collect against
//     ONE address, which is the resource [Service.RequestMagicLink]'s
//     residual timing channel needs (the same argument
//     [WithPasswordResetRateLimiter]'s doc makes for its own flow).
//   - It bounds GRIEFING. RequestMagicLink invalidates an address's earlier
//     "magic_link" token every time a new one is minted, so anyone who
//     merely knows an address can kill a victim's genuine, unclicked link
//     at will by looping requests. That is inherent to the re-issue
//     contract [Store.DeleteVerificationsByUserAndPurpose] documents, not
//     a bug this method can avoid while honouring it.
//   - With [WithMagicLinkProvisioning] enabled, it bounds ACCOUNT
//     CREATION: a denial from this limiter provisions nothing, so this is
//     the control that keeps "anyone who can receive mail can create an
//     account" from also meaning "anyone at all can create unlimited
//     accounts". See WithMagicLinkProvisioning's own doc.
//
// This package configures no default here, for the reason [WithRateLimiter]'s
// own default is nil: the right bucket size is an operator decision.
func WithMagicLinkRateLimiter(l RateLimiter) Option {
	return func(c *config) { c.magicLinkLimiter = l }
}

// WithRequireVerifiedEmail controls whether [Service.Login] refuses an
// otherwise-successful login for an account whose email is not yet
// verified, with [ErrEmailNotVerified]. The default is false: an unverified
// account may still log in. See Login's doc for exactly when this check
// runs relative to the password check.
//
// One other method reads it, and only as a consequence of what it means to
// Login: [Service.UnlinkIdentity] asks whether the account could authenticate
// with its password before it removes an external identity, and under this
// option an unverified account cannot — so the unlink is refused with
// [ErrLastCredential] rather than removing the only credential that works.
// See [Service.passwordCanAuthenticate].
//
// [Service.SignInWith] deliberately does NOT honour it — see that method's
// "Why WithRequireVerifiedEmail does not apply here".
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
// u is the real, freshly-loaded [UserBase] the caller just authenticated —
// every field this package manages (ID, Email, EmailVerifiedAt, CreatedAt,
// UpdatedAt) is genuinely populated, with the single, deliberate exception
// of PasswordHash, which is cleared to "" before the callback ever sees it
// so an extender cannot embed a live credential digest into a JWT claim by
// accident (see [UserBase.PasswordHash]'s own doc).
//
// UserBase is the WHOLE record this package owns — see the package doc's
// "Why Service is not generic over your user type". A profile field of your
// own (a plan, a display name, a locale) lives in your own tables, so look
// it up inside the callback, keyed by u.ID:
//
//	auth.New(store, auth.WithClaimsExtender(func(u auth.UserBase) map[string]any {
//		profile := myApp.Profiles.Lookup(u.ID) // your own store, not this package's
//		return map[string]any{"plan": profile.Plan}
//	}))
//
// The callback runs on every [Service.Login] and every [Service.Refresh]
// that reaches the minting step, so its cost is paid per token issued: a
// lookup here is a lookup on the login path.
func WithClaimsExtender(f func(UserBase) map[string]any) Option {
	return func(c *config) {
		if f != nil {
			c.claimsExtender = f
		}
	}
}

// WithIdentityStore wires the OPTIONAL [IdentityStore] port, enabling
// external ("sign in with Google/GitHub/…") identities. The default is nil:
// a Service built without this option persists no identities at all, and
// every entry point that needs the port refuses with
// [ErrOAuthNotConfigured] rather than dereferencing nil. A nil s is ignored,
// leaving the default (or a prior option) in place.
//
// It is a separate port, not part of [Store], because [Store] is released:
// adding a method to it would break every third-party backend. See
// [IdentityStore]'s own doc, and auth/identity.go's package doc, for the
// boundary this port keeps — in particular that authlayer stores no provider
// access or refresh tokens.
func WithIdentityStore(s IdentityStore) Option {
	return func(c *config) {
		if s != nil {
			c.identityStore = s
		}
	}
}

// WithLinking sets the [Linking] policy governing when an external sign-in
// may implicitly attach a provider's identity to a PRE-EXISTING local
// account matched by email address. The default is [LinkVerified], which is
// Linking's zero value — see that constant's doc for why the safe policy is
// the one a caller gets by saying nothing.
//
// It PANICS when m is not one of the three declared constants, rather than
// silently falling back to some policy the caller did not choose. A linking
// mode is a security decision made once, at wiring time, by a human reading
// this option's doc; a typo'd or out-of-range value is a construction bug,
// and the alternative — a Service that exists holding a mode no branch of
// the ladder handles — is either a runtime denial nobody can explain or, far
// worse, a fallback that links more freely than intended. This matches
// [github.com/bernardoforcillo/authlayer/scope.New]'s stance on WithParent
// and [github.com/bernardoforcillo/authlayer/access.Access.NewRole]'s on a
// mis-declared role.
func WithLinking(m Linking) Option {
	return func(c *config) {
		switch m {
		case LinkVerified, LinkNever, LinkAlways:
			c.linking = m
		default:
			panic(fmt.Sprintf("authlayer/auth: WithLinking(%d): unknown linking mode", int(m)))
		}
	}
}

// WithMFAStore wires the OPTIONAL [MFAStore] port, enabling TOTP second
// factors and recovery codes. The default is nil: a Service built without
// this option persists no factor state at all, every account behaves
// exactly as it did before MFA existed, and every entry point that needs
// the port refuses with [ErrMFANotConfigured] rather than dereferencing
// nil. A nil s is ignored, leaving the default (or a prior option) in
// place.
//
// It is a separate port, not part of [Store], for the reason auth/mfa.go's
// package doc gives: a second factor is functionality a deployment may
// never offer, so a backend that cannot store one is still a complete
// backend — the same test [IdentityStore] passed and account deletion
// failed.
//
// Wiring the store is not sufficient on its own. Enrolment also needs
// [WithMFASecretCipher], and refuses without it.
func WithMFAStore(s MFAStore) Option {
	return func(c *config) {
		if s != nil {
			c.mfaStore = s
		}
	}
}

// WithMFASecretCipher wires the [Cipher] that encrypts TOTP secrets before
// they reach the [MFAStore], and decrypts them to validate a code. There is
// NO DEFAULT and no fallback: a Service without one refuses to enrol a
// factor at all, with [ErrMFACipherNotConfigured]. A nil c is ignored,
// leaving the default (or a prior option) in place.
//
// The refusal is the point, and auth/mfa.go's package doc argues it in
// full: a TOTP secret is the bearer credential the user's authenticator
// holds, so a table of plaintext secrets is a working second-factor bypass
// for every enrolled user the moment the database is read — which is
// precisely the compromise the second factor was added to survive.
// Refusing at enrolment turns a missing key into a loud failure on the
// first attempt instead of a silent one discovered in a breach.
//
// authlayer ships no implementation. The algorithm is the easy half;
// deciding where the key lives is the half that determines whether the
// ciphertext is worth anything, and that decision is the deployment's.
func WithMFASecretCipher(c Cipher) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.mfaCipher = c
		}
	}
}

// WithMFAEnforcement sets whether a second factor is optional or mandatory
// for password logins — see [Enforcement]. The default is
// [EnforcementOptional], which is Enforcement's zero value, so a caller who
// says nothing gets the policy that cannot lock anyone out.
//
// It PANICS on a value outside the two declared constants, matching
// [WithLinking]'s stance for the identical reason: an enforcement policy is
// a security decision made once, at wiring time, and a Service holding a
// mode no branch of [Service.Login] handles is either an unexplainable
// denial or a silent downgrade to "no second factor required".
func WithMFAEnforcement(m Enforcement) Option {
	return func(c *config) {
		switch m {
		case EnforcementOptional, EnforcementRequired:
			c.mfaEnforcement = m
		default:
			panic(fmt.Sprintf("authlayer/auth: WithMFAEnforcement(%d): unknown enforcement mode", int(m)))
		}
	}
}

// WithMFAChallengeTTL overrides how long a "mfa_challenge" [Verification]
// minted by [Service.Login] stays exchangeable through
// [Service.CompleteMFA]. The default is [defaultMFAChallengeTTL] (five
// minutes) — see that constant for why it is the shortest of the five
// verification lifetimes. A non-positive d is ignored, leaving the default
// (or a prior option) in place, exactly as [WithMagicLinkTTL] does: a
// zero-or-negative TTL would mint challenges that are already expired,
// making every MFA login unfinishable.
func WithMFAChallengeTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.mfaChallengeTTL = d
		}
	}
}

// WithMFAIssuer sets the issuer name written into the otpauth URI
// [Service.BeginMFAEnrolment] returns — the label an authenticator app
// shows above the account, and the one a user scans through to find the
// right code among thirty. Use the application's name, and keep it STABLE:
// changing it does not migrate anything, it merely relabels factors
// enrolled afterwards, leaving a user with two differently-named entries
// for one account.
//
// The default is empty, which renders a URI with no issuer label and no
// `issuer` parameter (see internal/totp.ProvisioningURI) — valid, scannable,
// and anonymous in the user's app. That is a deliberate no-default rather
// than a guess: this package does not know the application's name, and a
// placeholder would be scanned into thousands of authenticators before
// anyone noticed.
func WithMFAIssuer(name string) Option {
	return func(c *config) {
		c.mfaIssuer = name
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
type SignUpResult struct {
	// Created is true for a genuinely new account, false when the address
	// was already registered. See the type doc for what a caller may do
	// with that: decide whether to send mail, not what to answer.
	Created bool
	// User is the newly created user when Created is true, and the ZERO
	// [UserBase] when Created is false — never the account that was found.
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
	User UserBase
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

// LoginResult is the outcome of a successful [Service.Login] and of a
// successful [Service.Refresh]: the account, a freshly issued access token,
// and the plaintext of the refresh token that now names the caller's live
// session. Both methods populate all three fields — a login and a rotation
// hand back the same thing, so they return the same type rather than one
// returning a named struct and the other a positional tuple of two
// same-typed token strings a caller can transpose without the compiler
// noticing.
type LoginResult struct {
	// User is the authenticated account, freshly loaded from the Store —
	// never a cached or stale copy carried over from whatever session
	// lookup happened earlier in [Service.Refresh]'s ladder. PasswordHash
	// is always cleared to "" here, matching every other Service method
	// that hands back a [UserBase] — see [UserBase.PasswordHash]'s own doc.
	User UserBase
	// AccessToken is a fresh, short-lived HS256 JWT — see [WithJWT] — bound
	// to the session named by RefreshToken: from [Service.Login], the
	// session that login just created; from [Service.Refresh], the NEW
	// successor session, not the rotated-away predecessor. Verify one with
	// [Service.VerifyAccessToken].
	AccessToken string
	// RefreshToken is the plaintext of the session's refresh token, stored
	// by this package only as its sha256. Present it on the NEXT call to
	// [Service.Refresh]. A token already exchanged through Refresh is
	// rotated away and will fail with [ErrTokenReuse], revoking the whole
	// family, if presented again.
	RefreshToken string
	// MFA is non-nil on exactly one path: a [Service.Login] that
	// authenticated the password of an account owing a second factor. On
	// that path NO SESSION EXISTS — AccessToken and RefreshToken are both
	// "" and nothing was persisted — and the login finishes by exchanging
	// MFA.Token, with a TOTP or recovery code, through
	// [Service.CompleteMFA]. It is nil on every other successful outcome:
	// an ordinary Login, a [Service.Refresh], a [Service.RedeemMagicLink],
	// a [Service.SignInWith], and CompleteMFA's own result.
	//
	// # Why a caller written before this field existed still fails closed
	//
	// This field was added after v0.1.0, so code compiled against that
	// version reads AccessToken and never looks here. It gets "" — and ""
	// is not a degraded token, it is not a token at all:
	// [github.com/bernardoforcillo/authlayer/token.Parse] refuses it, and
	// so does every middleware built on it. The empty string is doing real
	// work in this design, and it is why the tokens are left empty rather
	// than populated "for convenience" alongside the challenge: an
	// unmodified v0.1.0 caller that ignores MFA entirely under-grants (its
	// users cannot sign in until it is updated) instead of handing out a
	// session the second factor was never presented for. Under-granting is
	// the only acceptable direction here, and a test in this package's
	// suite pins it against exactly that caller.
	//
	// A caller that DOES know about MFA must branch on MFA != nil before
	// touching either token, not on err != nil alone: an MFA-owed login is
	// a nil error and a successful outcome — the password was correct —
	// that simply is not finished yet.
	MFA *MFAChallenge
}

// Service mints, authenticates, and verifies accounts for one application.
// It is NOT generic over an application user type — unlike
// [github.com/bernardoforcillo/authlayer/scope.Service], which is generic
// over the container and member types it persists on your behalf. See the
// package doc, "Why Service is not generic over your user type", for the
// reasoning and for what to do with the profile fields this package
// deliberately does not carry.
//
// A Service performs no authorization of its own — there is nothing to
// authorize yet at sign-up or login — and is safe for concurrent use if its
// Store, Hasher, and RateLimiter are; it caches nothing.
type Service struct {
	store Store
	cfg   config
}

// New wires a [Store] and options into a Service.
//
// It returns no error, matching every other constructor in this codebase
// (scope.New, invite.New): every [Option] but one either applies a valid
// value or leaves the default in place (each option's own doc says which
// inputs it ignores), and there is no type argument to get wrong. The
// exception is [WithLinking], which PANICS on a mode outside its three
// declared constants rather than leaving the Service holding a policy no
// branch handles — see that option's doc, and scope.New, which takes the
// same construction-time stance on WithParent.
// The one configuration this constructor cannot check for you is [WithJWT]:
// there is no default signing key, so a Service built without one — or with
// one under the 32-byte HS256 floor — fails closed the first time
// [Service.Login] tries to issue a token, or [Service.VerifyAccessToken] to
// verify one, with token.ErrKeyTooShort. See that option's doc.
func New(store Store, opts ...Option) *Service {
	cfg := defaultConfig()
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return &Service{store: store, cfg: cfg}
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
// extra, never-returned row that ages out on its own after
// [WithVerificationTTL]'s window, same as any other unredeemed token, and
// never interferes with the real one being redeemed.
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
func (s *Service) SignUp(ctx context.Context, email, plainPassword string) (SignUpResult, error) {
	if failed := password.Validate(plainPassword, s.cfg.rules); len(failed) > 0 {
		return SignUpResult{}, fmt.Errorf("%w: %s", ErrWeakPassword, strings.Join(failed, ","))
	}

	normalized := NormalizeEmail(email)
	now := s.cfg.clock()

	hash, err := s.cfg.hasher.Hash(plainPassword)
	if err != nil {
		return SignUpResult{}, err
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
		return SignUpResult{}, err
	}

	// From here on, EVERY call is identical regardless of branch — see
	// "Fail closed, by construction" above. created is the only thing
	// that determines the shape of the final return.
	user, ferr := s.store.FindUserByEmail(ctx, normalized)
	if ferr != nil {
		return SignUpResult{}, ferr
	}

	plainToken, verr := s.mintSignupVerification(ctx, user.ID, user.Email, now)
	if verr != nil {
		return SignUpResult{}, verr
	}
	user.PasswordHash = ""

	if !created {
		// The zero UserBase, not the account that was found — see
		// [SignUpResult.User]. The caller attempted to register an address
		// they have proven nothing about; handing them that account's id,
		// CreatedAt and EmailVerifiedAt would answer "is this address
		// registered?" outright.
		return SignUpResult{Created: false}, nil
	}
	return SignUpResult{Created: true, User: user, VerifyToken: plainToken}, nil
}

// mintSignupVerification mints and persists a fresh "signup" [Verification]
// for (userID, email) and returns its plaintext token. Called by
// [Service.SignUp] on every invocation regardless of branch — see that
// method's "Fail closed, by construction" section — and never preceded by
// deleting any prior verification; see "What this does NOT do" there for
// why that would be a mistake.
func (s *Service) mintSignupVerification(ctx context.Context, userID, email string, now time.Time) (string, error) {
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
		ExpiresAt: now.Add(s.cfg.verificationTTL),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return plainToken, nil
}

// Login authenticates email/plainPassword and, unless the account owes a
// second factor (see "The pending state" below), mints a new
// session: an access token (a short-lived, HS256-signed JWT — see
// [WithJWT]) and a refresh token (a long-lived opaque bearer token, whose
// hash becomes the minted [Session]'s TokenHash). Both, with the
// authenticated account, come back in a [LoginResult] — the same type
// [Service.Refresh] returns, since a login and a rotation hand a caller the
// same three things. ip and userAgent are
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
//  3. An ANONYMIZED account (a non-nil [UserBase.DeletedAt] — see
//     [Service.AnonymizeAccount]) is likewise treated exactly like a lookup
//     miss: Dummy, then ErrInvalidCredentials. It is checked HERE, before
//     the password is looked at, because a stamped account may not be
//     authenticated by any route whatever its credentials say; and it
//     answers identically to cases 2 and 4 because anything else would tell
//     an anonymous caller that this address once had an account.
//  4. An account with no password credential (PasswordHash == "" — see
//     [UserBase]'s doc for why that is a real, supported state, an
//     OAuth-only account being the obvious example) is treated exactly
//     like a lookup miss: Dummy, then ErrInvalidCredentials. Falling
//     through to Verify against an empty hash would return false safely
//     (see [password.Hasher.Verify]'s own doc), but it would also do so
//     near-instantly rather than paying bcrypt's cost — reopening the
//     exact timing gap Dummy exists to close, this time distinguishing
//     "exists, no password" from "exists, wrong password" instead of
//     "exists" from "doesn't".
//  5. Verify the password. A mismatch is [ErrInvalidCredentials] — the
//     same sentinel as cases 2, 3 and 4, deliberately: a caller cannot
//     tell "no such account", "account is anonymized", "account has no
//     password", and "wrong password" apart from the error alone.
//  6. Only once credentials are proven does this check
//     [WithRequireVerifiedEmail]: an unverified account fails with
//     [ErrEmailNotVerified] here, never earlier, so a caller who does not
//     already know the password cannot use the verified-or-not distinction
//     as its own enumeration channel.
//  7. Only once credentials are proven AND point 6 has passed does this
//     consult the second factor, if an [MFAStore] is wired. A CONFIRMED
//     [MFAFactor] means the login is not finished: this returns a
//     [LoginResult] whose AccessToken and RefreshToken are EMPTY and whose
//     MFA field carries a short-lived [MFAChallenge], with a nil error and
//     no Session row created — see "The pending state" below. An
//     UNCONFIRMED factor gates nothing. With [EnforcementRequired] an
//     account with no confirmed factor is refused here with
//     [ErrMFARequired], a sentinel of its own so an application can route
//     the user into enrolment instead of showing them "wrong password".
//     Ordered after point 6 for the same reason point 6 is ordered after
//     point 5: neither "is MFA enrolled?" nor "is the address verified?"
//     may become an oracle for a caller who has not proven the password.
//  8. Only once every check above has passed does this touch the Store
//     with a write ([Store.CreateSession]) — and even that is ordered
//     LAST, after [token.Issue] has already succeeded (see mintSession,
//     the minting tail this method and [Service.SignInWith] share): a
//     misconfigured signing key ([WithJWT] never called, or too short)
//     fails before any Session row is persisted, rather than leaving an
//     orphaned, unreachable-by-refresh-token row behind that
//     [Store.ListSessionsByUser] would still report.
//
// # The pending state
//
// A login that owes a second factor returns (LoginResult, nil): a nil
// error, because the password WAS correct, and a result carrying nothing a
// caller can authenticate with. The tokens are the empty string, not a
// short-lived or restricted token, so a caller written against v0.1.0 that
// reads AccessToken and ignores MFA receives a value
// [github.com/bernardoforcillo/authlayer/token.Parse] refuses rather than
// one it accepts. See [LoginResult.MFA]'s own doc, which carries the whole
// argument, and [Service.CompleteMFA], which finishes the login.
//
// # Fail closed
//
// Any Store or RateLimiter error not covered by a case above is returned
// as-is, never folded into ErrInvalidCredentials or a silent success — see
// the package-level "Fail closed" constraint this method, like every other
// one in this file, is held to.
func (s *Service) Login(ctx context.Context, email, plainPassword, ip, userAgent string) (LoginResult, error) {
	var zero LoginResult

	if ip == "" {
		return zero, ErrMissingIP
	}
	if s.cfg.limiter != nil {
		allowed, err := s.cfg.limiter.Allow(ctx, ip)
		if err != nil {
			return zero, err
		}
		if !allowed {
			return zero, ErrRateLimited
		}
	}

	normalized := NormalizeEmail(email)
	u, err := s.store.FindUserByEmail(ctx, normalized)
	switch {
	case errors.Is(err, ErrUserNotFound):
		s.cfg.hasher.Dummy(plainPassword)
		return zero, ErrInvalidCredentials
	case err != nil:
		return zero, err
	}

	// An ANONYMIZED account is treated exactly like a lookup miss — Dummy,
	// then ErrInvalidCredentials — so neither the error nor the cost tells
	// an anonymous caller that this address once had an account. See
	// [Service.AnonymizeAccount], "Every entry point that refuses a stamped
	// account"; this check is deliberately its own rather than one shared
	// guard several paths reach.
	if u.DeletedAt != nil {
		s.cfg.hasher.Dummy(plainPassword)
		return zero, ErrInvalidCredentials
	}

	if u.PasswordHash == "" {
		s.cfg.hasher.Dummy(plainPassword)
		return zero, ErrInvalidCredentials
	}
	if !s.cfg.hasher.Verify(plainPassword, u.PasswordHash) {
		return zero, ErrInvalidCredentials
	}

	if s.cfg.requireVerifiedEmail && u.EmailVerifiedAt == nil {
		return zero, ErrEmailNotVerified
	}

	// Step 7: the second factor, consulted only once the password and
	// every check above it have passed. A confirmed factor short-circuits
	// the mint entirely and hands back a challenge with EMPTY tokens — see
	// mfaAtLogin, and [LoginResult.MFA] for what a caller that has never
	// heard of this field gets.
	challenge, err := s.mfaAtLogin(ctx, u)
	if err != nil {
		return zero, err
	}
	if challenge != nil {
		// Deliberately NOT mintSession: no session row, no access token,
		// no refresh token. PasswordHash is scrubbed here because this is
		// the one success path that does not go through mintSession, which
		// is where every other return value gets scrubbed.
		u.PasswordHash = ""
		return LoginResult{User: u, MFA: challenge}, nil
	}

	return s.mintSession(ctx, u, ip, userAgent)
}

// mintSession is the session-issuing tail shared by [Service.Login] and
// [Service.SignInWith]: given a user whose identity the caller has ALREADY
// established, it mints a root session — a fresh refresh token, its
// [Session] row, and a matching access token — and returns the three things
// a successful authentication hands back.
//
// # It authenticates nothing
//
// This helper performs no credential check, no rate-limit check, no
// email-verification check and no linking-policy check. Every one of those
// belongs to whoever calls it, and the three callers run different sets:
// [Service.Login] proves possession of a password and honours
// [WithRequireVerifiedEmail]; [Service.SignInWith] proves nothing itself and
// stands instead on a provider's assertion plus the [Linking] policy;
// [Service.RedeemMagicLink] proves nothing itself either, standing on a
// verification it has already claimed and burned. A FOURTH caller would
// mint a live session for whoever u names with no check at all, so any
// future one must be read as the assertion "I have already decided this
// user is authenticated".
//
// It exists because there must be exactly ONE minting path. Two would drift,
// and the drift would not be a compile error: a scrub, a claim, or the
// family-id rule fixed in one and forgotten in the other surfaces as a live
// credential digest inside a JWT claim, or as a session no revocation can
// reach. [Service.Refresh] deliberately does NOT use it — a rotation
// inherits its predecessor's FamilyID rather than starting a new chain,
// which is the one thing this function hard-codes the other way.
//
// The order inside is load-bearing, and is the order [Service.Login]'s own
// doc describes at point 6: PasswordHash is scrubbed BEFORE the claims
// extender runs, and [github.com/bernardoforcillo/authlayer/token.Issue]
// runs BEFORE [Store.CreateSession], so a misconfigured signing key fails
// without leaving an orphaned session row behind.
//
// u is taken BY VALUE and its PasswordHash cleared here, so no caller can
// leak a credential digest through the returned record or into a
// [WithClaimsExtender] callback by forgetting to scrub first.
//
// ip and userAgent are recorded on the [Session] as audit fields and are
// not validated here; a caller that requires them non-empty checks that
// itself, as [Service.Login] does with [ErrMissingIP].
func (s *Service) mintSession(ctx context.Context, u UserBase, ip, userAgent string) (LoginResult, error) {
	var zero LoginResult

	now := s.cfg.clock()
	sessionID := s.cfg.idGen()
	refreshPlain, refreshHash, err := token.GenerateOpaque()
	if err != nil {
		return zero, err
	}

	// Cleared before the claims extender runs, not after: this way neither
	// the extender (an application-supplied callback that could otherwise
	// embed it into a JWT claim without realizing) nor this method's own
	// return value ever sees a live credential digest — see
	// [UserBase.PasswordHash]'s own doc for why that field carries json:"-"
	// but is additionally cleared here rather than relying on that alone.
	u.PasswordHash = ""

	// u is the ONE user value both the claims extender and this method's
	// own return statement use — see [WithClaimsExtender]'s doc for why the
	// extender must see the real, just-authenticated identity rather than a
	// separately (and identically) reconstructed one.
	var extra map[string]any
	if s.cfg.claimsExtender != nil {
		extra = s.cfg.claimsExtender(u)
	}
	// Issued BEFORE CreateSession, deliberately — see "Order of checks"
	// point 7 above: a bad signing key must fail before any Session row
	// exists to be orphaned.
	accessToken, err := token.Issue(token.Claims{
		Subject:   u.ID,
		SessionID: sessionID,
		Email:     u.Email,
		Extra:     extra,
	}, s.signingKey(), s.cfg.accessTTL)
	if err != nil {
		return zero, err
	}

	if _, err := s.store.CreateSession(ctx, Session{
		ID:        sessionID,
		UserID:    u.ID,
		TokenHash: refreshHash,
		// FamilyID: this session is the root of its own rotation chain —
		// nothing to inherit from at a fresh sign-in — so it names itself.
		// A successor minted by a future refresh carries this same value
		// forward (see auth.go's package doc, "Sessions, families, and
		// rotation").
		FamilyID:  sessionID,
		ExpiresAt: now.Add(s.cfg.refreshTTL),
		CreatedAt: now,
		UserAgent: userAgent,
		IP:        ip,
	}); err != nil {
		return zero, err
	}

	return LoginResult{User: u, AccessToken: accessToken, RefreshToken: refreshPlain}, nil
}

// signingKey returns the current signing key ([WithJWT]'s keys[0]), or nil
// if none was configured. Returning nil rather than indexing an empty slice
// (which would panic) lets [token.Issue]'s own key-length check —
// token.ErrKeyTooShort for anything under 32 bytes, nil included — be what
// fails a misconfigured Service closed, with a clear, existing sentinel,
// instead of this package inventing a second one or panicking itself.
func (s *Service) signingKey() []byte {
	if len(s.cfg.signingKey) == 0 {
		return nil
	}
	return s.cfg.signingKey[0]
}

// VerifyAccessToken verifies raw — an access token minted by
// [Service.Login] or [Service.Refresh] — against the keys [WithJWT]
// configured, and returns its claims. Every key in that list is tried, not
// only the signing key, which is what makes a key rotation transparent to
// tokens already in flight (see [token.Parse]).
//
// This exists so an application does not have to keep a SECOND copy of the
// key material beside the Service that already holds it. Verifying an
// access token is the most frequent operation in a real deployment — once
// per request — and every other credential this package issues is redeemed
// through a method of its own; without this one, that single hottest path
// was the exception, and duplicated key material is how a rotation goes
// half-applied.
//
// # Errors
//
// The errors are [github.com/bernardoforcillo/authlayer/token]'s own,
// unwrapped and unchanged: ErrMalformedToken, ErrUnsupportedAlgorithm,
// ErrInvalidSignature, ErrExpiredToken, and ErrKeyTooShort — compare with
// [errors.Is] against the token package, not this one. This method
// deliberately adds no auth-level sentinel of its own: it performs no
// authentication decision beyond what token.Parse already performs, so a
// translated error would carry no information the original does not, while
// costing the caller the ability to tell "expired" from "forged".
//
// A Service built without [WithJWT] returns token.ErrKeyTooShort here,
// matching how [Service.Login] fails closed on the same misconfiguration —
// a missing key is not distinguishable from a zero-length one, and neither
// may be treated as "verified".
//
// # What a nil error does and does not mean
//
// It means the token was signed by one of the configured keys and has not
// expired. It does NOT mean the session behind it still exists: an access
// token is stateless, this method makes no [Store] call at all (which is
// why it takes no context.Context), and a token issued for a session that
// [Service.Logout], [Service.LogoutAll], [Service.RevokeSession],
// [Service.ChangePassword], [Service.ResetPassword] or [Service.Refresh]'s
// reuse response has since revoked keeps verifying here until its own TTL
// runs out. See [Service.LogoutAll]'s doc, "What this does not revoke".
// An application that needs revocation honoured sooner looks the returned
// [token.Claims.SessionID] up in the Store on every request; this method
// hands back the claim so that choice is available, and does not make it.
//
// # The pairing with ChangePassword
//
// [Service.ChangePassword] takes a currentSessionID so it can spare the
// caller's own session while revoking every other one, and the value it
// wants is exactly the SessionID claim on the access token that
// authenticated the request. This method is how a handler obtains it:
//
//	claims, err := svc.VerifyAccessToken(bearer)
//	if err != nil {
//		// 401 — do not proceed
//	}
//	err = svc.ChangePassword(ctx, claims.Subject, claims.SessionID, current, next)
//
// Passing an empty or foreign currentSessionID is not an error; it revokes
// everything, which is the fail-closed direction — see that method's doc.
func (s *Service) VerifyAccessToken(raw string) (token.Claims, error) {
	if len(s.cfg.signingKey) == 0 {
		return token.Claims{}, fmt.Errorf("%w: no signing key is configured; call WithJWT", token.ErrKeyTooShort)
	}
	return token.Parse(raw, s.cfg.signingKey...)
}

// User loads the account identified by userID, returning [ErrUserNotFound]
// when there is none. PasswordHash is cleared to "" on the returned value,
// like every other path in this package that hands a [UserBase] back — see
// that field's own doc.
//
// It is otherwise a thin wrapper over [Store.FindUserByID], and that scrub
// is exactly why it exists. Without it the only exported way to read a user
// was the Store's own method, which returns the row as stored — including
// the LIVE bcrypt digest — so the read path a caller was forced onto was
// the one path in this package that did not scrub, and the caller had to
// know to do it themselves. [Service.SignUp], [Service.Login],
// [Service.Refresh] and [Service.VerifyEmail] each hand back a user because
// they just did something to it; this method exists for the ordinary case
// of having only an id, most often the Subject claim off an access token
// [Service.VerifyAccessToken] just verified. It is the counterpart of
// [github.com/bernardoforcillo/authlayer/scope.Service.Container], which
// exists on that Service for the same "another package needs to read one by
// id" reason.
//
// It reads nothing from the context and performs no check that the caller
// is entitled to ask — exactly like scope.Service.Container. Do not expose
// it directly to end users: a handler must have already decided, by its own
// reasoning, that this account's record belongs in front of whoever is
// asking. The record is small and fixed (see the package doc, "Why Service
// is not generic over your user type"), so what it discloses is an id, an
// email address, a verification stamp and two timestamps — but an email
// address handed to the wrong caller is still a disclosure, and the id
// itself is what every other method in this package authorizes on.
//
// It does NOT refuse an ANONYMIZED account, deliberately, and is the one
// account-reading method that does not — see [Service.AnonymizeAccount],
// "What deliberately keeps working". Reading the stamped row is how an
// application discovers that the account is anonymized at all: the record
// this returns carries [UserBase.DeletedAt], and testing it is what a
// per-request SessionID ("sid") check is supposed to do. Refusing here
// would remove the only signal and leave a caller unable to distinguish an
// anonymized account from a Store outage. A caller that wants "live
// accounts only" tests DeletedAt itself, on the record it just got.
func (s *Service) User(ctx context.Context, userID string) (UserBase, error) {
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return UserBase{}, err
	}
	u.PasswordHash = ""
	return u, nil
}

// PurgeExpired deletes every [Session] and [Verification] expired strictly
// before `before` — both by ExpiresAt — and returns how many rows were
// removed in total, across both kinds. It is a direct pass-through to
// [Store.PurgeExpired], matching
// [github.com/bernardoforcillo/authlayer/invite.Service.PurgeExpired]'s own
// relationship to its Store. It exists on Service because a caller
// ordinarily holds only the *Service, and this package REQUIRES the
// housekeeping: rotated-but-unexpired session rows are retained on purpose
// (they are what makes a replay detectable — see auth.go's package doc), so
// nothing else ever removes them, and one device refreshing at the
// 15-minute default accumulates about 97 rows a day.
//
// It is housekeeping, not a security boundary: an expired session or
// verification is already unusable through every lookup, rotation and
// redemption path in this package before it is ever purged — [Service.Refresh]
// rejects an expired session with [ErrTokenInvalid], and [Service.VerifyEmail]
// and [Service.ResetPassword] reject an expired token with
// [ErrVerificationExpired], all without consulting this method. Purging
// reclaims storage and keeps the tables (and therefore the scans over them
// — see [Service.RequestPasswordReset]'s doc, point 5) small. UserBase rows
// are never purged; users do not expire.
//
// Like invite's, it performs NO authorization and reads nothing from the
// context: a single call spans every user the Store holds, and deleting an
// already-dead row confers no standing on anyone. That does not make it
// safe to expose to an end user, though — an unauthenticated or
// under-privileged caller who could trigger it at will gets a
// denial-of-service knob against the whole deployment. Call it only from a
// trusted context: a cron job, a superuser console, never a per-request
// handler wired to caller input.
//
// The cutoff is taken literally and is not clamped to the present: `before`
// is compared against ExpiresAt, so a future value removes rows that have
// not expired yet — signing out live sessions and voiding live tokens.
// Ordinarily pass the current time. The Service clock ([WithClock]) is
// deliberately not consulted here, matching invite's signature: the caller
// scheduling this housekeeping is the one that decides its cutoff, and a
// job that means "everything older than a week ago" says so directly.
func (s *Service) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	return s.store.PurgeExpired(ctx, before)
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
// burn it. A token whose account has been ANONYMIZED (a non-nil
// [UserBase.DeletedAt]) is [ErrUserNotFound], likewise before the claim:
// redeeming an "email_change" here would call [Store.UpdateUserEmail] and
// put a real, verified address back onto a scrubbed row. See
// [Service.AnonymizeAccount], "Every entry point that refuses a stamped
// account", for why that check is here even though anonymization already
// deletes every pending verification.
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
// not to repeat. That method shipped admit-first, claim-second, which left
// the invite row in place while the membership was being granted — so the
// token stayed redeemable "by ANYONE presenting it, not merely by the
// original caller retrying", and a one-time credential paid out more than
// once. Applying first would let every caller racing on the
// same token reach MarkEmailVerified/UpdateUserEmail — both idempotent
// writes to the SAME target user and address, so a race does not escalate
// to a different account the way AcceptInvite's did — but it would still
// leave the verification row claimable by a concurrent caller for the
// entire duration of the apply step, which is exactly the window
// claim-then-apply exists to close to zero.
//
// One consequence worth stating plainly, matching AcceptInvite's own: this
// is NOT safe to retry with the same token. A failure after the claim
// succeeds (MarkEmailVerified, UpdateUserEmail, or the sweep below
// returning an error) burns the verification anyway — the row is already
// gone. That is the safe direction: under-verifying (the caller must
// request a fresh token) rather than leaving a claimed-but-not-yet-applied
// token redeemable by a second presentation.
//
// # An address rotation invalidates the reset tokens
//
// After an "email_change" redemption — and only that branch — every
// outstanding "password_reset" [Verification] for the account is
// invalidated via [Store.DeleteVerificationsByUserAndPurpose], fail-closed
// like every other sweep in this package.
//
// A reset token is only ever deliverable to the ONE address it was minted
// for (that is the whole basis on which [Service.ResetPassword] treats
// redeeming one as proof of control). Moving the account's address away
// from there — often precisely because that mailbox is no longer
// trustworthy — would otherwise leave a link sitting in the abandoned
// mailbox able to reset the password of the account at its NEW address,
// for the rest of [WithPasswordResetTTL]'s window. This is the mirror of
// the sweep [Service.ChangePassword] and [Service.ResetPassword] already
// perform in the other direction, where rotating the CREDENTIAL
// invalidates the pending identifier change.
//
// The sweep does not run on the "signup" branch: that redemption certifies
// the address the account already holds and rotates nothing, so a reset
// token for that same mailbox is still a token for that same mailbox.
//
// Its scope is SEQUENTIAL ONLY, exactly as [Service.ChangePassword]'s doc
// (point 6) discloses for its own: a [Service.RequestPasswordReset] whose
// [Store.CreateVerification] is genuinely concurrent with this call can
// still mint a token that survives it.
//
// # What this does NOT revoke
//
// Sessions. An "email_change" redemption leaves every [Session] belonging
// to the account exactly as it found it — a device signed in before the
// change keeps refreshing afterwards, now under the new address. That is a
// deliberate decision, not an omission:
//
//   - This method is UNAUTHENTICATED by construction: it is redeemed by
//     whoever holds the link, typically on a device with no session at all.
//     Giving an unauthenticated endpoint a sign-out-every-device effect
//     would hand a denial-of-service lever to anyone who obtains the link —
//     a forwarded mail, a shared mailbox, a URL left in a browser history —
//     without ever knowing the password.
//   - [Service.RequestEmailChange] requires the current password to arm the
//     token (see its doc), so a redemption is not on its own evidence that
//     the account's live sessions became untrustworthy. The one-time token
//     the sweep above destroys is a different matter: it is a credential
//     that outlives the mailbox it was sent to.
//   - The application keeps the choice. "Changing your address signs you
//     out everywhere" composes from [Service.LogoutAll], which is
//     authenticated, is an unambiguous security action, and sweeps both
//     verification purposes of its own.
func (s *Service) VerifyEmail(ctx context.Context, plainToken string) (UserBase, error) {
	var zero UserBase

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

	// An ANONYMIZED account may not be verified into. This is the refusal
	// with the sharpest consequence of the whole sweep: an "email_change"
	// redemption calls [Store.UpdateUserEmail], which would move a real,
	// VERIFIED address back onto a stamped row — undoing the scrub and
	// taking that address out of circulation again — and a "signup"
	// redemption would certify the undeliverable scrubbed address itself.
	// [Service.AnonymizeAccount] deletes every verification before it
	// stamps, so this is defence in depth; it is checked BEFORE the claim
	// below so a call that cannot succeed does not burn the token. See that
	// method's "Every entry point that refuses a stamped account".
	if holder, herr := s.store.FindUserByID(ctx, v.UserID); herr != nil {
		return zero, herr
	} else if holder.DeletedAt != nil {
		return zero, ErrUserNotFound
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
	if v.Purpose == PurposeEmailChange {
		// The identifier just moved, so every credential-recovery token
		// issued against the OLD one has to go — see the method doc's
		// "An address rotation invalidates the reset tokens". Fail-closed,
		// like every other sweep in this package.
		if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, v.UserID, PurposePasswordReset); err != nil {
			return zero, err
		}
	}

	u, err := s.store.FindUserByID(ctx, v.UserID)
	if err != nil {
		return zero, err
	}
	u.PasswordHash = ""
	return u, nil
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
//     returns [ErrTokenReuse]. See "Why the whole family" below. That
//     revocation needs the family id MarkRotated returns with its ok=false,
//     so an empty one is refused rather than used: see "Fail closed" for
//     the [ErrStoreContract] case. A
//     tokenHash that MarkRotated itself can no longer find (the row was
//     deleted between step 1 and here — PurgeExpired, LogoutAll, or another
//     reuse revocation racing this one) is also reported as ErrTokenInvalid,
//     matching step 1's miss case, not surfaced as the raw Store sentinel.
//  4. Only a true ok from step 3 goes on to mint a successor: a fresh
//     opaque refresh token (in the SAME FamilyID as the rotated session, so
//     the chain still traces back to one login) and a fresh access token.
//     THIS IS THE PROPERTY THE WHOLE METHOD EXISTS TO ENFORCE — see the
//     next section for why. The account itself is loaded here, and two
//     states of it stop the rotation dead: a user row that is GONE (the
//     [Store.FindUserByID] miss propagates as [ErrUserNotFound]) and one
//     that is ANONYMIZED (a non-nil [UserBase.DeletedAt] — the same
//     ErrUserNotFound; see [Service.AnonymizeAccount]). In both the
//     presented token was genuine, won step 3, and still buys nothing.
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
// Step 3's replay branch fails closed one step earlier, too. Revoking the
// family needs the FamilyID of the row MarkRotated refused to rotate, and
// MarkRotated's contract is to return that row — but a backend answering
// (Session{}, false, nil) instead, which nothing in the port enforces,
// would send DeleteSessionsByFamily an empty id that matches no rows: the
// alarm fires, ErrTokenReuse comes back, and the family the caller believes
// was revoked is still live, an attacker's successor included. Neither
// revoking on a meaningless key nor skipping the revocation is acceptable,
// so an empty FamilyID here is refused as the contract violation it is —
// wrapping [ErrStoreContract] alongside ErrTokenReuse, for the same reason
// the DeleteSessionsByFamily failure above wraps both.
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
func (s *Service) Refresh(ctx context.Context, refreshPlain string) (LoginResult, error) {
	var zero LoginResult
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
		// First: this Store must have handed back the row it refused to
		// rotate. [Store.MarkRotated] documents that it does; nothing
		// enforces it, and a backend returning (Session{}, false, nil)
		// would send DeleteSessionsByFamily an empty family id, which
		// matches nothing — the alarm fires, ErrTokenReuse comes back, and
		// containment silently does not happen. Neither proceeding with a
		// meaningless key nor skipping the revocation is acceptable here,
		// so this fails closed and says which contract was broken, while
		// keeping the ErrTokenReuse signal a caller matches on — see
		// [ErrStoreContract] and the method doc's "Fail closed".
		if rotated.FamilyID == "" {
			return zero, fmt.Errorf("%w: %w: MarkRotated reported a replay but returned a Session with no FamilyID, leaving no family to revoke", ErrTokenReuse, ErrStoreContract)
		}
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
	// An ANONYMIZED account mints nothing, however valid the token was.
	// AnonymizeAccount revokes every session before it stamps, so reaching
	// this with a stamped user means the row was stamped by some other
	// route; either way a rotation must not hand back a live session for an
	// account no one may authenticate as. ErrUserNotFound, matching what
	// this same load already returns for a row that is genuinely gone — see
	// [Service.AnonymizeAccount], "Every entry point that refuses a stamped
	// account".
	if u.DeletedAt != nil {
		return zero, ErrUserNotFound
	}
	u.PasswordHash = ""

	successorID := s.cfg.idGen()
	refreshPlainNew, refreshHashNew, err := token.GenerateOpaque()
	if err != nil {
		return zero, err
	}

	var extra map[string]any
	if s.cfg.claimsExtender != nil {
		extra = s.cfg.claimsExtender(u)
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
		// fields describe the login that STARTED this family, never the
		// device that just rotated it. A thief rotating a stolen token
		// therefore appears in the victim's family wearing the victim's
		// fingerprint.
		//
		// Dropping the inheritance instead (leaving both fields empty)
		// would not make the listing more honest and would make it far less
		// useful: at the 15-minute default access TTL every live session is
		// a successor within minutes of login, so a "your devices" screen
		// would show blank device and location for essentially every row,
		// while a blank row identifies a thief no better than an inherited
		// one does. An application that needs the rotating device recorded
		// per-refresh needs Refresh to TAKE ip/userAgent, which is a
		// signature this package does not offer today.
		UserAgent: rotated.UserAgent,
		IP:        rotated.IP,
	})
	if err != nil {
		return zero, err
	}
	if !ok {
		return zero, ErrSessionRevoked
	}

	return LoginResult{User: u, AccessToken: accessToken, RefreshToken: refreshPlainNew}, nil
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
// Two things, and both are deliberate.
//
// First, VERIFICATIONS. Logout sweeps NONE — not "password_reset", not
// "email_change", and not "magic_link". Every one of them survives this
// call untouched and stays redeemable for the rest of its own TTL. That
// includes a pending magic link, which is a working SIGN-IN for whoever
// holds it: logging one device out does not invalidate it, and clicking it
// afterwards signs in again.
//
// This is deliberate, and it is the whole bottom half of
// [Service.ChangePassword]'s doc, "The sweep matrix". Logout is a
// per-device, routine action — a browser signing itself out — and sweeping
// here would break a legitimate flow with no attacker in it: request an
// email change (or a magic link) on a desktop, log out of that desktop,
// click the link that arrives on a phone. That flow is the ordinary case;
// a user signing out of one browser is not telling this package the
// account is compromised.
//
// [Service.LogoutAll] is the unambiguous "something is wrong" control and
// it DOES sweep all three purposes; [Service.ChangePassword] and
// [Service.ResetPassword] sweep them too. A caller that wants a single
// device's logout to invalidate those tokens must call LogoutAll instead —
// this method will not do it for them.
//
// Second, ACCESS TOKENS. Either way — one row or the whole family —
// "revoked" means the [Session] row is gone, so the REFRESH token cannot be
// presented again. It does NOT invalidate an ACCESS token already issued
// for that session: a short-lived
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
func (s *Service) Logout(ctx context.Context, refreshPlain string) error {
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
		//
		// The same family-id guard [Service.Refresh] carries, for the same
		// reason: a Store handing back a Session with no FamilyID would
		// turn this into DeleteSessionsByFamily(ctx, ""), which matches no
		// rows and returns nil — this method would report success having
		// revoked nothing. See [ErrStoreContract].
		if sess.FamilyID == "" {
			return fmt.Errorf("%w: FindSessionByHash returned a rotated Session with no FamilyID, leaving no family to revoke", ErrStoreContract)
		}
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
// bounded by "What this does not revoke" below — and invalidates every
// outstanding "password_reset", "email_change" and "magic_link"
// [Verification] for that account. A user with none of them is not an
// error.
//
// The revocation is implemented as one [Store.DeleteSessionsByFamily] call
// per DISTINCT family among the user's sessions, rather than one
// [Store.DeleteSession] call per row returned by
// [Store.ListSessionsByUser]: DeleteSessionsByFamily also removes that
// family's rotated-but-unexpired predecessors (see auth.go's package doc
// for why those rows are retained rather than deleted at rotation time),
// not merely whichever rows happened to still exist at the instant the
// list was read. The sweep is three [Store.DeleteVerificationsByUserAndPurpose]
// calls, one per purpose, all fail-closed, and all run AFTER the
// revocation: see the section below.
//
// # Why this sweeps verifications, and why Logout and RevokeSession do not
//
// "Sign out everywhere" is an unambiguous security action — the control a
// user reaches for on spotting an intruder — not routine navigation. Like
// [Service.ChangePassword] and [Service.ResetPassword], it must therefore
// leave nothing armed that can quietly undo it. Three verification purposes
// can — see [Service.ChangePassword]'s doc, "The sweep matrix", for the
// whole table:
//
// A still-live "password_reset" token grants a full credential rotation to
// whoever holds it, for the remainder of [WithPasswordResetTTL]'s window.
//
// A still-live "email_change" token is the stronger of the two: it lives
// [WithVerificationTTL]'s window (24h by default), and [Service.VerifyEmail]
// redeems it with NO authentication whatsoever, moving the account to
// another address — after which the victim cannot recover, because
// [Service.Login] and [Service.RequestPasswordReset] both look accounts up
// BY email. Arming one now costs the current password (see
// [Service.RequestEmailChange]), but a token armed before the credential
// leaked, or armed by the user themselves and then regretted, is exactly
// what this sweep is for.
//
// A still-live "magic_link" token is the most direct of the three: it is
// not a step towards a credential, it IS one, and
// [Service.RedeemMagicLink] exchanges it for a live session with nothing
// else asked. Leaving one armed would mean the very call that removed
// every session an intruder had also left them a way to make a new one,
// for the remainder of [WithMagicLinkTTL]'s window.
//
// [Service.Logout] and [Service.RevokeSession] deliberately sweep NOTHING,
// for any of the three purposes.
// They are per-device and routine — a browser signing itself out, a device
// dropped from a "your devices" listing — and sweeping there would break a
// legitimate flow with no attacker in it: request an email change or a
// magic link on a
// desktop, log out of that desktop, click the link that arrives on a phone.
// Each of those methods says so in its own doc.
//
// The sweep is purpose-scoped, like every other sweep in this package: a
// "signup" verification grants nothing over the credential or the address,
// and destroying it would strand a user who signed out everywhere before
// confirming their address, since this package exposes no resend path.
//
// All three sweeps carry the SAME guarantee, and it is SEQUENTIAL ONLY:
// nothing
// orders any of them against a concurrently-running [Service.RequestPasswordReset],
// [Service.RequestEmailChange] or [Service.RequestMagicLink] whose own
// [Store.CreateVerification] has
// not yet committed — see [Service.ChangePassword]'s doc, point 6, for the
// deterministic demonstration and for why closing that window would need a
// transaction [Store] does not offer.
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
func (s *Service) LogoutAll(ctx context.Context, userID string) error {
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

	// Then close ALL THREE token side doors — see the method doc's "Why
	// this sweeps verifications, and why Logout and RevokeSession do not",
	// and [Service.ChangePassword]'s "The sweep matrix". The revocation
	// runs FIRST, deliberately: it is what this caller actually asked for,
	// so a sweep failure still leaves every session gone and an error
	// telling the caller to retry, rather than leaving the intruder the
	// live sessions this call exists to cut.
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, userID, PurposePasswordReset); err != nil {
		return err
	}
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, userID, PurposeEmailChange); err != nil {
		return err
	}
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, userID, PurposeMagicLink); err != nil {
		return err
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
// login by rotation. One entry per login is NOT the same as one entry per
// device: [Service.Refresh] inherits UserAgent and IP from the row it
// rotates, so a stolen token rotated by a thief keeps showing the victim's
// own fingerprint inside the victim's family. See [Service.RevokeSession]'s
// doc, "Why a family, not a row".
//
// [Service.RevokeSession] takes a Session.ID but revokes that session's
// whole FAMILY, precisely so a handler built from this listing signs the
// device out whichever of its rows the user happened to pick — see that
// method's doc.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]Session, error) {
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
// A family is one login's rotation chain: every row sharing a FamilyID
// descends from a single [Service.Login] by successive refreshes. So
// "revoke the family" is what a "sign this device out" control has to
// mean, and every other revocation path in this package
// ([Service.LogoutAll], [Service.ChangePassword], [Service.ResetPassword],
// and [Service.Refresh]'s own reuse response) already works per family.
//
// "One login" is not the same as "one device", and the difference is the
// theft case. [Service.Refresh] copies the predecessor's UserAgent and IP
// into every successor it mints (see that method's own note on those
// fields), so a thief who rotates a stolen refresh token joins the victim's
// family carrying the VICTIM's audit fingerprint: a listing grouped by
// FamilyID shows one device where two are in use, and neither the row nor
// the grouping reveals the second. Revoking the family remains the right
// response — it signs the thief out along with the victim's own device,
// which is the safe direction — but a caller must not read a family as
// proof that exactly one device holds it.
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
// Two things, and both are deliberate.
//
// First, VERIFICATIONS. Like [Service.Logout] and unlike
// [Service.LogoutAll], this method sweeps NONE: a pending "password_reset",
// "email_change" or "magic_link" [Verification] survives it and stays
// redeemable for the rest of its own TTL — the magic link included, so the
// device dropped from the listing is not the only way back in, and a link
// already delivered still signs its holder in.
//
// Dropping one device from a listing is routine, not a
// declaration that the account is compromised, and sweeping here would
// break a legitimate flow with no attacker in it — request an email change
// (or a magic link) on a desktop, drop that desktop from the device list,
// click the link that arrives on a phone. [Service.LogoutAll] is the
// control that means "sign out everywhere, something is wrong", and it
// sweeps all three purposes. See [Service.ChangePassword]'s doc, "The
// sweep matrix", for the whole table this row belongs to.
//
// Second, ACCESS TOKENS. "Sign this device out" is a claim about [Session]
// rows, which is to say about the family's REFRESH tokens: they are gone,
// and [Service.Refresh] on any of them fails immediately. It does NOT
// invalidate an ACCESS token the device was already issued. That token is a stateless HS256 JWT (see
// [WithJWT] — 15 minutes by default) this package never looks up in the
// [Store], only verifies (see [token.Parse]), so the revoked device keeps
// whatever its access token alone authorizes for up to the remainder of
// that token's own TTL after this call returns nil. A "your devices" screen
// that reports "signed out" immediately is therefore accurate about the
// refresh side and up to one access TTL early about the rest — worth saying
// in the UI if the distinction matters to the operator. See
// [Service.LogoutAll]'s doc, "What this does not revoke", for the same
// bound in full and for the SessionID ("sid") claim that closes it.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	sessions, err := s.store.ListSessionsByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if sess.ID == sessionID {
			// Resolve the named session to its FAMILY and revoke that —
			// see the method doc's "Why a family, not a row" section.
			//
			// The same family-id guard [Service.Refresh] and
			// [Service.Logout] carry: an empty FamilyID would make this
			// DeleteSessionsByFamily(ctx, ""), which matches no rows and
			// returns nil — the "your devices" screen reports the device
			// signed out and it keeps refreshing, the exact failure the
			// family-not-row fix exists to end. See [ErrStoreContract].
			if sess.FamilyID == "" {
				return fmt.Errorf("%w: ListSessionsByUser returned the named Session with no FamilyID, leaving no family to revoke", ErrStoreContract)
			}
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
// It does NOT disconnect the account's external identities, and
// [Service.ResetPassword] does. The asymmetry is deliberate and is the same
// one this package draws between [Service.Logout] and [Service.LogoutAll]:
// the caller here proved they hold the current password and is performing a
// routine action, so unlinking their Google would be UX-hostile and would buy
// nothing. A reset is unauthenticated recovery, where every other credential
// on the account has to be assumed hostile — see that method's "Why an
// unauthenticated recovery sweeps identities".
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
// at mint time). [Service.VerifyAccessToken] is how to obtain it from that
// token without keeping a second copy of the signing keys; its doc has the
// two-line pairing. Passing an empty string, or an id that does not belong to
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
//  2. An ANONYMIZED account (a non-nil [UserBase.DeletedAt] — see
//     [Service.AnonymizeAccount]) is refused with the same ErrUserNotFound,
//     before the credential is even looked at: there is no password on such
//     an account to change, and arming a working one would hand the account
//     back to whoever asked.
//  3. An account with no password credential (PasswordHash == "" — see
//     [UserBase]'s doc) is treated like a lookup miss: [password.Hasher.Dummy]
//     runs (comparable-cost hygiene, mirroring [Service.Login]'s identical
//     stance on its own no-credential case — see that method's doc), then
//     [ErrInvalidCredentials].
//  4. current is checked against the stored hash via [password.Hasher.Verify].
//     A mismatch is ErrInvalidCredentials — nothing is written, and next is
//     never even validated, so a caller who does not know the current
//     password learns nothing about next's own validity either.
//  5. next is validated against the configured [password.Rules];
//     [ErrWeakPassword] on failure.
//  6. next is hashed and persisted via [Store.UpdateUserPassword].
//  7. Every outstanding "password_reset", "email_change" AND "magic_link"
//     [Verification] for this account is invalidated, via three
//     [Store.DeleteVerificationsByUserAndPurpose] calls — one per purpose,
//     all fail-closed. See "The sweep matrix" and "Why these purposes, and
//     what the sweep does not cover" below.
//  8. Every session NOT sharing currentSessionID's family is revoked via
//     [Store.DeleteSessionsByFamily], one call per distinct OTHER family —
//     the same "list, then delete per distinct family" shape
//     [Service.LogoutAll] uses, so a rotated-but-unexpired predecessor row
//     in another family is swept too, not just the currently-live session
//     in that family.
//
// # The sweep matrix
//
// This table is the whole of this package's doctrine on which actions
// destroy which pending [Verification] tokens. It is stated here, in full,
// because the last time it existed only as an assumption spread across five
// method docs, it was filled in for two of its three columns and the third
// was a full account takeover:
//
//	Remediation       | password_reset | email_change | magic_link
//	------------------|----------------|--------------|---------------------
//	ChangePassword    | swept          | swept        | swept
//	ResetPassword     | swept          | swept        | swept
//	LogoutAll         | swept          | swept        | swept
//	Logout            | not swept      | not swept    | not swept
//	RevokeSession     | not swept      | not swept    | not swept
//	RedeemMagicLink   | —              | —            | burns its own token
//
// The top three rows are the REMEDIATION actions: each is something a user
// does because they believe, or have just been told, that the account is at
// risk. Each therefore leaves nothing armed that can quietly undo it, and
// each sweeps fail-closed — a sweep that errors is returned to the caller,
// never swallowed.
//
// The bottom two rows are ROUTINE, per-device actions, and their emptiness
// is deliberate, not an omission — see [Service.Logout] and
// [Service.RevokeSession], which each say so in their own docs. Sweeping
// there would break a legitimate flow with no attacker in it: request a
// link (or an email change) on a laptop, sign that laptop out, click the
// link that arrives on a phone.
//
// "signup" appears in no column: it grants nothing over the credential or
// the address, and destroying it would strand a user who remediated before
// confirming their address, since this package exposes no resend path.
//
// # Why these purposes, and what the sweep does not cover
//
// A password change is the one action a user takes when they suspect
// compromise, so it must leave nothing armed that can quietly undo it.
// Three verification purposes can:
//
// A still-valid reset link — one whose [Service.RequestPasswordReset] call
// ran and returned BEFORE this call started — would otherwise stay
// redeemable AFTER the owner changed their password, taking the account
// right back for the remainder of the reset token's TTL.
//
// A still-valid "email_change" token is the STRONGER of the two, and
// sweeping only the reset one left the stronger door open: it lives
// [WithVerificationTTL]'s window (24h by default) rather than the reset
// token's [WithPasswordResetTTL] one (1h by default), and
// [Service.VerifyEmail] redeems it with NO authentication whatsoever,
// moving the address to the attacker's via [Store.UpdateUserEmail]. After
// that the victim cannot recover:
// [Service.Login] and [Service.RequestPasswordReset] both look accounts up
// BY email. [Service.RequestEmailChange] now requires the current password
// to mint one (see its doc, "Why this needs the current password"), so an
// attacker can no longer arm this from a stolen session alone — but a
// token armed BEFORE the credential leaked, or by the owner themselves
// before they suspected anything, is exactly what this sweep is for, and
// the whole point of a password change is that the old password may be in
// someone else's hands. Purpose-scoping the sweep is still right — an
// "email_change" token is not a "password_reset" token, and this method
// deliberately does not touch "signup" tokens, which grant nothing over
// the credential — but purpose-scoping was never a reason to leave a
// credential-rotation bypass armed.
//
// A still-valid "magic_link" token is the third door, and it is the most
// direct of the three: it does not let its holder SET a credential, it IS
// one. [Service.RedeemMagicLink] exchanges it for a live session with
// nothing else asked, so a link left armed hands the account back the
// moment this rotation finishes, for the remainder of [WithMagicLinkTTL]'s
// window. That window is the shortest of the three by default (fifteen
// minutes), which narrows the exposure but does not remove it: the user
// changing their password because they suspect a compromised mailbox is
// exactly the user whose pending link is already in the wrong hands.
//
// All three sweeps carry the SAME guarantee, and it is SEQUENTIAL ONLY: nothing
// orders either against a concurrently-running [Service.RequestPasswordReset]
// or [Service.RequestEmailChange] or [Service.RequestMagicLink] call. If
// that other call's own
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
func (s *Service) ChangePassword(ctx context.Context, userID, currentSessionID, current, next string) error {
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}
	// An ANONYMIZED account has no password to change and must not be given
	// one: arming a working credential on a stamped row would hand the
	// account back. Refused before the credential check, and with the same
	// ErrUserNotFound the load above returns for a row that is gone — see
	// [Service.AnonymizeAccount], "Every entry point that refuses a stamped
	// account".
	if u.DeletedAt != nil {
		return ErrUserNotFound
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

	// Close ALL THREE token side doors — see the method doc's point 6 and
	// "The sweep matrix". The email_change sweep is not a tidier variant of
	// the reset one, and the magic_link sweep is not a tidier variant of
	// either: each is a separate door, and shipping the fix for one of them
	// only is precisely the defect this matrix exists to prevent
	// recurring.
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, userID, PurposePasswordReset); err != nil {
		return err
	}
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, userID, PurposeEmailChange); err != nil {
		return err
	}
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, userID, PurposeMagicLink); err != nil {
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
//     row on the unknown branch to run either write against. The clock and
//     the configured id generator are pulled in by those same two writes
//     and so are branch-exclusive too; neither can fail, so neither adds
//     anything to point 3's error-set argument, but a caller-injected
//     [WithIDGenerator] with an observable side effect or its own cost (a
//     shared counter, an external ID service) would run only on the
//     known branch — the
//     default, internal/uid.NewV7, is a pure local computation and carries
//     no such risk.
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
//     nil), never propagated as ErrUserNotFound or anything else. An
//     ANONYMIZED account (a non-nil [UserBase.DeletedAt] — see
//     [Service.AnonymizeAccount]) is folded into that SAME branch rather
//     than given a refusal of its own, which is why no new error appears
//     in this method's set: a distinguishable answer there would tell an
//     anonymous caller that this address once had an account, which is
//     precisely the fact everything else in this method exists to withhold.
//     It takes the branch before point 1's two branch-exclusive writes, so
//     it costs the same as an unknown address as well as reading the same.
//
//  5. Timing is the channel that remains, and it is measured, not merely
//     theoretical. The harness that measures it is in the tree —
//     TestRequestPasswordResetTimingChannelLive in
//     [github.com/bernardoforcillo/authlayer/store/drops]'s integration
//     lane — so every figure below can be re-derived, and re-checked after
//     any change that touches this method:
//
//     AUTHLAYER_TEST_DSN=... go test -tags integration ./store/drops/ -run TimingChannel -v
//
//     It reports; it asserts no threshold, because absolute latencies are a
//     property of a machine and a flaky security test gets deleted.
//
//     What it measures, against a live PostgreSQL-backed [Store]: the known
//     branch is several times slower than the unknown one, and the two
//     distributions are DISJOINT at the known branch's 5th percentile
//     against the unknown branch's 95th — so on a quiet, same-host network
//     a single sample already separates them more often than not. Six runs
//     on one machine (Windows host, PostgreSQL in a container, loopback)
//     put the known-address median between 3.3ms and 8.7ms against an
//     unknown-address median between 0.5ms and 1.0ms: Δ≈2.8-8.0ms, roughly
//     5.5-12×. The disjointness held on every run; the absolute figures did
//     not, and a different machine will produce different ones — the ratio
//     and the disjointness are the durable findings, not the microseconds.
//     The unknown branch is the stable half; the known branch's spread is
//     write latency, which is whatever the host's storage stack is doing.
//     The same machine, running the same code on a different day, reported
//     known medians of 9.5-16.7ms; treat any absolute here as an order of
//     magnitude, not a figure.
//
//     What still makes a real deployment's channel WIDER than that is dead
//     tuples the server's autovacuum has not yet reclaimed: an early
//     version of the harness, vacuuming nothing, watched its own churn take
//     the known-address median from 6.3ms over 400 calls to 31.8ms over
//     1500 calls. TABLE SIZE no longer does.
//     [github.com/bernardoforcillo/authlayer/store/drops] indexes
//     verifications on (user_id, purpose), so the
//     DeleteVerificationsByUserAndPurpose in point 1 reads this user's own
//     rows instead of scanning every pending token the deployment is
//     holding for everybody. That was measured rather than assumed, in both
//     directions: seeding 40,000 other users' pending tokens moved the
//     known branch's floor from 2.3-2.5ms to 4.7-5.0ms WITHOUT the index
//     and left it at 2.4-2.8ms WITH it. A backend that omits the index —
//     any third-party [Store], or a deployment that owns these tables
//     through its own migrations — re-opens that growth term, which is why
//     the index is a security-relevant part of the schema and not only a
//     performance one.
//
//     Over realistic WAN jitter this needs on the order of 10² to 10³
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
func (s *Service) RequestPasswordReset(ctx context.Context, email, ip string) (string, bool, error) {
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
	// An ANONYMIZED account is not a known address: it takes the SAME
	// branch an unknown one takes, with the same calls and the same
	// ("", false, nil), rather than a new error. A distinguishable refusal
	// here would be exactly the enumeration oracle this method's whole
	// shape exists to close — see [Service.AnonymizeAccount], "Every entry
	// point that refuses a stamped account". u is the zero UserBase when
	// the lookup missed, so this is only ever consulted on the known path.
	if known && u.DeletedAt != nil {
		known = false
	}

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
		ExpiresAt: now.Add(s.cfg.passwordResetTTL),
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
// below), removing EVERY external identity linked to the account (see "Why an
// unauthenticated recovery sweeps identities" below — after a reset,
// connected accounts must be linked again), and revoking EVERY session the
// account has, on every device (see
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
// A token whose account has been ANONYMIZED (a non-nil
// [UserBase.DeletedAt]) is [ErrUserNotFound], also before the claim, and
// before the hashing: no working password may be set on an account no one
// may authenticate as. See [Service.AnonymizeAccount], "Every entry point
// that refuses a stamped account".
//
// # Ordering, and why it is not negotiable
//
// Exactly like [Service.VerifyEmail] — see that method's doc, "Ordering,
// and why it is not negotiable", for the incident this ordering is
// deliberately built not to repeat: an earlier
// [github.com/bernardoforcillo/authlayer/invite.Service.AcceptInvite]
// applied its effect before claiming its token, leaving a one-time
// credential redeemable by anyone who presented it while the effect was
// still being applied — this method claims the verification
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
// After [Store.UpdateUserPassword] succeeds, three
// [Store.DeleteVerificationsByUserAndPurpose] calls — one per purpose, all
// fail-closed — invalidate every OTHER outstanding "password_reset" token,
// every outstanding "email_change" token, AND every outstanding
// "magic_link" token for the same user. See [Service.ChangePassword]'s
// doc, "The sweep matrix", for the whole table these three rows belong
// to.
//
// The reset sweep: the token THIS call redeemed is already gone via the
// claim above, but a second, still-live token from an earlier
// [Service.RequestPasswordReset] call that already ran and returned BEFORE
// this call started is not, and would otherwise still grant a full password
// reset after this one already completed.
//
// The email_change sweep closes the stronger of the two doors, and sweeping
// only the reset one left it open: an "email_change" token lives
// [WithVerificationTTL]'s window (24h by default) rather than this token's
// [WithPasswordResetTTL] one (1h by default), and is redeemed by
// [Service.VerifyEmail] with NO authentication whatsoever — moving the
// account to the attacker's address, after which the victim cannot
// recover, since [Service.Login] and [Service.RequestPasswordReset] both
// look accounts up BY email. Minting one now takes the current password
// ([Service.RequestEmailChange]), so it can no longer be armed from a
// stolen session alone; a token armed before the credential leaked still
// can be, and a reset is a credential rotation most often performed
// precisely because the account may be compromised, so it must not leave
// that armed.
//
// # Why an unauthenticated recovery sweeps identities
//
// Every external identity on the account is removed too, via
// [IdentityStore.DeleteIdentity] — the connected Google, the connected
// GitHub, all of them — when the [Service] was built with
// [WithIdentityStore]. One with no identity store configured sweeps nothing
// and reports no error; see [Service.sweepIdentities] for that, and for the
// two-Services-one-users-table configuration it cannot cover.
//
// This method is UNAUTHENTICATED recovery. Whoever redeemed the token proved
// control of an address and NOTHING else — no password, no session, no
// device. It is therefore the one path in this package that must assume every
// other credential on the account is hostile, exactly as it already assumes
// every session is and revokes them all below.
//
// An external identity is such a credential, and it is the only one nothing
// else here can reach. Without the sweep the documented recovery did not
// recover: an attacker who provisioned an account holding the victim's
// address kept signing in through their identity after the victim had reset
// the password, logged in, and called [Service.LogoutAll] — every step the
// docs prescribe, with the account still not theirs at the end of it. The
// victim's own reset even certified the address on the way through, which
// unblocked [LinkVerified] for the attacker's later assertions.
//
// [Service.ChangePassword] deliberately does NOT sweep, and that asymmetry is
// the point rather than an oversight: its caller was ALREADY authenticated
// and is performing a routine action. Disconnecting somebody's Google because
// they rotated their password is UX-hostile and buys nothing. It mirrors the
// [Service.Logout] / [Service.LogoutAll] split this package already draws.
//
// # The consequence, stated plainly
//
// After a password reset, connected accounts must be linked again. A user who
// resets and then presses "Sign in with Google" is treated as an unknown
// (provider, subject): the ladder starts at the top, and rung 2 applies the
// [Linking] policy to whatever it finds at the asserted address — which, for
// an account this reset has just certified, means [LinkVerified] will link a
// verified assertion straight back. Tell the user that, or offer the link
// explicitly with [Service.LinkIdentity] after the reset.
//
// What the sweep does not do, said rather than implied: it removes links that
// EXIST. It cannot stop a provider that will keep asserting the address as
// verified from being linked again under [LinkVerified], because that is the
// trust this package's policy places in providers by configuration. Against
// such a provider no local action recovers anything; the remedy is
// [LinkNever], or not configuring it.
//
// The sweep runs BEFORE the session revocation below, not after. The order is
// what makes it worth anything: an identity left live while the revocation
// runs can mint a fresh session that the revocation has already passed,
// whereas removing it first means the revocation catches anything minted just
// before. TestResetPasswordSweepsIdentitiesBeforeSessions pins the order
// itself, since both orderings leave identical rows behind.
//
// The list and the deletes are separate calls, with the same SEQUENTIAL-ONLY
// scope the verification sweeps have.
//
// These are the same two side doors [Service.ChangePassword] closes for its
// The magic_link sweep closes the most direct door of the three. A magic
// link is not a step towards a credential, it IS one:
// [Service.RedeemMagicLink] exchanges it for a live session with nothing
// else asked of its holder. This method has just revoked every session the
// account had, precisely because whoever forced the reset may be holding
// one; a pending link left armed hands a fresh session straight back for
// the remainder of [WithMagicLinkTTL]'s window, and the mailbox it is
// sitting in is a plausible part of what went wrong in the first place.
//
// These are the same three side doors [Service.ChangePassword] closes for its
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
// # Why the revocation comes before the stamp
//
// Every session belonging to the verification's UserID is revoked — one
// [Store.DeleteSessionsByFamily] call per distinct family, the same "list,
// then delete per distinct family" shape [Service.LogoutAll] uses, so
// rotated-but-unexpired predecessor rows are swept too, not just each
// family's currently-live session — and that happens BEFORE the
// [Store.FindUserByID] read and [Store.MarkEmailVerified] stamp described
// above, not after.
//
// The order matters because the password write is already committed by
// this point. The stamp is a nicety: it exists so a deployment running
// [WithRequireVerifiedEmail](true) has a way out. The revocation is the
// security half of a reset — it is what takes the account back from
// whoever the user is resetting because of. Running the stamp first meant a
// FindUserByID or MarkEmailVerified failure returned an error with the
// credential rotated and every session, a thief's included, still
// refreshing: an optional step able to strand a mandatory one. Now a
// failure in the stamp leaves the reset's security guarantees fully in
// place and only the audit field unset.
//
// A Store, IdentityStore or Hasher error at any step is returned as-is — see
// the package's "Fail closed" constraint. In particular, a
// [Store.DeleteSessionsByFamily] or [IdentityStore.DeleteIdentity] failure
// partway through its loop is returned immediately, leaving whichever rows
// were already removed removed and the rest untouched — the caller sees a
// non-nil error either way and must not assume the reset "mostly worked".
//
// One configuration deserves naming, because it is the one case where a
// completed reset can leave an account it cannot immediately log in to. Under
// [WithRequireVerifiedEmail](true), an account whose address moved between
// the request and the redemption gets no stamp (see the two guards above),
// so it ends with a fresh password its own configuration will not accept and
// with its identities swept. It is recoverable, not lost: a reset requested
// for the account's CURRENT address certifies that one and restores the
// login.
func (s *Service) ResetPassword(ctx context.Context, plainToken, next string) error {
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

	// An ANONYMIZED account may not have a working password set on it,
	// however valid the token. This costs one read on every reset, and it
	// buys defence in depth rather than a reachable hole:
	// [Service.AnonymizeAccount] deletes every verification before it
	// stamps, so a token for a stamped account can only come from a route
	// this package does not own — but "cannot be reached today" is not a
	// property to build on, and the failure if it were reached is a live
	// credential on a closed account. Refused BEFORE the claim below, so
	// the token is not burned by a call that was never going to succeed.
	// See [Service.AnonymizeAccount], "Every entry point that refuses a
	// stamped account".
	if holder, herr := s.store.FindUserByID(ctx, v.UserID); herr != nil {
		return herr
	} else if holder.DeletedAt != nil {
		return ErrUserNotFound
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

	// Close ALL THREE token side doors — see the method doc above and
	// [Service.ChangePassword]'s "The sweep matrix". Each is a separate
	// door; sweeping a subset is the shape of the defect this matrix
	// exists to prevent recurring.
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, v.UserID, PurposePasswordReset); err != nil {
		return err
	}
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, v.UserID, PurposeEmailChange); err != nil {
		return err
	}
	if err := s.store.DeleteVerificationsByUserAndPurpose(ctx, v.UserID, PurposeMagicLink); err != nil {
		return err
	}

	// Remove every external identity BEFORE the sessions — see the method
	// doc's "Why an unauthenticated recovery sweeps identities". An identity
	// left standing is a live credential this rotation did not touch, and one
	// that can mint a fresh session; taking it away first means the session
	// revocation below also catches anything minted through it in the
	// meantime. A Service with no [WithIdentityStore] sweeps nothing and
	// reports no error.
	if err := s.sweepIdentities(ctx, v.UserID); err != nil {
		return err
	}

	// Revoke every session BEFORE the address stamp below — see the method
	// doc's "Why the revocation comes before the stamp". The credential is
	// already rotated and committed; nothing optional may run ahead of the
	// step that takes the account back.
	if err := s.revokeEverySession(ctx, v.UserID); err != nil {
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
	return nil
}

// RequestEmailChange mints an "email_change" [Verification] bound to
// newEmail for the already-authenticated user identified by userID, and
// returns its plaintext token — but only after current verifies against
// that account's existing password credential. Redeeming it — via
// [Service.VerifyEmail], which recognises [PurposeEmailChange] —
// overwrites the account's email to newEmail and marks that address
// verified; see VerifyEmail's own doc for the redemption side.
//
// # Why this needs the current password
//
// This method ARMS a rotation of the account's login identifier, and
// [Service.VerifyEmail] then redeems it with no authentication whatsoever.
// So it is held to the same standard as [Service.ChangePassword], which
// rotates the other credential and has always required the current
// password: an authenticated session alone is not enough to arm either one.
//
// Without this check the two rotations were asymmetric, and that asymmetry
// was itself the vulnerability. A briefly-held session — or a leaked
// access token, which per every revocation path's "What this does not
// revoke" section stays honoured for up to its own TTL even after
// [Service.LogoutAll] — bought an "email_change" token living
// [WithVerificationTTL]'s window (24h by default). Redeeming it moves the
// account to the attacker's address via [Store.UpdateUserEmail], after
// which the victim cannot recover: [Service.Login] and
// [Service.RequestPasswordReset] both look accounts up BY email. Requiring
// the password does not merely narrow that window; it removes the step
// change, because an attacker who has the password already owns the
// account by every other door too.
//
// The sweeps in [Service.ChangePassword], [Service.ResetPassword] and
// [Service.LogoutAll] contain an already-armed token; this check is what
// stops one being armed in the first place. Both halves are wanted: the
// sweeps still matter for a token the user armed themselves and then
// changed their mind about, or armed before a compromise they only later
// noticed.
//
// Unlike [Service.SignUp] and [Service.RequestPasswordReset], this method
// is not held to an enumeration-safety discipline: userID identifies an
// ALREADY-authenticated caller (an application calls this with the id from
// a caller's own validated access token, not with an id an anonymous
// prober supplies), so there is no unauthenticated audience this method
// needs to give nothing to. Accordingly it fails loudly and early rather
// than uniformly:
//
//  1. [Store.FindUserByID] loads userID; ErrUserNotFound propagates as-is
//     rather than being folded into some enumeration-safe shape — an
//     invalid userID here is a caller bug (a stale or forged id), not an
//     anonymous probe. An ANONYMIZED account (a non-nil
//     [UserBase.DeletedAt] — see [Service.AnonymizeAccount]) is refused
//     with the same ErrUserNotFound, before the credential check: this
//     method ARMS an identifier rotation, and redeeming what it mints
//     would call [Store.UpdateUserEmail] and put a real, deliverable
//     address back onto a scrubbed row.
//  2. current is checked against the stored hash, with the SAME timing
//     discipline [Service.ChangePassword] and [Service.Login] apply to
//     their own: an account holding no password credential at all
//     (PasswordHash == "" — see [UserBase]'s doc) runs
//     [password.Hasher.Dummy] and then returns [ErrInvalidCredentials],
//     so "this account cannot be verified against" costs the same as "the
//     password was simply wrong" and is reported identically. A mismatch
//     is ErrInvalidCredentials too; nothing is written, and newEmail is
//     never even normalized, so a caller who does not know the password
//     learns nothing about the address they proposed either — the same
//     stance ChangePassword takes on next.
//  3. newEmail is normalized (see [NormalizeEmail]) and, if that leaves it
//     empty — a literal "", or whitespace-only input — this returns
//     [ErrEmailRequired]. Without this, an empty newEmail minted a token
//     exactly like any other, and a successful redemption via
//     [Service.VerifyEmail] set [UserBase.Email] to "": reproduced
//     directly, this bricks the account — [Service.Login] and
//     [Service.RequestPasswordReset] both look accounts up BY email, so an
//     account with no email cannot be reached by either again. This was
//     this method's only input check before the guard above was added;
//     removing it (see the ErrEmailTaken discussion below, which removed
//     the OTHER check) would have left newEmail entirely unvalidated.
//  4. A fresh [Verification] is minted with Purpose [PurposeEmailChange]
//     and Email set to newEmail (never the account's OLD address — see
//     [Verification.Email]'s doc for why this field always carries the NEW
//     address for this purpose specifically), using the same
//     [WithVerificationTTL] window as a signup token.
//
// This method does NOT pre-check whether newEmail already belongs to a
// DIFFERENT user before minting — an earlier version did, returning
// [ErrEmailTaken] immediately. That check was removed: it turned this
// method into an un-rate-limited "is this address registered?" oracle for
// ANY authenticated caller — one signup buys unlimited queries against
// arbitrary addresses, with no [RateLimiter] of any kind gating it, unlike
// [Service.RequestPasswordReset]'s carefully-bounded equivalent. (The
// current-password check above narrows that oracle to a caller who also
// knows the account's password, but it was never the reason the pre-check
// had to go.) The pre-check was never the actual enforcement point:
// [Store.UpdateUserEmail] re-checks the identical condition atomically at
// REDEMPTION time regardless (see that method's doc), which is what
// genuinely closes the two-callers-racing-the-same-address race. Removing
// the pre-check costs a caller nothing but the timing of discovery: a
// request for an already-taken address still mints a token exactly like
// any other, and [Service.VerifyEmail] surfaces [ErrEmailTaken] at
// redemption instead — the one-time token is burned for nothing in that
// case, the same already-accepted cost [Service.VerifyEmail]'s "claims
// before applies" ordering imposes for every other doomed redemption.
// Requesting a change to the account's OWN current address is not an error
// either way: at redemption, [Store.UpdateUserEmail]'s uniqueness check
// excludes the caller's own row.
//
// A Store, Hasher or [token.GenerateOpaque] error at any step is returned
// as-is.
func (s *Service) RequestEmailChange(ctx context.Context, userID, current, newEmail string) (string, error) {
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	// An ANONYMIZED account may not arm an identifier rotation: redeeming
	// the token this would mint calls [Store.UpdateUserEmail], which would
	// move a real, deliverable address back onto a stamped row — undoing
	// the scrub and taking that address out of circulation again. See
	// [Service.AnonymizeAccount], "Every entry point that refuses a stamped
	// account".
	if u.DeletedAt != nil {
		return "", ErrUserNotFound
	}

	// The credential gate, before anything else this method could report —
	// see the method doc's "Why this needs the current password". This is
	// [Service.ChangePassword]'s check, verbatim, because arming an
	// identifier rotation is the same kind of act as rotating the password.
	if u.PasswordHash == "" {
		s.cfg.hasher.Dummy(current)
		return "", ErrInvalidCredentials
	}
	if !s.cfg.hasher.Verify(current, u.PasswordHash) {
		return "", ErrInvalidCredentials
	}

	normalized := NormalizeEmail(newEmail)
	if normalized == "" {
		return "", ErrEmailRequired
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
		ExpiresAt: now.Add(s.cfg.verificationTTL),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return plainToken, nil
}
