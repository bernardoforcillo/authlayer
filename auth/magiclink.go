package auth

import (
	"context"
)

// RequestMagicLink begins a passwordless sign-in for email: for an address
// this Service will issue a link to, it mints a "magic_link" [Verification]
// and returns (token, true, nil); otherwise it returns ("", false, nil) —
// deliberately never an error purely because the address is unregistered.
// "Will issue a link to" means a registered address by default, or ANY
// address when [WithMagicLinkProvisioning] is enabled, in which case an
// unrecognised address is registered first (see that option's doc for what
// enabling it exposes — it is not free).
//
// The CALLER carries the same obligation [Service.RequestPasswordReset]
// places on its own caller, for the same reason and word for word: whatever
// wraps this method MUST return a FIXED response, same status and body
// shape and rough latency, regardless of the outcome. ok exists to decide
// whether to actually send a sign-in email, never to shape an HTTP
// response, and neither does the returned token's presence. Surfacing
// either to an unauthenticated requester re-opens the existence oracle this
// method's entire shape exists to close, and it is the one thing this
// package cannot enforce from here.
//
// ip must be non-empty ([ErrMissingIP]) and, if a [RateLimiter] is
// configured via [WithRateLimiter], allows this ip ([ErrRateLimited]) —
// both checked before anything address-specific happens at all, the same
// ordering [Service.Login] and [Service.RequestPasswordReset] use. If
// [WithMagicLinkRateLimiter] is also configured, this method additionally
// consults it keyed by the normalized address; a denial from THAT limiter
// looks nothing like ErrRateLimited (point 2 below).
//
// # What this mints, and what a holder of it can do
//
// A "magic_link" token is a LOGIN CREDENTIAL, not an attestation: its
// holder exchanges it for a live session through [Service.RedeemMagicLink]
// with nothing else asked of them. That is why its default lifetime is the
// shortest of the four purposes ([WithMagicLinkTTL], fifteen minutes), why
// redemption burns it before issuing anything, and why every
// credential-rotation and remediation path in this package sweeps it — see
// [Service.ChangePassword]'s doc, "The sweep matrix", for the full table
// including the two methods that deliberately do NOT sweep it.
//
// Re-issue invalidates the previous link for the same account
// ([Store.DeleteVerificationsByUserAndPurpose], honouring that method's own
// documented contract), so at most one link per account is live at a time.
// That carries a griefing consequence identical to
// [Service.RequestPasswordReset]'s: anyone who merely knows an address can
// kill a victim's unclicked link by looping calls here.
// [WithMagicLinkRateLimiter] is what bounds it.
//
// # The enumeration property
//
// This method is held to exactly the discipline
// [Service.RequestPasswordReset]'s doc sets out under "The enumeration
// property, again" — read that method's numbered points for the full
// argument, including the [Service.SignUp] doc it inherits from. This
// section states only how each point lands here, and where this method's
// provisioning option changes the answer.
//
//  1. Identical calls, identical order, with disclosed exceptions. The ip
//     check, the IP [RateLimiter], email normalization, the address
//     [RateLimiter] (keyed by the normalized address whether or not it
//     identifies anyone — the limiter is never told which) and
//     [Store.FindUserByEmail] run in the SAME order on every call.
//     [token.GenerateOpaque] runs unconditionally too, right after the
//     lookup, whether or not its result is ever used.
//
//     The writes are branch-exclusive, because they need a real UserID to
//     run against: [Store.DeleteVerificationsByUserAndPurpose] and
//     [Store.CreateVerification], plus [Store.CreateUser] on the
//     provisioning branch only. The clock and the configured id generator
//     are pulled in by those same writes and so are branch-exclusive too;
//     the same caveat RequestPasswordReset records about a caller-injected
//     [WithIDGenerator] with an observable side effect applies unchanged.
//
//  2. Rate limiting by IP is a plain [ErrRateLimited], decided before any
//     address-specific behaviour runs. Rate limiting by ADDRESS is NOT: a
//     denial there returns ("", false, nil) — the exact shape an
//     unregistered address gets with provisioning off — never
//     ErrRateLimited, which would be an oracle reachable once enough
//     requests for THAT address have run. The denial is checked before the
//     branch it gates, so with provisioning ON it also creates no account.
//
//  3. The error sets are identical. Every call that runs on EVERY
//     invocation (the ip check, both limiters, FindUserByEmail) returns its
//     failure as-is: symmetric by construction. Every branch-exclusive
//     write's failure is instead FOLDED into the same ("", false, nil) —
//     CreateUser included. Surfacing any of them would be reachable on one
//     branch only, which is the "a store failure reachable on one branch
//     only is a binary oracle" trap. Masking them costs the caller a clean
//     signal that the store is unhealthy: a real, disclosed trade-off,
//     taken here for the same reason RequestPasswordReset takes it.
//
//  4. Never an error purely for an unknown address: with provisioning off
//     the ErrUserNotFound branch falls through to the same ("", false, nil)
//     every other deny path uses; with provisioning on there is no unknown
//     branch left to distinguish, since the address is registered and a
//     link is minted.
//
//     An ANONYMIZED account (a non-nil [UserBase.DeletedAt] — see
//     [Service.AnonymizeAccount]) is refused through this same shape and
//     for this same reason: ("", false, nil), never a new error. It is the
//     one refusal in this method that is about the ACCOUNT rather than the
//     address, and giving it its own error would hand an anonymous caller
//     a way to tell "anonymized" from "never registered" — the distinction
//     an existence oracle is made of. The check sits above the
//     provisioning branch, so a stamped account is not handed a fresh row
//     either, and no link is minted for it on any configuration.
//
//  5. Timing is the channel that remains, exactly as it does for
//     [Service.RequestPasswordReset] — see that method's point 5 for the
//     measured figures, the live harness that produces them, the
//     autovacuum and (user_id, purpose) index findings, and the symmetric
//     synthetic-row alternative this implementation deliberately does not
//     take. Everything there applies here unchanged, with ONE reversal
//     worth knowing: with [WithMagicLinkProvisioning] enabled the
//     UNKNOWN-address branch becomes the slower one (it performs an extra
//     [Store.CreateUser] the known branch never runs), so the sign of the
//     difference flips rather than disappearing. No figures for the
//     magic-link flow specifically have been measured on this machine, and
//     this doc will not quote the reset flow's numbers as though they had
//     been.
//
//     One asymmetry belongs to this method alone and is NOT closed by
//     point 3's fold. With provisioning ON and the users table
//     specifically failing writes while the verifications table stays
//     healthy, an unknown address returns ("", false, nil) — the fold —
//     while a known address still returns (token, true, nil). During such
//     an outage, and only then, the two branches are distinguishable. The
//     alternative — propagating CreateUser's error — is distinguishable
//     too, so the fold is the better of two imperfect options rather than
//     a complete answer, and it is recorded here rather than glossed.
//
// A [Store] error from a call that runs on every invocation is returned
// as-is; see the package's "Fail closed" constraint, and point 3 above for
// the deliberate, enumerated exceptions.
func (s *Service) RequestMagicLink(ctx context.Context, email, ip string) (string, bool, error) {
	if err := s.requireMethod(MethodMagicLink); err != nil {
		return "", false, err
	}
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
	// Everything address-specific, in the order the doc above argues for,
	// lives in the [magiclink] engine.
	engine, _ := s.magicEngine()
	return engine.Request(ctx, NormalizeEmail(email))
}

// RedeemMagicLink exchanges plainToken — a "magic_link" [Verification]
// minted by [Service.RequestMagicLink] — for a live session, and returns
// the same [LoginResult] [Service.Login] does: a scrubbed [UserBase], a
// signed access token and a refresh token. There is no PASSWORD step;
// presenting the token IS the first factor, which is what makes everything
// below the shape it is. It is not the second — an account owing one gets a
// challenge instead of a session, exactly as it does at Login; see "A link
// is a first factor, never a second" below.
//
// An unknown token is whatever [Store.FindVerificationByHash] reports
// (ErrVerificationNotFound). A known but expired token is
// [ErrVerificationExpired]. A token minted for any purpose OTHER than
// [PurposeMagicLink] is [ErrVerificationPurpose] — all three checked
// BEFORE the token is claimed, matching [Service.VerifyEmail] and
// [Service.ResetPassword]'s identical stance, so none of them burns the
// token. The purpose check is not bookkeeping: without it a
// "password_reset" token — which grants only the right to SET a password,
// through a flow that then revokes every session — would be exchangeable
// directly for a session here, turning a lower-privileged credential into
// an immediate account takeover.
//
// If the account is gone by redemption time, this is [ErrUserNotFound] —
// after the claim (see below), so the token is burned either way. That is
// the deliberate direction: under-granting, not leaving a claimed token
// redeemable.
//
// # A stamped account, and why this one refuses after the claim
//
// An ANONYMIZED account (a non-nil [UserBase.DeletedAt] — see
// [Service.AnonymizeAccount]) is refused with that same [ErrUserNotFound],
// and it is refused AFTER the claim rather than before it. That is the
// opposite of the choice [Service.ResetPassword] makes for its own stamped
// check, and the difference is what the token IS. A "password_reset" token
// grants the right to SET a credential, so refusing one before the claim
// leaves it for a legitimate redemption that a later un-stamping might
// permit; a "magic_link" token IS the credential, so a live one aimed at a
// closed account is a thing worth destroying, and destroying it on the way
// out costs nothing and needs no extra [Store.FindUserByID] to do it — the
// account is already loaded at that point.
//
// AnonymizeAccount deletes every verification before it stamps, so a token
// surviving to reach this check comes either from a request genuinely
// concurrent with that call or from a row written around this package.
// This is defence in depth, not the primary control.
//
// ip and userAgent are recorded on the new [Session] exactly as
// [Service.Login] records its own. Unlike Login, an EMPTY ip is not
// refused here: Login's [ErrMissingIP] exists because an empty ip collapses
// every caller into one shared [RateLimiter] bucket, and this method
// consults no limiter — [Service.RequestMagicLink] is the half of the pair
// that does, and it does refuse an empty ip. A caller that wants the audit
// field populated must pass it.
//
// # Claim before apply, and why it is not negotiable
//
// [Store.DeleteVerification] runs FIRST, before the user is even loaded,
// and its rows-affected gate is what makes exactly one of any number of
// concurrent redeemers see a nil error (see that method's contract on
// [Store]). Only then does anything get issued.
//
// The ordering is the whole reason two people clicking the same link do not
// both get in. Minting the session first and burning afterwards would leave
// a window in which a second presentation of the SAME token finds it still
// live and mints a second session — the identical defect
// [github.com/bernardoforcillo/authlayer/invite.Service.AcceptInvite]
// shipped and [Service.VerifyEmail]'s doc records under "Ordering, and why
// it is not negotiable". Here the consequence is sharper than there: the
// thing handed out is not an effect on a row, it is a working session, and
// a link forwarded, quoted in a reply, or read out of a shared mailbox is
// exactly how a second presentation happens without an attacker doing
// anything clever.
//
// Everything that CAN be checked before commitment therefore happens before
// it — expiry, purpose — and everything after the claim is a step whose
// failure costs the caller a burned token and no session. There is nothing
// left to validate after the burn.
//
// # Why a redemption verifies the address
//
// A magic link is only ever deliverable to the address it was minted for,
// so redeeming one IS proof of control of that address — the same argument
// that makes [Service.ResetPassword] stamp, arriving through a different
// door. A successful redemption therefore sets [UserBase.EmailVerifiedAt]
// via [Store.MarkEmailVerified] when it is not already set, with the same
// two guards ResetPassword applies, for the same reasons:
//
//   - Already verified: EmailVerifiedAt is left exactly as it was.
//     MarkEmailVerified would happily re-stamp it to now, but that field
//     records WHEN control was first proven, and a routine sign-in must
//     not move an audit value forward.
//   - A different address: the proof is about [Verification.Email], the
//     address the link was DELIVERED to, not whatever the row holds at
//     redemption time. If the account's address changed in between (and
//     was left unverified, as [Store.UpdateUserEmail] leaves it), nothing
//     is stamped — the sign-in still succeeds and certifies nothing.
//
// As in ResetPassword, the read and the stamp are two calls rather than one
// atomic step, and that is safe for the same reason: MarkEmailVerified
// re-checks the address against the row's CURRENT value atomically and
// returns ErrEmailMismatch rather than certifying an address nobody proved
// control of. The two guards are an optimization of intent; the Store is
// the enforcement point.
//
// The returned [LoginResult].User carries the stamp this call just wrote,
// rather than the pre-stamp value read a line earlier — a caller must not
// be told the address is unverified by the very call that verified it.
//
// This method does NOT consult [WithRequireVerifiedEmail]. That option
// exists to demand proof of address control before a login is honoured,
// and a redemption IS that proof: the link had to be received at the
// account's address to be presented at all, and the stamp above records it.
// Refusing here would mean refusing the one flow that can satisfy the
// requirement.
//
// # A link is a first factor, never a second
//
// An account holding a CONFIRMED [MFAFactor] does NOT get a session here.
// This method returns a [LoginResult] whose AccessToken and RefreshToken
// are EMPTY and whose MFA field carries a short-lived [MFAChallenge], with
// a nil error and no [Session] row created — the identical pending state
// [Service.Login] returns, finished the identical way through
// [Service.CompleteMFA]. Under [EnforcementRequired] an account with NO
// confirmed factor is refused outright with [ErrMFARequired].
//
// The reason is that this package delivers a password reset to the same
// mailbox. A link proves control of that mailbox — that is exactly what the
// stamp above records — so counting it as the SECOND factor would mean one
// compromised inbox both resets the password and satisfies the factor
// guarding it. auth/mfa_service.go's package doc, "What the second factor
// gates, door by door", carries the full argument and the matrix for the
// other three doors.
//
// The check runs AFTER the claim, deliberately, and that ordering is the
// same single-use property the section below defends: were it checked
// before, two people presenting one link would each receive a challenge,
// and one link would finish as two sessions. Claimed first, exactly one
// caller reaches the challenge, and the link is spent whether or not they
// go on to present a code. A user who cannot produce one must request
// another link — the same cost as any other post-claim refusal here.
//
// It also runs after the address stamp above, which matters:
// [Service.CompleteMFA] enforces [WithRequireVerifiedEmail] itself, so
// under that option a link that certifies the account's current address
// must stamp BEFORE the challenge is minted or the completion refuses the
// challenge this call just handed out. (A link whose address no longer
// matches the account's stamps nothing — see the two guards above — and
// under that option its challenge is indeed unfinishable; that is the same
// refusal such an account already meets at [Service.Login], not one this
// ordering introduces.)
//
// # What redemption does not touch
//
// Only the presented token is claimed. Other outstanding verifications for
// the account — including a pending "password_reset" or "email_change" —
// survive, and so does every existing session: signing in on a new device
// is not a revocation event. See [Service.ChangePassword]'s doc, "The sweep
// matrix", for the methods that DO sweep magic links and why these are not
// among them.
//
// A Store or [token.Issue] error at any step is returned as-is — see the
// package's "Fail closed" constraint. After the claim has succeeded, such a
// failure leaves the link burned and no session issued: the caller must
// request another link. This is the same accepted, disclosed trade-off
// [Service.ResetPassword] makes for its own post-claim steps.
func (s *Service) RedeemMagicLink(ctx context.Context, plainToken, ip, userAgent string) (LoginResult, error) {
	if err := s.requireMethod(MethodMagicLink); err != nil {
		return LoginResult{}, err
	}
	var zero LoginResult

	// Claim, expiry, purpose, burn-before-use, anonymized-account refusal
	// and the address verification all live in the [magiclink] engine.
	engine, backend := s.magicEngine()
	if _, err := engine.Redeem(ctx, plainToken); err != nil {
		return zero, mapMagicErr(err)
	}
	u := backend.user
	if backend.verified != nil {
		// Reflect the stamp in the record this call hands back, rather
		// than returning the stale pre-stamp value read a moment ago.
		u.EmailVerifiedAt = backend.verified
		u.UpdatedAt = *backend.verified
	}

	// [MagicLinkRedeemed]: the link is burned and the account has passed
	// every check. Before the second factor, so it is followed by either
	// [MFAChallenged] or [LoggedIn] — the redemption happened either way.
	if err := s.emit(ctx, Event{Kind: MagicLinkRedeemed, UserID: u.ID, IP: ip, UserAgent: userAgent}); err != nil {
		return zero, err
	}

	// The second factor, consulted last — this door's OWN call to
	// mfaAtSignIn. A confirmed factor short-circuits the mint and hands back
	// a challenge with EMPTY tokens; see the method doc's "A link is a first
	// factor, never a second".
	challenge, err := s.mfaAtSignIn(ctx, u)
	if err != nil {
		return zero, err
	}
	if challenge != nil {
		// Not mintSession: no session row or tokens. PasswordHash is
		// scrubbed here because this success path skips the scrub there.
		u.PasswordHash = ""
		if err := s.emit(ctx, Event{Kind: MFAChallenged, UserID: u.ID, IP: ip, UserAgent: userAgent}); err != nil {
			return zero, err
		}
		return LoginResult{User: u, MFA: challenge}, nil
	}

	// One minting path, shared with [Service.Login]. The nil is
	// [Session.MFAAt]: a link is not a second factor.
	return s.mintSession(ctx, u, ip, userAgent, nil, DetailMagicLink)
}
