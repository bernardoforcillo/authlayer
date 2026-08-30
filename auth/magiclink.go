package auth

import (
	"context"
	"errors"

	"github.com/bernardoforcillo/authlayer/token"
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
	if s.cfg.magicLinkLimiter != nil {
		allowed, err := s.cfg.magicLinkLimiter.Allow(ctx, normalized)
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
	// the method doc's "The enumeration property", point 1.
	plainToken, tokenHash, gerr := token.GenerateOpaque()
	if gerr != nil {
		return "", false, gerr
	}

	// The address-keyed denial is answered here, BEFORE the provisioning
	// branch below, so a denied request creates no account — see
	// [WithMagicLinkRateLimiter] and the method doc's point 2.
	if !addressAllowed {
		return "", false, nil
	}

	now := s.cfg.clock()

	if !known {
		if !s.cfg.magicLinkProvisioning {
			return "", false, nil
		}
		// Provisioning: bring the account into existence, with NO password
		// credential and an unset EmailVerifiedAt — asking for a link
		// proves nothing about the address; only redeeming one does (see
		// [Service.RedeemMagicLink]). See [WithMagicLinkProvisioning] for
		// what enabling this exposes.
		created, cerr := s.store.CreateUser(ctx, UserBase{
			ID:        s.cfg.idGen(),
			Email:     normalized,
			CreatedAt: now,
			UpdatedAt: now,
		})
		if cerr != nil {
			// See the method doc, point 3: a failure reachable ONLY on this
			// branch must not be surfaced as a distinguishable error.
			return "", false, nil
		}
		u = created
	}

	// From here on both branches run the identical mint sequence against a
	// real user row.

	// Invalidate any earlier "magic_link" token for this user before
	// minting the new one — honouring [Store.DeleteVerificationsByUserAndPurpose]'s
	// own documented contract, and keeping at most one live link per
	// account. Purpose-scoped: a pending "signup", "email_change" or
	// "password_reset" token is none of this method's business.
	if derr := s.store.DeleteVerificationsByUserAndPurpose(ctx, u.ID, PurposeMagicLink); derr != nil {
		// See point 3: a failure reachable ONLY on this branch must not be
		// surfaced as a distinguishable error.
		return "", false, nil
	}

	if _, cerr := s.store.CreateVerification(ctx, Verification{
		ID:        s.cfg.idGen(),
		UserID:    u.ID,
		TokenHash: tokenHash,
		Purpose:   PurposeMagicLink,
		Email:     u.Email,
		ExpiresAt: now.Add(s.cfg.magicLinkTTL),
		CreatedAt: now,
	}); cerr != nil {
		// See the method doc, point 3.
		return "", false, nil
	}

	return plainToken, true, nil
}
