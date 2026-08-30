package auth

import (
	"context"
	"errors"
)

// SignInWith signs a user in from an external provider's assertion, and is
// the only method in this package that can create an account without a
// password. The application runs the OAuth/OIDC dance itself and hands the
// validated result here as a [SignInRequest] — this package never talks to a
// provider (see auth/identity.go's package doc for that boundary and for why
// no provider token is stored).
//
// It requires [WithIdentityStore]; without it every call fails with
// [ErrOAuthNotConfigured] before anything is read or written.
//
// # The resolution ladder
//
// The whole method is two rungs, tried strictly in this order:
//
//  1. [IdentityStore.FindIdentityByProviderSubject] on
//     (Identity.Provider, Identity.Subject). A hit IS the account: its user
//     is signed in, [IdentityStore.TouchIdentity] stamps the use, and
//     Created is false.
//  2. On a miss, the ADDRESS decides — Identity.Email, or
//     [SignInRequest.FallbackEmail] when the provider returned none, both
//     normalized ([NormalizeEmail]). With neither present the call fails
//     with [ErrEmailRequired] having written nothing: users.email is unique,
//     so provisioning on an empty address would create the one row every
//     later address-less sign-in then collides with.
//     - No local account at that address: PROVISION one, with an empty
//     PasswordHash and EmailVerifiedAt set only if the provider asserted
//     the address verified. Created is true.
//     - A local account exists: LINK to it only if the configured [Linking]
//     policy allows, otherwise [ErrLinkRequiresVerification]. Created is
//     false.
//
// # Why the subject rung comes first
//
// The order is not an optimization; reversing it is a vulnerability, and it
// costs the same number of queries either way.
//
// The subject is the provider's stable, opaque identifier for the external
// account. The email is a mutable attribute OF that account. Resolving by
// subject first means a user who changes their address at the provider still
// lands on the same local account, rather than being silently split into a
// second one. That is the usability half.
//
// The security half is the same fact from the other side. If the address
// were consulted first, an established link would resolve to whichever local
// account the provider's CURRENT email field happens to name — so an
// attacker who can make a provider assert a victim's address (see [Linking],
// "The attack this exists to stop") would re-route an identity they already
// control onto the victim's account, and rung 1's guarantee that a link
// means one specific account would be worth nothing. With the subject first,
// an already-linked identity never consults the address at all: nothing a
// provider says about email can move it.
//
// This method therefore never writes Identity.Email or [UserBase.Email] from
// a later assertion. Both record what was true at link time; treat a
// divergence as information, never as authority.
//
// # What the linking policy is deciding
//
// Only the IMPLICIT link on rung 2 — an unknown external account whose
// address already belongs to someone here. [LinkVerified], the default,
// requires BOTH that the provider asserted the address verified AND that the
// local account's own email is already verified, because each half alone is
// forgeable by exactly the route the other closes:
//
//   - Without the provider half, anyone who can register a victim's address
//     at a provider that does not verify addresses signs in as the victim,
//     having never learned the password.
//   - Without the local half, an attacker signs up locally with an address
//     they do not own and waits; when the real owner arrives through a
//     provider that genuinely verified it, their identity is attached to the
//     ATTACKER's account — one the attacker still holds the password to.
//
// [ErrLinkRequiresVerification] is a "not like this", not a dead end: the
// remedy is for the application to authenticate the user by some other means
// and link deliberately.
//
// A [SignInRequest.FallbackEmail] is NEVER treated as verified, whatever
// Identity.EmailVerified says. That flag is the provider's claim about the
// address the provider returned; when it returned none, the claim is about
// nothing, and crediting it to an address the application supplied would let
// a verification of some entirely different address stand in for one of the
// victim's.
//
// # Fail closed
//
// Every store error is returned as-is and no session is minted. In
// particular an [IdentityStore.FindIdentityByProviderSubject] failure is
// NOT read as "no such identity" — folding it into a miss would demote every
// sign-in to rung 2 for the duration of an outage, letting the address
// decide accounts that an existing link already decided. An identity row
// naming a user that no longer exists fails with [ErrUserNotFound] rather
// than provisioning a replacement.
//
// [IdentityStore.TouchIdentity] is called BEFORE the session is minted for
// the same reason: a use this package cannot record is one it does not
// perform. The reverse ordering — mint, then touch — could hand out a live
// session and then report an error.
//
// # What is not atomic here, and why
//
// Rung 1's lookup and rung 2's write are two steps, and two sign-ins for the
// same new external account can both pass the lookup. That window is closed
// where it can be: by [IdentityStore.CreateIdentity]'s (provider, subject)
// uniqueness, which fails the loser with [ErrIdentityLinked], and by
// [Store.CreateUser]'s address uniqueness, which fails a concurrent
// provisioning with [ErrEmailTaken]. Both are propagated, never retried into
// a link — a retry would apply the ladder from the top, where the policy is
// enforced, whereas "it exists now, so link to it" would skip the policy for
// precisely the caller who lost the race. A retry from the application
// re-enters the ladder at the top, which is the correct outcome either way:
// where the race was over the same external account, rung 1 now resolves it
// directly; where it was over the address alone, rung 2 applies the policy
// to whichever account won.
//
// One window cannot be closed from here: the linking decision reads the
// local account and then writes the identity, and [Store] and [IdentityStore]
// may be different backends with no transaction spanning them (that is the
// point of the split port — see [IdentityStore]'s doc). A concurrent
// [Store.UpdateUserEmail] landing in between can therefore leave a link
// decided on an EmailVerifiedAt the account no longer has. The decision was
// correct as of the read, the address changed under it rather than the
// authorization being forged, and closing it would require a transaction the
// port deliberately does not offer.
//
// SignInResult.User never carries a live PasswordHash — see
// [UserBase.PasswordHash]. Note that an account provisioned here has no
// password credential AT ALL, not merely a scrubbed one: [Service.Login]
// refuses it (the empty string is not its password — see Login's "Order of
// checks", point 3), [Service.ChangePassword] cannot help (it needs a
// current password), and the only route to a first password is
// [Service.RequestPasswordReset] followed by [Service.ResetPassword].
func (s *Service) SignInWith(ctx context.Context, req SignInRequest) (SignInResult, error) {
	var zero SignInResult

	identities, err := s.identities()
	if err != nil {
		return zero, err
	}

	ext := req.Identity

	// Rung 1 — the (provider, subject) pair. See "Why the subject rung
	// comes first": this must stay above the address resolution below.
	linked, err := identities.FindIdentityByProviderSubject(ctx, ext.Provider, ext.Subject)
	switch {
	case err == nil:
		return s.signInLinkedIdentity(ctx, identities, linked, req)
	case !errors.Is(err, ErrIdentityNotFound):
		// Fail closed: a store that could not answer is not a store that
		// answered "no".
		return zero, err
	}

	// Rung 2 — the address. providerAsserted records WHOSE address this is,
	// which is what decides whether EmailVerified means anything.
	email := NormalizeEmail(ext.Email)
	providerAsserted := email != ""
	if !providerAsserted {
		email = NormalizeEmail(req.FallbackEmail)
	}
	if email == "" {
		return zero, ErrEmailRequired
	}
	// A fallback address is unverified by construction — see the method
	// doc. This conjunction is the only place EmailVerified is read.
	providerVerified := ext.EmailVerified && providerAsserted

	now := s.cfg.clock()

	u, err := s.store.FindUserByEmail(ctx, email)
	created := false
	switch {
	case errors.Is(err, ErrUserNotFound):
		newUser := UserBase{
			ID:        s.cfg.idGen(),
			Email:     email,
			CreatedAt: now,
			UpdatedAt: now,
			// PasswordHash is deliberately left empty: this account has no
			// password credential, and none can be invented here.
		}
		if providerVerified {
			verifiedAt := now
			newUser.EmailVerifiedAt = &verifiedAt
		}
		if u, err = s.store.CreateUser(ctx, newUser); err != nil {
			// Including ErrEmailTaken, which means a concurrent sign-in
			// provisioned this address first — see "What is not atomic
			// here". Propagated rather than resolved into a link, so the
			// policy is never skipped.
			return zero, err
		}
		created = true
	case err != nil:
		return zero, err
	default:
		if !s.mayLink(providerVerified, u) {
			return zero, ErrLinkRequiresVerification
		}
		// Linking certifies nothing about the local address: EmailVerifiedAt
		// is left exactly as it was, on every policy.
	}

	lastUsed := now
	if _, err := identities.CreateIdentity(ctx, Identity{
		ID:       s.cfg.idGen(),
		UserID:   u.ID,
		Provider: ext.Provider,
		Subject:  ext.Subject,
		// What the PROVIDER asserted, which is empty when it asserted
		// nothing — see [Identity.Email]. A FallbackEmail is the
		// application's value and belongs on the user row this call may have
		// just written it to, not in an audit field that claims to record a
		// provider's statement.
		Email:     NormalizeEmail(ext.Email),
		CreatedAt: now,
		// This link was created BY a sign-in, so it has been used: stamping
		// it at creation keeps [Identity.LastUsedAt]'s "nil means it never
		// signed the user in" true. A link made without a sign-in leaves it
		// nil.
		LastUsedAt: &lastUsed,
	}); err != nil {
		return zero, err
	}

	minted, err := s.mintSession(ctx, u, req.IP, req.UserAgent)
	if err != nil {
		return zero, err
	}
	return SignInResult{
		Created:      created,
		User:         minted.User,
		AccessToken:  minted.AccessToken,
		RefreshToken: minted.RefreshToken,
	}, nil
}

// signInLinkedIdentity is rung 1's tail: the external account is already
// linked, so linked.UserID names the account outright and no address is
// consulted at all — that is the property "Why the subject rung comes first"
// describes.
//
// The order is load-bearing. The user is loaded first (a row naming a user
// that no longer exists fails with ErrUserNotFound rather than resurrecting
// the account from the provider's asserted address), then the use is
// recorded, and only then is a session minted — so a store that cannot
// record the use issues nothing. A failure in the mint AFTER the touch
// leaves LastUsedAt stamped for a sign-in that did not complete; that is an
// audit field erring toward over-reporting, which is the safe direction for
// it and the only one available without a transaction across two ports.
func (s *Service) signInLinkedIdentity(ctx context.Context, identities IdentityStore, linked Identity, req SignInRequest) (SignInResult, error) {
	var zero SignInResult

	u, err := s.store.FindUserByID(ctx, linked.UserID)
	if err != nil {
		return zero, err
	}
	if err := identities.TouchIdentity(ctx, linked.ID, s.cfg.clock()); err != nil {
		return zero, err
	}

	minted, err := s.mintSession(ctx, u, req.IP, req.UserAgent)
	if err != nil {
		return zero, err
	}
	return SignInResult{
		Created:      false,
		User:         minted.User,
		AccessToken:  minted.AccessToken,
		RefreshToken: minted.RefreshToken,
	}, nil
}

// mayLink applies the configured [Linking] policy to rung 2's
// existing-account case: may this external identity be attached to u
// implicitly, on the strength of a matching address?
//
// providerVerified is NOT ext.EmailVerified — it is that flag AND the fact
// that the address being matched is one the provider actually returned, so a
// [SignInRequest.FallbackEmail] can never inherit a verification. See
// [Service.SignInWith]'s doc.
//
// The default branch is unreachable: [WithLinking] panics at construction on
// any mode outside the three constants. It denies anyway, because the one
// thing a policy switch must never do is fall through to "allow" for a value
// nobody anticipated.
func (s *Service) mayLink(providerVerified bool, u UserBase) bool {
	switch s.cfg.linking {
	case LinkVerified:
		// BOTH halves, and each one closes an attack the other does not —
		// see [Service.SignInWith]'s "What the linking policy is deciding".
		return providerVerified && u.EmailVerifiedAt != nil
	case LinkNever:
		return false
	case LinkAlways:
		return true
	default:
		return false
	}
}
