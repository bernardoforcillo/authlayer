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
// and link deliberately with [Service.LinkIdentity], which this policy
// does NOT gate — see that method's doc for why the remedy cannot be
// gated by the rule that produced the refusal.
//
// A [SignInRequest.FallbackEmail] is NEVER treated as verified, whatever
// Identity.EmailVerified says. That flag is the provider's claim about the
// address the provider returned; when it returned none, the claim is about
// nothing, and crediting it to an address the application supplied would let
// a verification of some entirely different address stand in for one of the
// victim's.
//
// # Why [WithRequireVerifiedEmail] does not apply here
//
// That option gates [Service.Login] and is deliberately NOT honoured by this
// method. The asymmetry is not an oversight; it follows from what the
// address MEANS on each path.
//
// In a password login the address IS the claim: it is the identifier the
// user is asserting they hold, and an unverified one proves nothing about
// whether they hold it — the option exists so that someone who signed up
// with somebody else's address cannot use the account before the real owner
// notices. Here the account is identified by (Provider, Subject), which the
// provider actually authenticated. The address is corroborating detail, not
// the claim being made.
//
// Both rungs it could apply to are already covered, and more strictly:
//
//   - On the LINK rung, [LinkVerified] already requires the local account to
//     be verified — strictly stronger than this option, since it demands the
//     provider's half as well. [LinkAlways] is a deliberate opt-out of
//     exactly that check, and re-imposing half of it through a second option
//     would make the policy a caller chose mean something they did not choose.
//   - On the PROVISIONING rung the address lookup MISSED. No other account
//     holds that address, so there is nobody to take over from; the account
//     being created is the first claim on it, and refusing to create it
//     protects no one.
//
// What remains is a real if narrow inconsistency, stated plainly: an
// application that sets WithRequireVerifiedEmail(true) can still end up with
// an active, unverified account — provisioned here when the provider
// reports the address unverified. That account holds no password, so it can
// never reach Login's check at all (Login refuses an empty PasswordHash
// first). The remedy available today is to configure only providers that
// report verification status honestly, and to map a provider that does not
// report it to false. TestSignInWithIgnoresRequireVerifiedEmail pins both
// halves of this so it cannot drift into an accident.
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

// LinkIdentity attaches an external account to a local one DELIBERATELY:
// the application has already authenticated userID by some other means, ran
// the provider's dance, and is now recording the result. It mints no
// session and authenticates nobody — the caller supplies the account, and
// this method takes that as given.
//
// It requires [WithIdentityStore]; without it the call fails with
// [ErrOAuthNotConfigured] before anything is read or written.
//
// # It is not gated by the [Linking] policy, on purpose
//
// [WithLinking] governs the IMPLICIT link inside [Service.SignInWith] — the
// one decided on nothing but a matching email address, where the policy is
// the only thing standing between a provider's assertion and somebody
// else's account. Here the trust basis is different in kind: the
// application has authenticated the user, and is attaching an identity to
// the account that user just proved they hold.
//
// So [LinkNever] does NOT disable this method, and [LinkVerified] does not
// require either side to be verified here. That matters because this method
// is the documented remedy for [ErrLinkRequiresVerification]: an
// application that hits that refusal is meant to re-authenticate the user
// and call this. If the policy that produced the refusal also blocked the
// remedy, the error would be a dead end — and under LinkNever, which
// produces it most often, there would be no way to link an identity at all.
//
// # What it refuses
//
//   - The (Provider, Subject) pair is already linked to a DIFFERENT user:
//     [ErrIdentityLinked], and nothing is written. An existing link is never
//     re-pointed. Re-pointing would let anyone able to authenticate as
//     themselves claim a subject that then signs in as the victim, which is
//     the same end state as forging the victim's password.
//   - userID names no account: [ErrUserNotFound]. The account is read before
//     the link is written, so a row is never left dangling — pointing at a
//     user that does not exist, occupying a (Provider, Subject) pair nobody
//     can then use, and failing every sign-in that resolves it.
//
// Already linked to THIS user is not a refusal: the existing [Identity] is
// returned unchanged with a nil error, so a retried or repeated call is a
// no-op. "Unchanged" is the operative word — CreatedAt, LastUsedAt and Email
// keep recording what happened when the link was actually made, rather than
// being rewritten from today's assertion.
//
// # What it records
//
// [Identity.Email] is set to what the PROVIDER asserted, normalized. It is
// an audit and display field: it may legitimately differ from
// [UserBase.Email], it is never an authentication input once the link
// exists, and nothing here copies it onto the account. Linking likewise
// certifies nothing about the local address — [UserBase.EmailVerifiedAt] is
// untouched on every path.
//
// [Identity.LastUsedAt] is left nil, because no sign-in has happened. The
// sign-in paths stamp it at creation for exactly this reason: nil then means
// "this link has never signed the user in", which is a fact an application
// can act on, rather than an artifact of which code path created the row.
//
// # What is not atomic here
//
// The same cross-store reality [Service.SignInWith] documents applies, in a
// smaller form. The user read, the (Provider, Subject) lookup and the write
// are three steps, and [Store] and [IdentityStore] may be different backends
// with no transaction spanning them. Two concurrent links of the same pair
// can both pass the lookup; the loser is failed by
// [IdentityStore.CreateIdentity]'s (provider, subject) uniqueness with
// [ErrIdentityLinked], which is propagated rather than retried into a link —
// a retry would attach an external account somebody else just claimed. A
// user deleted between the read and the write is the residual window, and it
// leaves the same dangling row [Service.SignInWith] fails closed on.
func (s *Service) LinkIdentity(ctx context.Context, userID string, ext ExternalIdentity) (Identity, error) {
	var zero Identity

	identities, err := s.identities()
	if err != nil {
		return zero, err
	}

	// The account is read FIRST: nothing is ever linked to a user that does
	// not exist, not even idempotently.
	if _, err := s.store.FindUserByID(ctx, userID); err != nil {
		return zero, err
	}

	existing, err := identities.FindIdentityByProviderSubject(ctx, ext.Provider, ext.Subject)
	switch {
	case err == nil:
		if existing.UserID != userID {
			return zero, ErrIdentityLinked
		}
		// Already this user's. Hand back what is stored, untouched.
		return existing, nil
	case !errors.Is(err, ErrIdentityNotFound):
		// Fail closed: a store that could not answer is not a store that
		// answered "nobody holds this pair".
		return zero, err
	}

	return identities.CreateIdentity(ctx, Identity{
		ID:        s.cfg.idGen(),
		UserID:    userID,
		Provider:  ext.Provider,
		Subject:   ext.Subject,
		Email:     NormalizeEmail(ext.Email),
		CreatedAt: s.cfg.clock(),
		// LastUsedAt stays nil: this link was made without a sign-in, and
		// nil is how a caller tells the two apart.
	})
}

// UnlinkIdentity removes userID's identities at provider — every row for
// that pair, since nothing in the data model forbids a user holding two
// identities at the same provider and "unlink this provider" means all of
// them.
//
// It requires [WithIdentityStore]; without it the call fails with
// [ErrOAuthNotConfigured].
//
// It refuses to remove the account's last way in: with no other identity
// surviving the delete and no password credential, the call fails with
// [ErrLastCredential] and removes NOTHING. That is not a formality. An
// account with no identity and no password cannot be authenticated by
// anything in this package — not by [Service.Login], which refuses an empty
// PasswordHash, and not by [Service.SignInWith], which has no link left to
// resolve. The lockout would be permanent. [ErrIdentityNotFound] means
// there was nothing to unlink at that provider, which is a different answer
// an application's connected-accounts screen acts on differently.
//
// The decision and the delete happen inside
// [IdentityStore.DeleteIdentityIfNotLast] as ONE atomic step, which is why
// that method has the shape it does — see its doc for the read-then-write
// race that a "list, decide, delete" here would reopen, and that this
// project has shipped four times elsewhere.
//
// # Why the password state is read here and passed in
//
// The identity store owns `identities` and cannot see `users`, so this
// method reads the account and hands the answer down. [IdentityStore]'s own
// doc argues why that value cannot go stale in the dangerous direction: no
// [Service] method removes a password (both writers store a freshly hashed,
// non-empty value, and there is no "remove my password" and no account
// deletion in this package), so a true observed here cannot become a false
// under the delete. The other direction merely refuses a delete that would
// have been safe, which is self-correcting on retry.
//
// That argument depends on the read being FRESH and being the account's real
// state. It is performed on every call rather than cached, and the flag is
// derived from the stored [UserBase.PasswordHash] rather than assumed —
// passing a constant true would be exactly the lockout above, wearing a
// successful return.
func (s *Service) UnlinkIdentity(ctx context.Context, userID, provider string) error {
	identities, err := s.identities()
	if err != nil {
		return err
	}

	// Read the credential state fresh, immediately before the delete: see
	// "Why the password state is read here and passed in", and
	// [IdentityStore.DeleteIdentityIfNotLast]'s own staleness argument,
	// which this ordering is what makes true.
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}

	return identities.DeleteIdentityIfNotLast(ctx, userID, provider, u.PasswordHash != "")
}

// ListIdentities returns the external accounts linked to userID, and only
// that user's — it is a scoped pass-through to
// [IdentityStore.ListIdentitiesByUser], never a listing of anyone else's
// rows. An application renders it as a connected-accounts screen.
//
// It requires [WithIdentityStore]; without it the call fails with
// [ErrOAuthNotConfigured].
//
// A user with no linked accounts is not an error, and neither is a userID
// that names no account: both come back empty, which keeps this from
// answering "does this account exist?" for a caller who should not be asking.
// A store failure IS an error and is returned as-is — an empty list is a
// statement an application acts on, so an outage must not be able to make
// one. Whether "none" arrives as an empty or a nil slice is the port's
// business and deliberately unspecified: use len().
//
// Each [Identity.Email] is what the provider asserted at link time. It is an
// audit and display field, may differ from [UserBase.Email], and is never an
// authentication input.
func (s *Service) ListIdentities(ctx context.Context, userID string) ([]Identity, error) {
	identities, err := s.identities()
	if err != nil {
		return nil, err
	}
	return identities.ListIdentitiesByUser(ctx, userID)
}
