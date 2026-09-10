package auth

import (
	"context"
	"errors"
	"strings"
)

// requireProviderSubject rejects an [ExternalIdentity] whose Provider or
// Subject is blank — empty, or nothing but whitespace — with
// [ErrProviderSubjectRequired].
//
// It is one function called from both [Service.SignInWith] and
// [Service.LinkIdentity] rather than two inline checks, because those are
// the only two entry points that accept an ExternalIdentity and enforcing
// the rule in one of them would be worse than not enforcing it at all: an
// application would learn the rule from whichever path it exercised first
// and be ambushed by the other. See [ErrProviderSubjectRequired] for what a
// blank Subject actually does once it reaches a store.
//
// It trims only to TEST the value, never to rewrite it. Provider and Subject
// are matched byte-for-byte everywhere in this package (see
// [Identity.Subject]), so storing a trimmed value would create a link that
// no later sign-in with the caller's own, untrimmed input could resolve.
func requireProviderSubject(ext ExternalIdentity) error {
	if strings.TrimSpace(ext.Provider) == "" || strings.TrimSpace(ext.Subject) == "" {
		return ErrProviderSubjectRequired
	}
	return nil
}

// SignInWith signs a user in from an external provider's assertion, and is
// the only method in this package that can create an account without a
// password. The application runs the OAuth/OIDC dance itself and hands the
// validated result here as a [SignInRequest] — this package never talks to a
// provider (see auth/identity.go's package doc for that boundary and for why
// no provider token is stored).
//
// It requires [WithIdentityStore]; without it every call fails with
// [ErrOAuthNotConfigured] before anything is read or written. A blank — or
// whitespace-only — Identity.Provider or Identity.Subject is refused the
// same way, with [ErrProviderSubjectRequired]: see that sentinel for why an
// empty subject is a shared key rather than a value that simply misses.
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
//     - A local account exists: LINK to it only if the address came from
//     the PROVIDER and the configured [Linking] policy allows, otherwise
//     [ErrLinkRequiresVerification]. Created is false.
//
// Both rungs end at the SECOND FACTOR, not at a session: an account owing
// one gets a [MFAChallenge] in [SignInResult.MFA] and no tokens. See "An
// external identity is not a second factor" below.
//
// # A caller-supplied address never links
//
// The link branch is reached on nothing but a matching address, so WHOSE
// address it is decides what may be done with it. A
// [SignInRequest.FallbackEmail] may PROVISION a new account and may never
// LINK to an existing one — under every [Linking] policy, [LinkAlways]
// included, and the check sits above the policy switch for exactly that
// reason.
//
// The provider asserted no address on that path. Linking on one the caller
// supplied would attach an external account to a pre-existing local account
// on the strength of a string the caller typed: anyone able to complete a
// dance at any configured provider, with any throwaway account, names a
// victim's address and is signed in as them. LinkAlways's own justification
// is about a provider you operate and whose assertions you trust, and it
// says nothing about a path with no assertion in it at all.
//
// Provisioning stays allowed because nobody holds the address: there is no
// account to take over, and refusing would strand every user whose provider
// keeps their address private — the case FallbackEmail exists for.
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
// # A stamped account is refused on both rungs, separately
//
// An ANONYMIZED account (a non-nil [UserBase.DeletedAt] — see
// [Service.AnonymizeAccount]) is refused with [ErrUserNotFound], and this
// method carries TWO checks for it rather than one, because the two rungs
// reach an account by two different routes and a single guard placed on
// either one would leave the other open:
//
//   - Rung 1, in [Service.signInLinkedIdentity], after the account is
//     loaded and before [IdentityStore.TouchIdentity] stamps a use that is
//     not going to happen. [Service.AnonymizeAccount] removes every linked
//     identity before it stamps, so this rung should be unreachable for a
//     stamped account; the check is there because "should be unreachable"
//     is exactly the assumption that a deployment wiring two Services over
//     one users table — only one of them holding an [IdentityStore] — makes
//     false. See [Service.sweepIdentities] for that configuration.
//   - Rung 2, in the existing-account branch, above the [Linking] policy.
//     This one is genuinely reachable: an anonymized row still holds the
//     derived scrubbed address, and under [LinkAlways] a provider willing
//     to assert that address would otherwise link to it and sign in.
//
// Without both, an anonymized account would be MORE reachable through an
// external provider than through any local credential, since the scrub
// removes the password and leaves nothing for [Service.Login] to refuse on.
// Two separate checks also mean a mutation that removes either one fails a
// test naming that rung, which a shared guard could not prove.
//
// [Service.LinkIdentity] carries its own third check for the same reason;
// see its "What it refuses".
//
// # An external identity is not a second factor
//
// An account holding a CONFIRMED [MFAFactor] does NOT get a session here.
// This method returns a [SignInResult] whose AccessToken and RefreshToken
// are EMPTY and whose MFA field carries a short-lived [MFAChallenge], with
// a nil error and no [Session] row created — the identical pending state
// [Service.Login] returns, finished the identical way through
// [Service.CompleteMFA]. Under [EnforcementRequired] an account with NO
// confirmed factor is refused outright with [ErrMFARequired].
//
// The provider may have enforced a second factor of its own. This package
// cannot see whether it did, cannot name which one, and cannot know whether
// this deployment trusts it — [ExternalIdentity] carries no such field and
// could not be believed if it did. And under [LinkVerified] or [LinkAlways]
// an identity reaches an existing account on the strength of a matching
// ADDRESS, so accepting one as the factor would let any provider willing to
// assert an address stand in for it. auth/mfa_service.go's package doc,
// "What the second factor gates, door by door", carries the full argument
// and names the honest ways a deployment can trust a provider's own factor
// instead.
//
// Like the stamped-account refusal above, this is TWO checks, one per rung,
// for the same reason and pinned by a test naming each rung. Both run LAST,
// after everything else the rung does — which has one consequence worth
// stating rather than discovering: on rung 2 the identity is LINKED before
// the challenge is returned, so an external sign-in that stops at a
// challenge still leaves the link behind. That is deliberate. Checking
// above [IdentityStore.CreateIdentity] instead would mean an account with a
// confirmed factor could never link a provider through this method at all,
// since [Service.CompleteMFA] mints a session and does no linking. The
// residual is narrow — an attacker who can make the provider assert the
// victim's address gains a linked identity and no session, where before
// this section existed they gained a session outright.
//
// Provisioning under [EnforcementRequired] deserves its own sentence: a
// brand-new account has no confirmed factor, so it is created, linked, and
// then refused with ErrMFARequired. The account exists and cannot sign in
// until it enrols. A deployment running EnforcementRequired alongside
// external sign-up must therefore drive enrolment itself.
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
// The linking decision reads the local account from [Store] and then writes
// the identity to [IdentityStore], and the two may be different backends with
// no transaction spanning them (that is the point of the split port — see
// [IdentityStore]'s doc). A concurrent [Store.UpdateUserEmail] landing in
// between would otherwise leave the identity attached to an account that no
// longer holds the asserted address AT ALL — and rung 1 would then resolve
// that subject to that account forever, never consulting an address again.
//
// That one does not need a transaction, and is closed: after the write, the
// account is re-read and the row is retracted when the address it was matched
// on is no longer the account's. See [Service.confirmLinkedAddress] for the
// exact guarantee this restores, for why re-reading the address also covers
// the EmailVerifiedAt the decision stood on, and for the one residual — a
// retraction whose own delete fails leaves the row, and says so with an
// error.
//
// # The window that is DISCLOSED rather than closed
//
// On the provisioning branch [Store.CreateUser] commits before
// [IdentityStore.CreateIdentity] runs. A transient identity-backend failure
// therefore leaves a user row holding the address with no password and no
// identity, and this method returns the store's error.
//
// The cost is real. When the provider did not assert the address verified,
// every retry of the identical assertion now finds that account and is
// refused with [ErrLinkRequiresVerification] — the account exists, is
// unverified, and rung 2's policy will not link to it — so the sign-in the
// user was attempting cannot succeed however many times they try it.
//
// It is not, however, an address lost for good, and it has exactly one
// recovery: [Service.RequestPasswordReset] followed by
// [Service.ResetPassword], the same route this method's own password-less
// accounts take. Redeeming that token gives the account a password AND
// certifies the address, after which [Service.Login] works and a later
// verified assertion links under [LinkVerified].
// TestSignInWithLeavesTheProvisionedUserWhenTheIdentityWriteFails pins both
// halves, so this disclosure is checked rather than asserted.
//
// Compensating — deleting the just-created user — is what would close it,
// and [Store.DeleteUser] now exists to do it with. This method still does
// not, and the reason is no longer that the primitive is missing:
//
//   - The row is ADDRESSABLE the instant CreateUser commits. A concurrent
//     [Service.SignInWith], [Service.RequestPasswordReset] or
//     [Service.RequestMagicLink] at that same address can already have
//     found it and acted on it — minted a verification against it, or
//     linked a DIFFERENT external identity to it — by the time the
//     identity write here fails. Deleting it then destroys an account
//     somebody else is legitimately using, which is a strictly worse
//     failure than the one being compensated for.
//   - The compensating delete can itself fail, so it turns one disclosed
//     window into two, and the second one hands the caller an error that
//     describes the cleanup rather than the sign-in.
//
// The documented recovery above covers the window, it is pinned by a test
// rather than asserted, and it does not depend on this method guessing
// whether the row it created is still only its own.
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

	// A malformed assertion is refused before any store is touched — see
	// [ErrProviderSubjectRequired]. This is above rung 1 rather than folded
	// into it because a blank subject does not MISS the lookup, it matches
	// whatever earlier blank-subject row exists at that provider.
	if err := requireProviderSubject(ext); err != nil {
		return zero, err
	}

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
		// Rung 2's OWN anonymized-account refusal — see the method doc, "A
		// stamped account is refused on both rungs, separately". This is
		// the rung reachable under [LinkAlways] against a provider willing
		// to assert the scrubbed address a stamped row holds, and it is
		// checked ABOVE the policy so that no [Linking] setting can allow
		// past it.
		if u.DeletedAt != nil {
			return zero, ErrUserNotFound
		}
		// providerAsserted is passed, not just providerVerified, because the
		// fallback rule sits ABOVE the policy — see [Service.mayLink].
		if !s.mayLink(providerAsserted, providerVerified, u) {
			return zero, ErrLinkRequiresVerification
		}
		// Linking certifies nothing about the local address: EmailVerifiedAt
		// is left exactly as it was, on every policy.
	}

	lastUsed := now
	written, err := identities.CreateIdentity(ctx, Identity{
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
	})
	if err != nil {
		return zero, err
	}

	// The link rung decided on an address read from another store, so
	// confirm the account still holds it and retract the row if it does not
	// — see [Service.confirmLinkedAddress]. The provisioning rung is not
	// checked: the account was created by this very call, its id has not
	// left this function, and its address was free a moment ago.
	if !created {
		if err := s.confirmLinkedAddress(ctx, identities, written, u.ID, email); err != nil {
			return zero, err
		}
	}

	// The rung's events, once the identity row is known to stand: a
	// [SignedUp] for an account this call brought into existence, then the
	// [IdentityLinked] both rungs owe for the row they wrote. After
	// confirmLinkedAddress, deliberately — a retracted link is not a link.
	if created {
		if err := s.emit(ctx, Event{Kind: SignedUp, UserID: u.ID, IP: req.IP, UserAgent: req.UserAgent, Detail: DetailExternalIdentity}); err != nil {
			return zero, err
		}
	}
	if err := s.emit(ctx, Event{Kind: IdentityLinked, UserID: u.ID, IP: req.IP, UserAgent: req.UserAgent}); err != nil {
		return zero, err
	}

	// The second factor, consulted last — the ADDRESS rung's own call to
	// mfaAtSignIn, separate from rung 1's rather than a guard the two share,
	// exactly as each rung carries its own anonymized-account refusal. A
	// confirmed factor short-circuits the mint entirely and hands back a
	// challenge with EMPTY tokens; see the method doc's "An external
	// identity is not a second factor".
	challenge, err := s.mfaAtSignIn(ctx, u)
	if err != nil {
		return zero, err
	}
	if challenge != nil {
		// Deliberately NOT mintSession, so this line is the only thing
		// scrubbing the credential digest off the record handed back.
		u.PasswordHash = ""
		if err := s.emit(ctx, Event{Kind: MFAChallenged, UserID: u.ID, IP: req.IP, UserAgent: req.UserAgent}); err != nil {
			return zero, err
		}
		return SignInResult{Created: created, User: u, MFA: challenge}, nil
	}

	// nil: an external assertion is not a second factor — see
	// [SignInResult.MFA]. An account holding one left with a challenge.
	minted, err := s.mintSession(ctx, u, req.IP, req.UserAgent, nil, DetailExternalIdentity)
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
//
// It carries rung 1's own ANONYMIZED-account refusal, which is a SEPARATE
// check from rung 2's rather than a guard the two share — see
// [Service.SignInWith]'s "A stamped account is refused on both rungs,
// separately". It is placed after the user load and before
// [IdentityStore.TouchIdentity], so a refused sign-in does not stamp
// LastUsedAt for a use that did not happen.
//
// It carries rung 1's own SECOND-FACTOR check too, on the same terms and
// for the same reason, and that one is placed after TouchIdentity: the
// identity WAS used — the provider's assertion resolved to this account —
// and a sign-in that stops at a challenge is a sign-in in progress, not a
// refusal. See [Service.SignInWith]'s "An external identity is not a second
// factor".
func (s *Service) signInLinkedIdentity(ctx context.Context, identities IdentityStore, linked Identity, req SignInRequest) (SignInResult, error) {
	var zero SignInResult

	u, err := s.store.FindUserByID(ctx, linked.UserID)
	if err != nil {
		return zero, err
	}
	if u.DeletedAt != nil {
		return zero, ErrUserNotFound
	}
	if err := identities.TouchIdentity(ctx, linked.ID, s.cfg.clock()); err != nil {
		return zero, err
	}

	challenge, err := s.mfaAtSignIn(ctx, u)
	if err != nil {
		return zero, err
	}
	if challenge != nil {
		// Deliberately NOT mintSession, so this line is the only thing
		// scrubbing the credential digest off the record handed back.
		u.PasswordHash = ""
		if err := s.emit(ctx, Event{Kind: MFAChallenged, UserID: u.ID, IP: req.IP, UserAgent: req.UserAgent}); err != nil {
			return zero, err
		}
		return SignInResult{Created: false, User: u, MFA: challenge}, nil
	}

	// nil: an external assertion is not a second factor — see
	// [SignInResult.MFA]. An account holding one left with a challenge.
	minted, err := s.mintSession(ctx, u, req.IP, req.UserAgent, nil, DetailExternalIdentity)
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
// providerAsserted says whose address that is. providerVerified is NOT
// ext.EmailVerified — it is that flag AND providerAsserted, so a
// [SignInRequest.FallbackEmail] can never inherit a verification. See
// [Service.SignInWith]'s doc.
//
// # A caller-supplied address may provision, and may never link
//
// The first check is ABOVE the policy switch, deliberately, so that it holds
// under [LinkAlways] too.
//
// When the provider returned no address, the one being matched here came from
// [SignInRequest.FallbackEmail]: it is the APPLICATION's value, and the
// provider asserted nothing about it whatsoever. Linking on it would attach
// an external account to a pre-existing local account on the strength of a
// string the caller supplied — anyone who can complete a dance at any
// configured provider, with any throwaway account, names a victim's address
// and is signed in as them.
//
// [LinkAlways] would otherwise do exactly that, and its own doc does not
// cover it: the mode is blessed for "a single first-party identity provider
// that you operate, whose verification semantics you know, and which no third
// party can make assert an arbitrary address" — a justification about a
// PROVIDER's assertions, which says nothing about a path where the provider
// asserts no address at all. So the rule is not a fourth policy branch; it is
// a precondition every branch is subject to.
//
// Provisioning is untouched. Nobody holds the address, so there is no account
// to take over, and refusing would strand every user whose provider keeps
// their address private — the case FallbackEmail exists for.
//
// The default branch is unreachable: [WithLinking] panics at construction on
// any mode outside the three constants. It denies anyway, because the one
// thing a policy switch must never do is fall through to "allow" for a value
// nobody anticipated.
func (s *Service) mayLink(providerAsserted, providerVerified bool, u UserBase) bool {
	if !providerAsserted {
		return false
	}
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

// confirmLinkedAddress is rung 2's compensating re-read: the link was decided
// on an address read from [Store] and then written to [IdentityStore], and
// the two may be different backends with no transaction spanning them. This
// re-reads the account and retracts the row when the address it was matched
// on is no longer the account's.
//
// # What it buys, precisely
//
// Without it, a [Store.UpdateUserEmail] landing in that window leaves an
// identity attached to an account that does not hold the asserted address at
// ALL — and rung 1 then resolves that subject to that account forever,
// without ever consulting an address again. The row outlives the fact that
// justified it, and nothing later re-examines it.
//
// With it, the guarantee an uncontended link has is restored: at an instant
// at or after the row was written, the account held the address it was
// matched on. An address change landing AFTER that instant is not this
// method's business and never was — it is the ordinary event
// [Identity.Email]'s doc describes, and unlinking somebody's Google because
// they later changed their local address would be a bug of its own.
//
// # Why re-reading the ADDRESS also covers the verification
//
// [LinkVerified] decides on u.EmailVerifiedAt, so it might look as though
// that field needs re-reading too. It does not, because no [Service] method
// can clear it without also moving the address: [Store.UpdateUserEmail] is
// the only writer that clears it and it changes the address by definition,
// and [Service.VerifyEmail]'s email-change path re-stamps the new address
// verified before it returns. An address that did not move therefore cannot
// have silently lost the verification the decision stood on.
//
// The exception is the one this package always names: an application calling
// [Store.UpdateUserEmail] itself with the address the row already holds
// clears EmailVerifiedAt without moving anything, and this check will not see
// it. That is the same escape hatch [IdentityStore.DeleteIdentityIfNotLast]'s
// staleness argument discloses, reached the same way — by going around
// Service.
//
// # What it costs when it fires
//
// The retraction deletes a row this call wrote moments ago, so it removes
// nothing the account was relying on. A delete that itself FAILS is returned
// as-is and the row survives — the one residual, and the reason the error is
// propagated rather than swallowed: a caller must never read "your sign-in
// failed" as "nothing was written".
//
// [ErrIdentityNotFound] from the delete is not a failure: the row this call
// wrote is already gone, which is the state the retraction wanted.
func (s *Service) confirmLinkedAddress(ctx context.Context, identities IdentityStore, written Identity, userID, matched string) error {
	u, err := s.store.FindUserByID(ctx, userID)
	if err == nil && u.Email == matched {
		return nil
	}

	if derr := identities.DeleteIdentity(ctx, written.ID); derr != nil && !errors.Is(derr, ErrIdentityNotFound) {
		return derr
	}
	if err != nil {
		// The account could not be re-read at all — a deleted user, or a
		// store outage. Either way the link is retracted and the store's own
		// error is what the caller gets.
		return err
	}
	// The address moved under the decision. This is the same refusal the
	// policy itself produces, and it carries the same remedy: authenticate
	// the user by some other means and call [Service.LinkIdentity]. A retry
	// re-enters the ladder at the top, where the account at the CURRENT
	// address is the one the policy is applied to.
	return ErrLinkRequiresVerification
}

// sweepIdentities removes every external identity on userID's account. It has
// exactly three callers, and they are the three paths in
// [Service.ChangePassword]'s sweep matrix whose identity column says "swept":
// [Service.ResetPassword], [Service.DeleteAccount] and
// [Service.AnonymizeAccount]. ChangePassword and [Service.LogoutAll]
// deliberately do NOT call it — see ResetPassword's doc for why an
// unauthenticated recovery sweeps and an authenticated rotation does not.
//
// The optional port being absent is not an error here, and that is the whole
// reason this is a helper rather than a call to [Service.identities]. A
// deployment that offers no external sign-in has no identities to sweep, and
// turning every password reset — or every account deletion — in such a
// deployment into [ErrOAuthNotConfigured] would break the one flow this
// package documents as the way back into a locked-out account, and would
// make the other two unable to finish at all.
//
// A [Service] built WITHOUT [WithIdentityStore] over a users table that some
// OTHER Service does wire one to is the stated limit, and it is the same
// limit for all three callers: this sweep can only remove rows through the
// port the Service performing the call holds. Such a deployment must delete
// the identities itself — from [WithAccountDeletionHook] for the two
// deletion postures, which is the hook's purpose, and by hand for
// ResetPassword, which has no hook.
//
// The list and the deletes are separate calls, with the same SEQUENTIAL-ONLY
// scope its callers' verification sweeps disclose: an identity linked by a
// call genuinely concurrent with this one can survive it. Closing that would
// need a transaction the port does not offer, and the exposure is bounded by
// the linking policy, which still applies to that concurrent call — and, for
// the two deletion callers, by [Service.LinkIdentity]'s and
// [Service.SignInWith]'s own refusals once [UserBase.DeletedAt] is stamped.
//
// A failure partway through is returned immediately, leaving the identities
// already deleted deleted and the rest standing. Each survivor is still a
// way in, which is why the error is returned rather than swallowed and why
// every caller treats it as fatal to the operation.
//
// [ErrIdentityNotFound] from a delete is success: another caller removed the
// row first, which is the state this wanted.
func (s *Service) sweepIdentities(ctx context.Context, userID string) error {
	identities := s.cfg.identityStore
	if identities == nil {
		return nil
	}
	rows, err := identities.ListIdentitiesByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, i := range rows {
		if err := identities.DeleteIdentity(ctx, i.ID); err != nil && !errors.Is(err, ErrIdentityNotFound) {
			return err
		}
	}
	return nil
}

// passwordCanAuthenticate reports whether u's password credential is one this
// Service would actually accept — not merely whether a hash is stored.
//
// The distinction is the whole point. [Service.Login] refuses an empty
// PasswordHash AND, under [WithRequireVerifiedEmail](true), an unverified
// account. A stored hash on an unverified account under that option is
// therefore not a way in, and treating it as one is how
// [Service.UnlinkIdentity] would remove the only door that opens.
//
// It is deliberately the same pair of conditions [Service.Login] applies,
// read off the same config, rather than a second rule that could drift.
func (s *Service) passwordCanAuthenticate(u UserBase) bool {
	if u.PasswordHash == "" {
		return false
	}
	return !s.cfg.requireVerifiedEmail || u.EmailVerifiedAt != nil
}

// revokeEverySession revokes every session family userID holds — one
// [Store.DeleteSessionsByFamily] per distinct family, so rotated-but-unexpired
// predecessor rows go too rather than only each family's currently-live row.
//
// It is the "sweep everything, spare nothing" shape [Service.LogoutAll],
// [Service.ResetPassword] and [Service.UnlinkIdentity] share.
// [Service.ChangePassword] deliberately does NOT use it: that method spares
// the caller's own family, and holds the currentSessionID to identify it
// with.
//
// A failure partway through is returned immediately, leaving the families
// already revoked revoked and the rest untouched. The caller sees a non-nil
// error either way and must not assume the operation mostly worked.
func (s *Service) revokeEverySession(ctx context.Context, userID string) error {
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
//   - ext.Provider or ext.Subject is blank, or nothing but whitespace:
//     [ErrProviderSubjectRequired], before the account is even read. See
//     that sentinel for why a blank subject is a takeover key rather than a
//     harmless empty string.
//   - userID names no account: [ErrUserNotFound]. The account is read before
//     the link is written, so a row is never left dangling — pointing at a
//     user that does not exist, occupying a (Provider, Subject) pair nobody
//     can then use, and failing every sign-in that resolves it.
//   - userID names an ANONYMIZED account (a non-nil [UserBase.DeletedAt] —
//     see [Service.AnonymizeAccount]): the same [ErrUserNotFound], decided
//     from the same read and before the pair is looked up at all, so a
//     stamped row can never acquire a fresh credential. This method ARMS a
//     way in rather than using one, which puts it in
//     [Service.RequestEmailChange]'s category rather than
//     [Service.Login]'s: anonymization clears the password, so an identity
//     linked afterwards would be the account's ONLY credential and would
//     make it fully usable again through [Service.SignInWith]. The refusal
//     is this method's own explicit check, not one inherited from
//     SignInWith — see that method's "A stamped account is refused on both
//     rungs, separately" for why each entry point carries its own.
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

	// A malformed assertion is refused before any store is touched — see
	// [ErrProviderSubjectRequired] — and therefore before the user read
	// below, so a blank subject cannot be answered with ErrUserNotFound
	// instead of the input error it actually is.
	if err := requireProviderSubject(ext); err != nil {
		return zero, err
	}

	// The account is read FIRST: nothing is ever linked to a user that does
	// not exist, not even idempotently.
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return zero, err
	}
	// An ANONYMIZED account may not ACQUIRE a credential — see the method
	// doc, "What it refuses". Refused before the (Provider, Subject) pair is
	// even looked up, so a stamped row cannot be armed with a way in, and
	// not even the idempotent already-linked-to-this-user return is reached.
	if u.DeletedAt != nil {
		return zero, ErrUserNotFound
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

	written, err := identities.CreateIdentity(ctx, Identity{
		ID:        s.cfg.idGen(),
		UserID:    userID,
		Provider:  ext.Provider,
		Subject:   ext.Subject,
		Email:     NormalizeEmail(ext.Email),
		CreatedAt: s.cfg.clock(),
		// LastUsedAt stays nil: this link was made without a sign-in, and
		// nil is how a caller tells the two apart.
	})
	if err != nil {
		return zero, err
	}
	if err := s.emit(ctx, Event{Kind: IdentityLinked, UserID: userID}); err != nil {
		return zero, err
	}
	return written, nil
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
// surviving the delete, no WORKING password credential and no passkey, the
// call fails with [ErrLastCredential] and removes NOTHING. That is not a
// formality. An account with none of the three cannot be authenticated by
// anything in this package — not by [Service.Login], which refuses an empty
// PasswordHash, not by [Service.SignInWith], which has no link left to
// resolve, and not by [Service.FinishPasskeyLogin], which has no credential
// to resolve. The lockout would be permanent. [ErrIdentityNotFound] means
// there was nothing to unlink at that provider, which is a different answer
// an application's connected-accounts screen acts on differently.
//
// # Why the sessions go too
//
// A successful unlink revokes EVERY session family the account holds — the
// same "spare nothing" sweep [Service.LogoutAll] and [Service.ResetPassword]
// perform, via [Service.revokeEverySession].
//
// This is a credential removal, and every other credential change in this
// package sweeps. Without it, a session minted THROUGH the identity being
// removed keeps rotating for its full [WithRefreshTTL] — "disconnect this
// account" would leave the disconnected account's session live, which is the
// opposite of what the screen calling this says it does.
//
// It sweeps all of the user's families rather than only those minted through
// this identity, because a [Session] records no identity provenance: nothing
// in the row says which credential minted it, and a rotated successor would
// not carry it anyway. Adding that column is a [Store] schema change for a
// distinction that stops being true after the first refresh. The blunt sweep
// is also the safer default for the case that motivates an unlink at all —
// "that Google account is not mine any more" — where the sessions worth
// keeping are the ones the user can trivially re-create by signing in.
//
// There is no carve-out for the caller's own session, unlike
// [Service.ChangePassword]. That method is handed a currentSessionID it can
// identify the caller's family with; this one takes no session at all, and
// inventing a parameter for it would ask an application to nominate a session
// to spare with nothing here able to check the nomination is honest.
// Disconnecting a provider therefore signs the user out everywhere, and the
// connected-accounts screen should say so before it calls this.
//
// The ORDER is load-bearing in the small: the delete runs first, so a refusal
// — either sentinel — reaches the caller having changed nothing at all. A
// revocation that outlived its own refused operation would sign a user out of
// every device to tell them "no". Once the delete has committed, a failure in
// the revocation is returned as-is with the identity already gone; the caller
// sees an error and must not assume the unlink did not happen.
//
// The decision and the delete happen inside
// [IdentityStore.DeleteIdentityIfNotLast] as ONE atomic step, which is why
// that method has the shape it does — see its doc for the read-then-write
// race that a "list, decide, delete" here would reopen, and that this
// project has shipped four times elsewhere.
//
// # Why the other-credential state is read here and passed in
//
// The identity store owns `identities` and cannot see `users` or the passkey tables, so this
// method reads the account and hands the answer down. [IdentityStore]'s own
// doc argues why that value cannot go stale in a way that HARMS: the two
// methods that write a password ([Service.ChangePassword],
// [Service.ResetPassword]) both store a freshly hashed, non-empty value, so
// neither can turn a true into a false; and the two that remove one
// ([Service.AnonymizeAccount], [Service.DeleteAccount]) are ending the
// account outright, so the "lockout" a stale true could cause there is the
// state those methods exist to produce. The other direction merely refuses
// a delete that would have been safe, which is self-correcting on retry.
//
// The PASSKEY term can move the dangerous way — [Service.DeletePasskey]
// removes one concurrently — which is the mirror-image race disclosed in
// full on [CredentialStore.DeleteCredentialIfNotLast] and not closed here.
//
// That argument depends on the read being FRESH and being the account's real
// state. It is performed on every call rather than cached, and the flag is
// derived from the stored account rather than assumed — passing a constant
// true would be exactly the lockout above, wearing a successful return.
//
// # The question asked is "can it authenticate", not "is a hash stored"
//
// [Service.hasWayInBesides] answers it — the SAME arithmetic
// [Service.DeletePasskey] uses with the other kind excluded, so the two
// removers cannot drift into disagreeing about what a way in is. Its password
// term is [Service.passwordCanAuthenticate], and the difference is not
// academic. Under [WithRequireVerifiedEmail](true), [Service.Login] refuses
// an unverified account outright: a stored hash on such an account opens
// nothing, so counting it as a way in would let this method remove the only
// door that does open. The predicate reads the same option Login reads, so
// the two cannot disagree about what a working credential is.
//
// The arithmetic now spans all three credential kinds, and here that is a
// RELAXATION rather than a tightening: an account holding one identity and
// one passkey but no password used to be refused this unlink, and is not any
// more, because the passkey is a genuine way in and refusing was simply
// wrong. A [Service] wired without [WithCredentialStore] cannot see passkeys
// and behaves exactly as it did before — see [Service.hasWayInBesides], "An
// unwired optional port contributes nothing".
//
// It errs strict, which is the safe direction: an account that would in fact
// have been fine is refused an unlink until it verifies its address, and the
// refusal removes nothing.
//
// # A magic link is not counted, deliberately
//
// [Service.RequestMagicLink] and [Service.RedeemMagicLink] are a way into
// an account that needs neither a password nor an identity, so a reader
// meeting this predicate after meeting them will ask whether the
// arithmetic should have changed. It should not, and this says so rather
// than leaving the omission to look like an oversight.
//
//  1. That route is not new, and it never counted. A password-less account
//     has ALWAYS been reachable through [Service.RequestPasswordReset]
//     followed by [Service.ResetPassword] — that pair sets a first password
//     on an account with none and certifies the address while doing it, and
//     it is the documented recovery for exactly the accounts
//     [Service.SignInWith] provisions. If a route through the mailbox
//     counted as a surviving way in, this predicate would have been
//     vacuously true since v0.1.0 and [ErrLastCredential] would never have
//     fired at all. Magic links add a second door to a room that was
//     already reachable; they do not change what the door is made of.
//
//  2. The question this predicate answers is what the ACCOUNT holds, not
//     what a mailbox holder can obtain. A password hash and an [Identity]
//     are rows that survive the delete and can be presented afterwards. A
//     magic link does not exist until somebody asks for one, and whether
//     asking works depends on facts this package cannot see: whether the
//     application exposes that endpoint at all, and whether it can send
//     mail. Answering "yes, a way in survives" on the strength of an
//     endpoint the deployment may never have wired is the constant true
//     that "Why the password state is read here and passed in" identifies
//     as the lockout wearing a successful return.
//
//  3. The one case where it would matter is the case where it would be
//     most wrong. An account provisioned by [Service.SignInWith] against a
//     provider that did not assert the address verified holds an address
//     NOBODY has proven control of. Counting a magic link there would
//     permit removing that account's last identity and hand it to whoever
//     holds that mailbox — a takeover, arrived at through a check that
//     exists to prevent a lockout.
//
// The asymmetry with the password half is therefore not an inconsistency:
// [Service.passwordCanAuthenticate] asks whether a STORED credential is one
// [Service.Login] would accept, and there is no stored magic link to ask
// the question about.
func (s *Service) UnlinkIdentity(ctx context.Context, userID, provider string) error {
	identities, err := s.identities()
	if err != nil {
		return err
	}

	// Read the credential state fresh, immediately before the delete: see
	// "Why the other-credential state is read here and passed in", and
	// [IdentityStore.DeleteIdentityIfNotLast]'s own staleness argument,
	// which this ordering is what makes true. The question asked of the
	// account is whether it can AUTHENTICATE by some OTHER kind, not whether
	// a hash is stored — see [Service.hasWayInBesides].
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}
	otherWayIn, err := s.hasWayInBesides(ctx, u, kindIdentity)
	if err != nil {
		return err
	}

	// The delete comes first, so a refusal — ErrLastCredential or
	// ErrIdentityNotFound — reaches the caller having changed nothing at all.
	if err := identities.DeleteIdentityIfNotLast(ctx, userID, provider, otherWayIn); err != nil {
		return err
	}

	// The credential is gone; now take back what it minted. See "Why the
	// sessions go too".
	if err := s.revokeEverySession(ctx, userID); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: IdentityUnlinked, UserID: userID})
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
