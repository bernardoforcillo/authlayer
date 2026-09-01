// Package auth (this file) adds external — "OAuth", "social", "sign in with
// X" — identities to the credential model auth.go defines. It is a separate
// file rather than more of auth.go for one concrete reason: [Store] is a
// released, 18-method port, and adding a method to it would break every
// third-party backend that already implements it. [IdentityStore] is a
// second, OPTIONAL port instead, wired with [WithIdentityStore] and absent
// by default, exactly as invite.Store is its own port rather than more of
// this one.
//
// # What this package stores, and what it refuses to
//
// An [Identity] row is `(provider, subject, email)` plus two timestamps. It
// carries NO access token and NO refresh token from the provider, and this
// package is not an API client: it never calls a provider, never exchanges a
// code, never refreshes a provider grant. The application runs the OAuth
// dance with whatever client library it likes, and hands the resulting
// assertion here as an [ExternalIdentity]. That boundary is why there is no
// column to leak: a database dump of this table cannot be replayed against
// Google or GitHub on a user's behalf.
//
// # Why the subject, not the email, identifies the account
//
// `(provider, subject)` is the account key. An email address at a provider
// is mutable and, at some providers, re-assignable; the subject is the
// provider's own stable, opaque identifier for the account. Resolving a
// sign-in by subject first means a user changing their address at the
// provider still lands on the same local account, and — the security half —
// a provider asserting an address it should not means nothing on its own to
// an already-linked account. [Identity.Email] is an audit field. It is never
// an authentication input once the link exists.
package auth

import (
	"context"
	"errors"
	"time"
)

// Identity is one external account linked to one local [UserBase]: the row
// that says "this Google subject is this user".
//
// A user may hold several — one per provider, and nothing in this package's
// data model forbids two for the same provider — and each is an independent
// way into the account, which is why removing the last one is guarded (see
// [IdentityStore.DeleteIdentityIfNotLast] and [ErrLastCredential]).
//
// It carries no provider token of any kind, deliberately — see the file's
// package doc, "What this package stores, and what it refuses to".
type Identity struct {
	// ID is the record's surrogate key, stamped by the service (uid.NewV7).
	// [WithIDGenerator]'s "MUST be UUID-parseable to use store/drops"
	// constraint covers this column too.
	ID string `drop:"id"`
	// UserID is the local user this external account signs in as.
	UserID string `drop:"user_id"`
	// Provider names the issuer of Subject — "google", "github", "entra".
	// It is a plain string, not a typed enum, matching
	// [Verification.Purpose]'s stance: the application decides which
	// providers it supports, a persistence port does not.
	//
	// It is compared byte-for-byte, never case-folded, everywhere in this
	// package. "Google" and "google" are two different providers, and an
	// application that lets both reach this package will link the same
	// external account twice.
	Provider string `drop:"provider"`
	// Subject is the provider's own stable identifier for the external
	// account — OIDC's `sub` claim, GitHub's numeric user id. It is opaque:
	// this package never parses it, and never assumes it looks like
	// anything.
	//
	// An implementation MUST enforce that (Provider, Subject) is unique
	// across every Identity row — a composite UNIQUE constraint in a SQL
	// backend. This is the constraint that makes [ErrIdentityLinked] a
	// guarantee rather than advice: without it, two rows can name the same
	// external account against two DIFFERENT users, and a sign-in
	// resolving that subject lands on whichever row the backend happens to
	// return first. That is one external account silently able to sign in
	// as either of two local users, decided by row order — the same class
	// of defect [Session.TokenHash]'s own MUST exists to prevent, and this
	// project has already shipped a missing-uniqueness bug once
	// (invite.EmailInvite.TokenHash).
	Subject string `drop:"subject"`
	// Email is the address the PROVIDER asserted for this external account
	// at link time, normalized (see [NormalizeEmail]) on write by
	// [IdentityStore.CreateIdentity].
	//
	// It is an audit and display field. It may differ from the linked
	// [UserBase.Email] — legitimately, when the user changes their address
	// at the provider, and illegitimately, when a provider asserts an
	// address nobody proved control of — and this package never resolves an
	// already-linked sign-in through it: the (Provider, Subject) pair is
	// the account key. Treat a difference between this and UserBase.Email
	// as information, never as authority.
	Email string `drop:"email"`
	// CreatedAt is stamped by the service clock when the link was made.
	CreatedAt time.Time `drop:"created_at"`
	// LastUsedAt is when this identity last signed the user in, or nil when
	// it never has — the link exists but has not been used since it was
	// created. Stamped by [IdentityStore.TouchIdentity].
	LastUsedAt *time.Time `drop:"last_used_at"`
}

// ExternalIdentity is what an application's OAuth/OIDC client hands this
// package after it has completed the dance and validated the provider's
// response: the assertion, not the tokens.
//
// Everything in it is the PROVIDER's claim, and this package's trust in it
// is bounded accordingly — see [Linking] for exactly how far EmailVerified
// is trusted, and why the default policy refuses to trust it alone.
type ExternalIdentity struct {
	// Provider and Subject identify the external account — see
	// [Identity.Provider] and [Identity.Subject]. Both are required: a
	// blank Subject would make every account at that provider collide on
	// the same key.
	//
	// "Required" is enforced, not merely stated. [Service.SignInWith] and
	// [Service.LinkIdentity] — the only two entry points that accept an
	// ExternalIdentity — refuse a blank or whitespace-only value in either
	// field with [ErrProviderSubjectRequired], before touching any store.
	Provider, Subject string
	// Email is the address the provider asserted, which may be empty
	// (GitHub with a private address is the usual case) — see
	// [SignInRequest.FallbackEmail] for what to do then.
	Email string
	// EmailVerified is the provider's claim that IT has verified control of
	// Email — OIDC's `email_verified`. It is one half of what
	// [LinkVerified] requires before linking an external identity to a
	// pre-existing local account; the other half is that the local account
	// is itself verified. Neither half is trusted alone.
	//
	// A provider that does not report verification status at all must be
	// mapped to false. Defaulting an unknown to true hands account takeover
	// to anyone who can make that provider assert a victim's address.
	EmailVerified bool
}

// SignInRequest is the input to an external sign-in: the provider's
// assertion, plus the two context fields every session row carries.
type SignInRequest struct {
	// Identity is the provider's assertion — see [ExternalIdentity].
	Identity ExternalIdentity
	// FallbackEmail is the address to use when the provider returned none
	// (Identity.Email empty). It is the application's own value — collected
	// from the user, or already known — and it is used ONLY to PROVISION a
	// local account, never as evidence of verification: an address supplied
	// here is unverified by construction, whatever Identity.EmailVerified
	// says about the address the provider did not return.
	//
	// # It can provision, and it can never link
	//
	// When the address supplied here already belongs to a local account,
	// [Service.SignInWith] refuses with [ErrLinkRequiresVerification] — under
	// EVERY [Linking] policy, [LinkAlways] included. The provider vouched for
	// no address here, so linking on this one would attach an external
	// account to somebody else's local account on the strength of a string
	// the caller typed. The application's remedy is the usual one:
	// authenticate the user by some other means and call
	// [Service.LinkIdentity].
	//
	// The practical consequence, worth designing your callback around: a user
	// whose provider keeps their address private cannot reach an account they
	// already hold by typing its address here. They sign in with their
	// password (or a reset) first, and connect the provider afterwards.
	//
	// With both this and Identity.Email empty there is no address to key a
	// local account on, and provisioning one would write an empty string
	// into a unique column that every other password-less account would
	// then collide with.
	FallbackEmail string
	// IP and UserAgent are recorded on the [Session] the sign-in mints, as
	// audit/display fields only — never a security check, matching
	// [Session.IP] and [Session.UserAgent].
	IP, UserAgent string
}

// SignInResult is the outcome of an external sign-in: the same three things
// a password [LoginResult] carries, plus whether the account was created by
// this very call.
type SignInResult struct {
	// Created reports whether this sign-in provisioned a brand-new local
	// account (true) or signed in an existing one (false). Use it to run
	// first-run onboarding.
	//
	// # What it discloses, stated rather than smoothed over
	//
	// Reaching this field at all takes a COMPLETED dance at a configured
	// provider, so it is not the freely pollable oracle
	// [SignUpResult.Created] would be. It is not free of disclosure either,
	// and an earlier version of this doc claimed it was.
	//
	// On the [SignInRequest.FallbackEmail] path the address is the CALLER's,
	// so the outcome answers a question about it: an unregistered address
	// provisions (nil error, Created true), and a registered one is refused
	// with [ErrLinkRequiresVerification]. The distinguishing signal is the
	// error, not this field — after that refusal there is no SignInResult at
	// all — but an application that branches on Created is branching on the
	// same fact.
	//
	// The cost to a prober is one fresh (provider, subject) pair per probe,
	// since a reused subject resolves on rung 1 and never consults an
	// address: that means a throwaway account at a configured provider each
	// time, and a junk local account left behind on every miss. That is a
	// real cost, not a wall. [Service.SignInWith] consults no [RateLimiter]
	// (see its "Three deliberate differences from Login"), so rate limiting
	// this belongs at your callback, where the dance already lives.
	//
	// On the provider-asserted path the same refusal exists but the address
	// is not the caller's to choose: probing it means making the provider
	// assert each address, which is the assumption the whole [Linking] policy
	// already rests on.
	Created bool
	// User is the signed-in account, freshly loaded. PasswordHash is always
	// cleared to "" here, matching every other Service method that hands
	// back a [UserBase] — see [UserBase.PasswordHash]'s own doc.
	//
	// A user provisioned by an external sign-in has NO password credential
	// at all (PasswordHash is empty in the store, not merely scrubbed
	// here), which is a supported state — see [UserBase]'s own doc.
	User UserBase
	// AccessToken and RefreshToken are exactly what a password login mints
	// — see [LoginResult.AccessToken] and [LoginResult.RefreshToken] for
	// their lifetimes and for how to present the refresh token.
	AccessToken, RefreshToken string
}

// Linking is the policy governing when an external identity may be attached
// to a PRE-EXISTING local account during an external sign-in — that is, when
// the provider's (provider, subject) pair is unknown but its email address
// already belongs to someone here.
//
// It governs that IMPLICIT link only. An explicit, application-driven link
// of an identity to an already-authenticated user is a different operation
// with a different trust basis (the user just proved they hold the account)
// and is not gated by this policy.
//
// # The attack this exists to stop
//
// An email match is not authentication. Under a naive "the addresses match,
// so sign them in", anyone who can make ANY configured provider assert
// victim@example.com takes the victim's account without ever learning their
// password — by registering that address at a provider that does not verify
// it, or by exploiting a provider that lets an address be re-assigned.
// [LinkVerified] is the answer, and it requires BOTH sides to be verified
// because either one alone is forgeable by exactly that route.
type Linking int

const (
	// LinkVerified links an external identity to an existing local account
	// only when the provider asserted the address as verified AND the local
	// account's own email is already verified. Otherwise the sign-in is
	// refused with [ErrLinkRequiresVerification], and the application's
	// remedy is to have the user authenticate locally and link deliberately.
	//
	// It is deliberately the ZERO VALUE of Linking, so a caller who never
	// calls [WithLinking] gets this rather than a permissive policy. That
	// ordering is load-bearing: an int enum whose zero value was
	// [LinkAlways] would hand every application that forgot to configure a
	// policy the takeover described in the type's doc. A test pins
	// LinkVerified == 0 for that reason.
	LinkVerified Linking = iota
	// LinkNever never links implicitly: an unknown (provider, subject)
	// whose address already belongs to a local account is always refused
	// with [ErrLinkRequiresVerification], however verified both sides are.
	// Every link must then be made explicitly, by an application that has
	// authenticated the user by some other means first.
	LinkNever
	// LinkAlways links implicitly whenever the PROVIDER asserted the
	// matching address, trusting that assertion unconditionally — verified
	// or not, and whatever the local account's own verification state is.
	//
	// It is UNSAFE for any provider you do not fully control: it is exactly
	// the "an email match is authentication" behaviour [Linking]'s own doc
	// describes as account takeover. Its legitimate use is a single
	// first-party identity provider that you operate, whose verification
	// semantics you know, and which no third party can make assert an
	// arbitrary address.
	//
	// That justification is about a provider's assertions, and it is the
	// exact boundary of what this mode permits. It does NOT extend to
	// [SignInRequest.FallbackEmail], where the provider asserted no address
	// at all and the one being matched is the application's own value: a
	// fallback address may provision a new account under every policy, and
	// may link to an existing one under none, including this one. See
	// [Service.SignInWith]'s "A caller-supplied address never links".
	LinkAlways
)

// Sentinel errors for the external-identity surface. Compare with
// [errors.Is], never by string — the messages are not part of the API.
//
// They join the [Store] sentinels declared in auth.go rather than replacing
// them: an [IdentityStore] returns [ErrIDTaken] on a duplicate id, exactly
// as [Store.CreateUser] does.
var (
	// ErrIdentityNotFound: no [Identity] matches the given (provider,
	// subject) pair, id, or (user, provider) pair. Returned by
	// [IdentityStore.FindIdentityByProviderSubject],
	// [IdentityStore.TouchIdentity] and
	// [IdentityStore.DeleteIdentityIfNotLast].
	ErrIdentityNotFound = errors.New("authlayer/auth: identity not found")
	// ErrIdentityLinked: the (provider, subject) pair is already linked, to
	// a different user than the one being linked now. Returned by
	// [IdentityStore.CreateIdentity]. One external account must never map
	// to two local users — see [Identity.Subject]'s uniqueness MUST for
	// what breaks otherwise.
	ErrIdentityLinked = errors.New("authlayer/auth: external identity already linked to an account")
	// ErrProviderSubjectRequired: an [ExternalIdentity] arrived with a blank
	// — empty, or nothing but whitespace — Provider or Subject. Returned by
	// [Service.SignInWith] and [Service.LinkIdentity], before either of them
	// reads or writes anything.
	//
	// Both fields are required, [ExternalIdentity.Provider] and
	// [ExternalIdentity.Subject] say so, and this is what makes that
	// documented requirement true rather than advisory. Neither value is
	// normalized or trimmed anywhere in this package — they are matched
	// byte-for-byte, per [Identity.Subject] — so the check REJECTS a
	// whitespace-only value rather than quietly folding it to empty,
	// matching how [Service.RequestEmailChange] treats an address that
	// normalizes away to nothing.
	//
	// A blank Subject is not a harmless no-op. It is a key that every
	// account at that provider collides on: the first such call links a row
	// which any later blank-subject sign-in at the same provider then
	// resolves to — one caller signed in as another — and the only thing
	// standing in the way is the (Provider, Subject) uniqueness constraint,
	// which downgrades the second call from that takeover to an
	// [ErrIdentityLinked] naming an account the caller never mentioned.
	// Takeover and a baffling conflict are both the wrong answer to what is
	// simply a malformed request, so it is refused as one.
	ErrProviderSubjectRequired = errors.New("authlayer/auth: external identity requires a provider and a subject")
	// ErrLinkRequiresVerification: an external sign-in resolved to an
	// existing local account by email address, and the identity was not
	// attached to it. Three conditions produce it, and they share one remedy,
	// which is why they share one sentinel rather than getting three:
	//
	//  1. The configured [Linking] policy refused — see [LinkVerified] and
	//     [LinkNever].
	//  2. The address came from [SignInRequest.FallbackEmail], so the
	//     provider asserted no address at all and the one being matched is
	//     the caller's. Refused under every policy, [LinkAlways] included.
	//     Naming this one separately was considered and rejected: a sentinel
	//     names the remedy, not the cause, and the remedy here is identical.
	//     It is also a strict case of what this one already says — "verified
	//     on both sides" is unsatisfiable when one side asserted nothing.
	//  3. The account's address MOVED between the linking decision and the
	//     write, so the link was retracted — see
	//     [Service.SignInWith]'s "What is not atomic here, and why".
	//
	// It is a "not like this" refusal, not a dead end: the account exists and
	// the user may well own it. The remedy in all three cases is for the
	// application to authenticate the user locally (password, or a reset if
	// they have no password) and then link the identity explicitly with
	// [Service.LinkIdentity], which this policy does not gate.
	//
	// It discloses that SOMEBODY holds the address — see
	// [SignInResult.Created] for what that is worth to a prober, and where
	// rate limiting belongs.
	ErrLinkRequiresVerification = errors.New("authlayer/auth: linking this identity requires a verified email on both sides")
	// ErrLastCredential: removing this identity would leave the account
	// with no way in at all — no other identity, and no password credential
	// this [Service] would actually accept. Returned by
	// [IdentityStore.DeleteIdentityIfNotLast], which refuses the removal
	// rather than performing it.
	//
	// "Would actually accept" is the operative phrase, and it is stricter
	// than "a password hash is stored". Under [WithRequireVerifiedEmail](true)
	// [Service.Login] refuses an unverified account outright, so a hash on
	// such an account is not a way in and [Service.UnlinkIdentity] does not
	// count it as one — see [Service.passwordCanAuthenticate].
	ErrLastCredential = errors.New("authlayer/auth: refusing to remove the account's last credential")
	// ErrOAuthNotConfigured: an operation needing an [IdentityStore] was
	// attempted on a [Service] built without [WithIdentityStore].
	//
	// The port is optional — an application that offers no external sign-in
	// wires none, and the 18-method [Store] it already has is untouched —
	// so every entry point that needs one resolves it through a single
	// guard that returns this, rather than dereferencing a nil interface.
	ErrOAuthNotConfigured = errors.New("authlayer/auth: no identity store configured")
)

// IdentityStore is the optional persistence port for external identities:
// the `identities` table, and nothing else. It is deliberately NOT part of
// [Store] — see this file's package doc for why adding a method to a
// released port was not an option, and [github.com/bernardoforcillo/authlayer/invite.Store] for the same
// per-concern split elsewhere in this codebase.
//
// Like [Store] it performs no authorization, no hashing and no token minting
// of its own, and reports not-found and conflict conditions through the
// sentinels above. Unlike [Store] it owns exactly one table, and in
// particular it does NOT own `users`: [IdentityStore.DeleteIdentityIfNotLast]'s
// userHasPassword parameter is where that boundary becomes visible, and that
// method's doc explains why the parameter is safe.
type IdentityStore interface {
	// CreateIdentity persists i and returns what was stored. Email is
	// normalized (see [NormalizeEmail]) before the write, so the caller
	// need not normalize it first.
	//
	// Returns ErrIdentityLinked when (i.Provider, i.Subject) is already
	// linked — the duplicate this port exists to refuse — or ErrIDTaken
	// when i.ID already identifies a row. An existing row is NEVER
	// silently replaced or re-pointed at a different user: re-pointing a
	// link is how one person's external account ends up signing in as
	// someone else.
	//
	// The uniqueness decision and the write MUST be one step, the same
	// discipline [Store.CreateUser] documents at length for ErrEmailTaken.
	// A SQL backend gets this from the composite UNIQUE constraint on
	// (provider, subject) by classifying its violation; an in-process map
	// gets it by holding one mutex across both, which is equivalent there
	// precisely because a map write has no independent failure mode of its
	// own.
	CreateIdentity(ctx context.Context, i Identity) (Identity, error)
	// FindIdentityByProviderSubject loads the identity for the external
	// account named by (provider, subject), returning ErrIdentityNotFound
	// when there is none.
	//
	// This is the primary resolution path for an external sign-in, and it
	// is by subject rather than by email on purpose — see this file's
	// package doc, "Why the subject, not the email, identifies the
	// account". provider and subject are matched byte-for-byte; neither is
	// normalized or case-folded.
	FindIdentityByProviderSubject(ctx context.Context, provider, subject string) (Identity, error)
	// ListIdentitiesByUser returns every identity belonging to userID, and
	// only that user's — never another's. A user with no identities is not
	// an error.
	//
	// Whether "no identities" comes back as an empty slice or a nil one is
	// deliberately unspecified: implementations differ, and a caller MUST
	// use len() rather than a nil comparison. Order is likewise
	// unspecified — sort the result if you depend on one.
	ListIdentitiesByUser(ctx context.Context, userID string) ([]Identity, error)
	// TouchIdentity stamps the identity's LastUsedAt with now, or returns
	// ErrIdentityNotFound when id matches no row. It is the only mutation
	// this port performs on an existing row.
	TouchIdentity(ctx context.Context, id string, now time.Time) error
	// DeleteIdentity removes the single identity named by its surrogate id,
	// or returns ErrIdentityNotFound when id matches no row. It removes that
	// row and nothing else — not the user's other identities, not another
	// user's row that happens to share a provider.
	//
	// # It makes NO reachability check, and that is not an oversight
	//
	// [IdentityStore.DeleteIdentityIfNotLast] exists because "unlink this
	// provider" is a user-initiated removal that must never leave an account
	// with no way in. This method is the opposite kind of operation: it is
	// how the service RETRACTS a row it wrote itself, and how the three
	// paths in [Service.ChangePassword]'s sweep matrix that sweep
	// identities remove them. No caller of it is removing a way in that the
	// account is relying on:
	//
	//   - [Service.SignInWith]'s compensating delete removes an identity the
	//     same call created a moment earlier, leaving the account exactly as
	//     the call found it. Refusing that delete would preserve precisely
	//     the bad link it exists to retract.
	//   - [Service.ResetPassword] sweeps AFTER [Store.UpdateUserPassword]
	//     has committed a fresh password, so the account holds a credential
	//     the sweep cannot touch. See that method's doc for the one
	//     configuration in which that password is not yet a WORKING
	//     credential, and why it is recoverable rather than a lockout.
	//   - [Service.DeleteAccount] and [Service.AnonymizeAccount] sweep on
	//     the way to removing or stamping the account itself. "No way in"
	//     is the outcome they exist to produce, so a reachability check
	//     here would refuse the one removal that is supposed to leave
	//     nothing behind.
	//
	// An application MUST NOT reach for this in place of
	// DeleteIdentityIfNotLast on a connected-accounts screen: this method
	// will happily remove an account's last credential, which is the
	// permanent, silent lockout that method's "It MUST be atomic" section
	// exists to prevent.
	//
	// The delete is one step; there is no check to be split from it.
	DeleteIdentity(ctx context.Context, id string) error
	// DeleteIdentityIfNotLast removes userID's identities for provider —
	// but ONLY if doing so leaves the account reachable, which is the case
	// when either another identity survives the delete or userHasPassword
	// is true. Otherwise it returns ErrLastCredential and removes nothing.
	// Returns ErrIdentityNotFound when the user has no identity for that
	// provider at all.
	//
	// Nothing in the data model forbids a user holding two identities for
	// the SAME provider, so this removes every row matching (userID,
	// provider) rather than an arbitrary one of them — "unlink this
	// provider from this account" — and the reachability test is on what
	// would REMAIN afterwards, not on the total row count.
	//
	// # It MUST be atomic
	//
	// The check ("does another way in survive?") and the delete MUST be a
	// single atomic step: one statement, one transaction, or one
	// acquisition of the mutex that serialises the store. A read-then-write
	// implementation does not satisfy this contract even if each half is
	// individually correct.
	//
	// This is not a theoretical concern, and it is the reason this method
	// exists at all instead of the obvious "list the identities, decide,
	// then delete" in the service layer. A user with exactly two identities
	// and no password unlinks both at once — two clicks, two tabs, a
	// retried request. Each call reads the identity list, sees a sibling,
	// concludes the account stays reachable, and deletes. Both deletes
	// succeed, the account now has no identity and no password, and NOTHING
	// in this package can sign that user in again: there is no credential
	// left to present. The lockout is permanent and silent — both requests
	// returned success. This project has shipped that exact read-then-write
	// shape four times ([Store.MarkRotated], invite's ConsumeLink,
	// [Store.CreateSuccessorSession], [Store.DeleteSessionsByFamily]) and
	// closed it four times; this method is shaped to make it unreachable
	// rather than to be gotten right by whoever calls it.
	//
	// # Why userHasPassword is a parameter and not a lookup
	//
	// It reads like a layering mistake — the store deciding a question it
	// then has to be TOLD the answer to — and it is not. An IdentityStore
	// owns the `identities` table and nothing else; `users` belongs to
	// [Store], which may be a different backend entirely, wired separately.
	// This port cannot read a password hash, and giving it the ability to
	// would mean handing the identity backend the credential table.
	//
	// The value the caller computes is "can this account authenticate with
	// its password", not "is a hash stored" — see
	// [Service.passwordCanAuthenticate] for why the two differ under
	// [WithRequireVerifiedEmail].
	//
	// What makes passing the value in SAFE, rather than merely necessary,
	// is the direction the value can go stale in. The caller reads the user
	// first, so a change landing between that read and this call could in
	// principle invalidate it — but only one of the two directions is
	// dangerous:
	//
	//   - false becoming true (the account acquires a working password
	//     mid-call): this method refuses a delete that would in fact have
	//     been safe. Fail-closed, self-correcting on retry.
	//   - true becoming false (the account LOSES its working password
	//     mid-call): this method would allow the delete that locks it out.
	//
	// The dangerous direction is HARMLESS through [Service] for the hash
	// itself, which is a weaker statement than this doc used to make and is
	// the true one. Three groups of methods touch the hash, and none of
	// them produces a lockout here:
	//
	//   - The two that WRITE one ([Service.ChangePassword],
	//     [Service.ResetPassword]) both write a freshly hashed, non-empty
	//     value. Neither can turn a true into a false.
	//   - [Service.AnonymizeAccount] genuinely does CLEAR the hash — it is
	//     the one "remove my password" this package has — but only as part
	//     of ending the account: it sweeps every identity first, then
	//     stamps [UserBase.DeletedAt], after which every authentication
	//     entry point refuses the row. An unlink racing it can pass a true
	//     that is false by the time the delete runs, and what it leaves
	//     behind is an account nobody may authenticate as by design. That
	//     is the state the concurrent call was creating, not a lockout the
	//     unlink caused.
	//   - [Service.DeleteAccount] removes the row entirely, likewise after
	//     sweeping the identities. There is no account left to lock out.
	//
	// So the guarantee survives, with a different justification: a stale
	// true is reachable, and the only calls that make it stale are ones
	// whose whole purpose is that the account can no longer be
	// authenticated.
	//
	// Under [WithRequireVerifiedEmail](true) the verified half CAN move the
	// other way, and this doc says so rather than pretending otherwise:
	// [Store.UpdateUserEmail] clears EmailVerifiedAt, and
	// [Service.VerifyEmail]'s email-change path calls it before re-stamping
	// the new address. An unlink whose read lands in that instant passes a
	// true that is false by the time the delete runs, and the account is left
	// with a password its configuration will not accept and no identity. That
	// is not the permanent lockout the password case would be: the account
	// still holds an address it has just proved control of, so
	// [Service.RequestPasswordReset] followed by [Service.ResetPassword]
	// certifies it again and restores the login.
	//
	// The other way to reach the dangerous transition is for an application
	// to call [Store.UpdateUserPassword] with an empty hash itself, or
	// [Store.UpdateUserEmail] directly, going around Service. An application
	// that does that has removed a credential this package has no idea about;
	// it must not concurrently unlink identities, and if it grows a "remove
	// my password" feature, that feature owes the same last-credential check
	// this method makes.
	DeleteIdentityIfNotLast(ctx context.Context, userID, provider string, userHasPassword bool) error
}

// identities resolves the configured [IdentityStore], or reports
// [ErrOAuthNotConfigured]. It is the single gate every entry point needing
// the optional port passes through, so "no identity store was wired" is one
// typed error in one place rather than a nil dereference in several.
func (s *Service) identities() (IdentityStore, error) {
	if s.cfg.identityStore == nil {
		return nil, ErrOAuthNotConfigured
	}
	return s.cfg.identityStore, nil
}
