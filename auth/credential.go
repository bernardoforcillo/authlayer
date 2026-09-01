// Package auth (this file) adds WebAuthn credentials — "passkeys", "security
// keys", "Touch ID", "Windows Hello" — to the credential model auth.go
// defines. Like auth/identity.go it is a separate file carrying a separate,
// OPTIONAL port ([CredentialStore], wired with [WithCredentialStore]), for
// the same released-port reason that file gives: adding methods to [Store]
// would break every third-party backend that already implements it, and
// passkeys are functionality a deployment may never enable. auth.go's package
// doc carries the argument for why account DELETION went the other way and
// landed on the core port; the distinction is unchanged here, so read it
// there rather than re-derived here.
//
// # THIS PACKAGE PERFORMS NO WEBAUTHN VERIFICATION
//
// It is worth being blunt, because everything else in this file depends on
// the reader having understood it. authlayer stores the credential records,
// mints and burns the ceremony challenges, checks the signature counter and
// issues the session. The APPLICATION verifies the ceremony, with a WebAuthn
// library of its choice, BEFORE it calls [Service.FinishPasskeyRegistration]
// or [Service.FinishPasskeyLogin].
//
// This package does NOT check, and has no code that could check:
//
//   - the ATTESTATION STATEMENT — its format, its certificate chain, its
//     trust anchors, or whether the authenticator is one you accept at all;
//   - the CLIENT DATA HASH, and with it the type field ("webauthn.create"
//     versus "webauthn.get") and the token-binding state;
//   - the ORIGIN in the client data — the check that stops a credential
//     minted for your site being asserted from an attacker's;
//   - the RP ID HASH in the authenticator data;
//   - the USER-PRESENCE (UP) and USER-VERIFICATION (UV) flags — whether a
//     human touched the authenticator at all, and whether a PIN or biometric
//     was checked;
//   - the ASSERTION SIGNATURE, and therefore the public key entirely. A
//     [Credential.PublicKey] is opaque bytes to this package: it is stored,
//     returned, and never parsed.
//
// An application that calls this package's Finish methods without performing
// every one of those checks itself has a passkey login that verifies
// NOTHING: [VerifiedAssertion] is trusted wholesale, so anyone who can reach
// the endpoint signs in as anyone whose credential id they know. Both input
// types say so on themselves; this list is here so that no reader of this
// file can reach the port below without having met it.
//
// # Why the boundary is here and not two layers down
//
// Milestone 2 hand-rolled a JWT, and that was defensible: one algorithm,
// HS256, a few hundred lines, and every other `alg` rejected before
// verification. WebAuthn is not comparable — CBOR decoding, COSE key
// parsing, attestation-statement verification and signature checking across
// several algorithms, where a subtle parsing bug is an authentication bypass
// rather than a crash. So this file takes exactly the boundary
// auth/identity.go took for OAuth: authlayer owns the records and the
// session issue, the application owns the protocol. There is no CBOR, no
// COSE and no attestation parsing in this repository, and adding a WebAuthn
// dependency to get them is deliberately out of scope.
//
// The consequence, stated rather than implied: the security of a passkey
// login built on this package rests on the caller's verifier as much as on
// anything here.
//
// # What clone detection this package does provide
//
// One thing, and only one: the signature counter. Every assertion carries an
// authenticator-maintained counter, and [CredentialStore.UpdateSignCount] is
// a compare-and-set that refuses a value which did not increase — which is
// the signal WebAuthn defines this data to produce when a credential has
// been cloned. [Service.FinishPasskeyLogin] refuses the login when the store
// refuses the counter ([ErrClonedAuthenticator]).
//
// It is worth knowing what that does NOT cover. Many modern authenticators —
// most platform passkeys, anything synced through a credential manager —
// report a counter of zero forever, because a credential that legitimately
// exists on several devices cannot maintain a single increasing counter. For
// those credentials there is no clone detection here or anywhere else; see
// [Service.FinishPasskeyLogin]'s "The zero counter" for how this package
// treats them and why refusing them instead would lock out most of the
// world's passkeys.
package auth

import (
	"context"
	"errors"
	"time"
)

// The two ceremonies a [Challenge] can be minted for. A challenge minted for
// one MUST NOT complete the other — see [Challenge.Ceremony].
const (
	// CeremonyRegistration marks a challenge minted by
	// [Service.BeginPasskeyRegistration], redeemable only through
	// [Service.FinishPasskeyRegistration].
	CeremonyRegistration = "passkey_registration"
	// CeremonyLogin marks a challenge minted by [Service.BeginPasskeyLogin],
	// redeemable only through [Service.FinishPasskeyLogin].
	CeremonyLogin = "passkey_login"
)

// defaultPasskeyChallengeTTL is the default for [WithPasskeyChallengeTTL]:
// how long a [Challenge] stays claimable. It is the shortest lifetime in this
// package by a wide margin — shorter even than a magic link's fifteen minutes
// — because it bounds an interactive ceremony a user is in the middle of, not
// a credential that has to survive a mail round trip. A browser prompt the
// user has left unanswered for five minutes is a ceremony they have
// abandoned; the application begins another.
const defaultPasskeyChallengeTTL = 5 * time.Minute

// Credential is one WebAuthn credential — one passkey — belonging to one
// local [UserBase]: the row that says "this authenticator credential signs
// this user in".
//
// A user may hold several (a phone, a laptop, a hardware key), and each is an
// independent way into the account, which is why removing the last one is
// guarded — see [CredentialStore.DeleteCredentialIfNotLast] and
// [ErrLastCredential].
//
// Nothing in it is verified by this package. PublicKey in particular is
// opaque bytes: see this file's package doc.
type Credential struct {
	// ID is the record's surrogate key, stamped by the service (uid.NewV7),
	// and is NOT the authenticator's own id — that is CredentialID.
	// [WithIDGenerator]'s "MUST be UUID-parseable to use store/drops"
	// constraint covers this column too.
	//
	// It is the id an application shows on a "your passkeys" screen and
	// passes to [Service.DeletePasskey], precisely because it is this
	// package's own value rather than a byte string the authenticator chose.
	ID string `drop:"id"`
	// UserID is the local account this credential signs in as.
	UserID string `drop:"user_id"`
	// CredentialID is the authenticator's OWN identifier for the credential
	// — the raw bytes of `PublicKeyCredential.rawId`, not a base64url
	// rendering of them. This package never parses it and never assumes it
	// looks like anything; it is matched byte-for-byte.
	//
	// An implementation MUST enforce that CredentialID is unique across
	// every Credential row — a UNIQUE constraint in a SQL backend. This is
	// [Identity.Subject]'s (provider, subject) analogue and it carries the
	// same weight: without it two rows can name the same authenticator
	// credential against two DIFFERENT users, and a login resolving that
	// credential id lands on whichever row the backend happens to return
	// first. That is one passkey silently able to sign in as either of two
	// people, decided by row order. This project has already shipped a
	// missing-uniqueness bug once (invite.EmailInvite.TokenHash), and the
	// consequence here is an authentication bypass rather than a duplicate
	// record.
	//
	// It is also why an EMPTY CredentialID is refused at the service
	// entry points ([ErrCredentialIDRequired]): empty is not a value that
	// misses, it is a key every credential-less registration would collide
	// on, and the first row written under it is what every later empty-id
	// login would resolve to.
	CredentialID []byte `drop:"credential_id"`
	// PublicKey is the credential public key exactly as the application's
	// WebAuthn library produced it — COSE_Key bytes, in whatever encoding
	// that library hands over.
	//
	// It is OPAQUE here. This package does not decode it, does not learn its
	// algorithm, and never verifies a signature with it: it is stored so the
	// application can verify the NEXT assertion with it, and handed back
	// unchanged by [Service.ListPasskeys]. See this file's package doc.
	PublicKey []byte `drop:"public_key"`
	// SignCount is the last signature counter this package accepted for the
	// credential — the authenticator's own monotonic use counter, from the
	// registration's authenticator data and then from each assertion's.
	//
	// It is a uint32 because that is what WebAuthn defines it as (a 32-bit
	// unsigned value), and a backend MUST be able to store the whole range:
	// a counter above 2^31 truncated into a signed 32-bit column compares
	// wrong, and the comparison is the only reason the value is stored at
	// all. store/drops uses bigint for exactly this reason.
	//
	// Zero is a legitimate value and, on many authenticators, a permanent
	// one — see this file's package doc, "What clone detection this package
	// does provide".
	SignCount uint32 `drop:"sign_count"`
	// Transports is the application's own record of how the authenticator
	// can be reached ("usb", "internal", "hybrid", …), stored verbatim as a
	// single string this package neither parses nor validates. WebAuthn
	// defines it as a list; how a list becomes this string (comma-joined,
	// JSON) is the application's choice, because the only consumer is the
	// application putting it back into the next request's allowCredentials.
	//
	// It is a HINT for the client, never a security input. Empty is fine.
	Transports string `drop:"transports"`
	// Label is the human-readable name for this credential on a "your
	// passkeys" screen — "MacBook Touch ID", "blue YubiKey". It is the
	// application's value, stored verbatim, never parsed, and never unique.
	// Empty is fine.
	Label string `drop:"label"`
	// CreatedAt is stamped by the service clock when the credential was
	// registered.
	CreatedAt time.Time `drop:"created_at"`
	// LastUsedAt is when this credential last signed the user in, or nil
	// when it never has — registered but not yet used. Stamped by
	// [CredentialStore.UpdateSignCount] on a winning compare-and-set and by
	// [CredentialStore.TouchCredential] on the counter-less path, which is
	// why those are the two methods that take a `now`.
	LastUsedAt *time.Time `drop:"last_used_at"`
}

// Challenge is one outstanding WebAuthn ceremony: the random value this
// package minted, the ceremony it was minted for, and when it stops being
// claimable.
//
// It is not a credential and holding one grants nothing. Its whole job is to
// make an assertion non-replayable: the application puts the challenge into
// the ceremony options, its verifier checks that the client data echoed the
// same challenge back, and this package then burns the row so a second
// presentation of the same assertion finds nothing to claim. That burn is
// the ONLY replay protection a zero-counter authenticator has here.
type Challenge struct {
	// ID is the record's surrogate key, stamped by the service (uid.NewV7).
	ID string `drop:"id"`
	// UserID is the account the ceremony was begun for, or nil when it names
	// no account.
	//
	// A REGISTRATION challenge always names one: it was begun by an
	// application that had already authenticated that user, and
	// [Service.FinishPasskeyRegistration] refuses a challenge minted for
	// somebody else ([ErrChallengeUser]).
	//
	// A LOGIN challenge never does, and cannot: [Service.BeginPasskeyLogin]
	// is called before anyone has been identified — that is the point of a
	// discoverable credential — so there is no account to bind it to. nil
	// here is that fact, in the same way [Credential.LastUsedAt]'s nil is
	// "never used" rather than a zero timestamp. A backend MUST be able to
	// store it as NULL; writing "" instead would fail a uuid column outright
	// and would make a login challenge look like a registration challenge
	// for a user whose id is the empty string.
	UserID *string `drop:"user_id"`
	// Ceremony is [CeremonyRegistration] or [CeremonyLogin]. Like
	// [Verification.Purpose] it is a plain string this port neither
	// validates nor enumerates: the service layer owns the closed set.
	//
	// The binding is load-bearing, not bookkeeping. Without it a challenge
	// minted for a registration — which any authenticated user can obtain
	// for their own account, freely — completes a LOGIN, and the two
	// ceremonies stop being separable at all.
	Ceremony string `drop:"ceremony"`
	// Hash is sha256 of the challenge string this package handed the caller
	// (see [github.com/bernardoforcillo/authlayer/token.HashOpaque]), and
	// the value every lookup is by.
	//
	// The challenge itself is not a secret — it is sent to the browser in
	// the clear, by design, and appears in the client data — so this is not
	// the "never store a bearer token in plaintext" rule
	// [Verification.TokenHash] follows. It is the same SHAPE for a smaller
	// reason: a one-time value looked up by hash cannot be lifted out of a
	// database dump and presented, and there is no cost to it.
	//
	// An implementation MUST enforce that Hash is unique across every
	// Challenge row, for the reason [Verification.TokenHash]'s doc gives:
	// [CredentialStore.FindChallengeByHash] assumes at most one row can
	// match, and without the constraint its result silently depends on row
	// order.
	Hash string `drop:"challenge_hash"`
	// ExpiresAt is when this challenge stops being claimable. Always set —
	// an unexpiring ceremony is a replay window that never closes.
	ExpiresAt time.Time `drop:"expires_at"`
	// CreatedAt is stamped by the service clock when the ceremony began.
	CreatedAt time.Time `drop:"created_at"`
}

// NewCredential is what an application hands
// [Service.FinishPasskeyRegistration] after its WebAuthn library has
// verified an attestation response.
//
// # EVERY FIELD IS TRUSTED AND NONE IS VERIFIED
//
// This package checks that CredentialID and PublicKey are non-empty, that
// Challenge names a live registration ceremony for the account being
// registered, and that CredentialID is not already registered. It checks
// NOTHING ELSE, and in particular it does not verify the attestation
// statement, the client data, the origin, the RP ID hash, the UP/UV flags,
// or that PublicKey is the key that was actually attested — see this file's
// package doc for the full list of what the caller owes.
//
// Constructing one of these from an UNVERIFIED attestation response — or
// from fields an untrusted client sent you directly — registers whatever
// public key the caller chose against the account, which is a permanent
// authentication bypass: the attacker holds the private half and can sign in
// as that user from then on. Build it only from your verifier's OUTPUT,
// never from its input.
type NewCredential struct {
	// Challenge is the value [Service.BeginPasskeyRegistration] returned for
	// this ceremony, echoed back byte-for-byte. This package hashes it and
	// claims the matching row; it is not compared against the client data
	// here, because this package never parses client data — your verifier
	// does that, and this field is how the ceremony it verified is named to
	// this package.
	Challenge string
	// CredentialID is the authenticator's raw credential id — see
	// [Credential.CredentialID]. Required: an empty value is refused with
	// [ErrCredentialIDRequired].
	CredentialID []byte
	// PublicKey is the credential public key your verifier extracted — see
	// [Credential.PublicKey], which stores it unchanged and unparsed.
	// Required: an empty value is refused with [ErrPublicKeyRequired],
	// because a credential with no key can never authenticate anything and
	// would be a row that only takes a credential id out of circulation.
	PublicKey []byte
	// SignCount is the counter from the registration's authenticator data —
	// the baseline every later assertion is compared against. Zero is
	// legitimate and common.
	SignCount uint32
	// Transports and Label are the application's own fields — see
	// [Credential.Transports] and [Credential.Label]. Both may be empty.
	Transports, Label string
}

// VerifiedAssertion is what an application hands [Service.FinishPasskeyLogin]
// after its WebAuthn library has verified an assertion response. The name is
// the honest one: it is the RESULT of a verification the caller performed,
// and this package's entire trust in the login rests on that verification
// having actually happened.
//
// # EVERY FIELD IS TRUSTED AND NONE IS VERIFIED
//
// This package looks CredentialID up, claims the challenge, checks the
// signature counter against the stored one, and mints a session for whoever
// the credential belongs to. It does not verify the assertion signature — it
// never reads the public key at all — nor the client data, the origin, the
// RP ID hash, or the UP/UV flags. See this file's package doc for the full
// list.
//
// So: constructing one of these from an UNVERIFIED assertion is an
// AUTHENTICATION BYPASS. A caller who fills this in from a request body,
// from an assertion whose signature failed, or from a library call whose
// error was ignored, hands a session to anyone who knows a credential id —
// and credential ids are not secret. They are sent to the client on every
// login attempt, and stored in browsers.
//
// If you find yourself building one of these anywhere except immediately
// after a successful verification, stop.
type VerifiedAssertion struct {
	// Challenge is the value [Service.BeginPasskeyLogin] returned for this
	// ceremony, echoed back byte-for-byte — the challenge your verifier
	// checked the client data against.
	Challenge string
	// CredentialID is the raw credential id the assertion named — see
	// [Credential.CredentialID]. Required: an empty value is refused with
	// [ErrCredentialIDRequired] before any store is touched.
	CredentialID []byte
	// SignCount is the counter the assertion's authenticator data carried.
	// [Service.FinishPasskeyLogin] refuses the login when it did not
	// increase — see that method, and [CredentialStore.UpdateSignCount].
	SignCount uint32
}

// Sentinel errors for the passkey surface. Compare with [errors.Is], never
// by string — the messages are not part of the API.
//
// They join the [Store] sentinels declared in auth.go rather than replacing
// them: a [CredentialStore] returns [ErrIDTaken] on a duplicate surrogate
// id, exactly as [Store.CreateUser] does, and [ErrLastCredential] is shared
// verbatim with the identity port — see its doc, whose arithmetic now spans
// all three credential kinds.
var (
	// ErrCredentialNotFound: no [Credential] matches the given credential id
	// or surrogate id. Returned by
	// [CredentialStore.FindCredentialByCredentialID],
	// [CredentialStore.UpdateSignCount], [CredentialStore.TouchCredential],
	// [CredentialStore.DeleteCredential] and
	// [CredentialStore.DeleteCredentialIfNotLast].
	ErrCredentialNotFound = errors.New("authlayer/auth: credential not found")
	// ErrCredentialRegistered: the authenticator credential id is already
	// registered — to this account or to another one. Returned by
	// [CredentialStore.CreateCredential], which never re-points an existing
	// row at a different user and never overwrites its public key.
	//
	// It is refused rather than treated as a re-registration for either
	// account, because a second row would carry a different public key and a
	// different counter and there is no honest way to choose between them —
	// and because re-pointing a credential id is how one person's
	// authenticator ends up signing in as someone else. See
	// [Credential.CredentialID]'s uniqueness MUST.
	ErrCredentialRegistered = errors.New("authlayer/auth: credential already registered")
	// ErrCredentialIDRequired: a [NewCredential] or [VerifiedAssertion]
	// arrived with an empty CredentialID. Returned by
	// [Service.FinishPasskeyRegistration] and [Service.FinishPasskeyLogin]
	// before either reads or writes anything.
	//
	// An empty credential id is not a harmless miss, for the reason
	// [ErrProviderSubjectRequired] gives about a blank subject: it is a key
	// every empty-id row collides on, so the first one written is what every
	// later empty-id login resolves to — one caller signed in as another —
	// and the only thing standing in the way is the uniqueness constraint,
	// which downgrades that takeover to a baffling conflict. Both are the
	// wrong answer to a malformed request, so it is refused as one.
	ErrCredentialIDRequired = errors.New("authlayer/auth: credential id required")
	// ErrPublicKeyRequired: a [NewCredential] arrived with an empty
	// PublicKey. Returned by [Service.FinishPasskeyRegistration] before
	// anything is read or written. A credential with no key can never verify
	// an assertion, so registering one would take a credential id out of
	// circulation in exchange for a credential that cannot authenticate.
	ErrPublicKeyRequired = errors.New("authlayer/auth: credential public key required")
	// ErrChallengeNotFound: no [Challenge] matches the presented value —
	// never minted, already claimed, or purged. Returned by
	// [CredentialStore.FindChallengeByHash], [CredentialStore.DeleteChallenge]
	// and both Finish methods.
	//
	// "Already claimed" is the common case and it is not an error condition
	// to be smoothed over: a challenge is single-use, so a second
	// presentation of the same ceremony MUST land here.
	ErrChallengeNotFound = errors.New("authlayer/auth: challenge not found")
	// ErrChallengeExpired: the challenge exists but its ExpiresAt has
	// passed. Checked before the claim, so an expired challenge is not
	// burned by the attempt — it is already unusable, and the row is the
	// [Service.PurgeExpired] janitor's business.
	ErrChallengeExpired = errors.New("authlayer/auth: challenge expired")
	// ErrChallengeCeremony: the challenge exists and is live, but was minted
	// for the OTHER ceremony — a registration challenge presented to
	// [Service.FinishPasskeyLogin], or the reverse. Checked before the
	// claim, matching [ErrVerificationPurpose]'s stance, so a
	// wrongly-presented challenge is not burned.
	//
	// This is the check that keeps the two ceremonies separable. Any
	// authenticated user can obtain a registration challenge for their own
	// account, freely and repeatedly; without this check that challenge
	// completes a LOGIN, and the only remaining question is whose credential
	// id the caller names.
	ErrChallengeCeremony = errors.New("authlayer/auth: challenge was minted for a different ceremony")
	// ErrChallengeUser: a live registration challenge was presented to
	// [Service.FinishPasskeyRegistration] for a DIFFERENT account than the
	// one it was minted for. Checked before the claim.
	//
	// Reaching it means the application mixed two ceremonies up, and the
	// safe reading of that is not "register it against the account the
	// caller named": that would attach a credential to an account whose
	// ceremony never happened.
	ErrChallengeUser = errors.New("authlayer/auth: challenge was minted for a different account")
	// ErrClonedAuthenticator: the assertion's signature counter did not
	// increase, so [CredentialStore.UpdateSignCount] refused it and
	// [Service.FinishPasskeyLogin] refused the login. NOTHING is issued.
	//
	// # What it means, precisely
	//
	// The stored counter is the highest this package has accepted for the
	// credential. An authenticator that maintains one increments it on every
	// assertion, so a value at or below the stored one means the assertion
	// came from something that is not the authenticator's current state:
	// WebAuthn defines this as the signal for a CLONED authenticator, and it
	// is also what a replayed assertion produces.
	//
	// It is a signal, not a proof. A legitimately restored, reset or
	// downgraded authenticator can produce it too, and so can an
	// authenticator whose counter is buggy. What is NOT a cause is the
	// authenticator that reports zero forever: those never reach this check
	// at all — see [Service.FinishPasskeyLogin]'s "The zero counter".
	//
	// The remedy an application offers is to authenticate by another means
	// and remove the credential ([Service.DeletePasskey]), then register the
	// authenticator again — which mints a fresh row with a fresh baseline.
	// Silently accepting the counter instead would discard the only clone
	// detection in this system.
	ErrClonedAuthenticator = errors.New("authlayer/auth: sign counter did not increase; authenticator may be cloned")
	// ErrPasskeysNotConfigured: an operation needing a [CredentialStore] was
	// attempted on a [Service] built without [WithCredentialStore].
	//
	// The port is optional — an application that offers no passkeys wires
	// none, and the [Store] it already has is untouched — so every entry
	// point that needs one resolves it through a single guard that returns
	// this, rather than dereferencing a nil interface. It mirrors
	// [ErrOAuthNotConfigured] exactly.
	ErrPasskeysNotConfigured = errors.New("authlayer/auth: no credential store configured")
)

// CredentialStore is the optional persistence port for passkeys: the
// `credentials` table and the ceremony-challenge table, and nothing else. It
// is deliberately NOT part of [Store] — see this file's package doc, and
// auth/identity.go's, for why adding methods to a released port was not an
// option.
//
// Like [Store] it performs no authorization, no hashing and no verification
// of its own, and reports not-found and conflict conditions through the
// sentinels above. Unlike [Store] it does NOT own `users`:
// [CredentialStore.DeleteCredentialIfNotLast]'s userHasOtherCredential
// parameter is where that boundary becomes visible, and that method's doc
// explains why the parameter is safe.
//
// # Why the challenges live here and not on [Store]
//
// A ceremony challenge is passkey state and nothing else: a deployment that
// wires no CredentialStore has no ceremonies to record, and giving [Store] a
// table it would never write would be a breaking change to a released port
// for a feature its implementer may not have. It is one port because the two
// tables are one feature — an implementation that has one and not the other
// cannot serve a single ceremony.
//
// A login challenge names no user (see [Challenge.UserID]), which is the
// concrete reason the existing [Verification] machinery could not carry
// these: every Verification is bound to a user AND to an email address, and
// a passkey login begins before either is known.
type CredentialStore interface {
	// CreateCredential persists c and returns what was stored.
	//
	// Returns ErrCredentialRegistered when c.CredentialID is already
	// registered — the duplicate this port exists to refuse — or ErrIDTaken
	// when c.ID already identifies a row. An existing row is NEVER silently
	// replaced or re-pointed at a different user, and its PublicKey is never
	// overwritten: both are how one person's authenticator ends up signing
	// in as someone else.
	//
	// The uniqueness decision and the write MUST be one step, the same
	// discipline [Store.CreateUser] documents at length for ErrEmailTaken. A
	// SQL backend gets this from the UNIQUE constraint on credential_id by
	// classifying its violation; an in-process map gets it by holding one
	// mutex across both, which is equivalent there precisely because a map
	// write has no independent failure mode of its own.
	CreateCredential(ctx context.Context, c Credential) (Credential, error)
	// FindCredentialByCredentialID loads the credential the authenticator
	// named, returning ErrCredentialNotFound when there is none.
	//
	// credentialID is matched BYTE-FOR-BYTE. It is not normalized, decoded,
	// re-encoded or trimmed anywhere in this package, and a backend MUST NOT
	// do any of those either: a credential id is opaque bytes chosen by an
	// authenticator, and a backend that folded them (a text column with a
	// collation, say) could make two distinct credentials collide.
	//
	// This is the whole resolution path for a passkey login — the account is
	// whatever this row names — which is why [Credential.CredentialID]'s
	// uniqueness MUST is what makes it a fact rather than a coin flip over
	// row order.
	FindCredentialByCredentialID(ctx context.Context, credentialID []byte) (Credential, error)
	// ListCredentialsByUser returns every credential belonging to userID,
	// and only that user's — never another's. A user with none is not an
	// error.
	//
	// Whether "none" comes back as an empty slice or a nil one is
	// deliberately unspecified: implementations differ, and a caller MUST
	// use len() rather than a nil comparison. Order is likewise unspecified
	// — sort the result if you depend on one.
	ListCredentialsByUser(ctx context.Context, userID string) ([]Credential, error)
	// UpdateSignCount is this port's compare-and-set, and the only clone
	// detection in this package.
	//
	// It sets the credential's SignCount to newCount and its LastUsedAt to
	// now — but ONLY when newCount is strictly greater than the stored
	// value. It reports (true, nil) when it applied the update, (false, nil)
	// when it refused it, and ErrCredentialNotFound when id matches no row
	// at all. A refusal is not an error: it is an answer, and
	// [Service.FinishPasskeyLogin] is what turns it into
	// [ErrClonedAuthenticator].
	//
	// # It MUST refuse a count that did not increase, atomically
	//
	// "Did not increase" covers both a counter that went BACKWARDS and one
	// that stood STILL: an authenticator maintaining a counter increments it
	// on every assertion, so an equal value is as much evidence of a replay
	// or a clone as a lower one. An implementation that accepts either has
	// silently deleted the only clone detection in this system, and every
	// captured assertion becomes replayable for as long as its challenge
	// lives.
	//
	// The comparison and the write MUST be a single atomic step — one
	// statement whose WHERE carries the predicate, or one acquisition of the
	// mutex that serialises the store. A read-then-write implementation lets
	// two concurrent presentations of the SAME assertion both observe the
	// old value, both conclude their counter is greater, and both win, which
	// is precisely the replay this method exists to refuse. It is the same
	// obligation [Store.MarkRotated] carries, for the same reason, and this
	// project has shipped the read-then-write shape four times elsewhere.
	//
	// It does NOT decide whether the counter should have been consulted at
	// all. An authenticator that reports zero forever would be refused by
	// this rule on its second login, so the SERVICE decides when to call
	// this and when to call TouchCredential instead — see
	// [Service.FinishPasskeyLogin]'s "The zero counter". Encoding that
	// exception here instead would make "0 accepts 0" a rule a backend could
	// get subtly wrong, and would put a WebAuthn policy decision inside a
	// persistence port.
	UpdateSignCount(ctx context.Context, id string, newCount uint32, now time.Time) (bool, error)
	// TouchCredential stamps the credential's LastUsedAt with now, leaving
	// SignCount untouched, or returns ErrCredentialNotFound when id matches
	// no row.
	//
	// It exists for the counter-less authenticators UpdateSignCount cannot
	// serve: a credential whose counter is zero and stays zero is used
	// legitimately, and its LastUsedAt must still move. Splitting it out
	// keeps UpdateSignCount a pure compare-and-set rather than one with an
	// "unless both are zero" exception carved into it. It mirrors
	// [IdentityStore.TouchIdentity].
	TouchCredential(ctx context.Context, id string, now time.Time) error
	// DeleteCredential removes the single credential named by its SURROGATE
	// id ([Credential.ID], not the authenticator's), or returns
	// ErrCredentialNotFound when id matches no row. It removes that row and
	// nothing else — not the user's other credentials, not another user's.
	//
	// # It makes NO reachability check, and that is not an oversight
	//
	// [CredentialStore.DeleteCredentialIfNotLast] exists because "remove
	// this passkey" is a user-initiated removal that must never leave an
	// account with no way in. This method is the opposite kind of operation:
	// it is how a caller that is removing the ACCOUNT, or sweeping every
	// credential a compromised account holds, takes a row out — cases where
	// refusing to remove the last one would preserve exactly what the caller
	// is trying to destroy. It mirrors [IdentityStore.DeleteIdentity], whose
	// doc makes the same distinction at length.
	//
	// An application MUST NOT reach for this in place of
	// DeleteCredentialIfNotLast on a "your passkeys" screen: this method
	// will happily remove an account's last credential, which is the
	// permanent, silent lockout that method exists to prevent.
	//
	// The delete is one step; there is no check to be split from it.
	DeleteCredential(ctx context.Context, id string) error
	// DeleteCredentialIfNotLast removes userID's credential named by its
	// surrogate id — but ONLY if doing so leaves the account reachable,
	// which is the case when either another of that user's credentials
	// survives the delete or userHasOtherCredential is true. Otherwise it
	// returns ErrLastCredential and removes NOTHING. Returns
	// ErrCredentialNotFound when id names no credential OF THAT USER — a
	// credential belonging to somebody else is not found here, ever, whether
	// or not the id exists.
	//
	// # It MUST be atomic
	//
	// The check ("does another way in survive?") and the delete MUST be a
	// single atomic step: one statement, one transaction, or one
	// acquisition of the mutex that serialises the store. A read-then-write
	// implementation does not satisfy this contract even if each half is
	// individually correct.
	//
	// [IdentityStore.DeleteIdentityIfNotLast]'s doc spells out the failure
	// in full and it is the same one here, reached by the same route: a user
	// with exactly two passkeys and no password removes both at once — two
	// clicks, two tabs, a retried request. Each call reads the list, sees a
	// sibling, concludes the account stays reachable, and deletes. Both
	// succeed, nothing in this package can sign that user in again, and both
	// requests returned success. The lockout is permanent and silent.
	//
	// # Why userHasOtherCredential is a parameter and not a lookup
	//
	// The same boundary [IdentityStore.DeleteIdentityIfNotLast] documents:
	// this port owns its own tables and nothing else. `users` belongs to
	// [Store] and the identities to [IdentityStore] — three ports that may
	// be three different backends, wired separately — so this one cannot
	// read a password hash or count identities, and giving it the ability to
	// would mean handing the passkey backend the credential table.
	//
	// The value the caller computes is "can this account authenticate by
	// something OTHER than a passkey" — a working password, or a linked
	// external identity — see [Service.DeletePasskey], which computes it,
	// and [ErrLastCredential], whose arithmetic now spans all three kinds.
	//
	// What makes passing the value in SAFE, rather than merely necessary, is
	// the direction it can go stale in, and the answer is the identity
	// port's answer with one addition:
	//
	//   - false becoming true (the account acquires another credential
	//     mid-call): this method refuses a delete that would in fact have
	//     been safe. Fail-closed, self-correcting on retry.
	//   - true becoming false (the account LOSES its other credential
	//     mid-call): this method would allow the delete that locks it out.
	//
	// The dangerous direction is unreachable through [Service] for the
	// password (no method removes one; both writers store a freshly hashed,
	// non-empty value) and for [WithRequireVerifiedEmail]'s verified half it
	// is the same recoverable window
	// [IdentityStore.DeleteIdentityIfNotLast] discloses. The addition is the
	// identity half: [Service.UnlinkIdentity] CAN remove the linked identity
	// this value stood on, concurrently. That leaves an account with neither
	// — but only if the unlink itself concluded the passkey being removed
	// here made it safe, which is the mirror-image race, and it is the one
	// case this pair of guards cannot see. It is disclosed rather than
	// closed: closing it needs a transaction spanning two ports that may be
	// two backends. A user removing their last identity and their last
	// passkey simultaneously, from two tabs, can lock themselves out; every
	// sequential ordering of the same two operations refuses the second.
	DeleteCredentialIfNotLast(ctx context.Context, userID, id string, userHasOtherCredential bool) error
	// DeleteCredentialsByUser removes EVERY credential belonging to userID,
	// and only that user's — never another's. Matching NO rows is SUCCESS,
	// never ErrCredentialNotFound.
	//
	// It is the PASSKEY column of [Service.ChangePassword]'s sweep matrix:
	// the primitive [Service.DeleteAccount] and [Service.AnonymizeAccount]
	// call so that a terminated account leaves no credential row behind. A
	// surviving row would be a working sign-in credential filed under a user
	// id that no longer resolves, and a later account issued that same id
	// under a non-random [WithIDGenerator] would INHERIT a passkey it never
	// registered — the identical argument [Service.DeleteAccount]'s step 6
	// makes for sweeping identities, one credential kind later.
	//
	// # It makes NO reachability check either, and MUST NOT
	//
	// [CredentialStore.DeleteCredentialIfNotLast] refuses to remove an
	// account's last way in. This is the other kind of operation
	// [CredentialStore.DeleteCredential]'s doc names, taken by user instead
	// of by row: its callers are removing the ACCOUNT, and refusing to
	// remove the last credential there would preserve exactly what the
	// caller is trying to destroy — a passkey-only account would become
	// undeletable. An application MUST NOT reach for this from a "your
	// passkeys" screen; that screen's method is DeleteCredentialIfNotLast.
	//
	// Zero rows matched being success is the stance
	// [MFAStore.DeleteTrustedDevicesByUser] and
	// [Store.DeleteVerificationsByUser] already take, for the same reason:
	// most accounts hold no passkey at all, and a deletion must not fail
	// because there was nothing to sweep.
	//
	// # All of them, or an error
	//
	// A backend either removes every one of that user's rows or reports an
	// error. Removing SOME and reporting success is the one shape this
	// method must never have: the caller has just deleted the account's
	// sessions and is about to delete its row, so a survivor is a live,
	// password-less way into an account that nothing else can find any more.
	// The conformance suite seeds three credentials for one user precisely
	// so that a one-row implementation is caught.
	//
	// There is no decision here to be split from the write, so unlike
	// DeleteCredentialIfNotLast this needs no transaction of its own: one
	// DELETE keyed on user_id, or one acquisition of the mutex that
	// serialises an in-process store.
	//
	// # Why this method could simply be added
	//
	// [CredentialStore] is UNRELEASED — it arrived with passkeys in this
	// same development cycle and has no third-party implementation to break
	// — so growing it costs nothing, and the sweep is a method on the port
	// rather than a list-then-delete loop in [Service] like
	// [Service.sweepIdentities]'s. That asymmetry is a fact about WHEN each
	// port shipped, not a judgement about which shape is better: [Store] is
	// released, which is the whole reason passkeys got a port of their own
	// (see this file's package doc), and [IdentityStore] had already shipped
	// by the time its own sweep was needed.
	DeleteCredentialsByUser(ctx context.Context, userID string) error
	// CreateChallenge persists c and returns what was stored. Returns
	// ErrIDTaken when c.ID already identifies a row.
	//
	// A duplicate c.Hash MUST be refused too — see [Challenge.Hash]'s
	// uniqueness MUST — though which error that is is left to the backend,
	// exactly as [Store.CreateVerification]'s token-hash duplicate is: the
	// value is 32 bytes from crypto/rand, so a collision is not a condition
	// a caller can act on differently.
	CreateChallenge(ctx context.Context, c Challenge) (Challenge, error)
	// FindChallengeByHash loads the challenge whose Hash matches, returning
	// ErrChallengeNotFound when none does. Assumes Hash identifies at most
	// one row — see that field's doc.
	//
	// It performs NO expiry and NO ceremony check: both belong to the
	// service layer, which does them before claiming so that a
	// wrongly-presented challenge is not burned.
	FindChallengeByHash(ctx context.Context, hash string) (Challenge, error)
	// DeleteChallenge removes a challenge by id, returning
	// ErrChallengeNotFound when no row matched. This is the CLAIM: it runs
	// before anything is issued, and its rows-affected gate is what makes
	// exactly one of any number of concurrent presentations of the same
	// challenge see a nil error.
	//
	// That single-winner property is a MUST, not an implementation detail.
	// It is the whole reason two callers finishing one ceremony cannot both
	// get a session, and it is the same obligation [Store.DeleteVerification]
	// carries for a magic link. An implementation that reports success for a
	// row it did not actually remove — because it checked existence first
	// and deleted afterwards, non-atomically — admits both.
	DeleteChallenge(ctx context.Context, id string) error
	// PurgeExpiredChallenges deletes every challenge whose ExpiresAt is
	// strictly before `before`, and returns how many rows were removed. It
	// is housekeeping, not a security boundary: an expired challenge is
	// already refused by [Service.FinishPasskeyLogin] and
	// [Service.FinishPasskeyRegistration] long before it is purged.
	//
	// It exists because [Service.BeginPasskeyLogin] is an UNAUTHENTICATED
	// endpoint that writes a row per call. Without a janitor the table grows
	// without bound at whatever rate a caller chooses; [Service.PurgeExpired]
	// is where a deployment calls this, on the same schedule it already
	// purges sessions and verifications.
	PurgeExpiredChallenges(ctx context.Context, before time.Time) (int, error)
}

// WithCredentialStore wires the OPTIONAL [CredentialStore] port, enabling
// passkeys (WebAuthn credentials). The default is nil: a Service built
// without this option persists no credentials and no ceremonies at all, and
// every entry point that needs the port refuses with
// [ErrPasskeysNotConfigured] rather than dereferencing nil. A nil s is
// ignored, leaving the default (or a prior option) in place.
//
// It is a separate port, not part of [Store], because [Store] is released:
// adding methods to it would break every third-party backend. See
// [CredentialStore]'s own doc, and auth/credential.go's package doc — which
// states, in a list, everything this package does NOT verify about a
// WebAuthn ceremony. Read that before wiring this.
func WithCredentialStore(s CredentialStore) Option {
	return func(c *config) {
		if s != nil {
			c.credentialStore = s
		}
	}
}

// WithPasskeyChallengeTTL sets how long a [Challenge] minted by
// [Service.BeginPasskeyRegistration] or [Service.BeginPasskeyLogin] stays
// claimable. The default is five minutes. A non-positive d is ignored,
// leaving the default (or a prior option) in place, matching
// [WithMagicLinkTTL] and every other TTL option here.
//
// It bounds an interactive ceremony rather than a mailed credential, which
// is why the default is the shortest in this package: the window is meant to
// cover a user reaching for their phone or touching a key, not a mail round
// trip. Raising it widens the window in which a captured assertion can be
// replayed against a zero-counter authenticator — the challenge burn is the
// only replay protection those have — so raise it for the ceremony's sake,
// not for a caller's convenience.
func WithPasskeyChallengeTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.passkeyChallengeTTL = d
		}
	}
}
