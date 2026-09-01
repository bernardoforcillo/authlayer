package auth

import (
	"context"
	"time"

	"github.com/bernardoforcillo/authlayer/token"
)

// credentials resolves the configured [CredentialStore], or reports
// [ErrPasskeysNotConfigured]. It is the single gate every passkey entry
// point passes through, so "no credential store was wired" is one typed
// error in one place rather than a nil dereference in several. It mirrors
// [Service.identities] exactly.
func (s *Service) credentials() (CredentialStore, error) {
	if s.cfg.credentialStore == nil {
		return nil, ErrPasskeysNotConfigured
	}
	return s.cfg.credentialStore, nil
}

// credentialKind names one of the three ways an account can be
// authenticated by this package: its password, an external identity, or a
// passkey. It exists only as the argument to [Service.hasWayInBesides] —
// "besides WHICH kind" — and is unexported because the question it answers
// is this package's own.
type credentialKind int

const (
	// kindPassword is a working password credential — see
	// [Service.passwordCanAuthenticate]. Nothing excludes it today: no
	// method in this package removes a password.
	kindPassword credentialKind = iota
	// kindIdentity is a linked external identity ([Identity]), removable by
	// [Service.UnlinkIdentity].
	kindIdentity
	// kindPasskey is a WebAuthn credential ([Credential]), removable by
	// [Service.DeletePasskey].
	kindPasskey
)

// hasWayInBesides answers the "last way in" question that [ErrLastCredential]
// is the refusal for: could u still authenticate through some credential kind
// OTHER than `excluding`?
//
// # It is ONE arithmetic, deliberately
//
// Three credential kinds can sign an account in — a working password, a
// linked identity, a passkey — and two of them are removable. Each remover
// ([Service.UnlinkIdentity], [Service.DeletePasskey]) has to tell its store
// whether the OTHER kinds leave a door open, because neither store can see
// the other's tables (see [IdentityStore.DeleteIdentityIfNotLast] and
// [CredentialStore.DeleteCredentialIfNotLast] for why that value is a
// parameter rather than a lookup). Computing it twice, once per remover, is
// how the two answers drift until one of them is wrong in the direction that
// locks an account out. So it is computed here, once, and the caller says
// only which kind is being removed.
//
// The kind being removed is EXCLUDED rather than counted, because the store
// performing the removal is the one that counts its own survivors, atomically,
// as part of the delete: DeleteIdentityIfNotLast counts the identities that
// outlive the unlink, DeleteCredentialIfNotLast the passkeys that outlive the
// delete. Counting them here as well would be a read-then-write duplicate of
// the decision those methods are shaped to make unreachable.
//
// # The password term is "can it authenticate", not "is a hash stored"
//
// [Service.passwordCanAuthenticate] answers it, and the difference is not
// academic: under [WithRequireVerifiedEmail](true) [Service.Login] refuses an
// unverified account outright, so a stored hash on such an account opens
// nothing and must not be counted as a way in. That predicate reads the same
// option Login reads, so the two cannot disagree.
//
// # An unwired optional port contributes nothing
//
// A [Service] with no [WithIdentityStore] cannot see identities and a
// [Service] with no [WithCredentialStore] cannot see passkeys, so each term
// is skipped when its port is absent. That is the fail-closed reading: a way
// in this Service cannot reach is not a way in this Service can offer, and
// counting a port it does not hold would let it authorize the removal of the
// only credential it CAN see. The limit is the one
// [Service.sweepIdentities] already states for itself — a second Service
// wired differently over the same tables is outside what this one can
// reason about.
//
// A store failure is returned as-is and the answer is false: fail closed.
// The caller must not treat an outage as "no other way in" OR as "some other
// way in" — it must not proceed at all.
//
// # Freshness, and the one race this cannot close
//
// The read is performed on every call, immediately before the delete it
// feeds, because both stores' staleness arguments depend on it being fresh.
// Those docs enumerate which direction is dangerous and which is merely
// fail-closed; the one window neither guard can see — an unlink and a passkey
// delete running concurrently, each standing on the credential the other is
// removing — is disclosed in full on
// [CredentialStore.DeleteCredentialIfNotLast] and is not closed here. Closing
// it needs a transaction spanning two ports that may be two backends.
func (s *Service) hasWayInBesides(ctx context.Context, u UserBase, excluding credentialKind) (bool, error) {
	if excluding != kindPassword && s.passwordCanAuthenticate(u) {
		return true, nil
	}
	if excluding != kindIdentity && s.cfg.identityStore != nil {
		rows, err := s.cfg.identityStore.ListIdentitiesByUser(ctx, u.ID)
		if err != nil {
			return false, err
		}
		if len(rows) > 0 {
			return true, nil
		}
	}
	if excluding != kindPasskey && s.cfg.credentialStore != nil {
		rows, err := s.cfg.credentialStore.ListCredentialsByUser(ctx, u.ID)
		if err != nil {
			return false, err
		}
		if len(rows) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// claimChallenge validates and then BURNS the ceremony challenge
// plainChallenge names. It is the half of both Finish methods that decides
// whether this ceremony may proceed at all, and a nil error is the permission
// to proceed — the claimed row itself carries nothing either caller needs.
//
// The order is the contract:
//
//  1. [CredentialStore.FindChallengeByHash] — an unknown, already-claimed or
//     purged value is [ErrChallengeNotFound].
//  2. Expiry — [ErrChallengeExpired].
//  3. Ceremony — [ErrChallengeCeremony] when the challenge was minted for
//     the other ceremony.
//  4. Account binding — [ErrChallengeUser] when forUser is non-nil and the
//     challenge names a different account. forUser is nil for a login, which
//     names no account and cannot (see [Challenge.UserID]).
//  5. [CredentialStore.DeleteChallenge] — the CLAIM.
//
// Steps 1–4 run BEFORE the claim, so a challenge presented to the wrong
// ceremony, to the wrong account, or after it expired is refused WITHOUT
// being burned — matching [Service.RedeemMagicLink]'s and
// [Service.VerifyEmail]'s identical stance on a wrongly-presented token. A
// caller who presents a registration challenge to a login has made a mistake;
// destroying the ceremony they are actually in the middle of is not the
// answer to it.
//
// # Claim before apply, and why it is not negotiable
//
// The claim runs before ANYTHING is issued, and
// [CredentialStore.DeleteChallenge]'s rows-affected gate is what makes
// exactly one of any number of concurrent presentations of the same challenge
// see a nil error. Both Finish methods therefore call this before they mint,
// register, or advance a counter.
//
// Minting first and burning afterwards would leave a window in which a second
// presentation of the SAME assertion finds its challenge still live and is
// admitted too — the identical defect
// [github.com/bernardoforcillo/authlayer/invite.Service.AcceptInvite] shipped
// and [Service.RedeemMagicLink] is built not to repeat. It matters more here
// than almost anywhere else in this package: for a zero-counter
// authenticator, and most platform passkeys are one, this burn is the ONLY
// replay protection that exists (see [Service.FinishPasskeyLogin], "The zero
// counter"). The signature counter cannot help; there is nothing else.
//
// The consequence, stated rather than implied: a failure AFTER the claim
// leaves the challenge burned and nothing issued, so the ceremony is not
// retryable and the application must begin another. That is the same
// disclosed, deliberate direction [Service.RedeemMagicLink] takes —
// under-granting rather than leaving a claimed one-time value live.
func (s *Service) claimChallenge(ctx context.Context, creds CredentialStore, plainChallenge, ceremony string, forUser *string, now time.Time) error {
	c, err := creds.FindChallengeByHash(ctx, token.HashOpaque(plainChallenge))
	if err != nil {
		return err
	}
	if !now.Before(c.ExpiresAt) {
		return ErrChallengeExpired
	}
	if c.Ceremony != ceremony {
		// Checked before the claim, and load-bearing rather than
		// bookkeeping: any authenticated user can obtain a registration
		// challenge for their own account, freely and repeatedly, so
		// without this that challenge completes a LOGIN and the only
		// remaining question is whose credential id the caller names. See
		// [ErrChallengeCeremony].
		return ErrChallengeCeremony
	}
	if forUser != nil && (c.UserID == nil || *c.UserID != *forUser) {
		return ErrChallengeUser
	}

	// The claim: exactly one caller ever sees a nil error for this id, and it
	// runs before anything is issued — see "Claim before apply" above.
	return creds.DeleteChallenge(ctx, c.ID)
}

// BeginPasskeyRegistration starts a WebAuthn registration ceremony for
// userID and returns the CHALLENGE the application must put into the
// creation options it hands the browser. The account is taken as given: the
// application has already authenticated userID by some other means, exactly
// as [Service.LinkIdentity] takes its own account as given.
//
// It requires [WithCredentialStore]; without it the call fails with
// [ErrPasskeysNotConfigured] before anything is read or written. An account
// that does not exist, or that has been ANONYMIZED (a non-nil
// [UserBase.DeletedAt] — see [Service.AnonymizeAccount]), is
// [ErrUserNotFound]: a registration challenge names its account in the row it
// writes, and arming a ceremony that could arm a new credential on a closed
// account is exactly what that stamp forbids.
//
// The returned value is NOT a secret and is not a credential. It is sent to
// the browser in the clear, by design, and echoed back inside the client
// data; holding one grants nothing at all. Its whole job is to make the
// resulting attestation non-replayable, which is why this package stores only
// its hash (see [Challenge.Hash]) and burns the row on the first successful
// [Service.FinishPasskeyRegistration].
//
// It stays claimable for [WithPasskeyChallengeTTL] (five minutes by default)
// and for ONE claim. Nothing is invalidated by beginning a second ceremony:
// unlike a magic link, a challenge is not a credential in a mailbox that a
// re-issue must retract, so a user who starts a registration on two tabs has
// two live challenges and either may complete. Both age out through
// [Service.PurgeExpired].
//
// # What this does NOT do
//
// It does not build the WebAuthn creation options. The relying-party id and
// name, the user handle, the algorithm list, the attestation conveyance, the
// authenticator selection criteria and the exclude-credentials list are the
// application's — this package has no opinion about any of them, and no code
// that could form one. Pass [Service.ListPasskeys]'s result to build
// excludeCredentials yourself.
//
// Above all it does not verify the response that comes back. See
// auth/credential.go's package doc for the full list of what the application
// owes before it calls [Service.FinishPasskeyRegistration].
func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID string) (string, error) {
	creds, err := s.credentials()
	if err != nil {
		return "", err
	}

	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	// An ANONYMIZED account arms no ceremony. See [Service.AnonymizeAccount],
	// "Every entry point that refuses a stamped account"; this check is
	// deliberately its own rather than one shared guard several paths reach.
	if u.DeletedAt != nil {
		return "", ErrUserNotFound
	}

	plainChallenge, hash, err := token.GenerateOpaque()
	if err != nil {
		return "", err
	}

	now := s.cfg.clock()
	// A registration challenge always names its account — that is what
	// [Service.FinishPasskeyRegistration]'s ErrChallengeUser check compares
	// against, and it is taken from the row just read rather than from the
	// argument, so the id stored is one that exists.
	owner := u.ID
	if _, err := creds.CreateChallenge(ctx, Challenge{
		ID:        s.cfg.idGen(),
		UserID:    &owner,
		Ceremony:  CeremonyRegistration,
		Hash:      hash,
		ExpiresAt: now.Add(s.cfg.passkeyChallengeTTL),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return plainChallenge, nil
}

// FinishPasskeyRegistration records the credential the application's WebAuthn
// library just VERIFIED, attaching it to userID, and returns the stored
// [Credential]. It mints no session: registering a passkey is something an
// already-authenticated user does, not a way of becoming one.
//
// # It verifies nothing about the ceremony
//
// [NewCredential] is trusted wholesale. This method checks that CredentialID
// and PublicKey are non-empty, that Challenge names a live registration
// ceremony minted for THIS account, that the account exists and is not
// anonymized, and that the credential id is not already registered. It does
// not verify the attestation statement, the client data, the origin, the RP
// ID hash, or the UP/UV flags, and it never parses PublicKey — see
// auth/credential.go's package doc for the full list, and [NewCredential]'s
// own doc for what building one from an unverified response registers.
//
// # Order of checks
//
// Everything that can be decided before the challenge is claimed is decided
// before it, so a malformed or misdirected call does not destroy the ceremony
// the user is in the middle of:
//
//  1. The port — [ErrPasskeysNotConfigured].
//  2. An empty CredentialID ([ErrCredentialIDRequired]) or PublicKey
//     ([ErrPublicKeyRequired]), before any store is touched at all. See those
//     sentinels for why an empty credential id is refused rather than stored.
//  3. The account — [ErrUserNotFound] for a row that is gone or ANONYMIZED
//     (a non-nil [UserBase.DeletedAt]). Arming a new credential on a stamped
//     account would hand it back, which is what that stamp forbids.
//  4. The challenge: not found, expired ([ErrChallengeExpired]), minted for a
//     LOGIN ([ErrChallengeCeremony]), or minted for a different account
//     ([ErrChallengeUser]) — then, and only then, BURNED. See
//     [Service.claimChallenge].
//  5. [CredentialStore.CreateCredential], whose uniqueness constraint on the
//     credential id is what returns [ErrCredentialRegistered] for an
//     authenticator already registered — to this account or to another one.
//     The refusal is the store's and it is atomic with the write; there is no
//     check here to be raced.
//
// Step 5 running after the burn means a refused registration costs the caller
// its ceremony: the challenge is gone and the application must begin another.
// That is the deliberate direction — see [Service.claimChallenge], "Claim
// before apply".
//
// The returned [Credential] carries this package's own [Credential.ID], which
// is what a "your passkeys" screen shows and what [Service.DeletePasskey]
// takes; [Credential.LastUsedAt] is nil, because registering is not using.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID string, c NewCredential) (Credential, error) {
	var zero Credential

	creds, err := s.credentials()
	if err != nil {
		return zero, err
	}
	if len(c.CredentialID) == 0 {
		return zero, ErrCredentialIDRequired
	}
	if len(c.PublicKey) == 0 {
		return zero, ErrPublicKeyRequired
	}

	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return zero, err
	}
	// An ANONYMIZED account registers nothing, however well the ceremony
	// verified. See [Service.AnonymizeAccount], "Every entry point that
	// refuses a stamped account".
	if u.DeletedAt != nil {
		return zero, ErrUserNotFound
	}

	now := s.cfg.clock()
	if err := s.claimChallenge(ctx, creds, c.Challenge, CeremonyRegistration, &u.ID, now); err != nil {
		return zero, err
	}

	return creds.CreateCredential(ctx, Credential{
		ID:           s.cfg.idGen(),
		UserID:       u.ID,
		CredentialID: c.CredentialID,
		PublicKey:    c.PublicKey,
		SignCount:    c.SignCount,
		Transports:   c.Transports,
		Label:        c.Label,
		CreatedAt:    now,
		// LastUsedAt stays nil: this credential was registered, not used.
		// nil is how a caller tells the two apart.
	})
}

// BeginPasskeyLogin starts a WebAuthn authentication ceremony and returns the
// CHALLENGE the application puts into the request options it hands the
// browser. It names no account and takes none: a discoverable credential
// identifies its user at the END of the ceremony, which is the whole point of
// passkeys as a sign-in method.
//
// It requires [WithCredentialStore]; without it the call fails with
// [ErrPasskeysNotConfigured]. It reads no user, touches no account, and
// therefore cannot answer "does this address have a passkey?" for anybody —
// there is nothing here to enumerate.
//
// The returned value is not a secret and not a credential; see
// [Service.BeginPasskeyRegistration] for what it is and is not. It stays
// claimable for [WithPasskeyChallengeTTL] and for one claim.
//
// # This is an UNAUTHENTICATED endpoint that writes a row
//
// Every call inserts one [Challenge], and nothing here bounds the rate: this
// method takes no ip and consults no [RateLimiter], because it has no
// identifier to key one by and inventing one would be an ip parameter that
// does nothing but populate a bucket. Two things bound the table instead, and
// an application needs both:
//
//   - [Service.PurgeExpired], which removes challenges past their TTL. It is
//     the reason [CredentialStore.PurgeExpiredChallenges] exists, and a
//     deployment that never schedules it has a table that grows at whatever
//     rate a caller chooses.
//   - The application's own edge — the same place it rate-limits any other
//     unauthenticated POST. This package cannot do it for you here.
//
// The rows themselves are inert: a challenge grants nothing, names nobody,
// and is useless without an assertion signed by a private key the caller does
// not have.
func (s *Service) BeginPasskeyLogin(ctx context.Context) (string, error) {
	creds, err := s.credentials()
	if err != nil {
		return "", err
	}

	plainChallenge, hash, err := token.GenerateOpaque()
	if err != nil {
		return "", err
	}

	now := s.cfg.clock()
	if _, err := creds.CreateChallenge(ctx, Challenge{
		ID: s.cfg.idGen(),
		// UserID stays nil: this ceremony began before anyone was
		// identified, and nil is that fact — see [Challenge.UserID].
		Ceremony:  CeremonyLogin,
		Hash:      hash,
		ExpiresAt: now.Add(s.cfg.passkeyChallengeTTL),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return plainChallenge, nil
}

// FinishPasskeyLogin signs in the account the assertion's credential belongs
// to, returning the same [LoginResult] [Service.Login] and
// [Service.RedeemMagicLink] do: a scrubbed [UserBase], a signed access token
// and a refresh token. There is no password step and nothing else is asked —
// the assertion IS the authentication.
//
// # It verifies nothing, and that is the whole shape of this method
//
// [VerifiedAssertion] is trusted wholesale: this package looks
// a.CredentialID up, claims a.Challenge, checks a.SignCount against the
// stored counter, and mints. It does NOT verify the assertion signature — it
// never reads [Credential.PublicKey] at all — nor the client data, the
// origin, the RP ID hash, or the UP/UV flags. Read that type's doc and
// auth/credential.go's package doc before wiring this to an HTTP handler: a
// caller who fills a VerifiedAssertion in from a request body has built a
// sign-in-as-anyone endpoint, because credential ids are not secret.
//
// ip and userAgent are recorded on the new [Session] exactly as
// [Service.Login] records its own. An empty ip is not refused here, for
// [Service.RedeemMagicLink]'s reason: Login's [ErrMissingIP] exists because
// an empty ip collapses every caller into one [RateLimiter] bucket, and this
// method consults no limiter.
//
// # Order of checks
//
//  1. The port — [ErrPasskeysNotConfigured].
//  2. An empty a.CredentialID — [ErrCredentialIDRequired], before any store
//     is touched.
//  3. [CredentialStore.FindCredentialByCredentialID] — the whole resolution
//     path. The account is whatever that row names; there is no address and
//     no other input. [ErrCredentialNotFound] for an unknown credential id.
//  4. The account — [ErrUserNotFound] for a row that is gone or ANONYMIZED (a
//     non-nil [UserBase.DeletedAt]). A stamped account may not be
//     authenticated by any route, and a surviving credential row is a fact
//     about foreign keys, not about whether the account exists.
//  5. The challenge: not found, expired, or minted for a REGISTRATION
//     ([ErrChallengeCeremony]) — then BURNED. See [Service.claimChallenge].
//  6. The signature counter — see below. [ErrClonedAuthenticator].
//  7. mintSession.
//
// Steps 3 and 4 run before the claim so a stale or wrong credential id does
// not destroy a live ceremony. Step 6 runs AFTER it, deliberately: an
// assertion suspected of being a clone or a replay must not leave its
// challenge claimable for the next attempt, and the caller who meets
// ErrClonedAuthenticator is not a caller whose ceremony deserves preserving.
//
// # The signature counter, and the zero counter
//
// Every assertion carries the authenticator's own use counter, and this is
// the only clone detection in this package. [CredentialStore.UpdateSignCount]
// is a compare-and-set that applies a.SignCount only when it is strictly
// greater than the stored value; when it refuses, this method refuses the
// LOGIN with [ErrClonedAuthenticator] and issues nothing. Accepting the
// counter and signing the user in anyway would discard the detection
// entirely — the data would be recorded and never acted on, which is worse
// than not recording it, because it reads like a control that is not there.
//
// There is one documented exception, and it is a WebAuthn rule rather than a
// convenience. An authenticator that reports a counter of ZERO and a stored
// counter of zero does not maintain one at all — most platform passkeys and
// everything synced through a credential manager are in this category,
// because a credential that legitimately lives on several devices cannot
// keep a single increasing count. Applying the compare-and-set to those would
// refuse every login after the first. So when BOTH the asserted and the
// stored counter are zero, this method calls
// [CredentialStore.TouchCredential] instead: LastUsedAt moves, the counter
// does not, and no clone detection was available to be given up.
//
// The exception is exactly that narrow. A stored counter of 5 with an
// asserted 0 is a DECREASE and is refused; a stored 0 with an asserted 5 is
// an increase and is applied, and from then on that credential is held to the
// counter forever.
//
// For a zero-counter credential the challenge burn in step 5 is therefore the
// ONLY thing standing between a captured assertion and a replay, which is why
// [WithPasskeyChallengeTTL]'s default is the shortest lifetime in this
// package.
//
// # A passkey IS the second factor
//
// This is the ONE sign-in door that does not consult an [MFAFactor]. An
// account holding a confirmed TOTP factor signs in here outright — no
// [MFAChallenge], no [ErrMFARequired], not even under [EnforcementRequired]
// — where [Service.Login], [Service.RedeemMagicLink] and
// [Service.SignInWith] all stop and demand one.
//
// A passkey is a private key bound to hardware the user holds, registered to
// THIS account through this package's own [CredentialStore] and resolvable
// to no other. It is a possession factor by construction, and it shares no
// channel with the password or the mailbox — which is exactly what the other
// two doors fail: a magic link arrives where a password reset arrives, and
// an external assertion carries no statement about what the provider
// checked. Demanding a TOTP code on top of a passkey is a second factor
// demanded of a second factor.
//
// The decision rests on the caller, and that is worth naming twice. This
// method verifies nothing (see above), so "a passkey authenticated this" is
// the CALLER's claim; and this package never sees the WebAuthn
// user-verification (UV) flag, so it cannot tell a passkey unlocked with a
// biometric or a PIN from one that merely sat plugged in. A deployment that
// needs UV must require it in its verifier, because nothing here can.
// auth/mfa_service.go's package doc, "What the second factor gates, door by
// door", holds the matrix all four doors are decided in.
//
// # What a successful login does NOT do
//
// It verifies no email address ([Service.RedeemMagicLink] does, because a
// link had to be delivered to one; an assertion proves possession of a
// private key and says nothing about a mailbox) and it does not consult
// [WithRequireVerifiedEmail], which governs [Service.Login]'s password path.
// It revokes nothing: signing in on a new device is not a revocation event,
// exactly as it is not for Login.
//
// A Store, [CredentialStore] or [token.Issue] error at any step is returned
// as-is — see the package's "Fail closed" constraint. After the claim has
// succeeded such a failure leaves the challenge burned and no session issued;
// the application must begin another ceremony.
func (s *Service) FinishPasskeyLogin(ctx context.Context, a VerifiedAssertion, ip, userAgent string) (LoginResult, error) {
	var zero LoginResult

	creds, err := s.credentials()
	if err != nil {
		return zero, err
	}
	if len(a.CredentialID) == 0 {
		return zero, ErrCredentialIDRequired
	}

	// The whole resolution path: the account is whatever this row names. See
	// [Credential.CredentialID]'s uniqueness MUST for what makes that a fact
	// rather than a coin flip over row order.
	cred, err := creds.FindCredentialByCredentialID(ctx, a.CredentialID)
	if err != nil {
		return zero, err
	}

	u, err := s.store.FindUserByID(ctx, cred.UserID)
	if err != nil {
		return zero, err
	}
	// An ANONYMIZED account is authenticated by nothing, by any route. See
	// [Service.AnonymizeAccount], "Every entry point that refuses a stamped
	// account".
	if u.DeletedAt != nil {
		return zero, ErrUserNotFound
	}

	now := s.cfg.clock()
	if err := s.claimChallenge(ctx, creds, a.Challenge, CeremonyLogin, nil, now); err != nil {
		return zero, err
	}

	// The counter, after the claim and before the session — see "The
	// signature counter, and the zero counter" above.
	if a.SignCount == 0 && cred.SignCount == 0 {
		// A counter-less authenticator. Record the use; there is no
		// compare-and-set to be had.
		if err := creds.TouchCredential(ctx, cred.ID, now); err != nil {
			return zero, err
		}
	} else {
		applied, err := creds.UpdateSignCount(ctx, cred.ID, a.SignCount, now)
		if err != nil {
			return zero, err
		}
		if !applied {
			// The store refused a counter that did not increase. Refuse the
			// LOGIN — this is the only clone detection in the package, and
			// signing in anyway would discard it.
			return zero, ErrClonedAuthenticator
		}
	}

	// One minting path, shared with [Service.Login] — see mintSession.
	return s.mintSession(ctx, u, ip, userAgent)
}

// ListPasskeys returns the WebAuthn credentials registered to userID, and
// only that user's — it is a scoped pass-through to
// [CredentialStore.ListCredentialsByUser], never a listing of anyone else's
// rows. An application renders it as a "your passkeys" screen, and uses it to
// build the excludeCredentials list for the next
// [Service.BeginPasskeyRegistration].
//
// It requires [WithCredentialStore]; without it the call fails with
// [ErrPasskeysNotConfigured].
//
// A user with no passkeys is not an error, and neither is a userID that names
// no account: both come back empty, which keeps this from answering "does
// this account exist?" for a caller who should not be asking. A store failure
// IS an error and is returned as-is — an empty list is a statement an
// application acts on, so an outage must not be able to make one. Whether
// "none" arrives as an empty or a nil slice is the port's business and
// deliberately unspecified: use len().
//
// Each [Credential.PublicKey] comes back exactly as it was stored, unparsed.
// It is the application's input to the NEXT assertion's verification, and it
// is the only reason this package keeps it at all.
func (s *Service) ListPasskeys(ctx context.Context, userID string) ([]Credential, error) {
	creds, err := s.credentials()
	if err != nil {
		return nil, err
	}
	return creds.ListCredentialsByUser(ctx, userID)
}

// DeletePasskey removes userID's credential named by credentialRowID — the
// surrogate [Credential.ID] a "your passkeys" screen shows, NOT the
// authenticator's own credential id.
//
// It requires [WithCredentialStore]; without it the call fails with
// [ErrPasskeysNotConfigured].
//
// A credentialRowID that names no credential OF THAT USER is
// [ErrCredentialNotFound] — including one that names somebody else's, which
// is never found here and never removed. One account must not be able to
// remove another's way in by naming it.
//
// # It refuses to remove the account's last way in
//
// With no other passkey surviving the delete, no WORKING password credential
// and no linked identity, the call fails with [ErrLastCredential] and removes
// NOTHING. An account in that state would be authenticated by nothing in this
// package: [Service.Login] refuses an empty PasswordHash,
// [Service.SignInWith] has no link to resolve, and there would be no
// credential left to assert. The lockout would be permanent and silent.
//
// The arithmetic is [Service.hasWayInBesides], the SAME computation
// [Service.UnlinkIdentity] uses with the other kind excluded — one function,
// so the two removers cannot drift into disagreeing about what a way in is.
// It asks "can this account authenticate", not "is a hash stored": under
// [WithRequireVerifiedEmail](true) a hash on an unverified account opens
// nothing, and counting it would let this method remove the only door that
// does open. It errs strict, which is the safe direction — a refusal removes
// nothing and the user can retry after verifying.
//
// The surviving PASSKEYS are counted by
// [CredentialStore.DeleteCredentialIfNotLast] itself, atomically with the
// delete, which is why that method has the shape it does: a "list, decide,
// delete" here would reopen the read-then-write race that leaves a user with
// two passkeys and no password holding neither. See its "It MUST be atomic".
//
// # What this does not revoke
//
// Sessions. Removing one passkey leaves every [Session] the account holds
// exactly as it found it, and that is a decision rather than an omission —
// it is the one place this method deliberately differs from
// [Service.UnlinkIdentity], which sweeps every family.
//
//   - The two operations are not the same size. UnlinkIdentity removes EVERY
//     row at a provider — "this account is not mine any more", a categorical
//     statement about a whole credential source. This removes ONE credential
//     out of a set whose other members are, by the guard above, still there
//     and still working.
//   - A [Session] records no credential provenance — nothing in the row says
//     which credential minted it, and a rotated successor would not carry it
//     anyway — so a sweep here could only be all-or-nothing. Signing a user
//     out on their phone because they tidied an old laptop off their passkey
//     list is not what that screen says it does.
//   - The application keeps the choice, and it is one line: "removing a
//     passkey signs you out everywhere" composes from [Service.LogoutAll],
//     which is authenticated and unambiguous. The composition
//     [Service.VerifyEmail]'s doc offers for an address change is the same
//     one, for the same reason.
//
// An application removing a passkey because the DEVICE was lost should call
// LogoutAll too, and its UI should say so.
//
// The order is load-bearing in the small, matching UnlinkIdentity: the
// account is read fresh immediately before the delete, so the value handed
// down is the account's real, current state — passing a constant true would
// be exactly the lockout above, wearing a successful return.
func (s *Service) DeletePasskey(ctx context.Context, userID, credentialRowID string) error {
	creds, err := s.credentials()
	if err != nil {
		return err
	}

	// Read the credential state fresh, immediately before the delete: see
	// [Service.hasWayInBesides], "Freshness, and the one race this cannot
	// close", and [CredentialStore.DeleteCredentialIfNotLast]'s own staleness
	// argument, which this ordering is what makes true.
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}
	otherWayIn, err := s.hasWayInBesides(ctx, u, kindPasskey)
	if err != nil {
		return err
	}

	// The decision and the delete are ONE atomic step inside the store.
	return creds.DeleteCredentialIfNotLast(ctx, userID, credentialRowID, otherWayIn)
}
