// Package auth (this file) adds the second-factor state — an enrolled TOTP
// factor and its single-use recovery codes — to the credential model
// auth.go defines. The algorithm itself lives in
// [github.com/bernardoforcillo/authlayer/internal/totp]; this file is the
// persistence port and the types that cross it.
//
// # Why this is a separate optional port, and not four more methods on Store
//
// auth.go's package doc already argues the general question at length,
// under "Deletion, and why it is on this port rather than beside it": the
// test is not how many methods a port has, it is whether a backend that
// cannot do this thing is still a conforming backend. Deletion failed that
// test — every deployment eventually removes an account, so a Store that
// cannot is one nobody can finish deploying — and grew [Store] by four
// methods. [IdentityStore] passed it and became a separate, optional port.
//
// MFA lands on IdentityStore's side, and for the same reason: a second
// factor is FUNCTIONALITY. A deployment may never offer one, and a backend
// that cannot store a factor is a complete backend for every deployment
// that does not enable MFA. Requiring all eight of these methods of every
// existing [Store] implementation would charge every backend author for a
// feature most will never switch on. So [MFAStore] is wired with
// [WithMFAStore], is absent by default, and every entry point needing it
// resolves it through one guard that returns [ErrMFANotConfigured] rather
// than dereferencing nil.
//
// # Secrets are encrypted at rest, and enrolment refuses without a cipher
//
// A TOTP secret is not a password hash. It is the exact bearer credential
// the user's authenticator holds: whoever reads it can generate valid codes
// forever, for that account, without the user noticing. A database dump
// full of plaintext TOTP secrets is therefore not a partial disclosure the
// way a dump of bcrypt hashes is — it is a working second-factor bypass for
// every enrolled user at once, and the second factor exists precisely to
// survive the compromise that produced the dump.
//
// So [MFAFactor.SecretEnc] holds ciphertext, produced by the [Cipher] wired
// with [WithMFASecretCipher], and a Service with no cipher configured
// REFUSES TO ENROL rather than storing a plaintext secret. That is the
// fail-closed direction: an application whose operator forgot to configure
// a key gets a loud refusal at enrolment, not a table quietly filling with
// bearer credentials. This port never sees plaintext; it stores and returns
// the string it is given.
package auth

import (
	"context"
	"errors"
	"time"
)

// MFAFactor is one account's TOTP second factor. A user has at most one —
// the record is keyed by [MFAFactor.UserID], with no surrogate id — so
// re-enrolling REPLACES the factor rather than adding a second one. See
// [MFAStore.UpsertFactor], whose whole-row replacement is what makes that
// true.
//
// # What it deliberately does not carry
//
// No digit count, no period, no algorithm. Those are Service configuration,
// not per-factor state, which has one visible consequence worth stating
// plainly: changing a Service's TOTP parameters invalidates every factor
// already enrolled under the old ones, because the codes an authenticator
// generates from the same secret will no longer be the codes this Service
// computes. Treat such a change as a re-enrolment of the whole user base,
// not a configuration tweak.
type MFAFactor struct {
	// UserID is the account this factor belongs to, and the record's key.
	// An implementation MUST enforce that at most one row exists per user —
	// a PRIMARY KEY or UNIQUE constraint on the column in a SQL backend.
	// Two rows for one user would make [MFAStore.FindFactor] return
	// whichever the backend happened to reach first, so which secret
	// authenticates the account, and which LastStep guards it, would be
	// decided by row order.
	UserID string `drop:"user_id,pk"`
	// SecretEnc is the TOTP secret ENCRYPTED with the configured [Cipher] —
	// never the base32 secret itself. See this file's package doc for why a
	// plaintext column here is a second-factor bypass for the whole user
	// base, and [WithMFASecretCipher] for the refusal that keeps one from
	// existing.
	//
	// This port neither encrypts nor decrypts: it stores the string it is
	// handed and returns it unchanged.
	SecretEnc string `drop:"secret_enc"`
	// ConfirmedAt is when the user proved they had actually scanned the
	// secret, by presenting a valid code, or nil when they have not yet.
	//
	// nil is the load-bearing state, not an incidental one: an UNCONFIRMED
	// factor MUST NEVER gate a login. A user who scans nothing, or scans
	// into an app that then fails, would otherwise be locked out of their
	// own account by an enrolment they never completed. It is stamped
	// exactly once, by [MFAStore.ConfirmFactor]'s compare-and-set, and
	// nothing in this port clears it — a factor leaves the unconfirmed
	// state once and does not re-enter it, because re-enrolment writes a
	// whole new row through [MFAStore.UpsertFactor].
	ConfirmedAt *time.Time `drop:"confirmed_at"`
	// CreatedAt is when enrolment began, stamped by the service clock.
	CreatedAt time.Time `drop:"created_at"`
	// LastStep is the highest TOTP step this factor has already
	// authenticated with, or nil when it has authenticated none.
	//
	// It is the REPLAY GUARD's whole state. TOTP accepts a window of steps
	// either side of the server's own so the two clocks need not agree
	// exactly, and that window is also how long a code stays usable after
	// someone reads it over the user's shoulder or off a screen share.
	// Recording the step that was used, and refusing that step and every
	// earlier one, cuts that reuse window to nothing. See
	// [MFAStore.AdvanceStep], which is the compare-and-set that maintains
	// it, and internal/totp.Validate, which returns the matched step for
	// exactly this purpose.
	LastStep *int64 `drop:"last_step"`
}

// RecoveryCode is one single-use code that stands in for a TOTP code when
// the user has lost their authenticator. A user holds a set of them,
// generated at enrolment and replaced wholesale by
// [MFAStore.ReplaceRecoveryCodes].
//
// It is a credential the user still holds and may need, which is what
// distinguishes it from a half-completed login — see [Service.ChangePassword]'s
// sweep matrix for which remediation paths invalidate it.
type RecoveryCode struct {
	// ID is the record's surrogate key, stamped by the service (uid.NewV7).
	// [WithIDGenerator]'s "MUST be UUID-parseable to use store/drops"
	// constraint covers this column too.
	ID string `drop:"id"`
	// UserID is the account the code belongs to. Every code in one
	// [MFAStore.ReplaceRecoveryCodes] call MUST carry the userID that call
	// names — see [ErrRecoveryCodeUserMismatch].
	UserID string `drop:"user_id"`
	// CodeHash is the STORED hash of the plaintext code, produced by the
	// configured [github.com/bernardoforcillo/authlayer/password.Hasher] —
	// the same treatment a password gets, for the same reason: a recovery
	// code is a credential that authenticates an account on its own, and a
	// dump of plaintext codes is a working bypass of the second factor for
	// every user who has not used theirs.
	//
	// # It is matched byte-for-byte, and what that implies for the caller
	//
	// [MFAStore.ConsumeRecoveryCode] takes a codeHash and compares it to
	// this column with ordinary equality. That is not "hash the code the
	// user typed and look it up": the default Hasher is bcrypt, which
	// SALTS, so the same plaintext hashes differently every time and no
	// caller can recompute the stored value. A caller identifies the row by
	// verifying the presented plaintext against each of the user's stored
	// hashes (see [MFAStore.ListRecoveryCodes]) and then passes back the
	// hash it matched. The store's job is the atomic burn, not the
	// credential comparison.
	CodeHash string `drop:"code_hash"`
	// UsedAt is when this code was spent, or nil while it is still
	// available. Codes are BURNED rather than deleted so that a user can be
	// shown how many of their set remain, and so a support conversation
	// about "I already used that one" has an answer.
	UsedAt *time.Time `drop:"used_at"`
	// CreatedAt is when the set this code belongs to was generated.
	CreatedAt time.Time `drop:"created_at"`
}

// Cipher is the symmetric encryption port for TOTP secrets at rest: two
// methods, no key management, no algorithm choice exposed. Wire one with
// [WithMFASecretCipher].
//
// authlayer ships no implementation, deliberately. Encryption at rest is a
// key-management problem — where the key lives, how it rotates, whether a
// KMS or an HSM holds it — and a library that shipped a default would be
// shipping a default key location, which is the part that actually decides
// whether the ciphertext is worth anything. An AES-GCM implementation over
// a key from your secret manager is a dozen lines; the dozen lines are not
// the hard part.
//
// Implementations MUST be safe for concurrent use, like every other port
// here, and MUST be deterministic in neither direction beyond the
// round trip: this package only ever decrypts what it encrypted.
type Cipher interface {
	// Encrypt returns the ciphertext for plaintext, in whatever encoding
	// the implementation likes — it is stored verbatim in
	// [MFAFactor.SecretEnc], a text column, so it must be a string a
	// database can hold (base64, hex, or an armoured envelope; not raw
	// bytes with NUL in them).
	Encrypt(plaintext string) (string, error)
	// Decrypt reverses Encrypt. It MUST return an error rather than
	// garbage for a value it did not produce, for one it cannot
	// authenticate, or for one encrypted under a key it no longer holds:
	// a silently-wrong plaintext here becomes a secret whose codes never
	// validate, which the user experiences as "my authenticator stopped
	// working" and an operator debugs for a very long time.
	Decrypt(ciphertext string) (string, error)
}

// Sentinel errors for the MFA surface. Compare with [errors.Is], never by
// string — the messages are not part of the API.
//
// They join the [Store] sentinels declared in auth.go rather than replacing
// them: an [MFAStore] returns [ErrIDTaken] on a duplicate recovery-code id,
// exactly as [Store.CreateUser] does on a duplicate user id.
var (
	// ErrFactorNotFound: the user has no [MFAFactor] at all. Returned by
	// [MFAStore.FindFactor], [MFAStore.ConfirmFactor],
	// [MFAStore.AdvanceStep] and [MFAStore.DeleteFactor].
	//
	// It means "not enrolled", which is an ordinary state for most
	// accounts, not a failure — the account simply has no second factor.
	ErrFactorNotFound = errors.New("authlayer/auth: no MFA factor for this user")
	// ErrRecoveryCodeUserMismatch: a [MFAStore.ReplaceRecoveryCodes] call
	// was handed a code whose UserID is not the userID the call names.
	// The whole call is refused and NOTHING is written.
	//
	// Writing the row as given would file a live credential under another
	// account; rewriting its UserID to match would silently mint a
	// credential for an account the caller did not name. Both are worse
	// than refusing what is, unambiguously, a caller bug.
	ErrRecoveryCodeUserMismatch = errors.New("authlayer/auth: recovery code belongs to another user")
	// ErrMFANotConfigured: an operation needing an [MFAStore] was attempted
	// on a [Service] built without [WithMFAStore].
	//
	// The port is optional — an application offering no second factor wires
	// none — so every entry point that needs one resolves it through a
	// single guard that returns this, rather than dereferencing a nil
	// interface. It is the exact counterpart of [ErrOAuthNotConfigured].
	ErrMFANotConfigured = errors.New("authlayer/auth: no MFA store configured")
	// ErrMFACipherNotConfigured: enrolment was attempted on a [Service]
	// built without [WithMFASecretCipher].
	//
	// It is a REFUSAL TO ENROL, not a downgrade to plaintext, and that
	// choice is the whole argument in this file's package doc: a secret
	// stored in the clear is a second-factor bypass for every enrolled
	// user the moment the database is read. An operator who has not
	// configured a key finds out at the first enrolment attempt, which is
	// the only cheap moment to find out.
	ErrMFACipherNotConfigured = errors.New("authlayer/auth: no MFA secret cipher configured")
)

// MFAStore is the optional persistence port for second-factor state: the
// `mfa_factors` and `mfa_recovery_codes` tables, and nothing else. It is
// deliberately NOT part of [Store] — see this file's package doc for which
// rule decides that and why MFA falls on the same side of it as
// [IdentityStore].
//
// Like [Store] it performs no authorization, no hashing, no encryption and
// no token minting of its own: it stores the ciphertext and the hashes it
// is handed, and reports not-found and conflict conditions through the
// sentinels above. It does NOT own `users`, and never reads one.
//
// # Three of these methods are compare-and-set, and each carries a MUST
//
// [MFAStore.ConfirmFactor], [MFAStore.AdvanceStep] and
// [MFAStore.ConsumeRecoveryCode] each decide something from stored state
// and write in the same breath. For all three the check and the write MUST
// be a single atomic step — one statement, one transaction, or one
// acquisition of the mutex that serializes the store. A read-then-write
// implementation does not satisfy this contract even when each half is
// individually correct, and this project has shipped that exact shape four
// times elsewhere ([Store.MarkRotated], invite's ConsumeLink,
// [Store.CreateSuccessorSession], [Store.DeleteSessionsByFamily]) and
// closed it four times. Each method's own doc says what a split produces.
type MFAStore interface {
	// UpsertFactor persists f as userID's ONE factor, creating the record
	// or REPLACING an existing one in full.
	//
	// # "In full" is the MUST
	//
	// Every column is written from f, including the nil ones. An
	// implementation MUST NOT merge f over what is already stored — an
	// upsert that kept a previous non-nil ConfirmedAt would leave a
	// BRAND-NEW secret marked as already confirmed, so a re-enrolment the
	// user abandoned half way (they scanned nothing, or scanned into an app
	// that then failed) would gate every subsequent login with a secret no
	// authenticator holds. That is the permanent lockout
	// [MFAFactor.ConfirmedAt]'s nil state exists to prevent, reached
	// through the write path instead of the read path. The same applies to
	// LastStep: a new secret inherits no step history, and keeping one
	// would refuse the user's first genuine code.
	//
	// It reports no "did it exist" flag, because no caller needs one:
	// enrolment is the same act whether or not the account had an older
	// factor.
	UpsertFactor(ctx context.Context, f MFAFactor) error
	// FindFactor loads userID's factor, returning ErrFactorNotFound when
	// there is none. "None" is the ordinary state of an account that has
	// never enrolled, not a failure.
	FindFactor(ctx context.Context, userID string) (MFAFactor, error)
	// ConfirmFactor stamps ConfirmedAt with now if and only if it is
	// currently nil, and reports whether THIS call was the one that did it.
	// A second call on an already-confirmed factor returns (false, nil) and
	// leaves the original stamp alone — the moment of confirmation is a
	// fact about the account, not a value the latest caller overwrites.
	// ErrFactorNotFound when the user has no factor.
	//
	// # It MUST be atomic: exactly one concurrent confirmer sees true
	//
	// The check ("is it still unconfirmed?") and the stamp MUST be one
	// step. The winner is the caller that gets to hand the user their
	// recovery codes, and generating a set of codes REPLACES any previous
	// set (see ReplaceRecoveryCodes). Two callers both winning therefore
	// means two sets are generated and shown, and the second write silently
	// invalidates every code the user was just told to write down — a
	// user-visible lockout of the recovery path, produced by a race, on the
	// one screen a user is most likely to double-submit.
	ConfirmFactor(ctx context.Context, userID string, now time.Time) (bool, error)
	// AdvanceStep records step as the factor's most recent TOTP step, if
	// and only if it is strictly greater than the stored LastStep, and
	// reports whether it did. A step less than OR EQUAL to LastStep is
	// refused with (false, nil) and nothing is written. When LastStep is
	// nil — the factor has authenticated nothing yet — any step is
	// accepted. ErrFactorNotFound when the user has no factor.
	//
	// # This is the replay guard
	//
	// TOTP accepts a window of steps either side of the server's own, so
	// the same code stays valid for the whole window — typically a minute
	// and a half. Without this compare-and-set, a code read over a user's
	// shoulder, left on a shared screen, or captured by a phishing page is
	// a usable credential for the rest of that window, and the second
	// factor buys nothing against an attacker who is watching. Refusing a
	// step that has already been used, and every step before it, cuts the
	// reuse window to zero: the code the attacker saw is the code the user
	// just spent.
	//
	// # It MUST be atomic
	//
	// The comparison and the write MUST be one step. Two concurrent
	// presentations of the SAME code against a read-then-write
	// implementation both read the old LastStep, both find their step
	// greater, and both succeed — which is exactly the replay this method
	// exists to refuse, arriving as a race instead of a sequence. An
	// attacker replaying a captured code alongside the user's own
	// submission is not a hypothetical interleaving; it is the natural
	// shape of the attack.
	//
	// It does NOT check whether the factor is confirmed. That is the
	// service's decision, made before it ever gets here, and folding it in
	// would make this method quietly refuse for a reason it cannot report.
	AdvanceStep(ctx context.Context, userID string, step int64) (bool, error)
	// DeleteFactor removes userID's factor row, or returns
	// ErrFactorNotFound when there is none.
	//
	// # It removes the factor row ONLY
	//
	// It does not touch the user's recovery codes, exactly as
	// [Store.DeleteUser] removes the user row and not the sessions beside
	// it, and for the same reason: a store is pure persistence, and the
	// order and extent of a cascade is a policy decision belonging to the
	// caller. A caller disabling MFA therefore owes a
	// ReplaceRecoveryCodes(ctx, userID, nil) as well — the codes are
	// credentials in their own right, and leaving them behind leaves a
	// disabled second factor with a live way to satisfy it.
	DeleteFactor(ctx context.Context, userID string) error
	// ReplaceRecoveryCodes replaces userID's ENTIRE set of recovery codes
	// with codes: every existing row for that user is removed and every
	// code in codes is stored. An empty or nil codes clears the set, which
	// is how a caller revokes recovery codes without issuing new ones.
	//
	// Every code MUST carry UserID == userID; a call containing one that
	// does not is refused with ErrRecoveryCodeUserMismatch and writes
	// NOTHING. A code whose ID is already taken — by another user's row, or
	// by another code in the same call — is refused with ErrIDTaken, and
	// likewise writes nothing.
	//
	// # It MUST be atomic
	//
	// The removal and the insertion MUST be one step. Half of it is a set
	// of recovery codes the user has already been shown and cannot use, or
	// an account with no recovery codes at all whose user believes they
	// hold ten. Neither is recoverable by retrying, because the plaintext
	// codes are shown exactly once and never leave the caller's memory
	// again.
	//
	// It touches only userID's rows — never another user's, however the
	// implementation locates them.
	ReplaceRecoveryCodes(ctx context.Context, userID string, codes []RecoveryCode) error
	// ConsumeRecoveryCode burns userID's UNUSED recovery code whose stored
	// hash equals codeHash, stamping UsedAt with now, and reports whether
	// this call was the one that burned it. No such unused code — wrong
	// hash, already used, or no such user — is (false, nil), never an
	// error.
	//
	// codeHash is compared byte-for-byte against the stored column; see
	// [RecoveryCode.CodeHash] for why the caller passes back a hash it
	// found rather than one it computed from what the user typed.
	//
	// The (false, nil) on a miss is deliberate. This is a credential check,
	// and its only two honest answers are "burned it" and "did not": an
	// error would invite a caller to treat a mistyped code as a system
	// failure, and an ErrFactorNotFound-style sentinel would tell an
	// attacker which half of (user, code) they got wrong.
	//
	// # It MUST be atomic: exactly one concurrent consumer wins
	//
	// The "is it still unused?" check and the stamp MUST be one step. Two
	// callers presenting the same code against a read-then-write
	// implementation both see it unused and both succeed, which is a
	// single-use credential used twice — the whole property recovery codes
	// have. If more than one row somehow shares (userID, codeHash), an
	// implementation MUST burn all of them in that one step rather than an
	// arbitrary one, so that a duplicate cannot leave a second live copy
	// of a code that has just been spent.
	ConsumeRecoveryCode(ctx context.Context, userID, codeHash string, now time.Time) (bool, error)
	// ListRecoveryCodes returns every recovery code belonging to userID —
	// used and unused alike — and only that user's. A user with none is not
	// an error.
	//
	// Used codes are included because both callers need them: an
	// application showing "3 of 10 remaining", and the service's own
	// verification of a presented code, which must compare against the
	// user's hashes and learn from UsedAt that the matching one is spent
	// rather than silently missing it.
	//
	// Whether "none" comes back as an empty slice or a nil one is
	// deliberately unspecified: implementations differ, and a caller MUST
	// use len() rather than a nil comparison. Order is likewise
	// unspecified — sort the result if you depend on one.
	ListRecoveryCodes(ctx context.Context, userID string) ([]RecoveryCode, error)

	// --- trusted devices ---
	//
	// The seven methods below persist [TrustedDevice] — the long-lived
	// bearer token that stands in for the second factor on a machine the
	// user has vouched for. They are on THIS port rather than a new one
	// because a trusted device is only ever "skip the second factor": a
	// deployment with no MFA has no use for one, and a backend implementing
	// MFA but not these would be one on which the feature silently does not
	// exist. auth/trusted.go carries the whole design; this port stores
	// hashes and rows and decides nothing.

	// CreateTrustedDevice persists d and returns what was stored.
	//
	// ErrIDTaken when d.ID already identifies a row. A duplicate
	// [TrustedDevice.TokenHash] MUST be refused too — that field's own doc
	// carries the MUST and the reason — but the sentinel for it is
	// deliberately unspecified, exactly as it is for [Session.TokenHash]:
	// no caller distinguishes the two, and the service never presents a
	// hash it did not just generate.
	//
	// An existing row is NEVER silently replaced or re-pointed at another
	// user: that is how one person's cookie ends up skipping somebody
	// else's second factor.
	CreateTrustedDevice(ctx context.Context, d TrustedDevice) (TrustedDevice, error)
	// FindTrustedDeviceByHash loads the device whose TokenHash equals
	// tokenHash, returning ErrTrustedDeviceNotFound when there is none. The
	// hash is matched byte-for-byte.
	//
	// It does NOT filter by user or by expiry: [Service.trustedDeviceAtSignIn]
	// compares the row's UserID against the account whose password it just
	// verified, and its ExpiresAt against the service clock. Folding either
	// in here would make this method refuse for a reason it cannot report.
	FindTrustedDeviceByHash(ctx context.Context, tokenHash string) (TrustedDevice, error)
	// ListTrustedDevices returns every device belonging to userID — expired
	// ones included — and only that user's. A user with none is not an
	// error.
	//
	// Whether "none" comes back as an empty slice or a nil one is
	// deliberately unspecified, as it is for ListRecoveryCodes: use len().
	// Order is likewise unspecified.
	ListTrustedDevices(ctx context.Context, userID string) ([]TrustedDevice, error)
	// DeleteTrustedDevice removes the one device named by id, or returns
	// ErrTrustedDeviceNotFound when id matches no row.
	//
	// It performs no ownership check and cannot: this port is never told
	// which user is asking. [Service.RevokeTrustedDevice] establishes that
	// before it calls here, by scanning the caller's own devices.
	DeleteTrustedDevice(ctx context.Context, id string) error
	// DeleteTrustedDevicesByUser removes EVERY trusted device belonging to
	// userID, and only that user's. Matching no rows is SUCCESS, not
	// ErrTrustedDeviceNotFound — this is the primitive every sweep in
	// [Service.ChangePassword]'s matrix calls, and a remediation path must
	// not fail because the account had nothing to revoke.
	DeleteTrustedDevicesByUser(ctx context.Context, userID string) error
	// TouchTrustedDevice stamps LastUsedAt with now for the device named by
	// id, reporting whether a row was stamped. An unknown id is
	// (false, nil), never an error.
	//
	// The bool is load-bearing rather than informational:
	// [Service.LoginWithTrustedDevice] calls this AFTER resolving the device
	// and BEFORE minting the session, and treats false as "this device is
	// gone" — so a [Service.RevokeTrustedDevice] landing between the two
	// makes the sign-in fall back to the ordinary challenge rather than skip
	// a factor on the strength of a row that no longer exists.
	TouchTrustedDevice(ctx context.Context, id string, now time.Time) (bool, error)
	// PurgeExpiredTrustedDevices deletes every device whose ExpiresAt is
	// strictly before `before`, across every user, and reports how many rows
	// went. It is what [Service.PurgeExpired] calls, and it is housekeeping
	// rather than a security boundary: an expired device is already refused
	// by [Service.LoginWithTrustedDevice] long before it is purged.
	//
	// The cutoff is taken literally and is not clamped to the present — the
	// same contract [Store.PurgeExpired] carries.
	PurgeExpiredTrustedDevices(ctx context.Context, before time.Time) (int, error)
}

// mfa resolves the configured [MFAStore], or reports
// [ErrMFANotConfigured]. It is the single gate every entry point needing
// the optional port passes through, so "no MFA store was wired" is one
// typed error in one place rather than a nil dereference somewhere down the
// ladder — exactly as [Service.identities] is for the identity port.
func (s *Service) mfa() (MFAStore, error) {
	if s.cfg.mfaStore == nil {
		return nil, ErrMFANotConfigured
	}
	return s.cfg.mfaStore, nil
}

// mfaCipher resolves the configured [Cipher], or reports
// [ErrMFACipherNotConfigured]. Enrolment goes through this before it mints
// anything, so a Service with no cipher refuses to create a factor at all
// rather than storing a secret in the clear — see this file's package doc.
func (s *Service) mfaCipher() (Cipher, error) {
	if s.cfg.mfaCipher == nil {
		return nil, ErrMFACipherNotConfigured
	}
	return s.cfg.mfaCipher, nil
}
