// Package auth defines the persistence shape for authentication: a user's
// credential record, the sessions a login and its refreshes create, and the
// one-time tokens signup, email-change and password-reset flows hand out.
//
// Like invite and scope, this package is split into a pure-persistence port
// ([Store]) and the types it moves. It performs no hashing and no token
// minting of its own: [github.com/bernardoforcillo/authlayer/token]'s
// GenerateOpaque/HashOpaque produce an opaque bearer token and its sha256,
// Issue/Parse produce and verify the short-lived HS256 access token, and
// [github.com/bernardoforcillo/authlayer/password]'s Hasher hashes and
// verifies the password credential. A Store only persists and retrieves the
// records those layers hand it; the service layer that wires them together —
// [Service], with SignUp, Login, Refresh and the rest — lives in
// service.go, alongside this file.
//
// # Sessions, families, and rotation
//
// A login mints two tokens: a short-lived HS256 access token the caller never
// persists, and an opaque refresh token whose sha256 becomes a [Session]'s
// TokenHash — the plaintext itself is never stored, matching
// [github.com/bernardoforcillo/authlayer/invite]'s EmailInvite.TokenHash.
// Refreshing exchanges a still-current refresh token for a new access token
// and a new refresh token, minting a successor Session that shares the
// original's FamilyID. RotatedAt distinguishes the two states a Session can
// be in: nil means current — this is the one refresh token still good to
// present — and non-nil means superseded, stamped with when it was rotated
// away from.
//
// [Store.MarkRotated] is the primitive that makes rotation safe under
// concurrency: it is a compare-and-set that lets exactly one caller win the
// transition from current to superseded, however many concurrent callers
// present the same refresh token at once. See its doc comment for why the
// check and the mark must be a single atomic step, not two.
//
// Winning that compare-and-set is necessary but not sufficient to mint a
// successor: the winner still has to persist the new [Session] row, and
// that persist can itself race a DIFFERENT caller's family-wide revocation
// of the very family this winner's predecessor belongs to — a REPLAY
// against an OLDER token in the same chain, or an explicit
// [Store.DeleteSessionsByFamily] call from a logout, can complete between
// the winner's MarkRotated and its own insert. [Store.CreateSuccessorSession]
// closes that second race the same way MarkRotated closes the first: as a
// single atomic step, this time gated on whether the predecessor row is
// still there to succeed FROM. See that method's own doc for the exact
// contract and why "the predecessor still exists" is the right liveness
// check.
//
// A presented refresh token whose session is already rotated (MarkRotated
// returns ok=false with no error) is a replay: either two legitimate
// requests raced and the loser is being retried with a now-stale token, or an
// attacker is replaying a token they stole after the legitimate client
// already rotated past it. This package cannot tell those apart, so it does
// not try — the service layer's policy is to treat every replay as a
// compromise and revoke the whole family via [Store.DeleteSessionsByFamily],
// forcing every device sharing that login to sign in again. That is a
// deliberate, security-first tradeoff: an occasional false positive from a
// genuine race is the cost of never leaving a stolen token's family alive.
//
// # Verification tokens
//
// [Verification] covers three one-time flows that all share the same shape —
// mint an opaque token, email or otherwise deliver it, redeem it once — so
// they share one table rather than three: Purpose distinguishes "signup"
// (issued before EmailVerifiedAt is set), "email_change" (redeemed to
// overwrite UserBase.Email via [Store.UpdateUserEmail]), and
// "password_reset" (redeemed to overwrite UserBase.PasswordHash). Email
// carries the address the token was minted for, regardless of Purpose — see
// that field's own doc for why it is never conditionally populated. Like
// EmailInvite, only the token's hash is stored.
package auth

import (
	"context"
	"errors"
	"strings"
	"time"
)

// UserBase carries the identity and credential fields authentication needs.
// Email is always the output of [NormalizeEmail] — see that function's doc —
// and is meant to be unique across every user; [Store.CreateUser] enforces
// that.
//
// PasswordHash being empty is a real, supported state, not a zero-value
// accident: a user created through an OAuth-only or magic-link-only flow (a
// later plan) may hold no password credential at all, and an empty
// PasswordHash means exactly that — there is no password to verify against,
// so a password login for this user must fail rather than call
// [github.com/bernardoforcillo/authlayer/password.Hasher.Verify] against an
// empty string.
type UserBase struct {
	// ID is the record's surrogate key, stamped by the service.
	ID string `drop:"id"`
	// Email is the user's address, always normalized — see [NormalizeEmail].
	// Unique across every user; the tag's "unique" option is the inline
	// mechanism store/drops derives a UNIQUE constraint from (see
	// org.Organization.Slug for the precedent), though a backend remains
	// free to declare it some other way (e.g. pg.Table.AddUnique).
	Email string `drop:"email,unique"`
	// EmailVerifiedAt is when the user confirmed this address via a
	// "signup"-purpose [Verification]. nil means unverified.
	EmailVerifiedAt *time.Time `drop:"email_verified_at"`
	// PasswordHash is the bcrypt (or other [github.com/bernardoforcillo/authlayer/password.Hasher])
	// output for this user's password credential. Empty means no password
	// credential exists for this user — see the type doc.
	//
	// json:"-" is deliberate, not an oversight: this is a live, active
	// credential digest, and the ordinary way it would otherwise leak is
	// not a careless one — a handler that JSON-encodes its own type
	// embedding UserBase (exactly what auth/service.go's Service[U] hands
	// back from SignUp, Login, and VerifyEmail) ships it to the client by
	// default unless every such handler remembers to strip it by hand. A
	// struct tag closes that for every embedding type and every call site
	// at once, present and future, rather than depending on each one
	// remembering to. It does not protect a non-JSON leak (a log line, a
	// %+v, a different encoder) — see auth/service.go's own additional,
	// explicit clearing on its returned values for that.
	PasswordHash string `drop:"password_hash" json:"-"`
	// CreatedAt is stamped by the service clock at signup.
	CreatedAt time.Time `drop:"created_at"`
	// UpdatedAt is stamped by the service clock on every write to this row.
	UpdatedAt time.Time `drop:"updated_at"`
}

// Session is one refresh token's row: minted at login or at a prior
// rotation, and current until [Store.MarkRotated] supersedes it. See the
// package doc's "Sessions, families, and rotation" section for the full
// model.
type Session struct {
	// ID is the record's surrogate key, stamped by the service.
	ID string `drop:"id"`
	// UserID is the user this session belongs to.
	UserID string `drop:"user_id"`
	// TokenHash is sha256(refresh token plaintext) — see
	// [github.com/bernardoforcillo/authlayer/token.HashOpaque]. The plaintext
	// itself is never stored, matching EmailInvite.TokenHash's rationale.
	//
	// An implementation MUST enforce that TokenHash is unique across every
	// Session row — a UNIQUE constraint in a SQL backend. [Store.FindSessionByHash]
	// and [Store.MarkRotated] both assume at most one row can ever match a
	// given hash. Without that guarantee, a token-generation bug or a hash
	// collision that lets two rows share a TokenHash breaks MarkRotated's
	// single-winner contract with no atomicity defect at all: two concurrent
	// callers can each independently select a different one of the colliding
	// rows, and each correctly, atomically wins the row it happened to pick
	// — reported as two successful rotations, exactly the undetectable
	// parallel session this whole design exists to prevent, reached by a
	// different path than the one MarkRotated's own doc warns about.
	// FindSessionByHash degrades more mildly but still silently: it resolves
	// to whichever colliding row the backend happens to return first. This
	// project has already shipped this exact omission once — invite's
	// EmailInvite.TokenHash had no uniqueness constraint until a later fix —
	// so it is stated here as a MUST rather than left implicit.
	TokenHash string `drop:"token_hash"`
	// FamilyID groups a session with every session it was rotated from and
	// into: the whole rotation chain traces back to one login and shares this
	// value. [Store.DeleteSessionsByFamily] revokes the entire chain at once
	// on replay detection.
	FamilyID string `drop:"family_id"`
	// ExpiresAt is when this session's refresh token stops being presentable,
	// independent of rotation. An expired-but-unrotated session is ordinary
	// end-of-life, not a replay — see [Store.MarkRotated]'s doc for why
	// expiry is deliberately not part of its predicate.
	ExpiresAt time.Time `drop:"expires_at"`
	// CreatedAt is stamped by the service clock when this session was minted
	// — at login for the family's first session, at rotation for every
	// successor.
	CreatedAt time.Time `drop:"created_at"`
	// RotatedAt is nil while this session is current — its refresh token is
	// the one still good to present — and set to when [Store.MarkRotated]
	// superseded it once it is not.
	RotatedAt *time.Time `drop:"rotated_at"`
	// UserAgent is the client's User-Agent header at the time this session
	// was minted, an audit/display field only — never a security check.
	UserAgent string `drop:"user_agent"`
	// IP is the client's address at the time this session was minted, an
	// audit/display field only — never a security check.
	IP string `drop:"ip"`
}

// Verification is a one-time, hashed token backing the signup,
// email-change, and password-reset flows. See the package doc's
// "Verification tokens" section for how Purpose distinguishes the three.
type Verification struct {
	// ID is the record's surrogate key, stamped by the service.
	ID string `drop:"id"`
	// UserID is the user this verification is for.
	UserID string `drop:"user_id"`
	// TokenHash is sha256(token plaintext) — see
	// [github.com/bernardoforcillo/authlayer/token.HashOpaque]. The plaintext
	// itself is never stored, matching EmailInvite.TokenHash's rationale.
	//
	// An implementation MUST enforce that TokenHash is unique across every
	// Verification row, for the same reason [Session.TokenHash]'s doc gives:
	// [Store.FindVerificationByHash] assumes at most one row can match, and
	// without the constraint its result silently depends on row order rather
	// than being well-defined.
	TokenHash string `drop:"token_hash"`
	// Purpose is one of "signup", "email_change", or "password_reset". It is
	// a plain string, not a typed enum, matching Session and EmailInvite's
	// stance elsewhere in this codebase: the service layer defines and
	// validates the closed set of values it accepts, a persistence port does
	// not.
	Purpose string `drop:"purpose"`
	// Email is the address this verification token is bound to — always
	// populated and always normalized (see [NormalizeEmail]), regardless of
	// Purpose:
	//
	//   - "signup": the address being confirmed as owned — the same address
	//     that was already on UserBase.Email when the token was minted.
	//   - "email_change": the *new* address the token was minted for, to be
	//     switched to on redemption via [Store.UpdateUserEmail] — never the
	//     user's old/current address.
	//   - "password_reset": the address the token was delivered to, kept for
	//     consistency even though a password-reset redemption calls
	//     [Store.UpdateUserPassword], not [Store.MarkEmailVerified], and
	//     this field plays no role in that check today.
	//
	// This field MUST NOT be conditionally populated by Purpose. It used to
	// be named NewEmail and was documented empty for every Purpose but
	// "email_change" — which meant a "signup" redemption had nothing
	// recorded to compare against but the row's own *current* Email, making
	// [Store.MarkEmailVerified]'s email-match check compare the current
	// address to itself and always pass: the exact race that check exists to
	// close, left wide open for the one flow — signup — where an attacker
	// most wants an unproven address certified. Always populating this
	// field, for every Purpose, is what gives that check something real to
	// compare against.
	//
	// [Store.CreateVerification] normalizes it on write, the same as
	// UserBase.Email: a raw, non-normalized value stored here would let a
	// case/whitespace variant slip past both FindUserByEmail's normalized
	// probe (for email_change, once redeemed via UpdateUserEmail) and
	// MarkEmailVerified's own comparison (for every Purpose).
	Email string `drop:"email"`
	// ExpiresAt is when this token stops being redeemable. Always set —
	// there is no "never expires" case for a verification token, matching
	// EmailInvite.ExpiresAt's rationale.
	ExpiresAt time.Time `drop:"expires_at"`
	// CreatedAt is stamped by the service clock when this token was minted.
	CreatedAt time.Time `drop:"created_at"`
}

// NormalizeEmail trims leading and trailing whitespace and lowercases s.
//
// Every Store method that reads or writes an email — a UserBase's Email
// ([Store.CreateUser], [Store.FindUserByEmail], [Store.UpdateUserEmail]) or
// a Verification's Email ([Store.CreateVerification], which is the address
// the token was minted for, regardless of Purpose — see that field's own
// doc) — applies it, on both the write and the read side, so
// "Bob@Example.com ", " bob@example.com", and "bob@example.com" all resolve
// to the exact same row: none of them can create a duplicate account, and
// none of them can slip past a uniqueness check by varying only case or
// surrounding whitespace.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Sentinel errors returned by an auth.Store implementation and consumed by
// the service layer built on top. Compare with [errors.Is], never by string —
// the messages are not part of the API.
//
// They fall into three groups:
//
//   - Not found — ErrUserNotFound, ErrSessionNotFound,
//     ErrVerificationNotFound. A Store returns these itself whenever a
//     lookup or a delete by id or by hash finds no row, and
//     [Store.MarkRotated] returns ErrSessionNotFound the same way when
//     tokenHash matches no session at all — as opposed to matching one
//     already rotated, which is (Session, false, nil): see that method's own
//     doc for why those two outcomes are deliberately distinguished. The
//     three user-mutation methods (MarkEmailVerified, UpdateUserPassword,
//     UpdateUserEmail) return it too, on the same "no such id" miss.
//   - Conflict — ErrEmailTaken, ErrIDTaken. [Store.CreateUser] and
//     [Store.UpdateUserEmail] return ErrEmailTaken when the normalized email
//     already belongs to a different user; see [NormalizeEmail] for why the
//     comparison is always on the normalized form. CreateUser, CreateSession
//     and CreateVerification return ErrIDTaken when the given id already
//     identifies a row of that same kind — see each method's own doc.
//   - Precondition — ErrEmailMismatch. [Store.MarkEmailVerified] returns
//     this when the email the caller is certifying is not the user's
//     current address; see that method's own doc for why this exists and
//     what race it closes.
var (
	// ErrUserNotFound: no user with that id or email exists.
	ErrUserNotFound = errors.New("authlayer/auth: user not found")
	// ErrEmailTaken: another user already holds this normalized email.
	ErrEmailTaken = errors.New("authlayer/auth: email already registered")
	// ErrIDTaken: a Create* call was given an id that already identifies a
	// row of that same kind (user, session, or verification). Ids are
	// minted by the service (uid.NewV7()), so a collision is not expected
	// in ordinary operation, but a backend must never silently replace the
	// existing row on a collision — see each Create* method's own doc.
	ErrIDTaken = errors.New("authlayer/auth: id already exists")
	// ErrSessionNotFound: no session with that id or token hash exists.
	ErrSessionNotFound = errors.New("authlayer/auth: session not found")
	// ErrVerificationNotFound: no verification with that id or token hash
	// exists.
	ErrVerificationNotFound = errors.New("authlayer/auth: verification not found")
	// ErrEmailMismatch: [Store.MarkEmailVerified] was asked to certify an
	// email that is not the user's current address. See that method's own
	// doc for why it requires and checks the address rather than trusting
	// whatever the row currently holds.
	ErrEmailMismatch = errors.New("authlayer/auth: email does not match the user's current address")
)

// Store is the persistence port for authentication. Unlike scope.Store it is
// not generic — UserBase, Session and Verification are fixed shapes, so
// every backend shares one table triple — matching
// [github.com/bernardoforcillo/authlayer/invite.Store]'s stance for the same
// reason.
//
// A Store performs no authorization, no hashing, and no token minting or
// verification of its own — see the package doc for which package owns each
// of those. It persists and retrieves fully-formed records the service layer
// hands it, and reports not-found and conflict conditions through the
// sentinels above.
type Store interface {
	// CreateUser persists u and returns what was stored. Email is normalized
	// (see [NormalizeEmail]) before the uniqueness check and the write, so
	// the caller need not normalize it first, though doing so is harmless.
	// Returns ErrEmailTaken if another user already holds the same
	// normalized email, or ErrIDTaken if a user with this ID already
	// exists — an existing row is never silently replaced by a second
	// CreateUser call with the same ID.
	//
	// It MUST decide ErrEmailTaken from the same attempt that performs the
	// write, not from a separate, earlier existence check whose own
	// authorization or availability can differ from the write's. A single
	// INSERT that classifies a unique-constraint violation into
	// ErrEmailTaken — the shape [store/drops.AuthStore.CreateUser] uses —
	// satisfies this by construction. A preliminary SELECT followed by a
	// conditional INSERT does NOT, unless the backend has no failure mode
	// under which the read can succeed while the write independently
	// cannot; an in-process map with no separate write-permission concept
	// at all — the shape [store/memory.AuthStore.CreateUser] uses —
	// satisfies this trivially without literally attempting a write first,
	// precisely because that failure mode does not exist for it. See that
	// method's own doc for why check-then-write is acceptable THERE
	// specifically, not as a general license to check first.
	//
	// This is a security requirement, not an implementation-style
	// preference: [github.com/bernardoforcillo/authlayer/auth.Service.SignUp]
	// calls CreateUser as its ONLY signal for new-vs-duplicate, and every
	// call it performs afterward runs identically regardless of the
	// outcome — see that method's own doc, "Enumeration safety depends on
	// the Store". If an implementation can decide ErrEmailTaken WITHOUT
	// attempting the write, a condition that blocks writes but not
	// reads — a database role granted SELECT but not INSERT, most
	// concretely — makes CreateUser fail only for a genuinely new address
	// (which needs the write to succeed) while a duplicate short-circuits
	// to ErrEmailTaken from the read alone. That reopens the exact
	// enumeration oracle this package's service layer exists to close,
	// this time from inside a single Store method rather than from
	// SignUp's own control flow, where no amount of care in SignUp itself
	// can see or prevent it.
	CreateUser(ctx context.Context, u UserBase) (UserBase, error)
	// FindUserByID loads a user by id, returning ErrUserNotFound when there
	// is none.
	FindUserByID(ctx context.Context, id string) (UserBase, error)
	// FindUserByEmail normalizes email (see [NormalizeEmail]) and loads the
	// user with that normalized address, returning ErrUserNotFound when
	// there is none.
	//
	// It MUST read-your-writes with CreateUser on the same Store: a row
	// CreateUser has already returned successfully for MUST be visible to
	// a FindUserByEmail call that follows it, including one running
	// immediately afterward in the same request, not merely one running
	// later. This is a security requirement, not a performance note.
	// [github.com/bernardoforcillo/authlayer/auth.Service.SignUp] calls
	// CreateUser, then unconditionally calls FindUserByEmail to read back
	// what it just wrote, on every invocation regardless of new-vs-duplicate
	// — see that method's own doc, "Enumeration safety depends on the
	// Store". An implementation that answers reads from a lagging replica
	// breaks this specifically for the new-address branch: CreateUser's
	// write has not yet replicated, so the immediate FindUserByEmail
	// returns ErrUserNotFound for an address that, moments earlier, was
	// successfully created — while a genuinely duplicate address, whose
	// row has existed (and so replicated) for longer, is far less likely
	// to hit the same lag. That reopens the identical enumeration oracle
	// from yet another place neither SignUp nor its tests can see: the
	// Store implementation's own read/write topology.
	FindUserByEmail(ctx context.Context, email string) (UserBase, error)
	// MarkEmailVerified stamps EmailVerifiedAt and UpdatedAt with now on the
	// user identified by userID, but only if email (normalized — see
	// [NormalizeEmail]) matches that user's *current* Email. Returns
	// ErrUserNotFound when there is no such user, or ErrEmailMismatch when
	// the user exists but its current Email is not the one the caller is
	// certifying. Calling it again with the same, still-current email after
	// the address is already verified simply re-stamps both timestamps to
	// the new now — it is idempotent, not an error.
	//
	// It MUST check email against the user's current Email and perform the
	// write as a single atomic step — the same discipline
	// [Store.UpdateUserEmail] and [Store.MarkRotated] require of themselves.
	// A read-then-write implementation (a SELECT to compare email, followed
	// by a separate UPDATE) does not satisfy this contract even if each half
	// is individually safe: it only narrows the race this method exists to
	// close, it does not eliminate it. A concurrent UpdateUserEmail can still
	// land between the SELECT and the UPDATE, changing the row's address
	// after this method has already decided email matches, so the UPDATE
	// goes on to certify an address different from the one it checked — the
	// same false verification this method exists to prevent, reached through
	// a smaller, harder-to-notice window instead of a closed one.
	//
	// email exists to close a race with UpdateUserEmail, not as a redundant
	// double-check. A verification token is minted for one specific
	// address, and time can pass before it is redeemed; during that window
	// a different flow can call UpdateUserEmail and change the row's Email
	// out from under the pending verification. A MarkEmailVerified that took
	// only userID would certify whatever address the row happened to hold
	// at the instant it ran — possibly an address nobody has proven control
	// of at all, which is exactly the outcome UpdateUserEmail's
	// clear-EmailVerifiedAt-on-change behavior exists to prevent,
	// reintroduced silently through the gap between one flow's
	// UpdateUserEmail call and its own following MarkEmailVerified call.
	// Requiring and checking email turns that race into a loud
	// ErrEmailMismatch instead of a silent false verification: this is the
	// redemption step for a "signup"-purpose Verification, and the step an
	// "email_change" redemption calls immediately after UpdateUserEmail —
	// in both cases, the caller passes Verification.Email, the exact address
	// the token was minted for regardless of Purpose (see that field's own
	// doc — it is never conditionally populated, precisely so this check has
	// something real to compare against for every Purpose, not only
	// email_change), and the store refuses to certify anything else.
	MarkEmailVerified(ctx context.Context, userID, email string, now time.Time) error
	// UpdateUserPassword overwrites PasswordHash and stamps UpdatedAt with
	// now on the user identified by userID, returning ErrUserNotFound when
	// there is none. Passing an empty passwordHash is how a caller removes
	// the password credential entirely — see UserBase's doc for why that is
	// a real, supported state rather than an error condition.
	UpdateUserPassword(ctx context.Context, userID, passwordHash string, now time.Time) error
	// UpdateUserEmail normalizes email (see [NormalizeEmail]), overwrites
	// UserBase.Email, unconditionally clears EmailVerifiedAt back to nil, and
	// stamps UpdatedAt with now, on the user identified by userID. Returns
	// ErrUserNotFound when there is none, or ErrEmailTaken if a *different*
	// user already holds the same normalized address — checked and written
	// under one atomic step, the same discipline CreateUser uses, so two
	// concurrent changes to the same address cannot both succeed.
	//
	// EmailVerifiedAt is always cleared, never left alone and never set from
	// the new address: this method only records that the row's address
	// changed, not that anyone has proven control of the new one — the store
	// has no way to know that on its own. A caller that has independently
	// proven control — by construction, that is exactly what redeeming an
	// "email_change" Verification means, since its token was only ever
	// deliverable to the new address — calls MarkEmailVerified immediately
	// afterward to record that proof as a second, explicit step. Folding
	// verification into this method would let any caller set Email to an
	// address it never confirmed and have the store report it verified
	// anyway, which is exactly the kind of silent trust this port does not
	// extend to its callers elsewhere (see MarkRotated's doc for the same
	// principle applied to rotation).
	UpdateUserEmail(ctx context.Context, userID, email string, now time.Time) error

	// CreateSession persists an already-stamped session and returns what was
	// stored. Returns ErrIDTaken if a session with this ID already exists —
	// an existing row is never silently replaced. See [Session.TokenHash]'s
	// doc for the uniqueness obligation this method's caller (and, in turn,
	// its backend) carries for TokenHash specifically, which this method does
	// not itself check.
	CreateSession(ctx context.Context, s Session) (Session, error)
	// FindSessionByHash loads the session whose TokenHash matches, returning
	// ErrSessionNotFound when none does. This is the lookup a refresh or an
	// access check runs: hash the presented opaque token with
	// [github.com/bernardoforcillo/authlayer/token.HashOpaque] and look it up
	// by hash, since the plaintext itself is never stored (see [Session]).
	// Assumes TokenHash identifies at most one row — see that field's doc.
	FindSessionByHash(ctx context.Context, tokenHash string) (Session, error)
	// ListSessionsByUser returns every session belonging to userID, rotated
	// or not, expired or not — the caller filters. A user with none is not
	// an error; the result may be an empty slice or nil, which len and range
	// treat alike, so do not distinguish them. Order is unspecified.
	ListSessionsByUser(ctx context.Context, userID string) ([]Session, error)
	// DeleteSession removes a session by id, returning ErrSessionNotFound
	// when no row matched. This is a single-session logout.
	DeleteSession(ctx context.Context, id string) error
	// DeleteSessionsByFamily removes every session sharing familyID, however
	// many there are. This is the reuse-detection response: see the package
	// doc's "Sessions, families, and rotation" section for when the service
	// layer calls it. Deleting zero rows is not an error.
	//
	// On a backend where [Store.CreateSuccessorSession] takes a row-level
	// lock on the predecessor for its transaction's duration (see that
	// method's doc), a single autocommit DELETE here is NOT sufficient: its
	// snapshot is taken before any wait it does acquiring that same row's
	// lock, so once unblocked it sees only what existed at that earlier
	// instant — the predecessor, never a successor CreateSuccessorSession
	// committed while this call was waiting. Such a backend MUST re-snapshot
	// AFTER the wait — a SELECT ... FOR UPDATE (or equivalent lock) over the
	// family's rows followed by the DELETE, inside one transaction, is the
	// shape [github.com/bernardoforcillo/authlayer/store/drops.AuthStore]
	// uses. A backend whose CreateSuccessorSession takes no such lock (e.g.
	// store/memory's single-mutex design, where the lock spans both methods'
	// entire bodies) has no such gap to close.
	//
	// A backend using that SELECT-then-DELETE shape carries a second
	// obligation this method's callers do not see directly: two concurrent
	// calls to THIS method, on the SAME familyID, can deadlock each other.
	// SELECT ... FOR UPDATE with no ORDER BY gives no guarantee that two
	// concurrent executions acquire a family's row locks in the same order,
	// so one call can hold a lock the other wants while waiting on a lock
	// the other holds — a genuine lock-order-inversion deadlock a single
	// autocommit DELETE could never exhibit. A backend using the row-lock-
	// then-delete shape MUST additionally serialize concurrent calls on the
	// same family — a per-family advisory transaction lock taken before the
	// row-locking SELECT, as [github.com/bernardoforcillo/authlayer/store/drops.AuthStore]
	// does, is sufficient; adding an ORDER BY to the SELECT is NOT, since
	// the DELETE that follows has no ordering of its own.
	DeleteSessionsByFamily(ctx context.Context, familyID string) error
	// MarkRotated atomically marks the session identified by tokenHash as
	// superseded, if and only if it is not already. ok reports whether THIS
	// caller won; exactly one concurrent caller may see true — conditional on
	// TokenHash actually identifying at most one Session row; see that
	// field's doc for what breaks if a backend does not enforce that.
	//
	// It MUST be a single atomic step. A read-then-write lets two concurrent
	// refreshes both observe an unrotated session and both mint a successor
	// — after which the presented token is never replayed, reuse detection
	// never fires, and a stolen token becomes an undetectable parallel
	// session. That is the failure this whole design exists to prevent, so
	// an implementation that splits the check and the mark across two lock
	// acquisitions (or two SQL statements, or a read followed by a separate
	// conditional write) does not satisfy this contract even if each half is
	// individually safe — the atomicity has to span both.
	//
	// Expiry is deliberately NOT part of this predicate: an expired token is
	// ordinary end-of-life and must not revoke a family. The caller checks
	// expiry separately, against the returned Session's ExpiresAt, and
	// decides what an expired-but-successfully-rotated or
	// expired-and-already-rotated result means for its own flow. Do not
	// "helpfully" fold an ExpiresAt check into this method — see the package
	// doc for why an expired session is not a replay.
	//
	// A tokenHash matching no session at all is reported as (Session{},
	// false, ErrSessionNotFound). A tokenHash matching a session that is
	// already rotated is reported as (that session, false, nil) — not an
	// error: this method only performs the compare-and-set, it does not
	// decide what a lost race means. The caller inspects the returned
	// Session (in particular RotatedAt) to tell "someone else's legitimate
	// retry" from "replay" and to decide whether to call
	// DeleteSessionsByFamily.
	MarkRotated(ctx context.Context, tokenHash string, now time.Time) (Session, bool, error)
	// CreateSuccessorSession atomically inserts s — a session a rotation is
	// minting as the successor of the session identified by predecessorID —
	// but ONLY if predecessorID still identifies a row at the moment of this
	// call. ok reports whether s was actually persisted: true means
	// predecessorID still existed and s is now stored, exactly like
	// [Store.CreateSession]'s own success; false means predecessorID no
	// longer identified any row, s was NOT persisted, and the caller must
	// treat this as "the family was revoked out from under this rotation" —
	// see the package doc's "Sessions, families, and rotation" section for
	// why that outcome exists at all. false is not itself an error, the same
	// stance [Store.MarkRotated]'s own ok=false takes: it is an expected
	// outcome of a real race, not a failure this method experienced.
	//
	// # Why this method exists at all
	//
	// A caller that already knows it won [Store.MarkRotated] (ok=true) still
	// cannot safely call the unconditional [Store.CreateSession] to persist
	// the successor: MarkRotated's ok=true only proves the predecessor
	// row EXISTED and was unrotated at that earlier instant, not that it
	// still exists NOW. A concurrent caller replaying a DIFFERENT,
	// already-superseded token from the SAME family loses its own
	// MarkRotated race and responds by calling
	// [Store.DeleteSessionsByFamily] — which can complete, deleting the
	// predecessor (and everything else in the family) entirely, in the
	// window between this caller's own MarkRotated success and its
	// CreateSession call. An unconditional CreateSession run after that
	// window has closed silently resurrects the family with exactly one
	// live, fully-functional session — the reuse alarm fired and revoked
	// everything correctly, and this call then quietly undoes it. This
	// method is what closes that window: it does not ask "did I win
	// MarkRotated" (already known, and not enough) but "is there still a
	// family here to join", checked and acted on as one atomic step.
	//
	// It MUST be a single atomic step, the same discipline
	// [Store.MarkRotated] requires of itself and for the identical reason: a
	// read-then-write implementation — SELECT to check predecessorID exists,
	// then a separate INSERT — leaves the exact window open that this method
	// exists to close, even though each half is individually safe. A
	// DeleteSessionsByFamily landing between the check and the insert is
	// invisible to a caller that already finished checking, and the insert
	// proceeds anyway. A single statement whose insert is conditioned on the
	// existence check within one atomic operation — an
	// `INSERT ... SELECT ... WHERE EXISTS (...)` in a SQL backend, one mutex
	// acquisition spanning both the check and the write in an in-process
	// one — satisfies this; a backend composing an explicit transaction with
	// row-level locking on the predecessor for the transaction's duration
	// (so a concurrent DELETE targeting that row blocks until this
	// transaction resolves) satisfies it too, and is the shape
	// [github.com/bernardoforcillo/authlayer/store/drops.AuthStore]'s
	// implementation uses.
	//
	// Returns ErrIDTaken if a session with s.ID already exists, the same
	// condition [Store.CreateSession] itself reports it under — checked as
	// part of the same atomic step, independent of predecessorID's own
	// existence.
	CreateSuccessorSession(ctx context.Context, predecessorID string, s Session) (Session, bool, error)

	// CreateVerification normalizes v.Email (see [NormalizeEmail]),
	// persists the result, and returns what was stored. Returns ErrIDTaken
	// if a verification with this ID already exists — an existing row is
	// never silently replaced. See [Verification.TokenHash]'s doc for the
	// uniqueness obligation this method's caller (and, in turn, its backend)
	// carries for TokenHash, which this method does not itself check.
	CreateVerification(ctx context.Context, v Verification) (Verification, error)
	// FindVerificationByHash loads the verification whose TokenHash matches,
	// returning ErrVerificationNotFound when none does. Like
	// FindSessionByHash, this hashes the presented plaintext token before
	// looking it up. Assumes TokenHash identifies at most one row — see that
	// field's doc.
	FindVerificationByHash(ctx context.Context, tokenHash string) (Verification, error)
	// DeleteVerification removes a verification by id, returning
	// ErrVerificationNotFound when no row matched. This is what redeeming a
	// verification calls once its purpose has been carried out, so the same
	// token cannot be redeemed twice.
	DeleteVerification(ctx context.Context, id string) error
	// DeleteVerificationsByUserAndPurpose removes every verification for
	// (userID, purpose), however many there are. This is what re-issuing a
	// verification calls first, so requesting a new password-reset email
	// invalidates any earlier one instead of leaving both redeemable.
	// Deleting zero rows is not an error.
	DeleteVerificationsByUserAndPurpose(ctx context.Context, userID, purpose string) error

	// PurgeExpired deletes every Session and Verification expired strictly
	// before `before` — both by ExpiresAt — and returns how many rows were
	// removed in total, across both kinds. It is housekeeping, not a
	// security boundary: an expired session or verification is already
	// unusable through the normal lookup and rotation paths before it is
	// ever purged. UserBase rows are never purged — users do not expire.
	PurgeExpired(ctx context.Context, before time.Time) (int, error)
}
