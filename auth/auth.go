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
// Login, Refresh, Signup, and so on — comes in a later task.
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
// (issued before EmailVerifiedAt is set), "email_change" (NewEmail carries
// the address being switched to, redeemed to overwrite UserBase.Email), and
// "password_reset" (redeemed to overwrite UserBase.PasswordHash). Like
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
	// Unique across every user.
	Email string `drop:"email"`
	// EmailVerifiedAt is when the user confirmed this address via a
	// "signup"-purpose [Verification]. nil means unverified.
	EmailVerifiedAt *time.Time `drop:"email_verified_at"`
	// PasswordHash is the bcrypt (or other [github.com/bernardoforcillo/authlayer/password.Hasher])
	// output for this user's password credential. Empty means no password
	// credential exists for this user — see the type doc.
	PasswordHash string `drop:"password_hash"`
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
	TokenHash string `drop:"token_hash"`
	// Purpose is one of "signup", "email_change", or "password_reset". It is
	// a plain string, not a typed enum, matching Session and EmailInvite's
	// stance elsewhere in this codebase: the service layer defines and
	// validates the closed set of values it accepts, a persistence port does
	// not.
	Purpose string `drop:"purpose"`
	// NewEmail is the address an "email_change" verification redeems to.
	// Empty for every other Purpose.
	NewEmail string `drop:"new_email"`
	// ExpiresAt is when this token stops being redeemable. Always set —
	// there is no "never expires" case for a verification token, matching
	// EmailInvite.ExpiresAt's rationale.
	ExpiresAt time.Time `drop:"expires_at"`
	// CreatedAt is stamped by the service clock when this token was minted.
	CreatedAt time.Time `drop:"created_at"`
}

// NormalizeEmail trims leading and trailing whitespace and lowercases s.
//
// Every Store method that reads or writes a UserBase's Email —
// [Store.CreateUser] and [Store.FindUserByEmail] — applies it, on both the
// write and the read side, so "Bob@Example.com ", " bob@example.com", and
// "bob@example.com" all resolve to the exact same row: none of them can
// create a duplicate account, and none of them can slip past CreateUser's
// uniqueness check by varying only case or surrounding whitespace.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Sentinel errors returned by an auth.Store implementation and consumed by
// the service layer built on top. Compare with [errors.Is], never by string —
// the messages are not part of the API.
//
// They fall into two groups:
//
//   - Not found — ErrUserNotFound, ErrSessionNotFound,
//     ErrVerificationNotFound. A Store returns these itself whenever a
//     lookup or a delete by id or by hash finds no row, and
//     [Store.MarkRotated] returns ErrSessionNotFound the same way when
//     tokenHash matches no session at all — as opposed to matching one
//     already rotated, which is (Session, false, nil): see that method's own
//     doc for why those two outcomes are deliberately distinguished.
//   - Conflict — ErrEmailTaken. [Store.CreateUser] returns this when the
//     normalized email already belongs to another user; see [NormalizeEmail]
//     for why the comparison is always on the normalized form.
var (
	// ErrUserNotFound: no user with that id or email exists.
	ErrUserNotFound = errors.New("authlayer/auth: user not found")
	// ErrEmailTaken: another user already holds this normalized email.
	ErrEmailTaken = errors.New("authlayer/auth: email already registered")
	// ErrSessionNotFound: no session with that id or token hash exists.
	ErrSessionNotFound = errors.New("authlayer/auth: session not found")
	// ErrVerificationNotFound: no verification with that id or token hash
	// exists.
	ErrVerificationNotFound = errors.New("authlayer/auth: verification not found")
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
	// normalized email.
	CreateUser(ctx context.Context, u UserBase) (UserBase, error)
	// FindUserByID loads a user by id, returning ErrUserNotFound when there
	// is none.
	FindUserByID(ctx context.Context, id string) (UserBase, error)
	// FindUserByEmail normalizes email (see [NormalizeEmail]) and loads the
	// user with that normalized address, returning ErrUserNotFound when
	// there is none.
	FindUserByEmail(ctx context.Context, email string) (UserBase, error)

	// CreateSession persists an already-stamped session and returns what was
	// stored.
	CreateSession(ctx context.Context, s Session) (Session, error)
	// FindSessionByHash loads the session whose TokenHash matches, returning
	// ErrSessionNotFound when none does. This is the lookup a refresh or an
	// access check runs: hash the presented opaque token with
	// [github.com/bernardoforcillo/authlayer/token.HashOpaque] and look it up
	// by hash, since the plaintext itself is never stored (see [Session]).
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
	DeleteSessionsByFamily(ctx context.Context, familyID string) error
	// MarkRotated atomically marks the session identified by tokenHash as
	// superseded, if and only if it is not already. ok reports whether THIS
	// caller won; exactly one concurrent caller may see true.
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

	// CreateVerification persists an already-stamped verification and
	// returns what was stored.
	CreateVerification(ctx context.Context, v Verification) (Verification, error)
	// FindVerificationByHash loads the verification whose TokenHash matches,
	// returning ErrVerificationNotFound when none does. Like
	// FindSessionByHash, this hashes the presented plaintext token before
	// looking it up.
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
