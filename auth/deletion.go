// Package auth (this file) is the deletion posture: removing an account and
// everything this package holds for it, and giving the application a hook
// for everything it does not.
//
// Where service.go's methods each own one flow (sign up, log in, refresh),
// [Service.DeleteAccount] is a CASCADE across every record kind the [Store]
// persists, and the interesting part of it is the ORDER — see that method's
// doc. The three by-user primitives it sequences ([Store.DeleteSessionsByUser],
// [Store.DeleteVerificationsByUser], [Store.DeleteUser]) are deliberately
// separate methods on the port rather than one DeleteAccount there, because
// the order is a policy decision that belongs to this layer: see auth.go's
// package doc, "Deletion, and why it is on this port rather than beside it".
package auth

import "context"

// WithAccountDeletionHook registers the function [Service.DeleteAccount]
// calls to let the application tear down everything authlayer does not own,
// before authlayer removes anything of its own. A nil f is ignored, leaving
// the default (no hook) or a prior option in place, matching [WithHasher]
// and every other option in this package.
//
// # The contract, in three sentences
//
// It fires BEFORE any authlayer row is written. An error it returns ABORTS
// the deletion, and nothing has been written at that point — the account is
// left exactly as it was. It runs on the caller's goroutine and shares the
// caller's context, so a slow hook slows the request and a cancelled
// context cancels the deletion.
//
// # Why it runs first, and not last
//
// A hook that ran after the cascade could report a failure but could not
// undo one: the sessions, the verifications and the user row would already
// be gone, and the application would be left holding rows keyed on a user
// id that no longer resolves. A half-deleted account is worse than an
// undeleted one — the user asked for their data to be removed and it
// partially is, with no record of what remains — so the hook goes first,
// where "the application's cleanup failed" and "nothing happened" are the
// same state.
//
// The concrete case this exists for is the
// [github.com/bernardoforcillo/authlayer/scope] membership tables. This
// package's [Store] persists users, sessions and verifications and nothing
// else; a user's memberships live in scope's own store, behind a different
// port this package holds no reference to, and there is no call
// DeleteAccount could make to reach them. Deleting the user row while those
// memberships survive leaves a container whose member list names an account
// that no longer exists — which the application's own authorization checks
// will keep honouring until something notices. Your own tables (a profile
// row, uploaded files, an audit trail you intend to purge rather than keep)
// are the same shape of problem, and the same hook is where they go.
//
// # What the hook is handed, and what it must tolerate
//
// It receives only the user id — the same string [Service.DeleteAccount]
// was given, and the key everything an application stores about a user is
// reachable by. It is NOT handed the [UserBase]: a hook that needs the
// address (to remove it from a mailing list, say) must load it itself,
// through the Store or its own tables, BEFORE the account goes; after
// DeleteAccount returns there is nothing left to look it up from.
//
// It MUST tolerate being called more than once for the same user id.
// DeleteAccount's steps after the hook are not atomic (see that method's
// doc), so a caller whose deletion failed part-way through will reasonably
// retry — and the retry runs the hook again, against an application that
// has already done its cleanup. "Delete these rows if they are there" is
// the shape that survives; "decrement a counter" is not.
//
// The hook's error is returned to DeleteAccount's caller AS-IS, unwrapped,
// the same way a [Store] error is and matching
// [github.com/bernardoforcillo/authlayer/scope]'s own hook behaviour. That
// means a caller cannot tell from the error alone whether the hook or the
// Store failed; a hook that needs its failures distinguishable should
// return an error its own caller can match on, which is entirely in the
// application's hands.
func WithAccountDeletionHook(f func(ctx context.Context, userID string) error) Option {
	return func(c *config) {
		if f != nil {
			c.accountDeletionHook = f
		}
	}
}

// DeleteAccount permanently removes userID's account and everything this
// package holds for it — every session, every verification, and the user
// row itself — after re-authenticating the caller with currentPassword and
// giving the application's own cleanup (see [WithAccountDeletionHook]) the
// chance to run and to refuse.
//
// This is the HARD posture: the row is gone, and the address it held is
// free for a new sign-up immediately afterwards. Nothing keyed on the user
// id resolves any more, which is exactly what a deployment holding foreign
// keys into the users table must think about before choosing it.
//
// # Order, and why it is not negotiable
//
//  1. [Store.FindUserByID] loads the account. A miss is [ErrUserNotFound],
//     propagated as-is; any other Store error is propagated as-is too. An
//     account already ANONYMIZED (a non-nil [UserBase.DeletedAt]) is still
//     deletable and is not treated specially — a hard delete supersedes a
//     soft one, and refusing here would leave a stamped row with no way to
//     ever remove it.
//  2. Re-authentication, when the account HAS a password: currentPassword
//     is checked against the stored hash with the configured
//     [github.com/bernardoforcillo/authlayer/password.Hasher], exactly as
//     [Service.ChangePassword] does, and a mismatch is
//     [ErrInvalidCredentials]. Nothing is written and the hook does not
//     run. See "An account with no password" for the other case.
//  3. The hook, if one is configured — BEFORE any authlayer row is
//     written. Its error aborts, and nothing has been written yet, which is
//     the whole reason it is here rather than at the end. See
//     [WithAccountDeletionHook].
//  4. [Store.DeleteSessionsByUser] — every family, current and superseded
//     alike. ACCESS STOPS HERE, before anything irreversible has happened.
//  5. [Store.DeleteVerificationsByUser] — every purpose, including any a
//     later flow or the deployment itself defines: no pending reset link or
//     email-change token may outlive the account it was minted for. That is
//     why this is the by-USER sweep and not
//     [Store.DeleteVerificationsByUserAndPurpose] over the three purposes
//     this package happens to name.
//  6. Identities — OWED, and not implemented. See "The identity sweep this
//     does not do yet".
//  7. [Store.DeleteUser] — the user row, LAST.
//
// Steps 4 and 7 are the pair that matters. Sessions before the row means a
// deletion that fails part-way leaves an account that CANNOT BE USED and is
// still there to retry against. The row before sessions would mean one
// whose users-table row is gone while its [Session] rows survive it,
// reachable from nothing that walks the users table and unswept until they
// expire on their own. The first is recoverable; the second leaves credential
// rows behind with nothing left to find them from. See "What is not atomic
// here, and why" for the full statement.
//
// # An account with no password
//
// An account whose [UserBase.PasswordHash] is empty — registered through a
// social login, or through a magic link, never through [Service.SignUp] —
// has no credential to check currentPassword against, so this method does
// not check one: it proceeds ON THE CALLER'S AUTHORITY, whatever
// currentPassword holds, including "".
//
// That is a deliberate asymmetry with [Service.ChangePassword], which
// treats the same empty hash as [ErrInvalidCredentials], and it is stated
// here rather than left to be discovered because the two methods look
// alike and do not behave alike. ChangePassword can refuse and lose
// nothing: an account with no password has no password to change, so the
// refusal denies an operation that was meaningless anyway. Refusing HERE
// would deny a real, meaningful request — "delete my account" — to every
// OAuth-only user in the deployment, permanently, with no path this package
// offers to satisfy it.
//
// The consequence is that for such an account this method verifies NOTHING
// of its own, and whatever authorization stands between an HTTP request and
// this call is the entire control. Establish that the caller owns the
// account before calling — a valid session for this exact user id at
// minimum, and a re-authentication step of the deployment's own (the OAuth
// provider re-consulted, a second factor) where the account's value
// justifies it.
//
// Two follow-ons worth stating plainly. An ANONYMIZED account has had its
// password hash cleared, so it falls in this branch by construction: no
// deletion of an anonymized account ever re-authenticates. And this branch
// is observable — passing the wrong password to an account that has one is
// ErrInvalidCredentials, passing anything at all to an account that does
// not succeeds — so a caller learns whether the account has a password
// credential. That caller is the accountholder, acting on their own id, so
// it is disclosed rather than defended against; it is not an enumeration
// oracle, which is why (unlike ChangePassword) this method does not run
// [github.com/bernardoforcillo/authlayer/password.Hasher.Dummy] to equalize cost on a branch whose outcome is
// already plainly visible.
//
// # What is not atomic here, and why
//
// Steps 4 through 7 are FOUR SEPARATE STORE CALLS with no transaction
// around them, and there cannot be one. [Store] exposes no transaction
// (see auth.go's package doc), the identity sweep step 6 is owed may live
// behind a DIFFERENT port with a DIFFERENT backend entirely, and the hook
// at step 3 reaches tables this package has no connection to at all. There
// is no scope in which a single commit could cover them.
//
// So a failure part-way is reachable, and this method does not pretend
// otherwise: it stops at the first error and returns it, leaving whatever
// earlier steps already removed removed. What the ORDER buys is that every
// such partial state falls on the same side:
//
//   - Fail at step 5 or 7: the sessions are gone and the row is still
//     there. The account cannot be logged into and cannot be refreshed
//     into, and it is still present to retry the whole call against —
//     which is safe, because steps 4 and 5 both treat "matched no rows" as
//     success (see their own docs on [Store]) and so cost nothing the
//     second time.
//   - Fail at step 4: nothing at all has been removed. The hook has
//     already run, which is why it must tolerate running again (see
//     [WithAccountDeletionHook]).
//
// The direction this ordering makes UNREACHABLE is the one that matters: an
// account whose user row is gone while its sessions survive it. Put the row
// first and a failure at the session sweep leaves exactly that. Every one
// of those rows is then an orphan — [Store.ListSessionsByUser] still
// returns them, [Store.PurgeExpired] will not remove them until they expire
// on their own (up to [WithRefreshTTL]'s window, 30 days by default), and
// nothing is left in the users table to find them from, so a deployment
// auditing its own data by walking users would not see them at all.
// [Service.Refresh] does refuse them, on its own [Store.FindUserByID] at
// step 4 rather than on the token — but "the account reports as deleted
// while the Store still holds its credentials" is a state worth never
// producing, and reversing these two steps is all it takes.
//
// A caller that needs a partial deletion to be VISIBLE rather than merely
// safe should record its own intent-to-delete before calling and clear it
// after: this package keeps no such marker of its own, and the row this
// method removes is the only place one could live. The soft posture that
// keeps the row and stamps [UserBase.DeletedAt] instead is the answer for a
// deployment that cannot tolerate the row disappearing at all; it is not on
// this branch yet.
//
// # The identity sweep this does not do yet
//
// Step 6 is listed and NOT implemented. OAuth identities are persisted
// through a separate, optional port that does not exist on this branch, so
// there is nothing here to call: a deployment that has linked social
// identities to an account must delete them itself, from the deletion hook,
// until that port lands and this method sweeps them between steps 5 and 7.
// This is stated rather than silently omitted because the gap has teeth —
// an identity row surviving its user is a credential pointing at an id that
// no longer resolves, and a later sign-up that happens to be issued the
// same id would inherit it.
//
// # What this does not revoke
//
// ACCESS tokens. "Every session is gone" means every [Session] row — every
// REFRESH token — is removed, so [Service.Refresh] fails on all of them
// immediately. It does NOT invalidate an ACCESS token already issued for
// one: a short-lived HS256 JWT (see [WithJWT] — 15 minutes by default) is
// stateless, and this package never looks a presented one up in the [Store],
// only verifies its signature and expiry (see [github.com/bernardoforcillo/authlayer/token.Parse] and
// [Service.VerifyAccessToken]). A device holding one keeps working, on
// whatever that token alone authorizes, for up to the remainder of its own
// TTL AFTER THE ACCOUNT NO LONGER EXISTS. That bound is inherent to a
// stateless access token and every other revocation path in this package
// carries it identically — see [Service.LogoutAll]'s doc, "What this does
// not revoke", for the full statement and for the SessionID ("sid") claim
// an application checks per-request to close it. It is worth more attention
// here than anywhere else in the package, because here there is no longer a
// user row for such a check to resolve against, so a deployment doing that
// lookup must treat "no such user" as a refusal rather than as an error.
//
// A [Store] or [github.com/bernardoforcillo/authlayer/password.Hasher] error at any step is returned as-is, and
// so is the hook's — see the package's "Fail closed" constraint.
func (s *Service) DeleteAccount(ctx context.Context, userID, currentPassword string) error {
	// Step 1. ErrUserNotFound and every other Store error propagate as-is.
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Step 2. Re-authenticate, but ONLY when there is a credential to
	// re-authenticate against. An empty hash is not a failed check here —
	// it is an account that has no password at all, and refusing it would
	// deny every OAuth-only and magic-link-only user a deletion for good.
	// See the method doc, "An account with no password", for the asymmetry
	// with ChangePassword and for what the caller therefore owes.
	if u.PasswordHash != "" && !s.cfg.hasher.Verify(currentPassword, u.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Step 3. The hook, BEFORE any row of ours is written. Its error aborts
	// with nothing deleted, which is only true because this is first.
	if s.cfg.accountDeletionHook != nil {
		if err := s.cfg.accountDeletionHook(ctx, userID); err != nil {
			return err
		}
	}

	// Step 4. Access stops here, before anything irreversible.
	if err := s.store.DeleteSessionsByUser(ctx, userID); err != nil {
		return err
	}

	// Step 5. Every purpose, not the three this package names — see
	// Store.DeleteVerificationsByUser's own doc.
	if err := s.store.DeleteVerificationsByUser(ctx, userID); err != nil {
		return err
	}

	// Step 6, OWED: the identity sweep goes exactly here, between the
	// verifications and the user row, once the optional identity port
	// exists on this branch. It belongs after step 5 for the same reason
	// step 5 follows step 4 — a linked identity is a way IN — and before
	// step 7 so the row outlives everything that points at it. See the
	// method doc, "The identity sweep this does not do yet".

	// Step 7. The row, last.
	return s.store.DeleteUser(ctx, userID)
}
