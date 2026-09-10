// Package auth (this file) is the deletion posture: removing an account and
// everything this package holds for it, and giving the application a hook
// for everything it does not.
//
// Where service.go's methods each own one flow (sign up, log in, refresh),
// [Service.DeleteAccount] is a CASCADE across every record kind this
// package persists — the three the [Store] owns AND the external identities
// the optional [IdentityStore] owns — and the interesting part of it is the
// ORDER, see that method's doc. The three by-user primitives it sequences
// ([Store.DeleteSessionsByUser], [Store.DeleteVerificationsByUser],
// [Store.DeleteUser]) are deliberately separate methods on the port rather
// than one DeleteAccount there, because the order is a policy decision that
// belongs to this layer: see auth.go's package doc, "Deletion, and why it is
// on this port rather than beside it". The identity sweep is one step in
// that same order rather than a fifth primitive, because it reaches a
// DIFFERENT port, which is also why nothing here is transactional.
//
// # Two postures, one shape
//
// [Service.AnonymizeAccount] is the SOFT posture and shares that shape
// exactly: same re-authentication rule (including its password-less
// asymmetry), same hook, same fail-safe order, same non-atomicity
// disclosure. It differs in one step and one consequence. The step: where
// DeleteAccount ends with [Store.DeleteUser], AnonymizeAccount ends with
// [Store.MarkUserDeleted], which keeps the row and scrubs it. The
// consequence: a stamped row is one every authentication entry point has to
// REFUSE, which is a requirement on service.go rather than on this file —
// AnonymizeAccount's doc enumerates every one of them, and there is a test
// per entry point.
//
// A deployment chooses between them on one question: does anything outside
// this package hold the user id? If an audit trail, an order history or a
// foreign key does, the hard posture leaves it dangling and the soft one
// does not. If nothing does, the hard posture is the one that actually
// removes the data.
package auth

import "context"

// WithAccountDeletionHook registers the function BOTH
// [Service.DeleteAccount] and [Service.AnonymizeAccount] call to let the
// application tear down everything authlayer does not own, before authlayer
// removes or scrubs anything of its own. A nil f is ignored, leaving the
// default (no hook) or a prior option in place, matching [WithHasher] and
// every other option in this package.
//
// One hook covers both postures, and is not told which one is running. That
// is deliberate: the hook's job is the data authlayer cannot reach — the
// [github.com/bernardoforcillo/authlayer/scope] memberships, the
// application's own tables — and that data has to go in both cases. An
// anonymized account whose memberships survived would still be a member of
// every container it was in, which is the exact failure the hook exists to
// prevent, so there is no version of "soft" that means "leave the
// application's rows alone". A deployment that genuinely wants to keep
// something on the soft path knows which of its own tables that is; the
// hook does not need to be told the posture to decide it.
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
// It receives only the user id — the same string [Service.DeleteAccount] or
// [Service.AnonymizeAccount] was given, and the key everything an
// application stores about a user is reachable by. It is NOT handed the
// [UserBase]: a hook that needs the address (to remove it from a mailing
// list, say) must load it itself, through the Store or its own tables,
// BEFORE the account goes. Afterwards there is nothing left to look it up
// from — a hard delete removed the row, and a soft one scrubbed the address
// off it.
//
// It MUST tolerate being called more than once for the same user id. Both
// methods' steps after the hook are not atomic (see their own docs), so a
// caller whose deletion failed part-way through will reasonably retry — and
// the retry runs the hook again, against an application that has already
// done its cleanup. "Delete these rows if they are there" is the shape that
// survives; "decrement a counter" is not. A deployment that anonymizes and
// LATER hard-deletes the same account runs the hook twice for that reason
// too, with an ordinary success in between.
//
// The hook's error is returned to the calling method's caller AS-IS, unwrapped,
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
// package holds for it — every session, every verification, every linked
// external identity, and the user row itself — after re-authenticating the
// caller with currentPassword and giving the application's own cleanup (see
// [WithAccountDeletionHook]) the chance to run and to refuse.
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
//     Point 2 has a SECOND half since step-up landed:
//     [Service.RequireFreshMFA] with currentSessionID. An account holding a
//     CONFIRMED [MFAFactor] must present this call from a session of its
//     own that proved a second factor inside [WithStepUpWindow], or this is
//     [ErrStepUpRequired] with nothing written and no hook fired; an
//     account with no confirmed factor is unaffected, and that method's doc
//     carries the reasoning for both halves. It runs after the password
//     check so a wrong password is reported as a wrong password, and before
//     point 3 so a refusal has run none of the application's own cleanup.
//     An ALREADY-ANONYMIZED account is exempt from it: it holds no session
//     that could ever satisfy the check and nothing signs into it, so
//     gating it would contradict point 1 and leave a stamped row nothing
//     could remove. For an account with a confirmed factor and NO password,
//     this check is the only credential in the call — see "An account with
//     no password".
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
//  6. Identities, when the [Service] was built with [WithIdentityStore]:
//     every [Identity] linked to the account, via
//     [IdentityStore.DeleteIdentity]. A linked social account is a way IN
//     that needs no password at all, so it goes for the same reason step 5
//     goes and before step 7 so the row outlives everything pointing at
//     it. A Service with no identity store configured sweeps nothing here
//     and reports no error — see [Service.sweepIdentities] for that, and
//     for the two-Services-one-users-table configuration it cannot cover,
//     which is this step's one stated limit.
//     Step 6 has had a SECOND half since trusted devices landed and a
//     THIRD since passkeys got a column, and the split between them is
//     "is this a way IN".
//     6b. PASSKEYS, when the [Service] was built with
//     [WithCredentialStore]: every [Credential] the account holds, in one
//     [CredentialStore.DeleteCredentialsByUser] via
//     [Service.sweepCredentials]. It sits with step 6 rather than with 6c
//     because it is the same KIND of thing — a way IN that needs no
//     password at all, and the most direct one this package has, since
//     [Service.FinishPasskeyLogin] asks for nothing else. A surviving row
//     is a working sign-in credential filed under an id that no longer
//     resolves, and a later account issued that id under a non-random
//     [WithIDGenerator] would inherit it. The sweep is by USER and makes no
//     reachability check: [ErrLastCredential] is precisely the refusal that
//     would preserve what this call is destroying. A Service with no
//     credential store sweeps nothing here and reports no error, the same
//     limit step 6 carries.
//     6c. The account's second-factor state, when the [Service] was built
//     with [WithMFAStore] — every [TrustedDevice]
//     ([Service.sweepTrustedDevices]), then every [RecoveryCode] and the
//     [MFAFactor] itself ([Service.sweepMFAState]). Two calls on two lines,
//     because they are two columns of the sweep matrix and removing one
//     must fail only its own cell. Neither is a way IN on its own — both
//     need a first factor this call is about to remove — which is why they
//     follow steps 6 and 6b rather than preceding them, and they still
//     precede step 7 so the row outlives everything keyed on it. A Service
//     with no MFA store sweeps nothing here and reports no error, the same
//     limit step 6 carries. See "The second-factor state goes too" below.
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
// # The second-factor state goes too
//
// Step 6c sweeps what no REMEDIATION path in the matrix sweeps: the
// [MFAFactor], the [RecoveryCode]s, and the [TrustedDevice]s. The asymmetry
// is the whole of this column's argument.
//
// A remediation path must not touch the factor. [Service.ChangePassword] and
// [Service.ResetPassword] rotate the FIRST factor, and sweeping the second
// one there would mean that whoever compromised a password — or a mailbox,
// on the reset path — could strip the second factor by exercising the
// recovery flow it exists to survive. Two independent factors would collapse
// into one, in the direction of the attacker. So they leave it alone, and
// the matrix says so.
//
// Termination is not remediation. Here the account is ending, and every row
// keyed on the user id has to go with it, for two reasons this package
// already accepts elsewhere:
//
//   - A surviving [MFAFactor] row is an encrypted TOTP secret filed under an
//     id that no longer resolves, and a surviving [RecoveryCode] set is a
//     handful of password-grade hashes beside it. The identity sweep at step
//     6 states the consequence for its own rows and it is identical here: a
//     later account issued the same id would INHERIT a confirmed second
//     factor it never enrolled, and a confirmed factor is a login gate — so
//     the inheriting user would be asked for a code only its predecessor
//     could produce. [WithIDGenerator] makes an id sequence a supported
//     configuration, so "ids are never reused" is a property of the default
//     generator and not of this package.
//   - "Delete my account" means the data as well as the access. A TOTP
//     secret is a bearer credential the user handed over; leaving it in the
//     database after they asked for removal is the same defect as leaving
//     their address there.
//
// [Service.AnonymizeAccount] performs the identical sweep, where it matters
// MORE rather than less: that posture keeps the row, so a factor left behind
// would sit under a LIVE user id, on an account the deployment has told the
// user is closed.
//
// Trusted devices are the fourth column and need no separate argument here:
// they are swept by every path in the matrix that sweeps anything, because a
// long-lived token whose only meaning is "skip the second factor" has no
// reading under which it should survive a remediation or a termination.
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
// Steps 4 through 7 are SEPARATE STORE CALLS with no transaction around
// them, and there cannot be one. [Store] exposes no transaction (see
// auth.go's package doc), step 6's identities live behind a DIFFERENT port
// ([IdentityStore]) that may be a DIFFERENT backend entirely, and the hook
// at step 3 reaches tables this package has no connection to at all. There
// is no scope in which a single commit could cover them.
//
// So a failure part-way is reachable, and this method does not pretend
// otherwise: it stops at the first error and returns it, leaving whatever
// earlier steps already removed removed. What the ORDER buys is that every
// such partial state falls on the same side:
//
//   - Fail at step 5, 6 or 7: the sessions are gone and the row is still
//     there. The account cannot be logged into and cannot be refreshed
//     into, and it is still present to retry the whole call against —
//     which is safe, because steps 4 and 5 both treat "matched no rows" as
//     success (see their own docs on [Store]) and step 6 treats a row
//     another caller already removed as success too, so none of them costs
//     anything the second time. A failure INSIDE step 6 can leave some of
//     the account's identities deleted and the rest standing; each of those
//     survivors is still a way in, which is why the error is returned
//     rather than swallowed and why the retry above is not optional.
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
// method removes is the only place one could live.
// [Service.AnonymizeAccount] — the soft posture, which keeps the row and
// stamps [UserBase.DeletedAt] instead — is the answer for a deployment that
// cannot tolerate the row disappearing at all. It is not a substitute for
// this method: it leaves the id resolvable on purpose, and a deployment
// that must genuinely erase the row still wants this one.
//
// # The identity sweep, and the one configuration it cannot reach
//
// Step 6 removes every [Identity] the configured [IdentityStore] holds for
// the account. An identity row surviving its user would be a credential
// pointing at an id that no longer resolves, and a later account issued
// that same id would inherit it — which is why this is a sweep rather than
// something left to the hook.
//
// It can only remove rows through the port THIS Service holds. A Service
// built WITHOUT [WithIdentityStore], over a users table that some OTHER
// Service does wire one to, sweeps nothing and reports no error: the
// identities survive, and that deployment must delete them from the hook.
// That is the same stated limit [Service.sweepIdentities] carries for
// [Service.ResetPassword], and it is a property of the wiring, not of this
// method.
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
func (s *Service) DeleteAccount(ctx context.Context, userID, currentSessionID, currentPassword string) error {
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

	// Step 2b. Step-up, on this method's own line — see
	// [Service.RequireFreshMFA]. After the password check and BEFORE the
	// hook, so a refused deletion has run none of the application's own
	// cleanup. A no-op for an account with no confirmed factor; for an
	// account that has one AND no password, it is the only credential in
	// this call.
	//
	// An ANONYMIZED account is exempt, and that exemption is load-bearing:
	// such an account holds no sessions (the anonymization deleted them)
	// and can be signed into by nothing, so the check could never be
	// satisfied — and this method must keep working against a stamped row,
	// or a deployment that anonymized an account with a confirmed factor
	// would be left holding a row nothing could ever remove. See "A stamped
	// account is still deletable" and [Service.RequireFreshMFA]'s "An
	// account with no confirmed factor is not gated", which is the same
	// argument reached by a different route: an unsatisfiable refusal on an
	// operation that grants nothing is a lockout, not a control.
	if u.DeletedAt == nil {
		if err := s.RequireFreshMFA(ctx, userID, currentSessionID); err != nil {
			return err
		}
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

	// Step 6. Every linked identity, between the verifications and the
	// user row. It belongs after step 5 for the same reason step 5 follows
	// step 4 — a linked identity is a way IN — and before step 7 so the row
	// outlives everything that points at it. A Service with no
	// [WithIdentityStore] sweeps nothing here and reports no error; see
	// [Service.sweepIdentities].
	if err := s.sweepIdentities(ctx, userID); err != nil {
		return err
	}

	// Step 6b. Every passkey, on this method's own line — the matrix's
	// eighth column. It sits BESIDE the identity sweep rather than with 6c
	// because it is the same kind of thing: a way IN that needs no password,
	// and the most direct one this package has. A failure at 6c with the
	// credentials still standing would leave a live, password-less door into
	// an account whose sessions are already gone; the reverse cannot happen.
	// A Service with no [WithCredentialStore] sweeps nothing here and reports
	// no error — see [Service.sweepCredentials].
	if err := s.sweepCredentials(ctx, userID); err != nil {
		return err
	}

	// Step 6c. The second-factor state: every [TrustedDevice], then the
	// recovery codes and the [MFAFactor]. Two calls on two lines, because
	// they are two columns of the matrix and removing one must fail only its
	// own cell. See "The second-factor state goes too" in the method doc for
	// why a termination path sweeps what no remediation path does.
	//
	// After steps 6 and 6b rather than before them because neither is a way
	// IN — both require a first factor this call is about to remove — and
	// before step 7 so the row still outlives everything keyed on it. A
	// Service with no [WithMFAStore] sweeps nothing here and reports no
	// error, the same limit [Service.sweepIdentities] carries.
	if err := s.sweepTrustedDevices(ctx, userID); err != nil {
		return err
	}
	if err := s.sweepMFAState(ctx, userID); err != nil {
		return err
	}

	// Step 7. The row, last.
	if err := s.store.DeleteUser(ctx, userID); err != nil {
		return err
	}
	// [AccountDeleted], after the row: the id on the event resolves to
	// nothing any more, which is the fact the hook is being told.
	return s.emit(ctx, Event{Kind: AccountDeleted, UserID: userID, SessionID: currentSessionID})
}

// anonymizedEmailPrefix and anonymizedEmailDomain spell the scrubbed
// address [Service.AnonymizeAccount] writes: anonymizedEmailPrefix + the
// user's own id + anonymizedEmailDomain.
//
// The domain is under .invalid, which RFC 2606 §2 reserves precisely so that
// it can never be delegated and mail to it can never be delivered — so the
// scrubbed address is unusable by construction rather than by convention,
// even if someone later points a real MX record at every domain the
// deployment owns. The prefix is what makes a row recognisable at a glance
// in a `SELECT email FROM users` an operator runs.
const (
	anonymizedEmailPrefix = "deleted-"
	anonymizedEmailDomain = "@example.invalid"
)

// anonymizedEmail is the address [Service.AnonymizeAccount] scrubs an
// account down to. See that method's doc, "The scrubbed address", for the
// full reasoning; the short version is that the user id is the only value in
// hand that is already unique across the users table, which is what keeps
// two anonymizations from colliding on Email's UNIQUE constraint.
//
// It is not normalized here. [Store.MarkUserDeleted] normalizes on the way
// in, exactly as [Store.UpdateUserEmail] does, so this returns the address
// in its natural form and the store decides the canonical one.
func anonymizedEmail(userID string) string {
	return anonymizedEmailPrefix + userID + anonymizedEmailDomain
}

// AnonymizeAccount is the SOFT counterpart to [Service.DeleteAccount]: it
// keeps userID's row and empties it, after the same re-authentication with
// currentPassword and the same chance for the application's own cleanup
// (see [WithAccountDeletionHook]) to run and to refuse.
//
// What survives is the id and the timestamps. What goes is everything that
// could identify or authenticate the person: the address is replaced with an
// undeliverable one derived from the id, the password hash is cleared, the
// address verification is cleared, and every session, every verification and
// every linked external identity the account held is removed. [UserBase.DeletedAt] is stamped, and from that
// moment every authentication entry point in this package refuses the
// account — see "Every entry point that refuses a stamped account" below,
// which is the part of this feature that must not be got wrong.
//
// Choose this over DeleteAccount when something outside this package holds
// the user id — an audit trail, an order history, a foreign key that cannot
// be dropped. Choose DeleteAccount when nothing does, because this method
// deliberately leaves a row behind.
//
// # Order, and why it is the same as DeleteAccount's
//
//  1. [Store.FindUserByID] loads the account. A miss is [ErrUserNotFound],
//     propagated as-is; any other Store error too. An account ALREADY
//     anonymized is not refused — see "Anonymizing twice" below.
//  2. Re-authentication, when the account HAS a password: currentPassword
//     is checked against the stored hash with the configured
//     [github.com/bernardoforcillo/authlayer/password.Hasher], and a
//     mismatch is [ErrInvalidCredentials] with nothing written and no hook
//     fired. An account with NO password proceeds on the caller's
//     authority, whatever currentPassword holds — the same asymmetry with
//     [Service.ChangePassword], for the same reasons, that
//     [Service.DeleteAccount]'s doc sets out at length under "An account
//     with no password". Everything it says there applies here unchanged,
//     including what the caller therefore owes: establish that the caller
//     owns the account before calling.
//     Point 2's second half is [Service.RequireFreshMFA] with
//     currentSessionID — DeleteAccount's, verbatim, including the exemption
//     for an account that is already anonymized, which here is also what
//     keeps "Anonymizing twice" true. It is this method's OWN call, not one
//     the two postures share.
//  3. The hook, if one is configured — BEFORE any authlayer row is written,
//     so its error aborts with nothing written. See
//     [WithAccountDeletionHook], and note it is the SAME hook DeleteAccount
//     fires and is not told which posture is running.
//  4. [Store.DeleteSessionsByUser] — every family. ACCESS STOPS HERE.
//  5. [Store.DeleteVerificationsByUser] — every purpose. No pending reset
//     or email-change token may outlive the account.
//  6. Identities, when the [Service] was built with [WithIdentityStore]:
//     every [Identity] linked to the account, via
//     [IdentityStore.DeleteIdentity], exactly as in
//     [Service.DeleteAccount]. This is the step that must not be skipped on
//     the soft path: a surviving identity is a way in that needs no
//     password, and step 7 clears the password hash — so an anonymized
//     account whose identities survived would be MORE reachable through
//     [Service.SignInWith] than through anything else, not less. A Service
//     with no identity store configured sweeps nothing here and reports no
//     error; see [Service.sweepIdentities] for that limit.
//     Steps 6b and 6c are [Service.DeleteAccount]'s verbatim. 6b is every
//     [Credential] the account holds, and it matters MORE on this posture
//     than on the hard one for the reason step 7 makes plain: the row
//     SURVIVES and its password hash is cleared, so a surviving passkey
//     would be the only thing left that could authenticate an account the
//     deployment has told its owner is closed — which is exactly what
//     [UserBase.DeletedAt] forbids, and why [Service.FinishPasskeyLogin]
//     refuses a stamped row too. 6c is every [TrustedDevice], then the
//     [RecoveryCode]s and the [MFAFactor], on two lines; a factor left
//     behind is an encrypted TOTP secret filed under a live user id. See
//     "The second-factor state goes too" in DeleteAccount's doc.
//  7. [Store.MarkUserDeleted] — the scrub and the stamp, LAST, and as ONE
//     atomic step: that method's own MUST is what keeps a caller from ever
//     seeing a row stamped-but-not-scrubbed or scrubbed-but-not-stamped.
//     Read its doc for why each of those halves is a security bug on its
//     own.
//
// Step 7 replaces DeleteAccount's [Store.DeleteUser] and is the only
// difference in the sequence. It is last for the same reason the user row is
// last there: a failure part-way must leave an account that CANNOT BE USED
// and is still there to retry against, never one whose data is gone while
// its credentials live.
//
// # The scrubbed address
//
// The account's Email becomes, exactly:
//
//	deleted-<the account's own user id>@example.invalid
//
// with the whole thing normalized by the Store on the way in (see
// [NormalizeEmail]), so for a UUIDv7 id it reads
// deleted-01900e1a-....@example.invalid in the table. Three properties, each
// load-bearing:
//
//   - UNIQUE, because the user id already is. [UserBase.Email] carries a
//     UNIQUE constraint, so two anonymized accounts landing on one address
//     would mean the second anonymization fails with [ErrEmailTaken] and an
//     account the user asked to close stays open. Deriving from the id is
//     what rules that out; a constant like "deleted@example.invalid" would
//     work exactly once per deployment. One caveat, stated rather than
//     glossed: [NormalizeEmail] lower-cases, so this inherits uniqueness
//     from the CASE-FOLDED id, not the raw one. The default id generator
//     mints lower-case UUIDv7s, so that is a distinction without a
//     difference — but a [WithIDGenerator] that can mint two ids differing
//     only in case would make their two anonymizations collide, and the
//     second would be refused with ErrEmailTaken having written nothing.
//   - UNDELIVERABLE, because .invalid is reserved by RFC 2606 §2 as a
//     top-level domain that can never be delegated. No mail reaches it, no
//     password-reset link can be sent to it, and it cannot collide with a
//     real address a user might one day register.
//   - RECOGNISABLE, so an operator reading the users table can tell an
//     anonymized row from a live one without joining anything, and can find
//     them all with a LIKE. (DeletedAt is the field to actually TEST; the
//     prefix is for human eyes.)
//
// It is not a secret and must not be treated as one: anyone who knows the
// user id can compute it. That is precisely why the entry points below
// refuse the row rather than relying on the address being unguessable — a
// [Service.RequestPasswordReset] naming the scrubbed address must get the
// same nothing an unknown address gets.
//
// The original address, meanwhile, is FREE the moment this returns: a new
// [Service.SignUp] under it succeeds and creates a genuinely new account
// with a new id. The anonymized row and the new account coexist, which is
// the point — the old id keeps resolving for whatever still references it.
//
// # Every entry point that refuses a stamped account
//
// A non-nil [UserBase.DeletedAt] means "no one may authenticate as this
// account, by any route" ([UserBase.DeletedAt] says so). That is enforced
// here, one explicit check per entry point, never one shared guard several
// paths happen to pass through — so removing any single one of them fails
// exactly one test:
//
//   - [Service.Login] — [ErrInvalidCredentials], after
//     [github.com/bernardoforcillo/authlayer/password.Hasher.Dummy], which
//     makes it indistinguishable in both error and cost from a wrong
//     password and from an unknown address. Anything else would tell an
//     anonymous caller that a particular address once had an account.
//   - [Service.RequestPasswordReset] — ("", false, nil), NOT an error. This
//     method's whole contract is that a caller cannot learn whether an
//     address is registered, so a stamped account takes the same branch an
//     unknown address takes, with the same call sequence: no verification is
//     minted and nothing distinguishes the two.
//   - [Service.Refresh] — [ErrUserNotFound], at step 4, so a refresh token
//     that somehow outlived step 4 above still buys nothing.
//   - [Service.ChangePassword] — ErrUserNotFound, before the credential is
//     even checked. There is no password on a stamped account to change,
//     and arming a new one would hand the account back.
//   - [Service.RequestEmailChange] — ErrUserNotFound. This one ARMS an
//     identifier rotation, so allowing it would let a caller move a real,
//     deliverable address back onto an anonymized row.
//   - [Service.ResetPassword] — ErrUserNotFound, before the token is
//     burned. Step 5 already deleted every pending token, so this is
//     defence in depth against one minted by a route this package does not
//     own — but "defence in depth" is not "unreachable", and a reset that
//     succeeded here would put a working password on a closed account.
//   - [Service.VerifyEmail] — ErrUserNotFound, before the token is burned.
//     This is the entry point with the sharpest consequence and the one
//     easiest to miss, because it takes no address and no password: an
//     "email_change" redemption calls [Store.UpdateUserEmail], which would
//     move a real, VERIFIED address back onto the stamped row, un-scrubbing
//     it and taking that address out of circulation again.
//   - [Service.RequestMagicLink] — ("", false, nil), NOT an error, for
//     exactly the reason RequestPasswordReset returns the same thing: this
//     method's entire shape is a promise that a caller cannot learn whether
//     an address is registered, and a new error here would be the oracle
//     that promise exists to close. A stamped account takes the same branch
//     an unregistered address takes, and — with
//     [WithMagicLinkProvisioning] enabled — is not provisioned either, so
//     nothing is minted and nothing is created. See that method's doc for
//     the one residual this leaves.
//   - [Service.RedeemMagicLink] — ErrUserNotFound, AFTER the claim, so the
//     link is burned on the way out. That is the opposite side of
//     ResetPassword's choice above, deliberately: a "magic_link" token IS a
//     session credential rather than the right to set one, so destroying
//     one aimed at a closed account is remediation rather than a cost, and
//     it needs no extra read to do it.
//   - [Service.SignInWith] — ErrUserNotFound, on BOTH rungs of its ladder
//     and with a separate check on each, because they reach an account two
//     different ways: rung 1 through a linked [Identity], rung 2 through a
//     matching address. Step 6 above has already removed the identities, so
//     rung 1 is defence in depth; rung 2 is reachable under [LinkAlways]
//     against a provider willing to assert the scrubbed address. Without
//     these an anonymized account would be MORE reachable through an
//     external provider than through any local credential, since step 7
//     removes the password and leaves nothing else to refuse on.
//   - [Service.LinkIdentity] — ErrUserNotFound, before the pair is even
//     looked up, so a stamped row can never acquire a fresh credential.
//     This one ARMS a way in rather than using one, which puts it in
//     RequestEmailChange's category, not Login's.
//
// ErrUserNotFound, rather than a new sentinel, is deliberate. It is already
// in every one of those methods' documented error sets (each of them can
// meet a row that vanished under it), so no caller's error handling changes;
// and it says the true thing, which is that for authentication purposes the
// account is gone. The row surviving is a fact about the deployment's
// foreign keys, not about whether the account exists.
//
// # What deliberately keeps working
//
//   - [Service.User] returns the stamped row, PasswordHash cleared as
//     always. Reading it is how an application discovers an account is
//     anonymized at all, so refusing here would remove the only signal.
//   - [Service.DeleteAccount] hard-deletes a stamped account. Refusing
//     would leave a row nothing could ever remove.
//   - AnonymizeAccount itself — see "Anonymizing twice".
//   - [Service.Logout], [Service.LogoutAll], [Service.ListSessions] and
//     [Service.RevokeSession] are unguarded because they only ever REVOKE.
//     None of them grants access, and step 4 has already emptied the
//     account's sessions, so there is nothing left for any of them to do:
//     Logout and LogoutAll return nil, ListSessions returns nothing, and
//     RevokeSession returns [ErrSessionNotFound] because the id it was
//     given no longer names one of the account's sessions — which is what
//     it returns for any unknown session id, stamped account or not.
//   - [Service.SignUp] is not an entry point into an existing account at
//     all: it never returns the account it found, only whether it created
//     one. A sign-up naming the scrubbed address takes SignUp's ordinary
//     already-registered branch — [SignUpResult.Created] false, a zero
//     User, a nil error, and no way in — the same as any taken address. A
//     sign-up naming the ORIGINAL address creates a genuinely new account,
//     which is the intended behaviour and is what "the address is free
//     again" means.
//   - [Service.VerifyAccessToken] cannot check, because it never touches the
//     Store — see "What this does not revoke".
//
// # The one refusal this package cannot make
//
// [Service.VerifyAccessToken] never touches the [Store], so it cannot see
// DeletedAt at all — see "What this does not revoke" below. Every refusal
// listed above is a refusal to MINT or ROTATE; an access token already
// issued keeps verifying on its own signature until it expires. That is the
// single hole in "no one may authenticate as this account, by any route",
// it is bounded by [WithJWT]'s TTL (fifteen minutes by default), and the
// per-request SessionID lookup that closes it is described below.
//
// # What is not atomic here, and why
//
// Steps 4 through 7 are SEPARATE STORE CALLS with no transaction around
// them, and there cannot be one, for exactly the reasons
// [Service.DeleteAccount]'s "What is not atomic here, and why" gives: the
// port exposes no transaction, step 6's identities live behind a different
// port that may be a different backend, and the hook reaches tables this
// package has no connection to. Step 7 is atomic WITHIN ITSELF — that is
// [Store.MarkUserDeleted]'s MUST — but not with respect to steps 4 to 6.
//
// So a failure part-way is reachable, and every partial state falls on the
// same side:
//
//   - Fail at step 5, 6 or 7: the sessions are gone and the row is still
//     there, unstamped and still holding its own address. The account cannot
//     be logged into or refreshed into, and the whole call can simply be run
//     again — steps 4 and 5 both treat "matched no rows" as success, step 6
//     treats an identity another caller already removed as success, and
//     step 7 is idempotent for the same reason "Anonymizing twice" gives.
//     A failure INSIDE step 6 is the one partial state worth naming: some
//     identities gone, the rest standing, and the row not yet stamped — so
//     the account is still refused nowhere and its surviving identities
//     still sign in. It is an UNANONYMIZED account, which is the safe
//     direction, and the returned error is the signal to run the call
//     again.
//   - Fail at step 4: nothing at all has been removed. The hook has already
//     run, which is why it must tolerate running again.
//
// The state this ordering makes UNREACHABLE is a stamped row that still has
// live sessions — an account every entry point reports as closed while its
// refresh tokens keep rotating.
//
// # Anonymizing twice
//
// A second AnonymizeAccount on an already-anonymized account succeeds and
// changes nothing meaningful — including when the account holds a confirmed
// [MFAFactor], which is why the step-up check exempts a stamped row: nothing here
// sweeps factor rows, and a stamped account has no session left that could
// ever prove one. It re-runs the hook (which must tolerate that
// — see [WithAccountDeletionHook]), sweeps three already-empty record kinds,
// and re-writes the same scrubbed address the row already holds, which
// [Store.MarkUserDeleted] does not treat as a self-conflict. It also never
// re-authenticates, because step 2's no-password branch is where an
// anonymized account lands by construction: its hash was cleared the first
// time.
//
// That last point is worth stating plainly rather than leaving to be
// inferred, because it means the re-authentication gate protects the FIRST
// anonymization only. Nothing is lost — there is nothing left on the row to
// take — but a caller must not read "AnonymizeAccount checks the password"
// as a property that holds on every call.
//
// # What this does not revoke
//
// ACCESS tokens, identically to [Service.DeleteAccount] — see that method's
// "What this does not revoke" for the full statement. Every [Session] row is
// gone, so [Service.Refresh] fails on all of them immediately, but a
// short-lived HS256 JWT already issued keeps verifying against
// [Service.VerifyAccessToken] until its own TTL runs out, because that call
// never consults the Store. Here the deployment-side check that closes it is
// EASIER than after a hard delete: the user row still exists, so an
// application looking up the SessionID ("sid") claim per request finds a real
// account and can test DeletedAt directly, instead of having to treat "no
// such user" as a refusal.
//
// A [Store] or
// [github.com/bernardoforcillo/authlayer/password.Hasher] error at any step
// is returned as-is, and so is the hook's — see the package's "Fail closed"
// constraint.
func (s *Service) AnonymizeAccount(ctx context.Context, userID, currentSessionID, currentPassword string) error {
	// Step 1. ErrUserNotFound and every other Store error propagate as-is.
	// An already-anonymized account is NOT refused here — see the method
	// doc, "Anonymizing twice".
	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Step 2. Re-authenticate, but ONLY when there is a credential to
	// re-authenticate against — DeleteAccount's rule verbatim, including
	// the asymmetry with ChangePassword that its doc explains. An
	// already-anonymized account has no hash and lands here by
	// construction.
	if u.PasswordHash != "" && !s.cfg.hasher.Verify(currentPassword, u.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Step 2b. Step-up, on this method's OWN line — DeleteAccount's rule
	// verbatim, and its own call rather than one the two share, so that
	// removing either fails only its own test. See [Service.RequireFreshMFA].
	//
	// The same exemption for an ALREADY-ANONYMIZED account, for the same
	// reason and for one more: this method is documented to be repeatable
	// (see "Anonymizing twice"), and a stamped account has no session left
	// that could ever satisfy the check. Step 6c now sweeps the [MFAFactor]
	// too, so an account this method has already run against normally holds
	// no confirmed factor and would not be gated anyway — but "normally" is
	// not "always" (a partial failure, or a second Service wired over the
	// same tables), and gating the repeat on the exception would turn a
	// documented no-op into a permanent refusal.
	if u.DeletedAt == nil {
		if err := s.RequireFreshMFA(ctx, userID, currentSessionID); err != nil {
			return err
		}
	}

	// Step 3. The hook, BEFORE any row of ours is written. Its error aborts
	// with nothing written, which is only true because this is first.
	if s.cfg.accountDeletionHook != nil {
		if err := s.cfg.accountDeletionHook(ctx, userID); err != nil {
			return err
		}
	}

	// Step 4. Access stops here, before anything irreversible.
	if err := s.store.DeleteSessionsByUser(ctx, userID); err != nil {
		return err
	}

	// Step 5. Every purpose, not the three this package names.
	if err := s.store.DeleteVerificationsByUser(ctx, userID); err != nil {
		return err
	}

	// Step 6. Every linked identity, between the verifications and the
	// stamp — a surviving identity is a way in that needs no password, and
	// step 7 is about to remove the password. A Service with no
	// [WithIdentityStore] sweeps nothing here and reports no error; see
	// [Service.sweepIdentities].
	if err := s.sweepIdentities(ctx, userID); err != nil {
		return err
	}

	// Step 6b. Every passkey — [Service.DeleteAccount]'s step 6b verbatim,
	// and the step this posture needs most: step 7 clears the password hash,
	// so a surviving credential would be the only thing left that could
	// authenticate a row the deployment has told its owner is closed.
	if err := s.sweepCredentials(ctx, userID); err != nil {
		return err
	}

	// Step 6c. The second-factor state — [Service.DeleteAccount]'s step 6c
	// verbatim, two calls on two lines so each column of the matrix fails
	// alone. It matters MORE on this posture than on the hard one: the row
	// survives here, so a factor left behind is an encrypted TOTP secret and
	// a set of recovery-code hashes filed under a live user id that the
	// account's owner has asked to be scrubbed. See "The second-factor state
	// goes too" in [Service.DeleteAccount]'s doc.
	if err := s.sweepTrustedDevices(ctx, userID); err != nil {
		return err
	}
	if err := s.sweepMFAState(ctx, userID); err != nil {
		return err
	}

	// Step 7. The scrub and the stamp, last, and as one atomic step: the
	// address becomes undeliverable, the credential and the verification go,
	// and DeletedAt is what every entry point above then refuses on.
	if err := s.store.MarkUserDeleted(ctx, userID, anonymizedEmail(userID), s.cfg.clock()); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: AccountAnonymized, UserID: userID, SessionID: currentSessionID})
}
