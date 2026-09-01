// Package auth (this file) is step-up authentication: the rule that the
// handful of actions which can take an account away must be performed from a
// session that proved a second factor RECENTLY, not merely at some point in
// its history.
//
// # Freshness is a time, and that is the whole design
//
// [Session.MFAAt] records WHEN a session last proved a factor.
// [Service.RequireFreshMFA] refuses when it is nil, and refuses again once
// it is older than [WithStepUpWindow] — fifteen minutes by default.
//
// The alternative, a boolean "this session has passed MFA", is what makes
// the feature worthless. A refresh token lives thirty days by default
// ([WithRefreshTTL]), so a session that satisfied a boolean check would keep
// satisfying it for a month after the code was typed, from a laptop left in
// a hotel room, by whoever picked it up. The second factor is bought to
// answer "is the accountholder here NOW", and only a timestamp compared
// against a window can answer that. Spec §4.5 is explicit about it and so is
// this implementation: there is no boolean anywhere on this path.
//
// # An account with no confirmed factor is not gated
//
// This is the rule that decides whether the feature is shippable, and it is
// stated before the ladder because it is the one a reader must not miss: an
// account with NO confirmed [MFAFactor] cannot step up. There is nothing it
// could present, no flow that would satisfy the refusal, and no support path
// short of a human. So [Service.RequireFreshMFA] returns nil for it.
//
// Without that no-op, turning step-up on would lock every non-MFA user out
// of changing their own password — the majority of a typical deployment's
// users, refused by a check they cannot satisfy, on the very action they
// take when they think they have been compromised. The same reasoning covers
// an UNCONFIRMED factor (which gates nothing anywhere else in this package
// either — see auth/mfa_service.go) and a Service with no [WithMFAStore]
// wired at all.
//
// The consequence is worth naming rather than hiding: step-up protects
// accounts that hold a second factor, and NOT the ones that do not. It is a
// second lock on a door that already has one, never a first lock on a door
// that has none.
//
// # What it gates, and what it deliberately does not
//
// Five methods call it, each on its own line rather than through a guard
// they share:
//
//   - [Service.ChangePassword] — rotating the credential.
//   - [Service.RequestEmailChange] — arming an identifier rotation, which
//     [Service.VerifyEmail] then redeems with no authentication at all.
//   - [Service.DeleteAccount] and [Service.AnonymizeAccount] — the two
//     irreversible ones.
//   - [Service.DisableMFA] — turning the second factor off, which is the
//     single most valuable action available to whoever holds a stolen
//     session, and the one that makes every other gate in this file
//     removable.
//
// Each of the five ALSO requires the account's current password, and the
// step-up check runs AFTER that check, never before: a caller who does not
// know the password is told exactly that, and learns nothing about what
// second factor the account holds. The one gap in that pairing belongs to
// [Service.DeleteAccount] and [Service.AnonymizeAccount], which proceed
// without a password for an account that HAS none (see DeleteAccount's "An
// account with no password") — for such an account holding a confirmed
// factor, this check is then the only credential in the call. Both also
// exempt an already-ANONYMIZED account, which holds no session that could
// satisfy it; each states why in its own ordering.
//
// [Service.LogoutAll] and [Service.RevokeSession] are deliberately NOT
// gated. Both only ever REMOVE access, so the worst a stolen session can do
// with them is sign its own thief out; gating them would mean a user who
// suspects a compromise, and whose window has lapsed, cannot cut sessions
// off until they find their authenticator. Refusing a remediation is the
// wrong direction to fail in.
//
// There is no in-place step-up method — nothing that re-stamps the session a
// caller already holds. A user whose window has lapsed proves the factor by
// signing in again, and [Service.CompleteMFA] hands back a NEW session, so
// an application meeting [ErrStepUpRequired] must be prepared to replace the
// tokens it holds rather than to patch the ones it has. That is the same
// exchange [Service.Login] already performs, and adding a second way to
// reach the stamp would mean a second path to audit.
//
// # Mutations, recorded
//
// Two, both run and both restored:
//
//   - Accepting a nil [Session.MFAAt] (dropping the nil check, so a session
//     that never completed MFA passes): failed
//     TestRequireFreshMFARefusesASessionThatNeverProvedAFactor and the five
//     per-method tests, and nothing else.
//   - Dropping the window comparison (so any stamp, however old, passes):
//     failed TestRequireFreshMFARefusesASessionStampedOutsideTheWindow,
//     TestWithStepUpWindowConfiguresTheWindow and
//     TestRefreshCarriesTheFreshnessStampForward — the three tests that are
//     about age rather than about presence — and nothing else.
package auth

import (
	"context"
	"errors"
	"time"
)

// defaultStepUpWindow is how long a proven second factor stays FRESH when
// [WithStepUpWindow] says nothing: fifteen minutes.
//
// It is the same fifteen minutes as the default access-token TTL, and that
// is not a coincidence — it is roughly one session of continuous work, long
// enough that a user changing their password right after signing in is not
// asked for a code twice, short enough that an unattended session goes cold
// before somebody else sits down at it. It is not derived from the access
// TTL and does not move with it: they answer different questions, and a
// deployment that lengthens one has said nothing about the other.
const defaultStepUpWindow = 15 * time.Minute

// ErrStepUpRequired: the action needs a second factor proven RECENTLY, and
// the session named has either never proven one or proved one longer ago
// than [WithStepUpWindow] allows. Nothing was written.
//
// It is deliberately its own sentinel and NOT [ErrMFARequired], because the
// two ask for opposite things. ErrMFARequired means "this account has no
// second factor; go and enrol one", and an application catching it routes
// the user to [Service.BeginMFAEnrolment]. This one means "this account HAS
// one; prove it again", and the route is a fresh sign-in ending in
// [Service.CompleteMFA]. Sending a user with a working authenticator into
// enrolment would refuse them with [ErrMFAAlreadyEnrolled] and leave them
// nowhere.
//
// It is also not [ErrInvalidCredentials]: the credential presented was
// correct, and telling a user their password was wrong when it was right
// sends them to a password reset that changes nothing.
var ErrStepUpRequired = errors.New("authlayer/auth: this action needs a recently proven second factor")

// WithStepUpWindow sets how long a proven second factor stays fresh — how
// old [Session.MFAAt] may be before [Service.RequireFreshMFA] refuses. The
// default is [defaultStepUpWindow], fifteen minutes.
//
// d == 0 DISABLES step-up entirely: RequireFreshMFA returns nil without
// reading anything, and the five methods that call it behave exactly as they
// did before this feature existed. That is a real configuration, not a
// degenerate one — a deployment may reasonably decide its sensitive actions
// are sufficiently protected by the password they already require — and it
// is spelled with the zero value so that it is chosen explicitly rather than
// arrived at.
//
// It is NOT the default, though, and that asymmetry is deliberate: this
// option's unsafe direction is "off", so a Service built by a route that
// forgets [defaultConfig] would carry no step-up at all if zero meant
// "default". defaultConfig assigns the fifteen minutes explicitly, and
// [WithMFAEnforcement]'s opposite stance (zero value = the safe policy)
// holds there because ITS unsafe direction is a lockout rather than a
// bypass.
//
// A NEGATIVE d is ignored, leaving the default (or a prior option) in place,
// matching [WithMagicLinkTTL]'s treatment of the same input. A negative
// window is not "very strict"; it is a window nothing can ever fall inside,
// which would refuse every gated action for every account with a factor —
// including the freshest possible session, one stamped microseconds earlier.
func WithStepUpWindow(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.stepUpWindow = d
		}
	}
}

// RequireFreshMFA reports whether the session named by sessionID, belonging
// to userID, has proved a second factor recently enough to perform a
// sensitive action: nil when it has (or when the account has no factor to
// prove — see below), [ErrStepUpRequired] when it has not.
//
// It is exported because an application's own sensitive actions — deleting a
// workspace, rotating an API key, moving money — deserve the same gate this
// package puts on its own, and there is no way to reach [Session.MFAAt]
// through the public API otherwise.
//
// userID and sessionID are the pair an application already holds after
// validating an access token: the Subject and SessionID claims (see
// [token.Claims] and [Service.VerifyAccessToken]). Passing BOTH is not
// bookkeeping. A session id alone would let a caller satisfy this check with
// any freshly stepped-up session it could obtain — including one on its own
// account — while acting on somebody else's userID, which is precisely the
// authorization this method exists to perform. The session must belong to
// the user named, and a session id that does not is [ErrStepUpRequired],
// indistinguishable from a stale one.
//
// # The ladder
//
//  1. [WithStepUpWindow] is 0: nil, immediately, with no Store call at all.
//     Step-up is off.
//  2. No [WithMFAStore]: nil. This deployment holds no factors, so no
//     account in it can step up.
//  3. [MFAStore.FindFactor] misses, or finds an UNCONFIRMED factor: nil.
//     THE ACCOUNT CANNOT STEP UP — see this file's package doc, "An account
//     with no confirmed factor is not gated". Any other store error is
//     returned as-is and gates the action closed.
//  4. [Store.ListSessionsByUser] locates sessionID among userID's own
//     sessions. Not there — an unknown id, an empty one, or another
//     account's — is [ErrStepUpRequired].
//  5. [Session.MFAAt] is nil: [ErrStepUpRequired]. The session never proved
//     a factor.
//  6. MFAAt is older than the window: [ErrStepUpRequired]. The comparison
//     is half-open, matching every other expiry in this package
//     (`now.Before(stamp.Add(window))`), so a stamp exactly the window's age
//     is stale.
//
// The lookup is a list-and-scan rather than a read by id because [Store] has
// no read-by-id for sessions, and adding one would be a new obligation on
// every backend for a value this method can already reach — the same
// list-and-scan [Service.RevokeSession] and [Service.ChangePassword] already
// perform on the same table.
//
// A rotated (superseded) session is not treated specially: it is a row like
// any other, and the access token minted for it stays valid for its own TTL
// whether or not it has since been rotated away. Refusing one here would
// refuse a caller whose other tab happened to refresh a moment earlier.
func (s *Service) RequireFreshMFA(ctx context.Context, userID, sessionID string) error {
	if s.cfg.stepUpWindow == 0 {
		return nil
	}
	if s.cfg.mfaStore == nil {
		return nil
	}

	// An account with nothing to prove is not asked to prove it.
	switch f, err := s.cfg.mfaStore.FindFactor(ctx, userID); {
	case errors.Is(err, ErrFactorNotFound):
		return nil
	case err != nil:
		return err
	case f.ConfirmedAt == nil:
		return nil
	}

	sessions, err := s.store.ListSessionsByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if sess.ID != sessionID {
			continue
		}
		if sess.MFAAt == nil {
			// This session has never proved a factor. A boolean flag would
			// have nothing else to say; a timestamp says "not yet".
			return ErrStepUpRequired
		}
		if !s.cfg.clock().Before(sess.MFAAt.Add(s.cfg.stepUpWindow)) {
			return ErrStepUpRequired
		}
		return nil
	}
	// Not this user's session (or no session at all). Fail closed, and with
	// the same error a stale one gets: a caller holding somebody else's
	// session id learns nothing from the difference.
	return ErrStepUpRequired
}
