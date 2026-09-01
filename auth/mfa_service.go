// Package auth (this file) is the second factor as a user experiences it:
// enrolling one, the login that stops half way when one is owed, and the
// exchange that finishes such a login. auth/mfa.go holds the persistence
// port these methods drive and the argument for why it is optional;
// internal/totp holds the algorithm.
//
// # Enrolment is two steps, and the second one is not a formality
//
// [Service.BeginMFAEnrolment] mints a secret and hands back a provisioning
// URI, leaving [MFAFactor.ConfirmedAt] nil.
// [Service.ConfirmMFAEnrolment] requires a working code before stamping it.
// Splitting them is the difference between a feature and a support queue: a
// user who scans nothing, scans a URI their app rejects, or scans into a
// phone that is then wiped has, at the end of step one, a factor they
// cannot satisfy. If that factor gated logins, they would be locked out of
// their own account by an enrolment they never finished, with no way back
// that does not involve a human. So an unconfirmed factor gates NOTHING —
// [Service.Login] steps straight past it — and the only act that can stamp
// it is presenting a code the authenticator actually generated.
//
// Recovery codes fall out of the same reasoning one step further along: the
// authenticator can be lost AFTER a successful enrolment too, and then the
// factor is satisfiable by nobody. They are generated at confirmation,
// returned once in plaintext, and stored only as hashes.
//
// # The pending login, and why it is a Verification
//
// A login that owes a second factor cannot return a session and cannot
// return an error either — the password was right. It returns a
// [LoginResult] with empty tokens and a non-nil [LoginResult.MFA]: a
// short-lived, single-use handle to a login that is half done.
//
// That handle is a [Verification] with the new [PurposeMFAChallenge], not a
// sixth table, and the choice is worth stating because a reader will
// wonder. A challenge needs exactly what a Verification already is: a
// random opaque token stored as its sha256, an owner, an expiry, and a
// single-use claim whose atomicity is already a documented MUST on
// [Store.DeleteVerification] and already implemented and tested in both
// backends. A dedicated table would restate all five, add a migration,
// grow [Store] by three methods every existing backend author would owe,
// and get [Store.PurgeExpired] wrong at least once. What it would buy is
// separation for its own sake. The cost of sharing is that "verification"
// now names one thing that is not an address attestation, and that is paid
// for by [PurposeMFAChallenge]'s own doc and by the purpose checks in
// [Service.VerifyEmail], [Service.ResetPassword] and
// [Service.RedeemMagicLink], each of which already refuses purposes it does
// not own.
//
// # What the second factor gates, door by door
//
// This package has FOUR ways into an account, and a second factor that
// bounds only one of them bounds nothing: a deployment that turns MFA on
// believing it mandatory, and offers a magic link beside it, has a second
// factor anyone can walk around. An earlier version gated [Service.Login]
// alone and disclosed the rest as a limitation. It is no longer a
// limitation; every door is decided, and this is the decision:
//
//	Door                        | An account with a CONFIRMED factor | EnforcementRequired, no confirmed factor
//	----------------------------|------------------------------------|----------------------------------------
//	Service.Login               | [MFAChallenge], no session         | [ErrMFARequired]
//	Service.RedeemMagicLink     | [MFAChallenge], no session         | [ErrMFARequired]
//	Service.SignInWith          | [MFAChallenge], no session         | [ErrMFARequired]
//	Service.FinishPasskeyLogin  | a session outright                 | a session outright
//
// Three of the four consult [Service.mfaAtSignIn]; each calls it ITSELF,
// from its own line, rather than through one shared guard the four reach —
// the same discipline the anonymized-account refusals follow, and for the
// same reason: each door has its own test, and removing any one call fails
// exactly that door's test.
//
// Two mutations are recorded rather than asserted. Deleting the call from
// RedeemMagicLink failed both of that door's tests
// (TestRedeemMagicLinkOwesTheSecondFactor and
// TestRedeemMagicLinkRefusesWhenEnforcementRequiresAFactorNobodyHas) plus
// the four-door pin TestEverySignInDoorsDecisionOnTheSecondFactorIsPinned,
// and left every other door's test passing. Deleting SignInWith's rung-1
// call while leaving rung 2's in place failed
// TestSignInWithOwesTheSecondFactorOnTheSubjectRung and NOTHING else —
// which is what proves the two rungs are two checks rather than one guard
// reached twice.
//
// # Why a magic link is not a second factor
//
// A magic link proves control of a mailbox — genuinely, which is why
// [Service.RedeemMagicLink] stamps [UserBase.EmailVerifiedAt]. But that
// same mailbox is where [Service.RequestPasswordReset] delivers, so it is
// already the recovery channel for the FIRST factor. Counting it as the
// second collapses two of the three things a second factor exists to keep
// apart: whoever reads the mailbox would hold both the way to reset the
// password and the way past the factor guarding it. A stolen mailbox is
// the commonest account compromise there is, and it is precisely the one
// MFA is bought to survive.
//
// So a link stands in for the password, never for the factor, and a
// redemption by an account owing one returns a challenge with empty tokens
// exactly as Login does.
//
// # Why an external identity is not one either
//
// A provider may enforce a second factor of its own, and frequently does.
// This package cannot see whether it did, cannot name which one, and
// cannot know whether the deployment trusts it — the assertion
// [Service.SignInWith] receives carries no such statement, and
// [ExternalIdentity] has nowhere to put one. Accepting an external
// identity as the factor would therefore mean trusting an unverifiable
// claim nobody made.
//
// It is also weaker than it looks. Under [LinkVerified] or [LinkAlways] an
// identity is attached to an existing account on the strength of a matching
// ADDRESS, so "signed in with Google" collapses back onto the mailbox
// argument above for any provider willing to assert the address.
//
// A deployment that DOES trust a particular provider's own second factor
// has an honest way to say so, and it is not a flag on this package: run
// [EnforcementOptional] and do not enrol those users, or gate the provider
// at the callback, where the deployment knows which provider answered and
// what it asserted. This package refuses to encode a trust decision it
// cannot verify.
//
// # Why a passkey IS one
//
// [Service.FinishPasskeyLogin] is the door decided the other way. A passkey
// is a private key bound to hardware the user holds, registered to THIS
// account through this package's own [CredentialStore] and resolvable to no
// other — a possession factor by construction, and one that shares no
// channel with the password or the mailbox. Demanding a TOTP code after one
// is a second factor demanded of a second factor; requiring nothing is the
// common reading, and it is this package's.
//
// Two limits are worth stating rather than implying. First, this package
// does not verify the assertion — see [VerifiedAssertion] — so "a passkey
// authenticated this login" is a claim the CALLER makes; a caller that
// fills a VerifiedAssertion in from a request body has not built a second
// factor, it has built a sign-in-as-anyone endpoint. Second, this package
// never sees the WebAuthn user-verification (UV) flag, so it cannot tell a
// passkey unlocked with a biometric or a PIN from one that merely sat on a
// plugged-in key. A deployment that needs UV must check it in the verifier
// before calling, because nothing below this line can.
//
// The consequence of the decision is that a passkey login stamps
// [Session.MFAAt] — see [Service.RequireFreshMFA] — so a passkey satisfies
// step-up too. It has to: an account holding both a passkey and a confirmed
// TOTP factor would otherwise sign in by passkey and then be unable to
// change its own password, with no way to satisfy the refusal short of
// signing in again by another door.
//
// # What this costs, stated plainly
//
// Under [EnforcementRequired], an account with no confirmed factor is now
// refused at three doors rather than one, and [ErrMFARequired] carries no
// user id — so an application routing such a user into enrolment must
// resolve the account itself, from the address it already holds. That is
// already true of Login and is not new; what IS new is that it now applies
// to a magic link and to an external sign-in, INCLUDING one that has just
// provisioned a brand-new account. Such an account exists, is linked, and
// cannot sign in until it enrols. A deployment running EnforcementRequired
// alongside external sign-up must therefore hand new users an enrolment
// step of its own, or the sign-up dead-ends.
//
// # TOTP parameters are fixed, deliberately
//
// Six digits, a thirty-second period, HMAC-SHA-1, and one step of skew
// either side. [MFAFactor]'s doc explains why they are not stored per
// factor — they are Service configuration, and changing them invalidates
// every factor enrolled under the old ones — and this file is where that
// configuration lives, as unexported constants rather than options.
//
// Two reasons, one practical and one structural. Practically, these four
// values are what every authenticator app implements and several implement
// ONLY: a deployment that raised the digit count would enrol users into
// factors their app renders unusable, discovered one support ticket at a
// time. Structurally, exposing the algorithm would mean re-declaring
// internal/totp.Algorithm in this package's public API purely to pass it
// back down, since internal/ is not importable by a consumer — a public
// type whose only purpose is to be forwarded. If a deployment ever needs
// them, the option to add is one that takes all four together, because
// three of the four combinations of "changed" and "not changed" are a
// silent mass re-enrolment.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/totp"
	"github.com/bernardoforcillo/authlayer/token"
)

// The fixed TOTP parameters — see this file's package doc, "TOTP parameters
// are fixed, deliberately", for why they are constants rather than options.
const (
	// mfaDigits is the code length. Six is RFC 4226's minimum, every
	// authenticator's default, and the only length some of them render.
	mfaDigits = 6
	// mfaPeriod is the time step. Thirty seconds is RFC 6238's own.
	mfaPeriod = 30 * time.Second
	// mfaAlgorithm is the HMAC hash. SHA-1 is RFC 6238's default and the
	// only one universally implemented by authenticator apps; see
	// internal/totp.Algorithm's doc for why that is not the weakness it
	// looks like.
	mfaAlgorithm = totp.SHA1
	// mfaSkew is how many steps either side of the server's own are
	// accepted, absorbing clock drift between the server and the phone: one
	// step, so a code is accepted for at most ninety seconds around its own.
	//
	// The width of this window is exactly how long an observed code would
	// stay usable — which is why every acceptance is followed by
	// [MFAStore.AdvanceStep], the compare-and-set that refuses the step just
	// used and every earlier one, cutting the reuse window to nothing.
	mfaSkew = 1
)

// Recovery-code shape. Ten codes of eighty bits each: enough that losing a
// phone is survivable more than once, few enough that a user will actually
// store them, and wide enough that guessing one is not a strategy.
const (
	// recoveryCodeCount is how many codes one confirmation issues.
	recoveryCodeCount = 10
	// recoveryCodeBytes is the entropy per code, before encoding. Ten bytes
	// render as sixteen base32 characters.
	recoveryCodeBytes = 10
)

// recoveryCodeCodec is the encoding recovery codes are rendered in: RFC
// 4648 base32, unpadded, upper case. Chosen over hex or base64 because a
// human transcribes these from paper: base32's alphabet has no lower case
// to lose, no '+' or '/' to mangle, and no 0/O or 1/l pair to confuse.
var recoveryCodeCodec = base32.StdEncoding.WithPadding(base32.NoPadding)

// Enforcement is whether a sign-in MAY be completed without a second factor
// or MUST NOT be. It governs the three doors that consult one —
// [Service.Login], [Service.RedeemMagicLink] and [Service.SignInWith] — and
// not [Service.FinishPasskeyLogin], which IS a second factor; see
// auth/mfa_service.go's package doc, "What the second factor gates, door by
// door". It never affects enrolment, which an account reaches through
// [Service.BeginMFAEnrolment] regardless.
type Enforcement int

const (
	// EnforcementOptional lets an account without a confirmed [MFAFactor]
	// sign in with a password (or a magic link, or an external identity)
	// alone, and gates one that HAS a confirmed factor behind
	// [Service.CompleteMFA]. Each account is treated according to what it
	// has actually enrolled.
	//
	// It is deliberately the ZERO VALUE, so a Service that never calls
	// [WithMFAEnforcement] — including one built by a route that forgets to
	// run through defaultConfig — carries the policy that cannot lock a
	// user out of an account they can otherwise authenticate. The unsafe
	// direction of a mis-set enforcement mode is not "too permissive" here;
	// it is an entire user base refused at the door. A test pins
	// EnforcementOptional == 0.
	EnforcementOptional Enforcement = iota
	// EnforcementRequired refuses any password login, magic-link redemption
	// or external sign-in by an account with no CONFIRMED factor, with
	// [ErrMFARequired]. It does not refuse a passkey login, which needs no
	// other factor — see this file's package doc, "What the second factor
	// gates, door by door".
	//
	// The distinct sentinel is the whole point of the mode being usable: an
	// application catching it routes the user into enrolment, which is the
	// one action that clears the refusal. Folding it into
	// [ErrInvalidCredentials] would tell a user whose password was correct
	// that it was wrong, and send them to a password reset that changes
	// nothing.
	//
	// It does NOT retroactively invalidate anything. Sessions already
	// issued to unenrolled accounts stay live and keep rotating through
	// [Service.Refresh] — enforcement is checked at the sign-in doors and
	// nowhere else — so switching a deployment over is a change to how
	// people sign in NEXT time, not a mass logout. An operator who wants
	// both calls [Service.LogoutAll] themselves.
	EnforcementRequired
)

// Sentinel errors for the MFA service surface, joining the port's own in
// auth/mfa.go. Compare with [errors.Is], never by string.
var (
	// ErrMFARequired: [WithMFAEnforcement] is [EnforcementRequired] and the
	// account that just came through a gated sign-in door — a password
	// login, a magic-link redemption, or an external sign-in — has no
	// CONFIRMED [MFAFactor].
	//
	// It is deliberately its own sentinel rather than [ErrInvalidCredentials],
	// and deliberately raised only AFTER the password check has passed. An
	// application seeing it knows the person at the keyboard is the
	// accountholder and is missing exactly one thing, so it can send them
	// to [Service.BeginMFAEnrolment]; a shared sentinel would send them to
	// a password reset instead. Raising it before the password check would
	// turn "does this account have MFA?" into an oracle for anyone who
	// knows an address.
	ErrMFARequired = errors.New("authlayer/auth: this account must enrol a second factor before signing in")
	// ErrMFAAlreadyEnrolled: an enrolment step was attempted against an
	// account that already holds a CONFIRMED factor —
	// [Service.BeginMFAEnrolment] refusing to overwrite one, or
	// [Service.ConfirmMFAEnrolment] finding nothing left to confirm.
	//
	// BeginMFAEnrolment's refusal is a security control, not tidiness. That
	// method takes no password: without this, anyone holding a live session
	// — a borrowed laptop, a stolen access token, an XSS payload — could
	// call it and replace a confirmed factor with an unconfirmed one, and
	// an unconfirmed factor gates nothing. The second factor would be
	// silently off, with no credential presented and nothing for the user
	// to notice. Re-enrolment therefore goes through [Service.DisableMFA],
	// which demands the current password, and then Begin/Confirm.
	ErrMFAAlreadyEnrolled = errors.New("authlayer/auth: a confirmed MFA factor is already enrolled")
	// ErrMFACodeInvalid: the presented second factor did not authenticate.
	// One sentinel covers every way that can happen — a wrong TOTP code, a
	// correct one whose step was already spent (a replay, refused by
	// [MFAStore.AdvanceStep]), a wrong recovery code, and a recovery code
	// that was already burnt.
	//
	// They are not distinguished for the reason [ErrInvalidCredentials]
	// does not distinguish its own four cases: the differences are
	// interesting only to whoever is guessing. "That code was right but you
	// already used it" in particular tells an attacker replaying a
	// shoulder-surfed code that they had the right code and merely arrived
	// second — which is precisely the fact worth hiding from them.
	ErrMFACodeInvalid = errors.New("authlayer/auth: second-factor code is invalid")
)

// MFAChallenge is the handle to a login that has passed its password check
// and owes a second factor: what [Service.Login] returns in
// [LoginResult.MFA] instead of a session, and what [Service.CompleteMFA]
// exchanges for one.
//
// It is not a credential on its own and never becomes one. Holding it
// proves the password was presented; presenting it WITH a code the account's
// authenticator (or its recovery set) produced is what finishes the login.
type MFAChallenge struct {
	// Token is the plaintext handle, stored by this package only as its
	// sha256 on a [PurposeMFAChallenge] [Verification]. Hand it back to
	// [Service.CompleteMFA]. It is SINGLE-USE — the first completion burns
	// it, and every later presentation is [ErrVerificationNotFound] — and
	// bound to the one account it was minted for: the user a completion
	// signs in is read off the stored row, never off anything the caller
	// supplies alongside it.
	Token string
	// ExpiresAt is when the challenge stops being exchangeable, as
	// [WithMFAChallengeTTL] configures. Past it, [Service.CompleteMFA]
	// returns [ErrVerificationExpired] without burning anything, and the
	// user signs in again from the top.
	ExpiresAt time.Time
	// Methods names what [Service.CompleteMFA] will ACCEPT for this
	// challenge: "totp" and "recovery_code". It is a statement about the
	// endpoint, not an inventory of the account — it does not promise the
	// user has any unused recovery codes left, and this package does not
	// count them here, because doing so would spend a query on every MFA
	// login to answer a question the completion attempt answers anyway.
	//
	// The slice is freshly allocated per challenge, so a caller may sort or
	// filter it without reaching into another challenge's state.
	Methods []string
}

// mfaChallengeMethods returns the method list a fresh [MFAChallenge]
// carries. A function rather than a package-level slice: a shared slice is
// a mutable global that any caller can rewrite for every other caller.
func mfaChallengeMethods() []string {
	return []string{"totp", "recovery_code"}
}

// BeginMFAEnrolment starts TOTP enrolment for userID: it mints a fresh
// secret, stores it ENCRYPTED as that account's one [MFAFactor] with
// [MFAFactor.ConfirmedAt] left nil, and returns the secret in plaintext
// alongside the otpauth URI an authenticator app scans.
//
// The returned secret and URI are the same secret twice, in the two forms a
// user needs: the URI for a QR code, the bare secret for typing in by hand
// when a camera is not available. Both are bearer credentials for the
// factor being enrolled — show them once, over the authenticated channel
// that called this, and never log either.
//
// # Nothing is gated yet
//
// The factor this creates is UNCONFIRMED, and an unconfirmed factor gates
// no login ([Service.Login] steps past it) and satisfies no challenge. A
// user who abandons enrolment here is exactly where they were; a user whose
// app rejected the URI can simply call this again, and the whole row is
// replaced (see [MFAStore.UpsertFactor], whose whole-row MUST is what makes
// a second attempt a clean one rather than a new secret wearing the old
// one's ConfirmedAt). This file's package doc argues why that ordering is
// not negotiable.
//
// # It refuses to overwrite a confirmed factor
//
// An account that already holds a CONFIRMED factor gets
// [ErrMFAAlreadyEnrolled] and nothing is written. This method asks for no
// password, so without that refusal it would be a password-free way to turn
// a user's second factor off: overwrite the confirmed row with an
// unconfirmed one and the account is back to a password alone, silently.
// See [ErrMFAAlreadyEnrolled]'s own doc. Rotating a factor goes through
// [Service.DisableMFA] first.
//
// # Fail closed
//
// [ErrMFANotConfigured] with no [WithMFAStore]; [ErrMFACipherNotConfigured]
// with no [WithMFASecretCipher], checked BEFORE a secret is generated so a
// Service missing a key never holds one it cannot store safely;
// [ErrUserNotFound] for an unknown account and for an ANONYMIZED one (a
// non-nil [UserBase.DeletedAt] — see [Service.AnonymizeAccount], "Every
// entry point that refuses a stamped account"). Any other Store, Cipher or
// crypto/rand failure is returned as-is.
func (s *Service) BeginMFAEnrolment(ctx context.Context, userID string) (secret, uri string, err error) {
	st, err := s.mfa()
	if err != nil {
		return "", "", err
	}
	// Before crypto/rand is touched: a Service with no cipher must never
	// hold a plaintext secret it has nowhere safe to put. See
	// [WithMFASecretCipher].
	cipher, err := s.mfaCipher()
	if err != nil {
		return "", "", err
	}

	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if u.DeletedAt != nil {
		return "", "", ErrUserNotFound
	}

	// An existing factor is replaceable only while it is unconfirmed. A
	// missing one is the ordinary case and not an error here.
	switch f, ferr := st.FindFactor(ctx, userID); {
	case errors.Is(ferr, ErrFactorNotFound):
		// Never enrolled; carry on.
	case ferr != nil:
		return "", "", ferr
	case f.ConfirmedAt != nil:
		return "", "", ErrMFAAlreadyEnrolled
	}

	plainSecret, err := totp.GenerateSecret()
	if err != nil {
		return "", "", err
	}
	enc, err := cipher.Encrypt(plainSecret)
	if err != nil {
		return "", "", err
	}

	if err := st.UpsertFactor(ctx, MFAFactor{
		UserID:    userID,
		SecretEnc: enc,
		// ConfirmedAt and LastStep stay nil: this factor has proven
		// nothing and authenticated nothing.
		CreatedAt: s.cfg.clock(),
	}); err != nil {
		return "", "", err
	}

	return plainSecret, totp.ProvisioningURI(plainSecret, s.cfg.mfaIssuer, u.Email, mfaDigits, mfaPeriod, mfaAlgorithm), nil
}

// ConfirmMFAEnrolment finishes what [Service.BeginMFAEnrolment] started:
// given a code the account's authenticator just produced, it stamps
// [MFAFactor.ConfirmedAt] and returns a fresh set of recovery codes in
// plaintext.
//
// From the moment this returns, the account owes a second factor at every
// password login.
//
// # The recovery codes are returned exactly once
//
// They are shown here and never again: this package stores only their
// hashes, produced by the configured [github.com/bernardoforcillo/authlayer/password.Hasher],
// for the reason it stores password hashes — each one authenticates the
// account on its own, and a dump of plaintext codes is a working
// second-factor bypass for every user who has not spent theirs. There is no
// method to re-read them, because there is nothing to read. A caller that
// does not show them to the user has issued the user nothing.
//
// A second confirmation is impossible ([ErrMFAAlreadyEnrolled]), so the
// only way to a new set is [Service.DisableMFA] and a fresh enrolment. That
// is deliberate: a regenerate-codes endpoint that asked for no credential
// would let anyone holding a session replace the codes a user has on paper.
//
// # Order, and what each step buys
//
// The code is validated, then the replay guard is advanced, then the
// compare-and-set stamps, then the codes are generated and stored. The
// middle two are both compare-and-sets and both matter:
// [MFAStore.AdvanceStep] means the code just used cannot be used again for
// the login that immediately follows, and [MFAStore.ConfirmFactor] means
// exactly one of two concurrent confirmations wins. The stamp comes BEFORE
// the codes because the winner of that compare-and-set is by definition the
// caller entitled to issue them: generating first would let a loser's set
// overwrite the winner's, invalidating codes the user was just told to
// write down — see [MFAStore.ConfirmFactor]'s own doc, which names this as
// the reason it must be atomic.
//
// # Fail closed
//
// [ErrMFANotConfigured], [ErrMFACipherNotConfigured], [ErrFactorNotFound]
// when enrolment was never begun, [ErrMFAAlreadyEnrolled] when it is
// already finished, [ErrMFACodeInvalid] for a code that does not validate
// or whose step is already spent. A Cipher that cannot decrypt what it
// wrote, or a stored secret internal/totp refuses, surfaces as that error
// rather than as a wrong code: it is a broken deployment, not a user
// mistake.
//
// One trade-off is disclosed rather than hidden. If [MFAStore.ReplaceRecoveryCodes]
// fails after the stamp has landed, this returns that error with the factor
// already CONFIRMED and no recovery codes stored. The account has a working
// second factor and no fallback; the remedy is [Service.DisableMFA] and a
// fresh enrolment. The alternative — storing codes before the stamp — trades
// this for the concurrent-overwrite defect above, which produces codes the
// user believes in and cannot use, and that is the worse of the two.
func (s *Service) ConfirmMFAEnrolment(ctx context.Context, userID, code string) ([]string, error) {
	st, err := s.mfa()
	if err != nil {
		return nil, err
	}
	cipher, err := s.mfaCipher()
	if err != nil {
		return nil, err
	}

	f, err := st.FindFactor(ctx, userID)
	if err != nil {
		return nil, err
	}
	if f.ConfirmedAt != nil {
		return nil, ErrMFAAlreadyEnrolled
	}

	now := s.cfg.clock()
	step, err := s.validateTOTP(cipher, f, code, now)
	if err != nil {
		return nil, err
	}
	// The replay guard is armed from the very first code, not from the
	// first login: without this, the code that confirmed the factor would
	// still be valid for the login the user makes seconds later.
	switch ok, aerr := st.AdvanceStep(ctx, userID, step); {
	case aerr != nil:
		return nil, aerr
	case !ok:
		return nil, ErrMFACodeInvalid
	}

	switch ok, cerr := st.ConfirmFactor(ctx, userID, now); {
	case cerr != nil:
		return nil, cerr
	case !ok:
		// Someone else won the compare-and-set — a double-submitted form
		// is the usual cause — and they are the caller holding the codes.
		return nil, ErrMFAAlreadyEnrolled
	}

	plain, records, err := s.newRecoveryCodes(userID, now)
	if err != nil {
		return nil, err
	}
	if err := st.ReplaceRecoveryCodes(ctx, userID, records); err != nil {
		return nil, err
	}
	return plain, nil
}

// CompleteMFA finishes a login that [Service.Login] left pending: given the
// [MFAChallenge.Token] it returned and a second-factor code, it mints the
// session Login withheld and returns the same [LoginResult] an ordinary
// login does — with [LoginResult.MFA] nil, because there is nothing left to
// owe.
//
// code is either a TOTP code from the account's authenticator or one of the
// recovery codes [Service.ConfirmMFAEnrolment] issued. Which one is decided
// by its SHAPE — exactly mfaDigits ASCII digits is read as a TOTP code, and
// anything else as a recovery code — rather than by trying both. Both
// formats are public, so the dispatch leaks nothing, and it keeps a wrong
// six-digit guess from costing a bcrypt verify per stored recovery code
// (see below).
//
// ip and userAgent are recorded on the new [Session] exactly as
// [Service.Login] records its own. An empty ip is not refused here — this
// method consults no [RateLimiter], and Login, which does, has already
// refused an empty one for this login.
//
// # Verifying a recovery code costs one hasher verify per stored code
//
// [MFAStore.ConsumeRecoveryCode] compares the hash byte-for-byte, and the
// default Hasher is bcrypt, which salts — so the stored value cannot be
// recomputed from what the user typed. The only way to identify the row is
// to list the account's codes and verify the plaintext against each stored
// hash until one matches, then hand that hash back for the atomic burn.
// [RecoveryCode.CodeHash]'s doc fixes this flow; the cost is stated here
// rather than buried: one bcrypt verify per stored code, ten by default, on
// every recovery-code attempt. It is bounded by the challenge — reaching
// this method at all requires having just passed a rate-limited password
// check — and it is why the shape dispatch above exists, so ordinary TOTP
// traffic never pays it.
//
// # Claim before apply
//
// The challenge is burned ([Store.DeleteVerification], whose rows-affected
// gate makes exactly one of any number of concurrent callers see nil)
// BEFORE any session is minted. That ordering is what stops one challenge
// from becoming two sessions, and it is the same rule
// [Service.RedeemMagicLink] states at length under "Claim before apply, and
// why it is not negotiable".
//
// Everything that CAN be decided before the claim is decided before it —
// expiry, purpose, the account, the factor, and the code itself — which is
// the other half of that same rule, and it is what makes a WRONG code cost
// the user nothing: the challenge survives and they can try the next code
// their app shows. A replayed code is treated identically, so a user whose
// code was already spent retries rather than restarting the login.
//
// Two irreversible writes therefore precede the claim: the
// [MFAStore.AdvanceStep] that spends the TOTP step, and the
// [MFAStore.ConsumeRecoveryCode] that burns a recovery code. If the claim
// then LOSES — another caller holding the same challenge got there first —
// the code is spent and no session was issued. That costs a recovery code
// in the one case where two callers hold the same challenge at once, which
// means either the user double-submitted (and the other submission is
// signing them in) or the challenge was stolen (and spending the code is
// the least of it). Reversing the order to protect that case would burn the
// challenge on every mistyped code, which is the far commoner event.
//
// # Fail closed
//
// An unknown token is [ErrVerificationNotFound]; an expired one
// [ErrVerificationExpired]; a token of any OTHER purpose
// [ErrVerificationPurpose] — all three before the claim, so none of them
// burns anything. That third refusal is load-bearing: without it a
// "magic_link" or "password_reset" token would be exchangeable here for a
// session, and this method's entire premise is that a session is exactly
// what a caller does not get without a second factor.
//
// The account is re-checked, not assumed, because a challenge outlives the
// instant it was minted: an ANONYMIZED account is [ErrUserNotFound], and
// [WithRequireVerifiedEmail] is enforced again ([ErrEmailNotVerified]) in
// case the address changed in the interval. A factor that has vanished or
// been left unconfirmed is [ErrFactorNotFound] — an unconfirmed factor
// satisfies a challenge no more than it gates a login. A code that does not
// authenticate is [ErrMFACodeInvalid]. Every other Store, Cipher or
// [token.Issue] failure is returned as-is.
func (s *Service) CompleteMFA(ctx context.Context, challengeToken, code, ip, userAgent string) (LoginResult, error) {
	var zero LoginResult

	v, err := s.store.FindVerificationByHash(ctx, token.HashOpaque(challengeToken))
	if err != nil {
		return zero, err
	}

	now := s.cfg.clock()
	if !now.Before(v.ExpiresAt) {
		return zero, ErrVerificationExpired
	}
	if v.Purpose != PurposeMFAChallenge {
		// Before the claim, so a wrongly-presented token is not burned —
		// and, critically, no other purpose becomes a session here.
		return zero, ErrVerificationPurpose
	}

	st, err := s.mfa()
	if err != nil {
		return zero, err
	}

	// The account, re-read rather than carried: this challenge was minted
	// in an earlier request and the row may have moved since.
	u, err := s.store.FindUserByID(ctx, v.UserID)
	if err != nil {
		return zero, err
	}
	if u.DeletedAt != nil {
		return zero, ErrUserNotFound
	}
	if s.cfg.requireVerifiedEmail && u.EmailVerifiedAt == nil {
		return zero, ErrEmailNotVerified
	}

	f, err := st.FindFactor(ctx, v.UserID)
	if err != nil {
		return zero, err
	}
	// The challenge names the account; the factor must be that account's.
	// [MFAStore.FindFactor] is contracted to return only the named user's
	// row, so this can only fail for a backend that does not scope its
	// lookup — and the consequence of trusting such a backend is that one
	// user's authenticator satisfies another user's challenge, which is
	// the whole property a second factor has. Checked rather than assumed,
	// for the same reason [ErrStoreContract]'s other three triggers are.
	if f.UserID != v.UserID {
		return zero, fmt.Errorf("%w: FindFactor(%q) returned a factor for %q", ErrStoreContract, v.UserID, f.UserID)
	}
	if f.ConfirmedAt == nil {
		// An unconfirmed factor is, for every authentication purpose, no
		// factor at all — see this file's package doc.
		return zero, ErrFactorNotFound
	}

	if err := s.spendMFACode(ctx, st, f, v.UserID, code, now); err != nil {
		return zero, err
	}

	// The claim: exactly one caller ever sees a nil error for this id, and
	// it runs before anything is issued.
	if err := s.store.DeleteVerification(ctx, v.ID); err != nil {
		return zero, err
	}

	// One minting path, shared with [Service.Login] — see mintSession. The
	// &now is [Session.MFAAt]: a factor was just presented and spent, and
	// this is the instant that makes the new session FRESH for
	// [Service.RequireFreshMFA]. It is stamped in the same INSERT as the
	// row, so no session of this method's ever exists unstamped.
	return s.mintSession(ctx, u, ip, userAgent, &now)
}

// DisableMFA removes userID's second factor and every recovery code with
// it, after proving the caller knows the account's CURRENT password AND
// holds a session that proved the factor recently.
//
// The password is not ceremony. Disabling MFA is the one operation that
// makes an account strictly easier to break into, so it is the one that
// must not be reachable from a session alone: a borrowed laptop, a stolen
// access token or an XSS payload all carry a live session and none of them
// carries the password. It is the same stance [Service.ChangePassword]
// takes on the credential it replaces.
//
// # It also needs a FRESH second factor
//
// currentSessionID is the caller's own session — the SessionID claim off
// the access token that authenticated this request, exactly as
// [Service.ChangePassword] takes it — and [Service.RequireFreshMFA] must
// pass on it: the session must have proved a second factor within
// [WithStepUpWindow], or this is [ErrStepUpRequired] and nothing is
// removed.
//
// Of the seven methods step-up gates, this is the one whose absence would
// undo the other six. An attacker holding a session AND the password can,
// without this check, simply turn the factor off and then perform every
// other gated action unchallenged; the gate on the credential rotation
// would be worth nothing while the gate on the credential ITSELF was
// missing.
//
// It strands nobody who was not already stranded. Every door that can mint
// a session for an account with a confirmed factor either proves that
// factor ([Service.Login] plus [Service.CompleteMFA], a magic link or an
// external sign-in plus the same completion) or IS one
// ([Service.FinishPasskeyLogin]) — so a user who can reach this method at
// all can reach it freshly. A lost authenticator is answered by a RECOVERY
// CODE: completing a challenge with one stamps [Session.MFAAt] exactly as a
// TOTP code does, which is what keeps "I lost my phone" a self-service
// operation and not a support ticket. A user with neither the
// authenticator nor a code cannot sign in in the first place, so this check
// takes nothing further from them.
//
// # It clears the codes first, then the factor
//
// [MFAStore.DeleteFactor] removes the factor row only — the port is
// explicit that the cascade is the caller's decision — so this owes a
// [MFAStore.ReplaceRecoveryCodes](ctx, userID, nil) as well, and runs it
// FIRST. The order is chosen for what a RETRY does after a partial failure:
// clearing first and failing leaves MFA fully on (the user still has their
// authenticator, and a retry redoes both steps cleanly), whereas deleting
// first and failing leaves an account whose retry gets [ErrFactorNotFound]
// and never reaches the codes at all, stranding them.
//
// # It revokes every trusted device
//
// [Service.sweepTrustedDevices] runs here too, on its own line, and this is
// the row of the sweep matrix that needed the most argument.
//
// A [TrustedDevice] token means one thing and one thing only: "skip the
// second factor". Once there is no second factor there is nothing to skip,
// so the obvious reading is that a surviving device is merely meaningless —
// [Service.trustedDeviceAtSignIn] refuses to consult one for an account with
// no confirmed factor, so it grants nothing the day after this call.
//
// It is worse than meaningless, though, and that is why the sweep is here.
// Re-enrolment goes DisableMFA → [Service.BeginMFAEnrolment] →
// [Service.ConfirmMFAEnrolment] (see [ErrMFAAlreadyEnrolled], which is what
// forces that route). Leaving the devices behind means a user who turns MFA
// off and back on — after losing a phone, after changing authenticator apps
// — finds every machine they ever trusted silently skipping the NEW factor,
// a token minted against a secret that no longer exists. Whoever holds one
// of those cookies gets the benefit of a second factor they were never
// tested against. Sweeping here is what makes "trusted" mean "trusted for
// the factor that is enrolled now".
//
// It runs BEFORE the codes and the factor for the same retry reason their
// own order is chosen: a failure at this point leaves MFA fully on with
// nothing trusted, which is a state the user can live in and a retry can
// clear.
//
// Outstanding [MFAChallenge]s are deliberately NOT swept, because they need
// no sweeping: [Service.CompleteMFA] loads the factor before it accepts
// anything, so once the factor is gone every live challenge is already
// unusable. A sweep would delete rows [Store.PurgeExpired] removes anyway.
//
// # Fail closed
//
// [ErrMFANotConfigured] with no [WithMFAStore]; [ErrUserNotFound] for an
// unknown or ANONYMIZED account; [ErrInvalidCredentials] for a wrong
// password AND for an account with no password credential at all — an
// OAuth-only account cannot satisfy this check, and the honest consequence
// is that such an account's MFA is not disableable through this method.
// [ErrFactorNotFound] when there is nothing enrolled. Any other Store
// failure is returned as-is, the trusted-device sweep's included: a device
// left standing while this call reports success is a bypass armed for the
// next enrolment, and nothing would prompt a retry.
func (s *Service) DisableMFA(ctx context.Context, userID, currentSessionID, currentPassword string) error {
	st, err := s.mfa()
	if err != nil {
		return err
	}

	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.DeletedAt != nil {
		return ErrUserNotFound
	}
	if u.PasswordHash == "" {
		s.cfg.hasher.Dummy(currentPassword)
		return ErrInvalidCredentials
	}
	if !s.cfg.hasher.Verify(currentPassword, u.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Step-up, on this method's own line — see [Service.RequireFreshMFA]
	// and "It also needs a FRESH second factor" above. After the password
	// check, so a wrong password is reported as one. Never a no-op in
	// practice: reaching the line below means the account holds a confirmed
	// factor, which is exactly the case RequireFreshMFA does gate.
	if err := s.RequireFreshMFA(ctx, userID, currentSessionID); err != nil {
		return err
	}

	// The trusted devices, on this method's own line and BEFORE the factor
	// goes — see the method doc, "It revokes every trusted device", for what
	// a surviving one would mean, and why it runs first: a failure here
	// leaves MFA fully on with nothing trusted, which is the direction a
	// retry can fix.
	if err := s.sweepTrustedDevices(ctx, userID); err != nil {
		return err
	}

	// Codes first — see the method doc for why the retry semantics decide
	// this order.
	if err := st.ReplaceRecoveryCodes(ctx, userID, nil); err != nil {
		return err
	}
	return st.DeleteFactor(ctx, userID)
}

// sweepMFAState removes userID's SECOND-FACTOR state: every recovery code,
// then the [MFAFactor] itself. It is the MFA column of
// [Service.ChangePassword]'s sweep matrix, and only the two TERMINATION rows
// call it — see that table for why no remediation path does.
//
// It tolerates [ErrFactorNotFound], because "this account never enrolled" is
// the ordinary state of most accounts and is not a failure of a sweep whose
// job is to leave nothing behind. Every other error is returned as-is.
//
// The codes go first, matching [Service.DisableMFA]'s order and for the same
// reason: a partial failure leaving the factor with no codes is a user who
// can still authenticate, while one leaving codes with no factor is a set of
// live credentials for a second factor that no longer exists.
//
// A [Service] with no [WithMFAStore] holds no factors, so it sweeps nothing
// and reports no error — the same stated limit [Service.sweepIdentities]
// carries for its own port.
func (s *Service) sweepMFAState(ctx context.Context, userID string) error {
	if s.cfg.mfaStore == nil {
		return nil
	}
	if err := s.cfg.mfaStore.ReplaceRecoveryCodes(ctx, userID, nil); err != nil {
		return err
	}
	if err := s.cfg.mfaStore.DeleteFactor(ctx, userID); err != nil && !errors.Is(err, ErrFactorNotFound) {
		return err
	}
	return nil
}

// mfaAtSignIn is the second-factor step of every door that HAS one: it
// returns a minted [MFAChallenge] when the sign-in must stop and be
// finished through [Service.CompleteMFA], (nil, nil) when it may proceed to
// a session, and an error when it must be refused outright.
//
// Three doors call it — [Service.Login], [Service.RedeemMagicLink] and
// [Service.SignInWith], the last from BOTH of its rungs — and each calls it
// on its own line rather than through a guard they share, so that removing
// one call fails exactly one door's test. [Service.FinishPasskeyLogin]
// deliberately does not call it at all. See this file's package doc, "What
// the second factor gates, door by door", for the matrix and the reasoning
// behind every cell.
//
// At every call site it runs LAST, after the door's own authentication has
// already succeeded — the password and [WithRequireVerifiedEmail] at Login,
// the claimed link at RedeemMagicLink, the resolved identity at SignInWith
// — so nothing it reveals is reachable by a caller who has not already
// authenticated.
//
// The three "may proceed" cases are worth naming, because two of them are
// the ones that keep users out of a support queue: no [MFAStore] wired at
// all, no factor enrolled, and a factor that exists but is UNCONFIRMED. The
// last is the load-bearing one — see this file's package doc — and it is
// the difference between an abandoned enrolment being a non-event and being
// a permanent lockout. Under [EnforcementRequired] the first of the three
// is a misconfiguration ([ErrMFANotConfigured], loud, rather than every
// user being refused with a message about enrolling somewhere they cannot)
// and the other two are [ErrMFARequired].
func (s *Service) mfaAtSignIn(ctx context.Context, u UserBase) (*MFAChallenge, error) {
	required := s.cfg.mfaEnforcement == EnforcementRequired

	if s.cfg.mfaStore == nil {
		if required {
			// EnforcementRequired without a store is a wiring bug, and the
			// honest answer is which piece is missing. Reporting
			// ErrMFARequired here would send every user of the deployment
			// to an enrolment flow that cannot work.
			return nil, ErrMFANotConfigured
		}
		return nil, nil
	}

	f, err := s.cfg.mfaStore.FindFactor(ctx, u.ID)
	switch {
	case errors.Is(err, ErrFactorNotFound):
		if required {
			return nil, ErrMFARequired
		}
		return nil, nil
	case err != nil:
		return nil, err
	}
	if f.ConfirmedAt == nil {
		if required {
			return nil, ErrMFARequired
		}
		return nil, nil
	}

	return s.mintMFAChallenge(ctx, u)
}

// mintMFAChallenge writes the [PurposeMFAChallenge] [Verification] backing
// one pending login and returns its plaintext handle.
//
// It deliberately does NOT delete the account's earlier challenges the way
// [Service.RequestMagicLink] deletes earlier links. A magic link IS the
// credential, so keeping one live at a time bounds what a leaked mailbox is
// worth; a challenge is worth nothing without a second factor, and sweeping
// would mean a user signing in on a phone and a laptop at the same moment
// finds the first of the two dead half way through. Challenges age out
// through [Store.PurgeExpired] like every other verification.
func (s *Service) mintMFAChallenge(ctx context.Context, u UserBase) (*MFAChallenge, error) {
	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		return nil, err
	}
	now := s.cfg.clock()
	expires := now.Add(s.cfg.mfaChallengeTTL)

	if _, err := s.store.CreateVerification(ctx, Verification{
		ID:        s.cfg.idGen(),
		UserID:    u.ID,
		TokenHash: hash,
		Purpose:   PurposeMFAChallenge,
		// Populated because [Verification.Email]'s contract is
		// unconditional, and normalized because the Store stored it that
		// way. It certifies nothing here — see [PurposeMFAChallenge].
		Email:     u.Email,
		ExpiresAt: expires,
		CreatedAt: now,
	}); err != nil {
		return nil, err
	}

	return &MFAChallenge{Token: plain, ExpiresAt: expires, Methods: mfaChallengeMethods()}, nil
}

// spendMFACode authenticates code against userID's factor and SPENDS it:
// the TOTP step is advanced, or the recovery code burnt, before this
// returns nil. A code that does not authenticate is [ErrMFACodeInvalid]
// and nothing is spent.
//
// The dispatch is on shape — see [Service.CompleteMFA] — and it is total:
// every input is tried as exactly one of the two.
func (s *Service) spendMFACode(ctx context.Context, st MFAStore, f MFAFactor, userID, code string, now time.Time) error {
	if looksLikeTOTPCode(code) {
		cipher, err := s.mfaCipher()
		if err != nil {
			return err
		}
		step, err := s.validateTOTP(cipher, f, code, now)
		if err != nil {
			return err
		}
		// The replay guard. Without this compare-and-set a code observed
		// over a shoulder stays usable for the rest of its skew window —
		// see [MFAStore.AdvanceStep].
		switch ok, aerr := st.AdvanceStep(ctx, userID, step); {
		case aerr != nil:
			return aerr
		case !ok:
			return ErrMFACodeInvalid
		}
		return nil
	}
	return s.spendRecoveryCode(ctx, st, userID, code, now)
}

// looksLikeTOTPCode reports whether code has the shape of a TOTP code:
// exactly mfaDigits ASCII digits. Recovery codes are base32 and sixteen
// characters, so the two sets do not overlap.
func looksLikeTOTPCode(code string) bool {
	if len(code) != mfaDigits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// validateTOTP decrypts f's secret and checks code against it, returning
// the step that matched. A code that does not validate is
// [ErrMFACodeInvalid]; a secret the Cipher or internal/totp refuses is that
// error, unwrapped, because a broken deployment must not present itself as
// a user typing badly.
func (s *Service) validateTOTP(cipher Cipher, f MFAFactor, code string, now time.Time) (int64, error) {
	secret, err := cipher.Decrypt(f.SecretEnc)
	if err != nil {
		return 0, err
	}
	step, ok, err := totp.Validate(secret, code, now, mfaDigits, mfaPeriod, mfaAlgorithm, mfaSkew)
	switch {
	case errors.Is(err, totp.ErrEmptyCode):
		// An empty code is a user handing over nothing, not a malformed
		// deployment; it is the same refusal as a wrong one.
		return 0, ErrMFACodeInvalid
	case err != nil:
		return 0, err
	case !ok:
		return 0, ErrMFACodeInvalid
	}
	return step, nil
}

// spendRecoveryCode finds userID's unused recovery code matching plain and
// burns it, or reports [ErrMFACodeInvalid].
//
// The plaintext is verified against every stored hash rather than looked up
// by one — the configured Hasher salts, so there is no hash to look up —
// and the matched hash is then handed to the store's compare-and-set, which
// is what makes the code single-use under concurrency. See
// [Service.CompleteMFA]'s "Verifying a recovery code costs one hasher
// verify per stored code".
//
// Codes belonging to any other user are skipped rather than trusted.
// [MFAStore.ListRecoveryCodes] is contracted to return only the named
// user's, so this can only bite against a backend that does not scope its
// query — and what it prevents there is one account's recovery code
// satisfying another account's challenge.
func (s *Service) spendRecoveryCode(ctx context.Context, st MFAStore, userID, plain string, now time.Time) error {
	if plain == "" {
		return ErrMFACodeInvalid
	}
	codes, err := st.ListRecoveryCodes(ctx, userID)
	if err != nil {
		return err
	}

	matched := ""
	for _, c := range codes {
		if c.UserID != userID || c.UsedAt != nil {
			continue
		}
		if s.cfg.hasher.Verify(plain, c.CodeHash) {
			matched = c.CodeHash
			break
		}
	}
	if matched == "" {
		return ErrMFACodeInvalid
	}

	switch ok, cerr := st.ConsumeRecoveryCode(ctx, userID, matched, now); {
	case cerr != nil:
		return cerr
	case !ok:
		// Someone else burnt it between the list and the burn. Reported
		// as an invalid code, not as a race: see [ErrMFACodeInvalid].
		return ErrMFACodeInvalid
	}
	return nil
}

// newRecoveryCodes mints recoveryCodeCount fresh codes, returning the
// plaintexts to hand the user once and the [RecoveryCode] records to store.
// Only the hashes are ever persisted; the plaintexts exist in this process
// and in whatever the caller shows the user, and nowhere else.
func (s *Service) newRecoveryCodes(userID string, now time.Time) ([]string, []RecoveryCode, error) {
	plain := make([]string, 0, recoveryCodeCount)
	records := make([]RecoveryCode, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		b := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("authlayer/auth: read random recovery code: %w", err)
		}
		code := recoveryCodeCodec.EncodeToString(b)
		hash, err := s.cfg.hasher.Hash(code)
		if err != nil {
			return nil, nil, err
		}
		plain = append(plain, code)
		records = append(records, RecoveryCode{
			ID:        s.cfg.idGen(),
			UserID:    userID,
			CodeHash:  hash,
			CreatedAt: now,
		})
	}
	return plain, records, nil
}
