// Package auth (this file) is the trusted device: a long-lived bearer token
// that stands in for the SECOND factor on a machine the user has already
// vouched for, so that "remember this browser for thirty days" does not mean
// typing a code at every sign-in.
//
// # It replaces the second factor and NEVER the first
//
// This is the whole of the security argument and it is stated before
// anything else. [Service.LoginWithTrustedDevice] runs the SAME password
// check [Service.Login] runs, in the same order, and consults the device
// token only AFTER that check has passed. A device token presented with a
// wrong password authenticates nobody; a device token presented with no
// password authenticates nobody. What it buys its holder is exactly one
// thing: [Service.mfaAtSignIn] is not consulted, so no [MFAChallenge] is
// returned and the session is stamped [Session.MFAAt] as though a factor had
// been presented.
//
// Letting it skip the password too would not be a weaker second factor. It
// would be a FULL AUTHENTICATION BYPASS: the token is a single opaque string
// living in a cookie, readable by any XSS payload, copyable off a stolen or
// borrowed machine, and valid for thirty days by default — so a deployment
// that let it stand alone would have replaced "password AND second factor"
// with "one cookie", which is strictly worse than having neither feature.
// TestATrustedDeviceDoesNotSkipThePassword says so in its failure message
// and exists to be the test that fails.
//
// # Minting one requires a FRESH second factor
//
// [Service.TrustThisDevice] calls [Service.RequireFreshMFA]. Without that,
// whoever holds a stolen session mints themselves a permanent second-factor
// bypass on the way out — the session expires, the trust does not — and the
// feature turns a fifteen-minute compromise into a thirty-day one. This is
// the single most important line in this file, and mutation (a) recorded
// below is the check that it is still there.
//
// It also refuses an account with NO CONFIRMED FACTOR, with
// [ErrMFARequired], and that refusal is not tidiness either. RequireFreshMFA
// is deliberately a no-op for such an account (see auth/stepup.go — without
// that no-op, step-up would lock every non-MFA user out), so without this
// second, explicit check a stolen session on a factor-less account could
// mint a trusted device that grants nothing TODAY and silently skips the
// factor the user enrols TOMORROW. The bypass would be armed before the
// thing it bypasses existed. An account that cannot step up cannot trust a
// device either.
//
// # Only the hash is stored
//
// [TrustedDevice.TokenHash] holds [token.HashOpaque]'s output and the
// plaintext is returned exactly once, to the caller, and never again — the
// same treatment [Session.TokenHash] and the invite tokens get, for the same
// reason: this token IS a credential, so a database dump full of plaintext
// ones is a working second-factor bypass for every user who has ever
// clicked "trust this device". The column carries a UNIQUE constraint with
// the same MUST the other token-hash columns carry.
//
// # Revocation, and where the sweeps live
//
// A trusted device is a credential, so it belongs in the sweep matrix, and
// [Service.ChangePassword]'s doc holds the whole table. The short version:
// every remediation path revokes every device ([Service.ChangePassword],
// [Service.ResetPassword], [Service.LogoutAll]), both termination paths do
// ([Service.DeleteAccount], [Service.AnonymizeAccount]), and so does
// [Service.DisableMFA] — a token whose only meaning is "skip the second
// factor" is not merely pointless once there is no second factor, it is a
// bypass waiting for the user to re-enrol. [Service.RevokeTrustedDevice]
// drops one on request; [Service.PurgeExpired] removes the expired rows.
//
// # Mutations, recorded
//
// Three, all run and all restored:
//
//   - Dropping [Service.RequireFreshMFA] from [Service.TrustThisDevice]:
//     failed the three tests about that one call and nothing else —
//     TestTrustThisDeviceRefusesASessionThatHasNotFreshlyProvedAFactor,
//     TestTrustThisDeviceRefusesAStaleSession and
//     TestTrustThisDeviceRefusesAnotherUsersSession, which are "never
//     proved", "proved too long ago" and "proved on another account".
//   - Letting a trusted device skip the PASSWORD (moving the device branch
//     above the credential check): failed
//     TestATrustedDeviceDoesNotSkipThePassword and nothing else.
//   - Dropping the expiry comparison in [Service.trustedDeviceAtSignIn]:
//     failed TestAnExpiredTrustedDeviceDoesNotSkipTheChallenge and nothing
//     else.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/token"
)

// defaultTrustedDeviceTTL is how long a device stays trusted when
// [WithTrustedDeviceTTL] says nothing: thirty days.
//
// It matches the default [WithRefreshTTL] deliberately. The two answer the
// same question from opposite sides — "how long may this machine stay signed
// in" and "how long may this machine skip the second factor" — and a device
// trusted for longer than its session can survive would keep skipping the
// factor for a user who has been signed out for weeks. They are not derived
// from one another and do not move together: a deployment that lengthens the
// refresh TTL has said nothing about how long it is willing to skip a
// factor, and the shorter of the two is always the safer default.
const defaultTrustedDeviceTTL = 30 * 24 * time.Hour

// ErrTrustedDeviceNotFound: no [TrustedDevice] matches — an unknown hash at
// [MFAStore.FindTrustedDeviceByHash], or an id at
// [Service.RevokeTrustedDevice] that names no device OF THAT USER.
//
// The second case is deliberately indistinguishable from the first: a caller
// handed another account's device id learns only that it is not theirs,
// which is the same answer [Service.RevokeSession] gives for the identical
// question.
var ErrTrustedDeviceNotFound = errors.New("authlayer/auth: no such trusted device")

// TrustedDevice is one machine a user has vouched for: a long-lived bearer
// token that satisfies the SECOND factor at [Service.LoginWithTrustedDevice]
// and nothing else. It never satisfies the first — see this file's package
// doc, which is where that argument lives in full.
//
// A user may hold several (a laptop, a phone, a desktop at work), so unlike
// [MFAFactor] this record has a surrogate id and no per-user uniqueness rule.
type TrustedDevice struct {
	// ID is the record's surrogate key, stamped by the service (uid.NewV7),
	// and the handle [Service.ListTrustedDevices] shows and
	// [Service.RevokeTrustedDevice] takes. [WithIDGenerator]'s "MUST be
	// UUID-parseable to use store/drops" constraint covers this column.
	ID string `drop:"id"`
	// UserID is the account this device is trusted for. A device minted for
	// one account MUST do nothing for another: [Service.LoginWithTrustedDevice]
	// compares this against the account the password just authenticated, and
	// a mismatch falls through to the ordinary challenge.
	UserID string `drop:"user_id"`
	// TokenHash is the STORED hash of the opaque token
	// ([token.HashOpaque]), never the token. An implementation MUST enforce
	// uniqueness on this column — a UNIQUE constraint in a SQL backend —
	// for the reason [Session.TokenHash] carries the same MUST: two rows
	// sharing a hash make [MFAStore.FindTrustedDeviceByHash] return
	// whichever the backend reached first, so WHICH ACCOUNT a token skips
	// the second factor for would be decided by row order.
	TokenHash string `drop:"token_hash"`
	// Label is the application's own display string for the device ("Ada's
	// MacBook", a parsed user agent). It is stored verbatim, is never
	// consulted by any decision this package makes, and is not validated:
	// an empty label is a device with no name, not an error.
	Label string `drop:"label"`
	// CreatedAt is when the user vouched for the device.
	CreatedAt time.Time `drop:"created_at"`
	// ExpiresAt is when the trust lapses — CreatedAt plus
	// [WithTrustedDeviceTTL]. The comparison is half-open like every other
	// expiry in this package (`now.Before(ExpiresAt)`), and an expired row
	// is refused by [Service.LoginWithTrustedDevice] long before
	// [Service.PurgeExpired] removes it.
	ExpiresAt time.Time `drop:"expires_at"`
	// LastUsedAt is when this device last skipped a challenge, or nil while
	// it never has. It is what a "your trusted devices" screen shows beside
	// each row, and what an operator reads when a user reports a device they
	// do not recognise.
	LastUsedAt *time.Time `drop:"last_used_at"`
}

// WithTrustedDeviceTTL sets how long a device stays trusted after
// [Service.TrustThisDevice] mints it. The default is
// [defaultTrustedDeviceTTL], thirty days. d <= 0 is ignored, leaving the
// default (or a prior option) in place, matching [WithMagicLinkTTL]'s
// treatment of the same input.
//
// This is the whole of the window in which a token sitting in a cookie is a
// working second-factor bypass, so it is the one knob that bounds "the
// laptop was stolen after it was trusted". It is not the only control — the
// token is bound to one account, every remediation path revokes it (see
// [Service.ChangePassword]'s "The sweep matrix"), and
// [Service.RevokeTrustedDevice] drops one on request — but it is the only
// one that acts without anybody noticing anything.
//
// Zero does NOT disable the feature the way [WithStepUpWindow]'s zero
// disables step-up, and the asymmetry is deliberate: this option's unsafe
// direction is "longer", so a zero arriving from an unset config field must
// fall back to a bounded default rather than to a device that never expires.
// A deployment that wants no trusted devices at all simply never calls
// [Service.TrustThisDevice] — with no device minted there is nothing to
// present.
func WithTrustedDeviceTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.trustedDeviceTTL = d
		}
	}
}

// TrustThisDevice mints a trusted-device token for userID and returns its
// PLAINTEXT — once, here, and never again; only the hash is stored. The
// caller puts it somewhere the machine will present it at the next sign-in
// (an HttpOnly, Secure, SameSite cookie is the intended home) and passes it
// back through [Service.LoginWithTrustedDevice].
//
// label is the application's display string for the device and is stored
// verbatim; see [TrustedDevice.Label].
//
// # What it requires, and why each of the two is separate
//
// sessionID is the caller's own session — the SessionID claim off the access
// token that authenticated this request — and userID the Subject claim
// beside it, exactly as [Service.RequireFreshMFA] takes them.
//
//  1. The account must hold a CONFIRMED [MFAFactor], or this is
//     [ErrMFARequired]. A device that skips the second factor is meaningless
//     without one, and minting it anyway would arm a bypass BEFORE the thing
//     it bypasses exists — see this file's package doc.
//  2. That session must have proved a factor inside [WithStepUpWindow], or
//     this is [ErrStepUpRequired] and nothing is written. This is the check
//     that keeps a stolen session from becoming a permanent bypass, and it
//     is the reason this method is not simply "write a row".
//
// The two are separate calls rather than one because they refuse different
// things and route the caller to different places: ErrMFARequired sends a
// user to [Service.BeginMFAEnrolment], ErrStepUpRequired sends them to a
// fresh sign-in ending in [Service.CompleteMFA]. Order matters only in that
// the factor check runs first, so an account with nothing enrolled is told
// that rather than being told to prove something it does not have.
//
// # Fail closed
//
// [ErrMFANotConfigured] with no [WithMFAStore] — a deployment holding no
// factors has nothing for a device to stand in for. [ErrUserNotFound] for an
// unknown or ANONYMIZED account: a stamped row holds no sessions and must
// never acquire a fresh credential (see [Service.AnonymizeAccount], "Every
// entry point that refuses a stamped account"). Any Store or MFAStore error
// is returned as-is and nothing is minted.
//
// It deliberately does NOT check the account's password. Every other
// credential-arming method in this package does, and the difference is that
// those are reachable from a session alone while this one is not: the
// freshness requirement above already demands a second factor presented
// minutes ago, which a stolen session cannot produce. Asking for the
// password as well would refuse every password-less account — an OAuth-only
// or passkey-only user with a confirmed factor — a feature they can
// otherwise use.
func (s *Service) TrustThisDevice(ctx context.Context, userID, sessionID, label string) (string, error) {
	st, err := s.mfa()
	if err != nil {
		return "", err
	}

	u, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	// An ANONYMIZED account arms no credential, however the caller reached
	// here. See [Service.AnonymizeAccount], "Every entry point that refuses
	// a stamped account"; this check is deliberately its own rather than one
	// shared guard several paths reach.
	if u.DeletedAt != nil {
		return "", ErrUserNotFound
	}

	// A device that skips the second factor needs a second factor to skip.
	// This is NOT redundant with the RequireFreshMFA below: that call is a
	// documented no-op for exactly this account, so without this line a
	// factor-less account would mint a bypass for the factor it enrols
	// next week.
	switch f, ferr := st.FindFactor(ctx, u.ID); {
	case errors.Is(ferr, ErrFactorNotFound):
		return "", ErrMFARequired
	case ferr != nil:
		return "", ferr
	case f.ConfirmedAt == nil:
		return "", ErrMFARequired
	}

	// The line this whole feature turns on — see [Service.RequireFreshMFA].
	// Without it a stolen session mints a thirty-day second-factor bypass.
	if err := s.RequireFreshMFA(ctx, u.ID, sessionID); err != nil {
		return "", err
	}

	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		return "", err
	}
	now := s.cfg.clock()
	if _, err := st.CreateTrustedDevice(ctx, TrustedDevice{
		ID:        s.cfg.idGen(),
		UserID:    u.ID,
		TokenHash: hash,
		Label:     label,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.trustedDeviceTTL),
		// LastUsedAt stays nil: trusting a device is not using one.
	}); err != nil {
		return "", err
	}
	return plain, nil
}

// ListTrustedDevices returns every device userID has vouched for, expired
// ones included, in whatever order the store gives them. It is what a "your
// trusted devices" screen renders, beside [Service.ListSessions].
//
// Expired rows are included rather than filtered because they are what a
// user is looking at when they ask "why does this machine keep asking me for
// a code" — and because filtering here would make the listing disagree with
// [Service.RevokeTrustedDevice], which will happily drop one. Compare
// [TrustedDevice.ExpiresAt] against your own clock to render them
// differently; [Service.PurgeExpired] is what eventually removes them.
//
// [TrustedDevice.TokenHash] is returned as stored. It is a hash, not a
// credential, exactly as [Service.ListSessions] returns [Session.TokenHash]
// — but it is also not something to render, and an application putting this
// result straight into a JSON response is publishing the shape of its own
// token store for no reason.
//
// [ErrMFANotConfigured] with no [WithMFAStore]. It performs no authorization
// of its own: the caller establishes that whoever is asking owns userID,
// exactly as [Service.ListSessions] requires.
func (s *Service) ListTrustedDevices(ctx context.Context, userID string) ([]TrustedDevice, error) {
	st, err := s.mfa()
	if err != nil {
		return nil, err
	}
	return st.ListTrustedDevices(ctx, userID)
}

// RevokeTrustedDevice drops ONE of userID's trusted devices — the one named
// by deviceID — so that machine is asked for a second factor again at its
// next sign-in. [ErrTrustedDeviceNotFound] when deviceID names no device of
// that user's, INCLUDING when it names somebody else's.
//
// The ownership check is a list-and-scan over userID's own devices, exactly
// as [Service.RevokeSession] scans that user's own sessions and for the
// identical reason: without it, a deviceID is a bare surrogate key and any
// caller who guessed or was leaked one could revoke a stranger's device.
// Scanning the user's own rows makes "not yours" and "not there"
// indistinguishable, which is the answer both deserve.
//
// It revokes the DEVICE and nothing else: the machine's [Session] rows are
// untouched and it stays signed in — dropping a device from the trusted list
// is a statement about the second factor, not about access. Use
// [Service.RevokeSession] or [Service.LogoutAll] for the other half; see
// [Service.ChangePassword]'s doc, "The sweep matrix", for the whole table.
func (s *Service) RevokeTrustedDevice(ctx context.Context, userID, deviceID string) error {
	st, err := s.mfa()
	if err != nil {
		return err
	}
	devices, err := st.ListTrustedDevices(ctx, userID)
	if err != nil {
		return err
	}
	for _, d := range devices {
		if d.ID == deviceID {
			return st.DeleteTrustedDevice(ctx, deviceID)
		}
	}
	return ErrTrustedDeviceNotFound
}

// trustedDeviceAtSignIn resolves deviceToken against u, returning the device
// that may stand in for u's second factor or (nil, nil) when none may.
//
// It is consulted by [Service.LoginWithTrustedDevice] ONLY after the password
// has been verified — that ordering is the feature's whole safety argument
// and lives in this file's package doc — and its answer decides exactly one
// thing: whether [Service.mfaAtSignIn] runs.
//
// # Every "no" is a fall-through, not a refusal
//
// An empty token, no [WithMFAStore], an account with no confirmed factor, an
// unknown hash, another user's device, an expired one: all of them return
// (nil, nil), and the sign-in proceeds to the ordinary second-factor
// challenge. That is the fail-closed direction here, because the failure
// mode being avoided is "skipped the factor it should not have", and asking
// for a code is never dangerous. Turning any of them into an error would
// mean a user whose trust cookie went stale — the ordinary case, after
// thirty days — could not sign in at all, which is a lockout produced by a
// convenience feature.
//
// A store ERROR is different and is returned: it means the answer is
// unknown, not that it is "no".
//
// The confirmed-factor check is what keeps this from bypassing
// [EnforcementRequired]. With no confirmed factor there is nothing for a
// device to stand in for, so mfaAtSignIn runs and applies the enforcement
// policy exactly as it would have — a trusted device can never turn
// ErrMFARequired into a session.
func (s *Service) trustedDeviceAtSignIn(ctx context.Context, u UserBase, deviceToken string) (*TrustedDevice, error) {
	if deviceToken == "" || s.cfg.mfaStore == nil {
		return nil, nil
	}

	switch f, err := s.cfg.mfaStore.FindFactor(ctx, u.ID); {
	case errors.Is(err, ErrFactorNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	case f.ConfirmedAt == nil:
		return nil, nil
	}

	d, err := s.cfg.mfaStore.FindTrustedDeviceByHash(ctx, token.HashOpaque(deviceToken))
	switch {
	case errors.Is(err, ErrTrustedDeviceNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	// A device minted for one account does nothing for another. The password
	// just authenticated u; this token names somebody else.
	if d.UserID != u.ID {
		return nil, nil
	}
	// Half-open, like every other expiry in this package.
	if !s.cfg.clock().Before(d.ExpiresAt) {
		return nil, nil
	}
	return &d, nil
}

// sweepTrustedDevices removes every trusted device on userID's account. It
// is the trusted-device column of [Service.ChangePassword]'s sweep matrix,
// called on its OWN LINE by each path whose cell says "swept" so that
// removing one call fails exactly one cell's test.
//
// A [Service] with no [WithMFAStore] holds no devices, so it sweeps nothing
// and reports no error — the same stated limit [Service.sweepIdentities]
// carries for its own port: a second Service wired differently over the same
// tables is outside what this one can reason about.
func (s *Service) sweepTrustedDevices(ctx context.Context, userID string) error {
	if s.cfg.mfaStore == nil {
		return nil
	}
	return s.cfg.mfaStore.DeleteTrustedDevicesByUser(ctx, userID)
}
