package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/token"
)

// DeviceResponse is the RFC 8628 §3.2 device authorization response, with
// that section's JSON names. VerificationURI is the application's own
// consent URL — this package knows no URLs — so set it, and optionally
// VerificationURIComplete (the same URL with the user code already in it),
// before serialising.
type DeviceResponse struct {
	// DeviceCode is the plaintext the client polls with, returned exactly
	// once; only its hash is stored.
	DeviceCode string `json:"device_code"`
	// UserCode is the code the person types, formatted XXXX-XXXX.
	UserCode string `json:"user_code"`
	// VerificationURI is where the person goes to type it. Left empty by
	// this package; required on the wire.
	VerificationURI string `json:"verification_uri"`
	// VerificationURIComplete optionally carries the code in the URL.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	// ExpiresIn is the lifetime of the device code in seconds.
	ExpiresIn int64 `json:"expires_in"`
	// Interval is the minimum seconds between polls.
	Interval int `json:"interval"`
}

// userCodeAlphabet is RFC 8628 §6.1's recommendation: twenty consonants,
// no vowels (so no words form), none of 0/O/1/I/S/5. Eight characters
// give 20^8 ≈ 2.6×10^10 codes, which at [WithDeviceTTL]'s ten minutes and
// any realistic rate of pending authorizations is far beyond the
// guessing budget a polling interval and a user-code endpoint's own rate
// limit allow — that endpoint MUST be rate limited by the application
// (§5.1), since a user code is the one credential here a person could
// type by mistake.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// userCodeLen is the stored length; the display form adds one dash.
const userCodeLen = 8

// newUserCode draws eight characters of userCodeAlphabet from crypto/rand.
// A crypto/rand failure is returned rather than degraded.
func newUserCode() (string, error) {
	var b [userCodeLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("authlayer/oauth: generate user code: %w", err)
	}
	out := make([]byte, userCodeLen)
	for i, r := range b {
		// 256 mod 20 = 16, so a plain modulo would bias the first sixteen
		// letters; discard and redraw instead.
		for r >= 240 {
			var one [1]byte
			if _, err := rand.Read(one[:]); err != nil {
				return "", fmt.Errorf("authlayer/oauth: generate user code: %w", err)
			}
			r = one[0]
		}
		out[i] = userCodeAlphabet[int(r)%len(userCodeAlphabet)]
	}
	return string(out), nil
}

// FormatUserCode renders a stored user code for display: XXXX-XXXX.
func FormatUserCode(code string) string {
	if len(code) != userCodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// NormalizeUserCode turns what a person typed into the stored form: dashes
// and spaces removed, upper-cased. [Service.DeviceByUserCode],
// [Service.ApproveDevice] and [Service.DenyDevice] apply it themselves; it
// is exported so an application can echo the canonical code back.
func NormalizeUserCode(typed string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(typed)))
}

// BeginDeviceAuthorization is RFC 8628 §3.1: the client asks for a device
// code and a user code, and receives both, the device code's plaintext
// exactly once. The client is identified but not authenticated here —
// RFC 8628 §3.1 authenticates a confidential client at this endpoint too,
// and this package defers that to [Service.PollDevice], where it is
// enforced on every poll, so a device code minted by anyone who knows a
// client id never mints a token without the secret. Refusals:
// [ErrClientNotFound], [ErrClientDisabled], [ErrUnauthorizedClient] when
// the client does not hold GrantDeviceCode, [ErrInvalidScope].
//
// The user code is eight characters of BCDFGHJKLMNPQRSTVWXZ, returned
// formatted XXXX-XXXX and stored without the dash; the row's uniqueness on
// it is the Store's MUST, and the vanishingly rare collision is returned
// as the store's error rather than retried.
func (s *Service) BeginDeviceAuthorization(ctx context.Context, clientID, scopeStr string) (DeviceResponse, error) {
	c, err := s.st.FindClient(ctx, clientID)
	if err != nil {
		return DeviceResponse{}, err
	}
	if c.DisabledAt != nil {
		return DeviceResponse{}, ErrClientDisabled
	}
	if err := requireGrantType(c, GrantDeviceCode); err != nil {
		return DeviceResponse{}, err
	}
	scopeStr, err = s.allowedScope(c, scopeStr)
	if err != nil {
		return DeviceResponse{}, err
	}
	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		return DeviceResponse{}, err
	}
	userCode, err := newUserCode()
	if err != nil {
		return DeviceResponse{}, err
	}
	now := s.cfg.clock()
	interval := int(s.cfg.deviceInterval / time.Second)
	if _, err := s.st.CreateDeviceAuthorization(ctx, DeviceAuthorization{
		ID:             s.cfg.idgen(),
		DeviceCodeHash: hash,
		UserCode:       userCode,
		ClientID:       c.ID,
		Scope:          scopeStr,
		Status:         DeviceStatusPending,
		Interval:       interval,
		ExpiresAt:      now.Add(s.cfg.deviceTTL),
		CreatedAt:      now,
	}); err != nil {
		return DeviceResponse{}, err
	}
	return DeviceResponse{
		DeviceCode: plain,
		UserCode:   FormatUserCode(userCode),
		ExpiresIn:  int64(s.cfg.deviceTTL / time.Second),
		Interval:   interval,
	}, nil
}

// pendingDevice loads the authorization a typed user code names and
// refuses one that is expired ([ErrExpiredToken]) or no longer pending
// ([ErrDeviceNotPending]), returning it with its client.
func (s *Service) pendingDevice(ctx context.Context, userCode string, now time.Time) (DeviceAuthorization, Client, error) {
	d, err := s.st.FindDeviceByUserCode(ctx, NormalizeUserCode(userCode))
	if err != nil {
		return DeviceAuthorization{}, Client{}, err
	}
	if !now.Before(d.ExpiresAt) {
		return DeviceAuthorization{}, Client{}, ErrExpiredToken
	}
	if d.Status != DeviceStatusPending {
		return DeviceAuthorization{}, Client{}, ErrDeviceNotPending
	}
	c, err := s.st.FindClient(ctx, d.ClientID)
	if err != nil {
		return DeviceAuthorization{}, Client{}, err
	}
	if c.DisabledAt != nil {
		return DeviceAuthorization{}, Client{}, ErrClientDisabled
	}
	return d, c, nil
}

// DeviceByUserCode resolves what a person typed into the pending
// authorization and its client, for the consent screen to show what is
// asking and for which scopes. The code is normalised first — dashes and
// spaces dropped, upper-cased — so "bcdf-ghjk" finds BCDFGHJK. An unknown
// code is [ErrDeviceNotFound]; an expired one [ErrExpiredToken]; one
// already decided [ErrDeviceNotPending]; a disabled client
// [ErrClientDisabled]. No subject is needed: the screen may be reached
// before sign-in. Rate limit the endpoint behind this (RFC 8628 §5.1).
func (s *Service) DeviceByUserCode(ctx context.Context, userCode string) (DeviceAuthorization, Client, error) {
	return s.pendingDevice(ctx, userCode, s.cfg.clock())
}

// ApproveDevice records the user's consent to the authorization the typed
// code names: it creates the [Grant] from the ctx subject to the client in
// the ctx container — the same escalation guard as [Service.Approve], see
// [Approval] — and moves the authorization from pending to approved
// through [Store.SetDeviceStatus]'s compare-and-set. If that transition is
// lost — a concurrent approval or denial got there first — the grant just
// created is revoked again and [ErrDeviceNotPending] is returned, so a
// lost race leaves no live delegation behind. The next poll then mints.
//
// The same refusals as [Service.DeviceByUserCode] apply first, then
// scope.ErrNotMember, scope.ErrPrivilegeEscalation and
// [ErrEmptyPermissions] from the delegation guard.
func (s *Service) ApproveDevice(ctx context.Context, userCode string, a Approval) error {
	user, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	now := s.cfg.clock()
	d, c, err := s.pendingDevice(ctx, userCode, now)
	if err != nil {
		return err
	}
	g, err := s.delegate(ctx, user, containerID, c, d.Scope, a)
	if err != nil {
		return err
	}
	won, err := s.st.SetDeviceStatus(ctx, d.ID, DeviceStatusPending, DeviceStatusApproved, g.ID, now)
	if err != nil {
		return err
	}
	if !won {
		rerr := s.st.RevokeGrant(ctx, g.ID, now)
		herr := s.emit(ctx, Event{Kind: GrantRevoked, ContainerID: containerID, ActorID: user, ClientID: c.ID, GrantID: g.ID, Detail: DetailApprovalLost, At: now})
		return errors.Join(ErrDeviceNotPending, rerr, herr)
	}
	for _, e := range []Event{
		{Kind: GrantCreated, ContainerID: containerID, ActorID: user, ClientID: c.ID, GrantID: g.ID, At: now},
		{Kind: DeviceApproved, ContainerID: containerID, ActorID: user, ClientID: c.ID, GrantID: g.ID, At: now},
	} {
		if err := s.emit(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// DenyDevice records the user's refusal: pending → denied through the
// compare-and-set, after which the client's next poll gets
// [ErrAccessDenied]. A lost transition is [ErrDeviceNotPending]. The ctx
// subject is recorded on the [DeviceDenied] event; no container is needed
// and no standing is checked, since refusing needs no permission.
func (s *Service) DenyDevice(ctx context.Context, userCode string) error {
	now := s.cfg.clock()
	d, c, err := s.pendingDevice(ctx, userCode, now)
	if err != nil {
		return err
	}
	won, err := s.st.SetDeviceStatus(ctx, d.ID, DeviceStatusPending, DeviceStatusDenied, "", now)
	if err != nil {
		return err
	}
	if !won {
		return ErrDeviceNotPending
	}
	actor, _ := scope.SubjectFrom(ctx)
	return s.emit(ctx, Event{Kind: DeviceDenied, ContainerID: c.ContainerID, ActorID: actor, ClientID: c.ID, At: now})
}

// PollDevice is RFC 8628 §3.4: the client authenticates and presents its
// device code, and receives either tokens or one of the four §3.5
// answers, each a sentinel:
//
//   - [ErrAuthorizationPending] — the user has not decided; poll again
//     after Interval seconds.
//   - [ErrSlowDown] — this poll came sooner than Interval seconds after
//     the last; add five seconds to your interval and poll again. The poll
//     is stamped, so polling faster only lengthens the wait.
//   - [ErrAccessDenied] — the user refused.
//   - [ErrExpiredToken] — the code expired before the user decided; start
//     over.
//
// On approved, the authorization moves approved → redeemed through the
// compare-and-set — so one device code mints exactly once, however many
// polls race — and the grant's tokens are minted: a delegated access token
// and, when the client holds GrantRefreshToken, a refresh token. A code
// already redeemed, unknown (wrapping ErrDeviceNotFound), or issued to
// another client is [ErrInvalidGrant]. Client authentication comes first:
// [ErrInvalidClient], [ErrClientDisabled], [ErrUnauthorizedClient].
func (s *Service) PollDevice(ctx context.Context, clientID, clientSecret, deviceCode string) (TokenResponse, error) {
	c, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := requireGrantType(c, GrantDeviceCode); err != nil {
		return TokenResponse{}, err
	}
	now := s.cfg.clock()
	d, err := s.st.FindDeviceByCodeHash(ctx, token.HashOpaque(deviceCode))
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			return TokenResponse{}, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
		}
		return TokenResponse{}, err
	}
	if d.ClientID != c.ID {
		return TokenResponse{}, fmt.Errorf("%w: device code was issued to another client", ErrInvalidGrant)
	}
	tooSoon := d.LastPolledAt != nil && now.Before(d.LastPolledAt.Add(time.Duration(d.Interval)*time.Second))
	if err := s.st.TouchDevicePoll(ctx, d.ID, now); err != nil {
		return TokenResponse{}, err
	}
	if tooSoon {
		return TokenResponse{}, ErrSlowDown
	}
	if !now.Before(d.ExpiresAt) {
		return TokenResponse{}, ErrExpiredToken
	}
	switch d.Status {
	case DeviceStatusPending:
		return TokenResponse{}, ErrAuthorizationPending
	case DeviceStatusDenied:
		return TokenResponse{}, ErrAccessDenied
	case DeviceStatusRedeemed:
		return TokenResponse{}, fmt.Errorf("%w: device code already redeemed", ErrInvalidGrant)
	case DeviceStatusApproved:
	default:
		return TokenResponse{}, fmt.Errorf("%w: device authorization in unknown status %q", ErrInvalidGrant, d.Status)
	}
	won, err := s.st.SetDeviceStatus(ctx, d.ID, DeviceStatusApproved, DeviceStatusRedeemed, "", now)
	if err != nil {
		return TokenResponse{}, err
	}
	if !won {
		return TokenResponse{}, fmt.Errorf("%w: device code already redeemed", ErrInvalidGrant)
	}
	g, err := s.liveGrant(ctx, d.GrantID, now)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return TokenResponse{}, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
		}
		return TokenResponse{}, err
	}
	resp, err := s.issueDelegated(ctx, c, g, "", now)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := s.emit(ctx, Event{
		Kind: TokenIssued, ContainerID: g.ContainerID, ActorID: g.UserID,
		ClientID: c.ID, GrantID: g.ID, Detail: GrantDeviceCode, At: now,
	}); err != nil {
		return TokenResponse{}, err
	}
	return resp, nil
}
