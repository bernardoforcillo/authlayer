package oauth

import (
	"context"
	"time"
)

// EventKind identifies a lifecycle event emitted by the Service. The shape
// mirrors scope's, auth's and apikey's hooks — one Hook interface, one Event
// struct, a HookFunc adapter, [WithHooks] to register — so an audit sink
// written for any of them needs no new pattern here.
type EventKind int

// The lifecycle events. The comments note which optional Event fields carry
// a value for each kind.
const (
	// ClientCreated is emitted by CreateClient. ClientID is the new client,
	// ActorID the creating user, ContainerID the owning container.
	ClientCreated EventKind = iota
	// ClientRegistered is emitted by RegisterClient. ClientID is the new
	// client; there is no actor and no container.
	ClientRegistered
	// ClientDisabled is emitted by DisableClient.
	ClientDisabled
	// ClientEnabled is emitted by EnableClient.
	ClientEnabled
	// ClientDeleted is emitted by DeleteClient once the client and
	// everything of it are gone.
	ClientDeleted
	// GrantCreated is emitted by Approve and ApproveDevice. GrantID is the
	// new grant, ActorID the approving user, ClientID the client it
	// delegates to.
	GrantCreated
	// GrantRevoked is emitted by every path that revokes a grant: the user's
	// RevokeGrant (ActorID the user), a client's Revoke (ActorID empty),
	// and the replay responses in ExchangeCode and Refresh (Detail says
	// which). Also emitted for the grant a losing ApproveDevice created
	// and then revoked.
	GrantRevoked
	// TokenIssued is emitted by ClientCredentials, ExchangeCode and
	// PollDevice. Detail is the grant type, ActorID the token's subject,
	// GrantID the grant for a delegated token.
	TokenIssued
	// TokenRefreshed is emitted by Refresh on success.
	TokenRefreshed
	// TokenReuseDetected is emitted by Refresh when a rotated refresh token
	// is presented again, and by ExchangeCode when a redeemed code is:
	// Detail is DetailRefreshReplayed or DetailCodeReplayed. The family and
	// the grant are already revoked when it fires.
	TokenReuseDetected
	// DeviceApproved is emitted by ApproveDevice. ActorID is the approving
	// user, GrantID the grant created.
	DeviceApproved
	// DeviceDenied is emitted by DenyDevice.
	DeviceDenied
	// TokenAuthenticated is emitted by Authenticate on success. ActorID is
	// the principal's subject. Detail is DetailTouchFailed when the
	// best-effort TouchGrant failed, else empty — the one place that
	// failure is reported.
	TokenAuthenticated
	// AuthenticationFailed is emitted by Authenticate on a refusal. Detail
	// says why, in the fixed vocabulary below. It fires for every
	// presentation of an unparseable string, so a hook here is on the
	// unauthenticated path: keep it cheap.
	AuthenticationFailed
)

// The fixed vocabulary of [Event.Detail]. Never free text and never a
// token, so an event can be logged as-is.
const (
	// DetailTouchFailed: TokenAuthenticated, but [Store.TouchGrant] returned
	// an error; LastUsedAt was not advanced.
	DetailTouchFailed = "touch_failed"
	// DetailTokenInvalid: the signer refused the token — malformed, a bad
	// signature, an unknown key, or expired.
	DetailTokenInvalid = "token_invalid"
	// DetailIssuerMismatch: the token's iss is not this Service's issuer.
	DetailIssuerMismatch = "issuer_mismatch"
	// DetailAudienceMismatch: none of the token's aud is one this Service
	// was built with.
	DetailAudienceMismatch = "audience_mismatch"
	// DetailNotAnAccessToken: the token verified but is not one this
	// package minted — no client_id, a session id, or no container.
	DetailNotAnAccessToken = "not_an_access_token"
	// DetailGrantNotFound: a delegated token names a grant that is gone.
	DetailGrantNotFound = "grant_not_found"
	// DetailGrantRevoked: the grant's RevokedAt is set.
	DetailGrantRevoked = "grant_revoked"
	// DetailGrantExpired: the grant's ExpiresAt is not in the future.
	DetailGrantExpired = "grant_expired"
	// DetailClientNotFound: a client-credentials token names a client that
	// is gone.
	DetailClientNotFound = "client_not_found"
	// DetailClientDisabled: the client's DisabledAt is set.
	DetailClientDisabled = "client_disabled"
	// DetailSubjectMismatch: the token's sub or client_id does not match
	// the grant or client it names — a token from another deployment
	// sharing the signing key, or a forged claim set.
	DetailSubjectMismatch = "subject_mismatch"
	// DetailCodeReplayed: an authorization code was presented twice.
	DetailCodeReplayed = "code_replayed"
	// DetailRefreshReplayed: a rotated refresh token was presented again.
	DetailRefreshReplayed = "refresh_replayed"
	// DetailWrongClient: a code or refresh token was presented by a client
	// other than the one it was issued to; the grant is revoked.
	DetailWrongClient = "wrong_client"
	// DetailUserRevoked: GrantRevoked through the grantor's own RevokeGrant.
	DetailUserRevoked = "user"
	// DetailClientRevoked: GrantRevoked through the client's Revoke.
	DetailClientRevoked = "client"
	// DetailApprovalLost: GrantRevoked for the grant an ApproveDevice
	// created before losing the status compare-and-set.
	DetailApprovalLost = "approval_lost"
)

// Event describes a mutation, an issuance or an authentication, for hooks
// — audit, webhooks, metrics. Fields other than Kind and At are set when
// relevant to the event; see the [EventKind] constants.
type Event struct {
	// Kind is which event occurred.
	Kind EventKind
	// ContainerID is the scope it happened in, when known.
	ContainerID string
	// ActorID is who did it: the ctx subject for every management call and
	// every approval, the token's subject for an issuance or an
	// authentication, empty for a refused authentication and for a
	// client-initiated revocation.
	ActorID string
	// ClientID is the client involved, when there is one.
	ClientID string
	// GrantID is the grant involved, when there is one.
	GrantID string
	// Detail is a fixed-vocabulary qualifier (the Detail* constants): the
	// grant type on TokenIssued, the reason on AuthenticationFailed, the
	// path on GrantRevoked and TokenReuseDetected.
	Detail string
	// At is the event time, stamped from the Service clock if left zero.
	At time.Time
}

// Hook observes lifecycle events.
//
// Hooks fire after the store change has been applied but before the method
// returns, and a hook that returns an error is returned to the caller —
// exactly scope's rule. None of this package's mutations runs in a
// transaction with its hook, so a failing hook leaves the change in place
// while the caller sees an error; for a token endpoint that means the
// tokens WERE minted and the client does NOT receive them, which is safe (a
// token nobody holds is inert) but wasteful. On a refusal the hook's error
// is joined onto the sentinel rather than replacing it, so errors.Is still
// holds. Keep side effects that must not be retried out of hooks, and
// prefer returning nil for best-effort work such as logging.
//
// Hooks run in the order they were registered with [WithHooks]; the first
// error stops the chain. They are called on the caller's goroutine and share
// its context.
type Hook interface {
	On(ctx context.Context, e Event) error
}

// HookFunc adapts a function to the Hook interface.
type HookFunc func(ctx context.Context, e Event) error

// On implements Hook.
func (f HookFunc) On(ctx context.Context, e Event) error { return f(ctx, e) }
