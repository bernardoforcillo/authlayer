package apikey

import (
	"context"
	"time"
)

// EventKind identifies a lifecycle event emitted by the Service. The shape
// mirrors scope's own hooks — one Hook interface, one Event struct, a
// HookFunc adapter, [WithHooks] to register — so an audit sink written for
// scope needs no new pattern here.
type EventKind int

// The lifecycle events. The comments note which optional Event fields carry
// a value for each kind.
const (
	// ServiceAccountCreated is emitted by CreateServiceAccount once BOTH the
	// record and the membership exist. ServiceAccountID is the new account,
	// RoleKey its role, ActorID the creating user. scope emits its own
	// MemberAdded for the membership half, with ActorID equal to the
	// account's id — see [scope.Service.GrantMembership] for why — so an
	// audit trail attributing the admission to a person reads it from THIS
	// event.
	ServiceAccountCreated EventKind = iota
	// ServiceAccountDisabled is emitted by DisableServiceAccount.
	ServiceAccountDisabled
	// ServiceAccountEnabled is emitted by EnableServiceAccount.
	ServiceAccountEnabled
	// ServiceAccountRoleChanged is emitted by ChangeServiceAccountRole.
	// RoleKey is the new role; scope emits MemberRoleChanged alongside.
	ServiceAccountRoleChanged
	// ServiceAccountDeleted is emitted by DeleteServiceAccount once the
	// membership, the record and every key are gone.
	ServiceAccountDeleted
	// KeyCreated is emitted by CreateKey. KeyID is the new key. The
	// plaintext is never on an event.
	KeyCreated
	// KeyRevoked is emitted by RevokeKey.
	KeyRevoked
	// KeyAuthenticated is emitted by Authenticate on success. ActorID is the
	// service account (the principal that just came into being), KeyID the
	// key. Detail is DetailTouchFailed when the best-effort TouchKey failed,
	// else empty — this is the one place that failure is reported.
	KeyAuthenticated
	// KeyAuthenticationFailed is emitted by Authenticate on a refusal.
	// Detail says why, in the fixed vocabulary below; the other fields are
	// filled as far as the refusal got — nothing at all for an unknown key,
	// the key and account for a disabled account. It fires for every
	// presentation of an unknown string, so a hook here is on the
	// unauthenticated path: keep it cheap.
	KeyAuthenticationFailed
)

// The fixed vocabulary of [Event.Detail]. Never free text and never a
// plaintext key, so an event can be logged as-is.
const (
	// DetailTouchFailed: KeyAuthenticated, but [Store.TouchKey] returned an
	// error; LastUsedAt was not advanced.
	DetailTouchFailed = "touch_failed"
	// DetailKeyNotFound: no key hashes to the presented plaintext.
	DetailKeyNotFound = "key_not_found"
	// DetailKeyRevoked: the key's RevokedAt is set.
	DetailKeyRevoked = "key_revoked"
	// DetailKeyExpired: the key's ExpiresAt is not in the future.
	DetailKeyExpired = "key_expired"
	// DetailAccountDisabled: the key is live but its account is disabled.
	DetailAccountDisabled = "account_disabled"
	// DetailAccountNotFound: the key resolved but its account did not — a
	// key that outlived its account, which [Store.DeleteServiceAccount]'s
	// cascade MUST prevent; refused all the same.
	DetailAccountNotFound = "account_not_found"
)

// Event describes a mutation, or an authentication, for hooks — audit,
// webhooks, metrics. Fields other than Kind, ContainerID and At are set when
// relevant to the event; see the [EventKind] constants.
type Event struct {
	// Kind is which event occurred.
	Kind EventKind
	// ContainerID is the scope it happened in, when known.
	ContainerID string
	// ActorID is who did it: the ctx subject for every management call, the
	// service account itself for KeyAuthenticated, empty for a refused
	// authentication.
	ActorID string
	// ServiceAccountID is the account involved, when there is one.
	ServiceAccountID string
	// KeyID is the key involved, when there is one.
	KeyID string
	// RoleKey is the role involved, on ServiceAccountCreated and
	// ServiceAccountRoleChanged.
	RoleKey string
	// Detail is a fixed-vocabulary qualifier (the Detail* constants), set on
	// KeyAuthenticationFailed always and on KeyAuthenticated when the touch
	// failed.
	Detail string
	// At is the event time, stamped from the Service clock if left zero.
	At time.Time
}

// Hook observes lifecycle events.
//
// Hooks fire after the store change has been applied but before the method
// returns, and a hook that returns an error is returned to the caller —
// exactly [scope.Hook]'s rule. None of this package's mutations runs in a
// transaction with its hook, so a failing hook leaves the change in place
// while the caller sees an error; for Authenticate that means the key WAS
// touched and the caller does NOT get the principal. On a refused
// authentication the hook's error is joined onto the sentinel rather than
// replacing it, so errors.Is(err, ErrKeyRevoked) still holds. Keep side
// effects that must not be retried out of hooks, and prefer returning nil
// for best-effort work such as logging.
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
