package scope

import (
	"context"
	"time"
)

// EventKind identifies a lifecycle event emitted after a successful mutation.
type EventKind int

// The lifecycle events the engine emits. The comments note which optional
// Event fields carry a value for each kind.
const (
	// ContainerCreated is emitted by CreateContainer, inside the same
	// transaction that persists the container and the owner's membership.
	// ActorID is the new owner.
	ContainerCreated EventKind = iota
	// MemberAdded is emitted by AddMember. TargetID is the added user and
	// RoleKey the role they were given.
	MemberAdded
	// MemberRoleChanged is emitted by ChangeMemberRole. TargetID is the member
	// and RoleKey their new role; the previous role is not reported.
	MemberRoleChanged
	// MemberRemoved is emitted by RemoveMember and by LeaveContainer. On a
	// leave, TargetID equals ActorID.
	MemberRemoved
	// RoleCreated is emitted by CreateRole. RoleKey is the new custom role.
	RoleCreated
	// RoleUpdated is emitted by UpdateRole. RoleKey identifies the role whose
	// name and grants were replaced.
	RoleUpdated
	// RoleDeleted is emitted by DeleteRole. RoleKey is the removed custom role,
	// which was verified to have no members.
	RoleDeleted
	// OwnershipTransferred is emitted by TransferOwnership. ActorID is the
	// outgoing owner and TargetID the incoming one. Note that the outgoing
	// owner keeps their membership and its role key.
	OwnershipTransferred
)

// Event describes a mutation for hooks (audit, webhooks, cache invalidation,
// outbox). TargetID / RoleKey are set when relevant to the event; see the
// [EventKind] constants for which fields each kind populates.
type Event struct {
	// Kind is which mutation occurred.
	Kind EventKind
	// ContainerID is the scope the mutation happened in.
	ContainerID string
	// ActorID is the user who performed it (the ctx subject).
	ActorID string
	// TargetID is the user the mutation was performed on, when there is one.
	TargetID string
	// RoleKey is the role involved, when there is one.
	RoleKey string
	// At is the event time, stamped from the Service clock if left zero — so a
	// hook can rely on it being set even though the engine constructs events
	// without it.
	At time.Time
}

// Hook observes lifecycle events.
//
// Hooks fire after the mutation has been applied to the store but before the
// operation returns, and a hook that returns an error aborts the operation: the
// error is propagated to the caller, and where the mutation runs in a
// transaction (CreateContainer) the whole thing is rolled back. That makes a
// hook a usable place for a transactional outbox, but it also means a hook that
// fails on a non-transactional operation leaves the store change in place while
// the caller sees an error — so keep side effects that must not be retried out
// of hooks, and prefer returning nil for best-effort work such as logging.
//
// Hooks run in the order they were registered with [WithHooks]; the first error
// stops the chain. They are called on the caller's goroutine and share its
// context, so a slow hook slows the request.
type Hook interface {
	On(ctx context.Context, e Event) error
}

// HookFunc adapts a function to the Hook interface.
type HookFunc func(ctx context.Context, e Event) error

// On implements Hook.
func (f HookFunc) On(ctx context.Context, e Event) error { return f(ctx, e) }
