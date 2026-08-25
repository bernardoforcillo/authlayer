package scope

import "context"

// A Store is pure persistence. The engine decides — it stamps ids, owners and
// timestamps, resolves roles, and runs every authorization check — then hands
// the Store fully-formed values to write, or keys to read by. A Store performs
// no authorization of its own and interprets no permission bytes.
//
// The contract a backend must honour is mostly about which sentinel error to
// return when a lookup finds nothing, because the engine branches on those:
// returning a generic "not found" instead of ErrNotMember, for example, turns a
// clean "you are not a member" answer into an opaque failure. The error each
// method owes is documented on it below; store/memory is the reference
// implementation and store/drops the production one.

// MemberStanding is a flattened membership row: which container, which role
// key, and who owns that container. It is what a cross-container decision
// needs, and a backend can fetch it in one join rather than one query per
// container.
//
// It is deliberately not generic. The engine reads only these three fields
// when answering "which containers grant this user X?", so pulling whole
// container and member values would cost more and buy nothing.
type MemberStanding struct {
	// ContainerID is the container the membership belongs to.
	ContainerID string `drop:"container_id"`
	// RoleKey is the role held there — a code-defined default or a custom key.
	RoleKey string `drop:"role_key"`
	// OwnerID is the CONTAINER's owner, not the member. It lets the engine
	// apply OwnerBypass without a second lookup.
	OwnerID string `drop:"owner_id"`
}

// ContainerStore persists scope containers of type C.
type ContainerStore[C any] interface {
	// CreateContainer persists an already-populated container (the engine has
	// stamped its base id/owner/timestamps) and returns what was stored. A
	// unique-constraint violation on a custom field (e.g. a slug) must be
	// reported as ErrConflict.
	CreateContainer(ctx context.Context, c C) (C, error)
	// FindContainer loads a container by id, returning ErrContainerNotFound
	// when there is none. Every authorization check begins here.
	FindContainer(ctx context.Context, id string) (C, error)
	// UpdateContainerOwner reassigns ownership, returning
	// ErrContainerNotFound when no row matched. It must change only the owner
	// (and any updated-at bookkeeping), never a membership.
	UpdateContainerOwner(ctx context.Context, id, newOwnerID string) error
	// ListUserContainers returns every container userID is a member of. A user
	// with no memberships yields an empty slice, not an error. Order is
	// unspecified.
	ListUserContainers(ctx context.Context, userID string) ([]C, error)
}

// MemberStore persists memberships of type M, keyed by (containerID, userID).
type MemberStore[M any] interface {
	// AddMember persists an already-stamped membership, returning
	// ErrAlreadyMember if (container, user) is taken. Enforcing that
	// uniqueness is the Store's job — the engine does not pre-check it.
	AddMember(ctx context.Context, m M) (M, error)
	// FindMember loads one membership, returning ErrNotMember when absent.
	// This is the hot path: it runs on every permission check for a non-owner.
	FindMember(ctx context.Context, containerID, userID string) (M, error)
	// ListMembers returns every membership in a container, or
	// ErrContainerNotFound. Order is unspecified.
	ListMembers(ctx context.Context, containerID string) ([]M, error)
	// UpdateMemberRole rewrites a membership's role key, returning
	// ErrNotMember when no row matched.
	UpdateMemberRole(ctx context.Context, containerID, userID, roleKey string) error
	// RemoveMember deletes a membership, returning ErrNotMember when no row
	// matched.
	RemoveMember(ctx context.Context, containerID, userID string) error
	// CountMembersWithRole counts memberships holding roleKey. It backs the
	// ErrRoleInUse check in DeleteRole, so it must count committed rows rather
	// than an estimate.
	CountMembersWithRole(ctx context.Context, containerID, roleKey string) (int, error)
	// ListUserStandings returns one [MemberStanding] per membership userID
	// holds, across every container. A user with no memberships yields an
	// empty slice, not an error. Order is unspecified.
	//
	// It backs Service.ContainersWith and therefore the per-action query
	// guards: a backend should satisfy it with a single join rather than a
	// query per container.
	//
	// Fill each standing's OwnerID from the container, never from the
	// membership (see [MemberStanding]). The engine compares it against userID
	// to apply OwnerBypass, so a backend that returns the member's own id there
	// makes every standing look owned: every per-action guard silently degrades
	// to membership level and every member passes every check. It is the one
	// implementer mistake in this port that fails open.
	ListUserStandings(ctx context.Context, userID string) ([]MemberStanding, error)
}

// RoleStore persists custom roles. It is not generic: [RoleRecord] is fixed, so
// every backend shares one role table shape.
//
// Permissions cross this boundary as opaque bytes ([access.Permission.Encode]);
// a Store must round-trip them unchanged and never parse them.
type RoleStore interface {
	// CreateRole persists an already-stamped role, returning ErrRoleKeyTaken
	// when (container, key) is taken.
	CreateRole(ctx context.Context, r RoleRecord) (RoleRecord, error)
	// FindRole loads one custom role, returning ErrRoleNotFound when absent.
	// The engine calls it whenever a membership names a key the code-defined
	// role registry does not know.
	FindRole(ctx context.Context, containerID, key string) (RoleRecord, error)
	// ListRoles returns a container's custom roles (not the defaults, which
	// live in code).
	ListRoles(ctx context.Context, containerID string) ([]RoleRecord, error)
	// UpdateRole replaces a role's name and permissions, returning
	// ErrRoleNotFound when no row matched.
	UpdateRole(ctx context.Context, containerID, key, name string, permissions []byte) error
	// DeleteRole removes a custom role, returning ErrRoleNotFound when no row
	// matched. The engine has already verified no member holds it.
	DeleteRole(ctx context.Context, containerID, key string) error
}

// Store is the full persistence port: containers, members, roles, and a
// transaction. It is composed from the smaller interfaces so a backend (or a
// decorator — caching, metrics, multi-tenant routing) can reuse or override a
// slice of it by embedding the parts it does not change.
//
// Implement it to put authlayer on a backend it does not ship with; the type
// parameters are the same C and M the Service is instantiated with.
type Store[C any, M any] interface {
	ContainerStore[C]
	MemberStore[M]
	RoleStore
	// WithTx runs fn inside a single transaction, passing a tx-scoped Store
	// that fn must use for its writes. Returning an error from fn must roll
	// back and propagate that error.
	//
	// The engine uses it for CreateContainer, where the container, the owner's
	// membership and the ContainerCreated hook must commit together or not at
	// all. A backend without real transactions may approximate it — the
	// in-memory store snapshots and restores — but a production backend should
	// use the database's.
	WithTx(ctx context.Context, fn func(Store[C, M]) error) error
}
