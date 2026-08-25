package scope

import (
	"context"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
)

// Container is the read side of a scope container: the engine reads a
// container's id and owner. Any type embedding ContainerBase satisfies it.
type Container interface {
	ContainerID() string
	ContainerOwner() string
}

// Member is the read side of a membership: the engine reads which container and
// user it links and which role it grants. Any type embedding MemberBase
// satisfies it.
type Member interface {
	MemberContainer() string
	MemberUser() string
	MemberRole() string
}

// MutableContainer is the write side used by the engine (to stamp base fields
// on create) and by Store implementations (to apply an owner change). Embed
// ContainerBase to inherit it.
type MutableContainer interface {
	Container
	SetID(string)
	SetOwner(string)
	SetTimes(created, updated time.Time)
}

// MutableMember is the write side used by the engine and stores. Embed
// MemberBase to inherit it.
type MutableMember interface {
	Member
	SetKeys(container, user, role string)
	SetJoined(time.Time)
}

// Nested is the read side of a nested container: which scope contains it. Any
// type embedding [NestedBase] satisfies it. The engine type-asserts a loaded
// container to Nested when a parent is configured.
type Nested interface {
	ContainerParent() string
}

// ParentScope is the narrow view a child scope needs of its parent — resolving
// one user's standing there. *Service satisfies it.
//
// It is deliberately not generic: a child Service's type parameters are its
// own, and a parent with different ones could not otherwise be held as a field.
// Only the projected result crosses the boundary, never the parent's types.
type ParentScope interface {
	// Standing resolves userID's permissions in containerID and whether they
	// are elevated there. It returns ErrNotMember when the user has no
	// standing, and ErrContainerNotFound when the container is absent — both of
	// which a child treats as "no inherited standing" rather than a failure.
	Standing(ctx context.Context, containerID, userID string) (access.Permission, bool, error)
}
