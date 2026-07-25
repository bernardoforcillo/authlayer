package scope

import "time"

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
