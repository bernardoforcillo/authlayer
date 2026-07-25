// Package scope is the generic engine behind authlayer's RBAC. A scope is an
// authorization boundary (an organization, a team, a project) with an owner and
// members; each member holds exactly one role. It is generic over the container
// type C and the member type M: embed ContainerBase / MemberBase in your own
// structs to add custom fields while the engine reads and populates the base
// identity fields. The org package is the ready-made "organization" instance;
// most callers use that and never write a type parameter.
package scope

import "time"

// ContainerBase carries the identity and audit fields every scope container
// needs. Embed it in your container type and add any fields you like; drops
// persists the whole struct (it flattens embedded structs).
type ContainerBase struct {
	ID        string    `drop:"id"`
	OwnerID   string    `drop:"owner_id"`
	CreatedAt time.Time `drop:"created_at"`
	UpdatedAt time.Time `drop:"updated_at"`
}

// ContainerID returns the container's id.
func (b ContainerBase) ContainerID() string { return b.ID }

// ContainerOwner returns the owning user's id.
func (b ContainerBase) ContainerOwner() string { return b.OwnerID }

// SetID sets the container id (used by the engine and stores; embed the base
// to inherit it).
func (b *ContainerBase) SetID(id string) { b.ID = id }

// SetOwner sets the owning user's id.
func (b *ContainerBase) SetOwner(ownerID string) { b.OwnerID = ownerID }

// SetTimes sets the created/updated timestamps.
func (b *ContainerBase) SetTimes(c, u time.Time) { b.CreatedAt, b.UpdatedAt = c, u }

// MemberBase carries the membership key fields. Embed it in your member type.
type MemberBase struct {
	ContainerID string    `drop:"container_id"`
	UserID      string    `drop:"user_id"`
	RoleKey     string    `drop:"role_key"`
	JoinedAt    time.Time `drop:"joined_at"`
}

// MemberContainer returns the id of the container the member belongs to.
func (b MemberBase) MemberContainer() string { return b.ContainerID }

// MemberUser returns the member's user id.
func (b MemberBase) MemberUser() string { return b.UserID }

// MemberRole returns the member's role key.
func (b MemberBase) MemberRole() string { return b.RoleKey }

// SetKeys sets the membership key fields (container, user, role).
func (b *MemberBase) SetKeys(container, user, role string) {
	b.ContainerID, b.UserID, b.RoleKey = container, user, role
}

// SetJoined sets the joined-at timestamp.
func (b *MemberBase) SetJoined(t time.Time) { b.JoinedAt = t }
