package scope

import (
	"time"

	"github.com/bernardoforcillo/authlayer/access"
)

// Custom roles are the runtime half of authlayer's hybrid role model: the
// owner/admin/member defaults are fixed in code and identical in every
// container, while each container may define extra roles of its own. A custom
// role belongs to exactly one container and is invisible to every other, so two
// tenants may both define an "editor" that means different things.

// RoleRecord is the persistence shape of a custom, per-container role.
//
// Its permissions are stored as [access.Permission.Encode] bytes — newline
// separated "resource:action" names — so a Store needs no knowledge of the
// access engine and never interprets the blob: it writes and returns opaque
// bytes, and the engine decodes them against the current statements.
//
// Roles are deliberately not generic over a caller-supplied type, unlike
// containers and members: custom fields on those two cover the common need, and
// keeping the role shape fixed lets every Store share one table definition.
type RoleRecord struct {
	// ID is the record's surrogate key, stamped by the Service id generator.
	ID string `drop:"id"`
	// ContainerID scopes the role to one container.
	ContainerID string `drop:"container_id"`
	// Key is the identifier stored on memberships; unique per container.
	Key string `drop:"key"`
	// Name is a human-facing label, for display only.
	Name string `drop:"name"`
	// Permissions is the encoded grant set. Opaque to the Store.
	Permissions []byte `drop:"permissions"`
	// CreatedAt is stamped by the Service clock.
	CreatedAt time.Time `drop:"created_at"`
}

// RoleView is a resolved role — default or custom — for listing and inspection.
//
// Unlike [RoleRecord] it carries a decoded [access.Permission] rather than
// bytes, so a caller can ask what the role actually allows (Allows, IsFull,
// SubsetOf) without touching the encoding. It is returned by
// [Service.ListRoles], [Service.CreateRole] and [Service.UpdateRole].
type RoleView struct {
	// Key is the role key stored on memberships.
	Key string
	// Name is the display label. For default roles it is the key itself, since
	// code-defined roles carry no separate label.
	Name string
	// Permissions is the resolved grant set.
	Permissions access.Permission
	// IsDefault distinguishes a code-defined role from a container's own.
	// Default roles cannot be updated or deleted at runtime.
	IsDefault bool
}
