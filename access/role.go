package access

// Role is a named bundle of permissions.
//
// Two kinds of role exist and they differ only in where the grants come from:
//
//   - Default roles (owner, admin, member) are defined in code via
//     [Access.NewRole], registered process-wide, and identical in every
//     container.
//   - Custom roles are defined per container at runtime, validated with
//     [Access.Permission], persisted as encoded grants, and rebuilt on demand
//     with [Access.Decode]. They are not registered in the Access registry.
//
// Exactly one role is held per membership: authlayer deliberately does not
// support stacking roles, so a member's effective permissions are always
// exactly one role's Permissions and are trivially auditable.
type Role struct {
	// Key is the stable identifier stored on a membership (e.g. "admin",
	// "editor"). It is what [Access.Role] and the store look up.
	Key string
	// Permissions is the resolved grant set this role confers.
	Permissions Permission
}
