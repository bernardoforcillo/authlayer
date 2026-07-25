package scope

import (
	"slices"

	"github.com/bernardoforcillo/authlayer/access"
)

// Fixed control resources the engine checks on its own operations: membership
// changes require "member" grants and custom-role changes require "role"
// grants. The container's own resource name is not fixed — it is the
// containerResource argument to [ControlStatements] and [NewAccess], so an
// organization scope calls it "organization" and a team scope calls it "team".
const (
	ResourceMember = "member"
	ResourceRole   = "role"
)

// Actions used by the control statements. Applications are free to declare
// other verbs on their own resources; these three are the only ones the engine
// itself checks.
const (
	ActionCreate access.Action = "create"
	ActionUpdate access.Action = "update"
	ActionDelete access.Action = "delete"
)

// Default role keys seeded by [NewAccess]. These keys are reserved: a custom
// role may not reuse one (ErrRoleKeyTaken), and none of them can be updated or
// deleted at runtime (ErrDefaultRole).
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// ControlStatements returns the permission surface the engine enforces on its
// own operations for a scope whose container resource is containerResource:
//
//	containerResource: update, delete
//	member:            create, update, delete
//	role:              create, update, delete
//
// It is exported so an application can inspect the reserved surface — for
// instance to render a role editor — and so a caller assembling statements by
// hand can merge it in. [NewAccess] already merges it for you.
//
// Note that containerResource:update and containerResource:delete are declared
// but not enforced by the engine, which owns no update/delete operation on the
// container itself; they exist so an application's own "rename the org" and
// "delete the org" handlers have a permission to check with Authorize, and so
// the admin role can be defined as "everything except deleting the container".
func ControlStatements(containerResource string) map[string][]access.Action {
	return map[string][]access.Action{
		containerResource: {ActionUpdate, ActionDelete},
		ResourceMember:    {ActionCreate, ActionUpdate, ActionDelete},
		ResourceRole:      {ActionCreate, ActionUpdate, ActionDelete},
	}
}

// NewAccess builds an access.Access for a scope: the control statements for
// containerResource merged with appStatements, plus three seeded default roles.
//
// The defaults are derived from the merged surface, so they grow automatically
// with the application's own resources:
//
//   - owner  — every declared pair; IsFull, so it bypasses fine-grained checks.
//   - admin  — every declared pair except containerResource:delete. An admin
//     can therefore manage members, roles, and all app resources, but cannot
//     delete the container itself. Because the set is not full, an admin is
//     still subject to the privilege-escalation guard.
//   - member — no grants at all: standing only. A plain member can read the
//     member and role lists (any member may list) but can change nothing.
//     Grant capabilities beyond that with a custom role.
//
// appStatements may be nil when the application has no resources of its own.
// Duplicate actions between the two maps are merged, not duplicated. Passing an
// app statement for containerResource, "member", or "role" adds actions to the
// reserved resources rather than replacing them.
//
// Call this once at startup and share the result: it registers the default
// roles, and an *access.Access is only safe for concurrent use after
// registration is complete.
func NewAccess(containerResource string, appStatements map[string][]access.Action) *access.Access {
	merged := mergeStatements(ControlStatements(containerResource), appStatements)
	ac := access.New(access.NewStatements(merged))

	ac.NewRole(RoleOwner, allGrants(merged))

	adminGrants := allGrants(merged)
	adminGrants[containerResource] = without(adminGrants[containerResource], ActionDelete)
	ac.NewRole(RoleAdmin, adminGrants)

	ac.NewRole(RoleMember, map[string][]access.Action{})
	return ac
}

func mergeStatements(a, b map[string][]access.Action) map[string][]access.Action {
	out := make(map[string][]access.Action, len(a)+len(b))
	for _, src := range []map[string][]access.Action{a, b} {
		for resource, actions := range src {
			for _, act := range actions {
				if !slices.Contains(out[resource], act) {
					out[resource] = append(out[resource], act)
				}
			}
		}
	}
	return out
}

func allGrants(statements map[string][]access.Action) map[string][]access.Action {
	out := make(map[string][]access.Action, len(statements))
	for resource, actions := range statements {
		out[resource] = slices.Clone(actions)
	}
	return out
}

func without(actions []access.Action, act access.Action) []access.Action {
	return slices.DeleteFunc(slices.Clone(actions), func(a access.Action) bool { return a == act })
}
