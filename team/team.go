// Package team is a nested "team" instance of the generic scope engine: teams
// live inside organizations, using [scope.WithParent] to resolve standing from
// the org package's Service. Read org/org.go first — this package mirrors its
// shape — and scope/nested.go for what nesting adds.
//
//	orgSvc := org.New(org.NewAccess(team.ParentStatements()), memory.New[org.Organization, org.Member]())
//	teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc)
//
//	ctx := org.WithOrg(org.WithSubject(context.Background(), "alice"), acmeID)
//	platform, _ := teamSvc.CreateTeam(ctx, "Platform")
//
// # The parent-declaration requirement
//
// [ParentStatements] names what THIS package needs the organization's Access
// to declare — team:create — so that an organization role (not just the org
// owner, who always bypasses via ownership) can create a team. Merge it into
// the application's organization statements when building org.NewAccess, as
// the example above does. Forgetting it does not break anything visibly:
// [Service.CreateTeam] still works for the org owner (ownership always
// bypasses), so the omission surfaces only as everyone else being refused —
// exactly the silent failure [ParentStatements] exists to turn into a loud,
// checkable one. See [New] for where the requirement is enforced.
//
// # Two contexts, one key
//
// [WithTeam] and org.WithOrg both set the same underlying "active container"
// context key, so only one is active at a time. [Service.CreateTeam] reads the
// *organization* on the context — org.WithOrg — because that is the scope
// being created in. Every other team operation (Can, Authorize, AddMember, ...)
// reads the *team* on the context — [WithTeam]. Switch between them as your
// code moves from creating a team to operating within one.
//
// # What it adds
//
// As little as org does over scope: it fixes the two type parameters, names
// the container resource "team", wires [scope.WithParent] and
// [scope.WithContainerResource] into [New] so a caller cannot forget them,
// supplies [Service.CreateTeam] as a convenience over the generic
// CreateContainer, and re-exports the scope types, options, and errors under
// team-flavoured names — plus [ParentStatements], which org has no equivalent
// of because org is not nested in anything.
package team

import (
	"context"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/scope"
)

// Team is the "team" scope container: an organization-scoped boundary nested
// via scope.NestedBase, which adds the parent link on top of the base
// id/owner/timestamps that scope.ContainerBase carries. The base fields —
// including the parent link — are stamped by the engine on create; Name is
// yours.
type Team struct {
	scope.NestedBase
	Name string `drop:"name"`
}

// Member is a team membership: the base (team, user, role, joined-at) fields
// and nothing more. Define your own member type over scope.MemberBase if you
// need extra columns such as an invited-by id.
type Member struct {
	scope.MemberBase
}

// Control resource names, actions, and default role keys, re-exported from
// scope so callers can write team.ResourceMember rather than importing both
// packages. ResourceTeam is this instance's container resource name.
const (
	ResourceTeam                 = "team"
	ResourceMember               = scope.ResourceMember
	ResourceRole                 = scope.ResourceRole
	ActionCreate   access.Action = scope.ActionCreate
	ActionUpdate   access.Action = scope.ActionUpdate
	ActionDelete   access.Action = scope.ActionDelete
	RoleOwner                    = scope.RoleOwner
	RoleAdmin                    = scope.RoleAdmin
	RoleMember                   = scope.RoleMember
)

// Re-exported types so callers stay within the team package.
type (
	Store          = scope.Store[Team, Member]
	RoleView       = scope.RoleView
	MemberStanding = scope.MemberStanding
	Option         = scope.Option
	Hook           = scope.Hook
	Event          = scope.Event
	Policy         = scope.Policy
)

// Re-exported sentinel errors (team-flavoured names).
var (
	ErrTeamNotFound        = scope.ErrContainerNotFound
	ErrNotMember           = scope.ErrNotMember
	ErrForbidden           = scope.ErrForbidden
	ErrPrivilegeEscalation = scope.ErrPrivilegeEscalation
	ErrRoleNotFound        = scope.ErrRoleNotFound
	ErrRoleInUse           = scope.ErrRoleInUse
	ErrDefaultRole         = scope.ErrDefaultRole
	ErrLastOwner           = scope.ErrLastOwner
	ErrOwnerOnly           = scope.ErrOwnerOnly
	ErrAlreadyMember       = scope.ErrAlreadyMember
	ErrRoleKeyTaken        = scope.ErrRoleKeyTaken
	ErrSubjectMissing      = scope.ErrSubjectMissing
	ErrTeamMissing         = scope.ErrScopeMissing
	// ErrNotParentMember is returned by AddMember when Policy.MembersFromParent
	// (on by default) refuses a user with no standing in the parent
	// organization: you cannot be on a team without being in the organization
	// that owns it.
	ErrNotParentMember = scope.ErrNotParentMember
)

// Re-exported options and helpers.
var (
	WithHooks       = scope.WithHooks
	WithPolicy      = scope.WithPolicy
	WithClock       = scope.WithClock
	WithIDGenerator = scope.WithIDGenerator
	MembershipGuard = scope.MembershipGuard
	WithSubject     = scope.WithSubject
	SubjectFrom     = scope.SubjectFrom
)

// WithTeam annotates ctx with the active team id — the team every subsequent
// check and mutation applies to. Pair it with [WithSubject]:
//
//	ctx = team.WithTeam(team.WithSubject(ctx, userID), teamID)
//
// It writes the same context key org.WithOrg does (scope.WithScope, which is
// also drops' tenant key), so setting one clears the other as the active
// scope: use org.WithOrg while creating a team ([Service.CreateTeam] reads the
// organization on the context, not the team) and WithTeam for every other team
// operation. Every operation except CreateTeam requires it, returning
// [ErrTeamMissing] when unset.
func WithTeam(ctx context.Context, teamID string) context.Context {
	return scope.WithScope(ctx, teamID)
}

// TeamFrom returns the active team id and ok=false when unset.
func TeamFrom(ctx context.Context) (string, bool) { return scope.ScopeFrom(ctx) }

// NewAccess builds an access.Access for teams: the control statements
// (team/member/role) merged with appStatements, plus the seeded owner/admin/
// member default roles.
//
// appStatements is your application's own permission surface for team-scoped
// resources. Declare every resource you intend to check here — nothing can be
// granted that was not declared:
//
//	ac := team.NewAccess(map[string][]access.Action{
//	    "doc": {"read", "write"},
//	})
//
// Pass nil if the application has no team-scoped resources beyond the
// built-in control ones. Call it once at startup and share the result across
// requests. This is unrelated to [ParentStatements], which declares what the
// PARENT organization's Access must carry, not this one.
func NewAccess(appStatements map[string][]access.Action) *access.Access {
	return scope.NewAccess(ResourceTeam, appStatements)
}

// ParentStatements returns the statements the PARENT organization's Access
// must declare for team creation to work: team:create.
//
// Merge it into the application's own appStatements when building
// org.NewAccess, so an organization role — not just the owner, who always
// bypasses via ownership — can be granted the capability to create a team:
//
//	ac := org.NewAccess(team.ParentStatements())
//
// or, alongside the application's other organization resources:
//
//	appStatements := map[string][]access.Action{"project": {"create"}}
//	for res, actions := range team.ParentStatements() {
//	    appStatements[res] = actions
//	}
//	ac := org.NewAccess(appStatements)
//
// Skipping this merge is not a startup error — [Service.CreateTeam] still
// works for the organization owner, since ownership always bypasses the check
// — so the failure mode is silent rather than loud: every other organization
// member, admin included, gets ErrForbidden with nothing to say why. (An admin
// is not special-cased here: org.NewAccess grants the admin role every
// declared pair except organization:delete, so admin gains team:create only
// because this merge put it among the declared pairs in the first place —
// without the merge there is no team:create to inherit at all.) This function
// exists so that omission is a one-line diff to catch in review rather than a
// support ticket. See [New] for where the requirement is enforced against the
// organization's Access.
func ParentStatements() map[string][]access.Action {
	return map[string][]access.Action{ResourceTeam: {ActionCreate}}
}

// Service is team RBAC, nested inside an organization.
//
// It embeds the generic engine, so every scope.Service method is promoted and
// callable directly — Can, Authorize, HasPermission, Standing, ContainersWith,
// PermissionGuard, AddMember, ChangeMemberRole, RemoveMember, LeaveContainer,
// ListMembers, TransferOwnership, CreateRole, UpdateRole, DeleteRole,
// ListRoles — and their documentation lives on scope.Service. Only the
// team-flavoured convenience is declared here.
//
// A Service is safe for concurrent use if its Store is, and caches nothing:
// build one at startup and share it.
type Service struct {
	*scope.Service[Team, Member, *Team, *Member]
}

// New wires an access engine, a Store, the parent organization Service and
// options into a team Service.
//
// It configures nesting itself — [scope.WithParent](parent,
// [scope.InheritElevation]) and [scope.WithContainerResource]("team") — so a
// caller cannot construct a team Service that forgets either half, which
// [scope.WithParent] and [scope.WithContainerResource] both document as
// otherwise failing closed but silently. opts are applied after, in
// declaration order, so they may override the projection (pass your own
// scope.WithParent to install a different [scope.Inheritance]) or set anything
// else a plain [scope.New] caller could — WithPolicy, WithHooks, WithClock,
// WithIDGenerator.
//
// The default projection is [scope.InheritElevation]: whichever actor is
// truly elevated in the organization — under [org.NewAccess]'s default roles,
// that is the owner alone, via ownership — administers every team in it
// without joining one, and nothing else about their organization standing
// crosses over. That is the right default for a library: it costs the
// application nothing to wire, and it never reaches further than ownership
// already does.
//
// It deliberately does NOT extend to the built-in admin role. org.RoleAdmin
// is kept short of full permission (it excludes organization:delete) so the
// escalation guard still applies to admins within the organization itself,
// and InheritElevation reads that same "elevated" flag — so a plain admin
// gets nothing extra in a team by default either. Making an organization's
// admins also administer every team is an explicit choice: declare a
// capability on the organization's own surface (team:update, say) and pass
// your own scope.WithParent(parent, scope.InheritWhen("team", ...)) in opts
// to install it — that is what overriding the projection looks like.
//
// parent must be the organization Service (or anything satisfying
// [scope.ParentScope]) whose Access declares [ParentStatements] — merge it
// into org.NewAccess's appStatements, or only the organization owner will ever
// be able to create a team. See the package doc for the full requirement.
//
//	svc := team.New(ac, memory.New[team.Team, team.Member](), orgSvc)
func New(ac *access.Access, store Store, parent scope.ParentScope, opts ...scope.Option) *Service {
	base := []scope.Option{
		scope.WithParent(parent, scope.InheritElevation),
		scope.WithContainerResource(ResourceTeam),
	}
	return &Service{scope.New[Team, Member](ac, store, append(base, opts...)...)}
}

// CreateTeam creates a team with the given name inside the organization named
// on the context ([org.WithOrg]), owned by the ctx subject, who is also seeded
// as its first member with the owner role. Convenience over the generic
// CreateContainer.
//
// The subject needs team:create in the organization — declared there via
// [ParentStatements], which is what lets an admin (or any custom role holding
// it) create a team — or elevated organization standing, which only the owner
// has by default (ownership always bypasses the check outright). A subject
// with no organization standing gets ErrNotMember; one with standing but not
// that grant gets ErrForbidden. A subject with no organization on the context
// gets ErrTeamMissing, since that context key is shared with [WithTeam] — see
// the package doc.
//
//	ctx := org.WithOrg(org.WithSubject(r.Context(), currentUserID), orgID)
//	platform, err := svc.CreateTeam(ctx, "Platform")
func (s *Service) CreateTeam(ctx context.Context, name string) (Team, error) {
	return s.CreateContainer(ctx, Team{Name: name})
}
