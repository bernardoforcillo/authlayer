// Package org is the ready-made "organization" instance of the generic scope
// engine. It fixes the container type to [Organization] and the member type to
// [Member], so callers get organization RBAC without writing a type parameter:
//
//	svc := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member]())
//	o, _ := svc.CreateOrganization(org.WithSubject(ctx, "alice"), "Acme", "acme")
//
// # What it adds
//
// Almost nothing, deliberately. org fixes the two type parameters, names the
// container resource "organization", supplies [Service.CreateOrganization] as a
// convenience over the generic CreateContainer, renames the context helper to
// [WithOrg], and re-exports the scope types, options, and errors under
// organization-flavoured names. Everything else — Can, Authorize, AddMember,
// CreateRole, the policy, the hooks — is the scope engine's, promoted through
// an embedded scope.Service.
//
// The re-exported errors are aliases, not copies: org.ErrOrgNotFound *is*
// scope.ErrContainerNotFound, so errors.Is matches either name.
//
// # When to use scope directly
//
// Reach past this package when you need a different boundary — teams, projects,
// workspaces — or extra fields on memberships. Embed scope.ContainerBase and
// scope.MemberBase in your own types and call scope.New. This package's source
// is short and is the worked example of doing that.
package org

import (
	"context"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/scope"
)

// Organization is the "organization" scope container. Embed-based: it carries
// the base id/owner/timestamps from scope.ContainerBase plus a name and a
// unique slug.
//
// The base fields are stamped by the engine on create — setting them yourself
// has no effect — while Name and Slug are yours. A duplicate slug surfaces as
// [ErrSlugTaken] from stores that enforce it (the drops store does; the
// in-memory one does not).
type Organization struct {
	scope.ContainerBase
	Name string `drop:"name"`
	Slug string `drop:"slug,unique"`
}

// Member is an organization membership: the base (organization, user, role,
// joined-at) fields and nothing more. Define your own member type over
// scope.MemberBase if you need extra columns such as an invited-by id.
type Member struct {
	scope.MemberBase
}

// Control resource names, actions, and default role keys, re-exported from
// scope so callers can write org.ResourceMember rather than importing both
// packages. ResourceOrganization is this instance's container resource name.
const (
	ResourceOrganization               = "organization"
	ResourceMember                     = scope.ResourceMember
	ResourceRole                       = scope.ResourceRole
	ActionCreate         access.Action = scope.ActionCreate
	ActionUpdate         access.Action = scope.ActionUpdate
	ActionDelete         access.Action = scope.ActionDelete
	RoleOwner                          = scope.RoleOwner
	RoleAdmin                          = scope.RoleAdmin
	RoleMember                         = scope.RoleMember
)

// Re-exported types so callers stay within the org package.
type (
	Store          = scope.Store[Organization, Member]
	RoleView       = scope.RoleView
	MemberStanding = scope.MemberStanding
	Option         = scope.Option
	Hook           = scope.Hook
	Event          = scope.Event
	Policy         = scope.Policy
)

// Re-exported sentinel errors (organization-flavoured names).
var (
	ErrOrgNotFound         = scope.ErrContainerNotFound
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
	ErrSlugTaken           = scope.ErrConflict
	ErrSubjectMissing      = scope.ErrSubjectMissing
	ErrOrgMissing          = scope.ErrScopeMissing
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

// WithOrg annotates ctx with the active organization id — the organization
// every subsequent check and mutation applies to. Pair it with [WithSubject]:
//
//	ctx = org.WithOrg(org.WithSubject(ctx, userID), orgID)
//
// It writes drops' tenant key, so the same context also scopes drops queries
// and drives any mounted [MembershipGuard]. Every operation except
// CreateOrganization requires it, returning [ErrOrgMissing] when unset.
func WithOrg(ctx context.Context, orgID string) context.Context { return scope.WithScope(ctx, orgID) }

// OrgFrom returns the active organization id and ok=false when unset.
func OrgFrom(ctx context.Context) (string, bool) { return scope.ScopeFrom(ctx) }

// NewAccess builds an access.Access for organizations: the control statements
// (organization/member/role) merged with appStatements, plus the seeded
// owner/admin/member default roles.
//
// appStatements is your application's own permission surface. Declare every
// resource you intend to check here — nothing can be granted that was not
// declared:
//
//	ac := org.NewAccess(map[string][]access.Action{
//	    "project": {"create", "read", "update", "delete"},
//	    "billing": {"read", "update"},
//	})
//
// Pass nil if the application has no resources beyond the built-in control
// ones. Call it once at startup and share the result across requests.
func NewAccess(appStatements map[string][]access.Action) *access.Access {
	return scope.NewAccess(ResourceOrganization, appStatements)
}

// Service is organization RBAC.
//
// It embeds the generic engine, so every scope.Service method is promoted and
// callable directly — Can, Authorize, HasPermission, AddMember,
// ChangeMemberRole, RemoveMember, LeaveContainer, ListMembers,
// TransferOwnership, CreateRole, UpdateRole, DeleteRole, ListRoles — and their
// documentation lives on scope.Service. Only the organization-flavoured
// conveniences are declared here.
//
// A Service is safe for concurrent use if its Store is, and caches nothing:
// build one at startup and share it.
type Service struct {
	*scope.Service[Organization, Member, *Organization, *Member]
}

// New wires an access engine, a Store and options into an organization Service.
//
//	svc := org.New(ac, memory.New[org.Organization, org.Member](),
//	    org.WithHooks(auditHook),
//	    org.WithPolicy(policy),
//	)
func New(ac *access.Access, store Store, opts ...Option) *Service {
	return &Service{scope.New[Organization, Member](ac, store, opts...)}
}

// CreateOrganization creates an organization with the given name and slug,
// owned by the ctx subject, who is also seeded as its first member with the
// owner role. Convenience over the generic CreateContainer.
//
// It needs only a subject on the context ([WithSubject]) — there is no
// organization to scope to yet — and runs no permission check, so gate it
// upstream if not every user may create one. A duplicate slug is [ErrSlugTaken].
//
//	ctx := org.WithSubject(r.Context(), currentUserID)
//	acme, err := svc.CreateOrganization(ctx, "Acme", "acme")
func (s *Service) CreateOrganization(ctx context.Context, name, slug string) (Organization, error) {
	return s.CreateContainer(ctx, Organization{Name: name, Slug: slug})
}
