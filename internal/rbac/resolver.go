package rbac

import (
	"context"

	"github.com/bernardoforcillo/authlayer/internal/model"
	"github.com/bernardoforcillo/authlayer/internal/repository"

	"github.com/google/uuid"
)

const defaultMaxHierarchyDepth = 10

// Resolver computes effective permissions for a user by traversing the role hierarchy.
type Resolver struct {
	roleRepo      repository.RoleRepository
	rolePermRepo  repository.RolePermissionRepository
	orgMemberRepo repository.OrganizationMemberRepository
	teamMemberRepo repository.TeamMemberRepository
	saRoleRepo    repository.ServiceAccountRoleRepository
	cache         *Cache
	maxDepth      int
}

// NewResolver creates a new permission resolver.
func NewResolver(
	roleRepo repository.RoleRepository,
	rolePermRepo repository.RolePermissionRepository,
	orgMemberRepo repository.OrganizationMemberRepository,
	teamMemberRepo repository.TeamMemberRepository,
	saRoleRepo repository.ServiceAccountRoleRepository,
	cache *Cache,
) *Resolver {
	return &Resolver{
		roleRepo:       roleRepo,
		rolePermRepo:   rolePermRepo,
		orgMemberRepo:  orgMemberRepo,
		teamMemberRepo: teamMemberRepo,
		saRoleRepo:     saRoleRepo,
		cache:          cache,
		maxDepth:       defaultMaxHierarchyDepth,
	}
}

// ResolveUserPermissions returns all effective permissions for a user in the given org context.
func (r *Resolver) ResolveUserPermissions(ctx context.Context, userID uuid.UUID, orgID *uuid.UUID) ([]model.Permission, error) {
	key := cacheKey(userID, orgID)
	if cached, ok := r.cache.Get(key); ok {
		return r.permissionNamestoModels(cached), nil
	}

	roleIDs, err := r.collectRoleIDs(ctx, userID, orgID)
	if err != nil {
		return nil, err
	}

	// Expand role hierarchy for each role
	allRoleIDs := make(map[uuid.UUID]bool)
	for _, roleID := range roleIDs {
		ancestors, err := r.roleRepo.GetAncestors(ctx, roleID, r.maxDepth)
		if err != nil {
			return nil, err
		}
		for _, ancestor := range ancestors {
			allRoleIDs[ancestor.ID] = true
		}
	}

	expandedIDs := make([]uuid.UUID, 0, len(allRoleIDs))
	for id := range allRoleIDs {
		expandedIDs = append(expandedIDs, id)
	}

	perms, err := r.rolePermRepo.GetPermissionsByRoleIDs(ctx, expandedIDs)
	if err != nil {
		return nil, err
	}

	// Cache the result
	permNames := make([]string, len(perms))
	for i, p := range perms {
		permNames[i] = p.Name
	}
	r.cache.Set(key, permNames)

	return perms, nil
}

// ResolveServiceAccountPermissions returns all effective permissions for a service account.
func (r *Resolver) ResolveServiceAccountPermissions(ctx context.Context, saID uuid.UUID, orgID *uuid.UUID) ([]model.Permission, error) {
	saRoles, err := r.saRoleRepo.ListByServiceAccountID(ctx, saID)
	if err != nil {
		return nil, err
	}

	allRoleIDs := make(map[uuid.UUID]bool)
	for _, sar := range saRoles {
		if orgID != nil && sar.OrgID != *orgID {
			continue
		}
		ancestors, err := r.roleRepo.GetAncestors(ctx, sar.RoleID, r.maxDepth)
		if err != nil {
			return nil, err
		}
		for _, ancestor := range ancestors {
			allRoleIDs[ancestor.ID] = true
		}
	}

	expandedIDs := make([]uuid.UUID, 0, len(allRoleIDs))
	for id := range allRoleIDs {
		expandedIDs = append(expandedIDs, id)
	}

	return r.rolePermRepo.GetPermissionsByRoleIDs(ctx, expandedIDs)
}

func (r *Resolver) collectRoleIDs(ctx context.Context, userID uuid.UUID, orgID *uuid.UUID) ([]uuid.UUID, error) {
	var roleIDs []uuid.UUID

	if orgID != nil {
		membership, err := r.orgMemberRepo.GetMembership(ctx, *orgID, userID)
		if err != nil {
			return nil, err
		}
		roleIDs = append(roleIDs, membership.RoleID)
	}

	return roleIDs, nil
}

func (r *Resolver) permissionNamestoModels(names []string) []model.Permission {
	perms := make([]model.Permission, len(names))
	for i, name := range names {
		perms[i] = model.Permission{Name: name}
	}
	return perms
}
