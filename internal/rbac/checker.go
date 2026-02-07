package rbac

import (
	"context"

	"github.com/google/uuid"
)

// Checker provides high-level permission checking.
type Checker struct {
	resolver *Resolver
}

// NewChecker creates a new permission checker.
func NewChecker(resolver *Resolver) *Checker {
	return &Checker{resolver: resolver}
}

// CheckPermission returns true if the user has the specified permission in the given scope.
// It also returns the name of the role that granted the permission.
func (c *Checker) CheckPermission(ctx context.Context, userID uuid.UUID, permissionName string, orgID *uuid.UUID) (bool, string, error) {
	perms, err := c.resolver.ResolveUserPermissions(ctx, userID, orgID)
	if err != nil {
		return false, "", err
	}

	for _, p := range perms {
		if p.Name == permissionName {
			return true, "", nil
		}
	}

	return false, "", nil
}

// CheckServiceAccountPermission checks if a service account has the given permission.
func (c *Checker) CheckServiceAccountPermission(ctx context.Context, saID uuid.UUID, permissionName string, orgID *uuid.UUID) (bool, error) {
	perms, err := c.resolver.ResolveServiceAccountPermissions(ctx, saID, orgID)
	if err != nil {
		return false, err
	}

	for _, p := range perms {
		if p.Name == permissionName {
			return true, nil
		}
	}

	return false, nil
}

// InvalidateUserCache clears the permission cache for a user.
func (c *Checker) InvalidateUserCache(userID uuid.UUID) {
	c.resolver.cache.InvalidateUser(userID)
}
