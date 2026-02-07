package repository

import (
	"context"

	"github.com/bernardoforcillo/authlayer/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type roleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) RoleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) Create(ctx context.Context, role *model.Role) error {
	return r.db.WithContext(ctx).Create(role).Error
}

func (r *roleRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Role, error) {
	var role model.Role
	err := r.db.WithContext(ctx).
		Where("id = ?", id).
		Preload("Permissions").
		First(&role).Error
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *roleRepository) GetByNameAndOrg(ctx context.Context, name string, orgID *uuid.UUID) (*model.Role, error) {
	var role model.Role
	query := r.db.WithContext(ctx).Where("name = ?", name)
	if orgID != nil {
		query = query.Where("org_id = ?", *orgID)
	} else {
		query = query.Where("org_id IS NULL")
	}
	if err := query.First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *roleRepository) Update(ctx context.Context, role *model.Role) error {
	return r.db.WithContext(ctx).Save(role).Error
}

func (r *roleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Role{}).Error
}

func (r *roleRepository) ListByOrgID(ctx context.Context, orgID *uuid.UUID, pagination Pagination) ([]model.Role, int64, error) {
	var roles []model.Role
	var total int64

	query := r.db.WithContext(ctx).Model(&model.Role{})
	if orgID != nil {
		// Return both org-specific and system-level roles
		query = query.Where("org_id = ? OR org_id IS NULL", *orgID)
	} else {
		query = query.Where("org_id IS NULL")
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageSize := pagination.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	err := query.
		Preload("Permissions").
		Order("created_at ASC").
		Limit(pageSize).
		Find(&roles).Error
	if err != nil {
		return nil, 0, err
	}

	return roles, total, nil
}

// GetAncestors traverses the role hierarchy upward using a recursive CTE.
// Returns all ancestor roles (including the starting role) up to maxDepth levels.
func (r *roleRepository) GetAncestors(ctx context.Context, roleID uuid.UUID, maxDepth int) ([]model.Role, error) {
	if maxDepth <= 0 {
		maxDepth = 10
	}

	var roles []model.Role
	err := r.db.WithContext(ctx).Raw(`
		WITH RECURSIVE role_hierarchy AS (
			SELECT id, name, description, org_id, parent_role_id, created_at, updated_at, deleted_at, 1 AS depth
			FROM roles
			WHERE id = ? AND deleted_at IS NULL
			UNION ALL
			SELECT r.id, r.name, r.description, r.org_id, r.parent_role_id, r.created_at, r.updated_at, r.deleted_at, rh.depth + 1
			FROM roles r
			INNER JOIN role_hierarchy rh ON r.id = rh.parent_role_id
			WHERE rh.depth < ? AND r.deleted_at IS NULL
		)
		SELECT * FROM role_hierarchy
	`, roleID, maxDepth).Scan(&roles).Error
	if err != nil {
		return nil, err
	}

	return roles, nil
}
