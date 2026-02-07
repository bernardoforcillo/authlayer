package repository

import (
	"context"

	"github.com/bernardoforcillo/authlayer/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type rolePermissionRepository struct {
	db *gorm.DB
}

func NewRolePermissionRepository(db *gorm.DB) RolePermissionRepository {
	return &rolePermissionRepository{db: db}
}

func (r *rolePermissionRepository) Assign(ctx context.Context, roleID, permissionID uuid.UUID) error {
	rp := model.RolePermission{
		RoleID:       roleID,
		PermissionID: permissionID,
	}
	return r.db.WithContext(ctx).Create(&rp).Error
}

func (r *rolePermissionRepository) Revoke(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&model.RolePermission{}).Error
}

func (r *rolePermissionRepository) GetPermissionsByRoleIDs(ctx context.Context, roleIDs []uuid.UUID) ([]model.Permission, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}

	var perms []model.Permission
	err := r.db.WithContext(ctx).
		Distinct().
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id IN ?", roleIDs).
		Find(&perms).Error
	if err != nil {
		return nil, err
	}
	return perms, nil
}
