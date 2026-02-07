package repository

import (
	"context"

	"github.com/bernardoforcillo/authlayer/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type permissionRepository struct {
	db *gorm.DB
}

func NewPermissionRepository(db *gorm.DB) PermissionRepository {
	return &permissionRepository{db: db}
}

func (r *permissionRepository) Create(ctx context.Context, perm *model.Permission) error {
	return r.db.WithContext(ctx).Create(perm).Error
}

func (r *permissionRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Permission, error) {
	var perm model.Permission
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&perm).Error; err != nil {
		return nil, err
	}
	return &perm, nil
}

func (r *permissionRepository) GetByName(ctx context.Context, name string) (*model.Permission, error) {
	var perm model.Permission
	if err := r.db.WithContext(ctx).Where("name = ?", name).First(&perm).Error; err != nil {
		return nil, err
	}
	return &perm, nil
}

func (r *permissionRepository) List(ctx context.Context, pagination Pagination) ([]model.Permission, int64, error) {
	var perms []model.Permission
	var total int64

	query := r.db.WithContext(ctx).Model(&model.Permission{})

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageSize := pagination.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	if err := query.Order("name ASC").Limit(pageSize).Find(&perms).Error; err != nil {
		return nil, 0, err
	}

	return perms, total, nil
}

func (r *permissionRepository) GetByRoleID(ctx context.Context, roleID uuid.UUID) ([]model.Permission, error) {
	var perms []model.Permission
	err := r.db.WithContext(ctx).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ?", roleID).
		Find(&perms).Error
	if err != nil {
		return nil, err
	}
	return perms, nil
}
