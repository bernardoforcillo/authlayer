package repository

import (
	"context"

	"authz-go/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type serviceAccountRoleRepository struct {
	db *gorm.DB
}

func NewServiceAccountRoleRepository(db *gorm.DB) ServiceAccountRoleRepository {
	return &serviceAccountRoleRepository{db: db}
}

func (r *serviceAccountRoleRepository) Assign(ctx context.Context, sar *model.ServiceAccountRole) error {
	return r.db.WithContext(ctx).Create(sar).Error
}

func (r *serviceAccountRoleRepository) Revoke(ctx context.Context, saID, roleID, orgID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("service_account_id = ? AND role_id = ? AND org_id = ?", saID, roleID, orgID).
		Delete(&model.ServiceAccountRole{}).Error
}

func (r *serviceAccountRoleRepository) ListByServiceAccountID(ctx context.Context, saID uuid.UUID) ([]model.ServiceAccountRole, error) {
	var roles []model.ServiceAccountRole
	err := r.db.WithContext(ctx).
		Where("service_account_id = ?", saID).
		Preload("Role").
		Preload("Role.Permissions").
		Find(&roles).Error
	if err != nil {
		return nil, err
	}
	return roles, nil
}
