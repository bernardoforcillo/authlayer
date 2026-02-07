package repository

import (
	"context"

	"authz-go/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type serviceAccountRepository struct {
	db *gorm.DB
}

func NewServiceAccountRepository(db *gorm.DB) ServiceAccountRepository {
	return &serviceAccountRepository{db: db}
}

func (r *serviceAccountRepository) Create(ctx context.Context, sa *model.ServiceAccount) error {
	return r.db.WithContext(ctx).Create(sa).Error
}

func (r *serviceAccountRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.ServiceAccount, error) {
	var sa model.ServiceAccount
	err := r.db.WithContext(ctx).
		Where("id = ?", id).
		Preload("Roles").
		Preload("Roles.Role").
		First(&sa).Error
	if err != nil {
		return nil, err
	}
	return &sa, nil
}

func (r *serviceAccountRepository) Update(ctx context.Context, sa *model.ServiceAccount) error {
	return r.db.WithContext(ctx).Save(sa).Error
}

func (r *serviceAccountRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.ServiceAccount{}).Error
}

func (r *serviceAccountRepository) ListByOrgID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]model.ServiceAccount, int64, error) {
	var accounts []model.ServiceAccount
	var total int64

	query := r.db.WithContext(ctx).Model(&model.ServiceAccount{}).Where("org_id = ?", orgID)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageSize := pagination.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	err := query.
		Preload("Roles").
		Preload("Roles.Role").
		Order("created_at DESC").
		Limit(pageSize).
		Find(&accounts).Error
	if err != nil {
		return nil, 0, err
	}

	return accounts, total, nil
}
