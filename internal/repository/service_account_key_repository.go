package repository

import (
	"context"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type serviceAccountKeyRepository struct {
	db *gorm.DB
}

func NewServiceAccountKeyRepository(db *gorm.DB) ServiceAccountKeyRepository {
	return &serviceAccountKeyRepository{db: db}
}

func (r *serviceAccountKeyRepository) Create(ctx context.Context, key *model.ServiceAccountKey) error {
	return r.db.WithContext(ctx).Create(key).Error
}

func (r *serviceAccountKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*model.ServiceAccountKey, error) {
	var key model.ServiceAccountKey
	err := r.db.WithContext(ctx).
		Where("key_hash = ? AND revoked = false", keyHash).
		Preload("ServiceAccount").
		First(&key).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *serviceAccountKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).
		Model(&model.ServiceAccountKey{}).
		Where("id = ?", id).
		Update("revoked", true).Error
}

func (r *serviceAccountKeyRepository) ListByServiceAccountID(ctx context.Context, saID uuid.UUID, pagination Pagination) ([]model.ServiceAccountKey, int64, error) {
	var keys []model.ServiceAccountKey
	var total int64

	query := r.db.WithContext(ctx).Model(&model.ServiceAccountKey{}).Where("service_account_id = ?", saID)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageSize := pagination.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	if err := query.Order("created_at DESC").Limit(pageSize).Find(&keys).Error; err != nil {
		return nil, 0, err
	}

	return keys, total, nil
}

func (r *serviceAccountKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&model.ServiceAccountKey{}).
		Where("id = ?", id).
		Update("last_used_at", now).Error
}
