package repository

import (
	"context"
	"time"

	"authz-go/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type apiKeyRepository struct {
	db *gorm.DB
}

func NewAPIKeyRepository(db *gorm.DB) APIKeyRepository {
	return &apiKeyRepository{db: db}
}

func (r *apiKeyRepository) Create(ctx context.Context, apiKey *model.APIKey) error {
	return r.db.WithContext(ctx).Create(apiKey).Error
}

func (r *apiKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*model.APIKey, error) {
	var key model.APIKey
	err := r.db.WithContext(ctx).
		Where("key_hash = ? AND revoked = false", keyHash).
		Preload("User").
		First(&key).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *apiKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.APIKey, error) {
	var key model.APIKey
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&key).Error; err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *apiKeyRepository) ListByUserID(ctx context.Context, userID uuid.UUID, pagination Pagination) ([]model.APIKey, int64, error) {
	var keys []model.APIKey
	var total int64

	query := r.db.WithContext(ctx).Model(&model.APIKey{}).Where("user_id = ?", userID)

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

func (r *apiKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).
		Model(&model.APIKey{}).
		Where("id = ?", id).
		Update("revoked", true).Error
}

func (r *apiKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&model.APIKey{}).
		Where("id = ?", id).
		Update("last_used_at", now).Error
}
