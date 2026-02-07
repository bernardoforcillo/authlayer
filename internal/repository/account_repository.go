package repository

import (
	"context"

	"github.com/bernardoforcillo/authlayer/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type accountRepository struct {
	db *gorm.DB
}

func NewAccountRepository(db *gorm.DB) AccountRepository {
	return &accountRepository{db: db}
}

func (r *accountRepository) Create(ctx context.Context, account *model.Account) error {
	return r.db.WithContext(ctx).Create(account).Error
}

func (r *accountRepository) GetByProviderAndID(ctx context.Context, provider, providerAccountID string) (*model.Account, error) {
	var account model.Account
	err := r.db.WithContext(ctx).
		Where("provider = ? AND provider_account_id = ?", provider, providerAccountID).
		Preload("User").
		First(&account).Error
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *accountRepository) GetByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) (*model.Account, error) {
	var account model.Account
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, provider).
		First(&account).Error
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *accountRepository) DeleteByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) error {
	return r.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, provider).
		Delete(&model.Account{}).Error
}
