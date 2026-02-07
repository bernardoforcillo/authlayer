package repository

import (
	"context"
	"time"

	"authz-go/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type sessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) SessionRepository {
	return &sessionRepository{db: db}
}

func (r *sessionRepository) Create(ctx context.Context, session *model.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *sessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	var session model.Session
	err := r.db.WithContext(ctx).
		Where("token_hash = ?", tokenHash).
		Preload("User").
		First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *sessionRepository) RevokeByTokenHash(ctx context.Context, tokenHash string) error {
	return r.db.WithContext(ctx).
		Model(&model.Session{}).
		Where("token_hash = ?", tokenHash).
		Update("revoked", true).Error
}

func (r *sessionRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Model(&model.Session{}).
		Where("user_id = ? AND revoked = false", userID).
		Update("revoked", true).Error
}

func (r *sessionRepository) RevokeByFamily(ctx context.Context, family string) error {
	return r.db.WithContext(ctx).
		Model(&model.Session{}).
		Where("token_family = ? AND revoked = false", family).
		Update("revoked", true).Error
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&model.Session{}).Error
}
