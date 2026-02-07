package repository

import (
	"context"

	"github.com/bernardoforcillo/authlayer/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type invitationRepository struct {
	db *gorm.DB
}

func NewInvitationRepository(db *gorm.DB) InvitationRepository {
	return &invitationRepository{db: db}
}

func (r *invitationRepository) Create(ctx context.Context, invitation *model.Invitation) error {
	return r.db.WithContext(ctx).Create(invitation).Error
}

func (r *invitationRepository) GetByToken(ctx context.Context, token string) (*model.Invitation, error) {
	var inv model.Invitation
	err := r.db.WithContext(ctx).
		Where("token = ?", token).
		Preload("Organization").
		Preload("Role").
		First(&inv).Error
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

func (r *invitationRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status model.InvitationStatus) error {
	return r.db.WithContext(ctx).
		Model(&model.Invitation{}).
		Where("id = ?", id).
		Update("status", status).Error
}

func (r *invitationRepository) ListByOrgID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]model.Invitation, int64, error) {
	var invitations []model.Invitation
	var total int64

	query := r.db.WithContext(ctx).Model(&model.Invitation{}).Where("org_id = ?", orgID)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageSize := pagination.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	err := query.
		Preload("Role").
		Preload("Inviter").
		Order("created_at DESC").
		Limit(pageSize).
		Find(&invitations).Error
	if err != nil {
		return nil, 0, err
	}

	return invitations, total, nil
}
