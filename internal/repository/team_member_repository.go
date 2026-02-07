package repository

import (
	"context"

	"authz-go/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type teamMemberRepository struct {
	db *gorm.DB
}

func NewTeamMemberRepository(db *gorm.DB) TeamMemberRepository {
	return &teamMemberRepository{db: db}
}

func (r *teamMemberRepository) Add(ctx context.Context, member *model.TeamMember) error {
	return r.db.WithContext(ctx).Create(member).Error
}

func (r *teamMemberRepository) Remove(ctx context.Context, teamID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("team_id = ? AND user_id = ?", teamID, userID).
		Delete(&model.TeamMember{}).Error
}

func (r *teamMemberRepository) ListByTeamID(ctx context.Context, teamID uuid.UUID, pagination Pagination) ([]model.TeamMember, int64, error) {
	var members []model.TeamMember
	var total int64

	query := r.db.WithContext(ctx).Model(&model.TeamMember{}).Where("team_id = ?", teamID)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageSize := pagination.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	err := query.
		Preload("User").
		Preload("Role").
		Order("created_at DESC").
		Limit(pageSize).
		Find(&members).Error
	if err != nil {
		return nil, 0, err
	}

	return members, total, nil
}
