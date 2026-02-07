package repository

import (
	"context"

	"authz-go/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type teamRepository struct {
	db *gorm.DB
}

func NewTeamRepository(db *gorm.DB) TeamRepository {
	return &teamRepository{db: db}
}

func (r *teamRepository) Create(ctx context.Context, team *model.Team) error {
	return r.db.WithContext(ctx).Create(team).Error
}

func (r *teamRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Team, error) {
	var team model.Team
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&team).Error; err != nil {
		return nil, err
	}
	return &team, nil
}

func (r *teamRepository) Update(ctx context.Context, team *model.Team) error {
	return r.db.WithContext(ctx).Save(team).Error
}

func (r *teamRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Team{}).Error
}

func (r *teamRepository) ListByOrgID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]model.Team, int64, error) {
	var teams []model.Team
	var total int64

	query := r.db.WithContext(ctx).Model(&model.Team{}).Where("org_id = ?", orgID)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageSize := pagination.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	if err := query.Order("created_at DESC").Limit(pageSize).Find(&teams).Error; err != nil {
		return nil, 0, err
	}

	return teams, total, nil
}
