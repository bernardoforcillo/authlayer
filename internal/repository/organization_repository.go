package repository

import (
	"context"

	"github.com/bernardoforcillo/authlayer/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type organizationRepository struct {
	db *gorm.DB
}

func NewOrganizationRepository(db *gorm.DB) OrganizationRepository {
	return &organizationRepository{db: db}
}

func (r *organizationRepository) Create(ctx context.Context, org *model.Organization) error {
	return r.db.WithContext(ctx).Create(org).Error
}

func (r *organizationRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Organization, error) {
	var org model.Organization
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&org).Error; err != nil {
		return nil, err
	}
	return &org, nil
}

func (r *organizationRepository) GetBySlug(ctx context.Context, slug string) (*model.Organization, error) {
	var org model.Organization
	if err := r.db.WithContext(ctx).Where("slug = ?", slug).First(&org).Error; err != nil {
		return nil, err
	}
	return &org, nil
}

func (r *organizationRepository) Update(ctx context.Context, org *model.Organization) error {
	return r.db.WithContext(ctx).Save(org).Error
}

func (r *organizationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.Organization{}).Error
}

func (r *organizationRepository) ListByUserID(ctx context.Context, userID uuid.UUID, pagination Pagination) ([]model.Organization, int64, error) {
	var orgs []model.Organization
	var total int64

	subQuery := r.db.Model(&model.OrganizationMember{}).Select("org_id").Where("user_id = ?", userID)

	query := r.db.WithContext(ctx).Model(&model.Organization{}).Where("id IN (?)", subQuery)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	pageSize := pagination.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	if err := query.Order("created_at DESC").Limit(pageSize).Find(&orgs).Error; err != nil {
		return nil, 0, err
	}

	return orgs, total, nil
}
