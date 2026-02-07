package repository

import (
	"context"

	"authz-go/internal/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type organizationMemberRepository struct {
	db *gorm.DB
}

func NewOrganizationMemberRepository(db *gorm.DB) OrganizationMemberRepository {
	return &organizationMemberRepository{db: db}
}

func (r *organizationMemberRepository) Add(ctx context.Context, member *model.OrganizationMember) error {
	return r.db.WithContext(ctx).Create(member).Error
}

func (r *organizationMemberRepository) Remove(ctx context.Context, orgID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("org_id = ? AND user_id = ?", orgID, userID).
		Delete(&model.OrganizationMember{}).Error
}

func (r *organizationMemberRepository) GetMembership(ctx context.Context, orgID, userID uuid.UUID) (*model.OrganizationMember, error) {
	var member model.OrganizationMember
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND user_id = ?", orgID, userID).
		Preload("Role").
		Preload("User").
		First(&member).Error
	if err != nil {
		return nil, err
	}
	return &member, nil
}

func (r *organizationMemberRepository) UpdateRole(ctx context.Context, orgID, userID, roleID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Model(&model.OrganizationMember{}).
		Where("org_id = ? AND user_id = ?", orgID, userID).
		Update("role_id", roleID).Error
}

func (r *organizationMemberRepository) ListByOrgID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]model.OrganizationMember, int64, error) {
	var members []model.OrganizationMember
	var total int64

	query := r.db.WithContext(ctx).Model(&model.OrganizationMember{}).Where("org_id = ?", orgID)

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
