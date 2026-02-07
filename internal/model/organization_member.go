package model

import "github.com/google/uuid"

// OrganizationMember represents a user's membership in an organization.
type OrganizationMember struct {
	Base
	OrgID  uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_org_user" json:"org_id"`
	UserID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_org_user" json:"user_id"`
	RoleID uuid.UUID `gorm:"type:uuid;not null" json:"role_id"`

	Organization Organization `gorm:"foreignKey:OrgID" json:"organization,omitempty"`
	User         User         `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Role         Role         `gorm:"foreignKey:RoleID" json:"role,omitempty"`
}
