package model

import "github.com/google/uuid"

// Organization represents a tenant/workspace in the multi-tenant system.
type Organization struct {
	Base
	Name    string    `gorm:"size:255;not null" json:"name"`
	Slug    string    `gorm:"size:255;uniqueIndex;not null" json:"slug"`
	OwnerID uuid.UUID `gorm:"type:uuid;not null;index" json:"owner_id"`

	Owner   User                 `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
	Members []OrganizationMember `gorm:"foreignKey:OrgID" json:"members,omitempty"`
	Teams   []Team               `gorm:"foreignKey:OrgID" json:"teams,omitempty"`
	Roles   []Role               `gorm:"foreignKey:OrgID" json:"roles,omitempty"`
}
