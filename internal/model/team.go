package model

import "github.com/google/uuid"

// Team represents a sub-group within an organization.
type Team struct {
	Base
	Name  string    `gorm:"size:255;not null;uniqueIndex:idx_team_org_name" json:"name"`
	OrgID uuid.UUID `gorm:"type:uuid;not null;index;uniqueIndex:idx_team_org_name" json:"org_id"`

	Organization Organization `gorm:"foreignKey:OrgID" json:"organization,omitempty"`
	Members      []TeamMember `gorm:"foreignKey:TeamID" json:"members,omitempty"`
}
