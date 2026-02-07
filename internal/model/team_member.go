package model

import "github.com/google/uuid"

// TeamMember represents a user's membership in a team.
type TeamMember struct {
	Base
	TeamID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_team_user" json:"team_id"`
	UserID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_team_user" json:"user_id"`
	RoleID uuid.UUID `gorm:"type:uuid;not null" json:"role_id"`

	Team Team `gorm:"foreignKey:TeamID" json:"team,omitempty"`
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Role Role `gorm:"foreignKey:RoleID" json:"role,omitempty"`
}
