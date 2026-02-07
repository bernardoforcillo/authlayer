package model

// UserStatus represents the state of a user account.
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusBanned   UserStatus = "banned"
)

// User represents a human user in the system.
type User struct {
	Base
	Email         string     `gorm:"uniqueIndex;size:255;not null" json:"email"`
	PasswordHash  *string    `gorm:"size:255" json:"-"`
	Name          string     `gorm:"size:255;not null" json:"name"`
	Avatar        *string    `gorm:"size:512" json:"avatar,omitempty"`
	EmailVerified bool       `gorm:"default:false;not null" json:"email_verified"`
	Status        UserStatus `gorm:"size:20;default:'active';not null" json:"status"`

	// Associations
	Accounts            []Account            `gorm:"foreignKey:UserID" json:"accounts,omitempty"`
	Sessions            []Session            `gorm:"foreignKey:UserID" json:"sessions,omitempty"`
	APIKeys             []APIKey             `gorm:"foreignKey:UserID" json:"api_keys,omitempty"`
	OrganizationMembers []OrganizationMember `gorm:"foreignKey:UserID" json:"organization_memberships,omitempty"`
	TeamMembers         []TeamMember         `gorm:"foreignKey:UserID" json:"team_memberships,omitempty"`
}
