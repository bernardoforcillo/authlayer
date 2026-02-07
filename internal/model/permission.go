package model

// Permission represents a single permission (e.g., "org:read", "team:write").
type Permission struct {
	Base
	Name        string  `gorm:"size:100;uniqueIndex;not null" json:"name"`
	Description *string `gorm:"size:512" json:"description,omitempty"`

	Roles []Role `gorm:"many2many:role_permissions" json:"roles,omitempty"`
}
