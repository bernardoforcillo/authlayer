package model

import (
	"time"

	"github.com/google/uuid"
)

// APIKey represents a user-generated API key for programmatic access.
type APIKey struct {
	Base
	UserID     uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	Name       string     `gorm:"size:255;not null" json:"name"`
	KeyPrefix  string     `gorm:"size:8;not null" json:"key_prefix"`
	KeyHash    string     `gorm:"size:255;not null;uniqueIndex" json:"-"`
	Scopes     string     `gorm:"type:text" json:"scopes"` // JSON array
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Revoked    bool       `gorm:"default:false;not null" json:"revoked"`

	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}
