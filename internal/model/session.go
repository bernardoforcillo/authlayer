package model

import (
	"time"

	"github.com/google/uuid"
)

// Session represents a refresh token session for token rotation.
type Session struct {
	Base
	UserID      uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	TokenHash   string    `gorm:"size:255;not null;uniqueIndex" json:"-"`
	TokenFamily string    `gorm:"size:255;not null;index" json:"-"`
	ExpiresAt   time.Time `gorm:"not null" json:"expires_at"`
	IPAddress   *string   `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent   *string   `gorm:"size:512" json:"user_agent,omitempty"`
	Revoked     bool      `gorm:"default:false;not null" json:"revoked"`

	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}
