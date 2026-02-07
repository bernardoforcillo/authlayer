package model

import "github.com/google/uuid"

// Account represents an OAuth provider link for a user.
type Account struct {
	Base
	UserID            uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_provider" json:"user_id"`
	Provider          string    `gorm:"size:50;not null;uniqueIndex:idx_user_provider;uniqueIndex:idx_provider_account" json:"provider"`
	ProviderAccountID string    `gorm:"size:255;not null;uniqueIndex:idx_provider_account" json:"provider_account_id"`
	AccessToken       *string   `gorm:"size:2048" json:"-"`
	RefreshToken      *string   `gorm:"size:2048" json:"-"`
	TokenExpiresAt    *int64    `json:"token_expires_at,omitempty"`
	Scope             *string   `gorm:"size:512" json:"scope,omitempty"`
	IDToken           *string   `gorm:"type:text" json:"-"`

	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}
