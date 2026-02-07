package model

import (
	"time"

	"github.com/google/uuid"
)

// ServiceAccountStatus represents the state of a service account.
type ServiceAccountStatus string

const (
	ServiceAccountStatusActive   ServiceAccountStatus = "active"
	ServiceAccountStatusDisabled ServiceAccountStatus = "disabled"
)

// ServiceAccount represents a non-human identity (CI/CD, microservice, bot)
// that can authenticate and participate in RBAC.
type ServiceAccount struct {
	Base
	DisplayName       string               `gorm:"size:255;not null" json:"display_name"`
	Description       string               `gorm:"size:1024" json:"description"`
	OrgID             uuid.UUID            `gorm:"type:uuid;not null;index" json:"org_id"`
	CreatedBy         uuid.UUID            `gorm:"type:uuid;not null" json:"created_by"`
	Status            ServiceAccountStatus `gorm:"size:20;default:'active';not null" json:"status"`
	LastAuthenticatedAt *time.Time         `json:"last_authenticated_at,omitempty"`

	Organization Organization        `gorm:"foreignKey:OrgID" json:"organization,omitempty"`
	Creator      User                `gorm:"foreignKey:CreatedBy" json:"creator,omitempty"`
	Keys         []ServiceAccountKey `gorm:"foreignKey:ServiceAccountID" json:"keys,omitempty"`
	Roles        []ServiceAccountRole `gorm:"foreignKey:ServiceAccountID" json:"roles,omitempty"`
}

// ServiceAccountKey represents an API key for a service account.
type ServiceAccountKey struct {
	Base
	ServiceAccountID uuid.UUID  `gorm:"type:uuid;not null;index" json:"service_account_id"`
	Name             string     `gorm:"size:255;not null" json:"name"`
	KeyPrefix        string     `gorm:"size:8;not null" json:"key_prefix"`
	KeyHash          string     `gorm:"size:255;not null;uniqueIndex" json:"-"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	Revoked          bool       `gorm:"default:false;not null" json:"revoked"`

	ServiceAccount ServiceAccount `gorm:"foreignKey:ServiceAccountID" json:"service_account,omitempty"`
}

// ServiceAccountRole maps a service account to a role within an org.
type ServiceAccountRole struct {
	Base
	ServiceAccountID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_sa_role_org" json:"service_account_id"`
	RoleID           uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_sa_role_org" json:"role_id"`
	OrgID            uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_sa_role_org" json:"org_id"`

	ServiceAccount ServiceAccount `gorm:"foreignKey:ServiceAccountID" json:"service_account,omitempty"`
	Role           Role           `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	Organization   Organization   `gorm:"foreignKey:OrgID" json:"organization,omitempty"`
}
