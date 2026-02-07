package model

import (
	"time"

	"github.com/google/uuid"
)

// InvitationStatus represents the state of an organization invitation.
type InvitationStatus string

const (
	InvitationStatusPending  InvitationStatus = "pending"
	InvitationStatusAccepted InvitationStatus = "accepted"
	InvitationStatusDeclined InvitationStatus = "declined"
	InvitationStatusExpired  InvitationStatus = "expired"
)

// Invitation represents a pending invitation to join an organization.
type Invitation struct {
	Base
	OrgID     uuid.UUID        `gorm:"type:uuid;not null;index" json:"org_id"`
	Email     string           `gorm:"size:255;not null" json:"email"`
	RoleID    uuid.UUID        `gorm:"type:uuid;not null" json:"role_id"`
	Token     string           `gorm:"size:255;uniqueIndex;not null" json:"-"`
	Status    InvitationStatus `gorm:"size:20;default:'pending';not null" json:"status"`
	ExpiresAt time.Time        `gorm:"not null" json:"expires_at"`
	InviterID uuid.UUID        `gorm:"type:uuid;not null" json:"inviter_id"`

	Organization Organization `gorm:"foreignKey:OrgID" json:"organization,omitempty"`
	Role         Role         `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	Inviter      User         `gorm:"foreignKey:InviterID" json:"inviter,omitempty"`
}
