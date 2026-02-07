package model

import "github.com/google/uuid"

// Role represents a named set of permissions with optional hierarchy.
// If OrgID is nil, the role is a system-level role.
// ParentRoleID enables hierarchical RBAC (permission inheritance).
type Role struct {
	Base
	Name         string     `gorm:"size:100;not null;uniqueIndex:idx_role_org_name" json:"name"`
	Description  *string    `gorm:"size:512" json:"description,omitempty"`
	OrgID        *uuid.UUID `gorm:"type:uuid;index;uniqueIndex:idx_role_org_name" json:"org_id,omitempty"`
	ParentRoleID *uuid.UUID `gorm:"type:uuid;index" json:"parent_role_id,omitempty"`

	Organization *Organization `gorm:"foreignKey:OrgID" json:"organization,omitempty"`
	ParentRole   *Role         `gorm:"foreignKey:ParentRoleID" json:"parent_role,omitempty"`
	ChildRoles   []Role        `gorm:"foreignKey:ParentRoleID" json:"child_roles,omitempty"`
	Permissions  []Permission  `gorm:"many2many:role_permissions" json:"permissions,omitempty"`
}
