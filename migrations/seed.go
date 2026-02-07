package migrations

import (
	"authz-go/internal/model"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DefaultPermissions defines all system permissions using resource:action format.
var DefaultPermissions = []struct {
	Name        string
	Description string
}{
	// Organization
	{"org:create", "Create organizations"},
	{"org:read", "View organization details"},
	{"org:update", "Update organization settings"},
	{"org:delete", "Delete organizations"},

	// Team
	{"team:create", "Create teams within an organization"},
	{"team:read", "View team details"},
	{"team:update", "Update team settings"},
	{"team:delete", "Delete teams"},

	// Members
	{"member:invite", "Invite members to an organization"},
	{"member:remove", "Remove members from an organization"},
	{"member:update_role", "Change a member's role"},

	// Roles
	{"role:create", "Create new roles"},
	{"role:read", "View role details"},
	{"role:update", "Update roles"},
	{"role:delete", "Delete roles"},
	{"role:assign", "Assign roles to users"},

	// Permissions
	{"permission:read", "View permissions"},
	{"permission:assign", "Assign permissions to roles"},

	// Users
	{"user:read", "View user profiles"},
	{"user:update", "Update user profiles"},
	{"user:delete", "Delete user accounts"},
	{"user:list", "List all users"},

	// API Keys
	{"apikey:create", "Create API keys"},
	{"apikey:read", "View API keys"},
	{"apikey:revoke", "Revoke API keys"},

	// Service Accounts
	{"service_account:create", "Create service accounts"},
	{"service_account:read", "View service accounts"},
	{"service_account:update", "Update service accounts"},
	{"service_account:delete", "Delete service accounts"},
	{"service_account:manage_keys", "Manage service account keys"},
	{"service_account:assign_role", "Assign roles to service accounts"},
}

// DefaultRoles defines the system role hierarchy: viewer -> member -> admin -> owner.
var DefaultRoles = []struct {
	Name         string
	Description  string
	ParentName   string // empty = no parent
	Permissions  []string
}{
	{
		Name:        "viewer",
		Description: "Read-only access",
		Permissions: []string{
			"org:read", "team:read", "role:read", "permission:read", "user:read",
			"service_account:read",
		},
	},
	{
		Name:        "member",
		Description: "Standard member access",
		ParentName:  "viewer",
		Permissions: []string{
			"team:create", "apikey:create", "apikey:read", "apikey:revoke",
		},
	},
	{
		Name:        "admin",
		Description: "Administrative access",
		ParentName:  "member",
		Permissions: []string{
			"org:update", "team:update", "team:delete",
			"member:invite", "member:remove", "member:update_role",
			"role:create", "role:update", "role:assign",
			"user:list",
			"service_account:create", "service_account:update",
			"service_account:manage_keys", "service_account:assign_role",
		},
	},
	{
		Name:        "owner",
		Description: "Full access (organization owner)",
		ParentName:  "admin",
		Permissions: []string{
			"org:create", "org:delete",
			"role:delete", "permission:assign",
			"user:delete", "user:update",
			"service_account:delete",
		},
	},
}

// Seed creates default permissions and roles if they don't already exist.
func Seed(db *gorm.DB, logger *zap.Logger) error {
	// Create permissions
	permMap := make(map[string]model.Permission)
	for _, p := range DefaultPermissions {
		var existing model.Permission
		result := db.Where("name = ?", p.Name).First(&existing)
		if result.Error == nil {
			permMap[p.Name] = existing
			continue
		}

		desc := p.Description
		perm := model.Permission{
			Name:        p.Name,
			Description: &desc,
		}
		if err := db.Create(&perm).Error; err != nil {
			logger.Warn("failed to create permission", zap.String("name", p.Name), zap.Error(err))
			continue
		}
		permMap[p.Name] = perm
		logger.Info("created permission", zap.String("name", p.Name))
	}

	// Create roles
	roleMap := make(map[string]model.Role)
	for _, r := range DefaultRoles {
		var existing model.Role
		result := db.Where("name = ? AND org_id IS NULL", r.Name).First(&existing)
		if result.Error == nil {
			roleMap[r.Name] = existing
			continue
		}

		desc := r.Description
		role := model.Role{
			Name:        r.Name,
			Description: &desc,
		}

		if r.ParentName != "" {
			if parent, ok := roleMap[r.ParentName]; ok {
				role.ParentRoleID = &parent.ID
			}
		}

		if err := db.Create(&role).Error; err != nil {
			logger.Warn("failed to create role", zap.String("name", r.Name), zap.Error(err))
			continue
		}
		roleMap[r.Name] = role
		logger.Info("created role", zap.String("name", r.Name))

		// Assign permissions to role
		for _, permName := range r.Permissions {
			perm, ok := permMap[permName]
			if !ok {
				continue
			}
			rp := model.RolePermission{
				RoleID:       role.ID,
				PermissionID: perm.ID,
			}
			if err := db.Create(&rp).Error; err != nil {
				logger.Warn("failed to assign permission to role",
					zap.String("role", r.Name),
					zap.String("permission", permName),
					zap.Error(err),
				)
			}
		}
	}

	logger.Info("seed data completed",
		zap.Int("permissions", len(permMap)),
		zap.Int("roles", len(roleMap)),
	)

	return nil
}
