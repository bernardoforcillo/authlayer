package authzv1

type CreateRoleRequest struct {
	Name         string  `json:"name,omitempty"`
	Description  *string `json:"description,omitempty"`
	OrgId        *string `json:"org_id,omitempty"`
	ParentRoleId *string `json:"parent_role_id,omitempty"`
}

type CreateRoleResponse struct {
	Role *RoleInfo `json:"role,omitempty"`
}

type GetRoleRequest struct {
	RoleId string `json:"role_id,omitempty"`
}

type GetRoleResponse struct {
	Role                 *RoleInfo        `json:"role,omitempty"`
	InheritedPermissions []*PermissionInfo `json:"inherited_permissions,omitempty"`
}

type UpdateRoleRequest struct {
	RoleId       string  `json:"role_id,omitempty"`
	Name         *string `json:"name,omitempty"`
	Description  *string `json:"description,omitempty"`
	ParentRoleId *string `json:"parent_role_id,omitempty"`
}

type UpdateRoleResponse struct {
	Role *RoleInfo `json:"role,omitempty"`
}

type DeleteRoleRequest struct {
	RoleId string `json:"role_id,omitempty"`
}

type DeleteRoleResponse struct{}

type ListRolesRequest struct {
	OrgId      *string            `json:"org_id,omitempty"`
	Pagination *PaginationRequest `json:"pagination,omitempty"`
}

type ListRolesResponse struct {
	Roles      []*RoleInfo         `json:"roles,omitempty"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}

type AssignRoleRequest struct {
	UserId string `json:"user_id,omitempty"`
	RoleId string `json:"role_id,omitempty"`
	OrgId  string `json:"org_id,omitempty"`
	TeamId string `json:"team_id,omitempty"`
}

type AssignRoleResponse struct{}

type RevokeRoleRequest struct {
	UserId string `json:"user_id,omitempty"`
	RoleId string `json:"role_id,omitempty"`
	OrgId  string `json:"org_id,omitempty"`
	TeamId string `json:"team_id,omitempty"`
}

type RevokeRoleResponse struct{}

type CreatePermissionRequest struct {
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type CreatePermissionResponse struct {
	Permission *PermissionInfo `json:"permission,omitempty"`
}

type ListPermissionsRequest struct {
	Pagination *PaginationRequest `json:"pagination,omitempty"`
}

type ListPermissionsResponse struct {
	Permissions []*PermissionInfo   `json:"permissions,omitempty"`
	Pagination  *PaginationResponse `json:"pagination,omitempty"`
}

type AssignPermissionRequest struct {
	RoleId       string `json:"role_id,omitempty"`
	PermissionId string `json:"permission_id,omitempty"`
}

type AssignPermissionResponse struct{}

type RevokePermissionRequest struct {
	RoleId       string `json:"role_id,omitempty"`
	PermissionId string `json:"permission_id,omitempty"`
}

type RevokePermissionResponse struct{}

type CheckPermissionRequest struct {
	UserId         string  `json:"user_id,omitempty"`
	PermissionName string  `json:"permission_name,omitempty"`
	OrgId          *string `json:"org_id,omitempty"`
	TeamId         *string `json:"team_id,omitempty"`
}

type CheckPermissionResponse struct {
	Allowed     bool   `json:"allowed,omitempty"`
	MatchedRole string `json:"matched_role,omitempty"`
}

type GetUserPermissionsRequest struct {
	UserId string  `json:"user_id,omitempty"`
	OrgId  *string `json:"org_id,omitempty"`
}

type GetUserPermissionsResponse struct {
	Permissions []*PermissionInfo `json:"permissions,omitempty"`
}
