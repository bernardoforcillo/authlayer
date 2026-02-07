package service

import (
	"context"
	"errors"

	"authz-go/internal/model"
	"authz-go/internal/rbac"
	"authz-go/internal/repository"
	authzv1 "authz-go/pkg/proto/authz/v1"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type RBACService struct {
	authzv1.UnimplementedRBACServiceServer

	roleRepo     repository.RoleRepository
	permRepo     repository.PermissionRepository
	rolePermRepo repository.RolePermissionRepository
	orgMemberRepo repository.OrganizationMemberRepository
	teamMemberRepo repository.TeamMemberRepository
	checker      *rbac.Checker
	logger       *zap.Logger
}

func NewRBACService(
	roleRepo repository.RoleRepository,
	permRepo repository.PermissionRepository,
	rolePermRepo repository.RolePermissionRepository,
	orgMemberRepo repository.OrganizationMemberRepository,
	teamMemberRepo repository.TeamMemberRepository,
	checker *rbac.Checker,
	logger *zap.Logger,
) *RBACService {
	return &RBACService{
		roleRepo:       roleRepo,
		permRepo:       permRepo,
		rolePermRepo:   rolePermRepo,
		orgMemberRepo:  orgMemberRepo,
		teamMemberRepo: teamMemberRepo,
		checker:        checker,
		logger:         logger,
	}
}

func (s *RBACService) CreateRole(ctx context.Context, req *authzv1.CreateRoleRequest) (*authzv1.CreateRoleResponse, error) {
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}

	role := &model.Role{
		Name:        req.Name,
		Description: req.Description,
	}

	if req.OrgId != nil {
		orgID, err := uuid.Parse(*req.OrgId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
		}
		role.OrgID = &orgID
	}

	if req.ParentRoleId != nil {
		parentID, err := uuid.Parse(*req.ParentRoleId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid parent_role_id")
		}
		role.ParentRoleID = &parentID
	}

	if err := s.roleRepo.Create(ctx, role); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create role: %v", err)
	}

	return &authzv1.CreateRoleResponse{
		Role: roleToProto(role),
	}, nil
}

func (s *RBACService) GetRole(ctx context.Context, req *authzv1.GetRoleRequest) (*authzv1.GetRoleResponse, error) {
	id, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}

	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "role not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get role")
	}

	// Get inherited permissions through hierarchy
	ancestors, err := s.roleRepo.GetAncestors(ctx, id, 10)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get role hierarchy")
	}

	ancestorIDs := make([]uuid.UUID, len(ancestors))
	for i, a := range ancestors {
		ancestorIDs[i] = a.ID
	}

	inheritedPerms, err := s.rolePermRepo.GetPermissionsByRoleIDs(ctx, ancestorIDs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get permissions")
	}

	inherited := make([]*authzv1.PermissionInfo, len(inheritedPerms))
	for i, p := range inheritedPerms {
		inherited[i] = permToProto(&p)
	}

	return &authzv1.GetRoleResponse{
		Role:                 roleToProto(role),
		InheritedPermissions: inherited,
	}, nil
}

func (s *RBACService) UpdateRole(ctx context.Context, req *authzv1.UpdateRoleRequest) (*authzv1.UpdateRoleResponse, error) {
	id, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}

	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "role not found")
	}

	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		role.Description = req.Description
	}
	if req.ParentRoleId != nil {
		parentID, err := uuid.Parse(*req.ParentRoleId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid parent_role_id")
		}
		role.ParentRoleID = &parentID
	}

	if err := s.roleRepo.Update(ctx, role); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update role")
	}

	return &authzv1.UpdateRoleResponse{Role: roleToProto(role)}, nil
}

func (s *RBACService) DeleteRole(ctx context.Context, req *authzv1.DeleteRoleRequest) (*authzv1.DeleteRoleResponse, error) {
	id, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}

	if err := s.roleRepo.Delete(ctx, id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete role")
	}

	return &authzv1.DeleteRoleResponse{}, nil
}

func (s *RBACService) ListRoles(ctx context.Context, req *authzv1.ListRolesRequest) (*authzv1.ListRolesResponse, error) {
	var orgID *uuid.UUID
	if req.OrgId != nil {
		id, err := uuid.Parse(*req.OrgId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
		}
		orgID = &id
	}

	pagination := repository.Pagination{PageSize: 50}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	roles, total, err := s.roleRepo.ListByOrgID(ctx, orgID, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list roles")
	}

	protoRoles := make([]*authzv1.RoleInfo, len(roles))
	for i, r := range roles {
		protoRoles[i] = roleToProto(&r)
	}

	return &authzv1.ListRolesResponse{
		Roles: protoRoles,
		Pagination: &authzv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func (s *RBACService) AssignRole(ctx context.Context, req *authzv1.AssignRoleRequest) (*authzv1.AssignRoleResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}

	if req.OrgId != "" {
		orgID, err := uuid.Parse(req.OrgId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
		}
		if err := s.orgMemberRepo.UpdateRole(ctx, orgID, userID, roleID); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to assign role")
		}
	} else if req.TeamId != "" {
		// For teams, we'd update team member role
		return nil, status.Errorf(codes.Unimplemented, "team role assignment not yet implemented")
	}

	s.checker.InvalidateUserCache(userID)

	return &authzv1.AssignRoleResponse{}, nil
}

func (s *RBACService) RevokeRole(ctx context.Context, req *authzv1.RevokeRoleRequest) (*authzv1.RevokeRoleResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	if req.OrgId != "" {
		orgID, err := uuid.Parse(req.OrgId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
		}
		if err := s.orgMemberRepo.Remove(ctx, orgID, userID); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to revoke role")
		}
	}

	s.checker.InvalidateUserCache(userID)

	return &authzv1.RevokeRoleResponse{}, nil
}

func (s *RBACService) CreatePermission(ctx context.Context, req *authzv1.CreatePermissionRequest) (*authzv1.CreatePermissionResponse, error) {
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}

	perm := &model.Permission{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := s.permRepo.Create(ctx, perm); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create permission: %v", err)
	}

	return &authzv1.CreatePermissionResponse{
		Permission: permToProto(perm),
	}, nil
}

func (s *RBACService) ListPermissions(ctx context.Context, req *authzv1.ListPermissionsRequest) (*authzv1.ListPermissionsResponse, error) {
	pagination := repository.Pagination{PageSize: 50}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	perms, total, err := s.permRepo.List(ctx, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list permissions")
	}

	protoPerms := make([]*authzv1.PermissionInfo, len(perms))
	for i, p := range perms {
		protoPerms[i] = permToProto(&p)
	}

	return &authzv1.ListPermissionsResponse{
		Permissions: protoPerms,
		Pagination: &authzv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func (s *RBACService) AssignPermission(ctx context.Context, req *authzv1.AssignPermissionRequest) (*authzv1.AssignPermissionResponse, error) {
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}
	permID, err := uuid.Parse(req.PermissionId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid permission_id")
	}

	if err := s.rolePermRepo.Assign(ctx, roleID, permID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to assign permission")
	}

	return &authzv1.AssignPermissionResponse{}, nil
}

func (s *RBACService) RevokePermission(ctx context.Context, req *authzv1.RevokePermissionRequest) (*authzv1.RevokePermissionResponse, error) {
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}
	permID, err := uuid.Parse(req.PermissionId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid permission_id")
	}

	if err := s.rolePermRepo.Revoke(ctx, roleID, permID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke permission")
	}

	return &authzv1.RevokePermissionResponse{}, nil
}

func (s *RBACService) CheckPermission(ctx context.Context, req *authzv1.CheckPermissionRequest) (*authzv1.CheckPermissionResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	var orgID *uuid.UUID
	if req.OrgId != nil {
		id, err := uuid.Parse(*req.OrgId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
		}
		orgID = &id
	}

	allowed, matchedRole, err := s.checker.CheckPermission(ctx, userID, req.PermissionName, orgID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check permission")
	}

	return &authzv1.CheckPermissionResponse{
		Allowed:     allowed,
		MatchedRole: matchedRole,
	}, nil
}

func (s *RBACService) GetUserPermissions(ctx context.Context, req *authzv1.GetUserPermissionsRequest) (*authzv1.GetUserPermissionsResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	var orgID *uuid.UUID
	if req.OrgId != nil {
		id, err := uuid.Parse(*req.OrgId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
		}
		orgID = &id
	}

	// GetUserPermissions is not directly supported via Checker.
	// TODO: expose resolver.ResolveUserPermissions through Checker if needed.
	_, _ = userID, orgID
	return nil, status.Errorf(codes.Unimplemented, "GetUserPermissions not yet implemented; use CheckPermission for individual checks")
}

func roleToProto(r *model.Role) *authzv1.RoleInfo {
	info := &authzv1.RoleInfo{
		Id:   r.ID.String(),
		Name: r.Name,
	}
	if r.Description != nil {
		info.Description = r.Description
	}
	if r.OrgID != nil {
		orgID := r.OrgID.String()
		info.OrgId = &orgID
	}
	if r.ParentRoleID != nil {
		parentID := r.ParentRoleID.String()
		info.ParentRoleId = &parentID
	}
	if len(r.Permissions) > 0 {
		info.Permissions = make([]*authzv1.PermissionInfo, len(r.Permissions))
		for i, p := range r.Permissions {
			info.Permissions[i] = permToProto(&p)
		}
	}
	return info
}

func permToProto(p *model.Permission) *authzv1.PermissionInfo {
	info := &authzv1.PermissionInfo{
		Id:   p.ID.String(),
		Name: p.Name,
	}
	if p.Description != nil {
		info.Description = p.Description
	}
	return info
}
