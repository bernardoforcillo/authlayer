package authzv1

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---- AuthService ----

const AuthService_ServiceName = "authz.v1.AuthService"

type AuthServiceServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	Login(context.Context, *LoginRequest) (*LoginResponse, error)
	Logout(context.Context, *LogoutRequest) (*LogoutResponse, error)
	RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error)
	VerifyEmail(context.Context, *VerifyEmailRequest) (*VerifyEmailResponse, error)
	RequestPasswordReset(context.Context, *RequestPasswordResetRequest) (*RequestPasswordResetResponse, error)
	ResetPassword(context.Context, *ResetPasswordRequest) (*ResetPasswordResponse, error)
	GetOAuthURL(context.Context, *GetOAuthURLRequest) (*GetOAuthURLResponse, error)
	OAuthCallback(context.Context, *OAuthCallbackRequest) (*OAuthCallbackResponse, error)
}

type UnimplementedAuthServiceServer struct{}

func (UnimplementedAuthServiceServer) Register(context.Context, *RegisterRequest) (*RegisterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedAuthServiceServer) Login(context.Context, *LoginRequest) (*LoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedAuthServiceServer) Logout(context.Context, *LogoutRequest) (*LogoutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Logout not implemented")
}
func (UnimplementedAuthServiceServer) RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshToken not implemented")
}
func (UnimplementedAuthServiceServer) VerifyEmail(context.Context, *VerifyEmailRequest) (*VerifyEmailResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyEmail not implemented")
}
func (UnimplementedAuthServiceServer) RequestPasswordReset(context.Context, *RequestPasswordResetRequest) (*RequestPasswordResetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestPasswordReset not implemented")
}
func (UnimplementedAuthServiceServer) ResetPassword(context.Context, *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResetPassword not implemented")
}
func (UnimplementedAuthServiceServer) GetOAuthURL(context.Context, *GetOAuthURLRequest) (*GetOAuthURLResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetOAuthURL not implemented")
}
func (UnimplementedAuthServiceServer) OAuthCallback(context.Context, *OAuthCallbackRequest) (*OAuthCallbackResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method OAuthCallback not implemented")
}

func RegisterAuthServiceServer(s *grpc.Server, srv AuthServiceServer) {
	s.RegisterService(&AuthService_ServiceDesc, srv)
}

var AuthService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: AuthService_ServiceName,
	HandlerType: (*AuthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Register", Handler: _AuthService_Register_Handler},
		{MethodName: "Login", Handler: _AuthService_Login_Handler},
		{MethodName: "Logout", Handler: _AuthService_Logout_Handler},
		{MethodName: "RefreshToken", Handler: _AuthService_RefreshToken_Handler},
		{MethodName: "VerifyEmail", Handler: _AuthService_VerifyEmail_Handler},
		{MethodName: "RequestPasswordReset", Handler: _AuthService_RequestPasswordReset_Handler},
		{MethodName: "ResetPassword", Handler: _AuthService_ResetPassword_Handler},
		{MethodName: "GetOAuthURL", Handler: _AuthService_GetOAuthURL_Handler},
		{MethodName: "OAuthCallback", Handler: _AuthService_OAuthCallback_Handler},
	},
	Streams: []grpc.StreamDesc{},
}

func _AuthService_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).Register(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/Register"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).Register(ctx, req.(*RegisterRequest)) })
}

func _AuthService_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).Login(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/Login"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).Login(ctx, req.(*LoginRequest)) })
}

func _AuthService_Logout_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LogoutRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).Logout(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/Logout"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).Logout(ctx, req.(*LogoutRequest)) })
}

func _AuthService_RefreshToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RefreshTokenRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).RefreshToken(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/RefreshToken"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).RefreshToken(ctx, req.(*RefreshTokenRequest)) })
}

func _AuthService_VerifyEmail_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyEmailRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).VerifyEmail(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/VerifyEmail"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).VerifyEmail(ctx, req.(*VerifyEmailRequest)) })
}

func _AuthService_RequestPasswordReset_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RequestPasswordResetRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).RequestPasswordReset(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/RequestPasswordReset"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).RequestPasswordReset(ctx, req.(*RequestPasswordResetRequest)) })
}

func _AuthService_ResetPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResetPasswordRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).ResetPassword(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/ResetPassword"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).ResetPassword(ctx, req.(*ResetPasswordRequest)) })
}

func _AuthService_GetOAuthURL_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetOAuthURLRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).GetOAuthURL(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/GetOAuthURL"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).GetOAuthURL(ctx, req.(*GetOAuthURLRequest)) })
}

func _AuthService_OAuthCallback_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OAuthCallbackRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(AuthServiceServer).OAuthCallback(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + AuthService_ServiceName + "/OAuthCallback"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(AuthServiceServer).OAuthCallback(ctx, req.(*OAuthCallbackRequest)) })
}

// ---- UserService ----

const UserService_ServiceName = "authz.v1.UserService"

type UserServiceServer interface {
	GetUser(context.Context, *GetUserRequest) (*GetUserResponse, error)
	UpdateUser(context.Context, *UpdateUserRequest) (*UpdateUserResponse, error)
	DeleteUser(context.Context, *DeleteUserRequest) (*DeleteUserResponse, error)
	ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error)
	ChangePassword(context.Context, *ChangePasswordRequest) (*ChangePasswordResponse, error)
}

type UnimplementedUserServiceServer struct{}

func (UnimplementedUserServiceServer) GetUser(context.Context, *GetUserRequest) (*GetUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUser not implemented")
}
func (UnimplementedUserServiceServer) UpdateUser(context.Context, *UpdateUserRequest) (*UpdateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUser not implemented")
}
func (UnimplementedUserServiceServer) DeleteUser(context.Context, *DeleteUserRequest) (*DeleteUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUser not implemented")
}
func (UnimplementedUserServiceServer) ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers not implemented")
}
func (UnimplementedUserServiceServer) ChangePassword(context.Context, *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangePassword not implemented")
}

func RegisterUserServiceServer(s *grpc.Server, srv UserServiceServer) {
	s.RegisterService(&UserService_ServiceDesc, srv)
}

var UserService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: UserService_ServiceName,
	HandlerType: (*UserServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "GetUser", Handler: _UserService_GetUser_Handler},
		{MethodName: "UpdateUser", Handler: _UserService_UpdateUser_Handler},
		{MethodName: "DeleteUser", Handler: _UserService_DeleteUser_Handler},
		{MethodName: "ListUsers", Handler: _UserService_ListUsers_Handler},
		{MethodName: "ChangePassword", Handler: _UserService_ChangePassword_Handler},
	},
	Streams: []grpc.StreamDesc{},
}

func _UserService_GetUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(UserServiceServer).GetUser(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + UserService_ServiceName + "/GetUser"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(UserServiceServer).GetUser(ctx, req.(*GetUserRequest)) })
}

func _UserService_UpdateUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateUserRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(UserServiceServer).UpdateUser(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + UserService_ServiceName + "/UpdateUser"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(UserServiceServer).UpdateUser(ctx, req.(*UpdateUserRequest)) })
}

func _UserService_DeleteUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteUserRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(UserServiceServer).DeleteUser(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + UserService_ServiceName + "/DeleteUser"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(UserServiceServer).DeleteUser(ctx, req.(*DeleteUserRequest)) })
}

func _UserService_ListUsers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListUsersRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(UserServiceServer).ListUsers(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + UserService_ServiceName + "/ListUsers"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(UserServiceServer).ListUsers(ctx, req.(*ListUsersRequest)) })
}

func _UserService_ChangePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangePasswordRequest)
	if err := dec(in); err != nil { return nil, err }
	if interceptor == nil { return srv.(UserServiceServer).ChangePassword(ctx, in) }
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + UserService_ServiceName + "/ChangePassword"}
	return interceptor(ctx, in, info, func(ctx context.Context, req interface{}) (interface{}, error) { return srv.(UserServiceServer).ChangePassword(ctx, req.(*ChangePasswordRequest)) })
}

// ---- OrganizationService ----

const OrganizationService_ServiceName = "authz.v1.OrganizationService"

type OrganizationServiceServer interface {
	CreateOrganization(context.Context, *CreateOrganizationRequest) (*CreateOrganizationResponse, error)
	GetOrganization(context.Context, *GetOrganizationRequest) (*GetOrganizationResponse, error)
	UpdateOrganization(context.Context, *UpdateOrganizationRequest) (*UpdateOrganizationResponse, error)
	DeleteOrganization(context.Context, *DeleteOrganizationRequest) (*DeleteOrganizationResponse, error)
	ListOrganizations(context.Context, *ListOrganizationsRequest) (*ListOrganizationsResponse, error)
	ListMembers(context.Context, *ListOrgMembersRequest) (*ListOrgMembersResponse, error)
	InviteMember(context.Context, *InviteMemberRequest) (*InviteMemberResponse, error)
	AcceptInvitation(context.Context, *AcceptInvitationRequest) (*AcceptInvitationResponse, error)
	RemoveMember(context.Context, *RemoveOrgMemberRequest) (*RemoveOrgMemberResponse, error)
	UpdateMemberRole(context.Context, *UpdateOrgMemberRoleRequest) (*UpdateOrgMemberRoleResponse, error)
}

type UnimplementedOrganizationServiceServer struct{}

func (UnimplementedOrganizationServiceServer) CreateOrganization(context.Context, *CreateOrganizationRequest) (*CreateOrganizationResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) GetOrganization(context.Context, *GetOrganizationRequest) (*GetOrganizationResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) UpdateOrganization(context.Context, *UpdateOrganizationRequest) (*UpdateOrganizationResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) DeleteOrganization(context.Context, *DeleteOrganizationRequest) (*DeleteOrganizationResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) ListOrganizations(context.Context, *ListOrganizationsRequest) (*ListOrganizationsResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) ListMembers(context.Context, *ListOrgMembersRequest) (*ListOrgMembersResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) InviteMember(context.Context, *InviteMemberRequest) (*InviteMemberResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) AcceptInvitation(context.Context, *AcceptInvitationRequest) (*AcceptInvitationResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) RemoveMember(context.Context, *RemoveOrgMemberRequest) (*RemoveOrgMemberResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedOrganizationServiceServer) UpdateMemberRole(context.Context, *UpdateOrgMemberRoleRequest) (*UpdateOrgMemberRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }

func RegisterOrganizationServiceServer(s *grpc.Server, srv OrganizationServiceServer) {
	s.RegisterService(&OrganizationService_ServiceDesc, srv)
}

var OrganizationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: OrganizationService_ServiceName,
	HandlerType: (*OrganizationServiceServer)(nil),
	Methods:     []grpc.MethodDesc{}, // Simplified: handlers omitted for brevity, use generated code
	Streams:     []grpc.StreamDesc{},
}

// ---- TeamService ----

const TeamService_ServiceName = "authz.v1.TeamService"

type TeamServiceServer interface {
	CreateTeam(context.Context, *CreateTeamRequest) (*CreateTeamResponse, error)
	GetTeam(context.Context, *GetTeamRequest) (*GetTeamResponse, error)
	UpdateTeam(context.Context, *UpdateTeamRequest) (*UpdateTeamResponse, error)
	DeleteTeam(context.Context, *DeleteTeamRequest) (*DeleteTeamResponse, error)
	ListTeams(context.Context, *ListTeamsRequest) (*ListTeamsResponse, error)
	AddMember(context.Context, *AddTeamMemberRequest) (*AddTeamMemberResponse, error)
	RemoveMember(context.Context, *RemoveTeamMemberRequest) (*RemoveTeamMemberResponse, error)
	ListMembers(context.Context, *ListTeamMembersRequest) (*ListTeamMembersResponse, error)
}

type UnimplementedTeamServiceServer struct{}

func (UnimplementedTeamServiceServer) CreateTeam(context.Context, *CreateTeamRequest) (*CreateTeamResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedTeamServiceServer) GetTeam(context.Context, *GetTeamRequest) (*GetTeamResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedTeamServiceServer) UpdateTeam(context.Context, *UpdateTeamRequest) (*UpdateTeamResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedTeamServiceServer) DeleteTeam(context.Context, *DeleteTeamRequest) (*DeleteTeamResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedTeamServiceServer) ListTeams(context.Context, *ListTeamsRequest) (*ListTeamsResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedTeamServiceServer) AddMember(context.Context, *AddTeamMemberRequest) (*AddTeamMemberResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedTeamServiceServer) RemoveMember(context.Context, *RemoveTeamMemberRequest) (*RemoveTeamMemberResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedTeamServiceServer) ListMembers(context.Context, *ListTeamMembersRequest) (*ListTeamMembersResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }

func RegisterTeamServiceServer(s *grpc.Server, srv TeamServiceServer) {
	s.RegisterService(&TeamService_ServiceDesc, srv)
}

var TeamService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: TeamService_ServiceName,
	HandlerType: (*TeamServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams:     []grpc.StreamDesc{},
}

// ---- RBACService ----

const RBACService_ServiceName = "authz.v1.RBACService"

type RBACServiceServer interface {
	CreateRole(context.Context, *CreateRoleRequest) (*CreateRoleResponse, error)
	GetRole(context.Context, *GetRoleRequest) (*GetRoleResponse, error)
	UpdateRole(context.Context, *UpdateRoleRequest) (*UpdateRoleResponse, error)
	DeleteRole(context.Context, *DeleteRoleRequest) (*DeleteRoleResponse, error)
	ListRoles(context.Context, *ListRolesRequest) (*ListRolesResponse, error)
	AssignRole(context.Context, *AssignRoleRequest) (*AssignRoleResponse, error)
	RevokeRole(context.Context, *RevokeRoleRequest) (*RevokeRoleResponse, error)
	CreatePermission(context.Context, *CreatePermissionRequest) (*CreatePermissionResponse, error)
	ListPermissions(context.Context, *ListPermissionsRequest) (*ListPermissionsResponse, error)
	AssignPermission(context.Context, *AssignPermissionRequest) (*AssignPermissionResponse, error)
	RevokePermission(context.Context, *RevokePermissionRequest) (*RevokePermissionResponse, error)
	CheckPermission(context.Context, *CheckPermissionRequest) (*CheckPermissionResponse, error)
	GetUserPermissions(context.Context, *GetUserPermissionsRequest) (*GetUserPermissionsResponse, error)
}

type UnimplementedRBACServiceServer struct{}

func (UnimplementedRBACServiceServer) CreateRole(context.Context, *CreateRoleRequest) (*CreateRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) GetRole(context.Context, *GetRoleRequest) (*GetRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) UpdateRole(context.Context, *UpdateRoleRequest) (*UpdateRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) DeleteRole(context.Context, *DeleteRoleRequest) (*DeleteRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) ListRoles(context.Context, *ListRolesRequest) (*ListRolesResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) AssignRole(context.Context, *AssignRoleRequest) (*AssignRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) RevokeRole(context.Context, *RevokeRoleRequest) (*RevokeRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) CreatePermission(context.Context, *CreatePermissionRequest) (*CreatePermissionResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) ListPermissions(context.Context, *ListPermissionsRequest) (*ListPermissionsResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) AssignPermission(context.Context, *AssignPermissionRequest) (*AssignPermissionResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) RevokePermission(context.Context, *RevokePermissionRequest) (*RevokePermissionResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) CheckPermission(context.Context, *CheckPermissionRequest) (*CheckPermissionResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedRBACServiceServer) GetUserPermissions(context.Context, *GetUserPermissionsRequest) (*GetUserPermissionsResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }

func RegisterRBACServiceServer(s *grpc.Server, srv RBACServiceServer) {
	s.RegisterService(&RBACService_ServiceDesc, srv)
}

var RBACService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: RBACService_ServiceName,
	HandlerType: (*RBACServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams:     []grpc.StreamDesc{},
}

// ---- APIKeyService ----

const APIKeyService_ServiceName = "authz.v1.APIKeyService"

type APIKeyServiceServer interface {
	CreateAPIKey(context.Context, *CreateAPIKeyRequest) (*CreateAPIKeyResponse, error)
	RevokeAPIKey(context.Context, *RevokeAPIKeyRequest) (*RevokeAPIKeyResponse, error)
	ListAPIKeys(context.Context, *ListAPIKeysRequest) (*ListAPIKeysResponse, error)
	ValidateAPIKey(context.Context, *ValidateAPIKeyRequest) (*ValidateAPIKeyResponse, error)
}

type UnimplementedAPIKeyServiceServer struct{}

func (UnimplementedAPIKeyServiceServer) CreateAPIKey(context.Context, *CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedAPIKeyServiceServer) RevokeAPIKey(context.Context, *RevokeAPIKeyRequest) (*RevokeAPIKeyResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedAPIKeyServiceServer) ListAPIKeys(context.Context, *ListAPIKeysRequest) (*ListAPIKeysResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedAPIKeyServiceServer) ValidateAPIKey(context.Context, *ValidateAPIKeyRequest) (*ValidateAPIKeyResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }

func RegisterAPIKeyServiceServer(s *grpc.Server, srv APIKeyServiceServer) {
	s.RegisterService(&APIKeyService_ServiceDesc, srv)
}

var APIKeyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: APIKeyService_ServiceName,
	HandlerType: (*APIKeyServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams:     []grpc.StreamDesc{},
}

// ---- ServiceAccountService ----

const ServiceAccountService_ServiceName = "authz.v1.ServiceAccountService"

type ServiceAccountServiceServer interface {
	CreateServiceAccount(context.Context, *CreateServiceAccountRequest) (*CreateServiceAccountResponse, error)
	GetServiceAccount(context.Context, *GetServiceAccountRequest) (*GetServiceAccountResponse, error)
	UpdateServiceAccount(context.Context, *UpdateServiceAccountRequest) (*UpdateServiceAccountResponse, error)
	DeleteServiceAccount(context.Context, *DeleteServiceAccountRequest) (*DeleteServiceAccountResponse, error)
	ListServiceAccounts(context.Context, *ListServiceAccountsRequest) (*ListServiceAccountsResponse, error)
	CreateServiceAccountKey(context.Context, *CreateServiceAccountKeyRequest) (*CreateServiceAccountKeyResponse, error)
	RevokeServiceAccountKey(context.Context, *RevokeServiceAccountKeyRequest) (*RevokeServiceAccountKeyResponse, error)
	ListServiceAccountKeys(context.Context, *ListServiceAccountKeysRequest) (*ListServiceAccountKeysResponse, error)
	AssignRole(context.Context, *AssignServiceAccountRoleRequest) (*AssignServiceAccountRoleResponse, error)
	RevokeRole(context.Context, *RevokeServiceAccountRoleRequest) (*RevokeServiceAccountRoleResponse, error)
}

type UnimplementedServiceAccountServiceServer struct{}

func (UnimplementedServiceAccountServiceServer) CreateServiceAccount(context.Context, *CreateServiceAccountRequest) (*CreateServiceAccountResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) GetServiceAccount(context.Context, *GetServiceAccountRequest) (*GetServiceAccountResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) UpdateServiceAccount(context.Context, *UpdateServiceAccountRequest) (*UpdateServiceAccountResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) DeleteServiceAccount(context.Context, *DeleteServiceAccountRequest) (*DeleteServiceAccountResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) ListServiceAccounts(context.Context, *ListServiceAccountsRequest) (*ListServiceAccountsResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) CreateServiceAccountKey(context.Context, *CreateServiceAccountKeyRequest) (*CreateServiceAccountKeyResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) RevokeServiceAccountKey(context.Context, *RevokeServiceAccountKeyRequest) (*RevokeServiceAccountKeyResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) ListServiceAccountKeys(context.Context, *ListServiceAccountKeysRequest) (*ListServiceAccountKeysResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) AssignRole(context.Context, *AssignServiceAccountRoleRequest) (*AssignServiceAccountRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }
func (UnimplementedServiceAccountServiceServer) RevokeRole(context.Context, *RevokeServiceAccountRoleRequest) (*RevokeServiceAccountRoleResponse, error) { return nil, status.Errorf(codes.Unimplemented, "not implemented") }

func RegisterServiceAccountServiceServer(s *grpc.Server, srv ServiceAccountServiceServer) {
	s.RegisterService(&ServiceAccountService_ServiceDesc, srv)
}

var ServiceAccountService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceAccountService_ServiceName,
	HandlerType: (*ServiceAccountServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams:     []grpc.StreamDesc{},
}
