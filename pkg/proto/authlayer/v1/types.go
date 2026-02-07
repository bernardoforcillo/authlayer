// Package authlayerv1 contains the generated protobuf and gRPC types for the authz API.
// This file provides hand-written stubs that mirror what protoc-gen-go would generate.
// Replace these with actual generated code by running: buf generate
package authlayerv1

import (
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Re-export for convenience.
var _ = timestamppb.Now

// ---- Common types ----

type PaginationRequest struct {
	PageSize  int32  `protobuf:"varint,1,opt,name=page_size" json:"page_size,omitempty"`
	PageToken string `protobuf:"bytes,2,opt,name=page_token" json:"page_token,omitempty"`
}

type PaginationResponse struct {
	NextPageToken string `protobuf:"bytes,1,opt,name=next_page_token" json:"next_page_token,omitempty"`
	TotalCount    int32  `protobuf:"varint,2,opt,name=total_count" json:"total_count,omitempty"`
}

type UserStatus int32

const (
	UserStatus_USER_STATUS_UNSPECIFIED UserStatus = 0
	UserStatus_USER_STATUS_ACTIVE      UserStatus = 1
	UserStatus_USER_STATUS_INACTIVE    UserStatus = 2
	UserStatus_USER_STATUS_BANNED      UserStatus = 3
)

type UserInfo struct {
	Id            string                 `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	Email         string                 `protobuf:"bytes,2,opt,name=email" json:"email,omitempty"`
	Name          string                 `protobuf:"bytes,3,opt,name=name" json:"name,omitempty"`
	Avatar        *string                `protobuf:"bytes,4,opt,name=avatar" json:"avatar,omitempty"`
	EmailVerified bool                   `protobuf:"varint,5,opt,name=email_verified" json:"email_verified,omitempty"`
	Status        UserStatus             `protobuf:"varint,6,opt,name=status" json:"status,omitempty"`
	CreatedAt     *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=created_at" json:"created_at,omitempty"`
	UpdatedAt     *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=updated_at" json:"updated_at,omitempty"`
}

type MemberInfo struct {
	UserId   string                 `protobuf:"bytes,1,opt,name=user_id" json:"user_id,omitempty"`
	Name     string                 `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
	Email    string                 `protobuf:"bytes,3,opt,name=email" json:"email,omitempty"`
	RoleId   string                 `protobuf:"bytes,4,opt,name=role_id" json:"role_id,omitempty"`
	RoleName string                 `protobuf:"bytes,5,opt,name=role_name" json:"role_name,omitempty"`
	JoinedAt *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=joined_at" json:"joined_at,omitempty"`
}

type TokenPair struct {
	AccessToken          string                 `protobuf:"bytes,1,opt,name=access_token" json:"access_token,omitempty"`
	RefreshToken         string                 `protobuf:"bytes,2,opt,name=refresh_token" json:"refresh_token,omitempty"`
	AccessTokenExpiresAt *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=access_token_expires_at" json:"access_token_expires_at,omitempty"`
	RefreshTokenExpiresAt *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=refresh_token_expires_at" json:"refresh_token_expires_at,omitempty"`
}

// ---- RBAC types ----

type RoleInfo struct {
	Id           string           `json:"id,omitempty"`
	Name         string           `json:"name,omitempty"`
	Description  *string          `json:"description,omitempty"`
	OrgId        *string          `json:"org_id,omitempty"`
	ParentRoleId *string          `json:"parent_role_id,omitempty"`
	Permissions  []*PermissionInfo `json:"permissions,omitempty"`
}

type PermissionInfo struct {
	Id          string  `json:"id,omitempty"`
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// ---- Organization types ----

type OrganizationInfo struct {
	Id        string                 `json:"id,omitempty"`
	Name      string                 `json:"name,omitempty"`
	Slug      string                 `json:"slug,omitempty"`
	OwnerId   string                 `json:"owner_id,omitempty"`
	CreatedAt *timestamppb.Timestamp `json:"created_at,omitempty"`
}

// ---- Team types ----

type TeamInfo struct {
	Id          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	OrgId       string `json:"org_id,omitempty"`
	MemberCount int32  `json:"member_count,omitempty"`
}

// ---- API Key types ----

type APIKeyInfo struct {
	Id         string                 `json:"id,omitempty"`
	Name       string                 `json:"name,omitempty"`
	KeyPrefix  string                 `json:"key_prefix,omitempty"`
	Scopes     []string               `json:"scopes,omitempty"`
	ExpiresAt  *timestamppb.Timestamp `json:"expires_at,omitempty"`
	LastUsedAt *timestamppb.Timestamp `json:"last_used_at,omitempty"`
	CreatedAt  *timestamppb.Timestamp `json:"created_at,omitempty"`
}

// ---- Service Account types ----

type ServiceAccountStatus int32

const (
	ServiceAccountStatus_SERVICE_ACCOUNT_STATUS_UNSPECIFIED ServiceAccountStatus = 0
	ServiceAccountStatus_SERVICE_ACCOUNT_STATUS_ACTIVE      ServiceAccountStatus = 1
	ServiceAccountStatus_SERVICE_ACCOUNT_STATUS_DISABLED    ServiceAccountStatus = 2
)

type ServiceAccountInfo struct {
	Id                  string                 `json:"id,omitempty"`
	DisplayName         string                 `json:"display_name,omitempty"`
	Description         string                 `json:"description,omitempty"`
	OrgId               string                 `json:"org_id,omitempty"`
	CreatedBy           string                 `json:"created_by,omitempty"`
	Status              ServiceAccountStatus   `json:"status,omitempty"`
	CreatedAt           *timestamppb.Timestamp `json:"created_at,omitempty"`
	UpdatedAt           *timestamppb.Timestamp `json:"updated_at,omitempty"`
	LastAuthenticatedAt *timestamppb.Timestamp `json:"last_authenticated_at,omitempty"`
	Roles               []*RoleInfo            `json:"roles,omitempty"`
}

type ServiceAccountKeyInfo struct {
	Id               string                 `json:"id,omitempty"`
	ServiceAccountId string                 `json:"service_account_id,omitempty"`
	KeyPrefix        string                 `json:"key_prefix,omitempty"`
	Name             string                 `json:"name,omitempty"`
	CreatedAt        *timestamppb.Timestamp `json:"created_at,omitempty"`
	ExpiresAt        *timestamppb.Timestamp `json:"expires_at,omitempty"`
	LastUsedAt       *timestamppb.Timestamp `json:"last_used_at,omitempty"`
	Revoked          bool                   `json:"revoked,omitempty"`
}
