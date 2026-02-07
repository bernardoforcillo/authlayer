package authlayerv1

import "google.golang.org/protobuf/types/known/timestamppb"

type CreateServiceAccountRequest struct {
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	OrgId       string `json:"org_id,omitempty"`
}

type CreateServiceAccountResponse struct {
	ServiceAccount *ServiceAccountInfo `json:"service_account,omitempty"`
}

type GetServiceAccountRequest struct {
	ServiceAccountId string `json:"service_account_id,omitempty"`
}

type GetServiceAccountResponse struct {
	ServiceAccount *ServiceAccountInfo `json:"service_account,omitempty"`
}

type UpdateServiceAccountRequest struct {
	ServiceAccountId string                `json:"service_account_id,omitempty"`
	DisplayName      *string               `json:"display_name,omitempty"`
	Description      *string               `json:"description,omitempty"`
	Status           *ServiceAccountStatus `json:"status,omitempty"`
}

type UpdateServiceAccountResponse struct {
	ServiceAccount *ServiceAccountInfo `json:"service_account,omitempty"`
}

type DeleteServiceAccountRequest struct {
	ServiceAccountId string `json:"service_account_id,omitempty"`
}

type DeleteServiceAccountResponse struct{}

type ListServiceAccountsRequest struct {
	OrgId      string             `json:"org_id,omitempty"`
	Pagination *PaginationRequest `json:"pagination,omitempty"`
}

type ListServiceAccountsResponse struct {
	ServiceAccounts []*ServiceAccountInfo `json:"service_accounts,omitempty"`
	Pagination      *PaginationResponse   `json:"pagination,omitempty"`
}

type CreateServiceAccountKeyRequest struct {
	ServiceAccountId string                 `json:"service_account_id,omitempty"`
	Name             string                 `json:"name,omitempty"`
	ExpiresAt        *timestamppb.Timestamp `json:"expires_at,omitempty"`
}

type CreateServiceAccountKeyResponse struct {
	KeyInfo      *ServiceAccountKeyInfo `json:"key_info,omitempty"`
	PlainTextKey string                 `json:"plain_text_key,omitempty"`
}

type RevokeServiceAccountKeyRequest struct {
	KeyId string `json:"key_id,omitempty"`
}

type RevokeServiceAccountKeyResponse struct{}

type ListServiceAccountKeysRequest struct {
	ServiceAccountId string             `json:"service_account_id,omitempty"`
	Pagination       *PaginationRequest `json:"pagination,omitempty"`
}

type ListServiceAccountKeysResponse struct {
	Keys       []*ServiceAccountKeyInfo `json:"keys,omitempty"`
	Pagination *PaginationResponse      `json:"pagination,omitempty"`
}

type AssignServiceAccountRoleRequest struct {
	ServiceAccountId string `json:"service_account_id,omitempty"`
	RoleId           string `json:"role_id,omitempty"`
	OrgId            string `json:"org_id,omitempty"`
}

type AssignServiceAccountRoleResponse struct{}

type RevokeServiceAccountRoleRequest struct {
	ServiceAccountId string `json:"service_account_id,omitempty"`
	RoleId           string `json:"role_id,omitempty"`
	OrgId            string `json:"org_id,omitempty"`
}

type RevokeServiceAccountRoleResponse struct{}
