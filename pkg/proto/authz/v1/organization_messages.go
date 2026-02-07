package authzv1

type CreateOrganizationRequest struct {
	Name string `json:"name,omitempty"`
	Slug string `json:"slug,omitempty"`
}

type CreateOrganizationResponse struct {
	Organization *OrganizationInfo `json:"organization,omitempty"`
}

type GetOrganizationRequest struct {
	// Use Id or Slug (oneof in proto)
	Id   string `json:"id,omitempty"`
	Slug string `json:"slug,omitempty"`
}

type GetOrganizationResponse struct {
	Organization *OrganizationInfo `json:"organization,omitempty"`
}

type UpdateOrganizationRequest struct {
	OrgId string  `json:"org_id,omitempty"`
	Name  *string `json:"name,omitempty"`
	Slug  *string `json:"slug,omitempty"`
}

type UpdateOrganizationResponse struct {
	Organization *OrganizationInfo `json:"organization,omitempty"`
}

type DeleteOrganizationRequest struct {
	OrgId string `json:"org_id,omitempty"`
}

type DeleteOrganizationResponse struct{}

type ListOrganizationsRequest struct {
	Pagination *PaginationRequest `json:"pagination,omitempty"`
}

type ListOrganizationsResponse struct {
	Organizations []*OrganizationInfo `json:"organizations,omitempty"`
	Pagination    *PaginationResponse `json:"pagination,omitempty"`
}

type ListOrgMembersRequest struct {
	OrgId      string             `json:"org_id,omitempty"`
	Pagination *PaginationRequest `json:"pagination,omitempty"`
}

type ListOrgMembersResponse struct {
	Members    []*MemberInfo       `json:"members,omitempty"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}

type InviteMemberRequest struct {
	OrgId  string `json:"org_id,omitempty"`
	Email  string `json:"email,omitempty"`
	RoleId string `json:"role_id,omitempty"`
}

type InviteMemberResponse struct {
	InvitationId string `json:"invitation_id,omitempty"`
}

type AcceptInvitationRequest struct {
	Token string `json:"token,omitempty"`
}

type AcceptInvitationResponse struct {
	Organization *OrganizationInfo `json:"organization,omitempty"`
}

type RemoveOrgMemberRequest struct {
	OrgId  string `json:"org_id,omitempty"`
	UserId string `json:"user_id,omitempty"`
}

type RemoveOrgMemberResponse struct{}

type UpdateOrgMemberRoleRequest struct {
	OrgId  string `json:"org_id,omitempty"`
	UserId string `json:"user_id,omitempty"`
	RoleId string `json:"role_id,omitempty"`
}

type UpdateOrgMemberRoleResponse struct{}
