package authlayerv1

type CreateTeamRequest struct {
	OrgId string `json:"org_id,omitempty"`
	Name  string `json:"name,omitempty"`
}

type CreateTeamResponse struct {
	Team *TeamInfo `json:"team,omitempty"`
}

type GetTeamRequest struct {
	TeamId string `json:"team_id,omitempty"`
}

type GetTeamResponse struct {
	Team *TeamInfo `json:"team,omitempty"`
}

type UpdateTeamRequest struct {
	TeamId string  `json:"team_id,omitempty"`
	Name   *string `json:"name,omitempty"`
}

type UpdateTeamResponse struct {
	Team *TeamInfo `json:"team,omitempty"`
}

type DeleteTeamRequest struct {
	TeamId string `json:"team_id,omitempty"`
}

type DeleteTeamResponse struct{}

type ListTeamsRequest struct {
	OrgId      string             `json:"org_id,omitempty"`
	Pagination *PaginationRequest `json:"pagination,omitempty"`
}

type ListTeamsResponse struct {
	Teams      []*TeamInfo         `json:"teams,omitempty"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}

type AddTeamMemberRequest struct {
	TeamId string `json:"team_id,omitempty"`
	UserId string `json:"user_id,omitempty"`
	RoleId string `json:"role_id,omitempty"`
}

type AddTeamMemberResponse struct{}

type RemoveTeamMemberRequest struct {
	TeamId string `json:"team_id,omitempty"`
	UserId string `json:"user_id,omitempty"`
}

type RemoveTeamMemberResponse struct{}

type ListTeamMembersRequest struct {
	TeamId     string             `json:"team_id,omitempty"`
	Pagination *PaginationRequest `json:"pagination,omitempty"`
}

type ListTeamMembersResponse struct {
	Members    []*MemberInfo       `json:"members,omitempty"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}
