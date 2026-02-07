package authzv1

type GetUserRequest struct {
	UserId string `json:"user_id,omitempty"`
}

type GetUserResponse struct {
	User *UserInfo `json:"user,omitempty"`
}

type UpdateUserRequest struct {
	UserId string  `json:"user_id,omitempty"`
	Name   *string `json:"name,omitempty"`
	Avatar *string `json:"avatar,omitempty"`
}

type UpdateUserResponse struct {
	User *UserInfo `json:"user,omitempty"`
}

type DeleteUserRequest struct {
	UserId string `json:"user_id,omitempty"`
}

type DeleteUserResponse struct{}

type ListUsersRequest struct {
	Pagination *PaginationRequest `json:"pagination,omitempty"`
	Search     *string            `json:"search,omitempty"`
	Status     *UserStatus        `json:"status,omitempty"`
}

type ListUsersResponse struct {
	Users      []*UserInfo         `json:"users,omitempty"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password,omitempty"`
	NewPassword     string `json:"new_password,omitempty"`
}

type ChangePasswordResponse struct{}
