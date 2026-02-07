package authlayerv1

import "google.golang.org/protobuf/types/known/timestamppb"

// Ensure timestamppb is used
var _ = timestamppb.Now

type RegisterRequest struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
}

type RegisterResponse struct {
	User   *UserInfo  `json:"user,omitempty"`
	Tokens *TokenPair `json:"tokens,omitempty"`
}

type LoginRequest struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

type LoginResponse struct {
	User   *UserInfo  `json:"user,omitempty"`
	Tokens *TokenPair `json:"tokens,omitempty"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
}

type LogoutResponse struct{}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
}

type RefreshTokenResponse struct {
	Tokens *TokenPair `json:"tokens,omitempty"`
}

type VerifyEmailRequest struct {
	Token string `json:"token,omitempty"`
}

type VerifyEmailResponse struct {
	Verified bool `json:"verified,omitempty"`
}

type RequestPasswordResetRequest struct {
	Email string `json:"email,omitempty"`
}

type RequestPasswordResetResponse struct{}

type ResetPasswordRequest struct {
	Token       string `json:"token,omitempty"`
	NewPassword string `json:"new_password,omitempty"`
}

type ResetPasswordResponse struct{}

type GetOAuthURLRequest struct {
	Provider    string `json:"provider,omitempty"`
	RedirectUri string `json:"redirect_uri,omitempty"`
}

type GetOAuthURLResponse struct {
	AuthorizationUrl string `json:"authorization_url,omitempty"`
	State            string `json:"state,omitempty"`
}

type OAuthCallbackRequest struct {
	Provider    string `json:"provider,omitempty"`
	Code        string `json:"code,omitempty"`
	State       string `json:"state,omitempty"`
	RedirectUri string `json:"redirect_uri,omitempty"`
}

type OAuthCallbackResponse struct {
	User      *UserInfo  `json:"user,omitempty"`
	Tokens    *TokenPair `json:"tokens,omitempty"`
	IsNewUser bool       `json:"is_new_user,omitempty"`
}
