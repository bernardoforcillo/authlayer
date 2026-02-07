package oauth

import "context"

// UserInfo is the normalized user information returned by any OAuth provider.
type UserInfo struct {
	ProviderID    string
	Email         string
	Name          string
	Avatar        string
	EmailVerified bool
	RawClaims     map[string]interface{}
}

// Provider is the pluggable interface for OAuth/OIDC providers.
type Provider interface {
	// Name returns the provider identifier (e.g., "google", "github").
	Name() string

	// GetAuthorizationURL returns the OAuth authorization URL for redirect.
	GetAuthorizationURL(state string, redirectURI string) string

	// ExchangeCode exchanges an authorization code for user information.
	ExchangeCode(ctx context.Context, code string, redirectURI string) (*UserInfo, error)
}
