package oauth

import (
	"context"

	"authz-go/internal/config"
)

// NewGoogleProvider creates an OIDC provider pre-configured for Google.
func NewGoogleProvider(ctx context.Context, cfg config.OAuthProviderConfig) (*OIDCProvider, error) {
	if cfg.IssuerURL == "" {
		cfg.IssuerURL = "https://accounts.google.com"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	return NewOIDCProvider(ctx, "google", cfg)
}
