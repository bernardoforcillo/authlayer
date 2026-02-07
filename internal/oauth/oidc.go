package oauth

import (
	"context"

	"authz-go/internal/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider is a generic OIDC provider that works with any standard OIDC-compliant
// identity provider (Google, Azure AD, Okta, Auth0, Keycloak, etc.).
type OIDCProvider struct {
	name         string
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// NewOIDCProvider creates a new OIDC provider using OIDC discovery.
func NewOIDCProvider(ctx context.Context, name string, cfg config.OAuthProviderConfig) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	if len(oauth2Cfg.Scopes) == 0 {
		oauth2Cfg.Scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return &OIDCProvider{
		name:         name,
		oauth2Config: oauth2Cfg,
		verifier:     verifier,
	}, nil
}

func (p *OIDCProvider) Name() string {
	return p.name
}

func (p *OIDCProvider) GetAuthorizationURL(state string, redirectURI string) string {
	cfg := p.oauth2Config
	if redirectURI != "" {
		cfg.RedirectURL = redirectURI
	}
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string, redirectURI string) (*UserInfo, error) {
	cfg := p.oauth2Config
	if redirectURI != "" {
		cfg.RedirectURL = redirectURI
	}

	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, ErrNoIDToken
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Sub           string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	rawClaims := make(map[string]interface{})
	_ = idToken.Claims(&rawClaims)

	return &UserInfo{
		ProviderID:    claims.Sub,
		Email:         claims.Email,
		Name:          claims.Name,
		Avatar:        claims.Picture,
		EmailVerified: claims.EmailVerified,
		RawClaims:     rawClaims,
	}, nil
}
