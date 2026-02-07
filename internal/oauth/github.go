package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"authz-go/internal/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubProvider implements the Provider interface for GitHub.
// GitHub does not support standard OIDC discovery, so this uses
// GitHub's REST API to fetch user information.
type GitHubProvider struct {
	oauth2Config oauth2.Config
}

// NewGitHubProvider creates a new GitHub OAuth provider.
func NewGitHubProvider(cfg config.OAuthProviderConfig) *GitHubProvider {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"user:email", "read:user"}
	}
	return &GitHubProvider{
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     github.Endpoint,
			Scopes:       scopes,
		},
	}
}

func (p *GitHubProvider) Name() string {
	return "github"
}

func (p *GitHubProvider) GetAuthorizationURL(state string, redirectURI string) string {
	cfg := p.oauth2Config
	if redirectURI != "" {
		cfg.RedirectURL = redirectURI
	}
	return cfg.AuthCodeURL(state)
}

func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string, redirectURI string) (*UserInfo, error) {
	cfg := p.oauth2Config
	if redirectURI != "" {
		cfg.RedirectURL = redirectURI
	}

	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	client := cfg.Client(ctx, token)

	// Fetch user profile
	userResp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userResp.Body)
		return nil, fmt.Errorf("github: user API returned %d: %s", userResp.StatusCode, body)
	}

	var ghUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&ghUser); err != nil {
		return nil, err
	}

	// If email is empty, fetch from emails API
	email := ghUser.Email
	if email == "" {
		email, err = p.fetchPrimaryEmail(ctx, client)
		if err != nil {
			return nil, err
		}
	}

	name := ghUser.Name
	if name == "" {
		name = ghUser.Login
	}

	return &UserInfo{
		ProviderID:    fmt.Sprintf("%d", ghUser.ID),
		Email:         email,
		Name:          name,
		Avatar:        ghUser.AvatarURL,
		EmailVerified: true, // GitHub verifies emails
		RawClaims: map[string]interface{}{
			"login": ghUser.Login,
			"id":    ghUser.ID,
		},
	}, nil
}

func (p *GitHubProvider) fetchPrimaryEmail(ctx context.Context, client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("github: no email found")
}
