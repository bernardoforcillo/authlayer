package config

import (
	"encoding/json"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration, populated from environment variables.
type Config struct {
	// Server
	GRPCPort    int    `env:"GRPC_PORT" envDefault:"50051"`
	Environment string `env:"ENVIRONMENT" envDefault:"development"`

	// Database
	DatabaseURL string `env:"DATABASE_URL,required"`

	// JWT
	JWTAccessSecret      string        `env:"JWT_ACCESS_SECRET,required"`
	JWTRefreshSecret     string        `env:"JWT_REFRESH_SECRET,required"`
	JWTAccessExpiration  time.Duration `env:"JWT_ACCESS_EXPIRATION" envDefault:"15m"`
	JWTRefreshExpiration time.Duration `env:"JWT_REFRESH_EXPIRATION" envDefault:"168h"`

	// OAuth providers as JSON string
	OAuthProvidersJSON string `env:"OAUTH_PROVIDERS" envDefault:"{}"`

	// Rate Limiting
	RateLimitPerSecond int `env:"RATE_LIMIT_PER_SECOND" envDefault:"100"`

	// Logging
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`

	// Parsed OAuth providers (not from env directly)
	OAuthProviders map[string]OAuthProviderConfig `env:"-"`
}

// OAuthProviderConfig holds configuration for a single OAuth/OIDC provider.
type OAuthProviderConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	IssuerURL    string   `json:"issuer_url"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}

// Load parses environment variables and returns a Config.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}

	// Parse OAuth providers JSON
	cfg.OAuthProviders = make(map[string]OAuthProviderConfig)
	if cfg.OAuthProvidersJSON != "" && cfg.OAuthProvidersJSON != "{}" {
		if err := json.Unmarshal([]byte(cfg.OAuthProvidersJSON), &cfg.OAuthProviders); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}
