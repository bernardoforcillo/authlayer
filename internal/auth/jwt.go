package auth

import (
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

// Claims extends jwt.RegisteredClaims with application-specific fields.
type Claims struct {
	jwt.RegisteredClaims
	UserID      string `json:"uid"`
	Email       string `json:"email"`
	TokenType   string `json:"type"`   // "access" or "refresh"
	TokenFamily string `json:"family"` // for refresh token rotation detection
}

// JWTManager handles JWT token generation and validation.
type JWTManager struct {
	accessSecret      []byte
	refreshSecret     []byte
	accessExpiration  time.Duration
	refreshExpiration time.Duration
}

// NewJWTManager creates a new JWTManager from config.
func NewJWTManager(cfg *config.Config) *JWTManager {
	return &JWTManager{
		accessSecret:      []byte(cfg.JWTAccessSecret),
		refreshSecret:     []byte(cfg.JWTRefreshSecret),
		accessExpiration:  cfg.JWTAccessExpiration,
		refreshExpiration: cfg.JWTRefreshExpiration,
	}
}

// GenerateTokenPair creates a new access + refresh token pair.
func (m *JWTManager) GenerateTokenPair(userID, email, tokenFamily string) (*TokenPair, error) {
	if tokenFamily == "" {
		tokenFamily = uuid.New().String()
	}

	now := time.Now()
	accessExp := now.Add(m.accessExpiration)
	refreshExp := now.Add(m.refreshExpiration)

	// Access token
	accessClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			ID:        uuid.New().String(),
		},
		UserID:      userID,
		Email:       email,
		TokenType:   "access",
		TokenFamily: tokenFamily,
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(m.accessSecret)
	if err != nil {
		return nil, err
	}

	// Refresh token
	refreshClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			ID:        uuid.New().String(),
		},
		UserID:      userID,
		Email:       email,
		TokenType:   "refresh",
		TokenFamily: tokenFamily,
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(m.refreshSecret)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExp,
		RefreshTokenExpiresAt: refreshExp,
		TokenFamily:           tokenFamily,
	}, nil
}

// ValidateAccessToken validates an access JWT and returns its claims.
func (m *JWTManager) ValidateAccessToken(tokenStr string) (*Claims, error) {
	return m.validateToken(tokenStr, m.accessSecret, "access")
}

// ValidateRefreshToken validates a refresh JWT and returns its claims.
func (m *JWTManager) ValidateRefreshToken(tokenStr string) (*Claims, error) {
	return m.validateToken(tokenStr, m.refreshSecret, "refresh")
}

func (m *JWTManager) validateToken(tokenStr string, secret []byte, expectedType string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.TokenType != expectedType {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
