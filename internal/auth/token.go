package auth

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// TokenPair holds an access/refresh token pair with expiration times.
type TokenPair struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	TokenFamily           string
}

// GenerateRandomToken generates a cryptographically random base64url-encoded token.
func GenerateRandomToken(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
