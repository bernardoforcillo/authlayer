package middleware

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

type contextKey string

const (
	userIDKey         contextKey = "user_id"
	userEmailKey      contextKey = "user_email"
	apiScopesKey      contextKey = "api_scopes"
	serviceAccountKey contextKey = "service_account_id"
	authTypeKey       contextKey = "auth_type"
)

// AuthType indicates how the request was authenticated.
type AuthType string

const (
	AuthTypeUser           AuthType = "user"
	AuthTypeAPIKey         AuthType = "apikey"
	AuthTypeServiceAccount AuthType = "service_account"
)

var (
	ErrNoUserInContext = errors.New("no user in context")
)

// UserIDFromContext extracts the user ID from context.
func UserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value(userIDKey)
	if val == nil {
		return uuid.Nil, ErrNoUserInContext
	}
	id, ok := val.(uuid.UUID)
	if !ok {
		return uuid.Nil, ErrNoUserInContext
	}
	return id, nil
}

// UserEmailFromContext extracts the user email from context.
func UserEmailFromContext(ctx context.Context) string {
	val := ctx.Value(userEmailKey)
	if val == nil {
		return ""
	}
	email, _ := val.(string)
	return email
}

// AuthTypeFromContext returns how the request was authenticated.
func AuthTypeFromContext(ctx context.Context) AuthType {
	val := ctx.Value(authTypeKey)
	if val == nil {
		return ""
	}
	at, _ := val.(AuthType)
	return at
}

// ServiceAccountIDFromContext extracts the service account ID from context.
func ServiceAccountIDFromContext(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value(serviceAccountKey)
	if val == nil {
		return uuid.Nil, errors.New("no service account in context")
	}
	id, ok := val.(uuid.UUID)
	if !ok {
		return uuid.Nil, errors.New("invalid service account ID in context")
	}
	return id, nil
}

// SetUserInContext stores user info in context.
func SetUserInContext(ctx context.Context, userID uuid.UUID, email string) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	ctx = context.WithValue(ctx, userEmailKey, email)
	ctx = context.WithValue(ctx, authTypeKey, AuthTypeUser)
	return ctx
}

// SetAPIKeyInContext stores API key auth info in context.
func SetAPIKeyInContext(ctx context.Context, userID uuid.UUID, scopes []string) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	ctx = context.WithValue(ctx, apiScopesKey, scopes)
	ctx = context.WithValue(ctx, authTypeKey, AuthTypeAPIKey)
	return ctx
}

// SetServiceAccountInContext stores service account auth info in context.
func SetServiceAccountInContext(ctx context.Context, saID uuid.UUID) context.Context {
	ctx = context.WithValue(ctx, serviceAccountKey, saID)
	ctx = context.WithValue(ctx, authTypeKey, AuthTypeServiceAccount)
	return ctx
}
