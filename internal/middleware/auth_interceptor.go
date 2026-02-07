package middleware

import (
	"context"
	"encoding/json"
	"strings"

	"authz-go/internal/auth"
	"authz-go/internal/repository"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthInterceptor validates JWT Bearer tokens, API keys, and service account keys.
type AuthInterceptor struct {
	jwtManager *auth.JWTManager
	apiKeyRepo repository.APIKeyRepository
	saKeyRepo  repository.ServiceAccountKeyRepository
	publicMethods map[string]bool
}

// NewAuthInterceptor creates a new authentication interceptor.
func NewAuthInterceptor(
	jwtManager *auth.JWTManager,
	apiKeyRepo repository.APIKeyRepository,
	saKeyRepo repository.ServiceAccountKeyRepository,
	publicMethods []string,
) *AuthInterceptor {
	pm := make(map[string]bool)
	for _, m := range publicMethods {
		pm[m] = true
	}
	return &AuthInterceptor{
		jwtManager:    jwtManager,
		apiKeyRepo:    apiKeyRepo,
		saKeyRepo:     saKeyRepo,
		publicMethods: pm,
	}
}

// UnaryServerInterceptor returns a gRPC unary interceptor for authentication.
func (i *AuthInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if i.publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		newCtx, err := i.authenticate(ctx)
		if err != nil {
			return nil, err
		}

		return handler(newCtx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream interceptor for authentication.
func (i *AuthInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if i.publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		_, err := i.authenticate(ss.Context())
		if err != nil {
			return err
		}

		return handler(srv, ss)
	}
}

func (i *AuthInterceptor) authenticate(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing authorization header")
	}

	authHeader := values[0]

	// JWT Bearer token
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := i.jwtManager.ValidateAccessToken(token)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid user ID in token")
		}
		return SetUserInContext(ctx, userID, claims.Email), nil
	}

	// API Key (user)
	if strings.HasPrefix(authHeader, "ApiKey ") {
		key := strings.TrimPrefix(authHeader, "ApiKey ")
		keyHash := auth.HashToken(key)

		apiKey, err := i.apiKeyRepo.GetByKeyHash(ctx, keyHash)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid API key")
		}

		if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(timeNow()) {
			return nil, status.Errorf(codes.Unauthenticated, "API key expired")
		}

		// Update last used (fire and forget)
		go func() { _ = i.apiKeyRepo.UpdateLastUsed(context.Background(), apiKey.ID) }()

		var scopes []string
		if apiKey.Scopes != "" {
			_ = json.Unmarshal([]byte(apiKey.Scopes), &scopes)
		}
		return SetAPIKeyInContext(ctx, apiKey.UserID, scopes), nil
	}

	// Service Account Key
	if strings.HasPrefix(authHeader, "ServiceKey ") {
		key := strings.TrimPrefix(authHeader, "ServiceKey ")
		keyHash := auth.HashToken(key)

		saKey, err := i.saKeyRepo.GetByKeyHash(ctx, keyHash)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid service account key")
		}

		if saKey.ExpiresAt != nil && saKey.ExpiresAt.Before(timeNow()) {
			return nil, status.Errorf(codes.Unauthenticated, "service account key expired")
		}

		if saKey.ServiceAccount.Status != "active" {
			return nil, status.Errorf(codes.PermissionDenied, "service account is disabled")
		}

		go func() { _ = i.saKeyRepo.UpdateLastUsed(context.Background(), saKey.ID) }()

		return SetServiceAccountInContext(ctx, saKey.ServiceAccountID), nil
	}

	return nil, status.Errorf(codes.Unauthenticated, "unsupported authorization scheme")
}
