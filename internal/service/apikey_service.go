package service

import (
	"context"
	"encoding/json"
	"time"

	"authz-go/internal/auth"
	"authz-go/internal/middleware"
	"authz-go/internal/model"
	"authz-go/internal/repository"
	authzv1 "authz-go/pkg/proto/authz/v1"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type APIKeyService struct {
	authzv1.UnimplementedAPIKeyServiceServer

	apiKeyRepo repository.APIKeyRepository
	logger     *zap.Logger
}

func NewAPIKeyService(apiKeyRepo repository.APIKeyRepository, logger *zap.Logger) *APIKeyService {
	return &APIKeyService{
		apiKeyRepo: apiKeyRepo,
		logger:     logger,
	}
}

func (s *APIKeyService) CreateAPIKey(ctx context.Context, req *authzv1.CreateAPIKeyRequest) (*authzv1.CreateAPIKeyResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}

	// Generate random key
	plainKey, err := auth.GenerateRandomToken(32)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key")
	}

	scopesJSON, _ := json.Marshal(req.Scopes)

	apiKey := &model.APIKey{
		UserID:    callerID,
		Name:      req.Name,
		KeyPrefix: plainKey[:8],
		KeyHash:   auth.HashToken(plainKey),
		Scopes:    string(scopesJSON),
	}

	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		apiKey.ExpiresAt = &t
	}

	if err := s.apiKeyRepo.Create(ctx, apiKey); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create API key")
	}

	return &authzv1.CreateAPIKeyResponse{
		ApiKey:       apiKeyToProto(apiKey),
		PlainTextKey: plainKey,
	}, nil
}

func (s *APIKeyService) RevokeAPIKey(ctx context.Context, req *authzv1.RevokeAPIKeyRequest) (*authzv1.RevokeAPIKeyResponse, error) {
	id, err := uuid.Parse(req.ApiKeyId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid api_key_id")
	}

	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	// Verify ownership
	key, err := s.apiKeyRepo.GetByID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "API key not found")
	}
	if key.UserID != callerID {
		return nil, status.Errorf(codes.PermissionDenied, "cannot revoke another user's key")
	}

	if err := s.apiKeyRepo.Revoke(ctx, id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke API key")
	}

	return &authzv1.RevokeAPIKeyResponse{}, nil
}

func (s *APIKeyService) ListAPIKeys(ctx context.Context, req *authzv1.ListAPIKeysRequest) (*authzv1.ListAPIKeysResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	pagination := repository.Pagination{PageSize: 20}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	keys, total, err := s.apiKeyRepo.ListByUserID(ctx, callerID, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list API keys")
	}

	protoKeys := make([]*authzv1.APIKeyInfo, len(keys))
	for i, k := range keys {
		protoKeys[i] = apiKeyToProto(&k)
	}

	return &authzv1.ListAPIKeysResponse{
		ApiKeys: protoKeys,
		Pagination: &authzv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func (s *APIKeyService) ValidateAPIKey(ctx context.Context, req *authzv1.ValidateAPIKeyRequest) (*authzv1.ValidateAPIKeyResponse, error) {
	if req.Key == "" {
		return nil, status.Errorf(codes.InvalidArgument, "key is required")
	}

	keyHash := auth.HashToken(req.Key)
	key, err := s.apiKeyRepo.GetByKeyHash(ctx, keyHash)
	if err != nil {
		return &authzv1.ValidateAPIKeyResponse{Valid: false}, nil
	}

	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		return &authzv1.ValidateAPIKeyResponse{Valid: false}, nil
	}

	var scopes []string
	if key.Scopes != "" {
		_ = json.Unmarshal([]byte(key.Scopes), &scopes)
	}

	userID := key.UserID.String()
	return &authzv1.ValidateAPIKeyResponse{
		Valid:  true,
		UserId: &userID,
		Scopes: scopes,
	}, nil
}

func apiKeyToProto(k *model.APIKey) *authzv1.APIKeyInfo {
	info := &authzv1.APIKeyInfo{
		Id:        k.ID.String(),
		Name:      k.Name,
		KeyPrefix: k.KeyPrefix,
		CreatedAt: timestamppb.New(k.CreatedAt),
	}

	var scopes []string
	if k.Scopes != "" {
		_ = json.Unmarshal([]byte(k.Scopes), &scopes)
	}
	info.Scopes = scopes

	if k.ExpiresAt != nil {
		info.ExpiresAt = timestamppb.New(*k.ExpiresAt)
	}
	if k.LastUsedAt != nil {
		info.LastUsedAt = timestamppb.New(*k.LastUsedAt)
	}
	return info
}

// Suppress unused import
var _ = time.Now
