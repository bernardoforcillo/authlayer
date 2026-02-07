package service

import (
	"context"
	"errors"

	"github.com/bernardoforcillo/authlayer/internal/auth"
	"github.com/bernardoforcillo/authlayer/internal/middleware"
	"github.com/bernardoforcillo/authlayer/internal/model"
	"github.com/bernardoforcillo/authlayer/internal/repository"
	authlayerv1 "github.com/bernardoforcillo/authlayer/pkg/proto/authlayer/v1"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type ServiceAccountService struct {
	authlayerv1.UnimplementedServiceAccountServiceServer

	saRepo     repository.ServiceAccountRepository
	saKeyRepo  repository.ServiceAccountKeyRepository
	saRoleRepo repository.ServiceAccountRoleRepository
	roleRepo   repository.RoleRepository
	logger     *zap.Logger
}

func NewServiceAccountService(
	saRepo repository.ServiceAccountRepository,
	saKeyRepo repository.ServiceAccountKeyRepository,
	saRoleRepo repository.ServiceAccountRoleRepository,
	roleRepo repository.RoleRepository,
	logger *zap.Logger,
) *ServiceAccountService {
	return &ServiceAccountService{
		saRepo:     saRepo,
		saKeyRepo:  saKeyRepo,
		saRoleRepo: saRoleRepo,
		roleRepo:   roleRepo,
		logger:     logger,
	}
}

func (s *ServiceAccountService) CreateServiceAccount(ctx context.Context, req *authlayerv1.CreateServiceAccountRequest) (*authlayerv1.CreateServiceAccountResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	if req.DisplayName == "" || req.OrgId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "display_name and org_id are required")
	}

	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	sa := &model.ServiceAccount{
		DisplayName: req.DisplayName,
		Description: req.Description,
		OrgID:       orgID,
		CreatedBy:   callerID,
		Status:      model.ServiceAccountStatusActive,
	}

	if err := s.saRepo.Create(ctx, sa); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create service account: %v", err)
	}

	return &authlayerv1.CreateServiceAccountResponse{
		ServiceAccount: serviceAccountToProto(sa),
	}, nil
}

func (s *ServiceAccountService) GetServiceAccount(ctx context.Context, req *authlayerv1.GetServiceAccountRequest) (*authlayerv1.GetServiceAccountResponse, error) {
	id, err := uuid.Parse(req.ServiceAccountId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid service_account_id")
	}

	sa, err := s.saRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "service account not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get service account")
	}

	return &authlayerv1.GetServiceAccountResponse{
		ServiceAccount: serviceAccountToProto(sa),
	}, nil
}

func (s *ServiceAccountService) UpdateServiceAccount(ctx context.Context, req *authlayerv1.UpdateServiceAccountRequest) (*authlayerv1.UpdateServiceAccountResponse, error) {
	id, err := uuid.Parse(req.ServiceAccountId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid service_account_id")
	}

	sa, err := s.saRepo.GetByID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "service account not found")
	}

	if req.DisplayName != nil {
		sa.DisplayName = *req.DisplayName
	}
	if req.Description != nil {
		sa.Description = *req.Description
	}
	if req.Status != nil {
		switch *req.Status {
		case authlayerv1.ServiceAccountStatus_SERVICE_ACCOUNT_STATUS_ACTIVE:
			sa.Status = model.ServiceAccountStatusActive
		case authlayerv1.ServiceAccountStatus_SERVICE_ACCOUNT_STATUS_DISABLED:
			sa.Status = model.ServiceAccountStatusDisabled
		}
	}

	if err := s.saRepo.Update(ctx, sa); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update service account")
	}

	return &authlayerv1.UpdateServiceAccountResponse{
		ServiceAccount: serviceAccountToProto(sa),
	}, nil
}

func (s *ServiceAccountService) DeleteServiceAccount(ctx context.Context, req *authlayerv1.DeleteServiceAccountRequest) (*authlayerv1.DeleteServiceAccountResponse, error) {
	id, err := uuid.Parse(req.ServiceAccountId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid service_account_id")
	}

	if err := s.saRepo.Delete(ctx, id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete service account")
	}

	return &authlayerv1.DeleteServiceAccountResponse{}, nil
}

func (s *ServiceAccountService) ListServiceAccounts(ctx context.Context, req *authlayerv1.ListServiceAccountsRequest) (*authlayerv1.ListServiceAccountsResponse, error) {
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	pagination := repository.Pagination{PageSize: 20}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	accounts, total, err := s.saRepo.ListByOrgID(ctx, orgID, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list service accounts")
	}

	protoAccounts := make([]*authlayerv1.ServiceAccountInfo, len(accounts))
	for i, sa := range accounts {
		protoAccounts[i] = serviceAccountToProto(&sa)
	}

	return &authlayerv1.ListServiceAccountsResponse{
		ServiceAccounts: protoAccounts,
		Pagination: &authlayerv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func (s *ServiceAccountService) CreateServiceAccountKey(ctx context.Context, req *authlayerv1.CreateServiceAccountKeyRequest) (*authlayerv1.CreateServiceAccountKeyResponse, error) {
	saID, err := uuid.Parse(req.ServiceAccountId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid service_account_id")
	}

	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name is required")
	}

	// Verify service account exists
	_, err = s.saRepo.GetByID(ctx, saID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "service account not found")
	}

	plainKey, err := auth.GenerateRandomToken(32)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key")
	}

	key := &model.ServiceAccountKey{
		ServiceAccountID: saID,
		Name:             req.Name,
		KeyPrefix:        plainKey[:8],
		KeyHash:          auth.HashToken(plainKey),
	}

	if req.ExpiresAt != nil {
		t := req.ExpiresAt.AsTime()
		key.ExpiresAt = &t
	}

	if err := s.saKeyRepo.Create(ctx, key); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create service account key")
	}

	return &authlayerv1.CreateServiceAccountKeyResponse{
		KeyInfo:      saKeyToProto(key),
		PlainTextKey: plainKey,
	}, nil
}

func (s *ServiceAccountService) RevokeServiceAccountKey(ctx context.Context, req *authlayerv1.RevokeServiceAccountKeyRequest) (*authlayerv1.RevokeServiceAccountKeyResponse, error) {
	id, err := uuid.Parse(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid key_id")
	}

	if err := s.saKeyRepo.Revoke(ctx, id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke key")
	}

	return &authlayerv1.RevokeServiceAccountKeyResponse{}, nil
}

func (s *ServiceAccountService) ListServiceAccountKeys(ctx context.Context, req *authlayerv1.ListServiceAccountKeysRequest) (*authlayerv1.ListServiceAccountKeysResponse, error) {
	saID, err := uuid.Parse(req.ServiceAccountId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid service_account_id")
	}

	pagination := repository.Pagination{PageSize: 20}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	keys, total, err := s.saKeyRepo.ListByServiceAccountID(ctx, saID, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list keys")
	}

	protoKeys := make([]*authlayerv1.ServiceAccountKeyInfo, len(keys))
	for i, k := range keys {
		protoKeys[i] = saKeyToProto(&k)
	}

	return &authlayerv1.ListServiceAccountKeysResponse{
		Keys: protoKeys,
		Pagination: &authlayerv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func (s *ServiceAccountService) AssignRole(ctx context.Context, req *authlayerv1.AssignServiceAccountRoleRequest) (*authlayerv1.AssignServiceAccountRoleResponse, error) {
	saID, err := uuid.Parse(req.ServiceAccountId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid service_account_id")
	}
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	sar := &model.ServiceAccountRole{
		ServiceAccountID: saID,
		RoleID:           roleID,
		OrgID:            orgID,
	}

	if err := s.saRoleRepo.Assign(ctx, sar); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to assign role: %v", err)
	}

	return &authlayerv1.AssignServiceAccountRoleResponse{}, nil
}

func (s *ServiceAccountService) RevokeRole(ctx context.Context, req *authlayerv1.RevokeServiceAccountRoleRequest) (*authlayerv1.RevokeServiceAccountRoleResponse, error) {
	saID, err := uuid.Parse(req.ServiceAccountId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid service_account_id")
	}
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	if err := s.saRoleRepo.Revoke(ctx, saID, roleID, orgID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke role")
	}

	return &authlayerv1.RevokeServiceAccountRoleResponse{}, nil
}

// ---- Converters ----

func serviceAccountToProto(sa *model.ServiceAccount) *authlayerv1.ServiceAccountInfo {
	info := &authlayerv1.ServiceAccountInfo{
		Id:          sa.ID.String(),
		DisplayName: sa.DisplayName,
		Description: sa.Description,
		OrgId:       sa.OrgID.String(),
		CreatedBy:   sa.CreatedBy.String(),
		CreatedAt:   timestamppb.New(sa.CreatedAt),
		UpdatedAt:   timestamppb.New(sa.UpdatedAt),
	}

	switch sa.Status {
	case model.ServiceAccountStatusActive:
		info.Status = authlayerv1.ServiceAccountStatus_SERVICE_ACCOUNT_STATUS_ACTIVE
	case model.ServiceAccountStatusDisabled:
		info.Status = authlayerv1.ServiceAccountStatus_SERVICE_ACCOUNT_STATUS_DISABLED
	}

	if sa.LastAuthenticatedAt != nil {
		info.LastAuthenticatedAt = timestamppb.New(*sa.LastAuthenticatedAt)
	}

	if len(sa.Roles) > 0 {
		info.Roles = make([]*authlayerv1.RoleInfo, len(sa.Roles))
		for i, r := range sa.Roles {
			info.Roles[i] = roleToProto(&r.Role)
		}
	}

	return info
}

func saKeyToProto(k *model.ServiceAccountKey) *authlayerv1.ServiceAccountKeyInfo {
	info := &authlayerv1.ServiceAccountKeyInfo{
		Id:               k.ID.String(),
		ServiceAccountId: k.ServiceAccountID.String(),
		KeyPrefix:        k.KeyPrefix,
		Name:             k.Name,
		CreatedAt:        timestamppb.New(k.CreatedAt),
		Revoked:          k.Revoked,
	}

	if k.ExpiresAt != nil {
		info.ExpiresAt = timestamppb.New(*k.ExpiresAt)
	}
	if k.LastUsedAt != nil {
		info.LastUsedAt = timestamppb.New(*k.LastUsedAt)
	}

	return info
}
