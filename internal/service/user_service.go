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
	"gorm.io/gorm"
)

type UserService struct {
	authlayerv1.UnimplementedUserServiceServer

	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
	logger      *zap.Logger
}

func NewUserService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	logger *zap.Logger,
) *UserService {
	return &UserService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		logger:      logger,
	}
}

func (s *UserService) GetUser(ctx context.Context, req *authlayerv1.GetUserRequest) (*authlayerv1.GetUserResponse, error) {
	id, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get user")
	}

	return &authlayerv1.GetUserResponse{User: userToProto(user)}, nil
}

func (s *UserService) UpdateUser(ctx context.Context, req *authlayerv1.UpdateUserRequest) (*authlayerv1.UpdateUserResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	targetID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	if callerID != targetID {
		return nil, status.Errorf(codes.PermissionDenied, "can only update own profile")
	}

	user, err := s.userRepo.GetByID(ctx, targetID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Avatar != nil {
		user.Avatar = req.Avatar
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user")
	}

	return &authlayerv1.UpdateUserResponse{User: userToProto(user)}, nil
}

func (s *UserService) DeleteUser(ctx context.Context, req *authlayerv1.DeleteUserRequest) (*authlayerv1.DeleteUserResponse, error) {
	id, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	// Revoke all sessions
	_ = s.sessionRepo.RevokeAllByUserID(ctx, id)

	if err := s.userRepo.Delete(ctx, id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user")
	}

	return &authlayerv1.DeleteUserResponse{}, nil
}

func (s *UserService) ListUsers(ctx context.Context, req *authlayerv1.ListUsersRequest) (*authlayerv1.ListUsersResponse, error) {
	filter := repository.UserFilter{
		Search: req.Search,
	}
	if req.Status != nil {
		st := protoToUserStatus(*req.Status)
		filter.Status = &st
	}

	pagination := repository.Pagination{PageSize: 20}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	users, total, err := s.userRepo.List(ctx, filter, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list users")
	}

	protoUsers := make([]*authlayerv1.UserInfo, len(users))
	for i, u := range users {
		protoUsers[i] = userToProto(&u)
	}

	var nextToken string
	if len(users) > 0 {
		nextToken = users[len(users)-1].ID.String()
	}

	return &authlayerv1.ListUsersResponse{
		Users: protoUsers,
		Pagination: &authlayerv1.PaginationResponse{
			NextPageToken: nextToken,
			TotalCount:    int32(total),
		},
	}, nil
}

func (s *UserService) ChangePassword(ctx context.Context, req *authlayerv1.ChangePasswordRequest) (*authlayerv1.ChangePasswordResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	user, err := s.userRepo.GetByID(ctx, callerID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	if user.PasswordHash == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "account uses OAuth login, no password to change")
	}

	if err := auth.VerifyPassword(*user.PasswordHash, req.CurrentPassword); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "current password is incorrect")
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash password")
	}

	user.PasswordHash = &hash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update password")
	}

	// Revoke all existing sessions
	_ = s.sessionRepo.RevokeAllByUserID(ctx, callerID)

	return &authlayerv1.ChangePasswordResponse{}, nil
}

func protoToUserStatus(s authlayerv1.UserStatus) model.UserStatus {
	switch s {
	case authlayerv1.UserStatus_USER_STATUS_ACTIVE:
		return model.UserStatusActive
	case authlayerv1.UserStatus_USER_STATUS_INACTIVE:
		return model.UserStatusInactive
	case authlayerv1.UserStatus_USER_STATUS_BANNED:
		return model.UserStatusBanned
	default:
		return model.UserStatusActive
	}
}
