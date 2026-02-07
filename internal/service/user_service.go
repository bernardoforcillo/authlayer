package service

import (
	"context"
	"errors"

	"authz-go/internal/auth"
	"authz-go/internal/middleware"
	"authz-go/internal/model"
	"authz-go/internal/repository"
	authzv1 "authz-go/pkg/proto/authz/v1"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type UserService struct {
	authzv1.UnimplementedUserServiceServer

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

func (s *UserService) GetUser(ctx context.Context, req *authzv1.GetUserRequest) (*authzv1.GetUserResponse, error) {
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

	return &authzv1.GetUserResponse{User: userToProto(user)}, nil
}

func (s *UserService) UpdateUser(ctx context.Context, req *authzv1.UpdateUserRequest) (*authzv1.UpdateUserResponse, error) {
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

	return &authzv1.UpdateUserResponse{User: userToProto(user)}, nil
}

func (s *UserService) DeleteUser(ctx context.Context, req *authzv1.DeleteUserRequest) (*authzv1.DeleteUserResponse, error) {
	id, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	// Revoke all sessions
	_ = s.sessionRepo.RevokeAllByUserID(ctx, id)

	if err := s.userRepo.Delete(ctx, id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user")
	}

	return &authzv1.DeleteUserResponse{}, nil
}

func (s *UserService) ListUsers(ctx context.Context, req *authzv1.ListUsersRequest) (*authzv1.ListUsersResponse, error) {
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

	protoUsers := make([]*authzv1.UserInfo, len(users))
	for i, u := range users {
		protoUsers[i] = userToProto(&u)
	}

	var nextToken string
	if len(users) > 0 {
		nextToken = users[len(users)-1].ID.String()
	}

	return &authzv1.ListUsersResponse{
		Users: protoUsers,
		Pagination: &authzv1.PaginationResponse{
			NextPageToken: nextToken,
			TotalCount:    int32(total),
		},
	}, nil
}

func (s *UserService) ChangePassword(ctx context.Context, req *authzv1.ChangePasswordRequest) (*authzv1.ChangePasswordResponse, error) {
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

	return &authzv1.ChangePasswordResponse{}, nil
}

func protoToUserStatus(s authzv1.UserStatus) model.UserStatus {
	switch s {
	case authzv1.UserStatus_USER_STATUS_ACTIVE:
		return model.UserStatusActive
	case authzv1.UserStatus_USER_STATUS_INACTIVE:
		return model.UserStatusInactive
	case authzv1.UserStatus_USER_STATUS_BANNED:
		return model.UserStatusBanned
	default:
		return model.UserStatusActive
	}
}
