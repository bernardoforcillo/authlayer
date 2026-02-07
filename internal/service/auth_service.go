package service

import (
	"context"
	"errors"

	"github.com/bernardoforcillo/authlayer/internal/auth"
	"github.com/bernardoforcillo/authlayer/internal/middleware"
	"github.com/bernardoforcillo/authlayer/internal/model"
	"github.com/bernardoforcillo/authlayer/internal/oauth"
	"github.com/bernardoforcillo/authlayer/internal/repository"
	authlayerv1 "github.com/bernardoforcillo/authlayer/pkg/proto/authlayer/v1"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type AuthService struct {
	authlayerv1.UnimplementedAuthServiceServer

	userRepo    repository.UserRepository
	accountRepo repository.AccountRepository
	sessionRepo repository.SessionRepository
	jwtManager  *auth.JWTManager
	oauthReg    *oauth.Registry
	logger      *zap.Logger
}

func NewAuthService(
	userRepo repository.UserRepository,
	accountRepo repository.AccountRepository,
	sessionRepo repository.SessionRepository,
	jwtManager *auth.JWTManager,
	oauthReg *oauth.Registry,
	logger *zap.Logger,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		accountRepo: accountRepo,
		sessionRepo: sessionRepo,
		jwtManager:  jwtManager,
		oauthReg:    oauthReg,
		logger:      logger,
	}
}

func (s *AuthService) Register(ctx context.Context, req *authlayerv1.RegisterRequest) (*authlayerv1.RegisterResponse, error) {
	if req.Email == "" || req.Password == "" || req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email, password, and name are required")
	}

	// Check if user already exists
	_, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "email already registered")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(codes.Internal, "failed to check user: %v", err)
	}

	// Hash password
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash password")
	}

	user := &model.User{
		Email:        req.Email,
		PasswordHash: &hash,
		Name:         req.Name,
		Status:       model.UserStatusActive,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	// Generate tokens
	tokens, err := s.jwtManager.GenerateTokenPair(user.ID.String(), user.Email, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens")
	}

	// Store session
	if err := s.storeSession(ctx, user.ID, tokens); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store session")
	}

	return &authlayerv1.RegisterResponse{
		User:   userToProto(user),
		Tokens: tokenPairToProto(tokens),
	}, nil
}

func (s *AuthService) Login(ctx context.Context, req *authlayerv1.LoginRequest) (*authlayerv1.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email and password are required")
	}

	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get user")
	}

	if user.Status == model.UserStatusBanned {
		return nil, status.Errorf(codes.PermissionDenied, "account is banned")
	}

	if user.PasswordHash == nil {
		return nil, status.Errorf(codes.Unauthenticated, "this account uses OAuth login only")
	}

	if err := auth.VerifyPassword(*user.PasswordHash, req.Password); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	tokens, err := s.jwtManager.GenerateTokenPair(user.ID.String(), user.Email, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens")
	}

	if err := s.storeSession(ctx, user.ID, tokens); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store session")
	}

	return &authlayerv1.LoginResponse{
		User:   userToProto(user),
		Tokens: tokenPairToProto(tokens),
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, req *authlayerv1.LogoutRequest) (*authlayerv1.LogoutResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "refresh_token is required")
	}

	tokenHash := auth.HashToken(req.RefreshToken)
	if err := s.sessionRepo.RevokeByTokenHash(ctx, tokenHash); err != nil {
		s.logger.Warn("failed to revoke session", zap.Error(err))
	}

	return &authlayerv1.LogoutResponse{}, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, req *authlayerv1.RefreshTokenRequest) (*authlayerv1.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "refresh_token is required")
	}

	// Validate the JWT
	claims, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token: %v", err)
	}

	// Check session in DB
	tokenHash := auth.HashToken(req.RefreshToken)
	session, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "session not found")
	}

	// If session is already revoked, this is a reuse attack - revoke entire family
	if session.Revoked {
		s.logger.Warn("refresh token reuse detected, revoking family",
			zap.String("family", session.TokenFamily),
			zap.String("user_id", session.UserID.String()),
		)
		_ = s.sessionRepo.RevokeByFamily(ctx, session.TokenFamily)
		return nil, status.Errorf(codes.Unauthenticated, "token reuse detected, all sessions revoked")
	}

	// Revoke current session
	_ = s.sessionRepo.RevokeByTokenHash(ctx, tokenHash)

	// Generate new token pair with same family
	tokens, err := s.jwtManager.GenerateTokenPair(claims.UserID, claims.Email, claims.TokenFamily)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens")
	}

	userID, _ := uuid.Parse(claims.UserID)
	if err := s.storeSession(ctx, userID, tokens); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store session")
	}

	return &authlayerv1.RefreshTokenResponse{
		Tokens: tokenPairToProto(tokens),
	}, nil
}

func (s *AuthService) GetOAuthURL(ctx context.Context, req *authlayerv1.GetOAuthURLRequest) (*authlayerv1.GetOAuthURLResponse, error) {
	if req.Provider == "" {
		return nil, status.Errorf(codes.InvalidArgument, "provider is required")
	}

	provider, err := s.oauthReg.Get(req.Provider)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "provider %q not available", req.Provider)
	}

	state, err := auth.GenerateRandomToken(32)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate state")
	}

	url := provider.GetAuthorizationURL(state, req.RedirectUri)

	return &authlayerv1.GetOAuthURLResponse{
		AuthorizationUrl: url,
		State:            state,
	}, nil
}

func (s *AuthService) OAuthCallback(ctx context.Context, req *authlayerv1.OAuthCallbackRequest) (*authlayerv1.OAuthCallbackResponse, error) {
	if req.Provider == "" || req.Code == "" {
		return nil, status.Errorf(codes.InvalidArgument, "provider and code are required")
	}

	provider, err := s.oauthReg.Get(req.Provider)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "provider %q not available", req.Provider)
	}

	userInfo, err := provider.ExchangeCode(ctx, req.Code, req.RedirectUri)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "oauth exchange failed: %v", err)
	}

	// Check if account already linked
	account, err := s.accountRepo.GetByProviderAndID(ctx, req.Provider, userInfo.ProviderID)
	isNewUser := false

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(codes.Internal, "failed to check account")
	}

	var user *model.User

	if account != nil {
		// Existing account - login
		user, err = s.userRepo.GetByID(ctx, account.UserID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get user")
		}
	} else {
		// Check if user with this email exists
		user, err = s.userRepo.GetByEmail(ctx, userInfo.Email)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new user
			user = &model.User{
				Email:         userInfo.Email,
				Name:          userInfo.Name,
				Avatar:        &userInfo.Avatar,
				EmailVerified: userInfo.EmailVerified,
				Status:        model.UserStatusActive,
			}
			if err := s.userRepo.Create(ctx, user); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to create user")
			}
			isNewUser = true
		} else if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to check user")
		}

		// Link account
		newAccount := &model.Account{
			UserID:            user.ID,
			Provider:          req.Provider,
			ProviderAccountID: userInfo.ProviderID,
		}
		if err := s.accountRepo.Create(ctx, newAccount); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to link account")
		}
	}

	tokens, err := s.jwtManager.GenerateTokenPair(user.ID.String(), user.Email, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens")
	}

	if err := s.storeSession(ctx, user.ID, tokens); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store session")
	}

	return &authlayerv1.OAuthCallbackResponse{
		User:      userToProto(user),
		Tokens:    tokenPairToProto(tokens),
		IsNewUser: isNewUser,
	}, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, req *authlayerv1.VerifyEmailRequest) (*authlayerv1.VerifyEmailResponse, error) {
	// TODO: implement email verification token logic
	return nil, status.Errorf(codes.Unimplemented, "email verification not yet implemented")
}

func (s *AuthService) RequestPasswordReset(ctx context.Context, req *authlayerv1.RequestPasswordResetRequest) (*authlayerv1.RequestPasswordResetResponse, error) {
	// TODO: implement password reset token generation + email sending
	return &authlayerv1.RequestPasswordResetResponse{}, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, req *authlayerv1.ResetPasswordRequest) (*authlayerv1.ResetPasswordResponse, error) {
	// TODO: implement password reset with token validation
	return nil, status.Errorf(codes.Unimplemented, "password reset not yet implemented")
}

func (s *AuthService) storeSession(ctx context.Context, userID uuid.UUID, tokens *auth.TokenPair) error {
	session := &model.Session{
		UserID:      userID,
		TokenHash:   auth.HashToken(tokens.RefreshToken),
		TokenFamily: tokens.TokenFamily,
		ExpiresAt:   tokens.RefreshTokenExpiresAt,
	}

	// Extract IP/user-agent from gRPC metadata if available
	if ip := middleware.UserEmailFromContext(ctx); ip != "" {
		session.IPAddress = &ip
	}

	return s.sessionRepo.Create(ctx, session)
}

// ---- Helpers ----

func userToProto(u *model.User) *authlayerv1.UserInfo {
	info := &authlayerv1.UserInfo{
		Id:            u.ID.String(),
		Email:         u.Email,
		Name:          u.Name,
		Avatar:        u.Avatar,
		EmailVerified: u.EmailVerified,
		Status:        userStatusToProto(u.Status),
		CreatedAt:     timestamppb.New(u.CreatedAt),
		UpdatedAt:     timestamppb.New(u.UpdatedAt),
	}
	return info
}

func userStatusToProto(s model.UserStatus) authlayerv1.UserStatus {
	switch s {
	case model.UserStatusActive:
		return authlayerv1.UserStatus_USER_STATUS_ACTIVE
	case model.UserStatusInactive:
		return authlayerv1.UserStatus_USER_STATUS_INACTIVE
	case model.UserStatusBanned:
		return authlayerv1.UserStatus_USER_STATUS_BANNED
	default:
		return authlayerv1.UserStatus_USER_STATUS_UNSPECIFIED
	}
}

func tokenPairToProto(tp *auth.TokenPair) *authlayerv1.TokenPair {
	return &authlayerv1.TokenPair{
		AccessToken:           tp.AccessToken,
		RefreshToken:          tp.RefreshToken,
		AccessTokenExpiresAt:  timestamppb.New(tp.AccessTokenExpiresAt),
		RefreshTokenExpiresAt: timestamppb.New(tp.RefreshTokenExpiresAt),
	}
}
