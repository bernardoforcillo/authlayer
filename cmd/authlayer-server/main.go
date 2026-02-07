package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/auth"
	"github.com/bernardoforcillo/authlayer/internal/config"
	"github.com/bernardoforcillo/authlayer/internal/database"
	"github.com/bernardoforcillo/authlayer/internal/middleware"
	"github.com/bernardoforcillo/authlayer/internal/oauth"
	"github.com/bernardoforcillo/authlayer/migrations"
	"github.com/bernardoforcillo/authlayer/internal/rbac"
	"github.com/bernardoforcillo/authlayer/internal/repository"
	"github.com/bernardoforcillo/authlayer/internal/server"
	"github.com/bernardoforcillo/authlayer/internal/service"

	"go.uber.org/zap"
)

func main() {
	// 1. Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// 2. Initialize logger
	var logger *zap.Logger
	if cfg.Environment == "production" {
		logger, err = zap.NewProduction()
	} else {
		logger, err = zap.NewDevelopment()
	}
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Sync()

	// 3. Connect to database
	db, err := database.New(cfg, logger)
	if err != nil {
		logger.Fatal("failed to connect to database", zap.Error(err))
	}

	// 4. Run migrations
	if err := database.Migrate(db); err != nil {
		logger.Fatal("failed to run migrations", zap.Error(err))
	}
	logger.Info("database migrations completed")

	// 4b. Seed default roles and permissions
	if err := migrations.Seed(db, logger); err != nil {
		logger.Fatal("failed to seed data", zap.Error(err))
	}

	// 5. Create repositories
	userRepo := repository.NewUserRepository(db)
	accountRepo := repository.NewAccountRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	apiKeyRepo := repository.NewAPIKeyRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	orgMemberRepo := repository.NewOrganizationMemberRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	teamMemberRepo := repository.NewTeamMemberRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	permRepo := repository.NewPermissionRepository(db)
	rolePermRepo := repository.NewRolePermissionRepository(db)
	inviteRepo := repository.NewInvitationRepository(db)
	saRepo := repository.NewServiceAccountRepository(db)
	saKeyRepo := repository.NewServiceAccountKeyRepository(db)
	saRoleRepo := repository.NewServiceAccountRoleRepository(db)

	// 6. Create auth subsystem
	jwtManager := auth.NewJWTManager(cfg)

	// 7. Create OAuth registry and register providers
	oauthRegistry := oauth.NewRegistry()
	for name, providerCfg := range cfg.OAuthProviders {
		switch name {
		case "google":
			p, err := oauth.NewGoogleProvider(context.Background(), providerCfg)
			if err != nil {
				logger.Warn("failed to initialize Google OAuth provider", zap.Error(err))
			} else {
				oauthRegistry.Register(p)
				logger.Info("registered OAuth provider", zap.String("provider", "google"))
			}
		case "github":
			p := oauth.NewGitHubProvider(providerCfg)
			oauthRegistry.Register(p)
			logger.Info("registered OAuth provider", zap.String("provider", "github"))
		default:
			// Try as generic OIDC provider
			p, err := oauth.NewOIDCProvider(context.Background(), name, providerCfg)
			if err != nil {
				logger.Warn("failed to initialize OIDC provider", zap.String("name", name), zap.Error(err))
			} else {
				oauthRegistry.Register(p)
				logger.Info("registered OAuth provider", zap.String("provider", name))
			}
		}
	}

	// 8. Create RBAC engine
	rbacCache := rbac.NewCache(5 * time.Minute)
	rbacResolver := rbac.NewResolver(roleRepo, rolePermRepo, orgMemberRepo, teamMemberRepo, saRoleRepo, rbacCache)
	rbacChecker := rbac.NewChecker(rbacResolver)

	// 9. Create services
	authSvc := service.NewAuthService(userRepo, accountRepo, sessionRepo, jwtManager, oauthRegistry, logger)
	userSvc := service.NewUserService(userRepo, sessionRepo, logger)
	orgSvc := service.NewOrganizationService(orgRepo, orgMemberRepo, roleRepo, inviteRepo, userRepo, logger)
	teamSvc := service.NewTeamService(teamRepo, teamMemberRepo, logger)
	rbacSvc := service.NewRBACService(roleRepo, permRepo, rolePermRepo, orgMemberRepo, teamMemberRepo, rbacChecker, logger)
	apiKeySvc := service.NewAPIKeyService(apiKeyRepo, logger)
	serviceAccountSvc := service.NewServiceAccountService(saRepo, saKeyRepo, saRoleRepo, roleRepo, logger)

	// 10. Create interceptors
	publicMethods := []string{
		"/authz.v1.AuthService/Register",
		"/authz.v1.AuthService/Login",
		"/authz.v1.AuthService/RefreshToken",
		"/authz.v1.AuthService/GetOAuthURL",
		"/authz.v1.AuthService/OAuthCallback",
		"/authz.v1.AuthService/VerifyEmail",
		"/authz.v1.AuthService/RequestPasswordReset",
		"/authz.v1.AuthService/ResetPassword",
		"/authz.v1.APIKeyService/ValidateAPIKey",
		"/grpc.health.v1.Health/Check",
		"/grpc.health.v1.Health/Watch",
	}

	authInterceptor := middleware.NewAuthInterceptor(jwtManager, apiKeyRepo, saKeyRepo, publicMethods)

	// Method-level permission requirements (can be expanded)
	methodPerms := map[string]middleware.PermissionRequirement{
		"/authz.v1.UserService/ListUsers":                    {Permission: "user:list"},
		"/authz.v1.UserService/DeleteUser":                   {Permission: "user:delete"},
		"/authz.v1.OrganizationService/DeleteOrganization":   {Permission: "org:delete"},
		"/authz.v1.RBACService/CreateRole":                   {Permission: "role:create"},
		"/authz.v1.RBACService/DeleteRole":                   {Permission: "role:delete"},
		"/authz.v1.RBACService/AssignRole":                   {Permission: "role:assign"},
		"/authz.v1.RBACService/AssignPermission":             {Permission: "permission:assign"},
		"/authz.v1.RBACService/RevokePermission":             {Permission: "permission:assign"},
		"/authz.v1.OrganizationService/InviteMember":         {Permission: "member:invite"},
		"/authz.v1.OrganizationService/RemoveMember":         {Permission: "member:remove"},
		"/authz.v1.OrganizationService/UpdateMemberRole":     {Permission: "member:update_role"},
	}

	rbacInterceptor := middleware.NewRBACInterceptor(rbacChecker, methodPerms)

	// 11. Create and start server
	srv := server.New(
		cfg, logger,
		authInterceptor, rbacInterceptor,
		authSvc, userSvc, orgSvc, teamSvc, rbacSvc, apiKeySvc, serviceAccountSvc,
	)

	// 12. Handle graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
		srv.GracefulStop()
	}()

	if err := srv.Start(); err != nil {
		logger.Fatal("server failed", zap.Error(err))
	}
}
