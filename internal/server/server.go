package server

import (
	"fmt"
	"net"

	"authz-go/internal/config"
	"authz-go/internal/middleware"
	"authz-go/internal/service"
	authzv1 "authz-go/pkg/proto/authz/v1"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server wraps a gRPC server with all registered services and interceptors.
type Server struct {
	cfg        *config.Config
	grpcServer *grpc.Server
	logger     *zap.Logger
}

// New creates a new gRPC server with all services and interceptors wired up.
func New(
	cfg *config.Config,
	logger *zap.Logger,
	authInterceptor *middleware.AuthInterceptor,
	rbacInterceptor *middleware.RBACInterceptor,
	authSvc *service.AuthService,
	userSvc *service.UserService,
	orgSvc *service.OrganizationService,
	teamSvc *service.TeamService,
	rbacSvc *service.RBACService,
	apiKeySvc *service.APIKeyService,
	serviceAccountSvc *service.ServiceAccountService,
) *Server {
	// Create gRPC server with chained interceptors
	// Order: Recovery -> Logging -> RateLimit -> Auth -> RBAC
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			middleware.RecoveryUnaryInterceptor(logger),
			middleware.LoggingUnaryInterceptor(logger),
			middleware.RateLimitUnaryInterceptor(cfg.RateLimitPerSecond),
			authInterceptor.UnaryServerInterceptor(),
			rbacInterceptor.UnaryServerInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			middleware.RecoveryStreamInterceptor(logger),
			authInterceptor.StreamServerInterceptor(),
		),
	)

	// Register services
	authzv1.RegisterAuthServiceServer(grpcServer, authSvc)
	authzv1.RegisterUserServiceServer(grpcServer, userSvc)
	authzv1.RegisterOrganizationServiceServer(grpcServer, orgSvc)
	authzv1.RegisterTeamServiceServer(grpcServer, teamSvc)
	authzv1.RegisterRBACServiceServer(grpcServer, rbacSvc)
	authzv1.RegisterAPIKeyServiceServer(grpcServer, apiKeySvc)
	authzv1.RegisterServiceAccountServiceServer(grpcServer, serviceAccountSvc)

	// Register reflection for grpcurl/debugging
	reflection.Register(grpcServer)

	// Register health check
	RegisterHealthService(grpcServer)

	return &Server{
		cfg:        cfg,
		grpcServer: grpcServer,
		logger:     logger,
	}
}

// Start begins listening and serving gRPC requests.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.cfg.GRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.logger.Info("gRPC server starting", zap.String("address", addr))
	return s.grpcServer.Serve(lis)
}

// GracefulStop gracefully shuts down the server.
func (s *Server) GracefulStop() {
	s.logger.Info("shutting down gRPC server gracefully")
	s.grpcServer.GracefulStop()
}
