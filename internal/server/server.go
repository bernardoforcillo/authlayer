package server

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/bernardoforcillo/authlayer/internal/config"
	"github.com/bernardoforcillo/authlayer/internal/middleware"
	"github.com/bernardoforcillo/authlayer/internal/service"
	authlayerv1 "github.com/bernardoforcillo/authlayer/pkg/proto/authlayer/v1"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	authlayerv1.RegisterAuthServiceServer(grpcServer, authSvc)
	authlayerv1.RegisterUserServiceServer(grpcServer, userSvc)
	authlayerv1.RegisterOrganizationServiceServer(grpcServer, orgSvc)
	authlayerv1.RegisterTeamServiceServer(grpcServer, teamSvc)
	authlayerv1.RegisterRBACServiceServer(grpcServer, rbacSvc)
	authlayerv1.RegisterAPIKeyServiceServer(grpcServer, apiKeySvc)
	authlayerv1.RegisterServiceAccountServiceServer(grpcServer, serviceAccountSvc)

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

	// Start Gateway in background
	go func() {
		if err := s.startGateway(); err != nil {
			s.logger.Error("failed to start gateway", zap.Error(err))
		}
	}()

	s.logger.Info("gRPC server starting", zap.String("address", addr))
	return s.grpcServer.Serve(lis)
}

func (s *Server) startGateway() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	grpcAddr := fmt.Sprintf(":%d", s.cfg.GRPCPort)

	// Register services
	if err := authlayerv1.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return fmt.Errorf("failed to register auth service gateway: %w", err)
	}
	if err := authlayerv1.RegisterUserServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return fmt.Errorf("failed to register user service gateway: %w", err)
	}

	httpAddr := fmt.Sprintf(":%d", s.cfg.HTTPPort)
	s.logger.Info("HTTP gateway starting", zap.String("address", httpAddr))

	// Use standard http server
	return http.ListenAndServe(httpAddr, mux)
}

// GracefulStop gracefully shuts down the server.
func (s *Server) GracefulStop() {
	s.logger.Info("shutting down gRPC server gracefully")
	s.grpcServer.GracefulStop()
}
