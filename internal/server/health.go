package server

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// RegisterHealthService registers the standard gRPC health check service.
func RegisterHealthService(s *grpc.Server) {
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(s, healthServer)

	// Set all services as serving
	healthServer.SetServingStatus("authz.v1.AuthService", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("authz.v1.UserService", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("authz.v1.OrganizationService", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("authz.v1.TeamService", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("authz.v1.RBACService", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("authz.v1.APIKeyService", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("authz.v1.ServiceAccountService", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
}
