package middleware

import (
	"context"

	"github.com/bernardoforcillo/authlayer/internal/rbac"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PermissionRequirement defines what permission is needed for a gRPC method.
type PermissionRequirement struct {
	Permission string
}

// RBACInterceptor checks permissions for authenticated users.
type RBACInterceptor struct {
	checker           *rbac.Checker
	methodPermissions map[string]PermissionRequirement
}

// NewRBACInterceptor creates a new RBAC interceptor.
func NewRBACInterceptor(
	checker *rbac.Checker,
	methodPermissions map[string]PermissionRequirement,
) *RBACInterceptor {
	return &RBACInterceptor{
		checker:           checker,
		methodPermissions: methodPermissions,
	}
}

// UnaryServerInterceptor returns a gRPC unary interceptor for authorization.
func (i *RBACInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		requirement, exists := i.methodPermissions[info.FullMethod]
		if !exists {
			// No permission requirement defined; allow through
			return handler(ctx, req)
		}

		authType := AuthTypeFromContext(ctx)

		switch authType {
		case AuthTypeUser, AuthTypeAPIKey:
			userID, err := UserIDFromContext(ctx)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "no user in context")
			}

			allowed, _, err := i.checker.CheckPermission(ctx, userID, requirement.Permission, nil)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "permission check failed: %v", err)
			}
			if !allowed {
				return nil, status.Errorf(codes.PermissionDenied, "permission %q denied", requirement.Permission)
			}

		case AuthTypeServiceAccount:
			saID, err := ServiceAccountIDFromContext(ctx)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "no service account in context")
			}

			allowed, err := i.checker.CheckServiceAccountPermission(ctx, saID, requirement.Permission, nil)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "permission check failed: %v", err)
			}
			if !allowed {
				return nil, status.Errorf(codes.PermissionDenied, "permission %q denied", requirement.Permission)
			}

		default:
			return nil, status.Errorf(codes.Unauthenticated, "unknown auth type")
		}

		return handler(ctx, req)
	}
}
