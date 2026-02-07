package middleware

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// LoggingUnaryInterceptor logs gRPC unary requests with structured fields.
func LoggingUnaryInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		st, _ := status.FromError(err)

		fields := []zap.Field{
			zap.String("method", info.FullMethod),
			zap.Duration("duration", duration),
			zap.String("code", st.Code().String()),
		}

		if userID, uerr := UserIDFromContext(ctx); uerr == nil {
			fields = append(fields, zap.String("user_id", userID.String()))
		}

		if err != nil {
			fields = append(fields, zap.Error(err))
			logger.Warn("grpc request failed", fields...)
		} else {
			logger.Info("grpc request", fields...)
		}

		return resp, err
	}
}
