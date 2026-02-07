package middleware

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type rateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*tokenBucket
	limit    int
	interval time.Duration
}

type tokenBucket struct {
	tokens    int
	lastReset time.Time
}

func newRateLimiter(limitPerSecond int) *rateLimiter {
	return &rateLimiter{
		clients:  make(map[string]*tokenBucket),
		limit:    limitPerSecond,
		interval: time.Second,
	}
}

func (rl *rateLimiter) allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.clients[clientID]
	if !exists {
		rl.clients[clientID] = &tokenBucket{tokens: rl.limit - 1, lastReset: now}
		return true
	}

	if now.Sub(bucket.lastReset) >= rl.interval {
		bucket.tokens = rl.limit - 1
		bucket.lastReset = now
		return true
	}

	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

// RateLimitUnaryInterceptor provides per-client rate limiting.
func RateLimitUnaryInterceptor(limitPerSecond int) grpc.UnaryServerInterceptor {
	rl := newRateLimiter(limitPerSecond)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		clientID := "unknown"
		if p, ok := peer.FromContext(ctx); ok {
			clientID = p.Addr.String()
		}

		if !rl.allow(clientID) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}
