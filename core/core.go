// Package core holds the small pieces every authlayer package shares, so a
// deployment configures them once instead of once per Service.
//
//   - [Runtime]: the clock and id generator, injectable for tests and for
//     deterministic replays. Every Service accepts one with WithRuntime.
//   - [Hook], [HookFunc], [Hooks]: the generic observer shape. Each package
//     aliases it at its own Event type (auth.Hook is core.Hook[auth.Event]),
//     so existing hooks keep compiling and a helper written against core
//     works with all of them.
//   - [RateLimiter]: the attempt limiter auth consults, defined once.
//
// core imports nothing from authlayer and nothing outside the standard
// library, so any package may depend on it without a cycle.
package core

import (
	"context"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/uid"
)

// Runtime is the ambient state every Service reads: the current time and a
// source of fresh identifiers. A nil field means "the package default"
// (time.Now().UTC() and UUIDv7), so the zero Runtime changes nothing.
type Runtime struct {
	// Clock returns the current time.
	Clock func() time.Time
	// IDs returns a new unique identifier.
	IDs func() string
}

// Now returns the Runtime's time, or the UTC wall clock if Clock is nil.
func (r Runtime) Now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now().UTC()
}

// NewID returns a new identifier from the Runtime, or a UUIDv7 if IDs is nil.
func (r Runtime) NewID() string {
	if r.IDs != nil {
		return r.IDs()
	}
	return uid.NewV7()
}

// Fixed returns a Runtime whose clock never moves, for deterministic tests.
func Fixed(at time.Time) Runtime {
	return Runtime{Clock: func() time.Time { return at }}
}

// Hook observes events of type E. A non-nil error stops the chain and is
// returned to the caller that triggered the event. Hooks run on the caller's
// goroutine and share its context, so a slow hook slows the request.
type Hook[E any] interface {
	On(ctx context.Context, e E) error
}

// HookFunc adapts a function to [Hook].
type HookFunc[E any] func(ctx context.Context, e E) error

// On implements [Hook].
func (f HookFunc[E]) On(ctx context.Context, e E) error { return f(ctx, e) }

// Hooks is an ordered chain of [Hook]s.
type Hooks[E any] []Hook[E]

// Emit calls each hook in order and stops at the first error.
func (h Hooks[E]) Emit(ctx context.Context, e E) error {
	for _, hook := range h {
		if hook == nil {
			continue
		}
		if err := hook.On(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// RateLimiter decides whether an attempt keyed by key may proceed right now.
// A false, nil result is a refusal; a non-nil error means the limiter could
// not answer, which callers treat as a denial too.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}
