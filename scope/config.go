package scope

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// config is the resolved engine configuration. Build it with the defaults and
// mutate via Option.
type config struct {
	idgen  func() string
	clock  func() time.Time
	policy Policy
	hooks  []Hook
}

func defaultConfig() config {
	return config{
		idgen:  defaultID,
		clock:  func() time.Time { return time.Now().UTC() },
		policy: defaultPolicy(),
	}
}

func defaultID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Option customizes a Service. Options are applied in order at construction
// and never afterwards, so a Service's configuration is immutable once built.
type Option func(*config)

// WithIDGenerator sets the id generator used for containers and custom roles.
//
// The default is 12 bytes of crypto/rand hex-encoded (24 chars). Override it to
// use UUIDv7, ULIDs, or anything else your schema expects — the engine only
// requires that ids are unique and stable. A nil generator is ignored, leaving
// the default in place.
//
//	org.New(ac, store, org.WithIDGenerator(func() string { return uuid.NewString() }))
func WithIDGenerator(gen func() string) Option {
	return func(c *config) {
		if gen != nil {
			c.idgen = gen
		}
	}
}

// WithClock sets the clock used for created/updated, joined-at, and event
// timestamps. The default is time.Now().UTC(). A nil clock is ignored.
//
// Injecting a fixed clock makes assertions on stamped timestamps deterministic:
//
//	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
//	svc := org.New(ac, store, org.WithClock(func() time.Time { return at }))
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.clock = now
		}
	}
}

// WithPolicy replaces the authorization policy wholesale — escalation mode and
// both owner protections. It does not merge with the defaults, so pass a fully
// populated [Policy]; see that type for what the defaults are and why the zero
// value is not one.
func WithPolicy(p Policy) Option {
	return func(c *config) { c.policy = p }
}

// WithHooks appends lifecycle hooks fired after successful mutations. It
// appends rather than replaces, so several calls accumulate and hooks run in
// registration order.
//
// A hook that returns an error aborts the operation — see [Hook] for what that
// means transactionally before putting real side effects in one.
//
//	org.WithHooks(scope.HookFunc(func(ctx context.Context, e scope.Event) error {
//	    log.Printf("scope event kind=%d container=%s actor=%s", e.Kind, e.ContainerID, e.ActorID)
//	    return nil
//	}))
func WithHooks(hooks ...Hook) Option {
	return func(c *config) { c.hooks = append(c.hooks, hooks...) }
}
