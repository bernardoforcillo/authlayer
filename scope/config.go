package scope

import (
	"time"

	"github.com/bernardoforcillo/authlayer/internal/uid"
)

// config is the resolved engine configuration. Build it with the defaults and
// mutate via Option.
type config struct {
	idgen             func() string
	clock             func() time.Time
	policy            Policy
	hooks             []Hook
	parent            ParentScope
	inherit           Inheritance
	containerResource string
}

func defaultConfig() config {
	return config{
		idgen:  defaultID,
		clock:  func() time.Time { return time.Now().UTC() },
		policy: defaultPolicy(),
	}
}

func defaultID() string { return uid.NewV7() }

// Option customizes a Service. Options are applied in order at construction
// and never afterwards, so a Service's configuration is immutable once built.
type Option func(*config)

// WithIDGenerator sets the id generator used for containers and custom roles.
//
// The default is UUIDv7 (RFC 9562) — time-ordered, so ids minted later sort
// later and a b-tree index on the primary key stays dense. The engine itself
// only requires that ids are unique and stable. A nil generator is ignored,
// leaving the default in place.
//
// # A non-UUID generator needs WithTextLibraryIDs on store/drops
//
// The engine's own indifference is not the whole story, because the shipped
// PostgreSQL backend has to declare a column type.
// [github.com/bernardoforcillo/authlayer/store/drops] types every id this
// library mints for itself — a container's id, a role's id, and the
// container_id / parent_id columns that reference them — as PostgreSQL uuid
// BY DEFAULT, which is correct for the default generator and wrong for any
// other. Override this option and you must pass
// [github.com/bernardoforcillo/authlayer/store/drops.WithTextLibraryIDs] as
// well, which types those columns text instead:
//
//	st := dropsstore.New[org.Organization, org.Member](db, dropsstore.WithTextLibraryIDs())
//	svc := org.New(ac, st, org.WithIDGenerator(ulid.Make))
//
// Pass it to the invitation store too
// ([github.com/bernardoforcillo/authlayer/store/drops.WithInviteTextLibraryIDs])
// if that half is in use, and to the auth store
// ([github.com/bernardoforcillo/authlayer/store/drops.WithAuthTextLibraryIDs])
// if the same generator mints user ids.
//
// Without it, the first CreateContainer fails with SQLSTATE 22P02
// (invalid_text_representation), at the Store rather than at construction —
// and [github.com/bernardoforcillo/authlayer/store/memory] accepts any
// string, so a service tested only against that one passes everything and
// breaks on deployment. Both directions are pinned live:
// TestNonUUIDIDGeneratorFailsAgainstTheScopeStoreLive asserts that 22P02 and
// TestTextLibraryIDsRoundTripANonUUIDGeneratorLive round-trips a ULID
// generator end to end with the option on, both in store/drops's integration
// lane.
//
// [github.com/bernardoforcillo/authlayer/store/drops.WithTextUserIDs] is a
// DIFFERENT option and does not cover this, despite the name's apparent
// reach: it types the columns holding a user id supplied from OUTSIDE this
// library (user_id, owner_id, invited_by, created_by), so that the RBAC half
// can sit on an existing non-UUID user table. The two compose, and a
// deployment minting its own non-UUID ids for both generally wants both.
//
// Against a Store of your own, use whatever that schema accepts.
// [github.com/bernardoforcillo/authlayer/auth.WithIDGenerator] carries the
// identical requirement, for the identical reason.
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
