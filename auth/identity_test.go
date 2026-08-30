// This file is deliberately an in-package test (package auth, not
// auth_test): the properties it pins are about the ZERO VALUE of the
// unexported config struct and about the unexported identity-store guard,
// neither of which is reachable from outside the package. The rest of this
// package's tests live in auth_test and stay there — see service_test.go.
package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestLinkingDefaultIsLinkVerified pins the single most consequential
// decision in the OAuth surface: which linking policy a caller who never
// mentions one ends up with.
//
// Linking is an int enum, so a Service built with no WithLinking option
// carries whatever the zero value denotes. If LinkAlways were the zero
// value, every application that forgot to configure a policy would link an
// external identity to an existing local account on an email match alone —
// account takeover by anyone who can make a provider assert someone else's
// address. LinkVerified is therefore iota's first constant, and that is a
// load-bearing ordering, not a stylistic one.
func TestLinkingDefaultIsLinkVerified(t *testing.T) {
	if LinkVerified != 0 {
		t.Fatalf("LinkVerified = %d, want 0 so the zero value is the safe default", LinkVerified)
	}
	var c config
	if c.linking != LinkVerified {
		t.Fatalf("zero config linking = %v, want LinkVerified", c.linking)
	}
	if got := defaultConfig().linking; got != LinkVerified {
		t.Fatalf("defaultConfig().linking = %v, want LinkVerified", got)
	}
}

// TestWithLinkingRejectsUnknownMode pins that a mode outside the three
// declared constants is refused at construction rather than silently
// falling back to some policy the caller never asked for. A Service must
// never exist holding a linking mode no branch of the ladder handles.
func TestWithLinkingRejectsUnknownMode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("WithLinking(99) should panic at construction, not fail at sign-in")
		}
	}()
	New(nil, WithLinking(Linking(99)))
}

// TestWithLinkingAcceptsEveryDeclaredMode is the other half of the check
// above: the guard must reject only what is genuinely undeclared. A guard
// that panicked on a legitimate mode would be caught here rather than by an
// application's first sign-in.
func TestWithLinkingAcceptsEveryDeclaredMode(t *testing.T) {
	for _, m := range []Linking{LinkVerified, LinkNever, LinkAlways} {
		svc := New(nil, WithLinking(m))
		if svc.cfg.linking != m {
			t.Fatalf("WithLinking(%v): cfg.linking = %v", m, svc.cfg.linking)
		}
	}
}

// TestIdentitiesRefusesWithoutAnIdentityStore pins that the optional port
// being absent is an ordinary, typed refusal — not a nil dereference. Every
// entry point that needs an IdentityStore resolves it through this one
// guard, so this is the whole surface of that behaviour.
func TestIdentitiesRefusesWithoutAnIdentityStore(t *testing.T) {
	svc := New(nil) // no WithIdentityStore

	store, err := svc.identities()
	if !errors.Is(err, ErrOAuthNotConfigured) {
		t.Fatalf("identities() err = %v, want ErrOAuthNotConfigured", err)
	}
	if store != nil {
		t.Fatalf("identities() store = %v, want nil alongside the error", store)
	}
}

// TestWithIdentityStoreWiresThePort is the positive control for the guard:
// once the port is configured, the guard hands back exactly the value that
// was wired, with no error.
func TestWithIdentityStoreWiresThePort(t *testing.T) {
	want := stubIdentityStore{}
	svc := New(nil, WithIdentityStore(want))

	got, err := svc.identities()
	if err != nil {
		t.Fatalf("identities() err = %v, want nil", err)
	}
	if got != IdentityStore(want) {
		t.Fatalf("identities() = %#v, want the wired store %#v", got, want)
	}
}

// TestWithIdentityStoreIgnoresNil matches every other With* option in this
// package: a nil argument leaves the default (here, "not configured") in
// place rather than installing a nil interface value that would look
// configured to the guard and then panic on first use.
func TestWithIdentityStoreIgnoresNil(t *testing.T) {
	svc := New(nil, WithIdentityStore(stubIdentityStore{}), WithIdentityStore(nil))

	if _, err := svc.identities(); err != nil {
		t.Fatalf("identities() err = %v, want the earlier store to survive a nil option", err)
	}
}

// stubIdentityStore satisfies auth.IdentityStore without persisting
// anything. It exists so the option and guard tests above need no import of
// store/memory — which this in-package test file could not import anyway,
// since store/memory imports auth.
type stubIdentityStore struct{}

func (stubIdentityStore) CreateIdentity(_ context.Context, i Identity) (Identity, error) {
	return i, nil
}

func (stubIdentityStore) FindIdentityByProviderSubject(_ context.Context, _, _ string) (Identity, error) {
	return Identity{}, ErrIdentityNotFound
}

func (stubIdentityStore) ListIdentitiesByUser(_ context.Context, _ string) ([]Identity, error) {
	return nil, nil
}

func (stubIdentityStore) TouchIdentity(_ context.Context, _ string, _ time.Time) error {
	return ErrIdentityNotFound
}

func (stubIdentityStore) DeleteIdentity(_ context.Context, _ string) error {
	return ErrIdentityNotFound
}

func (stubIdentityStore) DeleteIdentityIfNotLast(_ context.Context, _, _ string, _ bool) error {
	return ErrIdentityNotFound
}
