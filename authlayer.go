// Package authlayer is the composition point: it holds the configuration
// every module of the framework shares and hands each module its own
// typed option, so a deployment states it once.
//
//	sh := authlayer.Shared{Runtime: core.Fixed(at)}
//
//	authSvc := auth.New(authStore, sh.Auth(), auth.WithJWT(keys, ttl))
//	scopeSvc := scope.New(ac, scopeStore, parent, sh.Scope())
//	keysSvc := apikey.New(scopeSvc, keyStore, sh.APIKey())
//	oauthSvc := oauth.New(oauthStore, scopeSvc, authSvc.Signer(), sh.OAuth())
//
// Each module stays importable and usable alone; nothing here is required.
// The package exists because the modules' options are different Go types
// (auth.Option, scope.Option, ...), so a shared setting cannot be one value
// without an adapter per module.
package authlayer

import (
	"context"

	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/scope"
)

// Shared is the configuration common to every module.
type Shared struct {
	// Runtime is the clock and id source all modules use. The zero value
	// leaves every module on its own default.
	Runtime core.Runtime
}

// Auth returns the shared settings as an [auth.Option].
func (s Shared) Auth() auth.Option { return auth.WithRuntime(s.Runtime) }

// Scope returns the shared settings as a [scope.Option].
func (s Shared) Scope() scope.Option { return scope.WithRuntime(s.Runtime) }

// APIKey returns the shared settings as an [apikey.Option].
func (s Shared) APIKey() apikey.Option { return apikey.WithRuntime(s.Runtime) }

// OAuth returns the shared settings as an [oauth.Option].
func (s Shared) OAuth() oauth.Option { return oauth.WithRuntime(s.Runtime) }

// UserRemover is what the scope-family services ([scope.Service],
// org.Service, team.Service — promoted through their embedded
// scope.Service) offer for account removal.
type UserRemover interface {
	RemoveUser(ctx context.Context, userID string) error
	RemoveUserAnonymized(ctx context.Context, userID string) error
}

// RemoveUserSweeper links account removal to containers: it returns an
// [auth.Sweeper] that, when an account is deleted or anonymized
// ([auth.SweepAccountRemoved]), removes the user from every container of each
// given service, in the order given — list nested services (teams) before the
// ones that contain them (organizations).
//
// Register it with [auth.WithSweeper]. A deleted account
// ([auth.SweepAccountRemoved]) leaves through RemoveUser; an anonymized one
// ([auth.SweepAccountAnonymized]) through RemoveUserAnonymized, so each
// service's [scope.Anonymizer] is told to scrub. It acts on no other reason, so a
// password change or logout leaves memberships alone. What happens to a
// container the user owns is each service's [scope.WithOrphanPolicy]; by
// default the removal is refused with [scope.ErrOwnsContainer] and the
// account is NOT deleted, because the sweep fails the operation closed.
//
// Each service removes atomically, but the services are separate stores: if a
// later one fails, earlier ones have already committed. Removal is
// idempotent, so retrying the account deletion completes it.
func RemoveUserSweeper(services ...UserRemover) auth.Sweeper {
	return auth.SweeperFunc(func(ctx context.Context, reason auth.SweepReason, userID string) error {
		if reason != auth.SweepAccountRemoved && reason != auth.SweepAccountAnonymized {
			return nil
		}
		for _, s := range services {
			var err error
			if reason == auth.SweepAccountAnonymized {
				err = s.RemoveUserAnonymized(ctx, userID)
			} else {
				err = s.RemoveUser(ctx, userID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}
