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
