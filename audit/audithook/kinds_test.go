package audithook

import (
	"testing"

	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/scope"
)

// Every kind each package declares, first to last, has an action name. A kind
// added upstream after the last one listed here needs its own row and a name.
func TestEveryKindHasAName(t *testing.T) {
	for k := scope.ContainerCreated; k <= scope.OwnershipTransferred; k++ {
		if a, ok := scopeActions[k]; !ok || a.kind == "" {
			t.Errorf("scope kind %d has no action name", k)
		}
	}
	for k := auth.SignedUp; k <= auth.AccountAnonymized; k++ {
		if a, ok := authActions[k]; !ok || a.kind == "" {
			t.Errorf("auth kind %d has no action name", k)
		}
	}
	for k := apikey.ServiceAccountCreated; k <= apikey.KeyAuthenticationFailed; k++ {
		if a, ok := apikeyActions[k]; !ok || a.kind == "" {
			t.Errorf("apikey kind %d has no action name", k)
		}
	}
	for k := oauth.ClientCreated; k <= oauth.AuthenticationFailed; k++ {
		if a, ok := oauthActions[k]; !ok || a.kind == "" {
			t.Errorf("oauth kind %d has no action name", k)
		}
	}
	for name, n := range map[string]int{"scope": len(scopeActions), "auth": len(authActions),
		"apikey": len(apikeyActions), "oauth": len(oauthActions)} {
		if want := map[string]int{"scope": 8, "auth": 24, "apikey": 9, "oauth": 14}[name]; n != want {
			t.Errorf("%s table has %d rows, want %d", name, n, want)
		}
	}
}
