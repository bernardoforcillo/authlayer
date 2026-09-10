// Command agents is a runnable, database-free tour of the oauth package:
// an authlayer application as an OAuth 2.1 authorization server for agents
// and machine clients, with tokens that never carry more power than the
// human or service account behind them.
//
//	go run ./examples/agents
//
// Everything runs against store/memory with an EdDSA signer whose JWKS is
// printed, so there is no database and no setup. examples/apikey covers
// service accounts and keys; this one exists because the interesting
// behaviour is at the seam between oauth, apikey and scope: a delegated
// token authenticates as the USER with the CLIENT as actor, capped, and
// the engine intersects that cap with the user's current standing at every
// check — so revoking the human's role revokes the agent, without touching
// a token.
//
// # What is deliberately NOT here
//
// Endpoints, a consent screen, and a client's token storage. Every call
// below is one an HTTP handler would make after decoding a request; the
// structs it returns are the response bodies, and the sentinels map to
// error codes through oauth.ErrorCode. This program prints secrets and
// tokens so the trace is readable; in production those strings are the
// credentials, and printing them is the one thing this example does that
// yours must not.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

// clock is a hand-advanced clock, so the device flow's polling interval
// passes when the tour says so rather than when a wall clock does.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func main() {
	ctx := context.Background()
	clk := &clock{now: time.Now().UTC()}

	// -- 1. Wire the three services ----------------------------------------
	//
	// org/scope owns membership and permissions; apikey owns service
	// accounts; oauth owns clients, grants and tokens. oauth.New takes the
	// *scope.Service as its Authority (org.Service embeds it as .Service),
	// a token.Signer, and the issuer every token is scoped to.
	orgSvc := org.New(
		org.NewAccess(map[string][]access.Action{"project": {"read", "deploy", "delete"}}),
		memory.New[org.Organization, org.Member]())
	keyStore := memory.NewAPIKeyStore()
	keySvc := apikey.New(orgSvc.Service, keyStore)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	signer, err := token.EdDSA("2026-09", priv, nil)
	must(err)

	as := oauth.New(memory.NewOAuthStore(), orgSvc.Service, signer,
		oauth.WithIssuer("https://auth.example"),
		oauth.WithClock(clk.Now),
		oauth.WithServiceAccounts(keyStore),
		oauth.WithDynamicRegistration(true),
		oauth.WithScopeMap(map[string]map[string][]access.Action{
			"project:read":   {"project": {"read"}},
			"project:deploy": {"project": {"deploy"}},
		}),
		oauth.WithHooks(oauth.HookFunc(func(_ context.Context, e oauth.Event) error {
			if e.Kind == oauth.TokenReuseDetected || e.Kind == oauth.GrantRevoked {
				fmt.Printf("  event %s grant=%s detail=%s\n", kindName(e.Kind), short(e.GrantID), e.Detail)
			}
			return nil
		})),
	)

	step("an organization, its owner, and a service account")
	alice := org.WithSubject(ctx, "alice")
	acme, err := orgSvc.CreateOrganization(alice, "Acme", "acme")
	must(err)
	owner := org.WithOrg(alice, acme.ID)
	_, err = orgSvc.AddMember(owner, "bob", org.RoleAdmin)
	must(err)
	_, err = orgSvc.CreateRole(owner, "deployer", "Deployer", map[string][]access.Action{"project": {"read", "deploy"}})
	must(err)
	sa, err := keySvc.CreateServiceAccount(owner, "ci", "deploys main", "deployer")
	must(err)
	fmt.Printf("  org %q: alice owner, bob admin; service account %s at role deployer\n", acme.Name, short(sa.ID))

	// -- 2. Client credentials: a machine client acts as the account --------
	//
	// The client is a credential of the service account, so minting it is
	// guarded like minting an API key: the cap within the account's role,
	// and within bob's own standing. The secret comes back exactly once.
	step("client credentials")
	cc, secret, err := as.CreateClient(org.WithOrg(org.WithSubject(ctx, "bob"), acme.ID), oauth.ClientSpec{
		Name: "ci bot", GrantTypes: []string{oauth.GrantClientCredentials},
		ServiceAccountID: sa.ID, Scopes: []string{"project:read", "project:deploy"},
		Permissions: map[string][]access.Action{"project": {"read", "deploy"}},
	})
	must(err)
	fmt.Printf("  client %s (confidential) secret (deliver once): %s…\n", short(cc.ID), secret[:8])
	tr, err := as.ClientCredentials(ctx, cc.ID, secret, "project:deploy")
	must(err)
	fmt.Printf("  token_type=%s expires_in=%d scope=%q refresh=%v\n", tr.TokenType, tr.ExpiresIn, tr.Scope, tr.RefreshToken != "")
	p, err := as.Authenticate(ctx, tr.AccessToken)
	must(err)
	fmt.Printf("  principal kind=%s sub=%s client=%s\n", p.Kind, short(p.ID), short(p.ClientID))
	bot := apikey.WithPrincipal(ctx, p)
	report("bot project:deploy (in role, in cap)", can(orgSvc, bot, "project", "deploy"), true)
	report("bot project:delete (not in role)", can(orgSvc, bot, "project", "delete"), false)
	report("bot member:create  (not in role)", can(orgSvc, bot, org.ResourceMember, org.ActionCreate), false)

	// -- 3. Device flow: an agent with no browser, approved by a person -----
	//
	// A public client has no secret; PKCE and client identity are what it
	// has, and a user's approval is the only source of its power. Bob
	// approves with a cap of project:read even though he holds far more.
	step("device authorization")
	bob := org.WithOrg(org.WithSubject(ctx, "bob"), acme.ID)
	cli, _, err := as.CreateClient(bob, oauth.ClientSpec{
		Name: "cli-agent", Public: true, GrantTypes: []string{oauth.GrantDeviceCode, oauth.GrantRefreshToken},
	})
	must(err)
	dr, err := as.BeginDeviceAuthorization(ctx, cli.ID, "project:read project:deploy")
	must(err)
	fmt.Printf("  the agent shows: enter code %s (expires in %ds, poll every %ds)\n", dr.UserCode, dr.ExpiresIn, dr.Interval)
	_, err = as.PollDevice(ctx, cli.ID, "", dr.DeviceCode)
	reportErr("agent polls before approval", err, oauth.ErrAuthorizationPending, "ErrAuthorizationPending")
	pending, client, err := as.DeviceByUserCode(ctx, strings.ToLower(dr.UserCode))
	must(err)
	fmt.Printf("  consent screen: %q asks for scope %q\n", client.Name, pending.Scope)
	must(as.ApproveDevice(bob, dr.UserCode, oauth.Approval{Permissions: map[string][]access.Action{"project": {"read"}}}))
	fmt.Println("  bob approves with a cap of project:read only")
	clk.advance(time.Duration(dr.Interval+1) * time.Second)
	agentTokens, err := as.PollDevice(ctx, cli.ID, "", dr.DeviceCode)
	must(err)
	ap, err := as.Authenticate(ctx, agentTokens.AccessToken)
	must(err)
	fmt.Printf("  principal kind=%s sub=%s act=%s grant=%s capped=%v\n", ap.Kind, ap.ID, short(ap.ClientID), short(ap.GrantID), ap.Permissions != nil)
	agent := apikey.WithPrincipal(ctx, ap)
	report("agent project:read   (bob can, cap allows)", can(orgSvc, agent, "project", "read"), true)
	report("agent project:delete (bob can, cap removes)", can(orgSvc, agent, "project", "delete"), false)
	report("bob   project:delete (himself)", can(orgSvc, bob, "project", "delete"), true)
	// The cap is intersected with bob's CURRENT standing: demote him and
	// the agent loses with him, without any token changing hands.
	must(orgSvc.ChangeMemberRole(owner, "bob", org.RoleMember))
	report("agent project:read after bob's demotion", can(orgSvc, agent, "project", "read"), false)
	must(orgSvc.ChangeMemberRole(owner, "bob", org.RoleAdmin))

	// -- 4. Refresh, and a replay ------------------------------------------
	step("refresh rotation and reuse detection")
	second, err := as.Refresh(ctx, cli.ID, "", agentTokens.RefreshToken)
	must(err)
	fmt.Println("  refreshed: a new access token and a new refresh token")
	_, err = as.Refresh(ctx, cli.ID, "", agentTokens.RefreshToken)
	reportErr("the OLD refresh token replayed", err, oauth.ErrTokenReuse, "ErrTokenReuse")
	_, err = as.Authenticate(ctx, second.AccessToken)
	reportErr("the new access token after the replay", err, oauth.ErrGrantRevoked, "ErrInvalidToken wrapping ErrGrantRevoked")

	// -- 5. Authorization code with PKCE, for a dynamically registered client
	step("authorization code + PKCE for an MCP-style client")
	mcp, _, err := as.RegisterClient(ctx, oauth.ClientRegistration{
		ClientName: "mcp-client", RedirectURIs: []string{"http://127.0.0.1:8123/callback"},
		TokenEndpointAuthMethod: oauth.AuthMethodNone, Scope: "project:read",
	})
	must(err)
	fmt.Printf("  registered %q as client %s (public, application-level)\n", mcp.Name, short(mcp.ID))
	verifier, challenge := pkce()
	req, _, err := as.BeginAuthorization(ctx, oauth.AuthorizationRequest{
		ClientID: mcp.ID, Scope: "project:read", State: "xyz", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	must(err)
	code, err := as.Approve(owner, req, oauth.Approval{}) // cap from the scope map
	must(err)
	fmt.Printf("  alice approves; redirect to %s?code=…&state=%s\n", req.RedirectURI, req.State)
	_, err = as.ExchangeCode(ctx, oauth.CodeExchange{ClientID: mcp.ID, Code: code, CodeVerifier: "not-the-verifier-not-the-verifier-not-the-verifier"})
	reportErr("exchange with the wrong verifier", err, oauth.ErrPKCEMismatch, "ErrPKCEMismatch")
	// A failed exchange consumed the code; approve again for the real one.
	code, err = as.Approve(owner, req, oauth.Approval{})
	must(err)
	x := oauth.CodeExchange{ClientID: mcp.ID, Code: code, CodeVerifier: verifier}
	mcpTokens, err := as.ExchangeCode(ctx, x)
	must(err)
	mp, err := as.Authenticate(ctx, mcpTokens.AccessToken)
	must(err)
	mcpCtx := apikey.WithPrincipal(ctx, mp)
	report("mcp project:read   (scope map cap)", can(orgSvc, mcpCtx, "project", "read"), true)
	report("mcp project:deploy (not in scopes)", can(orgSvc, mcpCtx, "project", "deploy"), false)
	_, err = as.ExchangeCode(ctx, x)
	reportErr("the code replayed", err, oauth.ErrCodeReused, "ErrCodeReused")

	// -- 6. Introspection and discovery ------------------------------------
	step("introspection and discovery")
	live, err := as.Introspect(ctx, tr.AccessToken)
	must(err)
	dead, err := as.Introspect(ctx, mcpTokens.AccessToken)
	must(err)
	fmt.Printf("  live client-credentials token: active=%v sub=%s\n", live.Active, short(live.Subject))
	fmt.Printf("  revoked delegated token:       active=%v\n", dead.Active)
	meta := as.ServerMetadata("", oauth.Endpoints{
		Authorization: "https://auth.example/authorize", Token: "https://auth.example/token",
		JWKS: "https://auth.example/jwks", DeviceAuthorization: "https://auth.example/device",
		Registration: "https://auth.example/register",
	})
	out, err := json.MarshalIndent(meta, "  ", "  ")
	must(err)
	fmt.Printf("  /.well-known/oauth-authorization-server:\n  %s\n", out)
	jwks, err := json.Marshal(signer.(token.PublicKeySetter).PublicKeySet())
	must(err)
	fmt.Printf("  jwks: %s\n", jwks)
	errCode, status := oauth.ErrorCode(oauth.ErrTokenReuse)
	fmt.Printf("  ErrorCode(ErrTokenReuse) = %q %d\n", errCode, status)
}

// pkce returns a verifier and its S256 challenge — what the client does
// before opening the browser.
func pkce() (verifier, challenge string) {
	var b [32]byte
	must2(rand.Read(b[:]))
	verifier = base64.RawURLEncoding.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func kindName(k oauth.EventKind) string {
	switch k {
	case oauth.TokenReuseDetected:
		return "TokenReuseDetected"
	case oauth.GrantRevoked:
		return "GrantRevoked"
	default:
		return fmt.Sprintf("EventKind(%d)", k)
	}
}

func can(svc *org.Service, ctx context.Context, resource string, action access.Action) bool {
	ok, err := svc.Can(ctx, resource, action)
	if err != nil && !errors.Is(err, scope.ErrNotMember) {
		panic(err)
	}
	return ok
}

// report prints a Can answer and panics if it is not the one the tour
// promises, so the trace is also an assertion.
func report(label string, got, want bool) {
	if got != want {
		panic(fmt.Sprintf("%s: got %v, want %v", label, got, want))
	}
	fmt.Printf("  %-44s -> %v\n", label, got)
}

// reportErr prints which sentinel a refusal came back as, and panics if it
// is not the promised one.
func reportErr(label string, err, want error, name string) {
	if !errors.Is(err, want) {
		panic(fmt.Sprintf("%s: got %v, want %s", label, err, name))
	}
	fmt.Printf("  %-44s -> %s\n", label, name)
}

func step(label string) {
	fmt.Printf("\n== %s ==\n", strings.ToUpper(label))
}

// short truncates an id for display. Never do this to a value you are
// comparing — only to one you are printing.
func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func must2(_ int, err error) { must(err) }
