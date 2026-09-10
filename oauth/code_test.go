package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
)

// newPKCE returns a verifier and its S256 challenge.
func newPKCE(t *testing.T) (verifier, challenge string) {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

const redirect = "https://app.example/cb"

// webClient creates a confidential authorization-code client with refresh.
func (f *fixture) webClient(t *testing.T, scopes ...string) (oauth.Client, string) {
	t.Helper()
	c, secret, err := f.svc.CreateClient(f.admin, oauth.ClientSpec{
		Name: "web", GrantTypes: []string{oauth.GrantAuthorizationCode, oauth.GrantRefreshToken},
		RedirectURIs: []string{redirect}, Scopes: scopes,
	})
	if err != nil {
		t.Fatalf("CreateClient(web): %v", err)
	}
	return c, secret
}

// authorize runs Begin → Approve → Exchange for user as the fixture's
// carol-shaped context and returns the token response.
func (f *fixture) authorize(t *testing.T, user context.Context, c oauth.Client, secret, scopeStr string, a oauth.Approval) oauth.TokenResponse {
	t.Helper()
	verifier, challenge := newPKCE(t)
	req := oauth.AuthorizationRequest{ClientID: c.ID, RedirectURI: redirect, Scope: scopeStr, State: "s", CodeChallenge: challenge, CodeChallengeMethod: "S256"}
	code, err := f.svc.Approve(user, req, a)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	resp, err := f.svc.ExchangeCode(context.Background(), oauth.CodeExchange{ClientID: c.ID, ClientSecret: secret, Code: code, RedirectURI: redirect, CodeVerifier: verifier})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	return resp
}

func TestBeginAuthorizationValidates(t *testing.T) {
	f := newFixture(t)
	c, _ := f.webClient(t, "project:read")
	ctx := context.Background()
	_, challenge := newPKCE(t)
	good := oauth.AuthorizationRequest{ClientID: c.ID, RedirectURI: redirect, Scope: "project:read", CodeChallenge: challenge, CodeChallengeMethod: "S256"}
	norm, got, err := f.svc.BeginAuthorization(ctx, good)
	if err != nil || got.ID != c.ID || norm.RedirectURI != redirect {
		t.Fatalf("Begin = %+v, %+v, %v", norm, got, err)
	}
	// A single registered URI is filled in when omitted.
	omitted := good
	omitted.RedirectURI = ""
	if norm, _, err := f.svc.BeginAuthorization(ctx, omitted); err != nil || norm.RedirectURI != redirect {
		t.Fatalf("omitted redirect = %+v, %v", norm, err)
	}
	// Scope is normalised.
	dup := good
	dup.Scope = " project:read   project:read "
	if norm, _, err := f.svc.BeginAuthorization(ctx, dup); err != nil || norm.Scope != "project:read" {
		t.Fatalf("scope normalisation = %q, %v", norm.Scope, err)
	}
	for name, tc := range map[string]struct {
		mut  func(*oauth.AuthorizationRequest)
		want error
	}{
		"unknown client":    {func(r *oauth.AuthorizationRequest) { r.ClientID = "nope" }, oauth.ErrClientNotFound},
		"unregistered URI":  {func(r *oauth.AuthorizationRequest) { r.RedirectURI = "https://evil.example/cb" }, oauth.ErrInvalidRedirectURI},
		"prefix URI":        {func(r *oauth.AuthorizationRequest) { r.RedirectURI = redirect + "/../x" }, oauth.ErrInvalidRedirectURI},
		"no challenge":      {func(r *oauth.AuthorizationRequest) { r.CodeChallenge, r.CodeChallengeMethod = "", "" }, oauth.ErrPKCERequired},
		"plain challenge":   {func(r *oauth.AuthorizationRequest) { r.CodeChallengeMethod = "plain" }, oauth.ErrPKCERequired},
		"short challenge":   {func(r *oauth.AuthorizationRequest) { r.CodeChallenge = "abc" }, oauth.ErrPKCERequired},
		"scope not allowed": {func(r *oauth.AuthorizationRequest) { r.Scope = "project:delete" }, oauth.ErrInvalidScope},
	} {
		req := good
		tc.mut(&req)
		if _, _, err := f.svc.BeginAuthorization(ctx, req); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	// A disabled client, and one without the grant.
	if err := f.svc.DisableClient(f.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.BeginAuthorization(ctx, good); !errors.Is(err, oauth.ErrClientDisabled) {
		t.Fatalf("disabled client err = %v", err)
	}
	cc, _ := f.mustCC(t, f.ccSpec())
	req := good
	req.ClientID = cc.ID
	if _, _, err := f.svc.BeginAuthorization(ctx, req); !errors.Is(err, oauth.ErrUnauthorizedClient) {
		t.Fatalf("client without authorization_code err = %v", err)
	}
}

func TestAuthorizationCodeFlowDelegatesWithinTheUsersCurrentStanding(t *testing.T) {
	f := newFixture(t)
	c, secret := f.webClient(t)
	ctx := context.Background()
	// Bob (admin) delegates project:read only.
	resp := f.authorize(t, f.admin, c, secret, "project:read", oauth.Approval{Permissions: map[string][]access.Action{"project": {"read"}}})
	if resp.RefreshToken == "" || resp.TokenType != "Bearer" || resp.Scope != "project:read" {
		t.Fatalf("response = %+v", resp)
	}
	claims, err := f.signer.Parse(resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "bob" || claims.Actor == nil || claims.Actor.Subject != c.ID || claims.ClientID != c.ID ||
		claims.Extra[oauth.ExtraGrantID] == "" || claims.Extra[oauth.ExtraContainerID] != f.orgID || claims.Extra[oauth.ExtraKind] != nil {
		t.Fatalf("claims = %+v", claims)
	}
	p, err := f.svc.Authenticate(ctx, resp.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Kind != apikey.KindDelegated || p.ID != "bob" || p.ClientID != c.ID || p.GrantID == "" || p.ContainerID != f.orgID || p.Permissions == nil {
		t.Fatalf("principal = %+v", p)
	}
	agent := apikey.WithPrincipal(ctx, p)
	if !can(t, f.orgSvc, agent, "project", "read") {
		t.Fatal("the agent should read: bob can, and the cap allows it")
	}
	if can(t, f.orgSvc, agent, "project", "delete") {
		t.Fatal("the agent must not delete: the cap removes it even though bob could")
	}
	if !can(t, f.orgSvc, f.admin, "project", "delete") {
		t.Fatal("bob himself can delete")
	}
	// Bob's role is lowered: the agent loses with him, no token change.
	if err := f.orgSvc.ChangeMemberRole(f.owner, "bob", org.RoleMember); err != nil {
		t.Fatal(err)
	}
	if can(t, f.orgSvc, agent, "project", "read") {
		t.Fatal("after bob's demotion the agent must not read: the cap intersects with the CURRENT standing")
	}
	// Bob removed entirely: Can folds to false, no error.
	if err := f.orgSvc.RemoveMember(f.owner, "bob"); err != nil {
		t.Fatal(err)
	}
	if can(t, f.orgSvc, agent, "project", "read") {
		t.Fatal("after bob's removal the agent has no standing")
	}
	if e, ok := f.lastEvent(oauth.TokenIssued); !ok || e.Detail != oauth.GrantAuthorizationCode || e.ActorID != "bob" || e.GrantID != p.GrantID {
		t.Fatalf("TokenIssued = %+v, %v", e, ok)
	}
	if e, ok := f.lastEvent(oauth.GrantCreated); !ok || e.ActorID != "bob" || e.ClientID != c.ID {
		t.Fatalf("GrantCreated = %+v, %v", e, ok)
	}
}

func TestApproveEscalationGuards(t *testing.T) {
	f := newFixture(t)
	c, _ := f.webClient(t)
	_, challenge := newPKCE(t)
	req := oauth.AuthorizationRequest{ClientID: c.ID, RedirectURI: redirect, CodeChallenge: challenge, CodeChallengeMethod: "S256"}

	// A cap above the approver's standing: carol (member) holds nothing.
	if _, err := f.svc.Approve(f.member, req, oauth.Approval{Permissions: map[string][]access.Action{"project": {"read"}}}); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("member delegating project:read err = %v, want ErrPrivilegeEscalation", err)
	}
	// An uncapped delegation of a standing that is nothing is still fine
	// (the agent can do nothing, exactly as carol can).
	if _, err := f.svc.Approve(f.member, req, oauth.Approval{}); err != nil {
		t.Fatalf("member delegating her whole (empty) standing: %v", err)
	}
	// A non-member cannot delegate at all.
	stranger := org.WithOrg(org.WithSubject(context.Background(), "zed"), f.orgID)
	if _, err := f.svc.Approve(stranger, req, oauth.Approval{}); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("non-member err = %v, want ErrNotMember", err)
	}
	// An admin above the owner: organization:delete is not admin's.
	if _, err := f.svc.Approve(f.admin, req, oauth.Approval{Permissions: map[string][]access.Action{org.ResourceOrganization: {org.ActionDelete}}}); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("admin delegating organization:delete err = %v, want ErrPrivilegeEscalation", err)
	}
	// The owner is elevated and may.
	if _, err := f.svc.Approve(f.owner, req, oauth.Approval{Permissions: map[string][]access.Action{org.ResourceOrganization: {org.ActionDelete}}}); err != nil {
		t.Fatalf("owner delegating organization:delete: %v", err)
	}
	// An empty cap is refused.
	if _, err := f.svc.Approve(f.admin, req, oauth.Approval{Permissions: map[string][]access.Action{}}); !errors.Is(err, oauth.ErrEmptyPermissions) {
		t.Fatalf("empty cap err = %v, want ErrEmptyPermissions", err)
	}
	// An undeclared permission fails closed.
	if _, err := f.svc.Approve(f.admin, req, oauth.Approval{Permissions: map[string][]access.Action{"project": {"launch"}}}); err == nil {
		t.Fatal("an undeclared (resource, action) pair compiled")
	}
}

func TestACappedApproverDelegatesNoMoreThanTheCap(t *testing.T) {
	f := newFixture(t)
	c, secret := f.webClient(t)
	// Bob acts through a restricted key: project:read only.
	ceiling, _ := f.orgSvc.Access().Permission(map[string][]access.Action{"project": {"read"}})
	capped := scope.WithPermissionCap(f.admin, ceiling)
	_, challenge := newPKCE(t)
	req := oauth.AuthorizationRequest{ClientID: c.ID, RedirectURI: redirect, CodeChallenge: challenge, CodeChallengeMethod: "S256"}
	if _, err := f.svc.Approve(capped, req, oauth.Approval{Permissions: map[string][]access.Action{"project": {"deploy"}}}); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("capped approver delegating beyond the cap err = %v, want ErrPrivilegeEscalation", err)
	}
	// No explicit cap: the grant is capped to the approver's capped standing.
	resp := f.authorize(t, capped, c, secret, "", oauth.Approval{})
	p, err := f.svc.Authenticate(context.Background(), resp.AccessToken)
	if err != nil || p.Permissions == nil {
		t.Fatalf("principal = %+v, %v; want a cap inherited from the approver", p, err)
	}
	agent := apikey.WithPrincipal(context.Background(), p)
	if !can(t, f.orgSvc, agent, "project", "read") || can(t, f.orgSvc, agent, "project", "deploy") {
		t.Fatal("the agent must hold exactly the approver's capped standing")
	}
}

func TestScopeMapTurnsScopesIntoTheCap(t *testing.T) {
	f := newFixture(t, oauth.WithScopeMap(map[string]map[string][]access.Action{
		"project:read":   {"project": {"read"}},
		"project:deploy": {"project": {"deploy"}},
		"org:admin":      {org.ResourceMember: {org.ActionCreate, org.ActionDelete}},
	}))
	c, secret := f.webClient(t)
	ctx := context.Background()
	resp := f.authorize(t, f.owner, c, secret, "project:read project:deploy", oauth.Approval{})
	p, err := f.svc.Authenticate(ctx, resp.AccessToken)
	if err != nil || p.Permissions == nil {
		t.Fatalf("principal = %+v, %v", p, err)
	}
	agent := apikey.WithPrincipal(ctx, p)
	if !can(t, f.orgSvc, agent, "project", "read") || !can(t, f.orgSvc, agent, "project", "deploy") || can(t, f.orgSvc, agent, "project", "delete") {
		t.Fatal("the cap must be the union of the approved scopes and nothing more — even for the owner")
	}
	if can(t, f.orgSvc, agent, org.ResourceMember, org.ActionCreate) {
		t.Fatal("a scope not requested confers nothing")
	}
	// A scope the map does not know, and no scope at all.
	_, challenge := newPKCE(t)
	req := oauth.AuthorizationRequest{ClientID: c.ID, RedirectURI: redirect, Scope: "everything", CodeChallenge: challenge, CodeChallengeMethod: "S256"}
	if _, _, err := f.svc.BeginAuthorization(ctx, req); !errors.Is(err, oauth.ErrInvalidScope) {
		t.Fatalf("unknown scope err = %v", err)
	}
	req.Scope = ""
	if _, err := f.svc.Approve(f.owner, req, oauth.Approval{}); !errors.Is(err, oauth.ErrInvalidScope) {
		t.Fatalf("no scope with a map err = %v, want ErrInvalidScope", err)
	}
	// An admin requesting org:admin gets refused only if it exceeds them:
	// member:create/delete is admin's, so it passes; carol cannot.
	req.Scope = "org:admin"
	if _, err := f.svc.Approve(f.member, req, oauth.Approval{}); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("member approving org:admin err = %v, want ErrPrivilegeEscalation", err)
	}
	if _, err := f.svc.Approve(f.admin, req, oauth.Approval{}); err != nil {
		t.Fatalf("admin approving org:admin: %v", err)
	}
}

func TestExchangeCodeRefusals(t *testing.T) {
	f := newFixture(t)
	c, secret := f.webClient(t)
	ctx := context.Background()
	mint := func() (code, verifier string) {
		verifier, challenge := newPKCE(t)
		req := oauth.AuthorizationRequest{ClientID: c.ID, RedirectURI: redirect, CodeChallenge: challenge, CodeChallengeMethod: "S256"}
		code, err := f.svc.Approve(f.admin, req, oauth.Approval{})
		if err != nil {
			t.Fatal(err)
		}
		return code, verifier
	}
	exchange := func(code, verifier, uri string) error {
		_, err := f.svc.ExchangeCode(ctx, oauth.CodeExchange{ClientID: c.ID, ClientSecret: secret, Code: code, RedirectURI: uri, CodeVerifier: verifier})
		return err
	}

	// Wrong verifier: refused, and the code is consumed.
	code, verifier := mint()
	if err := exchange(code, verifier+"x", redirect); !errors.Is(err, oauth.ErrPKCEMismatch) {
		t.Fatalf("wrong verifier err = %v", err)
	}
	if err := exchange(code, verifier, redirect); !errors.Is(err, oauth.ErrCodeReused) {
		t.Fatalf("code after a failed exchange err = %v, want ErrCodeReused (consumed)", err)
	}
	// Short verifier.
	code, _ = mint()
	if err := exchange(code, "short", redirect); !errors.Is(err, oauth.ErrPKCEMismatch) {
		t.Fatalf("short verifier err = %v", err)
	}
	// Wrong redirect URI; an omitted one is accepted.
	code, verifier = mint()
	if err := exchange(code, verifier, "https://other.example/cb"); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("wrong redirect err = %v", err)
	}
	code, verifier = mint()
	if err := exchange(code, verifier, ""); err != nil {
		t.Fatalf("omitted redirect_uri: %v", err)
	}
	// Unknown code.
	if err := exchange("nope", verifier, redirect); !errors.Is(err, oauth.ErrInvalidGrant) || !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("unknown code err = %v", err)
	}
	// Expired code: consumed and refused.
	code, verifier = mint()
	f.clock.Advance(2 * time.Minute)
	if err := exchange(code, verifier, redirect); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("expired code err = %v", err)
	}
	// Client authentication and grant type.
	code, verifier = mint()
	if _, err := f.svc.ExchangeCode(ctx, oauth.CodeExchange{ClientID: c.ID, ClientSecret: "wrong", Code: code, CodeVerifier: verifier}); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("wrong secret err = %v", err)
	}
	cc, ccSecret := f.mustCC(t, f.ccSpec())
	if _, err := f.svc.ExchangeCode(ctx, oauth.CodeExchange{ClientID: cc.ID, ClientSecret: ccSecret, Code: code, CodeVerifier: verifier}); !errors.Is(err, oauth.ErrUnauthorizedClient) {
		t.Fatalf("client without the grant err = %v", err)
	}
}

func TestReplayedCodeRevokesTheGrant(t *testing.T) {
	f := newFixture(t)
	c, secret := f.webClient(t)
	ctx := context.Background()
	verifier, challenge := newPKCE(t)
	req := oauth.AuthorizationRequest{ClientID: c.ID, RedirectURI: redirect, CodeChallenge: challenge, CodeChallengeMethod: "S256"}
	code, err := f.svc.Approve(f.admin, req, oauth.Approval{})
	if err != nil {
		t.Fatal(err)
	}
	x := oauth.CodeExchange{ClientID: c.ID, ClientSecret: secret, Code: code, RedirectURI: redirect, CodeVerifier: verifier}
	resp, err := f.svc.ExchangeCode(ctx, x)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); err != nil {
		t.Fatal(err)
	}
	// The replay.
	if _, err := f.svc.ExchangeCode(ctx, x); !errors.Is(err, oauth.ErrCodeReused) {
		t.Fatalf("replay err = %v, want ErrCodeReused", err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrGrantRevoked) {
		t.Fatalf("access token after the replay err = %v, want ErrInvalidToken wrapping ErrGrantRevoked", err)
	}
	if _, err := f.svc.Refresh(ctx, c.ID, secret, resp.RefreshToken); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("refresh after the replay err = %v, want ErrInvalidGrant (the token was deleted with the grant)", err)
	}
	if e, ok := f.lastEvent(oauth.TokenReuseDetected); !ok || e.Detail != oauth.DetailCodeReplayed {
		t.Fatalf("TokenReuseDetected = %+v, %v", e, ok)
	}
	if e, ok := f.lastEvent(oauth.GrantRevoked); !ok || e.Detail != oauth.DetailCodeReplayed {
		t.Fatalf("GrantRevoked = %+v, %v", e, ok)
	}
	// A code presented by another client revokes too.
	other, otherSecret := f.webClient(t)
	verifier, challenge = newPKCE(t)
	req.CodeChallenge = challenge
	code, err = f.svc.Approve(f.admin, req, oauth.Approval{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ExchangeCode(ctx, oauth.CodeExchange{ClientID: other.ID, ClientSecret: otherSecret, Code: code, CodeVerifier: verifier}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("wrong client err = %v", err)
	}
	if e, ok := f.lastEvent(oauth.GrantRevoked); !ok || e.Detail != oauth.DetailWrongClient {
		t.Fatalf("GrantRevoked = %+v, %v", e, ok)
	}
	grants, _ := f.svc.ListGrants(f.admin)
	if len(grants) != 0 {
		t.Fatalf("bob's live grants = %d, want 0 — both were revoked", len(grants))
	}
}

func TestRefreshRotatesAndReplayRevokesFamilyAndGrant(t *testing.T) {
	f := newFixture(t)
	c, secret := f.webClient(t)
	ctx := context.Background()
	first := f.authorize(t, f.admin, c, secret, "", oauth.Approval{})

	second, err := f.svc.Refresh(ctx, c.ID, secret, first.RefreshToken)
	if err != nil || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken {
		t.Fatalf("Refresh = %+v, %v", second, err)
	}
	if _, err := f.svc.Authenticate(ctx, second.AccessToken); err != nil {
		t.Fatal(err)
	}
	if e, ok := f.lastEvent(oauth.TokenRefreshed); !ok || e.ActorID != "bob" || e.ClientID != c.ID {
		t.Fatalf("TokenRefreshed = %+v, %v", e, ok)
	}
	// A refresh token introspects as active until rotated.
	if in, err := f.svc.Introspect(ctx, second.RefreshToken); err != nil || !in.Active || in.TokenType != "refresh_token" || in.Subject != "bob" || in.ClientID != c.ID {
		t.Fatalf("Introspect(refresh) = %+v, %v", in, err)
	}
	if in, err := f.svc.Introspect(ctx, first.RefreshToken); err != nil || in.Active {
		t.Fatalf("Introspect(rotated refresh) = %+v, %v; want inactive", in, err)
	}
	// The replay of the first token.
	if _, err := f.svc.Refresh(ctx, c.ID, secret, first.RefreshToken); !errors.Is(err, oauth.ErrTokenReuse) {
		t.Fatalf("replay err = %v, want ErrTokenReuse", err)
	}
	if _, err := f.svc.Refresh(ctx, c.ID, secret, second.RefreshToken); !errors.Is(err, oauth.ErrInvalidGrant) || !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("the current token after a replay err = %v, want ErrInvalidGrant wrapping ErrRefreshNotFound (family deleted)", err)
	}
	if _, err := f.svc.Authenticate(ctx, second.AccessToken); !errors.Is(err, oauth.ErrGrantRevoked) {
		t.Fatalf("access token after a replay err = %v, want ErrGrantRevoked", err)
	}
	if e, ok := f.lastEvent(oauth.TokenReuseDetected); !ok || e.Detail != oauth.DetailRefreshReplayed {
		t.Fatalf("TokenReuseDetected = %+v, %v", e, ok)
	}
}

func TestRefreshRefusals(t *testing.T) {
	f := newFixture(t)
	c, secret := f.webClient(t)
	ctx := context.Background()
	resp := f.authorize(t, f.admin, c, secret, "", oauth.Approval{})
	if _, err := f.svc.Refresh(ctx, c.ID, secret, "unknown"); !errors.Is(err, oauth.ErrInvalidGrant) || !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("unknown token err = %v", err)
	}
	if _, err := f.svc.Refresh(ctx, c.ID, "wrong", resp.RefreshToken); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("wrong secret err = %v", err)
	}
	// Another client presenting the token: refused and revoked.
	other, otherSecret := f.webClient(t)
	if _, err := f.svc.Refresh(ctx, other.ID, otherSecret, resp.RefreshToken); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("wrong client err = %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrGrantRevoked) {
		t.Fatalf("after a wrong-client refresh the grant must be revoked: %v", err)
	}
	// A client without refresh_token never gets one and cannot refresh.
	noRefresh, nrSecret, err := f.svc.CreateClient(f.admin, oauth.ClientSpec{Name: "nr", GrantTypes: []string{oauth.GrantAuthorizationCode}, RedirectURIs: []string{redirect}})
	if err != nil {
		t.Fatal(err)
	}
	nr := f.authorize(t, f.admin, noRefresh, nrSecret, "", oauth.Approval{})
	if nr.RefreshToken != "" {
		t.Fatal("a client without refresh_token was issued a refresh token")
	}
	if _, err := f.svc.Refresh(ctx, noRefresh.ID, nrSecret, "x"); !errors.Is(err, oauth.ErrUnauthorizedClient) {
		t.Fatalf("refresh without the grant type err = %v", err)
	}
	// Expired refresh token: consumed, refused, and a later replay is still a replay.
	short := oauth.New(f.st, f.orgSvc.Service, f.signer, oauth.WithIssuer(issuer), oauth.WithClock(f.clock.Now), oauth.WithRefreshTTL(time.Minute))
	verifier, challenge := newPKCE(t)
	code, err := short.Approve(f.admin, oauth.AuthorizationRequest{ClientID: c.ID, RedirectURI: redirect, CodeChallenge: challenge, CodeChallengeMethod: "S256"}, oauth.Approval{})
	if err != nil {
		t.Fatal(err)
	}
	sresp, err := short.ExchangeCode(ctx, oauth.CodeExchange{ClientID: c.ID, ClientSecret: secret, Code: code, CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(2 * time.Minute)
	if _, err := short.Refresh(ctx, c.ID, secret, sresp.RefreshToken); !errors.Is(err, oauth.ErrInvalidGrant) || errors.Is(err, oauth.ErrTokenReuse) {
		t.Fatalf("expired token err = %v, want ErrInvalidGrant", err)
	}
	if _, err := short.Refresh(ctx, c.ID, secret, sresp.RefreshToken); !errors.Is(err, oauth.ErrTokenReuse) {
		t.Fatalf("replay of a consumed expired token err = %v, want ErrTokenReuse", err)
	}
	// A revoked grant refuses refresh with its own sentinel.
	g := f.authorize(t, f.owner, c, secret, "", oauth.Approval{})
	grants, _ := f.svc.ListGrants(f.owner)
	if err := f.svc.RevokeGrant(f.owner, grants[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(ctx, c.ID, secret, g.RefreshToken); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("refresh under a revoked grant err = %v (the token went with the grant)", err)
	}
}

func TestRevokeIsRFC7009(t *testing.T) {
	f := newFixture(t)
	c, secret := f.webClient(t)
	ctx := context.Background()
	// A refresh token: family and grant gone.
	resp := f.authorize(t, f.admin, c, secret, "", oauth.Approval{})
	if err := f.svc.Revoke(ctx, c.ID, secret, resp.RefreshToken); err != nil {
		t.Fatalf("Revoke(refresh): %v", err)
	}
	if _, err := f.svc.Refresh(ctx, c.ID, secret, resp.RefreshToken); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("refresh after revoke err = %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrGrantRevoked) {
		t.Fatalf("access after revoke err = %v", err)
	}
	if e, ok := f.lastEvent(oauth.GrantRevoked); !ok || e.Detail != oauth.DetailClientRevoked || e.ActorID != "" {
		t.Fatalf("GrantRevoked = %+v, %v", e, ok)
	}
	// An access token: its grant is revoked.
	resp = f.authorize(t, f.admin, c, secret, "", oauth.Approval{})
	if err := f.svc.Revoke(ctx, c.ID, secret, resp.AccessToken); err != nil {
		t.Fatalf("Revoke(access): %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrGrantRevoked) {
		t.Fatalf("access after revoking the access token err = %v", err)
	}
	// Unknown tokens succeed; another client's token is refused.
	if err := f.svc.Revoke(ctx, c.ID, secret, "no-such-token"); err != nil {
		t.Fatalf("Revoke(unknown) = %v, want nil", err)
	}
	resp = f.authorize(t, f.admin, c, secret, "", oauth.Approval{})
	other, otherSecret := f.webClient(t)
	if err := f.svc.Revoke(ctx, other.ID, otherSecret, resp.RefreshToken); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("Revoke(other client's refresh) = %v, want ErrInvalidGrant", err)
	}
	if err := f.svc.Revoke(ctx, other.ID, otherSecret, resp.AccessToken); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("Revoke(other client's access) = %v, want ErrInvalidGrant", err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); err != nil {
		t.Fatalf("a refused revocation revoked something: %v", err)
	}
	// A client-credentials token has nothing to revoke.
	cc, ccSecret := f.mustCC(t, f.ccSpec())
	ccResp, err := f.svc.ClientCredentials(ctx, cc.ID, ccSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(ctx, cc.ID, ccSecret, ccResp.AccessToken); err != nil {
		t.Fatalf("Revoke(client-credentials token) = %v, want nil", err)
	}
	if _, err := f.svc.Authenticate(ctx, ccResp.AccessToken); err != nil {
		t.Fatalf("a client-credentials token cannot be recalled: %v", err)
	}
	// Client authentication first.
	if err := f.svc.Revoke(ctx, c.ID, "wrong", resp.RefreshToken); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("Revoke with a wrong secret = %v", err)
	}
}

func TestListAndRevokeGrantsAreTheUsersOwn(t *testing.T) {
	f := newFixture(t)
	c, secret := f.webClient(t)
	ctx := context.Background()
	bobTok := f.authorize(t, f.admin, c, secret, "", oauth.Approval{})
	f.authorize(t, f.admin, c, secret, "", oauth.Approval{}) // a second device
	f.authorize(t, f.owner, c, secret, "", oauth.Approval{})

	bobGrants, err := f.svc.ListGrants(f.admin)
	if err != nil || len(bobGrants) != 2 {
		t.Fatalf("bob's grants = %d, %v; want 2 — every approval is its own grant", len(bobGrants), err)
	}
	aliceGrants, _ := f.svc.ListGrants(f.owner)
	if len(aliceGrants) != 1 {
		t.Fatalf("alice's grants = %d, want 1", len(aliceGrants))
	}
	if _, err := f.svc.ListGrants(ctx); !errors.Is(err, scope.ErrSubjectMissing) {
		t.Fatalf("ListGrants without a subject err = %v", err)
	}
	// Alice, the OWNER, may not revoke bob's grant: it is his consent.
	if err := f.svc.RevokeGrant(f.owner, bobGrants[0].ID); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("owner revoking bob's grant err = %v, want ErrForbidden", err)
	}
	if err := f.svc.RevokeGrant(f.admin, "nope"); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("unknown grant err = %v", err)
	}
	// Bob revokes one of his two; the other keeps working.
	var revoked, kept oauth.Grant
	for _, g := range bobGrants {
		if g.ID == mustGrantID(t, f, bobTok.AccessToken) {
			revoked = g
		} else {
			kept = g
		}
	}
	if err := f.svc.RevokeGrant(f.admin, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RevokeGrant(f.admin, revoked.ID); err != nil {
		t.Fatalf("second revocation = %v, want nil", err)
	}
	if _, err := f.svc.Authenticate(ctx, bobTok.AccessToken); !errors.Is(err, oauth.ErrGrantRevoked) {
		t.Fatalf("revoked grant's token err = %v", err)
	}
	if _, err := f.svc.Refresh(ctx, c.ID, secret, bobTok.RefreshToken); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("revoked grant's refresh err = %v", err)
	}
	after, _ := f.svc.ListGrants(f.admin)
	if len(after) != 1 || after[0].ID != kept.ID {
		t.Fatalf("bob's grants after revoking one = %v", after)
	}
	if e, ok := f.lastEvent(oauth.GrantRevoked); !ok || e.Detail != oauth.DetailUserRevoked || e.ActorID != "bob" {
		t.Fatalf("GrantRevoked = %+v, %v", e, ok)
	}
	// A revoked grant is gone from the list, and offline verification
	// keeps accepting the token until it expires — the documented cost.
	offline := oauth.New(f.st, f.orgSvc.Service, f.signer, oauth.WithIssuer(issuer), oauth.WithOfflineVerification())
	if _, err := offline.Authenticate(ctx, bobTok.AccessToken); err != nil {
		t.Fatalf("offline verification after revocation = %v; want accepted until expiry", err)
	}
}

func mustGrantID(t *testing.T, f *fixture, raw string) string {
	t.Helper()
	claims, err := f.signer.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := claims.Extra[oauth.ExtraGrantID].(string)
	return id
}

func TestGrantTTLAndPurge(t *testing.T) {
	f := newFixture(t, oauth.WithGrantTTL(time.Hour))
	c, secret := f.webClient(t)
	ctx := context.Background()
	resp := f.authorize(t, f.admin, c, secret, "", oauth.Approval{})
	grants, _ := f.svc.ListGrants(f.admin)
	if len(grants) != 1 || grants[0].ExpiresAt == nil {
		t.Fatalf("grants = %+v", grants)
	}
	f.clock.Advance(2 * time.Hour)
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrGrantExpired) {
		t.Fatalf("expired grant err = %v", err)
	}
	if _, err := f.svc.Refresh(ctx, c.ID, secret, resp.RefreshToken); !errors.Is(err, oauth.ErrGrantExpired) {
		t.Fatalf("refresh under an expired grant err = %v", err)
	}
	f.clock.Advance(time.Hour)
	n, err := f.svc.PurgeExpired(ctx, f.clock.Now())
	if err != nil || n < 2 {
		t.Fatalf("PurgeExpired = %d, %v; want the grant and its refresh tokens at least", n, err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("purged grant err = %v", err)
	}
}
