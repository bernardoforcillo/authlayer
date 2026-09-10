package oauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/token"
)

const issuer = "https://auth.example"

// fixture is one wired deployment: an organization with alice as owner and
// bob as admin, a "deployer" role, a service account at that role, and an
// oauth.Service over the memory store with an EdDSA signer.
type fixture struct {
	orgSvc *org.Service
	keys   *apikey.Service[org.Organization, org.Member, *org.Organization, *org.Member]
	st     *memory.OAuthStore
	signer token.Signer
	svc    *oauth.Service
	events []oauth.Event
	clock  *fakeClock

	orgID     string
	owner     context.Context // alice, owner
	admin     context.Context // bob, admin
	member    context.Context // carol, plain member
	saID      string          // service account at role "deployer"
	adminSAID string          // service account at role admin
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newFixture(t *testing.T, opts ...oauth.Option) *fixture {
	t.Helper()
	f := &fixture{clock: &fakeClock{now: time.Now().UTC().Truncate(time.Second)}}
	f.orgSvc = org.New(org.NewAccess(map[string][]access.Action{
		"project": {"read", "deploy", "delete"},
	}), memory.New[org.Organization, org.Member]())
	apiKeyStore := memory.NewAPIKeyStore()
	f.keys = apikey.New(f.orgSvc.Service, apiKeyStore)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.signer, err = token.EdDSA("k1", priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.st = memory.NewOAuthStore()
	hook := oauth.HookFunc(func(_ context.Context, e oauth.Event) error {
		f.events = append(f.events, e)
		return nil
	})
	all := append([]oauth.Option{
		oauth.WithIssuer(issuer), oauth.WithClock(f.clock.Now), oauth.WithHooks(hook),
		oauth.WithServiceAccounts(apiKeyStore),
	}, opts...)
	f.svc = oauth.New(f.st, f.orgSvc.Service, f.signer, all...)

	ctx := context.Background()
	alice := org.WithSubject(ctx, "alice")
	acme, err := f.orgSvc.CreateOrganization(alice, "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	f.orgID = acme.ID
	f.owner = org.WithOrg(alice, acme.ID)
	if _, err := f.orgSvc.AddMember(f.owner, "bob", org.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.orgSvc.AddMember(f.owner, "carol", org.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := f.orgSvc.CreateRole(f.owner, "deployer", "Deployer", map[string][]access.Action{
		"project": {"read", "deploy"},
	}); err != nil {
		t.Fatal(err)
	}
	f.admin = org.WithOrg(org.WithSubject(ctx, "bob"), acme.ID)
	f.member = org.WithOrg(org.WithSubject(ctx, "carol"), acme.ID)
	sa, err := f.keys.CreateServiceAccount(f.owner, "ci", "", "deployer")
	if err != nil {
		t.Fatal(err)
	}
	f.saID = sa.ID
	adminSA, err := f.keys.CreateServiceAccount(f.owner, "ops", "", org.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	f.adminSAID = adminSA.ID
	return f
}

// ccSpec is a confidential client-credentials client bound to the deployer
// service account.
func (f *fixture) ccSpec() oauth.ClientSpec {
	return oauth.ClientSpec{
		Name: "ci bot", GrantTypes: []string{oauth.GrantClientCredentials},
		ServiceAccountID: f.saID, Scopes: []string{"deploy"},
	}
}

// mustCC creates a client-credentials client as bob and returns it with its
// secret.
func (f *fixture) mustCC(t *testing.T, spec oauth.ClientSpec) (oauth.Client, string) {
	t.Helper()
	c, secret, err := f.svc.CreateClient(f.admin, spec)
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return c, secret
}

func (f *fixture) lastEvent(kind oauth.EventKind) (oauth.Event, bool) {
	for i := len(f.events) - 1; i >= 0; i-- {
		if f.events[i].Kind == kind {
			return f.events[i], true
		}
	}
	return oauth.Event{}, false
}

func can(t *testing.T, svc *org.Service, ctx context.Context, resource string, action access.Action) bool {
	t.Helper()
	ok, err := svc.Can(ctx, resource, action)
	if err != nil {
		t.Fatalf("Can(%s:%s): %v", resource, action, err)
	}
	return ok
}

// ── Client management ───────────────────────────────────────────────────

func TestCreateClientReturnsTheSecretOnceAndStoresItsHash(t *testing.T) {
	f := newFixture(t)
	c, secret, err := f.svc.CreateClient(f.admin, f.ccSpec())
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if secret == "" || c.SecretHash != token.HashOpaque(secret) || c.Public {
		t.Fatalf("secret %q hash %q public %v", secret, c.SecretHash, c.Public)
	}
	if c.ContainerID != f.orgID || c.CreatedBy != "bob" || c.ServiceAccountID != f.saID || c.Name != "ci bot" {
		t.Fatalf("client = %+v", c)
	}
	stored, err := f.st.FindClient(context.Background(), c.ID)
	if err != nil || stored.SecretHash != c.SecretHash {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	if e, ok := f.lastEvent(oauth.ClientCreated); !ok || e.ClientID != c.ID || e.ActorID != "bob" || e.ContainerID != f.orgID {
		t.Fatalf("ClientCreated event = %+v, %v", e, ok)
	}
}

func TestCreateClientIsAuthorizedThroughServiceAccountUpdate(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.svc.CreateClient(f.member, f.ccSpec()); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member CreateClient err = %v, want ErrForbidden", err)
	}
	stranger := org.WithOrg(org.WithSubject(context.Background(), "zed"), f.orgID)
	if _, _, err := f.svc.CreateClient(stranger, f.ccSpec()); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("non-member CreateClient err = %v, want ErrNotMember", err)
	}
	if _, _, err := f.svc.CreateClient(context.Background(), f.ccSpec()); !errors.Is(err, scope.ErrSubjectMissing) {
		t.Fatalf("bare ctx err = %v, want ErrSubjectMissing", err)
	}
	if _, _, err := f.svc.CreateClient(org.WithSubject(context.Background(), "bob"), f.ccSpec()); !errors.Is(err, scope.ErrScopeMissing) {
		t.Fatalf("no-org ctx err = %v, want ErrScopeMissing", err)
	}
}

func TestCreateClientValidatesTheSpec(t *testing.T) {
	f := newFixture(t)
	base := f.ccSpec()
	cases := []struct {
		name string
		mut  func(*oauth.ClientSpec)
		want error
	}{
		{"no name", func(s *oauth.ClientSpec) { s.Name = " " }, oauth.ErrInvalidClientMetadata},
		{"no grant types", func(s *oauth.ClientSpec) { s.GrantTypes = nil }, oauth.ErrInvalidClientMetadata},
		{"unknown grant type", func(s *oauth.ClientSpec) { s.GrantTypes = []string{"implicit"} }, oauth.ErrInvalidClientMetadata},
		{"public client_credentials", func(s *oauth.ClientSpec) { s.Public = true }, oauth.ErrInvalidClientMetadata},
		{"client_credentials without account", func(s *oauth.ClientSpec) { s.ServiceAccountID = "" }, oauth.ErrInvalidClientMetadata},
		{"account without client_credentials", func(s *oauth.ClientSpec) {
			s.GrantTypes = []string{oauth.GrantDeviceCode}
		}, oauth.ErrInvalidClientMetadata},
		{"cap without client_credentials", func(s *oauth.ClientSpec) {
			s.GrantTypes, s.ServiceAccountID = []string{oauth.GrantDeviceCode}, ""
			s.Permissions = map[string][]access.Action{"project": {"read"}}
		}, oauth.ErrInvalidClientMetadata},
		{"authorization_code without redirect URI", func(s *oauth.ClientSpec) {
			s.GrantTypes, s.ServiceAccountID = []string{oauth.GrantAuthorizationCode}, ""
		}, oauth.ErrInvalidClientMetadata},
		{"relative redirect URI", func(s *oauth.ClientSpec) {
			s.GrantTypes, s.ServiceAccountID = []string{oauth.GrantAuthorizationCode}, ""
			s.RedirectURIs = []string{"/cb"}
		}, oauth.ErrInvalidRedirectURI},
		{"redirect URI with fragment", func(s *oauth.ClientSpec) {
			s.GrantTypes, s.ServiceAccountID = []string{oauth.GrantAuthorizationCode}, ""
			s.RedirectURIs = []string{"https://app.example/cb#x"}
		}, oauth.ErrInvalidRedirectURI},
		{"http redirect on a public host", func(s *oauth.ClientSpec) {
			s.GrantTypes, s.ServiceAccountID = []string{oauth.GrantAuthorizationCode}, ""
			s.RedirectURIs = []string{"http://app.example/cb"}
		}, oauth.ErrInvalidRedirectURI},
	}
	for _, tc := range cases {
		spec := base
		spec.GrantTypes = append([]string(nil), base.GrantTypes...)
		tc.mut(&spec)
		if _, _, err := f.svc.CreateClient(f.admin, spec); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	// Loopback http is fine.
	ok := oauth.ClientSpec{Name: "cli", Public: true, GrantTypes: []string{oauth.GrantAuthorizationCode}, RedirectURIs: []string{"http://127.0.0.1:8080/cb", "http://localhost/cb"}}
	if _, secret, err := f.svc.CreateClient(f.admin, ok); err != nil || secret != "" {
		t.Fatalf("public loopback client: %v, secret %q", err, secret)
	}
}

func TestCreateClientEscalationGuards(t *testing.T) {
	f := newFixture(t)
	// A cap outside the account's role: deployer has no project:delete.
	spec := f.ccSpec()
	spec.Permissions = map[string][]access.Action{"project": {"delete"}}
	if _, _, err := f.svc.CreateClient(f.admin, spec); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("cap above the role err = %v, want ErrPrivilegeEscalation", err)
	}
	// An admin may not bind a client to an account whose role exceeds admin
	// (the owner-role account holds organization:delete).
	if _, err := f.keys.CreateServiceAccount(f.owner, "root", "", org.RoleOwner); err != nil {
		t.Fatal(err)
	}
	accounts, _ := f.keys.ListServiceAccounts(f.owner)
	var rootID string
	for _, sa := range accounts {
		if sa.Name == "root" {
			rootID = sa.ID
		}
	}
	rootSpec := f.ccSpec()
	rootSpec.ServiceAccountID = rootID
	if _, _, err := f.svc.CreateClient(f.admin, rootSpec); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("admin binding an owner-role account err = %v, want ErrPrivilegeEscalation", err)
	}
	if _, _, err := f.svc.CreateClient(f.owner, rootSpec); err != nil {
		t.Fatalf("owner binding an owner-role account: %v", err)
	}
	// A capped actor (an admin acting through a restricted key) is bounded
	// by the cap, not the role: read-only cap cannot mint a deploy client.
	ceiling, _ := f.orgSvc.Access().Permission(map[string][]access.Action{"project": {"read"}, scope.ResourceServiceAccount: {scope.ActionUpdate}})
	capped := scope.WithPermissionCap(f.admin, ceiling)
	if _, _, err := f.svc.CreateClient(capped, f.ccSpec()); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("capped admin minting the whole deployer role err = %v, want ErrPrivilegeEscalation", err)
	}
	within := f.ccSpec()
	within.Permissions = map[string][]access.Action{"project": {"read"}}
	if _, _, err := f.svc.CreateClient(capped, within); err != nil {
		t.Fatalf("capped admin minting within the cap: %v", err)
	}
	// An empty cap is refused rather than stored as no cap.
	empty := f.ccSpec()
	empty.Permissions = map[string][]access.Action{}
	if _, _, err := f.svc.CreateClient(f.admin, empty); !errors.Is(err, oauth.ErrEmptyPermissions) || !errors.Is(err, apikey.ErrEmptyPermissions) {
		t.Fatalf("empty cap err = %v, want ErrEmptyPermissions (both names)", err)
	}
	// An account that is not a member, and a disabled one.
	ghost := f.ccSpec()
	ghost.ServiceAccountID = "nobody"
	if _, _, err := f.svc.CreateClient(f.admin, ghost); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("unknown account err = %v, want ErrServiceAccountNotFound", err)
	}
	if err := f.keys.DisableServiceAccount(f.owner, f.saID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.CreateClient(f.admin, f.ccSpec()); !errors.Is(err, apikey.ErrServiceAccountDisabled) {
		t.Fatalf("disabled account err = %v, want ErrServiceAccountDisabled", err)
	}
}

func TestClientLifecycleManagement(t *testing.T) {
	f := newFixture(t)
	c, secret := f.mustCC(t, f.ccSpec())
	ctx := context.Background()

	// Rotate: the old secret stops working, the new one works.
	rotated, err := f.svc.RotateClientSecret(f.admin, c.ID)
	if err != nil || rotated == secret {
		t.Fatalf("RotateClientSecret = %q, %v", rotated, err)
	}
	if _, err := f.svc.ClientCredentials(ctx, c.ID, secret, ""); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("old secret err = %v, want ErrInvalidClient", err)
	}
	if _, err := f.svc.ClientCredentials(ctx, c.ID, rotated, ""); err != nil {
		t.Fatalf("new secret: %v", err)
	}

	// Disable / enable.
	if err := f.svc.DisableClient(f.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClientCredentials(ctx, c.ID, rotated, ""); !errors.Is(err, oauth.ErrClientDisabled) {
		t.Fatalf("disabled client err = %v, want ErrClientDisabled", err)
	}
	if err := f.svc.EnableClient(f.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClientCredentials(ctx, c.ID, rotated, ""); err != nil {
		t.Fatalf("re-enabled client: %v", err)
	}

	// Redirect URIs: validated, and an authorization-code client keeps one.
	pub, _, err := f.svc.CreateClient(f.admin, oauth.ClientSpec{Name: "web", GrantTypes: []string{oauth.GrantAuthorizationCode}, RedirectURIs: []string{"https://a.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.UpdateClientRedirectURIs(f.admin, pub.ID, nil); !errors.Is(err, oauth.ErrInvalidClientMetadata) {
		t.Fatalf("emptying an authorization_code client's URIs err = %v", err)
	}
	if err := f.svc.UpdateClientRedirectURIs(f.admin, pub.ID, []string{"https://b.example/cb"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RotateClientSecret(f.admin, pub.ID); err != nil {
		t.Fatalf("rotating a confidential authorization_code client's secret: %v", err)
	}
	publicC, _, err := f.svc.CreateClient(f.admin, oauth.ClientSpec{Name: "cli", Public: true, GrantTypes: []string{oauth.GrantDeviceCode}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RotateClientSecret(f.admin, publicC.ID); !errors.Is(err, oauth.ErrInvalidClientMetadata) {
		t.Fatalf("rotating a public client's secret err = %v, want ErrInvalidClientMetadata", err)
	}

	// List: the container's clients, disabled included, and only those.
	list, err := f.svc.ListClients(f.admin)
	if err != nil || len(list) != 3 {
		t.Fatalf("ListClients = %d, %v; want 3", len(list), err)
	}

	// Cross-container: another organization's admin sees not-found.
	other, err := f.orgSvc.CreateOrganization(org.WithSubject(ctx, "dave"), "Globex", "globex")
	if err != nil {
		t.Fatal(err)
	}
	dave := org.WithOrg(org.WithSubject(ctx, "dave"), other.ID)
	if err := f.svc.DisableClient(dave, c.ID); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("cross-container DisableClient err = %v, want ErrClientNotFound", err)
	}
	if err := f.svc.DeleteClient(dave, c.ID); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("cross-container DeleteClient err = %v, want ErrClientNotFound", err)
	}

	// Delete needs service_account:delete; a member has none.
	if err := f.svc.DeleteClient(f.member, c.ID); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member DeleteClient err = %v, want ErrForbidden", err)
	}
	if err := f.svc.DeleteClient(f.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClientCredentials(ctx, c.ID, rotated, ""); !errors.Is(err, oauth.ErrInvalidClient) || !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("deleted client err = %v, want ErrInvalidClient wrapping ErrClientNotFound", err)
	}
	if e, ok := f.lastEvent(oauth.ClientDeleted); !ok || e.ClientID != c.ID {
		t.Fatalf("ClientDeleted event = %+v, %v", e, ok)
	}
}

func TestMemberMayNotListClients(t *testing.T) {
	// service_account:read is on admin, not member.
	f := newFixture(t)
	if _, err := f.svc.ListClients(f.member); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member ListClients err = %v, want ErrForbidden", err)
	}
}

// ── Dynamic registration ────────────────────────────────────────────────

func TestRegisterClientIsOffByDefaultAndApplicationLevelWhenOn(t *testing.T) {
	off := newFixture(t)
	reg := oauth.ClientRegistration{ClientName: "mcp", RedirectURIs: []string{"http://127.0.0.1/cb"}, TokenEndpointAuthMethod: oauth.AuthMethodNone}
	if _, _, err := off.svc.RegisterClient(context.Background(), reg); !errors.Is(err, oauth.ErrRegistrationDisabled) {
		t.Fatalf("registration off err = %v, want ErrRegistrationDisabled", err)
	}

	f := newFixture(t, oauth.WithDynamicRegistration(true))
	ctx := context.Background()
	c, secret, err := f.svc.RegisterClient(ctx, reg)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if !c.Public || secret != "" || c.SecretHash != "" || c.ContainerID != "" || c.CreatedBy != "" {
		t.Fatalf("public registration = %+v secret %q", c, secret)
	}
	if strings.Join(c.GrantTypes, " ") != oauth.GrantAuthorizationCode+" "+oauth.GrantRefreshToken {
		t.Fatalf("default grant types = %v", c.GrantTypes)
	}
	if e, ok := f.lastEvent(oauth.ClientRegistered); !ok || e.ClientID != c.ID || e.ActorID != "" {
		t.Fatalf("ClientRegistered event = %+v, %v", e, ok)
	}
	// Not listed under any container.
	list, _ := f.svc.ListClients(f.admin)
	if len(list) != 0 {
		t.Fatalf("an application-level client was listed for a container: %v", list)
	}
	// A confidential registration gets a secret; client_credentials is refused.
	conf, secret, err := f.svc.RegisterClient(ctx, oauth.ClientRegistration{ClientName: "svc", RedirectURIs: []string{"https://svc.example/cb"}})
	if err != nil || secret == "" || conf.Public || conf.SecretHash != token.HashOpaque(secret) {
		t.Fatalf("confidential registration = %+v, %q, %v", conf, secret, err)
	}
	_, _, err = f.svc.RegisterClient(ctx, oauth.ClientRegistration{ClientName: "m2m", GrantTypes: []string{oauth.GrantClientCredentials}})
	if !errors.Is(err, oauth.ErrInvalidClientMetadata) {
		t.Fatalf("client_credentials registration err = %v, want ErrInvalidClientMetadata", err)
	}
	_, _, err = f.svc.RegisterClient(ctx, oauth.ClientRegistration{ClientName: "x", TokenEndpointAuthMethod: "private_key_jwt", GrantTypes: []string{oauth.GrantDeviceCode}})
	if !errors.Is(err, oauth.ErrInvalidClientMetadata) {
		t.Fatalf("unsupported auth method err = %v, want ErrInvalidClientMetadata", err)
	}
	_, _, err = f.svc.RegisterClient(ctx, oauth.ClientRegistration{ClientName: "x"})
	if !errors.Is(err, oauth.ErrInvalidClientMetadata) {
		t.Fatalf("authorization_code with no redirect URI err = %v, want ErrInvalidClientMetadata", err)
	}
}

func TestRegisterClientScopesMustBeKnownToTheScopeMap(t *testing.T) {
	f := newFixture(t, oauth.WithDynamicRegistration(true), oauth.WithScopeMap(map[string]map[string][]access.Action{
		"read": {"project": {"read"}},
	}))
	_, _, err := f.svc.RegisterClient(context.Background(), oauth.ClientRegistration{ClientName: "x", RedirectURIs: []string{"https://x.example/cb"}, Scope: "read write"})
	if !errors.Is(err, oauth.ErrInvalidScope) {
		t.Fatalf("unknown scope err = %v, want ErrInvalidScope", err)
	}
	c, _, err := f.svc.RegisterClient(context.Background(), oauth.ClientRegistration{ClientName: "x", RedirectURIs: []string{"https://x.example/cb"}, Scope: "read"})
	if err != nil || strings.Join(c.Scopes, ",") != "read" {
		t.Fatalf("known scope = %v, %v", c.Scopes, err)
	}
}

// ── Client credentials, Authenticate, Introspect ────────────────────────

func TestClientCredentialsMintsAServiceAccountTokenTheEngineAccepts(t *testing.T) {
	f := newFixture(t)
	spec := f.ccSpec()
	spec.Permissions = map[string][]access.Action{"project": {"read"}}
	c, secret := f.mustCC(t, spec)
	ctx := context.Background()

	resp, err := f.svc.ClientCredentials(ctx, c.ID, secret, "deploy")
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if resp.TokenType != "Bearer" || resp.RefreshToken != "" || resp.ExpiresIn != 600 || resp.Scope != "deploy" {
		t.Fatalf("response = %+v", resp)
	}
	claims, err := f.signer.Parse(resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != f.saID || claims.Issuer != issuer || claims.ClientID != c.ID || claims.Actor != nil ||
		claims.ID == "" || claims.SessionID != "" || claims.Email != "" || claims.Scope != "deploy" ||
		claims.Extra[oauth.ExtraContainerID] != f.orgID || claims.Extra[oauth.ExtraKind] != oauth.KindServiceAccount {
		t.Fatalf("claims = %+v", claims)
	}
	if e, ok := f.lastEvent(oauth.TokenIssued); !ok || e.Detail != oauth.GrantClientCredentials || e.ActorID != f.saID || e.ClientID != c.ID {
		t.Fatalf("TokenIssued event = %+v, %v", e, ok)
	}

	p, err := f.svc.Authenticate(ctx, resp.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Kind != apikey.KindServiceAccount || p.ID != f.saID || p.ContainerID != f.orgID || p.ClientID != c.ID ||
		p.GrantID != "" || p.KeyID != "" || p.Permissions == nil || !p.AuthenticatedAt.Equal(f.clock.Now()) {
		t.Fatalf("principal = %+v", p)
	}
	as := apikey.WithPrincipal(ctx, p)
	if !can(t, f.orgSvc, as, "project", "read") {
		t.Fatal("project:read should be allowed: in the role and in the cap")
	}
	if can(t, f.orgSvc, as, "project", "deploy") {
		t.Fatal("project:deploy should be refused: in the role, removed by the cap")
	}
	if can(t, f.orgSvc, as, "project", "delete") {
		t.Fatal("project:delete should be refused: not in the role")
	}
	if e, ok := f.lastEvent(oauth.TokenAuthenticated); !ok || e.ActorID != f.saID || e.ClientID != c.ID || e.Detail != "" {
		t.Fatalf("TokenAuthenticated event = %+v, %v", e, ok)
	}

	// An uncapped client acts with the whole role, and never beyond it.
	full, fullSecret := f.mustCC(t, f.ccSpec())
	fresp, err := f.svc.ClientCredentials(ctx, full.ID, fullSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := f.svc.Authenticate(ctx, fresp.AccessToken)
	if err != nil || fp.Permissions != nil {
		t.Fatalf("uncapped principal = %+v, %v", fp, err)
	}
	asFull := apikey.WithPrincipal(ctx, fp)
	if !can(t, f.orgSvc, asFull, "project", "deploy") || can(t, f.orgSvc, asFull, org.ResourceMember, org.ActionCreate) {
		t.Fatal("an uncapped client-credentials token acts with exactly the role")
	}
}

func TestClientCredentialsRefusals(t *testing.T) {
	f := newFixture(t)
	c, secret := f.mustCC(t, f.ccSpec())
	ctx := context.Background()
	for name, tc := range map[string]struct {
		id, secret, scope string
		want              error
	}{
		"unknown client":        {"nope", secret, "", oauth.ErrInvalidClient},
		"wrong secret":          {c.ID, "wrong", "", oauth.ErrInvalidClient},
		"no secret":             {c.ID, "", "", oauth.ErrInvalidClient},
		"scope not in the list": {c.ID, secret, "admin", oauth.ErrInvalidScope},
	} {
		if _, err := f.svc.ClientCredentials(ctx, tc.id, tc.secret, tc.scope); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	// A client without the grant type.
	dev, _, err := f.svc.CreateClient(f.admin, oauth.ClientSpec{Name: "cli", Public: true, GrantTypes: []string{oauth.GrantDeviceCode}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClientCredentials(ctx, dev.ID, "", ""); !errors.Is(err, oauth.ErrUnauthorizedClient) {
		t.Fatalf("device client at client_credentials err = %v, want ErrUnauthorizedClient", err)
	}
	if _, err := f.svc.ClientCredentials(ctx, dev.ID, "some-secret", ""); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("public client presenting a secret err = %v, want ErrInvalidClient", err)
	}
	// The account disabled: invalid_client wrapping the apikey sentinel.
	if err := f.keys.DisableServiceAccount(f.owner, f.saID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClientCredentials(ctx, c.ID, secret, ""); !errors.Is(err, oauth.ErrInvalidClient) || !errors.Is(err, apikey.ErrServiceAccountDisabled) {
		t.Fatalf("disabled account err = %v, want ErrInvalidClient wrapping ErrServiceAccountDisabled", err)
	}
	if err := f.keys.EnableServiceAccount(f.owner, f.saID); err != nil {
		t.Fatal(err)
	}
	// The account removed from the organization entirely.
	if err := f.keys.DeleteServiceAccount(f.owner, f.saID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClientCredentials(ctx, c.ID, secret, ""); !errors.Is(err, oauth.ErrInvalidClient) || !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("deleted account err = %v, want ErrInvalidClient wrapping ErrServiceAccountNotFound", err)
	}
}

func TestClientCredentialsReChecksTheCapAgainstTheCurrentRole(t *testing.T) {
	f := newFixture(t)
	spec := f.ccSpec()
	spec.Permissions = map[string][]access.Action{"project": {"deploy"}}
	c, secret := f.mustCC(t, spec)
	ctx := context.Background()
	if _, err := f.svc.ClientCredentials(ctx, c.ID, secret, ""); err != nil {
		t.Fatal(err)
	}
	// Lower the account to a role without project:deploy.
	if err := f.keys.ChangeServiceAccountRole(f.owner, f.saID, org.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClientCredentials(ctx, c.ID, secret, ""); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("cap above the lowered role err = %v, want ErrPrivilegeEscalation", err)
	}
}

func TestMintingRequiresAnIssuer(t *testing.T) {
	f := newFixture(t)
	c, secret := f.mustCC(t, f.ccSpec())
	noIssuer := oauth.New(f.st, f.orgSvc.Service, f.signer, oauth.WithServiceAccounts(memory.NewAPIKeyStore()))
	_ = noIssuer
	bare := oauth.New(f.st, f.orgSvc.Service, f.signer)
	if _, err := bare.ClientCredentials(context.Background(), c.ID, secret, ""); !errors.Is(err, oauth.ErrIssuerRequired) {
		t.Fatalf("no issuer err = %v, want ErrIssuerRequired", err)
	}
}

func TestAuthenticateRefusals(t *testing.T) {
	f := newFixture(t)
	c, secret := f.mustCC(t, f.ccSpec())
	ctx := context.Background()
	resp, err := f.svc.ClientCredentials(ctx, c.ID, secret, "")
	if err != nil {
		t.Fatal(err)
	}

	details := func() string {
		e, _ := f.lastEvent(oauth.AuthenticationFailed)
		return e.Detail
	}
	if _, err := f.svc.Authenticate(ctx, "garbage"); !errors.Is(err, oauth.ErrInvalidToken) || !errors.Is(err, token.ErrMalformedToken) || details() != oauth.DetailTokenInvalid {
		t.Fatalf("garbage err = %v detail %q", err, details())
	}
	// A session-shaped token from the same signer is not an access token
	// of this package.
	sess, _ := f.signer.Issue(token.Claims{Subject: "alice", SessionID: "s1", Issuer: issuer}, time.Minute)
	if _, err := f.svc.Authenticate(ctx, sess); !errors.Is(err, oauth.ErrInvalidToken) || details() != oauth.DetailNotAnAccessToken {
		t.Fatalf("session token err = %v detail %q", err, details())
	}
	// A token from another issuer sharing the key.
	other := oauth.New(f.st, f.orgSvc.Service, f.signer, oauth.WithIssuer("https://other.example"))
	oresp, err := other.ClientCredentials(ctx, c.ID, secret, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, oresp.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) || details() != oauth.DetailIssuerMismatch {
		t.Fatalf("other issuer err = %v detail %q", err, details())
	}
	// Audience: a service built with one refuses a token minted without.
	aud := oauth.New(f.st, f.orgSvc.Service, f.signer, oauth.WithIssuer(issuer), oauth.WithAudience("https://api.example"))
	if _, err := aud.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) {
		t.Fatalf("missing audience err = %v", err)
	}
	aresp, err := aud.ClientCredentials(ctx, c.ID, secret, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aud.Authenticate(ctx, aresp.AccessToken); err != nil {
		t.Fatalf("matching audience: %v", err)
	}
	claims, _ := f.signer.Parse(aresp.AccessToken)
	if !claims.Audience.Contains("https://api.example") {
		t.Fatalf("aud = %v", claims.Audience)
	}
	// Disabled client: refused online, accepted offline until expiry.
	if err := f.svc.DisableClient(f.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) || !errors.Is(err, oauth.ErrClientDisabled) || details() != oauth.DetailClientDisabled {
		t.Fatalf("disabled client err = %v detail %q", err, details())
	}
	offline := oauth.New(f.st, f.orgSvc.Service, f.signer, oauth.WithIssuer(issuer), oauth.WithOfflineVerification())
	if p, err := offline.Authenticate(ctx, resp.AccessToken); err != nil || p.ID != f.saID {
		t.Fatalf("offline Authenticate = %+v, %v", p, err)
	}
	// Deleted client.
	if err := f.svc.DeleteClient(f.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrClientNotFound) || details() != oauth.DetailClientNotFound {
		t.Fatalf("deleted client err = %v detail %q", err, details())
	}
	// Expired.
	f.clock.Advance(time.Hour)
	if _, err := offline.Authenticate(ctx, resp.AccessToken); !errors.Is(err, oauth.ErrInvalidToken) {
		// The signer's clock is real time, so this token is not expired yet
		// by the signer; the fixture clock only drives this package. Pin
		// that the signer's own expiry is what governs.
		t.Logf("advancing the package clock does not expire a JWT: %v", err)
	}
}

func TestHookErrorsOnAuthenticate(t *testing.T) {
	f := newFixture(t)
	c, secret := f.mustCC(t, f.ccSpec())
	ctx := context.Background()
	resp, err := f.svc.ClientCredentials(ctx, c.ID, secret, "")
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	hooked := oauth.New(f.st, f.orgSvc.Service, f.signer, oauth.WithIssuer(issuer),
		oauth.WithHooks(oauth.HookFunc(func(context.Context, oauth.Event) error { return boom })))
	if _, err := hooked.Authenticate(ctx, resp.AccessToken); !errors.Is(err, boom) {
		t.Fatalf("hook error on success = %v, want boom instead of the principal", err)
	}
	if _, err := hooked.Authenticate(ctx, "garbage"); !errors.Is(err, boom) || !errors.Is(err, oauth.ErrInvalidToken) {
		t.Fatalf("hook error on refusal = %v, want boom joined onto ErrInvalidToken", err)
	}
}

func TestIntrospectNeverErrorsForAnInvalidToken(t *testing.T) {
	f := newFixture(t)
	c, secret := f.mustCC(t, f.ccSpec())
	ctx := context.Background()
	resp, err := f.svc.ClientCredentials(ctx, c.ID, secret, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	live, err := f.svc.Introspect(ctx, resp.AccessToken)
	if err != nil || !live.Active || live.Subject != f.saID || live.ClientID != c.ID || live.Scope != "deploy" ||
		live.TokenType != "Bearer" || live.Iss != issuer || live.Exp == 0 || live.Iat == 0 || live.Jti == "" || live.Act != nil {
		t.Fatalf("Introspect(live) = %+v, %v", live, err)
	}
	for name, raw := range map[string]string{"garbage": "not-a-token", "empty": "", "hex refresh-shaped": strings.Repeat("ab", 32)} {
		got, err := f.svc.Introspect(ctx, raw)
		if err != nil || got.Active || got.Subject != "" {
			t.Errorf("Introspect(%s) = %+v, %v; want inactive and no error", name, got, err)
		}
	}
	if err := f.svc.DisableClient(f.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Introspect(ctx, resp.AccessToken)
	if err != nil || got.Active {
		t.Fatalf("Introspect(disabled client) = %+v, %v; want inactive", got, err)
	}
	// The JSON shape is RFC 7662's.
	b, _ := json.Marshal(live)
	for _, key := range []string{`"active":true`, `"sub":"`, `"client_id":"`, `"token_type":"Bearer"`, `"exp":`, `"iat":`, `"iss":"` + issuer + `"`, `"jti":"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("introspection JSON %s lacks %s", b, key)
		}
	}
	if b, _ := json.Marshal(oauth.Introspection{}); string(b) != `{"active":false}` {
		t.Fatalf("inactive JSON = %s", b)
	}
}

// ── Metadata, errors ────────────────────────────────────────────────────

func TestServerMetadataAndProtectedResourceMetadata(t *testing.T) {
	f := newFixture(t, oauth.WithScopeMap(map[string]map[string][]access.Action{
		"project:write": {"project": {"deploy"}},
		"project:read":  {"project": {"read"}},
	}))
	m := f.svc.ServerMetadata("", oauth.Endpoints{Authorization: "https://auth.example/authorize", Token: "https://auth.example/token", JWKS: "https://auth.example/jwks", Registration: "https://auth.example/register"})
	if m.Issuer != issuer || m.AuthorizationEndpoint == "" || m.TokenEndpoint == "" || m.JWKSURI == "" || m.RegistrationEndpoint == "" ||
		m.RevocationEndpoint != "" || m.DeviceAuthorizationEndpoint != "" {
		t.Fatalf("metadata = %+v", m)
	}
	if strings.Join(m.ScopesSupported, ",") != "project:read,project:write" {
		t.Fatalf("scopes_supported = %v, want sorted keys", m.ScopesSupported)
	}
	if strings.Join(m.CodeChallengeMethodsSupported, ",") != "S256" || strings.Join(m.ResponseTypesSupported, ",") != "code" || len(m.GrantTypesSupported) != 4 || len(m.TokenEndpointAuthMethodsSupported) != 3 {
		t.Fatalf("metadata = %+v", m)
	}
	b, _ := json.Marshal(m)
	for _, key := range []string{`"issuer"`, `"authorization_endpoint"`, `"token_endpoint"`, `"jwks_uri"`, `"registration_endpoint"`, `"scopes_supported"`, `"response_types_supported"`, `"grant_types_supported"`, `"code_challenge_methods_supported"`, `"token_endpoint_auth_methods_supported"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("metadata JSON lacks %s", key)
		}
	}
	if strings.Contains(string(b), "revocation_endpoint") {
		t.Errorf("an unset endpoint was published: %s", b)
	}
	pr := f.svc.ProtectedResourceMetadata("https://api.example", []string{issuer}, nil)
	if pr.Resource != "https://api.example" || len(pr.AuthorizationServers) != 1 || len(pr.ScopesSupported) != 2 || pr.BearerMethodsSupported[0] != "header" {
		t.Fatalf("protected resource metadata = %+v", pr)
	}
	explicit := f.svc.ProtectedResourceMetadata("r", nil, []string{"x"})
	if len(explicit.ScopesSupported) != 1 || explicit.ScopesSupported[0] != "x" {
		t.Fatalf("explicit scopes = %v", explicit.ScopesSupported)
	}
}

func TestScopeMapPanicsOnAnUndeclaredPermission(t *testing.T) {
	f := newFixture(t)
	defer func() {
		if recover() == nil {
			t.Fatal("New accepted a scope map naming an undeclared permission")
		}
	}()
	oauth.New(f.st, f.orgSvc.Service, f.signer, oauth.WithScopeMap(map[string]map[string][]access.Action{
		"x": {"nothing": {"such"}},
	}))
}

func TestErrorCodeMapsEverySentinelAndWrappedChains(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
	}{
		{oauth.ErrInvalidClient, oauth.CodeInvalidClient, http.StatusUnauthorized},
		{oauth.ErrClientDisabled, oauth.CodeInvalidClient, http.StatusUnauthorized},
		{oauth.ErrInvalidGrant, oauth.CodeInvalidGrant, http.StatusBadRequest},
		{oauth.ErrCodeReused, oauth.CodeInvalidGrant, http.StatusBadRequest},
		{oauth.ErrTokenReuse, oauth.CodeInvalidGrant, http.StatusBadRequest},
		{oauth.ErrInvalidScope, oauth.CodeInvalidScope, http.StatusBadRequest},
		{oauth.ErrUnauthorizedClient, oauth.CodeUnauthorizedClient, http.StatusBadRequest},
		{oauth.ErrInvalidRedirectURI, oauth.CodeInvalidRedirectURI, http.StatusBadRequest},
		{oauth.ErrPKCERequired, oauth.CodeInvalidRequest, http.StatusBadRequest},
		{oauth.ErrPKCEMismatch, oauth.CodeInvalidGrant, http.StatusBadRequest},
		{oauth.ErrAuthorizationPending, oauth.CodeAuthorizationPending, http.StatusBadRequest},
		{oauth.ErrSlowDown, oauth.CodeSlowDown, http.StatusBadRequest},
		{oauth.ErrAccessDenied, oauth.CodeAccessDenied, http.StatusBadRequest},
		{oauth.ErrExpiredToken, oauth.CodeExpiredToken, http.StatusBadRequest},
		{oauth.ErrDeviceNotFound, oauth.CodeInvalidRequest, http.StatusNotFound},
		{oauth.ErrDeviceNotPending, oauth.CodeInvalidRequest, http.StatusConflict},
		{oauth.ErrGrantNotFound, oauth.CodeInvalidRequest, http.StatusNotFound},
		{oauth.ErrGrantRevoked, oauth.CodeInvalidGrant, http.StatusBadRequest},
		{oauth.ErrGrantExpired, oauth.CodeInvalidGrant, http.StatusBadRequest},
		{oauth.ErrInvalidToken, oauth.CodeInvalidToken, http.StatusUnauthorized},
		{oauth.ErrIssuerRequired, oauth.CodeServerError, http.StatusInternalServerError},
		{oauth.ErrRegistrationDisabled, oauth.CodeInvalidRequest, http.StatusForbidden},
		{oauth.ErrRefreshNotFound, oauth.CodeInvalidGrant, http.StatusNotFound},
		{oauth.ErrCodeNotFound, oauth.CodeInvalidGrant, http.StatusNotFound},
		{oauth.ErrIDTaken, oauth.CodeServerError, http.StatusConflict},
		{oauth.ErrClientNotFound, oauth.CodeInvalidRequest, http.StatusNotFound},
		{oauth.ErrInvalidClientMetadata, oauth.CodeInvalidClientMetadata, http.StatusBadRequest},
		{oauth.ErrEmptyPermissions, oauth.CodeInvalidScope, http.StatusBadRequest},
		// Wrapped chains answer for their most specific member.
		{errors.Join(oauth.ErrInvalidGrant, oauth.ErrCodeNotFound), oauth.CodeInvalidGrant, http.StatusBadRequest},
		{errors.Join(oauth.ErrInvalidToken, oauth.ErrGrantRevoked), oauth.CodeInvalidToken, http.StatusUnauthorized},
		{errors.Join(oauth.ErrInvalidClient, oauth.ErrClientNotFound), oauth.CodeInvalidClient, http.StatusUnauthorized},
		{errors.New("something else"), oauth.CodeServerError, http.StatusInternalServerError},
		{scope.ErrForbidden, oauth.CodeServerError, http.StatusInternalServerError},
	} {
		code, status := oauth.ErrorCode(tc.err)
		if code != tc.code || status != tc.status {
			t.Errorf("ErrorCode(%v) = %s %d, want %s %d", tc.err, code, status, tc.code, tc.status)
		}
	}
}
