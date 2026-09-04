//go:build integration

// Live end-to-end tests for the OAuth store against a real PostgreSQL. Run
// with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...`
// stays database-free. The oauth.Store contract itself is the exported
// authlayer/oauth/oauthtest suite, run here against a live server exactly as
// store/memory runs it in-process; what this file adds is what stays
// BACKEND-SPECIFIC — the DDL the suite cannot see, the error class
// PostgreSQL answers a rejected duplicate with, the jsonb and nullable
// round trips, and one end-to-end pass through the oauth.Service over the
// drops RBAC and API-key stores.
package dropsstore_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/oauth/oauthtest"
	"github.com/bernardoforcillo/authlayer/org"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
	"github.com/bernardoforcillo/authlayer/token"
)

func dropOAuthTables(t *testing.T, db *pg.DB, st *dropsstore.OAuthStore) {
	t.Helper()
	s := st.Schema()
	// Referencing tables first: a foreign key would refuse dropping a
	// referenced table while a referencing one still exists.
	for _, tbl := range []*pg.Table{s.RefreshTokens, s.DeviceAuthorizations, s.Codes, s.Grants, s.Clients} {
		if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
			t.Fatalf("drop %s: %v", tbl.Name(), err)
		}
	}
}

// newLiveOAuthStore opens a connection from AUTHLAYER_TEST_DSN, builds a
// fresh OAuthStore and drops/recreates the five tables so each test starts
// from an empty schema.
func newLiveOAuthStore(t *testing.T) (*sql.DB, *dropsstore.OAuthStore) {
	t.Helper()
	sqlDB, db := openLiveDB(t)
	st := dropsstore.NewOAuthStore(db)
	ctx := context.Background()
	dropOAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropOAuthTables(t, db, st) })
	return sqlDB, st
}

// TestOAuthStoreSatisfiesTheStoreContractLive runs the exported oauthtest
// suite against a real server: every documented obligation of oauth.Store —
// the four UNIQUEs, the three compare-and-sets, the two cascades and the
// referential refusals, which only a real constraint, a real row lock and
// a real transaction can demonstrate. The pool is warmed to
// oauthtest.RaceGoroutines connections before anything runs, for the reason
// TestAuthStoreSatisfiesTheStoreContractLive gives, and each check gets an
// empty schema through TRUNCATE rather than a drop-and-recreate.
func TestOAuthStoreSatisfiesTheStoreContractLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	sqlDB.SetMaxOpenConns(oauthtest.RaceGoroutines)
	sqlDB.SetMaxIdleConns(oauthtest.RaceGoroutines)
	warmPool(t, sqlDB, oauthtest.RaceGoroutines)

	st := dropsstore.NewOAuthStore(db)
	ctx := context.Background()
	dropOAuthTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropOAuthTables(t, db, st) })

	s := st.Schema()
	truncate := fmt.Sprintf("TRUNCATE %s, %s, %s, %s, %s", s.RefreshTokens.Name(), s.DeviceAuthorizations.Name(), s.Codes.Name(), s.Grants.Name(), s.Clients.Name())
	oauthtest.RunStoreContract(t, func(t *testing.T) oauth.Store {
		if _, err := sqlDB.ExecContext(ctx, truncate); err != nil {
			t.Fatalf("%s: %v", truncate, err)
		}
		return st
	})
}

// TestOAuthStoreRefusalsSurfaceTheDriversErrorsLive covers what the
// port-level suite deliberately does not: WHICH error each refusal comes
// back as. A duplicate hash or user code is the driver's own
// pg.ErrUniqueViolation, unwrapped; a duplicate id is oauth.ErrIDTaken
// wrapping it; a row naming no client or grant is the port's not-found
// sentinel wrapping the driver's foreign-key violation.
func TestOAuthStoreRefusalsSurfaceTheDriversErrorsLive(t *testing.T) {
	_, st := newLiveOAuthStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := oauth.Client{ID: uid.NewV7(), ContainerID: uid.NewV7(), Name: "bot", GrantTypes: []string{oauth.GrantDeviceCode}, CreatedBy: uid.NewV7(), CreatedAt: now, UpdatedAt: now}
	if _, err := st.CreateClient(ctx, c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	dup := c
	dup.Name = "impostor"
	if _, err := st.CreateClient(ctx, dup); !errors.Is(err, oauth.ErrIDTaken) || !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate client id err = %v, want ErrIDTaken wrapping pg.ErrUniqueViolation", err)
	}
	g := oauth.Grant{ID: uid.NewV7(), ClientID: c.ID, UserID: uid.NewV7(), ContainerID: c.ContainerID, CreatedAt: now}
	if _, err := st.CreateGrant(ctx, g); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	orphan := g
	orphan.ID, orphan.ClientID = uid.NewV7(), uid.NewV7()
	if _, err := st.CreateGrant(ctx, orphan); !errors.Is(err, oauth.ErrClientNotFound) || !errors.Is(err, pg.ErrForeignKeyViolation) {
		t.Fatalf("orphan grant err = %v, want ErrClientNotFound wrapping pg.ErrForeignKeyViolation", err)
	}
	code := oauth.AuthorizationCode{ID: uid.NewV7(), CodeHash: "hash-abc", ClientID: c.ID, GrantID: g.ID, CodeChallenge: "x", ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	if _, err := st.CreateCode(ctx, code); err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	code.ID = uid.NewV7()
	if _, err := st.CreateCode(ctx, code); !errors.Is(err, pg.ErrUniqueViolation) || errors.Is(err, oauth.ErrIDTaken) {
		t.Fatalf("duplicate code hash err = %v, want pg.ErrUniqueViolation unwrapped", err)
	}
	code.CodeHash, code.GrantID = "hash-other", uid.NewV7()
	if _, err := st.CreateCode(ctx, code); !errors.Is(err, oauth.ErrGrantNotFound) || !errors.Is(err, pg.ErrForeignKeyViolation) {
		t.Fatalf("orphan code err = %v, want ErrGrantNotFound wrapping pg.ErrForeignKeyViolation", err)
	}
	d := oauth.DeviceAuthorization{ID: uid.NewV7(), DeviceCodeHash: "dh", UserCode: "BCDFGHJK", ClientID: c.ID, Status: oauth.DeviceStatusPending, Interval: 5, ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	if _, err := st.CreateDeviceAuthorization(ctx, d); err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}
	d.ID, d.DeviceCodeHash = uid.NewV7(), "dh2"
	if _, err := st.CreateDeviceAuthorization(ctx, d); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate user code err = %v, want pg.ErrUniqueViolation", err)
	}
	rt := oauth.RefreshToken{ID: uid.NewV7(), TokenHash: "rh", GrantID: g.ID, ClientID: c.ID, FamilyID: uid.NewV7(), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if _, err := st.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	rt.ID = uid.NewV7()
	if _, err := st.CreateRefreshToken(ctx, rt); !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate token hash err = %v, want pg.ErrUniqueViolation", err)
	}
}

// TestOAuthStoreCreateSchemaLandsConstraintsOnRealPostgres reads the
// constraints and indexes back out of the catalog rather than inferring
// them from errors: the five primary keys, the four UNIQUEs, the six
// cascading foreign keys, the nine indexes. Also re-runs CreateSchema to
// confirm it stays idempotent against a real server.
func TestOAuthStoreCreateSchemaLandsConstraintsOnRealPostgres(t *testing.T) {
	sqlDB, st := newLiveOAuthStore(t)
	ctx := context.Background()
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (second run): %v", err)
	}
	rows, err := sqlDB.QueryContext(ctx, `
		SELECT c.conname, pg_get_constraintdef(c.oid)
		FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname LIKE 'oauth_%'
		ORDER BY t.relname, c.conname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]string{}
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-52s %s", name, def)
		found[name] = def
	}
	for _, want := range []struct{ name, def string }{
		{"oauth_clients_pkey", "PRIMARY KEY (id)"},
		{"oauth_grants_pkey", "PRIMARY KEY (id)"},
		{"oauth_codes_pkey", "PRIMARY KEY (id)"},
		{"oauth_device_authorizations_pkey", "PRIMARY KEY (id)"},
		{"oauth_refresh_tokens_pkey", "PRIMARY KEY (id)"},
		{"oauth_codes_code_hash_key", "UNIQUE (code_hash)"},
		{"oauth_device_authorizations_device_code_hash_key", "UNIQUE (device_code_hash)"},
		{"oauth_device_authorizations_user_code_key", "UNIQUE (user_code)"},
		{"oauth_refresh_tokens_token_hash_key", "UNIQUE (token_hash)"},
		{"oauth_grants_client_id_fkey", "FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE"},
		{"oauth_codes_client_id_fkey", "FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE"},
		{"oauth_codes_grant_id_fkey", "FOREIGN KEY (grant_id) REFERENCES oauth_grants(id) ON DELETE CASCADE"},
		{"oauth_device_authorizations_client_id_fkey", "FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE"},
		{"oauth_refresh_tokens_grant_id_fkey", "FOREIGN KEY (grant_id) REFERENCES oauth_grants(id) ON DELETE CASCADE"},
		{"oauth_refresh_tokens_client_id_fkey", "FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE"},
	} {
		def, ok := found[want.name]
		if !ok {
			t.Errorf("MISSING: constraint %s", want.name)
			continue
		}
		if def != want.def {
			t.Errorf("%s definition = %q, want %q", want.name, def, want.def)
		}
	}
	if _, ok := found["oauth_device_authorizations_grant_id_fkey"]; ok {
		t.Error("device_authorizations.grant_id carries a foreign key it must not")
	}
	idx, err := sqlDB.QueryContext(ctx, `SELECT indexname FROM pg_indexes WHERE tablename LIKE 'oauth_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	indexes := map[string]bool{}
	for idx.Next() {
		var name string
		if err := idx.Scan(&name); err != nil {
			t.Fatal(err)
		}
		indexes[name] = true
	}
	for _, want := range []string{
		"oauth_clients_container_id_idx", "oauth_grants_user_id_idx", "oauth_grants_client_id_idx",
		"oauth_codes_grant_id_idx", "oauth_codes_client_id_idx", "oauth_device_authorizations_client_id_idx",
		"oauth_refresh_tokens_grant_id_idx", "oauth_refresh_tokens_client_id_idx", "oauth_refresh_tokens_family_id_idx",
	} {
		if !indexes[want] {
			t.Errorf("MISSING: index %s (have %v)", want, indexes)
		}
	}
}

// TestOAuthServiceOverDropsLive is the one end-to-end pass: an organization
// in the drops RBAC store, a service account in the drops API-key store, a
// client-credentials client with a cap, a public device client, a
// dynamically registered public MCP client — the three shapes a client row
// takes, jsonb lists and NULL ids included — through every grant, a refresh
// replay, a revocation and the cascade delete, every step against the live
// server.
func TestOAuthServiceOverDropsLive(t *testing.T) {
	_, db := openLiveDB(t)
	ctx := context.Background()
	rbac := dropsstore.New[org.Organization, org.Member](db)
	dropAll(t, db, rbac)
	if err := rbac.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (rbac): %v", err)
	}
	t.Cleanup(func() { dropAll(t, db, rbac) })
	keys := dropsstore.NewAPIKeyStore(db)
	dropAPIKeyTables(t, db, keys)
	if err := keys.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (apikey): %v", err)
	}
	t.Cleanup(func() { dropAPIKeyTables(t, db, keys) })
	oa := dropsstore.NewOAuthStore(db)
	dropOAuthTables(t, db, oa)
	if err := oa.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (oauth): %v", err)
	}
	t.Cleanup(func() { dropOAuthTables(t, db, oa) })

	orgSvc := org.New(org.NewAccess(map[string][]access.Action{"project": {"read", "deploy", "delete"}}), rbac)
	keySvc := apikey.New(orgSvc.Service, keys)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.EdDSA("live", priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := oauth.New(oa, orgSvc.Service, signer,
		oauth.WithIssuer("https://auth.example"), oauth.WithServiceAccounts(keys), oauth.WithDynamicRegistration(true),
		oauth.WithScopeMap(map[string]map[string][]access.Action{"project:read": {"project": {"read"}}, "project:deploy": {"project": {"deploy"}}}))

	aliceID, bobID := uid.NewV7(), uid.NewV7()
	alice := org.WithSubject(ctx, aliceID)
	acme, err := orgSvc.CreateOrganization(alice, "Acme", "acme")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	owner := org.WithOrg(alice, acme.ID)
	if _, err := orgSvc.AddMember(owner, bobID, org.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	bob := org.WithOrg(org.WithSubject(ctx, bobID), acme.ID)
	sa, err := keySvc.CreateServiceAccount(owner, "ci", "", org.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}

	// 1. Client credentials, capped.
	cc, secret, err := svc.CreateClient(bob, oauth.ClientSpec{Name: "ci bot", GrantTypes: []string{oauth.GrantClientCredentials}, ServiceAccountID: sa.ID,
		Permissions: map[string][]access.Action{"project": {"read"}}})
	if err != nil {
		t.Fatalf("CreateClient(cc): %v", err)
	}
	resp, err := svc.ClientCredentials(ctx, cc.ID, secret, "project:read")
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	p, err := svc.Authenticate(ctx, resp.AccessToken)
	if err != nil || p.Kind != apikey.KindServiceAccount || p.ID != sa.ID {
		t.Fatalf("Authenticate(cc) = %+v, %v", p, err)
	}
	as := apikey.WithPrincipal(ctx, p)
	if ok, _ := orgSvc.Can(as, "project", "read"); !ok {
		t.Fatal("cc token project:read = false, want true")
	}
	if ok, _ := orgSvc.Can(as, "project", "deploy"); ok {
		t.Fatal("cc token project:deploy = true, want false — the cap removed it")
	}

	// 2. Device flow with a public client; the row's NULL ids round-trip.
	cli, _, err := svc.CreateClient(bob, oauth.ClientSpec{Name: "cli", Public: true, GrantTypes: []string{oauth.GrantDeviceCode, oauth.GrantRefreshToken}})
	if err != nil {
		t.Fatalf("CreateClient(cli): %v", err)
	}
	stored, err := oa.FindClient(ctx, cli.ID)
	if err != nil || stored.ServiceAccountID != "" || stored.ContainerID != acme.ID || !stored.Public || len(stored.GrantTypes) != 2 || stored.RedirectURIs != nil {
		t.Fatalf("stored public client = %+v, %v", stored, err)
	}
	dr, err := svc.BeginDeviceAuthorization(ctx, cli.ID, "project:read project:deploy")
	if err != nil {
		t.Fatalf("BeginDeviceAuthorization: %v", err)
	}
	if _, err := svc.PollDevice(ctx, cli.ID, "", dr.DeviceCode); !errors.Is(err, oauth.ErrAuthorizationPending) {
		t.Fatalf("poll before approval = %v", err)
	}
	if err := svc.ApproveDevice(bob, dr.UserCode, oauth.Approval{}); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	time.Sleep(6 * time.Second) // past the polling interval, on the real clock
	dresp, err := svc.PollDevice(ctx, cli.ID, "", dr.DeviceCode)
	if err != nil {
		t.Fatalf("PollDevice: %v", err)
	}
	dp, err := svc.Authenticate(ctx, dresp.AccessToken)
	if err != nil || dp.Kind != apikey.KindDelegated || dp.ID != bobID {
		t.Fatalf("Authenticate(device) = %+v, %v", dp, err)
	}
	agent := apikey.WithPrincipal(ctx, dp)
	if ok, _ := orgSvc.Can(agent, "project", "deploy"); !ok {
		t.Fatal("agent project:deploy = false, want true — in the scopes and bob holds it")
	}
	if ok, _ := orgSvc.Can(agent, "project", "delete"); ok {
		t.Fatal("agent project:delete = true, want false — not in the scopes")
	}

	// 3. Refresh, then replay: family and grant revoked.
	second, err := svc.Refresh(ctx, cli.ID, "", dresp.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := svc.Refresh(ctx, cli.ID, "", dresp.RefreshToken); !errors.Is(err, oauth.ErrTokenReuse) {
		t.Fatalf("replay = %v, want ErrTokenReuse", err)
	}
	if _, err := svc.Authenticate(ctx, second.AccessToken); !errors.Is(err, oauth.ErrGrantRevoked) {
		t.Fatalf("access after replay = %v, want ErrGrantRevoked", err)
	}

	// 4. A dynamically registered MCP client through the code flow.
	mcp, _, err := svc.RegisterClient(ctx, oauth.ClientRegistration{ClientName: "mcp", RedirectURIs: []string{"http://127.0.0.1:9/cb"}, TokenEndpointAuthMethod: oauth.AuthMethodNone, Scope: "project:read"})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if stored, err := oa.FindClient(ctx, mcp.ID); err != nil || stored.ContainerID != "" || stored.CreatedBy != "" || stored.Scopes[0] != "project:read" {
		t.Fatalf("stored registered client = %+v, %v", stored, err)
	}
	var vb [32]byte
	if _, err := rand.Read(vb[:]); err != nil {
		t.Fatal(err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(vb[:])
	sum := sha256.Sum256([]byte(verifier))
	req := oauth.AuthorizationRequest{ClientID: mcp.ID, Scope: "project:read", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), CodeChallengeMethod: "S256"}
	code, err := svc.Approve(owner, req, oauth.Approval{})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	x := oauth.CodeExchange{ClientID: mcp.ID, Code: code, CodeVerifier: verifier}
	cresp, err := svc.ExchangeCode(ctx, x)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, x); !errors.Is(err, oauth.ErrCodeReused) {
		t.Fatalf("code replay = %v, want ErrCodeReused", err)
	}
	if _, err := svc.Authenticate(ctx, cresp.AccessToken); !errors.Is(err, oauth.ErrGrantRevoked) {
		t.Fatalf("access after code replay = %v, want ErrGrantRevoked", err)
	}
	if in, err := svc.Introspect(ctx, cresp.AccessToken); err != nil || in.Active {
		t.Fatalf("Introspect(revoked) = %+v, %v", in, err)
	}

	// 5. Delete the device client: everything of it goes.
	grants, _ := svc.ListGrants(bob)
	if err := svc.DeleteClient(bob, cli.ID); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	for _, g := range grants {
		if g.ClientID == cli.ID {
			if _, err := oa.FindGrant(ctx, g.ID); !errors.Is(err, oauth.ErrGrantNotFound) {
				t.Fatalf("grant %s outlived its client: %v", g.ID, err)
			}
		}
	}
	if err := svc.RevokeGrant(bob, uid.NewV7()); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("RevokeGrant(unknown) = %v", err)
	}
}
