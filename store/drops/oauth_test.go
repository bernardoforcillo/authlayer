package dropsstore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bernardoforcillo/authlayer/oauth"
)

// This is the UNIT suite for the OAuth store: it runs against a fake driver
// and can therefore prove only what a builder produces — the schema's
// shape, the row conversions, and the SQL each method renders. Every
// property that belongs to a SERVER rather than a builder (the foreign keys
// really cascading, the UNIQUEs really refusing, the compare-and-sets
// really single-winner, the transactions really rolling back) is proved in
// oauth_integration_test.go against a real PostgreSQL, where the exported
// oauthtest suite also runs.

func newOAuthStore(fd *fakeDriver) *OAuthStore {
	return NewOAuthStore(pg.New(fd))
}

// ── schema / naming ─────────────────────────────────────────────────────

func TestOAuthSchemaDefaultTableNames(t *testing.T) {
	s := NewOAuthSchema()
	for got, want := range map[string]string{
		s.Clients.Name():              "oauth_clients",
		s.Grants.Name():               "oauth_grants",
		s.Codes.Name():                "oauth_codes",
		s.DeviceAuthorizations.Name(): "oauth_device_authorizations",
		s.RefreshTokens.Name():        "oauth_refresh_tokens",
	} {
		if got != want {
			t.Fatalf("table name %q, want %q", got, want)
		}
	}
}

func TestOAuthSchemaHonoursCustomNames(t *testing.T) {
	s := NewOAuthSchema(WithOAuthNames(OAuthNames{Clients: "apps", Grants: "consents", Codes: "app_codes", DeviceAuthorizations: "app_devices", RefreshTokens: "app_refresh"}))
	if s.Clients.Name() != "apps" || s.Grants.Name() != "consents" || s.Codes.Name() != "app_codes" || s.DeviceAuthorizations.Name() != "app_devices" || s.RefreshTokens.Name() != "app_refresh" {
		t.Fatalf("custom names not applied")
	}
	// Index names derive from the table name, so two differently-named
	// instances in one database cannot collide on them.
	for _, idx := range s.RefreshTokens.Indexes() {
		if !strings.HasPrefix(idx.Name(), "app_refresh_") {
			t.Fatalf("index %q not renamed with the table", idx.Name())
		}
	}
}

func TestOAuthSchemaIDColumnsDefaultToUUIDAndFollowTheOptions(t *testing.T) {
	s := NewOAuthSchema()
	for tag, col := range map[string]*pg.Column{
		"clients.id":                 s.Clients.Col("id"),
		"clients.container_id":       s.Clients.Col("container_id"),
		"clients.service_account_id": s.Clients.Col("service_account_id"),
		"clients.created_by":         s.Clients.Col("created_by"),
		"grants.client_id":           s.Grants.Col("client_id"),
		"grants.user_id":             s.Grants.Col("user_id"),
		"codes.grant_id":             s.Codes.Col("grant_id"),
		"devices.grant_id":           s.DeviceAuthorizations.Col("grant_id"),
		"refresh.family_id":          s.RefreshTokens.Col("family_id"),
	} {
		if got := col.Type().TypeSQL(); got != "uuid" {
			t.Fatalf("%s type = %q, want uuid by default", tag, got)
		}
	}
	lib := NewOAuthSchema(WithOAuthTextLibraryIDs())
	for tag, col := range map[string]*pg.Column{
		"clients.id":        lib.Clients.Col("id"),
		"grants.client_id":  lib.Grants.Col("client_id"),
		"codes.grant_id":    lib.Codes.Col("grant_id"),
		"refresh.family_id": lib.RefreshTokens.Col("family_id"),
	} {
		if got := col.Type().TypeSQL(); got != "text" {
			t.Fatalf("%s type = %q, want text under WithOAuthTextLibraryIDs", tag, got)
		}
	}
	if got := lib.Grants.Col("user_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithOAuthTextLibraryIDs leaked into user_id: %q", got)
	}
	usr := NewOAuthSchema(WithOAuthTextUserIDs())
	if got := usr.Grants.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("grants.user_id = %q, want text under WithOAuthTextUserIDs", got)
	}
	if got := usr.Clients.Col("created_by").Type().TypeSQL(); got != "text" {
		t.Fatalf("clients.created_by = %q, want text under WithOAuthTextUserIDs", got)
	}
	if got := usr.Grants.Col("client_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithOAuthTextUserIDs leaked into client_id: %q", got)
	}
}

// The four UNIQUEs are inline, through the records' own tag options.
func TestOAuthSchemaUniqueColumnsAreInline(t *testing.T) {
	s := NewOAuthSchema()
	for _, c := range []struct {
		tbl *pg.Table
		col string
	}{
		{s.Codes, "code_hash"},
		{s.DeviceAuthorizations, "device_code_hash"},
		{s.DeviceAuthorizations, "user_code"},
		{s.RefreshTokens, "token_hash"},
	} {
		if !c.tbl.Col(c.col).IsUnique() {
			t.Fatalf("%s.%s is not UNIQUE", c.tbl.Name(), c.col)
		}
	}
	for _, tbl := range s.tables() {
		if n := len(tbl.CompositeUniques()); n != 0 {
			t.Fatalf("%s registers %d composite unique(s), want 0", tbl.Name(), n)
		}
	}
}

// Every reference is a cascading foreign key; device.grant_id deliberately
// is not.
func TestOAuthSchemaForeignKeysCascade(t *testing.T) {
	s := NewOAuthSchema()
	for _, fk := range []struct {
		tbl    *pg.Table
		col    string
		target string
	}{
		{s.Grants, "client_id", "oauth_clients"},
		{s.Codes, "client_id", "oauth_clients"},
		{s.Codes, "grant_id", "oauth_grants"},
		{s.DeviceAuthorizations, "client_id", "oauth_clients"},
		{s.RefreshTokens, "grant_id", "oauth_grants"},
		{s.RefreshTokens, "client_id", "oauth_clients"},
	} {
		got := fk.tbl.Col(fk.col).ForeignKey()
		if got == nil {
			t.Fatalf("%s.%s declares no foreign key", fk.tbl.Name(), fk.col)
		}
		if got.Target.Table().Name() != fk.target || got.Target.Name() != "id" || got.OnDelete != "CASCADE" {
			t.Fatalf("%s.%s → %s.%s ON DELETE %q, want %s.id CASCADE", fk.tbl.Name(), fk.col, got.Target.Table().Name(), got.Target.Name(), got.OnDelete, fk.target)
		}
	}
	if s.DeviceAuthorizations.Col("grant_id").ForeignKey() != nil {
		t.Fatal("device_authorizations.grant_id must not carry a foreign key: it is NULL until approval and inert afterwards")
	}
}

func TestOAuthSchemaNullableAndTypedColumns(t *testing.T) {
	s := NewOAuthSchema()
	for _, c := range []struct {
		tbl *pg.Table
		col string
	}{
		{s.Clients, "container_id"}, {s.Clients, "service_account_id"}, {s.Clients, "created_by"}, {s.Clients, "disabled_at"},
		{s.Grants, "expires_at"}, {s.Grants, "last_used_at"}, {s.Grants, "revoked_at"},
		{s.Codes, "redeemed_at"},
		{s.DeviceAuthorizations, "grant_id"}, {s.DeviceAuthorizations, "last_polled_at"},
		{s.RefreshTokens, "rotated_at"},
	} {
		if c.tbl.Col(c.col).IsNotNull() {
			t.Fatalf("%s.%s is NOT NULL, want nullable", c.tbl.Name(), c.col)
		}
	}
	if got := s.Clients.Col("public").Type().TypeSQL(); got != "boolean" {
		t.Fatalf("clients.public = %q, want boolean", got)
	}
	for _, col := range []string{"redirect_uris", "grant_types", "scopes"} {
		if got := s.Clients.Col(col).Type().TypeSQL(); got != "jsonb" || !s.Clients.Col(col).IsNotNull() {
			t.Fatalf("clients.%s = %q not-null %v, want jsonb NOT NULL", col, got, s.Clients.Col(col).IsNotNull())
		}
	}
	if got := s.DeviceAuthorizations.Col("interval").Type().TypeSQL(); got != "integer" {
		t.Fatalf("device_authorizations.interval = %q, want integer", got)
	}
}

func TestOAuthSchemaIndexes(t *testing.T) {
	s := NewOAuthSchema()
	want := map[string][]string{
		"oauth_clients":               {"oauth_clients_container_id_idx"},
		"oauth_grants":                {"oauth_grants_user_id_idx", "oauth_grants_client_id_idx"},
		"oauth_codes":                 {"oauth_codes_grant_id_idx", "oauth_codes_client_id_idx"},
		"oauth_device_authorizations": {"oauth_device_authorizations_client_id_idx"},
		"oauth_refresh_tokens":        {"oauth_refresh_tokens_grant_id_idx", "oauth_refresh_tokens_client_id_idx", "oauth_refresh_tokens_family_id_idx"},
	}
	for _, tbl := range s.tables() {
		var got []string
		for _, idx := range tbl.Indexes() {
			got = append(got, idx.Name())
		}
		if strings.Join(got, ",") != strings.Join(want[tbl.Name()], ",") {
			t.Fatalf("%s indexes = %v, want %v", tbl.Name(), got, want[tbl.Name()])
		}
	}
}

// ── row conversions ─────────────────────────────────────────────────────

func TestClientRowRoundTripsEmptyIDsAsNULLAndListsAsJSON(t *testing.T) {
	now := time.Now().UTC()
	public := oauth.Client{ID: "c1", Name: "cli", Public: true, GrantTypes: []string{oauth.GrantDeviceCode}, CreatedAt: now, UpdatedAt: now}
	r := fromClient(public)
	if r.ContainerID != nil || r.ServiceAccountID != nil || r.CreatedBy != nil {
		t.Fatalf("empty ids must be NULL: %+v", r)
	}
	if string(r.RedirectURIs) != "[]" || string(r.Scopes) != "[]" || string(r.GrantTypes) != `["`+oauth.GrantDeviceCode+`"]` {
		t.Fatalf("lists = %s %s %s", r.RedirectURIs, r.GrantTypes, r.Scopes)
	}
	if r.Permissions == nil {
		t.Fatal("a nil cap must be written as an empty bytea, not NULL")
	}
	back, err := toClient(r)
	if err != nil || back.ContainerID != "" || back.ServiceAccountID != "" || back.CreatedBy != "" || back.RedirectURIs != nil || back.Scopes != nil || !back.Public {
		t.Fatalf("toClient = %+v, %v", back, err)
	}
	full := oauth.Client{ID: "c2", ContainerID: "acme", ServiceAccountID: "sa", CreatedBy: "alice", RedirectURIs: []string{"https://a/cb", "https://b/cb"}, Permissions: []byte("project:read")}
	back, err = toClient(fromClient(full))
	if err != nil || back.ContainerID != "acme" || back.ServiceAccountID != "sa" || back.CreatedBy != "alice" || len(back.RedirectURIs) != 2 || string(back.Permissions) != "project:read" {
		t.Fatalf("toClient(full) = %+v, %v", back, err)
	}
	if _, err := toClient(clientRow{RedirectURIs: json.RawMessage(`{"not":"a list"}`)}); err == nil {
		t.Fatal("a non-list document must not decode silently")
	}
}

func TestDeviceRowRoundTripsGrantID(t *testing.T) {
	pending := oauth.DeviceAuthorization{ID: "d", Status: oauth.DeviceStatusPending, Interval: 5}
	if r := fromDevice(pending); r.GrantID != nil {
		t.Fatal("a pending authorization's grant_id must be NULL")
	}
	approved := pending
	approved.GrantID = "g1"
	if back := toDevice(fromDevice(approved)); back.GrantID != "g1" || back.Interval != 5 {
		t.Fatalf("round trip = %+v", back)
	}
}

// ── CreateSchema ────────────────────────────────────────────────────────

func TestOAuthStoreCreateSchemaEmitsTablesInDependencyOrderThenIndexes(t *testing.T) {
	fd := &fakeDriver{}
	if err := newOAuthStore(fd).CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if len(fd.execs) != 14 {
		t.Fatalf("CreateSchema issued %d statements, want 14 (five tables, nine indexes):\n%s", len(fd.execs), strings.Join(fd.execs, "\n"))
	}
	order := []string{"oauth_clients", "oauth_grants", "oauth_codes", "oauth_device_authorizations", "oauth_refresh_tokens"}
	last := -1
	for _, name := range order {
		i := -1
		for k, sql := range fd.execs {
			if strings.HasPrefix(sql, "CREATE TABLE IF NOT EXISTS") && strings.Contains(sql, `"`+name+`"`) {
				i = k
				break
			}
		}
		if i <= last {
			t.Fatalf("%s created out of dependency order:\n%s", name, strings.Join(fd.execs, "\n"))
		}
		last = i
	}
	for _, sql := range fd.execs {
		if strings.HasPrefix(sql, "CREATE TABLE") && !strings.Contains(sql, "IF NOT EXISTS") {
			t.Fatalf("non-idempotent DDL: %s", sql)
		}
	}
	clients := fd.execs[0]
	for _, want := range []string{`"public" boolean NOT NULL`, `"redirect_uris" jsonb NOT NULL`, `"container_id" uuid`, `"secret_hash" text NOT NULL`} {
		if !strings.Contains(clients, want) {
			t.Fatalf("clients DDL lacks %q:\n%s", want, clients)
		}
	}
	if strings.Contains(clients, `"container_id" uuid NOT NULL`) {
		t.Fatalf("clients.container_id must be nullable:\n%s", clients)
	}
}

// ── SQL shapes ──────────────────────────────────────────────────────────

func TestRedeemCodeRendersTheCompareAndSet(t *testing.T) {
	fd := &fakeDriver{}
	st := newOAuthStore(fd)
	_, _, err := st.RedeemCode(context.Background(), "h", time.Now())
	if !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("RedeemCode on an empty table err = %v, want ErrCodeNotFound", err)
	}
	if len(fd.queries) != 2 {
		t.Fatalf("queries = %d, want 2 (the UPDATE ... RETURNING, then the classifying SELECT)", len(fd.queries))
	}
	upd := fd.queries[0]
	for _, want := range []string{"UPDATE", `"redeemed_at" = $`, `"code_hash" = $`, `"redeemed_at" IS NULL`, "RETURNING"} {
		if !strings.Contains(upd, want) {
			t.Fatalf("RedeemCode SQL lacks %q:\n%s", want, upd)
		}
	}
	where, _, _ := strings.Cut(upd, "RETURNING")
	if strings.Contains(where, "expires_at") {
		t.Fatalf("expiry must not be part of the predicate:\n%s", upd)
	}
}

func TestMarkRefreshRotatedRendersTheCompareAndSet(t *testing.T) {
	fd := &fakeDriver{}
	st := newOAuthStore(fd)
	_, _, err := st.MarkRefreshRotated(context.Background(), "h", time.Now())
	if !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("err = %v, want ErrRefreshNotFound", err)
	}
	upd := fd.queries[0]
	for _, want := range []string{"UPDATE", `"rotated_at" = $`, `"token_hash" = $`, `"rotated_at" IS NULL`, "RETURNING"} {
		if !strings.Contains(upd, want) {
			t.Fatalf("MarkRefreshRotated SQL lacks %q:\n%s", want, upd)
		}
	}
}

func TestSetDeviceStatusRendersTheCompareAndWritesGrantOnlyOnApproval(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newOAuthStore(fd)
	won, err := st.SetDeviceStatus(context.Background(), "d", oauth.DeviceStatusPending, oauth.DeviceStatusApproved, "g", time.Now())
	if err != nil || !won {
		t.Fatalf("SetDeviceStatus = %v, %v", won, err)
	}
	upd := fd.execs[0]
	for _, want := range []string{"UPDATE", `"status" = $`, `"grant_id" = $`, `"id" = $`} {
		if !strings.Contains(upd, want) {
			t.Fatalf("SetDeviceStatus SQL lacks %q:\n%s", want, upd)
		}
	}
	if strings.Count(upd, `"status" = $`) != 2 {
		t.Fatalf("the compare (status = $from in the WHERE) is missing:\n%s", upd)
	}
	fd.execs = nil
	if _, err := st.SetDeviceStatus(context.Background(), "d", oauth.DeviceStatusPending, oauth.DeviceStatusDenied, "g", time.Now()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fd.execs[0], "grant_id") {
		t.Fatalf("a denial must not touch grant_id:\n%s", fd.execs[0])
	}
	// Zero rows: classified by a follow-up read.
	fd.affected = 0
	won, err = st.SetDeviceStatus(context.Background(), "d", oauth.DeviceStatusPending, oauth.DeviceStatusDenied, "", time.Now())
	if !errors.Is(err, oauth.ErrDeviceNotFound) || won {
		t.Fatalf("zero rows on an empty table = %v, %v; want ErrDeviceNotFound", won, err)
	}
}

func TestDeleteClientRunsFiveDeletesInOneTransaction(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newOAuthStore(fd)
	if err := st.DeleteClient(context.Background(), "c"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if fd.begins != 1 || fd.commits != 1 || fd.rollbacks != 0 {
		t.Fatalf("begins/commits/rollbacks = %d/%d/%d, want 1/1/0", fd.begins, fd.commits, fd.rollbacks)
	}
	if len(fd.execs) != 5 {
		t.Fatalf("DeleteClient issued %d statements, want 5:\n%s", len(fd.execs), strings.Join(fd.execs, "\n"))
	}
	for i, tbl := range []string{"oauth_refresh_tokens", "oauth_codes", "oauth_device_authorizations", "oauth_grants", "oauth_clients"} {
		if !strings.HasPrefix(fd.execs[i], "DELETE FROM") || !strings.Contains(fd.execs[i], `"`+tbl+`"`) {
			t.Fatalf("statement %d = %s, want DELETE FROM %s", i, fd.execs[i], tbl)
		}
	}
	// A miss on the client rolls back.
	fd = &fakeDriver{affected: 0}
	if err := newOAuthStore(fd).DeleteClient(context.Background(), "c"); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("DeleteClient(unknown) = %v, want ErrClientNotFound", err)
	}
	if fd.rollbacks != 1 || fd.commits != 0 {
		t.Fatalf("rollbacks/commits = %d/%d, want 1/0", fd.rollbacks, fd.commits)
	}
}

func TestRevokeGrantDeletesTokensAndStampsInOneTransaction(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newOAuthStore(fd)
	if err := st.RevokeGrant(context.Background(), "g", time.Now()); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if fd.begins != 1 || fd.commits != 1 || len(fd.execs) != 2 {
		t.Fatalf("begins/commits/statements = %d/%d/%d, want 1/1/2", fd.begins, fd.commits, len(fd.execs))
	}
	if !strings.HasPrefix(fd.execs[0], "DELETE FROM") || !strings.Contains(fd.execs[0], "oauth_refresh_tokens") || !strings.Contains(fd.execs[0], `"grant_id" = $`) {
		t.Fatalf("first statement = %s", fd.execs[0])
	}
	if !strings.HasPrefix(fd.execs[1], "UPDATE") || !strings.Contains(fd.execs[1], `"revoked_at" = $`) {
		t.Fatalf("second statement = %s", fd.execs[1])
	}
}

func TestListClientsQueriesNULLForApplicationLevel(t *testing.T) {
	fd := &fakeDriver{}
	st := newOAuthStore(fd)
	if _, err := st.ListClients(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fd.queries[0], `"container_id" IS NULL`) {
		t.Fatalf(`ListClients("") SQL = %s, want container_id IS NULL`, fd.queries[0])
	}
	if _, err := st.ListClients(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fd.queries[1], `"container_id" = $`) {
		t.Fatalf("ListClients(acme) SQL = %s", fd.queries[1])
	}
}

func TestPurgeExpiredStopsAfterTheThreeSweepsWhenNoGrantIsDead(t *testing.T) {
	fd := &fakeDriver{affected: 2}
	st := newOAuthStore(fd)
	n, err := st.PurgeExpired(context.Background(), time.Now())
	if err != nil || n != 6 {
		t.Fatalf("PurgeExpired = %d, %v; want 6 (three sweeps of two rows)", n, err)
	}
	if len(fd.execs) != 3 || len(fd.queries) != 1 {
		t.Fatalf("execs/queries = %d/%d, want 3/1", len(fd.execs), len(fd.queries))
	}
	for i, tbl := range []string{"oauth_codes", "oauth_device_authorizations", "oauth_refresh_tokens"} {
		if !strings.Contains(fd.execs[i], `"`+tbl+`"`) || !strings.Contains(fd.execs[i], `"expires_at" < $`) {
			t.Fatalf("sweep %d = %s", i, fd.execs[i])
		}
	}
	if !strings.Contains(fd.queries[0], "revoked_at") || !strings.Contains(fd.queries[0], "expires_at") {
		t.Fatalf("dead-grant SELECT = %s", fd.queries[0])
	}
	if fd.commits != 1 {
		t.Fatalf("commits = %d, want 1", fd.commits)
	}
}

func TestCreateGrantClassifiesTheDriversErrors(t *testing.T) {
	fk := &pg.PgError{Sentinel: pg.ErrForeignKeyViolation, Err: errors.New("fk")}
	st := newOAuthStore(&fakeDriver{execErr: fk})
	if _, err := st.CreateGrant(context.Background(), oauth.Grant{ID: "g"}); !errors.Is(err, oauth.ErrClientNotFound) || !errors.Is(err, pg.ErrForeignKeyViolation) {
		t.Fatalf("fk violation = %v, want ErrClientNotFound wrapping it", err)
	}
	if _, err := st.CreateCode(context.Background(), oauth.AuthorizationCode{ID: "k"}); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("fk violation on a code = %v, want ErrGrantNotFound", err)
	}
	other := &pg.PgError{Sentinel: pg.ErrUniqueViolation, Constraint: "oauth_codes_code_hash_key", Err: errors.New("unique")}
	st = newOAuthStore(&fakeDriver{execErr: other})
	if _, err := st.CreateCode(context.Background(), oauth.AuthorizationCode{ID: "k"}); !errors.Is(err, pg.ErrUniqueViolation) || errors.Is(err, oauth.ErrIDTaken) {
		t.Fatalf("hash collision = %v, want pg.ErrUniqueViolation unwrapped", err)
	}
	// isPrimaryKeyViolation reads the DRIVER's own error for the constraint
	// name, so the fabricated error carries one.
	pkey := &pg.PgError{Sentinel: pg.ErrUniqueViolation, Constraint: "oauth_codes_pkey", Err: &pgconn.PgError{Code: "23505", ConstraintName: "oauth_codes_pkey"}}
	st = newOAuthStore(&fakeDriver{execErr: pkey})
	if _, err := st.CreateCode(context.Background(), oauth.AuthorizationCode{ID: "k"}); !errors.Is(err, oauth.ErrIDTaken) {
		t.Fatalf("pkey collision = %v, want ErrIDTaken", err)
	}
}
