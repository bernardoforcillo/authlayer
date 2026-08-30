//go:build integration

// Live end-to-end proof for the text-library-ids escape hatch. Run with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...`
// stays database-free.
//
// This file exists because the hatch is only worth anything if it works
// against a real PostgreSQL: the whole failure it removes — SQLSTATE 22P02
// from the uuid parser — is a server-side one that store/memory cannot
// reproduce and that no schema-shape unit test can observe. The unit tests in
// schema_test.go, auth_test.go and invite_test.go pin the COLUMN TYPES; these
// pin that the resulting DDL actually holds the values, in both directions.
package dropsstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/password"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// crockford is the base32 alphabet ULIDs are rendered in (Crockford's, with
// I, L, O and U removed).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newULIDGen returns an id generator producing 26-character Crockford base32
// strings — the exact shape github.com/oklog/ulid and every other ULID
// library emits, and the single most common answer to "what would someone
// pass to WithIDGenerator".
//
// It is written out here rather than depended on because the SHAPE is the
// whole point: PostgreSQL's uuid parser rejects a 26-character base32 string
// outright, which is the failure this hatch removes. Real ULID entropy would
// add nothing to that. The counter half guarantees uniqueness within a test
// without needing randomness at all, and the mutex is there because
// auth.Service and scope.Service both call the generator from whatever
// goroutine the request arrived on.
func newULIDGen() func() string {
	var mu sync.Mutex
	var n uint64
	return func() string {
		mu.Lock()
		n++
		v := n
		mu.Unlock()

		ms := uint64(time.Now().UTC().UnixMilli())
		b := make([]byte, 26)
		for i := 9; i >= 0; i-- {
			b[i] = crockford[ms&31]
			ms >>= 5
		}
		for i := 25; i >= 10; i-- {
			b[i] = crockford[v&31]
			v >>= 5
		}
		return string(b)
	}
}

// isULIDShaped reports whether id is one of newULIDGen's outputs, so an
// assertion can say "this really is the configured generator's value" rather
// than merely "not empty". A UUID carries hyphens, so nothing uid.NewV7 mints
// can pass this.
func isULIDShaped(id string) bool {
	if len(id) != 26 {
		return false
	}
	for _, r := range id {
		if !strings.ContainsRune(crockford, r) {
			return false
		}
	}
	return true
}

// columnType reads a column's declared type straight out of the live
// catalogue, which is the only witness to what CreateSchema actually emitted.
// A schema-object assertion proves what the builder holds in memory; this
// proves what reached the server.
func columnType(t *testing.T, sqlDB *sql.DB, table, column string) string {
	t.Helper()
	var typ string
	const q = "SELECT data_type FROM information_schema.columns " +
		"WHERE table_name = $1 AND column_name = $2"
	if err := sqlDB.QueryRowContext(context.Background(), q, table, column).Scan(&typ); err != nil {
		t.Fatalf("read %s.%s type: %v", table, column, err)
	}
	return typ
}

// newLiveTextIDStores builds both stores with the hatch on, drops and
// recreates all six tables, and hands back the pieces. The scope store gets
// WithTextUserIDs as well as WithTextLibraryIDs, because in this
// configuration its owner_id and user_id hold ids minted by auth's generator
// — the same non-UUID one.
func newLiveTextIDStores(t *testing.T) (*sql.DB, *dropsstore.AuthStore, *dropsstore.Store[org.Organization, org.Member]) {
	t.Helper()
	sqlDB, db := openLiveDB(t)

	authSt := dropsstore.NewAuthStore(db, dropsstore.WithAuthTextLibraryIDs())
	scopeSt := dropsstore.New[org.Organization, org.Member](db,
		dropsstore.WithTextLibraryIDs(), dropsstore.WithTextUserIDs())

	drop := func() {
		dropAuthTables(t, db, authSt)
		dropAll(t, db, scopeSt)
	}
	drop()
	ctx := context.Background()
	if err := authSt.CreateSchema(ctx); err != nil {
		t.Fatalf("AuthStore.CreateSchema under the hatch: %v", err)
	}
	if err := scopeSt.CreateSchema(ctx); err != nil {
		t.Fatalf("Store.CreateSchema under the hatch: %v", err)
	}
	t.Cleanup(drop)

	return sqlDB, authSt, scopeSt
}

// TestTextLibraryIDsRoundTripANonUUIDGeneratorLive is the proof that
// auth.WithIDGenerator and scope.WithIDGenerator are now honourable against
// the shipped PostgreSQL backend rather than merely documented as constrained.
//
// One ULID generator drives BOTH services, exactly as a real deployment
// would: the user id auth mints is the subject scope then stamps into
// owner_id and user_id, so if either half typed a column wrong the other half
// would fail. It runs a full auth arc (sign up, verify, log in, refresh —
// which exercises the compare-and-set rotation and therefore a second session
// id and a family id) and a full scope arc (create, add a member, create a
// custom role, change a role, authorize, list), reading the values back so
// the assertion is round-trip rather than write-only.
//
// Its counterparts in the negative direction are
// TestNonUUIDIDGeneratorFailsAgainstDropsLive (auth) and
// TestNonUUIDIDGeneratorFailsAgainstTheScopeStoreLive (scope), which both
// assert the 22P02 the hatch removes. Together the three pin that the option
// is load-bearing and not decorative: remove it and the negatives still pass
// while this one fails.
func TestTextLibraryIDsRoundTripANonUUIDGeneratorLive(t *testing.T) {
	_, authSt, scopeSt := newLiveTextIDStores(t)
	ctx := context.Background()
	gen := newULIDGen()

	authSvc := auth.New(authSt,
		auth.WithHasher(password.Bcrypt(bcrypt.MinCost)),
		auth.WithJWT([][]byte{bytes.Repeat([]byte("k"), 32)}, 15*time.Minute),
		auth.WithIDGenerator(gen),
	)
	orgSvc := org.New(org.NewAccess(map[string][]access.Action{
		"project": {"create", "delete"},
	}), scopeSt, org.WithIDGenerator(gen))

	// ── the auth arc ────────────────────────────────────────────────────
	owner, err := authSvc.SignUp(ctx, "ulid-owner@example.com", liveTestPassword)
	if err != nil {
		t.Fatalf("SignUp with a ULID generator under the hatch: %v", err)
	}
	if !isULIDShaped(owner.User.ID) {
		t.Fatalf("SignUp minted User.ID = %q, want the configured generator's shape", owner.User.ID)
	}
	if _, err := authSvc.VerifyEmail(ctx, owner.VerifyToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	login, err := authSvc.Login(ctx, "ulid-owner@example.com", liveTestPassword, "203.0.113.7", "agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Refresh rotates the session: it reads the predecessor by hash, inserts a
	// successor carrying the same family_id, and compare-and-sets the old row.
	// Every one of those touches an id column that used to be uuid.
	refreshed, err := authSvc.Refresh(ctx, login.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.RefreshToken == login.RefreshToken {
		t.Fatal("Refresh returned the same refresh token, so no rotation happened")
	}

	// Read back through the Store, not the Service, so the assertion is on
	// what PostgreSQL is holding.
	loaded, err := authSt.FindUserByID(ctx, owner.User.ID)
	if err != nil {
		t.Fatalf("FindUserByID(%q): %v", owner.User.ID, err)
	}
	if loaded.ID != owner.User.ID {
		t.Fatalf("users.id round-tripped as %q, want %q", loaded.ID, owner.User.ID)
	}
	sessions, err := authSt.ListSessionsByUser(ctx, owner.User.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("ListSessionsByUser returned %d rows, want 2 (login + its rotated successor)", len(sessions))
	}
	for _, s := range sessions {
		if !isULIDShaped(s.ID) {
			t.Fatalf("session id = %q, want the configured generator's shape", s.ID)
		}
		if s.UserID != owner.User.ID {
			t.Fatalf("session user_id = %q, want %q", s.UserID, owner.User.ID)
		}
		if !isULIDShaped(s.FamilyID) {
			t.Fatalf("session family_id = %q, want the configured generator's shape", s.FamilyID)
		}
	}

	// ── the scope arc, keyed by the very user id auth just minted ───────
	member, err := authSvc.SignUp(ctx, "ulid-member@example.com", liveTestPassword)
	if err != nil {
		t.Fatalf("SignUp (member): %v", err)
	}

	ownerCtx := org.WithSubject(ctx, owner.User.ID)
	acme, err := orgSvc.CreateOrganization(ownerCtx, "Acme", "acme")
	if err != nil {
		t.Fatalf("CreateOrganization with a ULID generator under the hatch: %v", err)
	}
	if !isULIDShaped(acme.ID) {
		t.Fatalf("CreateOrganization minted id = %q, want the configured generator's shape", acme.ID)
	}
	if acme.OwnerID != owner.User.ID {
		t.Fatalf("organizations.owner_id = %q, want the auth-minted %q", acme.OwnerID, owner.User.ID)
	}

	acmeCtx := org.WithOrg(ownerCtx, acme.ID)
	if _, err := orgSvc.AddMember(acmeCtx, member.User.ID, org.RoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if _, err := orgSvc.CreateRole(acmeCtx, "editor", "Editor", map[string][]access.Action{
		"project": {"create"},
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	// RoleView carries no id, so read the record back through the Store —
	// which is the stronger assertion anyway: the roles table has its own
	// library-minted id column and its own container_id, and both are text
	// here.
	roleRec, err := scopeSt.FindRole(ctx, acme.ID, "editor")
	if err != nil {
		t.Fatalf("FindRole: %v", err)
	}
	if !isULIDShaped(roleRec.ID) {
		t.Fatalf("CreateRole minted id = %q, want the configured generator's shape", roleRec.ID)
	}
	if roleRec.ContainerID != acme.ID {
		t.Fatalf("organization_roles.container_id = %q, want %q", roleRec.ContainerID, acme.ID)
	}
	if err := orgSvc.ChangeMemberRole(acmeCtx, member.User.ID, "editor"); err != nil {
		t.Fatalf("ChangeMemberRole: %v", err)
	}

	// The custom role resolved out of a text-keyed roles table still decides
	// permissions, so the hatch has not quietly broken authorization.
	memberCtx := org.WithOrg(org.WithSubject(ctx, member.User.ID), acme.ID)
	if ok, err := orgSvc.Can(memberCtx, "project", "create"); err != nil || !ok {
		t.Fatalf("Can(project:create) = %v, %v; want true for the editor role", ok, err)
	}
	if ok, _ := orgSvc.Can(memberCtx, org.ResourceOrganization, org.ActionDelete); ok {
		t.Fatal("editor must not be allowed organization:delete")
	}

	back, err := orgSvc.Container(acmeCtx, acme.ID)
	if err != nil {
		t.Fatalf("Container(%q): %v", acme.ID, err)
	}
	if back.ID != acme.ID || back.OwnerID != owner.User.ID {
		t.Fatalf("organization round-tripped as {id:%q owner:%q}, want {%q %q}",
			back.ID, back.OwnerID, acme.ID, owner.User.ID)
	}
	members, err := orgSvc.ListMembers(acmeCtx)
	if err != nil || len(members) != 2 {
		t.Fatalf("ListMembers = %d rows, %v; want 2", len(members), err)
	}
}

// TestCreateSchemaIDColumnTypesFollowTheHatchLive reads the emitted DDL back
// out of information_schema in BOTH modes, and re-runs CreateSchema to prove
// it stayed idempotent.
//
// The two halves are the whole contract of the option: with the hatch every
// id column is text, and — the part that protects existing deployments —
// without it every one of them is still uuid. The default moving would
// silently retype the primary key of every table this library owns.
func TestCreateSchemaIDColumnTypesFollowTheHatchLive(t *testing.T) {
	// The library-minted id columns, then the user-id columns that follow the
	// OTHER option on the scope store but this same one on the auth store.
	libraryCols := map[string][]string{
		"organizations":        {"id"},
		"organization_members": {"container_id"},
		"organization_roles":   {"id", "container_id"},
		"users":                {"id"},
		"sessions":             {"id"},
		"verifications":        {"id"},
	}
	authUserCols := map[string][]string{
		"sessions":      {"user_id"},
		"verifications": {"user_id"},
	}

	t.Run("with the hatch", func(t *testing.T) {
		sqlDB, authSt, _ := newLiveTextIDStores(t)
		ctx := context.Background()

		for tbl, cols := range libraryCols {
			for _, c := range cols {
				if got := columnType(t, sqlDB, tbl, c); got != "text" {
					t.Fatalf("%s.%s is %q on the server, want text under the hatch", tbl, c, got)
				}
			}
		}
		// The auth store's user_id columns reference users.id, so they must
		// have moved with it — see WithAuthTextLibraryIDs.
		for tbl, cols := range authUserCols {
			for _, c := range cols {
				if got := columnType(t, sqlDB, tbl, c); got != "text" {
					t.Fatalf("%s.%s is %q on the server, want text (it references users.id)", tbl, c, got)
				}
			}
		}

		// Idempotent: CreateSchema adds what is missing and alters nothing, so
		// a second run must succeed and change no type. Its constraint
		// statements are plpgsql DO blocks swallowing duplicate_table,
		// duplicate_object and invalid_table_definition; a second run is where
		// a missing guard would show up.
		if err := authSt.CreateSchema(ctx); err != nil {
			t.Fatalf("second AuthStore.CreateSchema under the hatch: %v", err)
		}
		if got := columnType(t, sqlDB, "users", "id"); got != "text" {
			t.Fatalf("users.id became %q after a second CreateSchema, want text", got)
		}
	})

	t.Run("without the hatch", func(t *testing.T) {
		sqlDB, db := openLiveDB(t)
		authSt := dropsstore.NewAuthStore(db)
		scopeSt := dropsstore.New[org.Organization, org.Member](db)
		drop := func() {
			dropAuthTables(t, db, authSt)
			dropAll(t, db, scopeSt)
		}
		drop()
		ctx := context.Background()
		if err := authSt.CreateSchema(ctx); err != nil {
			t.Fatalf("AuthStore.CreateSchema: %v", err)
		}
		if err := scopeSt.CreateSchema(ctx); err != nil {
			t.Fatalf("Store.CreateSchema: %v", err)
		}
		t.Cleanup(drop)

		for tbl, cols := range libraryCols {
			for _, c := range cols {
				if got := columnType(t, sqlDB, tbl, c); got != "uuid" {
					t.Fatalf("%s.%s is %q by default, want uuid — the default must not move", tbl, c, got)
				}
			}
		}
		for tbl, cols := range authUserCols {
			for _, c := range cols {
				if got := columnType(t, sqlDB, tbl, c); got != "uuid" {
					t.Fatalf("%s.%s is %q by default, want uuid", tbl, c, got)
				}
			}
		}
		if got := columnType(t, sqlDB, "organization_members", "user_id"); got != "uuid" {
			t.Fatalf("organization_members.user_id is %q by default, want uuid", got)
		}
	})
}

// TestNonUUIDIDGeneratorFailsAgainstTheScopeStoreLive is the scope-side
// negative, and the reason the hatch had to reach the scope constructors and
// not only the auth one: scope.WithIDGenerator's doc named ULIDs first, and a
// container id is a library-minted id exactly as a user id is.
//
// It asserts the SQLSTATE rather than merely "an error", because the exact
// code is what scope.WithIDGenerator's doc names and what a reader hitting it
// in production will search for; and it asserts the failing VALUE appears in
// the message, since that is what tells a reader which knob produced it.
//
// Its counterpart on the auth side is
// TestNonUUIDIDGeneratorFailsAgainstDropsLive, and the positive direction —
// the same shape of generator working once the hatch is on — is
// TestTextLibraryIDsRoundTripANonUUIDGeneratorLive.
func TestNonUUIDIDGeneratorFailsAgainstTheScopeStoreLive(t *testing.T) {
	_, db := openLiveDB(t)
	// WithTextUserIDs and NOT WithTextLibraryIDs, deliberately: this is the
	// configuration a reader would reach for on the name alone, and it is
	// exactly the one that does not help. owner_id is text here; the
	// container's own id is not, and that is what fails.
	st := dropsstore.New[org.Organization, org.Member](db, dropsstore.WithTextUserIDs())
	ctx := context.Background()
	dropAll(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAll(t, db, st) })

	n := 0
	svc := org.New(org.NewAccess(map[string][]access.Action{
		"project": {"create"},
	}), st, org.WithIDGenerator(func() string {
		n++
		return fmt.Sprintf("org_readable_%03d", n)
	}))

	_, err := svc.CreateOrganization(org.WithSubject(ctx, "not-a-uuid-either"), "Acme", "acme")
	if err == nil {
		t.Fatal("CreateOrganization succeeded with a non-UUID id generator and no WithTextLibraryIDs — if this now works, scope.WithIDGenerator's doc and WithTextLibraryIDs' own reason to exist are both stale")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("CreateOrganization err = %v (%T), want a *pgconn.PgError", err, err)
	}
	if pgErr.Code != "22P02" {
		t.Fatalf("CreateOrganization err SQLSTATE = %s, want 22P02 (invalid_text_representation): %v", pgErr.Code, err)
	}
	if !strings.Contains(err.Error(), "org_readable_") {
		t.Fatalf("CreateOrganization err does not name the rejected id, so a reader cannot tell which knob produced it: %v", err)
	}
	t.Logf("SQLSTATE %s: %v", pgErr.Code, err)
}
