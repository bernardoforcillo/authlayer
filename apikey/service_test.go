package apikey_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/team"
	"github.com/bernardoforcillo/authlayer/token"
)

type fixture struct {
	t     *testing.T
	ac    *access.Access
	org   *org.Service
	st    *memory.APIKeyStore
	svc   *apikey.Service[org.Organization, org.Member, *org.Organization, *org.Member]
	cID   string
	now   time.Time
	clock func() time.Time
	// events collects every hook event, in order.
	events []apikey.Event
}

// newFixture wires an organization with a "project" resource, an owner, an
// admin ("admin1") and a plain member ("member1"), and an apikey Service over
// a fixed clock the tests can advance through f.now.
func newFixture(t *testing.T, opts ...apikey.Option) *fixture {
	t.Helper()
	ac := org.NewAccess(map[string][]access.Action{
		"project": {"create", "read", "update", "delete"},
	})
	f := &fixture{t: t, ac: ac, now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	f.clock = func() time.Time { return f.now }
	f.org = org.New(ac, memory.New[org.Organization, org.Member](), org.WithClock(f.clock))
	f.st = memory.NewAPIKeyStore()
	base := []apikey.Option{
		apikey.WithClock(f.clock),
		apikey.WithHooks(apikey.HookFunc(func(_ context.Context, e apikey.Event) error {
			f.events = append(f.events, e)
			return nil
		})),
	}
	f.svc = apikey.New(f.org.Service, f.st, append(base, opts...)...)

	c, err := f.org.CreateOrganization(scope.WithSubject(context.Background(), "owner"), "Acme", "acme")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	f.cID = c.ID
	f.addMember("admin1", org.RoleAdmin)
	f.addMember("member1", org.RoleMember)
	return f
}

func (f *fixture) ctx(userID string) context.Context {
	return org.WithOrg(org.WithSubject(context.Background(), userID), f.cID)
}

func (f *fixture) addMember(userID, roleKey string) {
	f.t.Helper()
	if _, err := f.org.AddMember(f.ctx("owner"), userID, roleKey); err != nil {
		f.t.Fatalf("AddMember(%s, %s): %v", userID, roleKey, err)
	}
}

func (f *fixture) capOf(grants map[string][]access.Action) access.Permission {
	f.t.Helper()
	p, err := f.ac.Permission(grants)
	if err != nil {
		f.t.Fatalf("build cap %v: %v", grants, err)
	}
	return p
}

// account creates a service account as the owner, at roleKey.
func (f *fixture) account(roleKey string) apikey.ServiceAccount {
	f.t.Helper()
	sa, err := f.svc.CreateServiceAccount(f.ctx("owner"), "ci", "deploys things", roleKey)
	if err != nil {
		f.t.Fatalf("CreateServiceAccount(%s): %v", roleKey, err)
	}
	return sa
}

// key mints a key for sa as actor.
func (f *fixture) key(actor string, sa apikey.ServiceAccount, opts ...apikey.KeyOption) (apikey.Key, string) {
	f.t.Helper()
	k, plain, err := f.svc.CreateKey(f.ctx(actor), sa.ID, "k", opts...)
	if err != nil {
		f.t.Fatalf("CreateKey: %v", err)
	}
	return k, plain
}

func (f *fixture) can(ctx context.Context, resource string, actions ...access.Action) bool {
	f.t.Helper()
	ok, err := f.org.Can(ctx, resource, actions...)
	if err != nil {
		f.t.Fatalf("Can(%s %v): %v", resource, actions, err)
	}
	return ok
}

func (f *fixture) kinds() []apikey.EventKind {
	out := make([]apikey.EventKind, 0, len(f.events))
	for _, e := range f.events {
		out = append(out, e.Kind)
	}
	return out
}

// ── CreateServiceAccount ─────────────────────────────────────────────────────

func TestCreateServiceAccountWritesTheRecordAndTheMembership(t *testing.T) {
	f := newFixture(t)
	sa, err := f.svc.CreateServiceAccount(f.ctx("admin1"), "ci", "deploys", org.RoleMember)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if sa.ID == "" || sa.ContainerID != f.cID || sa.Name != "ci" || sa.Description != "deploys" || sa.CreatedBy != "admin1" {
		t.Fatalf("record = %+v", sa)
	}
	if !sa.CreatedAt.Equal(f.now) || !sa.UpdatedAt.Equal(f.now) || sa.DisabledAt != nil {
		t.Fatalf("stamps = %v %v %v, want the clock and nil", sa.CreatedAt, sa.UpdatedAt, sa.DisabledAt)
	}
	// The account is a member: scope resolves its role like anyone's.
	perms, elevated, err := f.org.Standing(context.Background(), f.cID, sa.ID)
	if err != nil || elevated || !perms.IsZero() {
		t.Fatalf("Standing(sa) = %v elevated=%v err=%v; want the member role", perms.IsZero(), elevated, err)
	}
	stored, err := f.st.FindServiceAccount(context.Background(), sa.ID)
	if err != nil || stored != sa {
		t.Fatalf("stored = %+v, %v; want the returned record", stored, err)
	}
	// The event names the real actor, unlike scope's MemberAdded.
	if len(f.events) != 1 || f.events[0].Kind != apikey.ServiceAccountCreated ||
		f.events[0].ActorID != "admin1" || f.events[0].ServiceAccountID != sa.ID ||
		f.events[0].RoleKey != org.RoleMember || f.events[0].ContainerID != f.cID || !f.events[0].At.Equal(f.now) {
		t.Fatalf("events = %+v", f.events)
	}
}

func TestCreateServiceAccountRequiresServiceAccountCreate(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.CreateServiceAccount(f.ctx("member1"), "ci", "", org.RoleMember); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member creating an account = %v, want ErrForbidden", err)
	}
	if _, err := f.svc.CreateServiceAccount(f.ctx("stranger"), "ci", "", org.RoleMember); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("stranger = %v, want ErrNotMember", err)
	}
	if _, err := f.svc.CreateServiceAccount(context.Background(), "ci", "", org.RoleMember); !errors.Is(err, scope.ErrSubjectMissing) {
		t.Fatalf("no subject = %v, want ErrSubjectMissing", err)
	}
	if got, _ := f.st.ListServiceAccounts(context.Background(), f.cID); len(got) != 0 {
		t.Fatalf("a refused create wrote %d record(s)", len(got))
	}
}

func TestCreateServiceAccountGuardsEscalation(t *testing.T) {
	f := newFixture(t)
	// An admin may not create an owner-role account (owner is Full).
	if _, err := f.svc.CreateServiceAccount(f.ctx("admin1"), "ci", "", org.RoleOwner); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("admin creating an owner-role account = %v, want ErrPrivilegeEscalation", err)
	}
	// But may create one at its own rank.
	if _, err := f.svc.CreateServiceAccount(f.ctx("admin1"), "ci", "", org.RoleAdmin); err != nil {
		t.Fatalf("admin creating an admin-role account: %v", err)
	}
	// An unknown role is ErrRoleNotFound, not an escalation.
	if _, err := f.svc.CreateServiceAccount(f.ctx("admin1"), "ci", "", "no-such-role"); !errors.Is(err, scope.ErrRoleNotFound) {
		t.Fatalf("unknown role = %v, want ErrRoleNotFound", err)
	}
	// The owner is elevated and exempt.
	if _, err := f.svc.CreateServiceAccount(f.ctx("owner"), "ci", "", org.RoleOwner); err != nil {
		t.Fatalf("owner creating an owner-role account: %v", err)
	}
}

// The guard compares against the actor's CAPPED standing: through a key
// restricted to service_account:create, an admin cannot create an admin-role
// account, even though the admin behind the key could.
func TestCreateServiceAccountGuardUsesTheCappedStanding(t *testing.T) {
	f := newFixture(t)
	capped := scope.WithPermissionCap(f.ctx("admin1"), f.capOf(map[string][]access.Action{
		scope.ResourceServiceAccount: {scope.ActionCreate},
	}))
	if _, err := f.svc.CreateServiceAccount(capped, "ci", "", org.RoleAdmin); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("capped admin creating an admin-role account = %v, want ErrPrivilegeEscalation", err)
	}
	if _, err := f.svc.CreateServiceAccount(capped, "ci", "", org.RoleMember); err != nil {
		t.Fatalf("capped admin creating a member-role account: %v", err)
	}
	// A capped owner is not elevated either.
	ownerCapped := scope.WithPermissionCap(f.ctx("owner"), f.capOf(map[string][]access.Action{
		scope.ResourceServiceAccount: {scope.ActionCreate},
	}))
	if _, err := f.svc.CreateServiceAccount(ownerCapped, "ci", "", org.RoleAdmin); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("capped owner creating an admin-role account = %v, want ErrPrivilegeEscalation", err)
	}
}

// On a nested scope under MembersFromParent, GrantMembership refuses a
// subject with no parent standing — which a freshly minted id never has. The
// record was written first, so the failure must compensate: no orphan record
// survives, and the error is scope's own.
func TestCreateServiceAccountCompensatesAFailedGrant(t *testing.T) {
	orgSvc := org.New(org.NewAccess(team.ParentStatements()), memory.New[org.Organization, org.Member]())
	teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc)
	st := memory.NewAPIKeyStore()
	keys := apikey.New(teamSvc.Service, st)

	octx := scope.WithSubject(context.Background(), "owner")
	o, err := orgSvc.CreateOrganization(octx, "Acme", "acme")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	tm, err := teamSvc.CreateTeam(org.WithOrg(octx, o.ID), "Platform")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	tctx := team.WithTeam(octx, tm.ID)

	_, err = keys.CreateServiceAccount(tctx, "ci", "", team.RoleMember)
	if !errors.Is(err, scope.ErrNotParentMember) {
		t.Fatalf("CreateServiceAccount on a nested scope = %v, want ErrNotParentMember", err)
	}
	if got, _ := st.ListServiceAccounts(context.Background(), tm.ID); len(got) != 0 {
		t.Fatalf("an inert record survived the failed grant: %+v", got)
	}
}

// ── List / Disable / Enable ──────────────────────────────────────────────────

func TestListServiceAccountsScopesAndRequiresRead(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)

	list, err := f.svc.ListServiceAccounts(f.ctx("admin1"))
	if err != nil || len(list) != 1 || list[0].ID != sa.ID {
		t.Fatalf("ListServiceAccounts = %+v, %v", list, err)
	}
	if _, err := f.svc.ListServiceAccounts(f.ctx("member1")); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member listing = %v, want ErrForbidden", err)
	}
	// Another container sees nothing of it.
	other, err := f.org.CreateOrganization(scope.WithSubject(context.Background(), "zed"), "Globex", "globex")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	zed := org.WithOrg(org.WithSubject(context.Background(), "zed"), other.ID)
	if list, err := f.svc.ListServiceAccounts(zed); err != nil || len(list) != 0 {
		t.Fatalf("other container lists %+v, %v", list, err)
	}
	// And cannot reach it by id either — a cross-tenant id is a missing one.
	if err := f.svc.DisableServiceAccount(zed, sa.ID); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("cross-tenant disable = %v, want ErrServiceAccountNotFound", err)
	}
	if _, err := f.svc.ListKeys(zed, sa.ID); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("cross-tenant ListKeys = %v, want ErrServiceAccountNotFound", err)
	}
	if err := f.svc.DeleteServiceAccount(zed, sa.ID); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("cross-tenant delete = %v, want ErrServiceAccountNotFound", err)
	}
	if _, _, err := f.svc.CreateKey(zed, sa.ID, "k"); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("cross-tenant CreateKey = %v, want ErrServiceAccountNotFound", err)
	}
}

func TestDisableAndEnableServiceAccount(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	_, plain := f.key("owner", sa)

	if err := f.svc.DisableServiceAccount(f.ctx("member1"), sa.ID); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member disabling = %v, want ErrForbidden", err)
	}
	f.now = f.now.Add(time.Minute)
	if err := f.svc.DisableServiceAccount(f.ctx("admin1"), sa.ID); err != nil {
		t.Fatalf("DisableServiceAccount: %v", err)
	}
	got, _ := f.st.FindServiceAccount(context.Background(), sa.ID)
	if got.DisabledAt == nil || !got.DisabledAt.Equal(f.now) || !got.UpdatedAt.Equal(f.now) {
		t.Fatalf("after disable: %+v", got)
	}
	// Every key is refused, and none can be minted, while disabled.
	if _, err := f.svc.Authenticate(context.Background(), plain); !errors.Is(err, apikey.ErrServiceAccountDisabled) {
		t.Fatalf("Authenticate while disabled = %v, want ErrServiceAccountDisabled", err)
	}
	if _, _, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "k2"); !errors.Is(err, apikey.ErrServiceAccountDisabled) {
		t.Fatalf("CreateKey while disabled = %v, want ErrServiceAccountDisabled", err)
	}
	// Idempotent.
	if err := f.svc.DisableServiceAccount(f.ctx("admin1"), sa.ID); err != nil {
		t.Fatalf("second disable: %v", err)
	}
	// The membership was untouched, so enabling restores the account.
	if err := f.svc.EnableServiceAccount(f.ctx("admin1"), sa.ID); err != nil {
		t.Fatalf("EnableServiceAccount: %v", err)
	}
	got, _ = f.st.FindServiceAccount(context.Background(), sa.ID)
	if got.DisabledAt != nil {
		t.Fatalf("after enable: %+v", got)
	}
	if _, err := f.svc.Authenticate(context.Background(), plain); err != nil {
		t.Fatalf("Authenticate after enable: %v", err)
	}
	if err := f.svc.EnableServiceAccount(f.ctx("admin1"), "nope"); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("enable unknown = %v, want ErrServiceAccountNotFound", err)
	}
}

// ── ChangeServiceAccountRole ─────────────────────────────────────────────────

func TestChangeServiceAccountRoleDelegatesToScope(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	_, plain := f.key("owner", sa)

	if err := f.svc.ChangeServiceAccountRole(f.ctx("member1"), sa.ID, org.RoleAdmin); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member changing a role = %v, want ErrForbidden", err)
	}
	// An admin may raise it to admin, not to owner.
	if err := f.svc.ChangeServiceAccountRole(f.ctx("admin1"), sa.ID, org.RoleOwner); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("admin raising to owner = %v, want ErrPrivilegeEscalation", err)
	}
	if err := f.svc.ChangeServiceAccountRole(f.ctx("admin1"), sa.ID, org.RoleAdmin); err != nil {
		t.Fatalf("ChangeServiceAccountRole: %v", err)
	}
	// The existing, unrestricted key now acts with the new role.
	p, err := f.svc.Authenticate(context.Background(), plain)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !f.can(apikey.WithPrincipal(context.Background(), p), scope.ResourceMember, scope.ActionCreate) {
		t.Fatal("a key follows its account's role: the raised role should grant member:create")
	}
	if err := f.svc.ChangeServiceAccountRole(f.ctx("admin1"), sa.ID, "nope"); !errors.Is(err, scope.ErrRoleNotFound) {
		t.Fatalf("unknown role = %v, want ErrRoleNotFound", err)
	}
	if last := f.events[len(f.events)-2]; last.Kind != apikey.ServiceAccountRoleChanged || last.RoleKey != org.RoleAdmin || last.ActorID != "admin1" {
		t.Fatalf("event = %+v, want ServiceAccountRoleChanged by admin1", last)
	}
}

// ── DeleteServiceAccount ─────────────────────────────────────────────────────

func TestDeleteServiceAccountRemovesMembershipRecordAndKeys(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	_, plain := f.key("owner", sa)

	if err := f.svc.DeleteServiceAccount(f.ctx("member1"), sa.ID); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member deleting = %v, want ErrForbidden", err)
	}
	if err := f.svc.DeleteServiceAccount(f.ctx("admin1"), sa.ID); err != nil {
		t.Fatalf("DeleteServiceAccount: %v", err)
	}
	if _, _, err := f.org.Standing(context.Background(), f.cID, sa.ID); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("membership after delete = %v, want ErrNotMember", err)
	}
	if _, err := f.st.FindServiceAccount(context.Background(), sa.ID); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("record after delete = %v, want ErrServiceAccountNotFound", err)
	}
	if last := f.events[len(f.events)-1]; last.Kind != apikey.ServiceAccountDeleted || last.ServiceAccountID != sa.ID || last.ActorID != "admin1" {
		t.Fatalf("event = %+v, want ServiceAccountDeleted by admin1", last)
	}
	if _, err := f.svc.Authenticate(context.Background(), plain); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("Authenticate after delete = %v, want ErrKeyNotFound — the keys went with the account", err)
	}
	if err := f.svc.DeleteServiceAccount(f.ctx("admin1"), sa.ID); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("second delete = %v, want ErrServiceAccountNotFound", err)
	}
}

// RemoveMember's target-rank guard applies: a non-elevated actor may not
// delete an account whose role exceeds their own capped standing.
func TestDeleteServiceAccountAppliesTheTargetRankGuard(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleOwner) // created by the owner, so allowed
	if err := f.svc.DeleteServiceAccount(f.ctx("admin1"), sa.ID); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("admin deleting an owner-role account = %v, want ErrPrivilegeEscalation", err)
	}
	if _, err := f.st.FindServiceAccount(context.Background(), sa.ID); err != nil {
		t.Fatalf("a refused delete removed the record: %v", err)
	}
}

// ── CreateKey ────────────────────────────────────────────────────────────────

func TestCreateKeyMintsAHashedPlaintextReturnedOnce(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	k, plain, err := f.svc.CreateKey(f.ctx("admin1"), sa.ID, "github")
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	// sk_ + 43 url-safe base64 characters of 32 random bytes, no padding.
	if !strings.HasPrefix(plain, "sk_") || len(plain) != 3+43 {
		t.Fatalf("plaintext %q: want sk_ + 43 chars", plain)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(plain[3:]); err != nil || len(raw) != 32 {
		t.Fatalf("plaintext body is not 32 url-safe base64 bytes: %v (%d)", err, len(raw))
	}
	if k.Prefix != plain[:11] || !strings.HasPrefix(k.Prefix, "sk_") {
		t.Fatalf("Prefix = %q, want the first 11 chars of %q", k.Prefix, plain)
	}
	if k.TokenHash != token.HashOpaque(plain) || k.TokenHash == plain {
		t.Fatal("TokenHash must be HashOpaque(plaintext), never the plaintext")
	}
	if k.ID == "" || k.ServiceAccountID != sa.ID || k.ContainerID != f.cID || k.Name != "github" || k.CreatedBy != "admin1" {
		t.Fatalf("key = %+v", k)
	}
	if k.Permissions != nil || k.ExpiresAt != nil || k.RevokedAt != nil || k.LastUsedAt != nil || !k.CreatedAt.Equal(f.now) {
		t.Fatalf("key stamps = %+v", k)
	}
	// The stored row carries no plaintext anywhere.
	stored, err := f.st.FindKey(context.Background(), k.ID)
	if err != nil || stored.TokenHash != k.TokenHash {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	if last := f.events[len(f.events)-1]; last.Kind != apikey.KeyCreated || last.KeyID != k.ID || last.ActorID != "admin1" {
		t.Fatalf("event = %+v", last)
	}
	// Two keys never share a plaintext.
	_, plain2 := f.key("admin1", sa)
	if plain2 == plain {
		t.Fatal("two keys share a plaintext")
	}
}

func TestCreateKeyRequiresServiceAccountUpdate(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	if _, _, err := f.svc.CreateKey(f.ctx("member1"), sa.ID, "k"); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member minting = %v, want ErrForbidden", err)
	}
	if _, _, err := f.svc.CreateKey(f.ctx("admin1"), "nope", "k"); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("unknown account = %v, want ErrServiceAccountNotFound", err)
	}
}

// A key is a grant of the account's standing, so minting one is guarded like
// AddMember: an admin may not mint an unrestricted key for an owner-role
// account, since holding it would make the admin an owner.
func TestCreateKeyGuardsTheAccountsRoleAgainstTheActor(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleOwner)
	if _, _, err := f.svc.CreateKey(f.ctx("admin1"), sa.ID, "k"); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("admin minting an unrestricted owner key = %v, want ErrPrivilegeEscalation", err)
	}
	// A key restricted to what the admin holds is fine.
	if _, _, err := f.svc.CreateKey(f.ctx("admin1"), sa.ID, "k", apikey.WithPermissions(map[string][]access.Action{
		"project": {"read"},
	})); err != nil {
		t.Fatalf("admin minting a restricted owner key: %v", err)
	}
	// One restricted to Full is still an owner key.
	full := map[string][]access.Action{}
	for res, acts := range scope.ControlStatements(org.ResourceOrganization) {
		full[res] = acts
	}
	full["project"] = []access.Action{"create", "read", "update", "delete"}
	if _, _, err := f.svc.CreateKey(f.ctx("admin1"), sa.ID, "k", apikey.WithPermissions(full)); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("admin minting a Full-capped owner key = %v, want ErrPrivilegeEscalation", err)
	}
	// The owner may mint it.
	if _, _, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "k"); err != nil {
		t.Fatalf("owner minting an owner key: %v", err)
	}
}

func TestCreateKeyWithPermissionsMustBeWithinTheRoleAndTheActor(t *testing.T) {
	f := newFixture(t)
	// A custom role holding project:read/update, and an account on it.
	if _, err := f.org.CreateRole(f.ctx("owner"), "editor", "Editor", map[string][]access.Action{
		"project": {"read", "update"},
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	sa := f.account("editor")

	// Within the role: fine.
	k, plain, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "ro", apikey.WithPermissions(map[string][]access.Action{
		"project": {"read"},
	}))
	if err != nil {
		t.Fatalf("CreateKey within the role: %v", err)
	}
	if string(k.Permissions) != "project:read" {
		t.Fatalf("Permissions = %q, want the encoded cap", k.Permissions)
	}
	// Outside the role: refused, even for the elevated owner — the cap
	// would mislead whoever reads it back.
	if _, _, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "k", apikey.WithPermissions(map[string][]access.Action{
		"project": {"delete"},
	})); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("cap outside the role = %v, want ErrPrivilegeEscalation", err)
	}
	// Within the role but outside the ACTOR's capped standing: refused.
	capped := scope.WithPermissionCap(f.ctx("admin1"), f.capOf(map[string][]access.Action{
		scope.ResourceServiceAccount: {scope.ActionUpdate},
		"project":                    {"read"},
	}))
	if _, _, err := f.svc.CreateKey(capped, sa.ID, "k", apikey.WithPermissions(map[string][]access.Action{
		"project": {"update"},
	})); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("cap outside the actor's cap = %v, want ErrPrivilegeEscalation", err)
	}
	if _, _, err := f.svc.CreateKey(capped, sa.ID, "k", apikey.WithPermissions(map[string][]access.Action{
		"project": {"read"},
	})); err != nil {
		t.Fatalf("cap within both: %v", err)
	}
	// An unrestricted key through the capped actor: the whole role
	// (read+update) exceeds the cap (read).
	if _, _, err := f.svc.CreateKey(capped, sa.ID, "k"); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("unrestricted key through a narrower cap = %v, want ErrPrivilegeEscalation", err)
	}
	// Argument refusals.
	if _, _, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "k", apikey.WithPermissions(map[string][]access.Action{})); !errors.Is(err, apikey.ErrEmptyPermissions) {
		t.Fatalf("empty cap = %v, want ErrEmptyPermissions", err)
	}
	if _, _, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "k", apikey.WithPermissions(map[string][]access.Action{"project": nil})); !errors.Is(err, apikey.ErrEmptyPermissions) {
		t.Fatalf("cap naming a resource with no actions = %v, want ErrEmptyPermissions", err)
	}
	if _, _, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "k", apikey.WithPermissions(map[string][]access.Action{"project": {"publish"}})); err == nil {
		t.Fatal("an undeclared grant compiled")
	}

	// And the key, once authenticated, is capped.
	p, err := f.svc.Authenticate(context.Background(), plain)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Permissions == nil || !p.Permissions.Allows("project", "read") || p.Permissions.Allows("project", "update") {
		t.Fatalf("Principal.Permissions = %+v, want project:read only", p.Permissions)
	}
	pctx := apikey.WithPrincipal(context.Background(), p)
	if !f.can(pctx, "project", "read") {
		t.Fatal("capped key cannot do what its cap and role both grant")
	}
	if f.can(pctx, "project", "update") {
		t.Fatal("capped key can do what the role grants but the cap removed")
	}
	if f.can(pctx, "project", "delete") {
		t.Fatal("capped key can do what neither grants")
	}
}

func TestCreateKeyWithExpiry(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	if _, _, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "k", apikey.WithExpiry(f.now)); !errors.Is(err, apikey.ErrInvalidExpiry) {
		t.Fatalf("expiry at now = %v, want ErrInvalidExpiry", err)
	}
	if _, _, err := f.svc.CreateKey(f.ctx("owner"), sa.ID, "k", apikey.WithExpiry(f.now.Add(-time.Second))); !errors.Is(err, apikey.ErrInvalidExpiry) {
		t.Fatalf("expiry in the past = %v, want ErrInvalidExpiry", err)
	}
	k, plain := f.key("owner", sa, apikey.WithExpiry(f.now.Add(time.Hour)))
	if k.ExpiresAt == nil || !k.ExpiresAt.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v", k.ExpiresAt)
	}
	if _, err := f.svc.Authenticate(context.Background(), plain); err != nil {
		t.Fatalf("Authenticate before expiry: %v", err)
	}
	// Valid strictly before: the instant itself is expired.
	f.now = f.now.Add(time.Hour)
	if _, err := f.svc.Authenticate(context.Background(), plain); !errors.Is(err, apikey.ErrKeyExpired) {
		t.Fatalf("Authenticate at expiry = %v, want ErrKeyExpired", err)
	}
	if last := f.events[len(f.events)-1]; last.Kind != apikey.KeyAuthenticationFailed || last.Detail != apikey.DetailKeyExpired || last.KeyID != k.ID {
		t.Fatalf("event = %+v", last)
	}
}

func TestWithKeyPrefix(t *testing.T) {
	f := newFixture(t, apikey.WithKeyPrefix("acme_"))
	sa := f.account(org.RoleMember)
	k, plain := f.key("owner", sa)
	if !strings.HasPrefix(plain, "acme_") || len(plain) != 5+43 || k.Prefix != plain[:13] {
		t.Fatalf("plain %q prefix %q", plain, k.Prefix)
	}
	if _, err := f.svc.Authenticate(context.Background(), plain); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// An empty prefix is ignored, not honoured.
	g := newFixture(t, apikey.WithKeyPrefix(""))
	_, plain2 := g.key("owner", g.account(org.RoleMember))
	if !strings.HasPrefix(plain2, "sk_") {
		t.Fatalf("empty WithKeyPrefix changed the prefix: %q", plain2)
	}
}

// ── Authenticate / WithPrincipal ─────────────────────────────────────────────

func TestAuthenticateReturnsAPrincipalTheEngineAccepts(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleAdmin)
	k, plain := f.key("owner", sa)

	f.now = f.now.Add(time.Minute)
	p, err := f.svc.Authenticate(context.Background(), plain) // no subject, no container
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Kind != apikey.KindServiceAccount || p.ID != sa.ID || p.ContainerID != f.cID || p.KeyID != k.ID ||
		p.Permissions != nil || !p.AuthenticatedAt.Equal(f.now) || p.ClientID != "" || p.GrantID != "" {
		t.Fatalf("principal = %+v", p)
	}
	// TouchKey stamped LastUsedAt.
	stored, _ := f.st.FindKey(context.Background(), k.ID)
	if stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(f.now) {
		t.Fatalf("LastUsedAt = %v, want %v", stored.LastUsedAt, f.now)
	}

	ctx := apikey.WithPrincipal(context.Background(), p)
	if sub, _ := scope.SubjectFrom(ctx); sub != sa.ID {
		t.Fatalf("subject = %q, want the account id", sub)
	}
	if c, _ := scope.ScopeFrom(ctx); c != f.cID {
		t.Fatalf("scope = %q, want the container", c)
	}
	if _, capped := scope.PermissionCapFrom(ctx); capped {
		t.Fatal("an unrestricted key must install no cap")
	}
	got, ok := apikey.PrincipalFrom(ctx)
	if !ok || got.KeyID != k.ID {
		t.Fatalf("PrincipalFrom = %+v, %v", got, ok)
	}
	if _, ok := apikey.PrincipalFrom(context.Background()); ok {
		t.Fatal("a bare context reports a principal")
	}
	// The admin-role account may create members and not delete the org.
	if !f.can(ctx, scope.ResourceMember, scope.ActionCreate) {
		t.Fatal("admin-role key cannot member:create")
	}
	if f.can(ctx, org.ResourceOrganization, org.ActionDelete) {
		t.Fatal("admin-role key can organization:delete")
	}
	if last := f.events[len(f.events)-1]; last.Kind != apikey.KeyAuthenticated || last.ActorID != sa.ID || last.KeyID != k.ID || last.Detail != "" {
		t.Fatalf("event = %+v", last)
	}
}

func TestAuthenticateRefusals(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	k, plain := f.key("owner", sa)

	if _, err := f.svc.Authenticate(context.Background(), "sk_nope"); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("unknown = %v, want ErrKeyNotFound", err)
	}
	if last := f.events[len(f.events)-1]; last.Kind != apikey.KeyAuthenticationFailed || last.Detail != apikey.DetailKeyNotFound || last.KeyID != "" {
		t.Fatalf("event = %+v", last)
	}
	if _, err := f.svc.Authenticate(context.Background(), ""); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("empty = %v, want ErrKeyNotFound", err)
	}
	// The hash, presented as a key, is not a key.
	if _, err := f.svc.Authenticate(context.Background(), k.TokenHash); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("hash-as-key = %v, want ErrKeyNotFound", err)
	}

	if err := f.svc.RevokeKey(f.ctx("admin1"), k.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := f.svc.Authenticate(context.Background(), plain); !errors.Is(err, apikey.ErrKeyRevoked) {
		t.Fatalf("revoked = %v, want ErrKeyRevoked", err)
	}
	if last := f.events[len(f.events)-1]; last.Detail != apikey.DetailKeyRevoked || last.KeyID != k.ID || last.ServiceAccountID != sa.ID {
		t.Fatalf("event = %+v", last)
	}
	// Revoked wins over disabled: the key is judged before the account.
	if err := f.svc.DisableServiceAccount(f.ctx("admin1"), sa.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := f.svc.Authenticate(context.Background(), plain); !errors.Is(err, apikey.ErrKeyRevoked) {
		t.Fatalf("revoked+disabled = %v, want ErrKeyRevoked", err)
	}
}

// A key whose account row is gone — which the Store's cascade MUST prevent —
// is refused all the same, and says so.
func TestAuthenticateRefusesAKeyWhoseAccountIsGone(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	k, plain := f.key("owner", sa)
	// Rebuild the orphan by hand: delete the account (cascade) and re-insert
	// the key row alone.
	if err := f.st.DeleteServiceAccount(context.Background(), sa.ID); err != nil {
		t.Fatalf("DeleteServiceAccount: %v", err)
	}
	if _, err := f.st.CreateServiceAccount(context.Background(), sa); err != nil {
		t.Fatalf("re-create account: %v", err)
	}
	if _, err := f.st.CreateKey(context.Background(), k); err != nil {
		t.Fatalf("re-create key: %v", err)
	}
	// Now remove just the account through a raw path the port does not
	// offer — simulate with a store double that answers not-found.
	svc := apikey.New(f.org.Service, accountless{f.st}, apikey.WithClock(f.clock))
	if _, err := svc.Authenticate(context.Background(), plain); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("orphan key = %v, want ErrServiceAccountNotFound", err)
	}
}

// accountless is a Store whose FindServiceAccount never finds anything.
type accountless struct{ apikey.Store }

func (accountless) FindServiceAccount(context.Context, string) (apikey.ServiceAccount, error) {
	return apikey.ServiceAccount{}, apikey.ErrServiceAccountNotFound
}

// touchFails is a Store whose TouchKey always fails.
type touchFails struct{ apikey.Store }

var errTouch = errors.New("touch failed")

func (touchFails) TouchKey(context.Context, string, time.Time) error { return errTouch }

// A TouchKey failure is bookkeeping, not authentication: the principal is
// returned and the event says what happened.
func TestAuthenticateSurvivesATouchFailure(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	k, plain := f.key("owner", sa)

	var events []apikey.Event
	svc := apikey.New(f.org.Service, touchFails{f.st}, apikey.WithClock(f.clock),
		apikey.WithHooks(apikey.HookFunc(func(_ context.Context, e apikey.Event) error {
			events = append(events, e)
			return nil
		})))
	p, err := svc.Authenticate(context.Background(), plain)
	if err != nil || p.KeyID != k.ID {
		t.Fatalf("Authenticate with a failing touch = %+v, %v; want the principal", p, err)
	}
	if len(events) != 1 || events[0].Kind != apikey.KeyAuthenticated || events[0].Detail != apikey.DetailTouchFailed {
		t.Fatalf("events = %+v, want one KeyAuthenticated with touch_failed", events)
	}
	stored, _ := f.st.FindKey(context.Background(), k.ID)
	if stored.LastUsedAt != nil {
		t.Fatal("LastUsedAt advanced through a failing touch")
	}
}

// A hook error on a successful authentication is returned instead of the
// principal (scope's rule); on a refusal it is joined onto the sentinel, so
// the refusal still reads as what it was.
func TestAuthenticateHookErrors(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	_, plain := f.key("owner", sa)
	errHook := errors.New("hook down")
	svc := apikey.New(f.org.Service, f.st, apikey.WithClock(f.clock),
		apikey.WithHooks(apikey.HookFunc(func(context.Context, apikey.Event) error { return errHook })))

	if p, err := svc.Authenticate(context.Background(), plain); !errors.Is(err, errHook) || p.ID != "" {
		t.Fatalf("hook error on success = %+v, %v; want the hook's error and no principal", p, err)
	}
	_, err := svc.Authenticate(context.Background(), "sk_nope")
	if !errors.Is(err, apikey.ErrKeyNotFound) || !errors.Is(err, errHook) {
		t.Fatalf("hook error on refusal = %v; want both ErrKeyNotFound and the hook's error", err)
	}
}

// ── RevokeKey / ListKeys / PurgeExpired ──────────────────────────────────────

func TestRevokeKeyScopesAndIsIdempotent(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	k, _ := f.key("owner", sa)

	if err := f.svc.RevokeKey(f.ctx("member1"), k.ID); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member revoking = %v, want ErrForbidden", err)
	}
	other, _ := f.org.CreateOrganization(scope.WithSubject(context.Background(), "zed"), "Globex", "globex")
	zed := org.WithOrg(org.WithSubject(context.Background(), "zed"), other.ID)
	if err := f.svc.RevokeKey(zed, k.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("cross-tenant revoke = %v, want ErrKeyNotFound", err)
	}
	if err := f.svc.RevokeKey(f.ctx("admin1"), "nope"); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("unknown key = %v, want ErrKeyNotFound", err)
	}
	if err := f.svc.RevokeKey(f.ctx("admin1"), k.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	stored, _ := f.st.FindKey(context.Background(), k.ID)
	if stored.RevokedAt == nil || !stored.RevokedAt.Equal(f.now) {
		t.Fatalf("RevokedAt = %v", stored.RevokedAt)
	}
	if err := f.svc.RevokeKey(f.ctx("admin1"), k.ID); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if last := f.events[len(f.events)-1]; last.Kind != apikey.KeyRevoked || last.KeyID != k.ID || last.ServiceAccountID != sa.ID {
		t.Fatalf("event = %+v", last)
	}
}

func TestListKeysReturnsRevokedAndExpiredToo(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	live, _ := f.key("owner", sa)
	revoked, _ := f.key("owner", sa)
	if err := f.svc.RevokeKey(f.ctx("owner"), revoked.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := f.svc.ListKeys(f.ctx("member1"), sa.ID); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("member listing keys = %v, want ErrForbidden", err)
	}
	keys, err := f.svc.ListKeys(f.ctx("admin1"), sa.ID)
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListKeys = %d keys, %v; want 2", len(keys), err)
	}
	for _, k := range keys {
		if k.ID != live.ID && k.ID != revoked.ID {
			t.Fatalf("unexpected key %+v", k)
		}
	}
}

func TestPurgeExpiredRemovesExpiredAndRevokedKeys(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	live, _ := f.key("owner", sa)
	expiring, _ := f.key("owner", sa, apikey.WithExpiry(f.now.Add(time.Hour)))
	revoked, _ := f.key("owner", sa)
	if err := f.svc.RevokeKey(f.ctx("owner"), revoked.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	n, err := f.svc.PurgeExpired(context.Background(), f.now.Add(2*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("PurgeExpired = %d, %v; want 2", n, err)
	}
	if _, err := f.st.FindKey(context.Background(), live.ID); err != nil {
		t.Fatalf("the live key was purged: %v", err)
	}
	for _, id := range []string{expiring.ID, revoked.ID} {
		if _, err := f.st.FindKey(context.Background(), id); !errors.Is(err, apikey.ErrKeyNotFound) {
			t.Fatalf("key %s survived the purge: %v", id, err)
		}
	}
	if _, err := f.st.FindServiceAccount(context.Background(), sa.ID); err != nil {
		t.Fatalf("PurgeExpired touched the account: %v", err)
	}
}

func TestEventOrderAcrossALifecycle(t *testing.T) {
	f := newFixture(t)
	sa := f.account(org.RoleMember)
	k, plain := f.key("owner", sa)
	if _, err := f.svc.Authenticate(context.Background(), plain); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := f.svc.RevokeKey(f.ctx("owner"), k.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := f.svc.Authenticate(context.Background(), plain); !errors.Is(err, apikey.ErrKeyRevoked) {
		t.Fatalf("Authenticate revoked = %v", err)
	}
	if err := f.svc.DeleteServiceAccount(f.ctx("owner"), sa.ID); err != nil {
		t.Fatalf("DeleteServiceAccount: %v", err)
	}
	want := []apikey.EventKind{
		apikey.ServiceAccountCreated, apikey.KeyCreated, apikey.KeyAuthenticated,
		apikey.KeyRevoked, apikey.KeyAuthenticationFailed, apikey.ServiceAccountDeleted,
	}
	got := f.kinds()
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
}
