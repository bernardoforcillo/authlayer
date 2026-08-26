package team_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
	"github.com/bernardoforcillo/authlayer/team"
)

// newOrgService builds an organization Service whose Access already declares
// team.ParentStatements(), so a team can be created by anyone the organization
// grants team:create to, not only its owner.
func newOrgService() *org.Service {
	ac := org.NewAccess(team.ParentStatements())
	return org.New(ac, memory.New[org.Organization, org.Member]())
}

// newTeamService builds a team Service nested under orgSvc.
func newTeamService(orgSvc *org.Service) *team.Service {
	return team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc)
}

// createOrg creates an organization owned by ownerID and returns it alongside
// a subject-only context for that owner (no active scope yet).
func createOrg(t *testing.T, orgSvc *org.Service, ownerID string) (org.Organization, context.Context) {
	t.Helper()
	ctx := org.WithSubject(context.Background(), ownerID)
	o, err := orgSvc.CreateOrganization(ctx, "Acme", "acme-"+ownerID)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	return o, ctx
}

// ---------------------------------------------------------------------------
// 1. Creating a team stamps the parent from the context and seeds the owner.
// ---------------------------------------------------------------------------

func TestCreateTeamStampsParentAndSeedsOwner(t *testing.T) {
	orgSvc := newOrgService()
	teamSvc := newTeamService(orgSvc)

	acme, _ := createOrg(t, orgSvc, "alice")

	// CreateTeam reads the ORGANIZATION off the context (org.WithOrg), not a
	// team — there is no team yet.
	createCtx := org.WithOrg(org.WithSubject(context.Background(), "alice"), acme.ID)
	platform, err := teamSvc.CreateTeam(createCtx, "Platform")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if platform.Name != "Platform" {
		t.Fatalf("Name = %q, want %q", platform.Name, "Platform")
	}
	if platform.ID == "" {
		t.Fatal("CreateTeam did not stamp an id")
	}
	if platform.ContainerParent() != acme.ID {
		t.Fatalf("ParentID = %q, want the organization on the context (%q)", platform.ContainerParent(), acme.ID)
	}
	if platform.ContainerOwner() != "alice" {
		t.Fatalf("OwnerID = %q, want the ctx subject %q", platform.ContainerOwner(), "alice")
	}

	// The owner was seeded as a team member with the owner role. Switch the
	// context's active scope from the organization to the team to check it.
	teamCtx := team.WithTeam(org.WithSubject(context.Background(), "alice"), platform.ID)
	members, err := teamSvc.ListMembers(teamCtx)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("len(members) = %d, want 1", len(members))
	}
	if got := members[0]; got.MemberUser() != "alice" || got.MemberRole() != team.RoleOwner {
		t.Fatalf("seeded member = (%q, %q), want (\"alice\", %q)", got.MemberUser(), got.MemberRole(), team.RoleOwner)
	}
}

// ---------------------------------------------------------------------------
// 2. An org admin administers a team without joining it.
// ---------------------------------------------------------------------------

// team.New's default projection ([scope.InheritElevation]) carries over only
// truly elevated (Full-permission / owner) parent standing — org's built-in
// admin role is deliberately kept short of Full (it excludes
// organization:delete) so the escalation guard still applies to it, which
// means a plain admin is NOT elevated in the parent and gets nothing from
// InheritElevation. Letting an admin administer every team is an explicit
// choice an application opts into with [scope.InheritWhen], passed as a
// New option that overrides the default — exactly the override opts exist
// for. The organization here declares team:update alongside
// [team.ParentStatements]'s team:create, so its admin role (every declared
// pair except organization:delete) picks it up automatically.
func TestOrgAdminAdministersTeamWithoutJoining(t *testing.T) {
	statements := team.ParentStatements()
	statements[team.ResourceTeam] = append(statements[team.ResourceTeam], team.ActionUpdate)
	orgSvc := org.New(org.NewAccess(statements), memory.New[org.Organization, org.Member]())
	teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc,
		scope.WithParent(orgSvc, scope.InheritWhen(team.ResourceTeam, team.ActionUpdate)))

	acme, orgCtx := createOrg(t, orgSvc, "alice")
	orgCtx = org.WithOrg(orgCtx, acme.ID)
	if _, err := orgSvc.AddMember(orgCtx, "bob", org.RoleAdmin); err != nil {
		t.Fatalf("seed org admin: %v", err)
	}

	createCtx := org.WithOrg(org.WithSubject(context.Background(), "alice"), acme.ID)
	platform, err := teamSvc.CreateTeam(createCtx, "Platform")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	bobCtx := team.WithTeam(org.WithSubject(context.Background(), "bob"), platform.ID)

	// bob holds no membership in the team at all.
	members, err := teamSvc.ListMembers(bobCtx)
	if err != nil {
		t.Fatalf("bob (org admin) could not list the team roster: %v", err)
	}
	for _, m := range members {
		if m.MemberUser() == "bob" {
			t.Fatal("fixture: bob already has a team membership")
		}
	}

	// Yet he administers it: elevated standing passes an arbitrary team check.
	if err := teamSvc.Authorize(bobCtx, team.ResourceTeam, team.ActionDelete); err != nil {
		t.Fatalf("org admin's inherited elevation did not pass team:delete: %v", err)
	}
	if ok, err := teamSvc.Can(bobCtx, team.ResourceMember, team.ActionCreate); err != nil || !ok {
		t.Fatalf("org admin member:create = %v,%v; want true,nil", ok, err)
	}

	_, elevated, err := teamSvc.Standing(context.Background(), platform.ID, "bob")
	if err != nil {
		t.Fatalf("Standing: %v", err)
	}
	if !elevated {
		t.Fatal("an org admin holding team:update is not elevated in the team")
	}
}

// ---------------------------------------------------------------------------
// 3. A team member who is not an org member is refused under
// Policy.MembersFromParent.
// ---------------------------------------------------------------------------

func TestAddMemberRefusesNonOrgMember(t *testing.T) {
	orgSvc := newOrgService()
	teamSvc := newTeamService(orgSvc)

	acme, orgCtx := createOrg(t, orgSvc, "alice")
	orgCtx = org.WithOrg(orgCtx, acme.ID)
	if _, err := orgSvc.AddMember(orgCtx, "bob", org.RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}

	createCtx := org.WithOrg(org.WithSubject(context.Background(), "alice"), acme.ID)
	platform, err := teamSvc.CreateTeam(createCtx, "Platform")
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	teamCtx := team.WithTeam(org.WithSubject(context.Background(), "alice"), platform.ID)

	// bob belongs to the organization, so he may join the team.
	if _, err := teamSvc.AddMember(teamCtx, "bob", team.RoleMember); err != nil {
		t.Fatalf("adding an organization member to the team: %v", err)
	}

	// zoe belongs to neither: refused under MembersFromParent, not silently
	// admitted.
	if _, err := teamSvc.AddMember(teamCtx, "zoe", team.RoleMember); !errors.Is(err, team.ErrNotParentMember) {
		t.Fatalf("err = %v, want ErrNotParentMember", err)
	}

	// The refusal is a refusal, not a partial write: zoe never made it into
	// the roster.
	members, err := teamSvc.ListMembers(teamCtx)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	for _, m := range members {
		if m.MemberUser() == "zoe" {
			t.Fatal("zoe was written to the team despite not being an organization member")
		}
	}
}

// ---------------------------------------------------------------------------
// 4. ParentStatements merged into org.NewAccess makes CreateTeam pass its
// parent-side permission check; an org member lacking team:create is refused.
// ---------------------------------------------------------------------------

func TestParentStatementsGateCreateTeam(t *testing.T) {
	// org.NewAccess merges team.ParentStatements(), so admin (which is granted
	// every declared pair) picks up team:create automatically.
	ac := org.NewAccess(team.ParentStatements())
	orgSvc := org.New(ac, memory.New[org.Organization, org.Member]())
	teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc)

	acme, orgCtx := createOrg(t, orgSvc, "alice")
	orgCtx = org.WithOrg(orgCtx, acme.ID)
	if _, err := orgSvc.AddMember(orgCtx, "bob", org.RoleAdmin); err != nil {
		t.Fatalf("seed org admin: %v", err)
	}
	if _, err := orgSvc.AddMember(orgCtx, "carol", org.RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}

	// bob holds team:create via the admin role, which the merged statements
	// made possible.
	bobCtx := org.WithOrg(org.WithSubject(context.Background(), "bob"), acme.ID)
	if _, err := teamSvc.CreateTeam(bobCtx, "Infra"); err != nil {
		t.Fatalf("org admin creating a team (parent-side check): %v", err)
	}

	// carol is a plain member: RoleMember grants nothing, so she has standing
	// but not the grant.
	carolCtx := org.WithOrg(org.WithSubject(context.Background(), "carol"), acme.ID)
	if _, err := teamSvc.CreateTeam(carolCtx, "Nope"); !errors.Is(err, team.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// TestCreateTeamWithoutParentStatementsRequiresElevatedActor documents the
// failure mode ParentStatements exists to prevent: an application that builds
// org.NewAccess WITHOUT merging team.ParentStatements() can still have its
// owner create teams (ownership always bypasses), but every other actor,
// admin included, is refused with no indication why — team:create was never a
// grantable permission on the organization's surface at all.
func TestCreateTeamWithoutParentStatementsRequiresElevatedActor(t *testing.T) {
	ac := org.NewAccess(nil) // ParentStatements() not merged in.
	orgSvc := org.New(ac, memory.New[org.Organization, org.Member]())
	teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc)

	acme, orgCtx := createOrg(t, orgSvc, "alice")
	orgCtx = org.WithOrg(orgCtx, acme.ID)
	if _, err := orgSvc.AddMember(orgCtx, "bob", org.RoleAdmin); err != nil {
		t.Fatalf("seed org admin: %v", err)
	}

	// The owner is unaffected: ownership bypasses the permission check.
	ownerCtx := org.WithOrg(org.WithSubject(context.Background(), "alice"), acme.ID)
	if _, err := teamSvc.CreateTeam(ownerCtx, "Owner Team"); err != nil {
		t.Fatalf("owner creating a team: %v", err)
	}

	// bob is an org admin, ordinarily entitled to run the whole org's
	// resources — but team:create was never declared, so even NewAccess's
	// admin role (every declared pair) does not carry it, and he is refused
	// exactly like anyone else. This is the silent failure ParentStatements
	// exists to make loud in application code: a caller who forgets to merge
	// it does not get a startup panic, they get every admin denied.
	bobCtx := org.WithOrg(org.WithSubject(context.Background(), "bob"), acme.ID)
	if _, err := teamSvc.CreateTeam(bobCtx, "Nope"); !errors.Is(err, team.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// Compile-time sanity: Team satisfies Nested — the whole point of embedding
// scope.NestedBase instead of scope.ContainerBase — and Member satisfies the
// plain scope.Member contract the store needs.
var (
	_ scope.Container = team.Team{}
	_ scope.Nested    = team.Team{}
	_ scope.Member    = team.Member{}
)
