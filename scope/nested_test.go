package scope

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bernardoforcillo/authlayer/access"
)

func TestInheritElevationPassesElevationThroughOnly(t *testing.T) {
	grants, elevated := InheritElevation(access.Permission{}, true)
	if !elevated {
		t.Fatal("an elevated parent standing did not confer elevation")
	}
	if len(grants) != 0 {
		t.Fatalf("InheritElevation invented grants: %v", grants)
	}

	if _, elevated := InheritElevation(access.Permission{}, false); elevated {
		t.Fatal("a non-elevated parent standing conferred elevation")
	}
}

func TestInheritWhenConfersElevationOnlyForTheNamedGrant(t *testing.T) {
	ac := access.New(access.NewStatements(map[string][]access.Action{
		"team": {"create", "update"},
	}))
	manager, err := ac.Permission(map[string][]access.Action{"team": {"update"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	bystander, err := ac.Permission(map[string][]access.Action{"team": {"create"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	inherit := InheritWhen("team", "update")

	if _, elevated := inherit(manager, false); !elevated {
		t.Fatal("holder of team:update was not elevated in the child")
	}
	if _, elevated := inherit(bystander, false); elevated {
		t.Fatal("holder of only team:create was elevated in the child")
	}
	// An already-elevated parent standing still carries through.
	if _, elevated := inherit(bystander, true); !elevated {
		t.Fatal("an elevated parent standing lost its elevation")
	}
}

func TestWithParentStoresBothHalves(t *testing.T) {
	c := defaultConfig()
	if c.parent != nil || c.inherit != nil {
		t.Fatal("a plain config already has a parent configured")
	}
	var p ParentScope = (*Service[testContainer, testMember, *testContainer, *testMember])(nil)
	WithParent(p, InheritElevation)(&c)
	if c.parent == nil || c.inherit == nil {
		t.Fatal("WithParent did not store both the parent and the projection")
	}
}

// A nil Inheritance must not silently mean "inherit nothing" — that would make
// a mis-wired parent look like a working one that never grants.
func TestWithParentDefaultsANilInheritance(t *testing.T) {
	c := defaultConfig()
	var p ParentScope = (*Service[testContainer, testMember, *testContainer, *testMember])(nil)
	WithParent(p, nil)(&c)
	if c.inherit == nil {
		t.Fatal("a nil Inheritance was stored as nil rather than defaulted")
	}
	if _, elevated := c.inherit(access.Permission{}, true); !elevated {
		t.Fatal("the defaulted Inheritance is not InheritElevation")
	}
}

// ---------------------------------------------------------------------------
// The two-scope fixture.
//
// A parent "organization" Service over testContainer/testMember, and a child
// "team" Service over the nested types below. The two Access surfaces overlap
// only in the names they both declare: the parent declares team:create and
// team:update (what a real application merges in so teams can be created and
// administered from the organization), while the child declares doc:read and
// doc:write, which the parent has never heard of. Nothing but names crosses.
// ---------------------------------------------------------------------------

const (
	resTeam = "team"
	resDoc  = "doc"
)

const (
	actionRead  access.Action = "read"
	actionWrite access.Action = "write"
)

type nestedContainer struct {
	NestedBase
	Name string
}

type nestedMember struct {
	MemberBase
}

// Compile-time proof the child types satisfy what the engine type-asserts for.
var (
	_ Container        = nestedContainer{}
	_ Nested           = nestedContainer{}
	_ MutableContainer = (*nestedContainer)(nil)
	_ Member           = nestedMember{}
	_ MutableMember    = (*nestedMember)(nil)
)

type (
	parentService = Service[testContainer, testMember, *testContainer, *testMember]
	childService  = Service[nestedContainer, nestedMember, *nestedContainer, *nestedMember]
	childStore    = memStore[nestedContainer, nestedMember, *nestedContainer, *nestedMember]
)

// newParentScope builds the parent organization Service. Its statements carry
// team:create and team:update on top of the control surface — the declaration
// team.ParentStatements will exist to make explicit.
func newParentScope() *parentService {
	ac := NewAccess(resOrg, map[string][]access.Action{
		resTeam: {ActionCreate, ActionUpdate},
	})
	return New(ac, newMemStore[testContainer, testMember]())
}

// newChildScopeOn builds a team Service nested under parent over an existing
// store, so two differently-configured services can look at the same rows.
func newChildScopeOn(st *childStore, parent ParentScope, inherit Inheritance, opts ...Option) *childService {
	ac := NewAccess(resTeam, map[string][]access.Action{
		resDoc: {actionRead, actionWrite},
	})
	base := []Option{WithParent(parent, inherit), WithContainerResource(resTeam)}
	return New(ac, st, append(base, opts...)...)
}

// newChildScope builds a team Service over a fresh store and returns both.
func newChildScope(parent ParentScope, inherit Inheritance, opts ...Option) (*childService, *childStore) {
	st := newMemStore[nestedContainer, nestedMember]()
	return newChildScopeOn(st, parent, inherit, opts...), st
}

// actorCtx builds a request context for userID acting in containerID.
func actorCtx(userID, containerID string) context.Context {
	return WithScope(WithSubject(context.Background(), userID), containerID)
}

// createTeam creates a team inside orgID through the child Service, which is
// the parented CreateContainer path: the creator needs team:create in the
// organization, and the new container's ParentID is stamped from the context.
func createTeam(t *testing.T, child *childService, orgID, creator string) nestedContainer {
	t.Helper()
	team, err := child.CreateContainer(actorCtx(creator, orgID), nestedContainer{Name: "Platform"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	return team
}

// seedTeamRow writes a team straight to the store, bypassing the engine. Some
// fixtures need shapes the engine will not produce: a team with no parent link,
// or one whose organization row is gone.
func seedTeamRow(t *testing.T, st *childStore, id, parentID, ownerID string) {
	t.Helper()
	var c nestedContainer
	c.SetID(id)
	c.SetOwner(ownerID)
	c.SetParent(parentID)
	if _, err := st.CreateContainer(context.Background(), c); err != nil {
		t.Fatalf("seed team %q: %v", id, err)
	}
}

// seedMemberRow writes a membership straight to the store, bypassing AddMember
// and therefore the MembersFromParent invariant — for fixtures that need a team
// member who never joined the organization.
func seedMemberRow(t *testing.T, st *childStore, containerID, userID, roleKey string) {
	t.Helper()
	var m nestedMember
	m.SetKeys(containerID, userID, roleKey)
	if _, err := st.AddMember(context.Background(), m); err != nil {
		t.Fatalf("seed member %q: %v", userID, err)
	}
}

// errParentDown stands for a parent that could not answer — a store outage,
// not a verdict.
var errParentDown = errors.New("scope_test: parent store is down")

// parentStub is a ParentScope double answering with a fixed standing or a fixed
// error, counting every consultation so a test can prove the parent rung was —
// or was not — reached. A real parent Service cannot prove that negative: it
// answers ErrContainerNotFound for an empty id, which the rung swallows.
type parentStub struct {
	perms    access.Permission
	elevated bool
	err      error
	calls    int
}

// Standing records the consultation and returns the configured answer.
func (p *parentStub) Standing(_ context.Context, _, _ string) (access.Permission, bool, error) {
	p.calls++
	if p.err != nil {
		return access.Permission{}, false, p.err
	}
	return p.perms, p.elevated, nil
}

// ---------------------------------------------------------------------------
// The parent rung in standing().
// ---------------------------------------------------------------------------

// An org admin administers a team they never joined — the point of nesting.
func TestNestedInheritedElevationWithoutMembership(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("seed org admin: %v", err)
	}
	if _, err := parent.AddMember(octx, "carol", RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}

	child, st := newChildScope(parent, InheritWhen(resTeam, ActionUpdate))
	team := createTeam(t, child, orgC.ContainerID(), "alice")

	// bob holds no membership in the team at all.
	if _, err := st.FindMember(context.Background(), team.ContainerID(), "bob"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("fixture: bob already has a team membership (%v)", err)
	}

	perms, elevated, err := child.Standing(context.Background(), team.ContainerID(), "bob")
	if err != nil {
		t.Fatalf("Standing: %v", err)
	}
	if !elevated {
		t.Fatal("an org admin holding team:update is not elevated in the team")
	}
	if !perms.IsFull() && perms.Allows(resDoc, actionRead) {
		t.Fatal("elevation arrived as invented grants rather than as elevation")
	}

	bob := actorCtx("bob", team.ContainerID())
	if err := child.Authorize(bob, resTeam, ActionDelete); err != nil {
		t.Fatalf("inherited elevation did not pass team:delete: %v", err)
	}
	if ok, err := child.Can(bob, resDoc, actionWrite); err != nil || !ok {
		t.Fatalf("doc:write = %v,%v; want true,nil", ok, err)
	}
	if _, err := child.ListMembers(bob); err != nil {
		t.Fatalf("an elevated non-member could not list the roster: %v", err)
	}

	// Inheritance is selective: a plain organization member holds no
	// team:update, so the projection confers nothing and carol has no standing.
	if _, _, err := child.Standing(context.Background(), team.ContainerID(), "carol"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("plain org member's standing = %v, want ErrNotMember", err)
	}
}

// Without a parent configured, the same setup denies: nesting is opt-in.
func TestNestedWithoutWithParentDeniesTheSameActor(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("seed org admin: %v", err)
	}

	child, st := newChildScope(parent, InheritWhen(resTeam, ActionUpdate))
	team := createTeam(t, child, orgC.ContainerID(), "alice")
	bob := actorCtx("bob", team.ContainerID())
	if err := child.Authorize(bob, resDoc, actionWrite); err != nil {
		t.Fatalf("precondition: the nested service must admit bob: %v", err)
	}

	// The same rows, the same actor, the same container — only WithParent is
	// gone. This is the existing un-nested behaviour, and it must not have
	// widened by a single grant.
	unparented := New(NewAccess(resTeam, map[string][]access.Action{
		resDoc: {actionRead, actionWrite},
	}), st)
	if err := unparented.Authorize(bob, resDoc, actionWrite); !errors.Is(err, ErrNotMember) {
		t.Fatalf("err = %v, want ErrNotMember: nesting must be opt-in", err)
	}
	if _, err := unparented.ListMembers(bob); !errors.Is(err, ErrNotMember) {
		t.Fatalf("ListMembers = %v, want ErrNotMember", err)
	}
}

// A child member's own role and the projected grants merge.
func TestNestedMemberPermissionsUnionWithInheritedGrants(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "carol", RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}

	// Standing in the organization confers doc:write in the team, and no
	// elevation — so what carol ends up with is a genuine merge of two halves.
	inherit := func(_ access.Permission, _ bool) (map[string][]access.Action, bool) {
		return map[string][]access.Action{resDoc: {actionWrite}}, false
	}
	child, _ := newChildScope(parent, inherit)
	team := createTeam(t, child, orgC.ContainerID(), "alice")

	tctx := actorCtx("alice", team.ContainerID())
	if _, err := child.CreateRole(tctx, "reader", "Reader", map[string][]access.Action{
		resDoc: {actionRead},
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if _, err := child.AddMember(tctx, "carol", "reader"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	carol := actorCtx("carol", team.ContainerID())
	if ok, err := child.Can(carol, resDoc, actionRead); err != nil || !ok {
		t.Fatalf("own role's doc:read = %v,%v; want true,nil", ok, err)
	}
	if ok, err := child.Can(carol, resDoc, actionWrite); err != nil || !ok {
		t.Fatalf("inherited doc:write = %v,%v; want true,nil", ok, err)
	}
	// Both at once: the union, not whichever half happened to win.
	if ok, err := child.Can(carol, resDoc, actionRead, actionWrite); err != nil || !ok {
		t.Fatalf("union of both = %v,%v; want true,nil", ok, err)
	}

	perms, elevated, err := child.Standing(context.Background(), team.ContainerID(), "carol")
	if err != nil {
		t.Fatalf("Standing: %v", err)
	}
	if elevated {
		t.Fatal("a merged, non-full permission set made the member elevated")
	}
	if perms.IsFull() {
		t.Fatal("the union produced a full permission set from two partial ones")
	}
	if perms.Allows(ResourceMember, ActionCreate) {
		t.Fatal("the union invented a grant neither side held")
	}
	if err := child.Authorize(carol, ResourceMember, ActionDelete); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ungranted member:delete = %v, want ErrForbidden", err)
	}
}

// A stranger to both scopes is still ErrNotMember.
func TestNestedStrangerIsNotMember(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "carol", RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}

	child, _ := newChildScope(parent, InheritElevation)
	team := createTeam(t, child, orgC.ContainerID(), "alice")

	// The identity of the error is what matters here, not merely the denial:
	// Can folds ErrForbidden and ErrNotMember into the same false, so a
	// resolution that wrongly *succeeded* on an empty inherited standing would
	// still look like a denial there. ErrNotMember is what proves no standing
	// was resolved at all.
	for _, u := range []struct{ id, who string }{
		{"zoe", "a stranger to both scopes"},
		{"carol", "an org member the projection grants nothing"},
	} {
		ctx := actorCtx(u.id, team.ContainerID())
		if err := child.Authorize(ctx, resDoc, actionRead); !errors.Is(err, ErrNotMember) {
			t.Fatalf("Authorize for %s = %v, want ErrNotMember", u.who, err)
		}
		if _, err := child.ListMembers(ctx); !errors.Is(err, ErrNotMember) {
			t.Fatalf("%s listed the team roster: %v", u.who, err)
		}
		if _, _, err := child.Standing(context.Background(), team.ContainerID(), u.id); !errors.Is(err, ErrNotMember) {
			t.Fatalf("Standing for %s = %v, want ErrNotMember", u.who, err)
		}
		if ok, err := child.HasPermission(context.Background(), team.ContainerID(), u.id, map[string][]access.Action{
			resDoc: {actionRead},
		}); ok || err != nil {
			t.Fatalf("HasPermission for %s = %v,%v; want false,nil", u.who, ok, err)
		}
	}
}

// A projection may name a resource and confer nothing on it. {resDoc: nil} is
// a map of length one that grants nothing, so a hinge testing the map's SHAPE
// admits a subject with no membership, while one testing what was actually
// CONFERRED turns them away.
//
// The consequence is concrete rather than theoretical: ListMembers admits
// anyone standing() does not reject, so a resolved-but-empty standing hands a
// stranger the container's roster and breaks that method's documented non-leak
// property. Reachable only through a custom Inheritance — InheritElevation and
// InheritWhen never return grants — but that is a documented extension point.
func TestNestedEmptyProjectedGrantConfersNoStanding(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "carol", RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}

	// resDoc is a resource the child DOES declare, so the grants compile
	// cleanly and raise no error: the conferral test is the only thing between
	// carol and standing she never earned.
	inherit := func(_ access.Permission, _ bool) (map[string][]access.Action, bool) {
		return map[string][]access.Action{resDoc: nil}, false
	}
	child, _ := newChildScope(parent, inherit)
	team := createTeam(t, child, orgC.ContainerID(), "alice")

	if _, _, err := child.Standing(context.Background(), team.ContainerID(), "carol"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("Standing = %v, want ErrNotMember", err)
	}
	carol := actorCtx("carol", team.ContainerID())
	if _, err := child.ListMembers(carol); !errors.Is(err, ErrNotMember) {
		t.Fatalf("ListMembers = %v, want ErrNotMember: the roster leaked", err)
	}
	// An empty request must not become a free "yes" either.
	if ok, err := child.HasPermission(context.Background(), team.ContainerID(), "carol", nil); ok || err != nil {
		t.Fatalf("HasPermission = %v,%v; want false,nil", ok, err)
	}
	if err := child.Authorize(carol, resDoc, actionRead); !errors.Is(err, ErrNotMember) {
		t.Fatalf("Authorize = %v, want ErrNotMember", err)
	}
}

// A parent lookup that finds nothing contributes nothing and does not fail.
func TestNestedParentNotMemberIsNotFatal(t *testing.T) {
	parent := newParentScope()
	_, orgC := ownerCtx(t, parent, "alice")
	child, st := newChildScope(parent, InheritElevation)
	team := createTeam(t, child, orgC.ContainerID(), "alice")

	// quinn holds a team membership but never joined the organization, so the
	// parent answers ErrNotMember. That is an answer, not a failure.
	seedMemberRow(t, st, team.ContainerID(), "quinn", RoleAdmin)
	quinn := actorCtx("quinn", team.ContainerID())
	if ok, err := child.Can(quinn, ResourceMember, ActionCreate); err != nil || !ok {
		t.Fatalf("member:create = %v,%v; want true,nil", ok, err)
	}

	// A team whose organization row is gone resolves the same way.
	seedTeamRow(t, st, "orphan", "ghost-org", "nobody")
	seedMemberRow(t, st, "orphan", "quinn", RoleAdmin)
	orphan := actorCtx("quinn", "orphan")
	if ok, err := child.Can(orphan, ResourceMember, ActionCreate); err != nil || !ok {
		t.Fatalf("orphaned team member:create = %v,%v; want true,nil", ok, err)
	}
	// Neither lookup conferred anything of its own: quinn's admin role stops
	// short of the container itself, and nothing topped it up.
	if ok, err := child.Can(quinn, resTeam, ActionDelete); err != nil || ok {
		t.Fatalf("team:delete = %v,%v; want false,nil", ok, err)
	}
}

// A parent lookup that fails for a real reason DOES fail the call — a store
// outage must not silently become "no inherited standing", which would look
// like a permission change.
func TestNestedParentStoreErrorPropagates(t *testing.T) {
	stub := &parentStub{err: errParentDown}
	child, st := newChildScope(stub, InheritElevation)
	seedTeamRow(t, st, "t1", "acme", "alice")
	seedMemberRow(t, st, "t1", "bob", RoleAdmin)

	bob := actorCtx("bob", "t1")
	// bob's own admin role grants member:create outright, so a swallowed parent
	// error shows up as a silent success rather than as a denial.
	if err := child.Authorize(bob, ResourceMember, ActionCreate); !errors.Is(err, errParentDown) {
		t.Fatalf("Authorize = %v, want the parent's error", err)
	}
	// Can must not fold it into a plain false either: a question that could not
	// be answered is not a denial.
	if ok, err := child.Can(bob, ResourceMember, ActionCreate); ok || !errors.Is(err, errParentDown) {
		t.Fatalf("Can = %v,%v; want false and the parent's error", ok, err)
	}
	if _, _, err := child.Standing(context.Background(), "t1", "bob"); !errors.Is(err, errParentDown) {
		t.Fatalf("Standing = %v, want the parent's error", err)
	}
	if stub.calls == 0 {
		t.Fatal("the parent was never consulted")
	}
}

// A container with an empty ParentID resolves without consulting the parent.
func TestNestedEmptyParentIDSkipsTheParentRung(t *testing.T) {
	// A poisoned parent: any consultation at all turns into a failed call, so
	// the rung being skipped is observable rather than merely plausible. A real
	// parent Service would answer ErrContainerNotFound for the empty id, which
	// the rung swallows — and the skip would be invisible.
	stub := &parentStub{err: errParentDown}
	child, st := newChildScope(stub, InheritElevation)
	seedTeamRow(t, st, "t1", "", "alice")
	seedMemberRow(t, st, "t1", "bob", RoleAdmin)

	bob := actorCtx("bob", "t1")
	if err := child.Authorize(bob, ResourceMember, ActionCreate); err != nil {
		t.Fatalf("a container with no parent link must resolve on its own: %v", err)
	}
	if stub.calls != 0 {
		t.Fatalf("the parent was consulted %d times for a container with an empty ParentID", stub.calls)
	}
}

// Under MembersFromParent, a child member must already belong to the parent.
func TestAddMemberRequiresParentMembership(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("seed org admin: %v", err)
	}

	child, st := newChildScope(parent, InheritElevation)
	team := createTeam(t, child, orgC.ContainerID(), "alice")
	tctx := actorCtx("alice", team.ContainerID())

	if _, err := child.AddMember(tctx, "bob", RoleMember); err != nil {
		t.Fatalf("adding an organization member to the team: %v", err)
	}
	if _, err := child.AddMember(tctx, "zoe", RoleMember); !errors.Is(err, ErrNotParentMember) {
		t.Fatalf("err = %v, want ErrNotParentMember", err)
	}
	// The refusal is a refusal, not a partial write.
	if _, err := st.FindMember(context.Background(), team.ContainerID(), "zoe"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("zoe was written to the team anyway: %v", err)
	}

	// The flag is read rather than hardcoded: clearing it lifts the
	// requirement over the very same rows.
	policy := defaultPolicy()
	policy.MembersFromParent = false
	open := newChildScopeOn(st, parent, InheritElevation, WithPolicy(policy))
	if _, err := open.AddMember(tctx, "zoe", RoleMember); err != nil {
		t.Fatalf("with MembersFromParent cleared, zoe should join: %v", err)
	}
}

// New panics when a parent is configured for a container with no parent link.
func TestNewPanicsWhenParentConfiguredOnANonNestedContainer(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("New accepted a parent for a container type carrying no parent link")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "NestedBase") {
			t.Fatalf("panic = %v; want a message naming NestedBase", r)
		}
	}()
	// testContainer embeds ContainerBase, not NestedBase, so it can never carry
	// a parent: nesting it is a wiring bug and must fail loudly at startup.
	New(NewAccess(resOrg, nil), newMemStore[testContainer, testMember](),
		WithParent(newParentScope(), InheritElevation))
}

// CreateContainer on a parented service is the one place the engine checks a
// permission on create, and the one place ParentID is stamped.
func TestNestedCreateContainerChecksTheParentAndStampsTheLink(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("seed org admin: %v", err)
	}
	if _, err := parent.AddMember(octx, "carol", RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}
	child, _ := newChildScope(parent, InheritElevation)

	team := createTeam(t, child, orgC.ContainerID(), "alice")
	if team.ContainerParent() != orgC.ContainerID() {
		t.Fatalf("ParentID = %q, want the organization on the context (%q)",
			team.ContainerParent(), orgC.ContainerID())
	}
	// An organization admin holds team:create and may create one too.
	if _, err := child.CreateContainer(actorCtx("bob", orgC.ContainerID()), nestedContainer{Name: "Infra"}); err != nil {
		t.Fatalf("org admin creating a team: %v", err)
	}
	// A plain organization member does not.
	if _, err := child.CreateContainer(actorCtx("carol", orgC.ContainerID()), nestedContainer{Name: "Nope"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	// Nor does a stranger to the organization.
	if _, err := child.CreateContainer(actorCtx("zoe", orgC.ContainerID()), nestedContainer{Name: "Nope"}); !errors.Is(err, ErrNotMember) {
		t.Fatalf("err = %v, want ErrNotMember", err)
	}
	// And with no organization on the context there is nothing to create in.
	if _, err := child.CreateContainer(WithSubject(context.Background(), "alice"), nestedContainer{Name: "Nope"}); !errors.Is(err, ErrScopeMissing) {
		t.Fatalf("err = %v, want ErrScopeMissing", err)
	}
}

// A projection naming a capability the child never declared is a configuration
// bug, and [Inheritance] promises it surfaces at resolution time rather than
// silently granting nothing. Both branches of the membership step compile the
// projected grants, so both must refuse.
func TestNestedUndeclaredProjectedGrantIsAnError(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "carol", RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}

	inherit := func(_ access.Permission, _ bool) (map[string][]access.Action, bool) {
		return map[string][]access.Action{"nonesuch": {actionRead}}, false
	}
	child, _ := newChildScope(parent, inherit)
	team := createTeam(t, child, orgC.ContainerID(), "alice")

	// Without a membership of her own: the projected grants are all carol has.
	if _, _, err := child.Standing(context.Background(), team.ContainerID(), "carol"); err == nil {
		t.Fatal("an undeclared projected grant resolved silently")
	}
	// And with one: the union path must refuse just as loudly.
	if _, err := child.AddMember(actorCtx("alice", team.ContainerID()), "carol", RoleMember); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if _, _, err := child.Standing(context.Background(), team.ContainerID(), "carol"); err == nil {
		t.Fatal("an undeclared projected grant merged silently into a member's own permissions")
	}
}
