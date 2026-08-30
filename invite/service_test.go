package invite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/invite"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// fixture wires a real scope.Service (org.Organization/org.Member, so the
// package needs no bespoke container/member types of its own) and a real
// invite.Service over an in-memory Store, exactly as an application would.
// Every test in this file runs against store/memory: it is what
// [memory.NewInviteStore] and [memory.New] build.
//
// store/memory's divergence from store/drops (memory silently allows what
// drops rejects via UNIQUE constraints — see that store's own doc) does NOT
// make the duplicate-rejection path unreachable through the Service in
// general: a colliding [invite.WithTokens] generator (two different
// invitations hashing to the same token_hash) or a race between two
// concurrent InviteByEmail calls for the same (container, email) both reach
// it on drops. Neither is exercised in this file — the first would need a
// deliberately colliding generator this suite doesn't construct, and the
// second needs real concurrency, which is out of scope for a
// store/memory-backed unit test — so nothing here should be read as
// covering that path either, but it is a testing-scope gap, not a design
// impossibility.
type fixture struct {
	t    *testing.T
	ac   *access.Access
	sc   *scope.Service[org.Organization, org.Member, *org.Organization, *org.Member]
	sst  *memory.Store[org.Organization, org.Member, *org.Organization, *org.Member]
	ist  *memory.InviteStore
	isvc *invite.Service[org.Organization, org.Member, *org.Organization, *org.Member]
	cID  string
}

func newFixture(t *testing.T, opts ...invite.Option) *fixture {
	t.Helper()
	return newFixtureFromAccess(t, org.NewAccess(nil), opts...)
}

// newFixtureWithAppRole is like newFixture but also declares an app resource
// ("project": create/read/update/delete) and registers a code-defined
// "viewer" role over it (project:read only) via access.Access.NewRole —
// exactly how an application registers its own roles, per access's own doc
// example (access/access.go). This is deliberately the shape
// scope.Service.ListRoles does NOT enumerate: it returns only
// owner/admin/member plus a container's stored custom roles, so "viewer"
// here is invisible to ListRoles even though it fully resolves through
// scope.Service.RolePermissions — and therefore through
// scope.Service.AddMember's own escalation guard. Used to pin that
// invite.Service treats such a role as it should: invitable, not silently
// nonexistent, and not shadowable by a stray stored row of the same key.
func newFixtureWithAppRole(t *testing.T, opts ...invite.Option) *fixture {
	t.Helper()
	ac := org.NewAccess(map[string][]access.Action{
		"project": {"create", "read", "update", "delete"},
	})
	ac.NewRole("viewer", map[string][]access.Action{"project": {"read"}})
	return newFixtureFromAccess(t, ac, opts...)
}

func newFixtureFromAccess(t *testing.T, ac *access.Access, opts ...invite.Option) *fixture {
	t.Helper()
	sst := memory.New[org.Organization, org.Member]()
	sc := scope.New[org.Organization, org.Member](ac, sst)
	ist := memory.NewInviteStore()
	isvc := invite.New(sc, ist, opts...)

	ctx := scope.WithSubject(context.Background(), "owner")
	c, err := sc.CreateContainer(ctx, org.Organization{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	return &fixture{t: t, ac: ac, sc: sc, sst: sst, ist: ist, isvc: isvc, cID: c.ContainerID()}
}

// ctx builds a context for userID acting within the fixture's container.
func (f *fixture) ctx(userID string) context.Context {
	return scope.WithScope(scope.WithSubject(context.Background(), userID), f.cID)
}

// addMember seeds userID into the fixture's container at roleKey, acting as
// the owner (who is always elevated and so can grant anything).
func (f *fixture) addMember(userID, roleKey string) {
	f.t.Helper()
	if _, err := f.sc.AddMember(f.ctx("owner"), userID, roleKey); err != nil {
		f.t.Fatalf("AddMember(%s, %s): %v", userID, roleKey, err)
	}
}

// ── InviteByEmail ────────────────────────────────────────────────────────────

func TestInviteByEmailMintsAndStoresHashedToken(t *testing.T) {
	f := newFixture(t)
	before := time.Now().UTC()
	inv, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "alice@example.com", org.RoleMember)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}
	if inv.Email != "alice@example.com" || inv.RoleKey != org.RoleMember ||
		inv.ContainerID != f.cID || inv.InvitedBy != "owner" || inv.ID == "" {
		t.Fatalf("invite = %+v", inv)
	}

	// Only sha256(token) is persisted — pin the exact algorithm, not just
	// "some non-empty hash".
	sum := sha256.Sum256([]byte(token))
	wantHash := hex.EncodeToString(sum[:])
	if inv.TokenHash != wantHash {
		t.Fatalf("TokenHash = %q, want sha256(token) = %q", inv.TokenHash, wantHash)
	}

	wantMin := before.Add(7 * 24 * time.Hour)
	wantMax := after.Add(7 * 24 * time.Hour)
	if inv.ExpiresAt.Before(wantMin) || inv.ExpiresAt.After(wantMax) {
		t.Fatalf("ExpiresAt = %v, want within default 7-day window [%v, %v]", inv.ExpiresAt, wantMin, wantMax)
	}

	got, err := f.ist.FindEmailInviteByTokenHash(context.Background(), inv.TokenHash)
	if err != nil {
		t.Fatalf("FindEmailInviteByTokenHash: %v", err)
	}
	if got.ID != inv.ID {
		t.Fatalf("stored invite id = %s, want %s", got.ID, inv.ID)
	}
}

func TestInviteByEmailRequiresInviteCreate(t *testing.T) {
	f := newFixture(t)
	f.addMember("mallory", org.RoleMember)
	if _, _, err := f.isvc.InviteByEmail(f.ctx("mallory"), "x@example.com", org.RoleMember); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestInviteByEmailGuardsEscalation(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)

	if _, _, err := f.isvc.InviteByEmail(f.ctx("admin1"), "x@example.com", org.RoleOwner); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("err = %v, want ErrPrivilegeEscalation", err)
	}
	if _, _, err := f.isvc.InviteByEmail(f.ctx("admin1"), "x@example.com", org.RoleAdmin); err != nil {
		t.Fatalf("admin inviting to its own role: %v", err)
	}
}

// TestInviteByEmailUnknownRoleIsErrRoleNotFound pins the M1 review fix: a
// roleKey that resolves to no role at all must be ErrRoleNotFound, not
// ErrPrivilegeEscalation — matching scope.Service's own resolveRole, which
// scope's guardEscalation checks before ever reaching the SubsetOf
// comparison. Conflating the two would misreport "no such role" as "you
// lack the privilege to grant it".
func TestInviteByEmailUnknownRoleIsErrRoleNotFound(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)
	if _, _, err := f.isvc.InviteByEmail(f.ctx("admin1"), "x@example.com", "role-that-does-not-exist"); !errors.Is(err, scope.ErrRoleNotFound) {
		t.Fatalf("err = %v, want ErrRoleNotFound", err)
	}
}

func TestInviteByEmailReplacesPendingInvite(t *testing.T) {
	f := newFixture(t)
	inv1, token1, err := f.isvc.InviteByEmail(f.ctx("owner"), "alice@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("first invite: %v", err)
	}
	inv2, token2, err := f.isvc.InviteByEmail(f.ctx("owner"), "alice@example.com", org.RoleAdmin)
	if err != nil {
		t.Fatalf("second invite: %v", err)
	}
	if token1 == token2 {
		t.Fatal("expected distinct tokens across a re-invite")
	}
	if inv1.ID == inv2.ID {
		t.Fatal("expected a fresh row, not an update in place")
	}

	if _, err := f.isvc.PreviewInvite(context.Background(), token1); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("preview of the old token err = %v, want ErrInviteNotFound", err)
	}
	p, err := f.isvc.PreviewInvite(context.Background(), token2)
	if err != nil {
		t.Fatalf("preview of the new token: %v", err)
	}
	if !p.Valid || p.RoleKey != org.RoleAdmin {
		t.Fatalf("preview = %+v, want a valid admin-role invite", p)
	}

	invites, err := f.ist.ListEmailInvites(context.Background(), f.cID)
	if err != nil {
		t.Fatalf("ListEmailInvites: %v", err)
	}
	if len(invites) != 1 {
		t.Fatalf("len(invites) = %d, want exactly 1 surviving row for alice", len(invites))
	}
}

// TestInviteByEmailReplacesAPendingInviteSpelledDifferently is the
// security-relevant half of TestInviteByEmailReplacesPendingInvite: "a
// re-invite REPLACES" has to hold across casing and surrounding whitespace,
// not merely across an identical string.
//
// Before [invite.NormalizeEmail] existed, it did not. erin@example.com and
// Erin@Example.com were two different (ContainerID, Email) pairs, so the
// sweep [invite.Service.InviteByEmail] performs first matched neither the
// other's row and the (ContainerID, Email) constraint saw no conflict: the
// container ended up holding TWO live, redeemable invitations for one human.
// A pending-invitations screen shows both, an admin revoking the one they
// recognise leaves the other redeemable at the invited role, and nothing
// anywhere reports that it is still out there.
//
// The assertion that carries the security weight is the last one: exactly one
// row, and the first token dead. Do not weaken it to "the second token
// works" — that passes with the defect fully present.
func TestInviteByEmailReplacesAPendingInviteSpelledDifferently(t *testing.T) {
	f := newFixture(t)

	_, lower, err := f.isvc.InviteByEmail(f.ctx("owner"), "erin@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("first invite: %v", err)
	}
	inv, upper, err := f.isvc.InviteByEmail(f.ctx("owner"), "  Erin@Example.COM\t", org.RoleAdmin)
	if err != nil {
		t.Fatalf("re-invite under a different spelling: %v", err)
	}

	// The security consequence first, so a regression reports what actually
	// went wrong rather than the cosmetic mismatch that precedes it.
	invites, err := f.ist.ListEmailInvites(context.Background(), f.cID)
	if err != nil {
		t.Fatalf("ListEmailInvites: %v", err)
	}
	if len(invites) != 1 {
		addresses := make([]string, 0, len(invites))
		for _, i := range invites {
			addresses = append(addresses, i.Email)
		}
		sort.Strings(addresses)
		t.Fatalf("the container holds %d live invitation(s) %v for ONE person, want exactly 1. Two spellings of one address are two redeemable tokens: an admin revoking the row they recognise leaves the other live, at the invited role, with nothing reporting that it is still out there", len(invites), addresses)
	}

	if _, err := f.isvc.PreviewInvite(context.Background(), lower); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("preview of the first token err = %v, want ErrInviteNotFound — re-inviting the same person under a different spelling must REPLACE the pending invitation, not leave a second one redeemable", err)
	}
	p, err := f.isvc.PreviewInvite(context.Background(), upper)
	if err != nil {
		t.Fatalf("preview of the second token: %v", err)
	}
	if !p.Valid || p.RoleKey != org.RoleAdmin {
		t.Fatalf("preview = %+v, want a valid admin-role invite", p)
	}

	if inv.Email != "erin@example.com" {
		t.Errorf("stored Email = %q, want the normalized %q — InviteByEmail must apply invite.NormalizeEmail before it writes", inv.Email, "erin@example.com")
	}
	if p.Email != "erin@example.com" {
		t.Errorf("Preview.Email = %q, want the normalized %q — a caller binding the invitation to its recipient compares this against a normalized auth.UserBase.Email", p.Email, "erin@example.com")
	}
}

// TestNormalizeEmailMatchesAuth pins that invite and auth fold addresses
// identically. The two are separate exported functions — invite takes no
// dependency on auth, deliberately — so nothing but this test and their
// shared internal implementation stops them drifting, and an application
// that compares an invited address against a verified account address is
// relying on them agreeing exactly.
func TestNormalizeEmailMatchesAuth(t *testing.T) {
	for _, in := range []string{
		"", "   ", "bob@example.com", "Bob@Example.com", "  BOB@EXAMPLE.COM \t",
		"\tCarol.Smith+Tag@Example.COM\n", "bo b@example.com",
	} {
		if got, want := invite.NormalizeEmail(in), auth.NormalizeEmail(in); got != want {
			t.Errorf("invite.NormalizeEmail(%q) = %q, auth.NormalizeEmail(%q) = %q — the two must agree byte for byte", in, got, in, want)
		}
	}
}

func TestWithInviteExpiryOverridesDefault(t *testing.T) {
	f := newFixture(t, invite.WithInviteExpiry(2*time.Hour))
	before := time.Now().UTC()
	inv, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if inv.ExpiresAt.Before(before.Add(2*time.Hour)) || inv.ExpiresAt.After(after.Add(2*time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want within 2h of now", inv.ExpiresAt)
	}
}

func TestWithInviteExpiryIgnoresNonPositiveDuration(t *testing.T) {
	f := newFixture(t, invite.WithInviteExpiry(0), invite.WithInviteExpiry(-time.Hour))
	before := time.Now().UTC()
	inv, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if inv.ExpiresAt.Before(before.Add(7*24*time.Hour)) || inv.ExpiresAt.After(after.Add(7*24*time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want the default 7-day window (non-positive durations ignored)", inv.ExpiresAt)
	}
}

type stubNotifier struct {
	calls int
	inv   invite.EmailInvite
	token string
	err   error
}

func (s *stubNotifier) Notify(_ context.Context, inv invite.EmailInvite, token string) error {
	s.calls++
	s.inv = inv
	s.token = token
	return s.err
}

func TestWithNotifierIsCalledWithTheStoredInviteAndPlainToken(t *testing.T) {
	n := &stubNotifier{}
	f := newFixture(t, invite.WithNotifier(n))
	inv, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if n.calls != 1 {
		t.Fatalf("Notify called %d times, want 1", n.calls)
	}
	if n.token != token || n.inv.ID != inv.ID {
		t.Fatalf("notifier saw (%q, id=%s), want (%q, id=%s)", n.token, n.inv.ID, token, inv.ID)
	}
}

func TestWithNotifierErrorPropagates(t *testing.T) {
	wantErr := errors.New("smtp down")
	f := newFixture(t, invite.WithNotifier(&stubNotifier{err: wantErr}))
	if _, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestWithTokensOverridesGenerator(t *testing.T) {
	f := newFixture(t, invite.WithTokens(func() string { return "fixed-token" }))
	_, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if token != "fixed-token" {
		t.Fatalf("token = %q, want %q", token, "fixed-token")
	}
}

// ── CreateLink ───────────────────────────────────────────────────────────────

func TestCreateLinkMintsCodeAndStores(t *testing.T) {
	f := newFixture(t)
	l, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 5, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if code == "" || l.Code != code {
		t.Fatalf("code = %q, l.Code = %q, want equal and non-empty", code, l.Code)
	}
	if l.RoleKey != org.RoleMember || l.ContainerID != f.cID || l.CreatedBy != "owner" ||
		l.MaxUses != 5 || l.ExpiresAt != nil || l.ID == "" {
		t.Fatalf("link = %+v", l)
	}
}

func TestCreateLinkRequiresInviteCreate(t *testing.T) {
	f := newFixture(t)
	f.addMember("mallory", org.RoleMember)
	if _, _, err := f.isvc.CreateLink(f.ctx("mallory"), org.RoleMember, 0, nil); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestCreateLinkGuardsEscalation(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)
	if _, _, err := f.isvc.CreateLink(f.ctx("admin1"), org.RoleOwner, 0, nil); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("err = %v, want ErrPrivilegeEscalation", err)
	}
}

func TestCreateLinkRespectsExplicitExpiry(t *testing.T) {
	f := newFixture(t)
	at := time.Now().UTC().Add(48 * time.Hour)
	l, _, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 0, &at)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if l.ExpiresAt == nil || !l.ExpiresAt.Equal(at) {
		t.Fatalf("ExpiresAt = %v, want %v", l.ExpiresAt, at)
	}
}

// ── ListInvites ──────────────────────────────────────────────────────────────

func TestListInvitesReturnsContainerScopedInvites(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "a@example.com", org.RoleMember); err != nil {
		t.Fatalf("invite a: %v", err)
	}
	if _, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "b@example.com", org.RoleMember); err != nil {
		t.Fatalf("invite b: %v", err)
	}
	invites, err := f.isvc.ListInvites(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListInvites: %v", err)
	}
	if len(invites) != 2 {
		t.Fatalf("len(invites) = %d, want 2", len(invites))
	}
}

func TestListInvitesRequiresInviteRead(t *testing.T) {
	f := newFixture(t)
	f.addMember("mallory", org.RoleMember)
	if _, err := f.isvc.ListInvites(f.ctx("mallory")); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// A negative maxUses names no reachable policy: 0 is unlimited and any
// positive value is a cap, so a negative one would mint a link whose
// exhaustion predicate (MaxUses != 0 && UseCount >= MaxUses) is already true
// at UseCount 0 — a credential that is dead the moment it is created, and
// silently so. Both shipped stores fail closed on it identically, so this is
// an argument error rather than a store divergence.
func TestCreateLinkRejectsNegativeMaxUses(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, -1, nil); !errors.Is(err, invite.ErrInvalidMaxUses) {
		t.Fatalf("err = %v, want ErrInvalidMaxUses", err)
	}
	links, err := f.isvc.ListLinks(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("len(links) = %d, want 0 — a refused CreateLink must persist nothing", len(links))
	}
	// 0 stays unlimited, so the guard has not moved the boundary.
	if _, _, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 0, nil); err != nil {
		t.Fatalf("CreateLink(maxUses=0): %v, want success — 0 means unlimited", err)
	}
}

// ── ListLinks — the security core ───────────────────────────────────────────

func TestListLinksElevatedSeesEveryCode(t *testing.T) {
	f := newFixture(t)
	_, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleOwner, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	links, err := f.isvc.ListLinks(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(links) != 1 || links[0].Code != code {
		t.Fatalf("links = %+v, want the owner (elevated) to see the real code %q", links, code)
	}
}

// TestListLinksRedactsCodeAboveReaderStanding is the single most important
// test in this plan (see task-5-brief.md). It pins the exact attack the
// redaction exists to close: admin acquires invite:read purely because it
// sits on the merged permission surface (scope.ControlStatements) — admin
// itself is NOT elevated, so without redaction it could read the owner's
// link code here, leave the container, and rejoin at the owner role through
// JoinViaLink -> GrantMembership, which runs no escalation check of its own
// by design. This test is the one the mandatory mutation check in the task
// brief is run against; see task-5-report.md for that run's actual output.
func TestListLinksRedactsCodeAboveReaderStanding(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)
	_, ownerCode, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleOwner, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	links, err := f.isvc.ListLinks(f.ctx("admin1"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("len(links) = %d, want 1", len(links))
	}
	got := links[0]
	if got.Code != "" {
		t.Fatalf("Code = %q, want redacted (empty) for a non-elevated admin reading an owner-role link", got.Code)
	}
	if got.Code == ownerCode {
		t.Fatal("redacted code must not equal the real code")
	}
	// Every other field must survive redaction, so the management screen and
	// RevokeLink still work on a link the reader cannot read the code of.
	if got.RoleKey != org.RoleOwner {
		t.Fatalf("RoleKey = %q, want %q — RoleKey is never redacted", got.RoleKey, org.RoleOwner)
	}
	if got.ContainerID != f.cID || got.CreatedBy != "owner" {
		t.Fatalf("link = %+v, want ContainerID/CreatedBy still populated", got)
	}
}

func TestListLinksKeepsCodeAtOrBelowReaderStanding(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)
	// SubsetOf is reflexive: a link at the reader's own role level must stay
	// visible.
	_, adminCode, err := f.isvc.CreateLink(f.ctx("admin1"), org.RoleAdmin, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink (admin-role): %v", err)
	}
	// And one strictly weaker than the reader.
	_, memberCode, err := f.isvc.CreateLink(f.ctx("admin1"), org.RoleMember, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink (member-role): %v", err)
	}

	links, err := f.isvc.ListLinks(f.ctx("admin1"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	byRole := map[string]invite.Link{}
	for _, l := range links {
		byRole[l.RoleKey] = l
	}
	if byRole[org.RoleAdmin].Code != adminCode {
		t.Fatalf("admin-role link Code = %q, want %q kept", byRole[org.RoleAdmin].Code, adminCode)
	}
	if byRole[org.RoleMember].Code != memberCode {
		t.Fatalf("member-role link Code = %q, want %q kept", byRole[org.RoleMember].Code, memberCode)
	}
}

// TestListLinksRedactsUnknownRole pins the second rule from the brief: a
// link naming a role the reader's scope cannot currently resolve must be
// redacted, not kept — an unresolvable role can never be shown to be a
// SubsetOf anything. This is seeded directly against the Store, bypassing
// the Service's own creation path (which cannot mint a link for a role that
// does not exist), simulating what a custom role deleted after a link was
// minted would leave behind: a link naming a key
// scope.Service.RolePermissions can no longer resolve.
func TestListLinksRedactsUnknownRole(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)
	ghost, err := f.ist.CreateLink(context.Background(), invite.Link{
		ID:          "ghost-link",
		ContainerID: f.cID,
		Code:        "ghost-code",
		RoleKey:     "role-that-does-not-exist",
		CreatedBy:   "owner",
		CreatedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed ghost link: %v", err)
	}

	links, err := f.isvc.ListLinks(f.ctx("admin1"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("len(links) = %d, want 1", len(links))
	}
	if links[0].Code != "" {
		t.Fatalf("Code = %q, want redacted for a link naming an unresolvable role", links[0].Code)
	}
	if links[0].RoleKey != ghost.RoleKey {
		t.Fatalf("RoleKey = %q, want %q", links[0].RoleKey, ghost.RoleKey)
	}
}

// TestDefaultRoleKeyResolvesFromRegistryNotAShadowingStoreRow pins the
// Critical finding from the Task 5 review. The pre-fix implementation
// resolved a role's permissions by indexing scope.Service.ListRoles'
// result — which emits the three code-defined defaults FIRST, then the
// container's stored roles — into a last-write-wins map, so a stored role
// row keyed with a default key (e.g. "owner") overwrote the real default's
// entry there, inverting scope.Service's own resolveRole precedence, which
// always checks the code-defined registry BEFORE ever falling back to the
// store. scope.Service.CreateRole refuses to create such a row
// (ErrRoleKeyTaken), but the RoleStore port does not forbid it and neither
// store implementation rejects it independently, so this is seeded directly
// against the raw scope store to simulate a backend that allows it.
//
// Today's implementation resolves every role through
// scope.Service.RolePermissions — a direct delegate to scope's own
// resolveRole, not a map built from ListRoles' output — so it can no
// longer be inverted by ordering at all. This test remains the regression
// pin for that class of bug.
//
// The reviewer demonstrated the live consequence end to end against the
// pre-fix code: scope.Service.AddMember(admin1 -> owner) was correctly
// refused, while invite.Service.CreateLink(admin1 -> owner) succeeded, and
// ListLinks then handed the non-elevated admin the owner's clear-text code.
// This test pins both halves of that: the mint-time escalation guard must
// still refuse, and the redaction must still redact, regardless of what the
// shadowing row's own (deliberately low) permissions say.
func TestDefaultRoleKeyResolvesFromRegistryNotAShadowingStoreRow(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)

	// Seed a stored role row keyed "owner" carrying deliberately LOW (empty)
	// permissions, bypassing scope.Service.CreateRole's own guard against a
	// default key.
	lowPerm, err := f.ac.Permission(map[string][]access.Action{})
	if err != nil {
		t.Fatalf("ac.Permission: %v", err)
	}
	if _, err := f.sst.CreateRole(context.Background(), scope.RoleRecord{
		ID:          "shadow-owner",
		ContainerID: f.cID,
		Key:         org.RoleOwner,
		Name:        "Fake Owner",
		Permissions: lowPerm.Encode(),
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed shadow owner role row: %v", err)
	}

	// (1) Mint-time escalation guard. If the shadowing low-permission row
	// won, admin's own permissions would trivially SubsetOf it and this
	// would wrongly succeed.
	if _, _, err := f.isvc.CreateLink(f.ctx("admin1"), org.RoleOwner, 0, nil); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("CreateLink(admin1 -> owner) err = %v, want ErrPrivilegeEscalation despite a shadowing low-permission stored row", err)
	}

	// (2) ListLinks redaction. The real owner mints a genuine owner-role
	// link (elevated, so the guard above does not apply to them); admin must
	// still have its Code redacted. If the shadowing row won, the fake
	// low-permission "owner" would look like a SubsetOf admin's own standing
	// and the real code would leak.
	_, ownerCode, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleOwner, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink(owner -> owner): %v", err)
	}
	links, err := f.isvc.ListLinks(f.ctx("admin1"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	var got invite.Link
	var found bool
	for _, l := range links {
		if l.RoleKey == org.RoleOwner {
			got, found = l, true
		}
	}
	if !found {
		t.Fatalf("no owner-role link found in %+v", links)
	}
	if got.Code != "" {
		t.Fatalf("Code = %q, want redacted despite a shadowing low-permission stored row", got.Code)
	}
	if got.Code == ownerCode {
		t.Fatal("redacted code must not equal the real code")
	}
}

// TestAppRegisteredCodeDefinedRoleIsInvitableAndVisible pins the first half
// of the round-2 review finding: guardEscalation and the ListLinks
// redaction must resolve a code-defined role an application registered
// itself (via access.Access.NewRole, exactly per that package's own doc
// example) even though scope.Service.ListRoles never enumerates it —
// ListRoles returns only owner/admin/member plus a container's stored
// custom roles. Before the fix, permissionsByRole was built purely from
// ListRoles' output, so "viewer" resolved to nothing and every attempt to
// invite to it failed with ErrRoleNotFound, and any link naming it was
// permanently redacted for every non-elevated reader regardless of their
// own standing. Demonstrated live by the reviewer:
// scope.Service.AddMember(admin1 -> "viewer") succeeded while
// invite.InviteByEmail(admin1 -> "viewer") returned ErrRoleNotFound.
func TestAppRegisteredCodeDefinedRoleIsInvitableAndVisible(t *testing.T) {
	f := newFixtureWithAppRole(t)
	f.addMember("admin1", org.RoleAdmin)

	// admin's own standing includes every declared pair except
	// containerResource:delete (scope.NewAccess's default admin grants),
	// which covers the app's own "project" resource too — so "viewer"
	// (project:read only) is a genuine SubsetOf admin's standing and both
	// calls must succeed.
	if _, _, err := f.isvc.InviteByEmail(f.ctx("admin1"), "x@example.com", "viewer"); err != nil {
		t.Fatalf("InviteByEmail(admin1 -> viewer): %v, want success — viewer is an app-registered code-defined role", err)
	}
	l, code, err := f.isvc.CreateLink(f.ctx("admin1"), "viewer", 0, nil)
	if err != nil {
		t.Fatalf("CreateLink(admin1 -> viewer): %v", err)
	}
	if code == "" || l.Code != code {
		t.Fatalf("link = %+v, code = %q", l, code)
	}

	links, err := f.isvc.ListLinks(f.ctx("admin1"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	var got invite.Link
	var found bool
	for _, li := range links {
		if li.ID == l.ID {
			got, found = li, true
		}
	}
	if !found {
		t.Fatalf("link %s not found in %+v", l.ID, links)
	}
	if got.Code != code {
		t.Fatalf("Code = %q, want %q kept — viewer's permissions are a SubsetOf admin's own standing", got.Code, code)
	}
}

// TestCreateLinkIgnoresStoreRowShadowingAppRegisteredRole pins the second,
// narrower-precondition half of the round-2 review finding: a stored role
// row keyed with an app-registered code-defined role's key (here "viewer",
// carrying empty permissions) must not be consulted at all, even for a role
// outside the three hardcoded defaults. This is seeded directly against the
// raw scope store, the same reachability premise already used for the
// "owner"-keyed row above: scope.Service.CreateRole in fact refuses this
// specific collision too (its isDefault check is really "is this key
// registered in the Access at all", which covers "viewer"), but the
// RoleStore port does not forbid it and neither store implementation
// rejects it independently, so a row like this remains a reachable state on
// a backend that does not defend against it.
//
// mallory holds a custom "recruiter" role granting invite:create/read/delete
// but nothing on "project" — enough to reach CreateLink's authorization
// check at all (org.RoleMember, holding zero grants, cannot even clear that
// first gate, which is why this needs a purpose-built role rather than a
// default one). Demonstrated live by the reviewer using an equivalent
// non-elevated actor: scope.Service.AddMember(actor -> "viewer") is
// correctly ErrPrivilegeEscalation (the REAL "viewer" grants project:read,
// which such an actor does not have), while
// invite.Service.CreateLink(actor -> "viewer") succeeded and returned a
// live code — because the pre-fix permissionsByRole map's only entry for
// "viewer" came from the shadowing row's empty permissions, and an empty
// Permission is vacuously a SubsetOf anything.
func TestCreateLinkIgnoresStoreRowShadowingAppRegisteredRole(t *testing.T) {
	f := newFixtureWithAppRole(t)

	if _, err := f.sc.CreateRole(f.ctx("owner"), "recruiter", "Recruiter", map[string][]access.Action{
		scope.ResourceInvite: {scope.ActionCreate, scope.ActionRead, scope.ActionDelete},
	}); err != nil {
		t.Fatalf("CreateRole(recruiter): %v", err)
	}
	f.addMember("mallory", "recruiter")

	emptyPerm, err := f.ac.Permission(map[string][]access.Action{})
	if err != nil {
		t.Fatalf("ac.Permission: %v", err)
	}
	if _, err := f.sst.CreateRole(context.Background(), scope.RoleRecord{
		ID:          "shadow-viewer",
		ContainerID: f.cID,
		Key:         "viewer",
		Name:        "Fake Viewer",
		Permissions: emptyPerm.Encode(),
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed shadow viewer role row: %v", err)
	}

	if _, _, err := f.isvc.CreateLink(f.ctx("mallory"), "viewer", 0, nil); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("CreateLink(mallory -> viewer) err = %v, want ErrPrivilegeEscalation despite a shadowing empty-permission stored row", err)
	}
}

// TestListLinksRedactsEveryCodeForAReaderWhoCannotMint pins half one of
// ListLinks' two-part mint test, the Critical from the whole-branch review.
//
// The disclosure rule used to be the escalation guard ALONE — elevated or
// RolePermissions(RoleKey).SubsetOf(readerStanding) — which asks only how
// HIGH the reader could have minted, never WHETHER they could have minted
// anything. A principal granted invite:read without invite:create therefore
// received the verbatim Code of every link whose role they subsume, even
// though their own CreateLink is refused. That is not an escalation for the
// reader (the codes stay within their own standing) but it is
// read-implies-admit: they acquire the power to admit arbitrary third
// parties, which invite:create exists to gate, and it falsifies the
// invariant scope.Service.GrantMembership's doc, the readme and the
// changelog all state — "nothing hands a usable credential to a principal
// who could not have minted it".
//
// The reviewer reproduced it end to end against a stock org.NewAccess: an
// "auditor" role granting only invite:read read an owner-minted code
// verbatim while its own CreateLink was refused, and an outsider then
// joined with that code.
//
// The configuration is ordinary and fully supported —
// scope.Service.CreateRole accepts any escalation-clean grant subset, so
// splitting invite:read from invite:create is a legal call for any admin.
// The link here is minted at the auditor's OWN role, so SubsetOf is
// reflexively true and half two of the test passes: the only thing that can
// redact this code is the invite:create gate. This is the test the mandated
// mutation check is run against.
func TestListLinksRedactsEveryCodeForAReaderWhoCannotMint(t *testing.T) {
	f := newFixture(t)
	if _, err := f.sc.CreateRole(f.ctx("owner"), "auditor", "Auditor", map[string][]access.Action{
		scope.ResourceInvite: {scope.ActionRead},
	}); err != nil {
		t.Fatalf("CreateRole(auditor): %v", err)
	}
	f.addMember("auditor1", "auditor")

	// The premise: this reader provably could not have minted any link here.
	if _, _, err := f.isvc.CreateLink(f.ctx("auditor1"), "auditor", 0, nil); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("CreateLink(auditor1) err = %v, want ErrForbidden — the premise of this test is that auditor cannot mint", err)
	}

	// A link at the reader's own role: SubsetOf is reflexive, so the
	// escalation half of the test passes and only the mint capability can
	// redact it.
	_, ownCode, err := f.isvc.CreateLink(f.ctx("owner"), "auditor", 0, nil)
	if err != nil {
		t.Fatalf("CreateLink(owner -> auditor): %v", err)
	}
	// And one strictly above them, which both halves would redact.
	if _, _, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleOwner, 0, nil); err != nil {
		t.Fatalf("CreateLink(owner -> owner): %v", err)
	}

	links, err := f.isvc.ListLinks(f.ctx("auditor1"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("len(links) = %d, want 2 — invite:read still lists every link", len(links))
	}
	for _, l := range links {
		if l.Code != "" {
			t.Fatalf("RoleKey %q Code = %q, want redacted: a reader without invite:create could not have minted ANY link, whatever the role", l.RoleKey, l.Code)
		}
	}
	if ownCode == "" {
		t.Fatal("the real code is empty; the assertion above would pass vacuously")
	}
	// Every other field must still survive, exactly as for the escalation
	// half: a read-only auditor screen still lists links, it just cannot
	// read a code back.
	byRole := map[string]invite.Link{}
	for _, l := range links {
		byRole[l.RoleKey] = l
	}
	if got := byRole["auditor"]; got.ContainerID != f.cID || got.CreatedBy != "owner" || got.ID == "" {
		t.Fatalf("link = %+v, want ContainerID/CreatedBy/ID still populated", got)
	}
}

// TestListLinksKeepsCodeForAMinterOnlyWithinTheirStanding pins half two,
// and that half one did not swallow it: a reader holding BOTH invite:read
// and invite:create still sees a Code only for links whose role they
// subsume. Together with the test above it fixes the conjunction — neither
// half alone is sufficient, and adding the invite:create gate must not have
// turned into "any minter sees everything".
func TestListLinksKeepsCodeForAMinterOnlyWithinTheirStanding(t *testing.T) {
	f := newFixture(t)
	if _, err := f.sc.CreateRole(f.ctx("owner"), "auditor", "Auditor", map[string][]access.Action{
		scope.ResourceInvite: {scope.ActionRead},
	}); err != nil {
		t.Fatalf("CreateRole(auditor): %v", err)
	}
	if _, err := f.sc.CreateRole(f.ctx("owner"), "recruiter", "Recruiter", map[string][]access.Action{
		scope.ResourceInvite: {scope.ActionCreate, scope.ActionRead},
	}); err != nil {
		t.Fatalf("CreateRole(recruiter): %v", err)
	}
	f.addMember("recruiter1", "recruiter")

	// Minted by the reader themselves, at a role strictly weaker than their
	// own standing ({invite:read} ⊂ {invite:create, invite:read}).
	_, belowCode, err := f.isvc.CreateLink(f.ctx("recruiter1"), "auditor", 0, nil)
	if err != nil {
		t.Fatalf("CreateLink(recruiter1 -> auditor): %v", err)
	}
	// Minted by the owner at a role far above the reader.
	_, aboveCode, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleOwner, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink(owner -> owner): %v", err)
	}

	links, err := f.isvc.ListLinks(f.ctx("recruiter1"))
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	byRole := map[string]invite.Link{}
	for _, l := range links {
		byRole[l.RoleKey] = l
	}
	if byRole["auditor"].Code != belowCode {
		t.Fatalf("auditor-role link Code = %q, want %q kept — the reader holds invite:create and subsumes the role", byRole["auditor"].Code, belowCode)
	}
	if byRole[org.RoleOwner].Code != "" {
		t.Fatalf("owner-role link Code = %q, want redacted — invite:create does not lift the escalation half", byRole[org.RoleOwner].Code)
	}
	if aboveCode == "" {
		t.Fatal("the real owner code is empty; the assertion above would pass vacuously")
	}
}

func TestListLinksRequiresInviteRead(t *testing.T) {
	f := newFixture(t)
	f.addMember("mallory", org.RoleMember)
	if _, err := f.isvc.ListLinks(f.ctx("mallory")); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// ── RevokeInvite / RevokeLink ────────────────────────────────────────────────

func TestRevokeInviteDeletesRow(t *testing.T) {
	f := newFixture(t)
	inv, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if err := f.isvc.RevokeInvite(f.ctx("owner"), inv.ID); err != nil {
		t.Fatalf("RevokeInvite: %v", err)
	}
	if _, err := f.ist.FindEmailInvite(context.Background(), inv.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("post-revoke lookup err = %v, want ErrInviteNotFound", err)
	}
}

func TestRevokeInviteRequiresInviteDelete(t *testing.T) {
	f := newFixture(t)
	f.addMember("mallory", org.RoleMember)
	inv, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if err := f.isvc.RevokeInvite(f.ctx("mallory"), inv.ID); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestRevokeInviteRefusesCrossContainer(t *testing.T) {
	f := newFixture(t)
	otherOwnerCtx := scope.WithSubject(context.Background(), "other-owner")
	oc, err := f.sc.CreateContainer(otherOwnerCtx, org.Organization{Name: "Other", Slug: "other"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	otherCtx := scope.WithScope(otherOwnerCtx, oc.ContainerID())

	victim, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "victim@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if err := f.isvc.RevokeInvite(otherCtx, victim.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("cross-container RevokeInvite err = %v, want ErrInviteNotFound", err)
	}
	if _, err := f.ist.FindEmailInvite(context.Background(), victim.ID); err != nil {
		t.Fatalf("invite was affected across containers: %v", err)
	}
}

func TestRevokeLinkStampsRevokedAt(t *testing.T) {
	f := newFixture(t)
	l, _, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if err := f.isvc.RevokeLink(f.ctx("owner"), l.ID); err != nil {
		t.Fatalf("RevokeLink: %v", err)
	}
	got, err := f.ist.FindLink(context.Background(), l.ID)
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.RevokedAt == nil {
		t.Fatal("RevokedAt was not stamped")
	}
}

func TestRevokeLinkRequiresInviteDelete(t *testing.T) {
	f := newFixture(t)
	f.addMember("mallory", org.RoleMember)
	l, _, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if err := f.isvc.RevokeLink(f.ctx("mallory"), l.ID); !errors.Is(err, scope.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestRevokeLinkRefusesCrossContainer(t *testing.T) {
	f := newFixture(t)
	otherOwnerCtx := scope.WithSubject(context.Background(), "other-owner")
	oc, err := f.sc.CreateContainer(otherOwnerCtx, org.Organization{Name: "Other", Slug: "other2"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	otherCtx := scope.WithScope(otherOwnerCtx, oc.ContainerID())

	l, _, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if err := f.isvc.RevokeLink(otherCtx, l.ID); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("cross-container RevokeLink err = %v, want ErrLinkNotFound", err)
	}
	got, err := f.ist.FindLink(context.Background(), l.ID)
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.RevokedAt != nil {
		t.Fatal("link was revoked across a container boundary")
	}
}

// ── PreviewInvite / PreviewLink ──────────────────────────────────────────────

func TestPreviewInviteIsUnauthenticated(t *testing.T) {
	f := newFixture(t)
	_, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleAdmin)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	// A bare context.Background(): no subject, no scope.
	p, err := f.isvc.PreviewInvite(context.Background(), token)
	if err != nil {
		t.Fatalf("PreviewInvite: %v", err)
	}
	if !p.Valid || p.ContainerID != f.cID || p.RoleKey != org.RoleAdmin || p.Email != "x@example.com" {
		t.Fatalf("preview = %+v", p)
	}
}

func TestPreviewInviteExpired(t *testing.T) {
	f := newFixture(t, invite.WithInviteExpiry(time.Nanosecond))
	_, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	p, err := f.isvc.PreviewInvite(context.Background(), token)
	if err != nil {
		t.Fatalf("PreviewInvite: %v", err)
	}
	if p.Valid {
		t.Fatal("expired invite reported Valid = true")
	}
	if p.RoleKey != org.RoleMember {
		t.Fatalf("expired preview should still report its other fields: %+v", p)
	}
}

func TestPreviewInviteUnknownToken(t *testing.T) {
	f := newFixture(t)
	if _, err := f.isvc.PreviewInvite(context.Background(), "does-not-exist"); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("err = %v, want ErrInviteNotFound", err)
	}
}

func TestPreviewLinkValidAndRevoked(t *testing.T) {
	f := newFixture(t)
	l, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 1, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	p, err := f.isvc.PreviewLink(context.Background(), code)
	if err != nil {
		t.Fatalf("PreviewLink: %v", err)
	}
	if !p.Valid || p.Email != "" || p.RoleKey != org.RoleMember || p.ContainerID != f.cID {
		t.Fatalf("preview = %+v", p)
	}

	if err := f.isvc.RevokeLink(f.ctx("owner"), l.ID); err != nil {
		t.Fatalf("RevokeLink: %v", err)
	}
	p, err = f.isvc.PreviewLink(context.Background(), code)
	if err != nil {
		t.Fatalf("PreviewLink after revoke: %v", err)
	}
	if p.Valid {
		t.Fatal("revoked link reported Valid = true")
	}
}

func TestPreviewLinkExhausted(t *testing.T) {
	f := newFixture(t)
	_, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 1, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	l, err := f.ist.FindLinkByCode(context.Background(), code)
	if err != nil {
		t.Fatalf("FindLinkByCode: %v", err)
	}
	if ok, err := f.ist.ConsumeLink(context.Background(), l.ID, time.Now().UTC()); err != nil || !ok {
		t.Fatalf("ConsumeLink = %v, %v, want true, nil", ok, err)
	}

	p, err := f.isvc.PreviewLink(context.Background(), code)
	if err != nil {
		t.Fatalf("PreviewLink: %v", err)
	}
	if p.Valid {
		t.Fatal("exhausted link reported Valid = true")
	}
}

func TestPreviewLinkUnknownCode(t *testing.T) {
	f := newFixture(t)
	if _, err := f.isvc.PreviewLink(context.Background(), "nope"); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("err = %v, want ErrLinkNotFound", err)
	}
}

// TestPreviewInviteReflectsRecheckInviterOnAccept pins the fix for the
// review's I2: before this fix, Preview.Valid ignored the
// RecheckInviterOnAccept refusal reason entirely, so an unauthenticated
// invite page could tell a visitor their invitation was good right up until
// AcceptInvite bounced them with scope.ErrPrivilegeEscalation. The preview
// must now agree with what acceptance is about to do.
func TestPreviewInviteReflectsRecheckInviterOnAccept(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)

	_, token, err := f.isvc.InviteByEmail(f.ctx("admin1"), "alice@example.com", org.RoleAdmin)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}

	if p, err := f.isvc.PreviewInvite(context.Background(), token); err != nil || !p.Valid {
		t.Fatalf("PreviewInvite before demotion = %+v, %v, want Valid=true", p, err)
	}

	if err := f.sc.ChangeMemberRole(f.ctx("owner"), "admin1", org.RoleMember); err != nil {
		t.Fatalf("ChangeMemberRole: %v", err)
	}

	p, err := f.isvc.PreviewInvite(context.Background(), token)
	if err != nil {
		t.Fatalf("PreviewInvite after demotion: %v", err)
	}
	if p.Valid {
		t.Fatal("preview reported Valid = true for an invitation whose inviter can no longer support the role")
	}
	if p.RoleKey != org.RoleAdmin {
		t.Fatalf("a not-valid preview should still report its other fields: %+v", p)
	}

	// The preview and acceptance must agree.
	if _, err := f.isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("AcceptInvite err = %v, want ErrPrivilegeEscalation, matching the preview", err)
	}
}

// TestPreviewInviteWithRecheckOffIgnoresInviterDemotion is the mirror: with
// the knob off, the same demotion must not affect the preview either, since
// AcceptInvite itself would not check it.
func TestPreviewInviteWithRecheckOffIgnoresInviterDemotion(t *testing.T) {
	f := newFixture(t, invite.WithRecheckInviterOnAccept(false))
	f.addMember("admin1", org.RoleAdmin)

	_, token, err := f.isvc.InviteByEmail(f.ctx("admin1"), "alice@example.com", org.RoleAdmin)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	if err := f.sc.ChangeMemberRole(f.ctx("owner"), "admin1", org.RoleMember); err != nil {
		t.Fatalf("ChangeMemberRole: %v", err)
	}

	if p, err := f.isvc.PreviewInvite(context.Background(), token); err != nil || !p.Valid {
		t.Fatalf("PreviewInvite with the recheck disabled = %+v, %v, want Valid=true", p, err)
	}
}

// TestPreviewLinkReflectsRecheckInviterOnAccept is PreviewLink's counterpart
// to TestPreviewInviteReflectsRecheckInviterOnAccept.
func TestPreviewLinkReflectsRecheckInviterOnAccept(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)

	_, code, err := f.isvc.CreateLink(f.ctx("admin1"), org.RoleAdmin, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	if p, err := f.isvc.PreviewLink(context.Background(), code); err != nil || !p.Valid {
		t.Fatalf("PreviewLink before demotion = %+v, %v, want Valid=true", p, err)
	}

	if err := f.sc.ChangeMemberRole(f.ctx("owner"), "admin1", org.RoleMember); err != nil {
		t.Fatalf("ChangeMemberRole: %v", err)
	}

	p, err := f.isvc.PreviewLink(context.Background(), code)
	if err != nil {
		t.Fatalf("PreviewLink after demotion: %v", err)
	}
	if p.Valid {
		t.Fatal("preview reported Valid = true for a link whose creator can no longer support the role")
	}

	if _, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "alice"), code); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("JoinViaLink err = %v, want ErrPrivilegeEscalation, matching the preview", err)
	}
}

// ── PurgeExpired ─────────────────────────────────────────────────────────────

func TestPurgeExpiredDelegatesToStore(t *testing.T) {
	f := newFixture(t, invite.WithInviteExpiry(time.Nanosecond))
	if _, _, err := f.isvc.InviteByEmail(f.ctx("owner"), "x@example.com", org.RoleMember); err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	n, err := f.isvc.PurgeExpired(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("PurgeExpired = %d, want 1", n)
	}
}

// ── AcceptInvite ─────────────────────────────────────────────────────────────

// memberRole returns the role of userID in members, and whether it was found
// at all — a small helper shared by the acceptance tests below, since
// checking who got admitted and at what role is their whole point.
func memberRole(members []org.Member, userID string) (string, bool) {
	for _, m := range members {
		if m.MemberUser() == userID {
			return m.MemberRole(), true
		}
	}
	return "", false
}

func TestAcceptInviteAdmitsAtInvitedRoleAndDeletesInvite(t *testing.T) {
	f := newFixture(t)
	inv, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "alice@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}

	c, err := f.isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token)
	if err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}
	if c.ContainerID() != f.cID {
		t.Fatalf("AcceptInvite container = %s, want %s", c.ContainerID(), f.cID)
	}

	members, err := f.sc.ListMembers(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	role, ok := memberRole(members, "alice")
	if !ok {
		t.Fatal("alice was not admitted")
	}
	if role != org.RoleMember {
		t.Fatalf("alice's role = %q, want %q", role, org.RoleMember)
	}

	if _, err := f.ist.FindEmailInvite(context.Background(), inv.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("post-accept invite lookup err = %v, want ErrInviteNotFound", err)
	}
}

// TestAcceptInviteSecondPresentationOfTheSameTokenIsRefused replaces an
// earlier "accepting twice is a no-op" test that pinned the WRONG design.
// AcceptInvite used to grant the membership first and delete the invite
// second, on the theory that a delete failure left a retryable row behind —
// but nothing actually claimed the invite before admitting, so while the row
// lived, the token stayed redeemable by anyone holding it, not merely by the
// original caller retrying (reproduced live: 14 of 400 concurrent rounds
// admitted two distinct subjects from one invitation, no fault injection
// needed — see TestAcceptInviteConcurrentCallsAdmitExactlyOneSubject below).
//
// With claim-first (delete via [Store.DeleteEmailInvite]'s rows-affected
// contract, then grant), the invite is a genuine one-time credential: the
// first AcceptInvite call claims and consumes it, and a second presentation
// of the SAME token — a deliberate retry by the same subject, or anyone else
// who obtained the token — finds nothing left to claim.
// [invite.ErrInviteNotFound] is the sentinel chosen because it is exactly
// what DeleteEmailInvite's own contract already returns for "no row
// matched" (invite/invite.go), and losing the claim race is indistinguishable
// from the token never having existed at all — the same framing
// [Store.ConsumeLink] already uses for a link's losing callers.
func TestAcceptInviteSecondPresentationOfTheSameTokenIsRefused(t *testing.T) {
	f := newFixture(t)
	_, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "alice@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}

	if _, err := f.isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token); err != nil {
		t.Fatalf("first AcceptInvite: %v", err)
	}

	if _, err := f.isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("second AcceptInvite with the same token err = %v, want ErrInviteNotFound", err)
	}

	members, err := f.sc.ListMembers(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	n := 0
	for _, m := range members {
		if m.MemberUser() == "alice" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("alice has %d membership rows, want exactly 1 — the refused retry must not admit her again", n)
	}
}

// TestAcceptInviteConcurrentCallsAdmitExactlyOneSubject is the test the
// review found missing, and the one that first demonstrated the Critical:
// n distinct, previously-unseen subjects all present the SAME one-time
// token at once. A one-time email invitation is, in effect, a MaxUses:1
// credential; this is AcceptInvite's counterpart to
// TestJoinViaLinkConcurrentCallsNeverExceedMaxUses, and it does not need any
// fault injection to fail against the grant-first ordering — that ordering
// left the token redeemable by anyone holding it for as long as the row
// existed, with no claim step gating admission at all.
//
// # This is NOT the load-bearing regression net — see the deterministic test below
//
// Unlike TestJoinViaLinkConcurrentCallsNeverExceedMaxUses' mutation (which
// fails 100% of runs, since the reversed link order removes GrantMembership's
// gate entirely), this one is a genuine race and is NOT deterministic per
// run: only a candidate whose own FindEmailInviteByTokenHash executes before
// the eventual winner's delete removes the row gets far enough to exploit
// grant-first at all, and store/memory's find is a mutex-held linear scan
// fast enough that one goroutine frequently runs the whole find-grant-delete
// sequence before a second one is even scheduled. Measured directly against
// the grant-first mutation at n=400: this implementer measured 6 of 10 runs
// failing (joined=2), 4 of 10 passing (joined=1); an independent reviewer
// measured 4 of 10 failing on their own run. Raising n to 2000 did not
// meaningfully improve the hit rate (3 of 10 failed) — the window is bounded
// by scheduling, not by how many candidates are waiting behind it. A 40-60%
// detector is a real signal — well above what "run it a few times" would
// miss — but the plan's single most important invariant should not rest on
// one alone when a deterministic alternative is cheap; see
// TestAcceptInviteInterleavedClaimIsDeterministicallyRefused, which forces
// the exact interleaving instead of hoping the scheduler produces it. This
// test is kept anyway because it exercises real contention at low cost and
// is a second, independent line of evidence — but it is not what this
// invariant's regression protection depends on. This is the same class of
// caveat store/memory's own TestInviteStoreSatisfiesTheStoreContract
// documents for a different mutation: a green run here is evidence the
// happy path works, and a red run is unambiguous proof of the bug, but a
// lone green run under a SUSPECTED regression is not proof the regression is
// absent.
func TestAcceptInviteConcurrentCallsAdmitExactlyOneSubject(t *testing.T) {
	f := newFixture(t)
	_, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "shared@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}

	const n = 400
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			<-start
			_, _ = f.isvc.AcceptInvite(scope.WithSubject(context.Background(), fmt.Sprintf("candidate%d", i)), token)
		}(i)
	}
	close(start)
	wg.Wait()

	members, err := f.sc.ListMembers(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	joined := 0
	for _, m := range members {
		if strings.HasPrefix(m.MemberUser(), "candidate") {
			joined++
		}
	}
	if joined != 1 {
		t.Fatalf("joined = %d of %d concurrent candidates presenting the SAME one-time token, want exactly 1", joined, n)
	}
}

// blockingFirstFindStore wraps a real Store, embedding it so every method is
// the genuine implementation — no fault injection anywhere — except
// FindEmailInviteByTokenHash, which always performs the real read first and
// then, on the FIRST call only, signals ready and blocks until released
// before returning the answer it already fetched. Performing the real read
// before parking is what makes the caller genuinely "hold" a valid, unclaimed
// record while parked, rather than being paused before ever reading one — the
// latter would let a competing claim delete the row before this call even
// looks at it, proving nothing about the ordering under test.
//
// "First" is decided by an atomic counter rather than sync.Once
// deliberately: sync.Once.Do serializes EVERY caller through the guarded
// section, not just the one racing to be first, so a second, unrelated call
// (alice's, below) would itself block behind the parked first caller and the
// test would deadlock — nobody left to call release. An atomic counter lets
// exactly one call block while every other call proceeds normally.
type blockingFirstFindStore struct {
	invite.Store
	calls   atomic.Int64
	ready   chan struct{}
	release chan struct{}
}

func (s *blockingFirstFindStore) FindEmailInviteByTokenHash(ctx context.Context, tokenHash string) (invite.EmailInvite, error) {
	// The real read happens FIRST, so the parked caller is holding an
	// already-fetched, valid, unclaimed record — not paused before ever
	// reading one, which would let a competing claim delete the row out from
	// under a find that has not happened yet and prove nothing about the
	// ordering under test.
	inv, err := s.Store.FindEmailInviteByTokenHash(ctx, tokenHash)
	if s.calls.Add(1) == 1 {
		close(s.ready)
		<-s.release
	}
	return inv, err
}

// TestAcceptInviteInterleavedClaimIsDeterministicallyRefused is the
// load-bearing regression net for the ordering fix — not
// TestAcceptInviteConcurrentCallsAdmitExactlyOneSubject above, whose
// grant-first detection rate measured 40-60% across two independent runs
// (this implementer's and the reviewer's), well short of the certainty this
// invariant deserves. This test forces the exact interleaving that
// demonstrates the bug instead of hoping Go's scheduler produces it: bob's
// AcceptInvite is parked, via blockingFirstFindStore, at the instant right
// after he has read a valid, unclaimed invitation record and right before he
// would claim it, while alice's AcceptInvite runs to completion on the main
// goroutine. Every method other than the one find call is the real Store —
// this is the leakyInviteStore technique from an earlier round of this task,
// reused for the opposite purpose: pinning a specific interleaving rather
// than faking a failure. Worth reaching for again wherever a probabilistic
// concurrency test's detection rate is in doubt.
//
// Measured against the reverted (grant-first) mutation: this test fails
// EVERY run, not most — see the mutation-check output in task-6-report.md.
func TestAcceptInviteInterleavedClaimIsDeterministicallyRefused(t *testing.T) {
	ac := org.NewAccess(nil)
	sst := memory.New[org.Organization, org.Member]()
	sc := scope.New[org.Organization, org.Member](ac, sst)
	bs := &blockingFirstFindStore{
		Store:   memory.NewInviteStore(),
		ready:   make(chan struct{}),
		release: make(chan struct{}),
	}
	isvc := invite.New(sc, bs)

	octx := scope.WithSubject(context.Background(), "owner")
	c, err := sc.CreateContainer(octx, org.Organization{Name: "Acme", Slug: "acme-interleave"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	cctx := scope.WithScope(octx, c.ContainerID())

	_, token, err := isvc.InviteByEmail(cctx, "shared@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}

	bobErr := make(chan error, 1)
	go func() {
		_, err := isvc.AcceptInvite(scope.WithSubject(context.Background(), "bob"), token)
		bobErr <- err
	}()

	// Wait for bob to have read (and hold) the invitation record, unclaimed.
	<-bs.ready

	if _, err := isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token); err != nil {
		t.Fatalf("alice's AcceptInvite: %v", err)
	}

	// Release bob only after alice has already claimed the invite.
	close(bs.release)
	if err := <-bobErr; !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("bob's AcceptInvite err = %v, want ErrInviteNotFound — alice already claimed the invite", err)
	}

	members, err := sc.ListMembers(cctx)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	admitted := map[string]bool{}
	for _, m := range members {
		admitted[m.MemberUser()] = true
	}
	if admitted["alice"] == admitted["bob"] {
		t.Fatalf("admitted alice=%v bob=%v, want exactly one of them admitted", admitted["alice"], admitted["bob"])
	}
}

// TestAcceptInviteForExistingLowerRoleMemberDoesNotPromote pins the
// documented sharp edge of folding scope.ErrAlreadyMember to success: a
// member who already holds a role BELOW the invitation's is not promoted,
// gets no error, and the invitation is still consumed (never over-privileges,
// can silently under-deliver an intended promotion — see AcceptInvite's own
// doc comment).
func TestAcceptInviteForExistingLowerRoleMemberDoesNotPromote(t *testing.T) {
	f := newFixture(t)
	f.addMember("alice", org.RoleMember)

	inv, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "alice@example.com", org.RoleAdmin)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}

	c, err := f.isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token)
	if err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}
	if c.ContainerID() != f.cID {
		t.Fatalf("container = %s, want %s", c.ContainerID(), f.cID)
	}

	members, err := f.sc.ListMembers(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	role, ok := memberRole(members, "alice")
	if !ok {
		t.Fatal("alice is no longer a member")
	}
	if role != org.RoleMember {
		t.Fatalf("alice's role = %q, want %q (unchanged — folding ErrAlreadyMember must not promote)", role, org.RoleMember)
	}

	if _, err := f.ist.FindEmailInvite(context.Background(), inv.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("post-accept invite lookup err = %v, want ErrInviteNotFound — the invite is consumed even though it did not promote", err)
	}
}

func TestAcceptInviteExpiredTokenDoesNotAdmit(t *testing.T) {
	f := newFixture(t, invite.WithInviteExpiry(time.Nanosecond))
	_, token, err := f.isvc.InviteByEmail(f.ctx("owner"), "alice@example.com", org.RoleMember)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	if _, err := f.isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token); !errors.Is(err, invite.ErrInviteExpired) {
		t.Fatalf("AcceptInvite err = %v, want ErrInviteExpired", err)
	}
	if _, _, err := f.sc.Standing(context.Background(), f.cID, "alice"); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("alice was admitted despite an expired token: Standing err = %v, want ErrNotMember", err)
	}
}

// TestAcceptInviteRecheckInviterOnAcceptRefusesADemotedInviter pins the
// default (true) behaviour of WithRecheckInviterOnAccept: admin1 mints an
// admin-level invite while still an admin, is demoted to member before alice
// ever accepts, and the still-pending invite must die with
// scope.ErrPrivilegeEscalation rather than pay out at a role admin1 can no
// longer grant.
func TestAcceptInviteRecheckInviterOnAcceptRefusesADemotedInviter(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)

	_, token, err := f.isvc.InviteByEmail(f.ctx("admin1"), "alice@example.com", org.RoleAdmin)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}

	if err := f.sc.ChangeMemberRole(f.ctx("owner"), "admin1", org.RoleMember); err != nil {
		t.Fatalf("ChangeMemberRole (demoting admin1): %v", err)
	}

	if _, err := f.isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("AcceptInvite err = %v, want ErrPrivilegeEscalation", err)
	}
	if _, _, err := f.sc.Standing(context.Background(), f.cID, "alice"); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("alice was admitted despite the inviter's demotion: Standing err = %v, want ErrNotMember", err)
	}
}

// TestAcceptInviteWithRecheckOffHonoursADemotedInvitersInvite is the mirror
// of the test above with the knob turned off: the identical demotion must no
// longer block acceptance, and alice is admitted at the role admin1 minted
// the invite for, not admin1's current (lower) role.
func TestAcceptInviteWithRecheckOffHonoursADemotedInvitersInvite(t *testing.T) {
	f := newFixture(t, invite.WithRecheckInviterOnAccept(false))
	f.addMember("admin1", org.RoleAdmin)

	_, token, err := f.isvc.InviteByEmail(f.ctx("admin1"), "alice@example.com", org.RoleAdmin)
	if err != nil {
		t.Fatalf("InviteByEmail: %v", err)
	}

	if err := f.sc.ChangeMemberRole(f.ctx("owner"), "admin1", org.RoleMember); err != nil {
		t.Fatalf("ChangeMemberRole (demoting admin1): %v", err)
	}

	if _, err := f.isvc.AcceptInvite(scope.WithSubject(context.Background(), "alice"), token); err != nil {
		t.Fatalf("AcceptInvite with the recheck disabled: %v", err)
	}

	members, err := f.sc.ListMembers(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	role, ok := memberRole(members, "alice")
	if !ok {
		t.Fatal("alice was not admitted despite the recheck being disabled")
	}
	if role != org.RoleAdmin {
		t.Fatalf("alice's role = %q, want %q", role, org.RoleAdmin)
	}
}

// ── JoinViaLink ──────────────────────────────────────────────────────────────

func TestJoinViaLinkAdmitsAtLinkRole(t *testing.T) {
	f := newFixture(t)
	_, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	c, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "alice"), code)
	if err != nil {
		t.Fatalf("JoinViaLink: %v", err)
	}
	if c.ContainerID() != f.cID {
		t.Fatalf("JoinViaLink container = %s, want %s", c.ContainerID(), f.cID)
	}

	members, err := f.sc.ListMembers(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	role, ok := memberRole(members, "alice")
	if !ok || role != org.RoleMember {
		t.Fatalf("alice's role = %q found=%v, want %q", role, ok, org.RoleMember)
	}
}

func TestJoinViaLinkRefusesARevokedLink(t *testing.T) {
	f := newFixture(t)
	l, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if err := f.isvc.RevokeLink(f.ctx("owner"), l.ID); err != nil {
		t.Fatalf("RevokeLink: %v", err)
	}

	if _, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "alice"), code); !errors.Is(err, invite.ErrLinkRevoked) {
		t.Fatalf("JoinViaLink err = %v, want ErrLinkRevoked", err)
	}
	if _, _, err := f.sc.Standing(context.Background(), f.cID, "alice"); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("alice was admitted via a revoked link: Standing err = %v, want ErrNotMember", err)
	}
}

func TestJoinViaLinkRefusesAnExhaustedLink(t *testing.T) {
	f := newFixture(t)
	_, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 1, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if _, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "alice"), code); err != nil {
		t.Fatalf("first JoinViaLink (consuming the only use): %v", err)
	}

	if _, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "bob"), code); !errors.Is(err, invite.ErrLinkExhausted) {
		t.Fatalf("JoinViaLink err = %v, want ErrLinkExhausted", err)
	}
	if _, _, err := f.sc.Standing(context.Background(), f.cID, "bob"); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("bob was admitted via an exhausted link: Standing err = %v, want ErrNotMember", err)
	}
}

func TestJoinViaLinkRefusesAnExpiredLink(t *testing.T) {
	f := newFixture(t)
	at := time.Now().UTC().Add(time.Nanosecond)
	_, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 0, &at)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	if _, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "alice"), code); !errors.Is(err, invite.ErrLinkExpired) {
		t.Fatalf("JoinViaLink err = %v, want ErrLinkExpired", err)
	}
	if _, _, err := f.sc.Standing(context.Background(), f.cID, "alice"); !errors.Is(err, scope.ErrNotMember) {
		t.Fatalf("alice was admitted via an expired link: Standing err = %v, want ErrNotMember", err)
	}
}

// TestJoinViaLinkForExistingMemberConsumesNoUse pins spec §6.5: rejoining via
// a link you already have standing in returns the container but takes
// nothing from MaxUses. Proven two ways: UseCount stays 0 after alice's
// call, and the MaxUses:1 link is still fully available afterwards for bob,
// who is not yet a member.
func TestJoinViaLinkForExistingMemberConsumesNoUse(t *testing.T) {
	f := newFixture(t)
	f.addMember("alice", org.RoleMember)
	l, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 1, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	c, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "alice"), code)
	if err != nil {
		t.Fatalf("JoinViaLink: %v", err)
	}
	if c.ContainerID() != f.cID {
		t.Fatalf("container = %s, want %s", c.ContainerID(), f.cID)
	}

	got, err := f.ist.FindLink(context.Background(), l.ID)
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.UseCount != 0 {
		t.Fatalf("UseCount = %d, want 0 — rejoining an existing member must not consume a use", got.UseCount)
	}

	if _, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "bob"), code); err != nil {
		t.Fatalf("bob's JoinViaLink against the still-unused MaxUses:1 link: %v", err)
	}
}

// TestJoinViaLinkRecheckInviterOnAcceptRefusesADemotedCreator is JoinViaLink's
// counterpart to TestAcceptInviteRecheckInviterOnAcceptRefusesADemotedInviter:
// the same guardEscalation call backs both AcceptInvite and JoinViaLink, and
// this pins that the link path is not somehow exempt.
func TestJoinViaLinkRecheckInviterOnAcceptRefusesADemotedCreator(t *testing.T) {
	f := newFixture(t)
	f.addMember("admin1", org.RoleAdmin)

	_, code, err := f.isvc.CreateLink(f.ctx("admin1"), org.RoleAdmin, 0, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if err := f.sc.ChangeMemberRole(f.ctx("owner"), "admin1", org.RoleMember); err != nil {
		t.Fatalf("ChangeMemberRole (demoting admin1): %v", err)
	}

	if _, err := f.isvc.JoinViaLink(scope.WithSubject(context.Background(), "alice"), code); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("JoinViaLink err = %v, want ErrPrivilegeEscalation", err)
	}
}

// TestJoinViaLinkConcurrentCallsNeverExceedMaxUses is the mandatory mutation-3
// pin from the task brief: it must fail if JoinViaLink's ordering is reversed
// to grant the membership before consuming the link's use.
//
// n distinct, previously-unseen users hit a MaxUses:1 link at once. With the
// ordering this test is written against — consume first, grant second — the
// atomic ConsumeLink (already exercised by invitetest's
// ConsumeLink/ConcurrentCallersAdmitExactlyOneWinner, which both backends
// run) admits at most one winner
// through to GrantMembership, so at most one of the n candidates can ever
// become a real member.
//
// Reversing the order breaks that guarantee in a way this test catches
// reliably, not by chance: every one of the n candidates is a distinct user
// GrantMembership has never seen, so with the grant moved ahead of the
// consume check, EVERY goroutine passes GrantMembership unconditionally —
// there is no ErrAlreadyMember to collide on — before any of them touch the
// link's use count at all. That is unlike store/memory's own concurrency
// test, which pins a sub-microsecond lock-reacquisition window inside a
// single atomic primitive and is flaky-clean under a naive read-then-write
// mutation; here the reversal removes the gate entirely; so under the
// mutation essentially all n candidates land as real members, not
// occasionally more than one. The assertion below checks actual membership
// rows, not how many calls merely reported success, precisely because a
// reversed implementation could still return an error to the losers of the
// consume race after already granting them a membership behind the scenes.
func TestJoinViaLinkConcurrentCallsNeverExceedMaxUses(t *testing.T) {
	f := newFixture(t)
	_, code, err := f.isvc.CreateLink(f.ctx("owner"), org.RoleMember, 1, nil)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	const n = 300
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			<-start
			_, _ = f.isvc.JoinViaLink(scope.WithSubject(context.Background(), fmt.Sprintf("candidate%d", i)), code)
		}(i)
	}
	close(start)
	wg.Wait()

	members, err := f.sc.ListMembers(f.ctx("owner"))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	joined := 0
	for _, m := range members {
		if strings.HasPrefix(m.MemberUser(), "candidate") {
			joined++
		}
	}
	if joined != 1 {
		t.Fatalf("joined = %d of %d concurrent candidates against a MaxUses:1 link, want exactly 1", joined, n)
	}
}
