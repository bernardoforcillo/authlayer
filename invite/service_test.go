package invite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
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
	ac := org.NewAccess(nil)
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
// minted would leave behind: a link naming a key ListRoles no longer
// returns.
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
// Critical finding from the Task 5 review: scope.Service.ListRoles emits the
// three code-defined defaults FIRST, then the container's stored roles.
// permissionsByRole indexes that slice into a map; building it last-write-
// wins would let a stored role row keyed with a default key (e.g. "owner")
// overwrite the real default's entry, inverting scope.Service's own
// resolveRole precedence, which always checks the code-defined registry
// BEFORE ever falling back to the store. scope.Service.CreateRole refuses to
// create such a row (ErrRoleKeyTaken), but the RoleStore port does not
// forbid it and neither store implementation rejects it independently, so
// this is seeded directly against the raw scope store to simulate a backend
// that allows it.
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
