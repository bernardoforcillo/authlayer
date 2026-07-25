// Command basic is a runnable, database-free tour of authlayer's organization
// RBAC: code-defined statements and default roles, per-organization custom
// roles, permission checks, and the privilege-escalation guard — all backed by
// the in-memory store.
//
//	go run ./examples/basic
package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func main() {
	// 1. Declare the app's own permission surface on top of the built-in
	//    organization/member/role control statements, then wire a Service.
	ac := org.NewAccess(map[string][]access.Action{
		"project": {"create", "read", "update", "delete"},
	})
	svc := org.New(ac, memory.New[org.Organization, org.Member]())

	// 2. alice creates an organization; she becomes its owner.
	ctx := org.WithSubject(context.Background(), "alice")
	acme, err := svc.CreateOrganization(ctx, "Acme", "acme")
	must(err)
	fmt.Printf("created org %q owned by alice\n", acme.Name)

	// From here on, operations run in alice's context scoped to the org.
	alice := org.WithOrg(ctx, acme.ID)

	// 3. alice adds bob as admin and carol as a plain member.
	_, err = svc.AddMember(alice, "bob", org.RoleAdmin)
	must(err)
	_, err = svc.AddMember(alice, "carol", org.RoleMember)
	must(err)
	fmt.Println("added bob (admin) and carol (member)")

	// 4. Permission checks read subject + org from the context.
	bob := org.WithOrg(org.WithSubject(context.Background(), "bob"), acme.ID)
	carol := org.WithOrg(org.WithSubject(context.Background(), "carol"), acme.ID)
	report("bob   member:create", can(svc, bob, org.ResourceMember, org.ActionCreate))
	report("bob   org:delete    ", can(svc, bob, org.ResourceOrganization, org.ActionDelete))
	report("carol project:create", can(svc, carol, "project", "create"))

	// 5. alice defines a custom "editor" role and grants it to carol.
	_, err = svc.CreateRole(alice, "editor", "Editor", map[string][]access.Action{
		"project": {"create", "update"},
	})
	must(err)
	must(svc.ChangeMemberRole(alice, "carol", "editor"))
	report("carol project:create (now editor)", can(svc, carol, "project", "create"))
	report("carol project:delete (not granted)", can(svc, carol, "project", "delete"))

	// 6. The privilege-escalation guard: admin bob cannot mint a role with a
	//    power he lacks (deleting the organization).
	_, err = svc.CreateRole(bob, "superadmin", "Super", map[string][]access.Action{
		org.ResourceOrganization: {org.ActionDelete},
	})
	fmt.Printf("bob creating a role beyond his powers -> %v (blocked: %t)\n",
		err, errors.Is(err, org.ErrPrivilegeEscalation))

	// 7. Query-level enforcement: org.MembershipGuard(...) returns a drops
	//    pg.Guard you mount with entity.AuthorizeWith(...) to filter a table's
	//    rows to the caller's organizations — driven by this same context.
	fmt.Println("done")
}

func can(svc *org.Service, ctx context.Context, resource string, actions ...access.Action) bool {
	ok, err := svc.Can(ctx, resource, actions...)
	must(err)
	return ok
}

func report(label string, allowed bool) {
	fmt.Printf("  %-36s %v\n", label, allowed)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
