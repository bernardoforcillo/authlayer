// Command apikey is a runnable, database-free tour of service accounts and
// API keys: a non-human member of an organization, a key that authenticates
// as it with a permission cap narrower than its role, and the three ways a
// key stops working — revocation, a disabled account, a deleted one.
//
//	go run ./examples/apikey
//
// Everything runs against store/memory, so there is no database and no
// setup. examples/basic covers the RBAC half on its own; this one exists
// because the interesting behaviour is at the seam between apikey and scope:
// the service account IS a member, so every Can and Authorize a request
// handler already makes works unchanged for a key.
//
// # What is deliberately NOT here
//
// A transport. authlayer returns the plaintext key to you exactly once and
// never sends it anywhere. This program prints it so the trace is readable;
// in production that string is the secret, and printing it is the one thing
// this example does that yours must not.
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func main() {
	ctx := context.Background()

	// -- 1. Wire the two services ----------------------------------------
	//
	// org/scope owns membership and permissions; apikey owns the service
	// account records and their keys. apikey.New wants the *scope.Service,
	// which org.Service embeds as .Service — the same seam invite.New uses.
	orgSvc := org.New(
		org.NewAccess(map[string][]access.Action{
			"project": {"read", "deploy", "delete"},
		}),
		memory.New[org.Organization, org.Member]())
	keySvc := apikey.New(orgSvc.Service, memory.NewAPIKeyStore())

	// -- 2. An organization, an admin, and a role for robots ---------------
	step("set up the organization")
	alice := org.WithSubject(ctx, "alice")
	acme, err := orgSvc.CreateOrganization(alice, "Acme", "acme")
	must(err)
	owner := org.WithOrg(alice, acme.ID)
	_, err = orgSvc.AddMember(owner, "bob", org.RoleAdmin)
	must(err)
	// A custom role is the honest shape for a service account: exactly what
	// the automation needs. project:read and project:deploy, nothing else.
	_, err = orgSvc.CreateRole(owner, "deployer", "Deployer", map[string][]access.Action{
		"project": {"read", "deploy"},
	})
	must(err)
	fmt.Printf("  org %q owned by alice; bob is admin; role %q = project:read,deploy\n", acme.Name, "deployer")

	// -- 3. Bob creates a service account ----------------------------------
	//
	// service_account:create sits on the control surface, so the built-in
	// admin role holds it. The escalation guard applies: bob may create an
	// account at a role within his own standing, and "deployer" is.
	step("create a service account")
	bob := org.WithOrg(org.WithSubject(ctx, "bob"), acme.ID)
	sa, err := keySvc.CreateServiceAccount(bob, "ci", "deploys from the main branch", "deployer")
	must(err)
	fmt.Printf("  service account %s (%q), role deployer, created by %s\n", short(sa.ID), sa.Name, sa.CreatedBy)
	// It is a member like any other: scope resolves its role.
	perms, _, err := orgSvc.Standing(ctx, acme.ID, sa.ID)
	must(err)
	fmt.Printf("  as a member it holds project:deploy = %v\n", perms.Allows("project", "deploy"))

	// -- 4. A key with restricted permissions ------------------------------
	//
	// The cap must sit within the account's role AND within bob's own
	// standing. The plaintext comes back exactly once; only its sha256 is
	// stored, so the record below cannot be turned back into a key.
	step("mint a restricted key")
	key, plain, err := keySvc.CreateKey(bob, sa.ID, "github-actions",
		apikey.WithPermissions(map[string][]access.Action{"project": {"read"}}))
	must(err)
	fmt.Printf("  key %s prefix %q — plaintext (deliver this once, then forget it): %s\n", short(key.ID), key.Prefix, plain)
	fmt.Printf("  stored: hash=%s... permissions=%q\n", short(key.TokenHash), key.Permissions)

	// -- 5. A key above the role is refused --------------------------------
	//
	// project:delete is not in "deployer", so a cap naming it would
	// intersect to less than it claims; the mint is refused rather than
	// stored misleadingly. The same guard refuses a cap above BOB's standing.
	step("a key above the role")
	_, _, err = keySvc.CreateKey(bob, sa.ID, "too-much",
		apikey.WithPermissions(map[string][]access.Action{"project": {"delete"}}))
	reportErr("project:delete cap on a deployer", err, scope.ErrPrivilegeEscalation, "ErrPrivilegeEscalation")

	// -- 6. Authenticate, and act ----------------------------------------
	//
	// Authenticate needs no subject on the context — the key is the
	// credential. WithPrincipal then annotates a fresh context the way
	// WithSubject and WithOrg would for a logged-in user, plus the cap.
	step("authenticate and act")
	p, err := keySvc.Authenticate(ctx, plain)
	must(err)
	fmt.Printf("  principal kind=%s id=%s key=%s capped=%v\n", p.Kind, short(p.ID), short(p.KeyID), p.Permissions != nil)
	asKey := apikey.WithPrincipal(ctx, p)
	report("project:read   (role yes, cap yes)", can(orgSvc, asKey, "project", "read"), true)
	report("project:deploy (role yes, cap no)", can(orgSvc, asKey, "project", "deploy"), false)
	report("project:delete (role no,  cap no)", can(orgSvc, asKey, "project", "delete"), false)

	// An unrestricted key acts with the whole role.
	_, full, err := keySvc.CreateKey(bob, sa.ID, "laptop")
	must(err)
	pf, err := keySvc.Authenticate(ctx, full)
	must(err)
	asFull := apikey.WithPrincipal(ctx, pf)
	report("unrestricted key project:deploy", can(orgSvc, asFull, "project", "deploy"), true)
	// ... and never more than the role: a deployer cannot manage members.
	report("unrestricted key member:create", can(orgSvc, asFull, org.ResourceMember, org.ActionCreate), false)

	// -- 7. Revoke ---------------------------------------------------------
	step("revoke")
	must(keySvc.RevokeKey(bob, key.ID))
	_, err = keySvc.Authenticate(ctx, plain)
	reportErr("revoked key", err, apikey.ErrKeyRevoked, "ErrKeyRevoked")

	// -- 8. Disable the account --------------------------------------------
	//
	// Every key of the account is refused while it is disabled — the move
	// for "something leaked, we do not yet know which key". The membership
	// and the keys are untouched, so EnableServiceAccount restores it exactly.
	step("disable the account")
	must(keySvc.DisableServiceAccount(bob, sa.ID))
	_, err = keySvc.Authenticate(ctx, full)
	reportErr("live key of a disabled account", err, apikey.ErrServiceAccountDisabled, "ErrServiceAccountDisabled")
	must(keySvc.EnableServiceAccount(bob, sa.ID))
	_, err = keySvc.Authenticate(ctx, full)
	must(err)
	fmt.Printf("  %-40s -> authenticates\n", "same key after re-enable")

	// -- 9. Delete: membership, record, keys -------------------------------
	//
	// Two stores, no cross-store transaction: the membership goes first (the
	// instant it is gone the account has no standing anywhere), then the
	// record and every key together, atomically, in the apikey store.
	step("delete the account")
	must(keySvc.DeleteServiceAccount(bob, sa.ID))
	_, err = keySvc.Authenticate(ctx, full)
	reportErr("key of a deleted account", err, apikey.ErrKeyNotFound, "ErrKeyNotFound")
	_, _, err = orgSvc.Standing(ctx, acme.ID, sa.ID)
	reportErr("membership of a deleted account", err, org.ErrNotMember, "ErrNotMember")
	accounts, err := keySvc.ListServiceAccounts(bob)
	must(err)
	fmt.Printf("  service accounts left: %d\n", len(accounts))
}

func can(svc *org.Service, ctx context.Context, resource string, action access.Action) bool {
	ok, err := svc.Can(ctx, resource, action)
	must(err)
	return ok
}

// report prints a Can answer and panics if it is not the one the tour
// promises, so the trace is also an assertion.
func report(label string, got, want bool) {
	if got != want {
		panic(fmt.Sprintf("%s: got %v, want %v", label, got, want))
	}
	fmt.Printf("  %-40s -> %v\n", label, got)
}

// reportErr prints which sentinel a refusal came back as, and panics if it
// is not the promised one.
func reportErr(label string, err, want error, name string) {
	if !errors.Is(err, want) {
		panic(fmt.Sprintf("%s: got %v, want %s", label, err, name))
	}
	fmt.Printf("  %-40s -> %s\n", label, name)
}

func step(label string) {
	fmt.Printf("\n== %s ==\n", strings.ToUpper(label))
}

// short truncates an id or hash for display. Never do this to a value you
// are comparing — only to one you are printing.
func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
