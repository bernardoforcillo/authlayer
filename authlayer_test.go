package authlayer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func TestSharedRuntimeReachesModules(t *testing.T) {
	at := time.Date(2030, 5, 6, 7, 8, 9, 0, time.UTC)
	sh := authlayer.Shared{Runtime: core.Runtime{
		Clock: func() time.Time { return at },
		IDs:   func() string { return "fixed-id" },
	}}
	store := memory.NewAuthStore()
	svc := auth.New(store, sh.Auth(), auth.WithHasher(password.Bcrypt(4)))

	res, err := svc.SignUp(context.Background(), "a@example.com", "Correct-Horse-Battery-9")
	if err != nil || !res.Created {
		t.Fatalf("SignUp = %+v, %v", res, err)
	}
	if !res.User.CreatedAt.Equal(at) || res.User.ID != "fixed-id" {
		t.Fatalf("user = %+v, want the shared clock and id", res.User)
	}
	// The other modules' adapters exist and are usable as options.
	_, _, _ = sh.Scope(), sh.APIKey(), sh.OAuth()
}

func TestAccountRemovalLeavesContainers(t *testing.T) {
	ctx := context.Background()
	orgs := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member]())
	svc := auth.New(memory.NewAuthStore(),
		auth.WithHasher(password.Bcrypt(4)),
		auth.WithSweeper(authlayer.RemoveUserSweeper(orgs)),
	)
	const pw = "Correct-Horse-Battery-9"
	alice, _ := svc.SignUp(ctx, "alice@example.com", pw)
	bob, _ := svc.SignUp(ctx, "bob@example.com", pw)

	actx := org.WithSubject(ctx, alice.User.ID)
	o, err := orgs.CreateOrganization(actx, "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	octx := org.WithOrg(actx, o.ID)
	if _, err := orgs.AddMember(octx, bob.User.ID, org.RoleMember); err != nil {
		t.Fatal(err)
	}

	// Bob is a plain member: deleting him just removes the membership.
	if err := svc.DeleteAccount(ctx, bob.User.ID, "", pw); err != nil {
		t.Fatalf("DeleteAccount(bob): %v", err)
	}
	if ms, _ := orgs.ListMembers(octx); len(ms) != 1 {
		t.Fatalf("members after bob left = %d, want 1", len(ms))
	}

	// Alice owns the organization: the default policy refuses, and the
	// account survives.
	if err := svc.DeleteAccount(ctx, alice.User.ID, "", pw); !errors.Is(err, scope.ErrOwnsContainer) {
		t.Fatalf("DeleteAccount(alice) err = %v, want ErrOwnsContainer", err)
	}
	if _, err := svc.User(ctx, alice.User.ID); err != nil {
		t.Fatalf("alice's account was deleted despite the refusal: %v", err)
	}
}
