package scope

import (
	"context"
	"errors"
	"testing"
)

var errVetoed = errors.New("vetoed")

func TestDeciderVetoesBeforeAnyWrite(t *testing.T) {
	var seen []Mutation
	svc := newTestService(WithDecider(DeciderFunc(func(_ context.Context, m Mutation) error {
		seen = append(seen, m)
		if m.Kind == OwnershipTransferred {
			return errVetoed
		}
		return nil
	})))
	octx, c := ownerCtx(t, svc, "alice")

	if _, err := svc.AddMember(octx, "bob", RoleMember); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := svc.TransferOwnership(octx, "bob"); !errors.Is(err, errVetoed) {
		t.Fatalf("TransferOwnership err = %v, want veto", err)
	}
	got, _ := svc.Container(octx, c.ContainerID())
	if got.ContainerOwner() != "alice" {
		t.Fatalf("owner = %q after a vetoed transfer", got.ContainerOwner())
	}
	kinds := []EventKind{}
	for _, m := range seen {
		kinds = append(kinds, m.Kind)
	}
	if len(kinds) != 3 || kinds[0] != ContainerCreated || kinds[1] != MemberAdded || kinds[2] != OwnershipTransferred {
		t.Fatalf("decider saw %v", kinds)
	}
}

func TestDeciderCannotGrantWhatTheEngineRefuses(t *testing.T) {
	svc := newTestService(WithDecider(DeciderFunc(func(context.Context, Mutation) error { return nil })))
	octx, _ := ownerCtx(t, svc, "alice")
	// bob is not a member, so he cannot add anyone, whatever the decider says.
	bctx := WithSubject(octx, "bob")
	if _, err := svc.AddMember(bctx, "carol", RoleMember); err == nil {
		t.Fatal("an allowing Decider let a non-member add a member")
	}
}

func TestRemoveUserRefusesOwnedContainersByDefault(t *testing.T) {
	svc := newTestService()
	octx, _ := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveUser(context.Background(), "alice"); !errors.Is(err, ErrOwnsContainer) {
		t.Fatalf("err = %v, want ErrOwnsContainer", err)
	}
	// Nothing changed.
	cs, _ := svc.store.ListUserContainers(context.Background(), "alice")
	if len(cs) != 1 {
		t.Fatalf("alice has %d containers after a refused removal", len(cs))
	}
}

func TestRemoveUserTransfersOwnershipThenRemoves(t *testing.T) {
	var events []Event
	svc := newTestService(
		WithOrphanPolicy(SuccessorFirstMember),
		WithHooks(HookFunc(func(_ context.Context, e Event) error { events = append(events, e); return nil })),
	)
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleMember); err != nil {
		t.Fatal(err)
	}
	// alice is also a plain member of someone else's container.
	cctx, c2 := ownerCtx(t, svc, "carol")
	if _, err := svc.AddMember(cctx, "alice", RoleMember); err != nil {
		t.Fatal(err)
	}
	events = nil

	if err := svc.RemoveUser(context.Background(), "alice"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	ctx := context.Background()
	got, _ := svc.store.FindContainer(ctx, c.ContainerID())
	if got.ContainerOwner() != "bob" {
		t.Fatalf("owner = %q, want bob", got.ContainerOwner())
	}
	if cs, _ := svc.store.ListUserContainers(ctx, "alice"); len(cs) != 0 {
		t.Fatalf("alice still in %d containers", len(cs))
	}
	if m, _ := svc.store.ListMembers(ctx, c2.ContainerID()); len(m) != 1 {
		t.Fatalf("carol's container has %d members, want 1", len(m))
	}
	var transfers, removals int
	for _, e := range events {
		switch e.Kind {
		case OwnershipTransferred:
			transfers++
		case MemberRemoved:
			removals++
			if e.ActorID != "" {
				t.Fatalf("system removal carries actor %q", e.ActorID)
			}
		}
	}
	if transfers != 1 || removals != 2 {
		t.Fatalf("events: %d transfers, %d removals", transfers, removals)
	}
}

func TestRemoveUserSoleOwnerAndBadSuccessor(t *testing.T) {
	ctx := context.Background()
	solo := newTestService(WithOrphanPolicy(SuccessorFirstMember))
	ownerCtx(t, solo, "alice")
	if err := solo.RemoveUser(ctx, "alice"); !errors.Is(err, ErrOwnsContainer) {
		t.Fatalf("sole owner err = %v, want ErrOwnsContainer", err)
	}

	bad := newTestService(WithOrphanPolicy(func(context.Context, string, []string) (Resolution, error) {
		return Resolution{Successor: "mallory"}, nil
	}))
	octx, _ := ownerCtx(t, bad, "alice")
	bad.AddMember(octx, "bob", RoleMember)
	if err := bad.RemoveUser(ctx, "alice"); !errors.Is(err, ErrBadSuccessor) {
		t.Fatalf("outsider successor err = %v, want ErrBadSuccessor", err)
	}

	abandon := newTestService(WithOrphanPolicy(func(context.Context, string, []string) (Resolution, error) {
		return Resolution{Abandon: true}, nil
	}))
	ownerCtx(t, abandon, "alice")
	if err := abandon.RemoveUser(ctx, "alice"); err != nil {
		t.Fatalf("abandon: %v", err)
	}
}
