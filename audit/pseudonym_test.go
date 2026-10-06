package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func newPseudonymous(t *testing.T) (*audit.Service, *memory.AuditStore, *memory.AuditKeyStore) {
	t.Helper()
	st, ks, clk := memory.NewAuditStore(), memory.NewAuditKeyStore(), &testClock{now: t0}
	svc := audit.New(st, audit.WithSubjectKeys(ks), audit.WithRuntime(core.Runtime{Clock: clk.Now}),
		audit.WithTopics(audit.Topic{Key: "menus"}))
	return svc, st, ks
}

func TestPseudonymsReplacePeopleAtWriteTime(t *testing.T) {
	svc, st, _ := newPseudonymous(t)
	ctx := context.Background()
	e, err := svc.Record(ctx, action(func(e *audit.Event) {
		e.Outcome = audit.OutcomeOK
		e.Actor.Display = "alice@example.com"
		e.OnBehalfOf = "bob"
		e.Resource = audit.Resource{Type: audit.ResourceUser, ID: "carol"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := st.Get(ctx, e.ID)
	for _, v := range []string{stored.Actor.ID, stored.OnBehalfOf, stored.Resource.ID} {
		if !strings.HasPrefix(v, audit.PseudonymPrefix) {
			t.Errorf("stored id %q is not a pseudonym", v)
		}
	}
	if stored.Actor.Display != "" || stored.Actor.ID == "alice" {
		t.Errorf("stored actor = %+v", stored.Actor)
	}
	if p, err := svc.Pseudonym(ctx, "alice"); err != nil || p != stored.Actor.ID {
		t.Errorf("Pseudonym(alice) = %q, %v; want %q", p, err, stored.Actor.ID)
	}
	// Not people: system and service accounts keep their ids.
	sys, _ := svc.Record(ctx, action(func(e *audit.Event) {
		e.Outcome = audit.OutcomeOK
		e.Actor = audit.Actor{Type: audit.ActorSystem, ID: "reaper"}
	}))
	if sys.Actor.ID != "reaper" {
		t.Errorf("system actor = %q", sys.Actor.ID)
	}
}

func TestFiltersTakeRealIdsAndForgetMakesTheTrailUnreachable(t *testing.T) {
	svc, st, ks := newPseudonymous(t)
	ctx := context.Background()
	for _, who := range []string{"alice", "alice", "bob"} {
		if _, err := svc.Record(ctx, action(func(e *audit.Event) {
			e.Outcome, e.Actor.ID = audit.OutcomeOK, who
		})); err != nil {
			t.Fatal(err)
		}
	}
	about, _ := svc.Record(ctx, action(func(e *audit.Event) {
		e.Outcome, e.Actor.ID = audit.OutcomeOK, "bob"
		e.Resource = audit.Resource{Type: audit.ResourceUser, ID: "alice"}
	}))
	trail := func(f audit.Filter) int {
		t.Helper()
		got, _, err := svc.List(ctx, f, audit.Page{})
		if err != nil {
			t.Fatal(err)
		}
		return len(got)
	}
	if n := trail(audit.Filter{Member: "alice"}); n != 3 {
		t.Errorf("alice's trail = %d, want 3 (two by her, one about her)", n)
	}
	if n := trail(audit.Filter{ActorID: "bob"}); n != 2 {
		t.Errorf("bob as actor = %d, want 2", n)
	}
	if n := trail(audit.Filter{Resource: audit.Resource{Type: audit.ResourceUser, ID: "alice"}}); n != 1 {
		t.Errorf("events about alice = %d, want 1", n)
	}
	var exported int
	if err := svc.Export(ctx, audit.Filter{Member: "alice"}, 10, func(audit.Event) error { exported++; return nil }); err != nil || exported != 3 {
		t.Errorf("Export = %d, %v; want 3", exported, err)
	}

	if err := svc.Forget(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Forget(ctx, "alice"); err != nil {
		t.Errorf("second Forget = %v, want idempotent", err)
	}
	if n := trail(audit.Filter{Member: "alice"}); n != 0 {
		t.Errorf("alice's trail after Forget = %d, want 0", n)
	}
	if _, err := svc.Pseudonym(ctx, "alice"); !errors.Is(err, audit.ErrForgotten) {
		t.Errorf("Pseudonym after Forget err = %v, want ErrForgotten", err)
	}
	// The events and bob's trail are intact; only the link to alice is gone.
	if n, _ := st.Count(ctx, audit.Filter{}); n != 4 {
		t.Errorf("events = %d, want all 4 kept", n)
	}
	if n := trail(audit.Filter{ActorID: "bob"}); n != 2 {
		t.Errorf("bob after alice's Forget = %d, want 2", n)
	}
	// A later event about her — the deletion itself — carries the shared
	// erased label, not a fresh key that would make her traceable again.
	again, _ := svc.Record(ctx, action(func(e *audit.Event) { e.Outcome, e.Actor.ID = audit.OutcomeOK, "alice" }))
	if again.Actor.ID != audit.ErasedPseudonym || again.Actor.ID == about.Resource.ID {
		t.Errorf("event after Forget carries %q, want %q", again.Actor.ID, audit.ErasedPseudonym)
	}
	if _, err := ks.Key(ctx, "alice"); !errors.Is(err, audit.ErrForgotten) {
		t.Errorf("a key was minted after Forget: %v", err)
	}
}

func TestCompletePseudonymizesAFilledUserResource(t *testing.T) {
	svc, st, _ := newPseudonymous(t)
	ctx := context.Background()
	open, _ := svc.Begin(ctx, action())
	if err := svc.Complete(ctx, open.ID, audit.Completion{Outcome: audit.OutcomeOK,
		Resource: audit.Resource{Type: audit.ResourceUser, ID: "carol"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(ctx, open.ID)
	if got.Resource.ID == "carol" || !strings.HasPrefix(got.Resource.ID, audit.PseudonymPrefix) {
		t.Errorf("resource = %+v", got.Resource)
	}
}

func TestForgetWithoutKeysIsInvalid(t *testing.T) {
	svc, _, _ := newService(t)
	if err := svc.Forget(context.Background(), "alice"); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Errorf("Forget err = %v, want ErrInvalidEvent", err)
	}
}
