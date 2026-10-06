package audit_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bernardoforcillo/authlayer/audit"
)

func TestClaimSucceedsOnce(t *testing.T) {
	p := audit.NewPending("ev1")
	if !p.Claim() {
		t.Fatal("first Claim = false")
	}
	for i := 0; i < 2; i++ {
		if p.Claim() {
			t.Fatal("a later Claim = true")
		}
	}
	if !audit.Annotate(audit.WithPending(context.Background(), audit.NewPending("ev2"))) {
		t.Fatal("Annotate on an unclaimed pending event = false")
	}
}

func TestAnnotateCollectsIntoThePendingEvent(t *testing.T) {
	ctx := context.Background()
	if audit.Annotate(ctx, audit.WithReason("x")) {
		t.Fatal("Annotate without a pending event = true")
	}
	p := audit.NewPending("ev1")
	ctx = audit.WithPending(ctx, p)
	if got, ok := audit.PendingFrom(ctx); !ok || got != p || got.ID() != "ev1" {
		t.Fatalf("PendingFrom = %v, %v", got, ok)
	}
	ok := audit.Annotate(ctx,
		audit.WithResource("menu", "m1"), audit.WithResource("menu", "m2"),
		audit.WithContainer("org1"), audit.WithContainer("org2"),
		audit.WithReason("first"), audit.WithReason("last"),
		audit.WithChanges(json.RawMessage(`{"a":1}`), json.RawMessage(`{"a":2}`)),
	)
	if !ok {
		t.Fatal("Annotate with a pending event = false")
	}
	c := p.Completion(audit.OutcomeOK, "", 9)
	if c.Resource != (audit.Resource{Type: "menu", ID: "m1"}) || c.ContainerID != "org1" || c.Reason != "last" ||
		string(c.Before) != `{"a":1}` || string(c.After) != `{"a":2}` || c.DurationMS != 9 || c.Outcome != audit.OutcomeOK {
		t.Errorf("Completion = %+v: want the first resource and container, the last reason, the changes", c)
	}
}

func TestWithResourceFillsEachFieldOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		anns []audit.Annotation
		want audit.Resource
	}{
		{"type first, id later", []audit.Annotation{audit.WithResource("menu", ""), audit.WithResource("menu", "m2")}, audit.Resource{Type: "menu", ID: "m2"}},
		{"another type's id is not taken", []audit.Annotation{audit.WithResource("menu", ""), audit.WithResource("lot", "l1")}, audit.Resource{Type: "menu"}},
		{"first full one wins", []audit.Annotation{audit.WithResource("menu", "m1"), audit.WithResource("menu", "m2")}, audit.Resource{Type: "menu", ID: "m1"}},
	} {
		p := audit.NewPending("ev")
		audit.Annotate(audit.WithPending(context.Background(), p), tc.anns...)
		if got := p.Completion(audit.OutcomeOK, "", 0).Resource; got != tc.want {
			t.Errorf("%s: Resource = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
