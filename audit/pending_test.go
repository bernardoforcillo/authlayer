package audit_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bernardoforcillo/authlayer/audit"
)

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
