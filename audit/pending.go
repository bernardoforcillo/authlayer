package audit

import (
	"context"
	"encoding/json"
	"sync"
)

type pendingKey struct{}

// Pending collects what code running inside an action adds to its event
// before completion. The interceptor that called Begin creates it, puts it on
// the context with WithPending, and turns it into a Completion afterwards.
// It is safe for concurrent use.
type Pending struct {
	mu          sync.Mutex
	id          string
	resource    Resource
	containerID string
	reason      string
	before      json.RawMessage
	after       json.RawMessage
}

// NewPending returns the collector for the open event id.
func NewPending(id string) *Pending { return &Pending{id: id} }

// ID is the open event's id.
func (p *Pending) ID() string { return p.id }

// WithPending returns ctx carrying p.
func WithPending(ctx context.Context, p *Pending) context.Context {
	return context.WithValue(ctx, pendingKey{}, p)
}

// PendingFrom returns the pending event on ctx, if any.
func PendingFrom(ctx context.Context) (*Pending, bool) {
	p, ok := ctx.Value(pendingKey{}).(*Pending)
	return p, ok && p != nil
}

// Annotation adds one fact to a pending event.
type Annotation func(*Pending)

// WithResource names the resource the action touched. The first annotation
// wins: the action's own target, not a side effect's.
func WithResource(typ, id string) Annotation {
	return func(p *Pending) {
		if p.resource == (Resource{}) {
			p.resource = Resource{Type: typ, ID: id}
		}
	}
}

// WithContainer names the tenant acted upon. The first annotation wins.
func WithContainer(id string) Annotation {
	return func(p *Pending) {
		if p.containerID == "" {
			p.containerID = id
		}
	}
}

// WithReason sets the closed-vocabulary reason. The last annotation wins.
func WithReason(reason string) Annotation {
	return func(p *Pending) { p.reason = reason }
}

// WithChanges records the touched resource's state around the action, as
// JSON. The Service redacts both sides and stores their Diff. The last
// annotation wins.
func WithChanges(before, after json.RawMessage) Annotation {
	return func(p *Pending) { p.before, p.after = before, after }
}

// Annotate applies anns to the pending event on ctx and reports whether there
// was one. Without a pending event it does nothing, so code may annotate
// unconditionally.
func Annotate(ctx context.Context, anns ...Annotation) bool {
	p, ok := PendingFrom(ctx)
	if !ok {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range anns {
		if a != nil {
			a(p)
		}
	}
	return true
}

// Completion returns what the annotations collected, with the outcome, code
// and duration the caller observed.
func (p *Pending) Completion(outcome Outcome, code string, durationMS int64) Completion {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Completion{
		Outcome: outcome, Code: code, Reason: p.reason,
		Before: p.before, After: p.after,
		Resource: p.resource, ContainerID: p.containerID, DurationMS: durationMS,
	}
}
