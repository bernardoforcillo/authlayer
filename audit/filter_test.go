package audit_test

import (
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
)

func TestFilterMatch(t *testing.T) {
	base := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	e := audit.Event{
		Topic: "menus", Action: "menu.update", Source: audit.SourceServer,
		OccurredAt:  base,
		Actor:       audit.Actor{Type: audit.ActorUser, ID: "u1"},
		OnBehalfOf:  "u2",
		ContainerID: "org1",
		Resource:    audit.Resource{Type: "menu", ID: "m1"},
		Outcome:     audit.OutcomeOK,
	}
	open := e
	open.Outcome = ""
	login := audit.Event{Topic: "auth", Action: "auth.login_failed", OccurredAt: base,
		Actor: audit.Actor{Type: audit.ActorAnonymous}, Resource: audit.Resource{Type: audit.ResourceUser, ID: "u3"}}

	tests := []struct {
		name string
		f    audit.Filter
		e    audit.Event
		want bool
	}{
		{"empty filter matches", audit.Filter{}, e, true},
		{"topic in set", audit.Filter{Topics: []string{"auth", "menus"}}, e, true},
		{"topic not in set", audit.Filter{Topics: []string{"auth"}}, e, false},
		{"from is inclusive", audit.Filter{From: base}, e, true},
		{"to is exclusive", audit.Filter{To: base}, e, false},
		{"inside the range", audit.Filter{From: base.Add(-time.Hour), To: base.Add(time.Hour)}, e, true},
		{"container", audit.Filter{ContainerID: "org2"}, e, false},
		{"member as actor", audit.Filter{Member: "u1"}, e, true},
		{"member as impersonated user", audit.Filter{Member: "u2"}, e, true},
		{"member as user resource", audit.Filter{Member: "u3"}, login, true},
		{"member elsewhere", audit.Filter{Member: "u9"}, e, false},
		{"actor id", audit.Filter{ActorID: "u2"}, e, false},
		{"resource type", audit.Filter{Resource: audit.Resource{Type: "menu"}}, e, true},
		{"resource id", audit.Filter{Resource: audit.Resource{Type: "menu", ID: "m2"}}, e, false},
		{"outcome", audit.Filter{Outcomes: []audit.Outcome{audit.OutcomeOK}}, e, true},
		{"open events never match outcomes", audit.Filter{Outcomes: []audit.Outcome{audit.OutcomeOK}}, open, false},
		{"source", audit.Filter{Source: audit.SourceClient}, e, false},
		{"action prefix", audit.Filter{ActionPrefix: "menu."}, e, true},
		{"action prefix is literal", audit.Filter{ActionPrefix: "menu%"}, e, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Match(tt.e); got != tt.want {
				t.Errorf("Match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOutcomeValid(t *testing.T) {
	for _, o := range []audit.Outcome{audit.OutcomeOK, audit.OutcomeDenied, audit.OutcomeFailed, audit.OutcomeUnknown} {
		if !o.Valid() {
			t.Errorf("%q.Valid() = false", o)
		}
	}
	for _, o := range []audit.Outcome{"", "OK", "done"} {
		if o.Valid() {
			t.Errorf("%q.Valid() = true", o)
		}
	}
}
