package audit_test

import (
	"encoding/json"
	"testing"

	"github.com/bernardoforcillo/authlayer/audit"
)

func TestEqualJSON(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{`{"a":1,"b":[1,2]}`, `{ "b": [1, 2], "a": 1 }`, true},
		{`{"a":1}`, `{"a":2}`, false},
		{`{"n":12345678901234567890}`, `{"n":12345678901234567890}`, true},
		{``, ``, true},
		{``, `{}`, false},
		{`not json`, `not json`, false},
		{`{"a":1} {"b":2}`, `{"a":1}`, false},
	}
	for _, tt := range tests {
		if got := audit.EqualJSON(json.RawMessage(tt.a), json.RawMessage(tt.b)); got != tt.want {
			t.Errorf("EqualJSON(%s, %s) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSameClosing(t *testing.T) {
	e := audit.Event{Outcome: audit.OutcomeOK, Code: "", Reason: "r", DurationMS: 5,
		Changes: json.RawMessage(`{"x":{"before":1,"after":2}}`)}
	same := audit.Closing{Outcome: audit.OutcomeOK, Reason: "r", DurationMS: 5,
		Changes: json.RawMessage(`{"x":{"after":2,"before":1}}`)}
	if !audit.SameClosing(e, same) {
		t.Error("SameClosing = false for an identical closing")
	}
	other := same
	other.Outcome = audit.OutcomeFailed
	if audit.SameClosing(e, other) {
		t.Error("SameClosing = true for a different outcome")
	}
}
