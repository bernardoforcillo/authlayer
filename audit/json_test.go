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
		// Numbers compare by value: jsonb and other stores rewrite their spelling.
		{`{"n":1e2}`, `{"n":100}`, true},
		{`{"n":1E+2}`, `{"n":100.0}`, true},
		{`{"n":1e-7}`, `{"n":0.0000001}`, true},
		{`{"n":1.50}`, `{"n":1.5}`, true},
		{`[-0]`, `[0]`, true},
		{`{"n":12345678901234567890}`, `{"n":12345678901234567891}`, false},
		{`{"n":1e2}`, `{"n":1e3}`, false},
		{`{"n":0.1}`, `{"n":0.10000000000000001}`, false},
		{`{"n":1}`, `{"n":"1"}`, false},
		{`{"a":[1,2]}`, `{"a":[2,1]}`, false},
		// Exponents beyond int64 keep the sign and never wrap.
		{`[-1e99999999999999999999]`, `[1e99999999999999999999]`, false},
		{`[-1e99999999999999999999]`, `[-1e99999999999999999999]`, true},
		{`[-1.0e99999999999999999999]`, `[-10e99999999999999999998]`, true},
		{`[10e9223372036854775807]`, `[1e-9223372036854775808]`, false},
		{`[10e9223372036854775807]`, `[1e9223372036854775808]`, true},
		{`[1.5e-9223372036854775808]`, `[15e-9223372036854775809]`, true},
		{`[1.5e-9223372036854775808]`, `[15e9223372036854775807]`, false},
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
