package audit_test

import (
	"encoding/json"
	"testing"

	"github.com/bernardoforcillo/authlayer/audit"
)

func TestDiff(t *testing.T) {
	tests := []struct {
		name, before, after, want string
	}{
		{"update", `{"a":1,"b":{"c":"x"},"l":[1,2]}`, `{"a":2,"b":{"c":"x"},"l":[1,2,3],"d":true}`,
			`{"a":{"before":1,"after":2},"l":{"before":[1,2],"after":[1,2,3]},"d":{"before":null,"after":true}}`},
		{"create", ``, `{"role":"editor","grants":{"menu":"update"}}`,
			`{"role":{"before":null,"after":"editor"},"grants.menu":{"before":null,"after":"update"}}`},
		{"delete", `{"role":"editor"}`, `null`, `{"role":{"before":"editor","after":null}}`},
		{"no change", `{"a":1}`, `{ "a": 1 }`, ``},
		{"not json", `{`, `{}`, `{"redaction_error":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audit.Diff(json.RawMessage(tt.before), json.RawMessage(tt.after))
			if tt.want == "" {
				if got != nil {
					t.Errorf("Diff = %s, want nil", got)
				}
				return
			}
			if !audit.EqualJSON(got, json.RawMessage(tt.want)) {
				t.Errorf("Diff =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}
