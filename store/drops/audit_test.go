package dropsstore

import (
	"strings"
	"testing"
)

func TestAuditDDLNamesAndGuards(t *testing.T) {
	ddl := strings.Join(AuditDDL(WithAuditNames(AuditNames{Events: `e"v`, Seals: "sl"}), WithAuditTextIDs()), ";\n")
	for _, want := range []string{`"e""v"`, `"sl"`, "id text PRIMARY KEY", AuditEventImmutable,
		AuditEventProtected, AuditSealImmutable, AuditDaySealed} {
		if !strings.Contains(ddl, want) {
			t.Errorf("AuditDDL lacks %q", want)
		}
	}
	if def := strings.Join(AuditDDL(), ";"); !strings.Contains(def, "id uuid PRIMARY KEY") || !strings.Contains(def, `"audit_seals"`) {
		t.Error("default DDL is not uuid ids over audit_events/audit_seals")
	}
}
