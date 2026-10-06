package dropsstore

import (
	"strings"
	"testing"
)

func TestAuditDDLNamesAndGuards(t *testing.T) {
	ddl := strings.Join(AuditDDL(WithAuditNames(AuditNames{Events: `e"v`, Seals: "sl"}), WithAuditTextLibraryIDs()), ";\n")
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

// The index set follows the spec: every Filter field a trail is read by has
// one, and Member's OR over actor, on_behalf_of and the user resource can be
// answered with a BitmapOr.
func TestAuditDDLIndexes(t *testing.T) {
	ddl := strings.Join(AuditDDL(), ";\n")
	for _, want := range []string{
		`"audit_events_topic_time" ON "audit_events" (topic, occurred_at)`,
		`"audit_events_open" ON "audit_events" (occurred_at) WHERE completed_at IS NULL`,
		`"audit_events_container" ON "audit_events" (container_id, seq DESC) WHERE container_id <> ''`,
		`"audit_events_actor" ON "audit_events" (actor_id, seq DESC) WHERE actor_id <> ''`,
		`"audit_events_resource" ON "audit_events" (resource_type, resource_id, seq DESC) WHERE resource_id <> ''`,
		`"audit_events_on_behalf_of" ON "audit_events" (on_behalf_of, seq DESC) WHERE on_behalf_of <> ''`,
		`"audit_events_client" ON "audit_events" (topic, occurred_at) WHERE ip <> '' OR user_agent <> ''`,
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("AuditDDL lacks the index %s", want)
		}
	}
	if n := strings.Count(ddl, "CREATE INDEX"); n != 7 {
		t.Errorf("AuditDDL creates %d indexes, want 7", n)
	}
}

// The guards must not resolve the tables through the caller's search_path:
// a TEMP table shadowing the seals would turn them off.
func TestAuditGuardsPinTheirNameResolution(t *testing.T) {
	ddl := AuditDDL()
	fns := 0
	for _, stmt := range ddl {
		if !strings.HasPrefix(stmt, "CREATE OR REPLACE FUNCTION") {
			continue
		}
		fns++
		if !strings.Contains(stmt, "SET search_path = pg_catalog, pg_temp") {
			t.Errorf("guard function does not pin its search_path:\n%s", stmt)
		}
	}
	if fns != 4 {
		t.Errorf("AuditDDL creates %d guard functions, want 4", fns)
	}
	if strings.Contains(strings.Join(ddl, "\n"), "DROP TRIGGER") {
		t.Error("AuditDDL drops a trigger: there is a window with no guard until it is created again")
	}
}
