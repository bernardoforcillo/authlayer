package scope

import (
	"testing"

	"github.com/bernardoforcillo/authlayer/access"
)

func TestInheritElevationPassesElevationThroughOnly(t *testing.T) {
	grants, elevated := InheritElevation(access.Permission{}, true)
	if !elevated {
		t.Fatal("an elevated parent standing did not confer elevation")
	}
	if len(grants) != 0 {
		t.Fatalf("InheritElevation invented grants: %v", grants)
	}

	if _, elevated := InheritElevation(access.Permission{}, false); elevated {
		t.Fatal("a non-elevated parent standing conferred elevation")
	}
}

func TestInheritWhenConfersElevationOnlyForTheNamedGrant(t *testing.T) {
	ac := access.New(access.NewStatements(map[string][]access.Action{
		"team": {"create", "update"},
	}))
	manager, err := ac.Permission(map[string][]access.Action{"team": {"update"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	bystander, err := ac.Permission(map[string][]access.Action{"team": {"create"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	inherit := InheritWhen("team", "update")

	if _, elevated := inherit(manager, false); !elevated {
		t.Fatal("holder of team:update was not elevated in the child")
	}
	if _, elevated := inherit(bystander, false); elevated {
		t.Fatal("holder of only team:create was elevated in the child")
	}
	// An already-elevated parent standing still carries through.
	if _, elevated := inherit(bystander, true); !elevated {
		t.Fatal("an elevated parent standing lost its elevation")
	}
}

func TestWithParentStoresBothHalves(t *testing.T) {
	c := defaultConfig()
	if c.parent != nil || c.inherit != nil {
		t.Fatal("a plain config already has a parent configured")
	}
	var p ParentScope = (*Service[testContainer, testMember, *testContainer, *testMember])(nil)
	WithParent(p, InheritElevation)(&c)
	if c.parent == nil || c.inherit == nil {
		t.Fatal("WithParent did not store both the parent and the projection")
	}
}

// A nil Inheritance must not silently mean "inherit nothing" — that would make
// a mis-wired parent look like a working one that never grants.
func TestWithParentDefaultsANilInheritance(t *testing.T) {
	c := defaultConfig()
	var p ParentScope = (*Service[testContainer, testMember, *testContainer, *testMember])(nil)
	WithParent(p, nil)(&c)
	if c.inherit == nil {
		t.Fatal("a nil Inheritance was stored as nil rather than defaulted")
	}
	if _, elevated := c.inherit(access.Permission{}, true); !elevated {
		t.Fatal("the defaulted Inheritance is not InheritElevation")
	}
}
