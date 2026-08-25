package scope

import (
	"testing"
	"time"
)

type testContainer struct {
	ContainerBase
	Name string
}

type testMember struct {
	MemberBase
}

// Compile-time proof the embedded bases satisfy the reader and mutable interfaces.
var (
	_ Container        = testContainer{}
	_ MutableContainer = (*testContainer)(nil)
	_ Member           = testMember{}
	_ MutableMember    = (*testMember)(nil)
)

func TestContainerBaseAccessorsAndSetters(t *testing.T) {
	var c testContainer
	pc := MutableContainer(&c)
	pc.SetID("c1")
	pc.SetOwner("alice")
	now := time.Now()
	pc.SetTimes(now, now)

	if c.ContainerID() != "c1" || c.ContainerOwner() != "alice" {
		t.Fatalf("container accessors wrong: %+v", c.ContainerBase)
	}
	if !c.CreatedAt.Equal(now) || !c.UpdatedAt.Equal(now) {
		t.Fatal("setTimes did not populate timestamps")
	}
}

func TestMemberBaseAccessorsAndSetters(t *testing.T) {
	var m testMember
	pm := MutableMember(&m)
	pm.SetKeys("c1", "bob", "admin")
	now := time.Now()
	pm.SetJoined(now)

	if m.MemberContainer() != "c1" || m.MemberUser() != "bob" || m.MemberRole() != "admin" {
		t.Fatalf("member accessors wrong: %+v", m.MemberBase)
	}
	if !m.JoinedAt.Equal(now) {
		t.Fatal("setJoined did not populate joined_at")
	}
}

func TestNestedBaseCarriesTheParentLink(t *testing.T) {
	var n NestedBase
	n.SetID("t1")
	n.SetOwner("alice")
	n.SetParent("acme")

	if n.ContainerID() != "t1" || n.ContainerOwner() != "alice" {
		t.Fatal("NestedBase lost the embedded ContainerBase behaviour")
	}
	if n.ContainerParent() != "acme" {
		t.Fatalf("ContainerParent() = %q, want acme", n.ContainerParent())
	}
	// It must satisfy both interfaces, since the engine type-asserts for Nested.
	var _ Container = n
	var _ Nested = n
}
