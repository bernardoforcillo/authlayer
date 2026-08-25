package scope

import "github.com/bernardoforcillo/authlayer/access"

// Inheritance projects a subject's standing in the parent scope onto the child.
//
// It returns grants named in the CHILD's vocabulary, plus whether the parent
// standing alone makes the subject elevated in the child. It receives the
// parent's Permission only to *query* it — the returned grants are compiled
// against the child's Access, because a Permission is a bitset over one
// Statements space and the parent's bits mean nothing in the child's.
//
// Returning grants the child's statements do not declare is an error at
// resolution time, not a silent no-op: a projection that names a capability the
// child never declared is a configuration bug worth surfacing.
type Inheritance func(parent access.Permission, parentElevated bool) (
	grants map[string][]access.Action, elevated bool)

// InheritElevation is the default projection: an actor elevated in the parent
// is elevated in the child, and nothing else carries across.
//
// This is the "an organization's owner or administrator can administer any team
// in it" rule, and it is what [WithParent] uses when given no projection.
func InheritElevation(_ access.Permission, parentElevated bool) (map[string][]access.Action, bool) {
	return nil, parentElevated
}

// InheritWhen returns an [Inheritance] conferring elevation in the child on
// anyone whose parent standing allows every action on resource.
//
//	scope.InheritWhen("team", org.ActionUpdate)
//
// Use it for "whoever may manage teams in the organization may administer each
// team", where the parent's statements declare the capability. An actor already
// elevated in the parent stays elevated regardless.
func InheritWhen(resource string, actions ...access.Action) Inheritance {
	return func(parent access.Permission, parentElevated bool) (map[string][]access.Action, bool) {
		return nil, parentElevated || parent.Allows(resource, actions...)
	}
}

// WithParent nests this scope inside another.
//
// p resolves standing in the parent — a *Service for the parent scope satisfies
// it. inherit projects that standing onto this one; passing nil selects
// [InheritElevation].
//
// The container type must embed [NestedBase] (or otherwise satisfy [Nested]);
// [New] panics otherwise, because a parent configured against a container that
// has no parent link is a startup wiring bug rather than a runtime condition.
//
//	svc := scope.New[Team, TeamMember](ac, store,
//	    scope.WithParent(orgSvc, scope.InheritElevation))
func WithParent(p ParentScope, inherit Inheritance) Option {
	return func(c *config) {
		c.parent = p
		if inherit == nil {
			inherit = InheritElevation
		}
		c.inherit = inherit
	}
}

// WithContainerResource names this scope's own container resource — the same
// string given to [NewAccess], "team" for a team scope.
//
// It matters only under [WithParent], and only for [Service.CreateContainer],
// which asks the parent whether the subject may perform <resource>:create
// there. The name has to be declared on the *parent's* surface for anyone but
// an elevated parent actor to hold it, which is why a nested scope package
// publishes the statements its parent must merge in.
//
//	scope.New[Team, TeamMember](ac, store,
//	    scope.WithParent(orgSvc, nil),
//	    scope.WithContainerResource("team"))
//
// Leaving it unset fails closed rather than open: an undeclared resource is
// never allowed, so creating a container in the parent then requires elevated
// standing there.
func WithContainerResource(resource string) Option {
	return func(c *config) { c.containerResource = resource }
}

// nestedSetter is the write half of a parent link. It stays unexported because
// SetParent is promoted from [NestedBase] and the engine is its only caller;
// [New] verifies a parented container type provides it.
type nestedSetter interface{ SetParent(string) }
