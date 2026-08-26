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
// "Elevated" means [access.Permission.IsFull] — the owner via OwnerBypass, or
// any role whose permissions grant everything. Under an org.NewAccess-style
// default role set that is the owner alone: the built-in admin role is
// deliberately kept short of IsFull (it excludes <container>:delete, so the
// escalation guard still applies to it), so InheritElevation confers nothing
// on a plain admin. This is the "an organization's owner can administer any
// team in it" rule, and it is what [WithParent] uses when given no projection.
//
// For "whoever may manage teams in the organization administers each team" —
// what most applications actually want — declare that capability on the
// parent's own surface and use [InheritWhen] instead:
//
//	scope.InheritWhen("team", org.ActionUpdate)
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
// A parented scope needs BOTH this option and [WithContainerResource]. Nesting
// changes [Service.CreateContainer] into a permission check against the parent,
// and the permission it looks for is <containerResource>:create — with no
// container resource named there is no such grant to hold, so creation falls
// back to requiring elevated standing in the parent. That fails closed rather
// than open, but it fails silently: an organization member holding exactly the
// grant meant to let them create teams is refused, with nothing in the error to
// say the scope was never told its own name.
//
// Every check on a nested scope now depends on the parent's availability: a
// non-owner check consults the parent's store before it looks at this scope's
// own membership, so a parent-store outage denies every non-owner check here,
// even one a local membership would otherwise have satisfied. That is the
// correct trade-off — failing closed beats guessing — but it is a dependency
// worth knowing you took.
//
// Parent chains must be acyclic. Two *Service values can't form a cycle by
// construction, since a parent has to already exist before it can be named as
// one — but ParentScope is an exported single-method interface, so a custom
// implementation with a field wired up after construction (a late-bound
// parent) can still build one. Either way the engine does not detect it:
// configuring a cycle recurses until the goroutine's stack overflows, a
// fail-stop crash in your own wiring rather than anything a request can
// trigger. Each level a check climbs costs one more store round trip.
//
//	svc := scope.New[Team, TeamMember](ac, store,
//	    scope.WithParent(orgSvc, scope.InheritElevation),
//	    scope.WithContainerResource("team"))
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
