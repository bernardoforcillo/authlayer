// Package access is authlayer's pure access-control engine: it turns a
// code-declared permission surface into compact, comparable permission sets. It
// depends on nothing but the standard library and knows nothing about
// organizations, databases, or HTTP — the scope and org packages build on it.
//
// # The four types
//
//   - [Statements] is the permission surface: which actions each resource
//     exposes, e.g. "project": {"create", "read"}. Declare it once at startup
//     with [NewStatements]; every (resource, action) pair receives a stable bit
//     index.
//   - [Permission] is an immutable set of grants over those statements, held as
//     a bitset — a check is a bit test, not a map lookup or string scan.
//   - [Role] is a named bundle of permissions. Exactly one role is held per
//     membership.
//   - [Access] binds a Statements to a registry of named roles and is the
//     factory for Permission values.
//
// # Fail closed
//
// A grant naming an undeclared (resource, action) pair is never silently
// dropped. [Access.NewRole] panics, because a mis-declared code-defined role is
// a startup programming error that should be loud; [Access.Permission] returns
// an error, because runtime and DB-sourced grants must be validated rather than
// trusted. [Permission.Allows] reports false for any undeclared pair, so a typo
// denies access instead of granting it.
//
// # Forward-compatible persistence
//
// [Permission.Encode] serialises grants as "resource:action" names, not bit
// indices, and [Access.Decode] re-resolves those names against the statements in
// force at decode time. Adding, removing, or reordering resources therefore
// never silently re-interprets a permission persisted earlier: a capability that
// no longer exists is dropped, and everything else keeps its meaning.
//
// # Example
//
//	st := access.NewStatements(map[string][]access.Action{
//	    "project": {"create", "read", "update", "delete"},
//	})
//	ac := access.New(st)
//	ac.NewRole("viewer", map[string][]access.Action{"project": {"read"}})
//
//	viewer, _ := ac.Role("viewer")
//	viewer.Permissions.Allows("project", "read")   // true
//	viewer.Permissions.Allows("project", "delete") // false
package access

import (
	"fmt"
	"strings"
)

// Access binds a Statements surface to a registry of named roles and acts as
// the factory for Permission values built from named grants.
//
// One Access is built at startup, shared by every request, and never mutated
// after the code-defined roles are registered — so it is safe for concurrent
// use as long as all NewRole calls happen during initialisation. Custom,
// per-container roles are NOT registered here: they live in the store and are
// rebuilt on demand with [Access.Decode], which keeps a tenant's roles out of
// process-wide state.
type Access struct {
	s     *Statements
	roles map[string]Role
}

// New returns an Access over the given statements, with no roles registered
// yet. Callers normally follow it with one NewRole call per code-defined role;
// scope.NewAccess does exactly that for the owner/admin/member defaults.
func New(s *Statements) *Access {
	return &Access{s: s, roles: make(map[string]Role)}
}

// NewRole registers a code-defined role under key and returns it. Grants must
// reference declared (resource, action) pairs; an undeclared grant panics,
// because a mis-declared default role is a startup programming error that
// should fail loudly rather than silently grant nothing. For dynamic,
// DB-sourced roles use Permission, which returns an error instead.
func (a *Access) NewRole(key string, grants map[string][]Action) Role {
	p, err := a.Permission(grants)
	if err != nil {
		panic("access: NewRole(" + key + "): " + err.Error())
	}
	r := Role{Key: key, Permissions: p}
	a.roles[key] = r
	return r
}

// Role returns the registered role for key and ok=false when none exists.
//
// Only code-defined roles are registered, so ok=false is also how the scope
// engine distinguishes a custom, per-container role (to be loaded from the
// store) from a default one — and how it rejects attempts to redefine, update,
// or delete a default role.
func (a *Access) Role(key string) (Role, bool) {
	r, ok := a.roles[key]
	return r, ok
}

// Full returns the Permission that grants every declared (resource, action)
// pair — the "administrator" set. A role holding Full bypasses fine-grained
// checks (see [Permission.IsFull]) and the privilege-escalation guard, and the
// container owner is granted Full under the default policy.
//
// Full is computed against the statements as declared, so it automatically
// covers resources an application adds later; it is not a wildcard stored
// anywhere, and a Permission built from an explicit grant map that happens to
// list every pair is indistinguishable from it.
func (a *Access) Full() Permission {
	p := newPermission(a.s)
	for i := range a.s.pairs {
		p.set(i)
	}
	return p
}

// Permission builds a Permission from grants. It returns an error if a
// (resource, action) pair is not declared in the statements — granting an
// undeclared capability is rejected so typos fail closed. This is the entry
// point for runtime/DB-sourced (custom) roles, where grants are dynamic.
func (a *Access) Permission(grants map[string][]Action) (Permission, error) {
	p := newPermission(a.s)
	for resource, actions := range grants {
		for _, act := range actions {
			i, ok := a.s.bitOf(resource, act)
			if !ok {
				return Permission{}, fmt.Errorf("access: undeclared permission %s:%s", resource, act)
			}
			p.set(i)
		}
	}
	return p, nil
}

// Union returns the permission granting every pair granted by any of ps.
//
// All arguments must come from this Access's Statements: a Permission is a
// bitset over one statement space, so combining permissions from two spaces
// would reinterpret bits rather than merge grants. A foreign permission is
// rejected with an error rather than silently misread. The zero Permission is
// accepted and contributes nothing, so a caller with no permission to merge
// need not special-case it.
//
// It backs nested scopes, where a member's own role permissions merge with the
// grants projected from their standing in the parent scope — both compiled
// against the child's statements.
func (a *Access) Union(ps ...Permission) (Permission, error) {
	out := newPermission(a.s)
	for _, p := range ps {
		if p.s == nil {
			continue // the zero Permission grants nothing
		}
		if p.s != a.s {
			return Permission{}, fmt.Errorf("access: Union of a permission from a different Statements")
		}
		for i := range p.bits {
			out.bits[i] |= p.bits[i]
		}
	}
	return out, nil
}

// Decode rebuilds a Permission from Encode's output, re-resolving each
// "resource:action" token against the current statements. Tokens for
// capabilities that no longer exist are dropped (a removed capability can no
// longer be granted); a token without a ':' separator is treated as corruption
// and returns an error.
func (a *Access) Decode(b []byte) (Permission, error) {
	p := newPermission(a.s)
	if len(b) == 0 {
		return p, nil
	}
	for tok := range strings.SplitSeq(string(b), "\n") {
		if tok == "" {
			continue
		}
		resource, action, found := strings.Cut(tok, ":")
		if !found {
			return Permission{}, fmt.Errorf("access: malformed encoded permission token %q", tok)
		}
		if i, ok := a.s.bitOf(resource, Action(action)); ok {
			p.set(i)
		}
	}
	return p, nil
}
