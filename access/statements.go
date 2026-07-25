package access

import (
	"fmt"
	"slices"
	"strings"
)

// Action is a capability verb on a resource, e.g. "create", "update", "delete".
//
// Actions are free-form: the engine gives no meaning to any particular verb
// beyond the create/update/delete trio it checks on its own control resources.
// An application may declare "read", "publish", "invite", or anything else, as
// long as the name is non-empty and contains no ':' or newline.
type Action string

type pair struct {
	resource string
	action   Action
}

// Statements is the immutable permission surface: which actions each resource
// exposes. It assigns every (resource, action) pair a stable bit index so a
// Permission can be represented as a compact bitset.
//
// "Stable" here means stable within one process lifetime, which is all a bitset
// needs — indices are never persisted. Because [NewStatements] sorts resources
// and actions before assigning indices, the same declaration always compiles to
// the same layout, but nothing depends on that: permissions cross the storage
// boundary as names (see [Permission.Encode]).
//
// A Statements is read-only after construction and safe for concurrent use.
type Statements struct {
	bit   map[string]map[Action]int
	pairs []pair // index -> pair (reverse lookup)
}

// NewStatements compiles the resource->actions map into a Statements.
//
// Resources and actions are sorted, and duplicate actions within a resource are
// collapsed, so the bit layout depends only on the set of declared pairs and
// not on map iteration order.
//
// Resource and action names must be non-empty and contain no ':' or newline
// (both are separators in the wire encoding). NewStatements panics otherwise —
// a malformed statement set is a startup programming error and should fail
// loudly at boot rather than produce a permission that cannot round-trip
// through storage.
func NewStatements(m map[string][]Action) *Statements {
	s := &Statements{bit: make(map[string]map[Action]int, len(m))}
	resources := make([]string, 0, len(m))
	for r := range m {
		resources = append(resources, r)
	}
	slices.Sort(resources)
	for _, r := range resources {
		validateName(r)
		actions := append([]Action(nil), m[r]...)
		slices.Sort(actions)
		am := make(map[Action]int, len(actions))
		for _, a := range actions {
			validateName(string(a))
			if _, dup := am[a]; dup {
				continue
			}
			am[a] = len(s.pairs)
			s.pairs = append(s.pairs, pair{resource: r, action: a})
		}
		s.bit[r] = am
	}
	return s
}

func validateName(n string) {
	if n == "" || strings.ContainsAny(n, ":\n") {
		panic(fmt.Sprintf("access: invalid name %q (must be non-empty and contain no ':' or newline)", n))
	}
}

// bitOf returns the bit index for (resource, action); ok is false when the
// pair is not declared.
func (s *Statements) bitOf(resource string, action Action) (int, bool) {
	am, ok := s.bit[resource]
	if !ok {
		return 0, false
	}
	i, ok := am[action]
	return i, ok
}

// nbits is the total number of declared (resource, action) pairs.
func (s *Statements) nbits() int { return len(s.pairs) }
