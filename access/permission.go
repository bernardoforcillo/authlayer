package access

import "strings"

// Permission is an immutable set of (resource, action) grants over a fixed
// Statements space, represented as a bitset for O(1) checks.
//
// Build one with [Access.Permission] (validated grants), [Access.Full] (every
// declared pair), or [Access.Decode] (stored grants). The zero Permission has
// no statements and denies everything: [Permission.Allows] and
// [Permission.IsFull] both report false, which makes an accidentally-unset
// Permission fail closed.
//
// Permissions are only meaningfully compared within one Statements space.
// [Permission.SubsetOf] compares raw bits, so comparing permissions built from
// two different Statements values is not meaningful.
type Permission struct {
	s    *Statements
	bits []uint64
}

func newPermission(s *Statements) Permission {
	return Permission{s: s, bits: make([]uint64, (s.nbits()+63)/64)}
}

func (p Permission) set(i int)      { p.bits[i/64] |= 1 << uint(i%64) }
func (p Permission) has(i int) bool { return p.bits[i/64]&(1<<uint(i%64)) != 0 }

// IsFull reports whether p grants every declared (resource, action) pair. It
// is the code-level equivalent of an "administrator" bit: an actor whose role
// IsFull is treated as elevated and bypasses fine-grained permission checks.
func (p Permission) IsFull() bool {
	if p.s == nil {
		return false
	}
	for i := range p.s.nbits() {
		if !p.has(i) {
			return false
		}
	}
	return true
}

// IsZero reports whether p grants nothing at all — the counterpart to
// [Permission.IsFull]. The zero Permission is zero, and so is one built from
// grants that named resources but no actions on them: [Access.Permission] with
// map[string][]Action{"doc": nil} validates and compiles, yet confers nothing.
//
// The distinction matters wherever a permission decides whether a subject has
// any standing at all, because "the caller handed me a non-empty grant map" and
// "the subject was actually granted something" are different questions and only
// the second one is safe to act on.
func (p Permission) IsZero() bool {
	for _, w := range p.bits {
		if w != 0 {
			return false
		}
	}
	return true
}

// SubsetOf reports whether every grant in p is also granted by other — i.e. p
// confers nothing other doesn't already have. This is the privilege-escalation
// guard: an actor may only grant a role whose permissions SubsetOf the actor's.
func (p Permission) SubsetOf(other Permission) bool {
	for i, w := range p.bits {
		var o uint64
		if i < len(other.bits) {
			o = other.bits[i]
		}
		if w&^o != 0 {
			return false
		}
	}
	return true
}

// Allows reports whether every action on resource is granted. With no actions
// it returns false (nothing to authorize). Undeclared pairs are never allowed,
// so a typo fails closed.
func (p Permission) Allows(resource string, actions ...Action) bool {
	if p.s == nil || len(actions) == 0 {
		return false
	}
	for _, a := range actions {
		i, ok := p.s.bitOf(resource, a)
		if !ok || !p.has(i) {
			return false
		}
	}
	return true
}

// Encode serialises the permission as newline-separated "resource:action"
// tokens in a stable order. It stores grant NAMES rather than bit indices, so
// a permission persisted today keeps its meaning even if the statement set
// later grows or is reordered — decoding re-resolves the names against the
// then-current Statements. Suitable for a bytea/text column.
func (p Permission) Encode() []byte {
	if p.s == nil {
		return nil
	}
	var b strings.Builder
	first := true
	for i, pr := range p.s.pairs {
		if !p.has(i) {
			continue
		}
		if !first {
			b.WriteByte('\n')
		}
		first = false
		b.WriteString(pr.resource)
		b.WriteByte(':')
		b.WriteString(string(pr.action))
	}
	return []byte(b.String())
}
