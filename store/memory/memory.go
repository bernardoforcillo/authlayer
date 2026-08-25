// Package memory provides an in-process, generic scope.Store backed by maps. It
// is a zero-dependency default for development, tests, and examples, and the
// reference implementation of the Store contract. It does not enforce
// uniqueness of custom fields (e.g. a slug) — that is a database concern; use
// the drops store for real deployments.
package memory

import (
	"context"
	"maps"
	"sync"

	"github.com/bernardoforcillo/authlayer/scope"
)

// Store is a concurrency-safe in-memory scope.Store[C, M]. It carries the
// pointer type parameters so it can mutate stored values in place on updates.
type Store[C scope.Container, M scope.Member,
	PC interface {
		*C
		scope.MutableContainer
	},
	PM interface {
		*M
		scope.MutableMember
	}] struct {
	mu         sync.Mutex
	txMu       sync.Mutex
	containers map[string]C
	members    map[string]map[string]M
	roles      map[string]map[string]scope.RoleRecord
}

// New returns an empty in-memory store. Type parameters are usually inferred at
// the call site of the enclosing instance (e.g. org.New).
func New[C scope.Container, M scope.Member,
	PC interface {
		*C
		scope.MutableContainer
	},
	PM interface {
		*M
		scope.MutableMember
	}]() *Store[C, M, PC, PM] {
	return &Store[C, M, PC, PM]{
		containers: map[string]C{},
		members:    map[string]map[string]M{},
		roles:      map[string]map[string]scope.RoleRecord{},
	}
}

// CreateContainer stores the container and initialises its (empty) member and
// role maps. It never reports ErrConflict: uniqueness of application fields
// such as a slug is a database concern this store does not model.
func (s *Store[C, M, PC, PM]) CreateContainer(_ context.Context, c C) (C, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := c.ContainerID()
	s.containers[id] = c
	s.members[id] = map[string]M{}
	s.roles[id] = map[string]scope.RoleRecord{}
	return c, nil
}

// FindContainer returns the container, or scope.ErrContainerNotFound.
func (s *Store[C, M, PC, PM]) FindContainer(_ context.Context, id string) (C, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.containers[id]
	if !ok {
		var zero C
		return zero, scope.ErrContainerNotFound
	}
	return c, nil
}

// UpdateContainerOwner rewrites the container's owner via the pointer type's
// SetOwner, or returns scope.ErrContainerNotFound.
func (s *Store[C, M, PC, PM]) UpdateContainerOwner(_ context.Context, id, newOwnerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.containers[id]
	if !ok {
		return scope.ErrContainerNotFound
	}
	PC(&c).SetOwner(newOwnerID)
	s.containers[id] = c
	return nil
}

// ListUserContainers returns every container the user belongs to, resolved
// through the membership map.
func (s *Store[C, M, PC, PM]) ListUserContainers(_ context.Context, userID string) ([]C, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []C
	for containerID, members := range s.members {
		if _, ok := members[userID]; !ok {
			continue
		}
		if c, ok := s.containers[containerID]; ok {
			out = append(out, c)
		}
	}
	return out, nil
}

// AddMember stores a membership, returning scope.ErrAlreadyMember when the
// (container, user) pair is taken and scope.ErrContainerNotFound when the
// container does not exist.
func (s *Store[C, M, PC, PM]) AddMember(_ context.Context, m M) (M, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cid, uid := m.MemberContainer(), m.MemberUser()
	mm, ok := s.members[cid]
	if !ok {
		var zero M
		return zero, scope.ErrContainerNotFound
	}
	if _, exists := mm[uid]; exists {
		var zero M
		return zero, scope.ErrAlreadyMember
	}
	mm[uid] = m
	return m, nil
}

// FindMember returns the membership, or scope.ErrNotMember — which also covers
// an unknown container, since a missing container has no members either.
func (s *Store[C, M, PC, PM]) FindMember(_ context.Context, cid, uid string) (M, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.members[cid][uid]
	if !ok {
		var zero M
		return zero, scope.ErrNotMember
	}
	return m, nil
}

// ListMembers returns every membership in the container, or
// scope.ErrContainerNotFound. Order follows Go map iteration and is therefore
// randomised — sort the result if a test depends on it.
func (s *Store[C, M, PC, PM]) ListMembers(_ context.Context, cid string) ([]M, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.containers[cid]; !ok {
		return nil, scope.ErrContainerNotFound
	}
	out := make([]M, 0, len(s.members[cid]))
	for _, m := range s.members[cid] {
		out = append(out, m)
	}
	return out, nil
}

// UpdateMemberRole rewrites the membership's role key via the pointer type's
// SetKeys, or returns scope.ErrNotMember.
func (s *Store[C, M, PC, PM]) UpdateMemberRole(_ context.Context, cid, uid, roleKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mm := s.members[cid]
	m, ok := mm[uid]
	if !ok {
		return scope.ErrNotMember
	}
	PM(&m).SetKeys(cid, uid, roleKey)
	mm[uid] = m
	return nil
}

// RemoveMember deletes the membership, or returns scope.ErrNotMember.
func (s *Store[C, M, PC, PM]) RemoveMember(_ context.Context, cid, uid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mm := s.members[cid]
	if _, ok := mm[uid]; !ok {
		return scope.ErrNotMember
	}
	delete(mm, uid)
	return nil
}

// CountMembersWithRole counts memberships holding roleKey. An unknown
// container counts zero rather than erroring, matching a SQL COUNT.
func (s *Store[C, M, PC, PM]) CountMembersWithRole(_ context.Context, cid, roleKey string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, m := range s.members[cid] {
		if m.MemberRole() == roleKey {
			n++
		}
	}
	return n, nil
}

// ListUserStandings flattens the user's memberships against their containers'
// owners — the in-memory equivalent of the drops store's single join.
func (s *Store[C, M, PC, PM]) ListUserStandings(_ context.Context, userID string) ([]scope.MemberStanding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []scope.MemberStanding
	for containerID, members := range s.members {
		m, ok := members[userID]
		if !ok {
			continue
		}
		c, ok := s.containers[containerID]
		if !ok {
			// A membership whose container is gone is not a standing.
			continue
		}
		out = append(out, scope.MemberStanding{
			ContainerID: containerID,
			RoleKey:     m.MemberRole(),
			OwnerID:     c.ContainerOwner(),
		})
	}
	return out, nil
}

// CreateRole stores a custom role, returning scope.ErrRoleKeyTaken when the
// (container, key) pair is taken and scope.ErrContainerNotFound when the
// container does not exist.
func (s *Store[C, M, PC, PM]) CreateRole(_ context.Context, r scope.RoleRecord) (scope.RoleRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rr, ok := s.roles[r.ContainerID]
	if !ok {
		return scope.RoleRecord{}, scope.ErrContainerNotFound
	}
	if _, exists := rr[r.Key]; exists {
		return scope.RoleRecord{}, scope.ErrRoleKeyTaken
	}
	rr[r.Key] = r
	return r, nil
}

// FindRole returns the custom role, or scope.ErrRoleNotFound.
func (s *Store[C, M, PC, PM]) FindRole(_ context.Context, cid, key string) (scope.RoleRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[cid][key]
	if !ok {
		return scope.RoleRecord{}, scope.ErrRoleNotFound
	}
	return r, nil
}

// ListRoles returns the container's custom roles (never the code-defined
// defaults), or scope.ErrContainerNotFound. Order is randomised, as for
// ListMembers.
func (s *Store[C, M, PC, PM]) ListRoles(_ context.Context, cid string) ([]scope.RoleRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.containers[cid]; !ok {
		return nil, scope.ErrContainerNotFound
	}
	out := make([]scope.RoleRecord, 0, len(s.roles[cid]))
	for _, r := range s.roles[cid] {
		out = append(out, r)
	}
	return out, nil
}

// UpdateRole replaces the role's name and encoded permissions, or returns
// scope.ErrRoleNotFound. The permission bytes are stored verbatim.
func (s *Store[C, M, PC, PM]) UpdateRole(_ context.Context, cid, key, name string, permissions []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rr := s.roles[cid]
	r, ok := rr[key]
	if !ok {
		return scope.ErrRoleNotFound
	}
	r.Name = name
	r.Permissions = permissions
	rr[key] = r
	return nil
}

// DeleteRole removes the custom role, or returns scope.ErrRoleNotFound.
func (s *Store[C, M, PC, PM]) DeleteRole(_ context.Context, cid, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rr := s.roles[cid]
	if _, ok := rr[key]; !ok {
		return scope.ErrRoleNotFound
	}
	delete(rr, key)
	return nil
}

// WithTx approximates a transaction by snapshotting the three maps, running fn
// against this same store, and restoring the snapshot if fn fails.
//
// A package-level mutex serialises transactions, so two never interleave, and
// the semantics are good enough for the engine's one transactional operation
// (CreateContainer). It is not a real transaction: the snapshot is shallow, so
// a container value mutated in place during fn is not rolled back, and writes
// made inside fn are visible to concurrent readers before it commits. Use the
// drops store where those distinctions matter.
func (s *Store[C, M, PC, PM]) WithTx(_ context.Context, fn func(scope.Store[C, M]) error) error {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	snap := s.snapshot()
	if err := fn(s); err != nil {
		s.restore(snap)
		return err
	}
	return nil
}

type snapshot[C scope.Container, M scope.Member] struct {
	containers map[string]C
	members    map[string]map[string]M
	roles      map[string]map[string]scope.RoleRecord
}

func (s *Store[C, M, PC, PM]) snapshot() snapshot[C, M] {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := snapshot[C, M]{
		containers: maps.Clone(s.containers),
		members:    make(map[string]map[string]M, len(s.members)),
		roles:      make(map[string]map[string]scope.RoleRecord, len(s.roles)),
	}
	for k, v := range s.members {
		snap.members[k] = maps.Clone(v)
	}
	for k, v := range s.roles {
		snap.roles[k] = maps.Clone(v)
	}
	return snap
}

func (s *Store[C, M, PC, PM]) restore(snap snapshot[C, M]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.containers = snap.containers
	s.members = snap.members
	s.roles = snap.roles
}
