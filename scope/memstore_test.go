package scope

import (
	"context"
	"maps"
)

// memStore is a generic in-memory Store[C,M] for engine tests. It carries the
// pointer type parameters so it can mutate stored values in place on updates.
type memStore[C Container, M Member,
	PC interface {
		*C
		MutableContainer
	},
	PM interface {
		*M
		MutableMember
	}] struct {
	containers map[string]C
	members    map[string]map[string]M
	roles      map[string]map[string]RoleRecord
}

func newMemStore[C Container, M Member,
	PC interface {
		*C
		MutableContainer
	},
	PM interface {
		*M
		MutableMember
	}]() *memStore[C, M, PC, PM] {
	return &memStore[C, M, PC, PM]{
		containers: map[string]C{},
		members:    map[string]map[string]M{},
		roles:      map[string]map[string]RoleRecord{},
	}
}

func (s *memStore[C, M, PC, PM]) CreateContainer(_ context.Context, c C) (C, error) {
	id := c.ContainerID()
	s.containers[id] = c
	s.members[id] = map[string]M{}
	s.roles[id] = map[string]RoleRecord{}
	return c, nil
}

func (s *memStore[C, M, PC, PM]) FindContainer(_ context.Context, id string) (C, error) {
	c, ok := s.containers[id]
	if !ok {
		var zero C
		return zero, ErrContainerNotFound
	}
	return c, nil
}

func (s *memStore[C, M, PC, PM]) UpdateContainerOwner(_ context.Context, id, newOwnerID string) error {
	c, ok := s.containers[id]
	if !ok {
		return ErrContainerNotFound
	}
	PC(&c).SetOwner(newOwnerID)
	s.containers[id] = c
	return nil
}

func (s *memStore[C, M, PC, PM]) ListUserContainers(_ context.Context, userID string) ([]C, error) {
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

func (s *memStore[C, M, PC, PM]) AddMember(_ context.Context, m M) (M, error) {
	cid, uid := m.MemberContainer(), m.MemberUser()
	mm, ok := s.members[cid]
	if !ok {
		var zero M
		return zero, ErrContainerNotFound
	}
	if _, exists := mm[uid]; exists {
		var zero M
		return zero, ErrAlreadyMember
	}
	mm[uid] = m
	return m, nil
}

func (s *memStore[C, M, PC, PM]) FindMember(_ context.Context, cid, uid string) (M, error) {
	m, ok := s.members[cid][uid]
	if !ok {
		var zero M
		return zero, ErrNotMember
	}
	return m, nil
}

func (s *memStore[C, M, PC, PM]) ListMembers(_ context.Context, cid string) ([]M, error) {
	if _, ok := s.containers[cid]; !ok {
		return nil, ErrContainerNotFound
	}
	out := make([]M, 0, len(s.members[cid]))
	for _, m := range s.members[cid] {
		out = append(out, m)
	}
	return out, nil
}

func (s *memStore[C, M, PC, PM]) UpdateMemberRole(_ context.Context, cid, uid, roleKey string) error {
	mm := s.members[cid]
	m, ok := mm[uid]
	if !ok {
		return ErrNotMember
	}
	PM(&m).SetKeys(cid, uid, roleKey)
	mm[uid] = m
	return nil
}

func (s *memStore[C, M, PC, PM]) RemoveMember(_ context.Context, cid, uid string) error {
	mm := s.members[cid]
	if _, ok := mm[uid]; !ok {
		return ErrNotMember
	}
	delete(mm, uid)
	return nil
}

func (s *memStore[C, M, PC, PM]) CountMembersWithRole(_ context.Context, cid, roleKey string) (int, error) {
	n := 0
	for _, m := range s.members[cid] {
		if m.MemberRole() == roleKey {
			n++
		}
	}
	return n, nil
}

func (s *memStore[C, M, PC, PM]) ListUserStandings(_ context.Context, userID string) ([]MemberStanding, error) {
	var out []MemberStanding
	for containerID, members := range s.members {
		m, ok := members[userID]
		if !ok {
			continue
		}
		c, ok := s.containers[containerID]
		if !ok {
			continue
		}
		out = append(out, MemberStanding{
			ContainerID: containerID,
			RoleKey:     m.MemberRole(),
			OwnerID:     c.ContainerOwner(),
		})
	}
	return out, nil
}

func (s *memStore[C, M, PC, PM]) CreateRole(_ context.Context, r RoleRecord) (RoleRecord, error) {
	rr, ok := s.roles[r.ContainerID]
	if !ok {
		return RoleRecord{}, ErrContainerNotFound
	}
	if _, exists := rr[r.Key]; exists {
		return RoleRecord{}, ErrRoleKeyTaken
	}
	rr[r.Key] = r
	return r, nil
}

func (s *memStore[C, M, PC, PM]) FindRole(_ context.Context, cid, key string) (RoleRecord, error) {
	r, ok := s.roles[cid][key]
	if !ok {
		return RoleRecord{}, ErrRoleNotFound
	}
	return r, nil
}

func (s *memStore[C, M, PC, PM]) ListRoles(_ context.Context, cid string) ([]RoleRecord, error) {
	if _, ok := s.containers[cid]; !ok {
		return nil, ErrContainerNotFound
	}
	out := make([]RoleRecord, 0, len(s.roles[cid]))
	for _, r := range s.roles[cid] {
		out = append(out, r)
	}
	return out, nil
}

func (s *memStore[C, M, PC, PM]) UpdateRole(_ context.Context, cid, key, name string, permissions []byte) error {
	rr := s.roles[cid]
	r, ok := rr[key]
	if !ok {
		return ErrRoleNotFound
	}
	r.Name = name
	r.Permissions = permissions
	rr[key] = r
	return nil
}

func (s *memStore[C, M, PC, PM]) DeleteRole(_ context.Context, cid, key string) error {
	rr := s.roles[cid]
	if _, ok := rr[key]; !ok {
		return ErrRoleNotFound
	}
	delete(rr, key)
	return nil
}

func (s *memStore[C, M, PC, PM]) WithTx(_ context.Context, fn func(Store[C, M]) error) error {
	snap := s.snapshot()
	if err := fn(s); err != nil {
		s.restore(snap)
		return err
	}
	return nil
}

func (s *memStore[C, M, PC, PM]) snapshot() *memStore[C, M, PC, PM] {
	cp := newMemStore[C, M, PC, PM]()
	maps.Copy(cp.containers, s.containers)
	for k, v := range s.members {
		cp.members[k] = maps.Clone(v)
	}
	for k, v := range s.roles {
		cp.roles[k] = maps.Clone(v)
	}
	return cp
}

func (s *memStore[C, M, PC, PM]) restore(snap *memStore[C, M, PC, PM]) {
	s.containers = snap.containers
	s.members = snap.members
	s.roles = snap.roles
}
