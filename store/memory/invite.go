package memory

import (
	"context"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
)

// InviteStore is a concurrency-safe in-memory invite.Store. It is the
// reference implementation of the Store contract, in particular for
// [InviteStore.ConsumeLink]'s atomicity requirement: every method holds mu for
// its entire body, so a check-then-write sequence can never be split by a
// concurrent call.
//
// Unlike [Store], it is not generic — [invite.EmailInvite] and [invite.Link]
// are fixed shapes — and it does not enforce uniqueness of TokenHash or Code;
// that is a database concern, matching this package's stance on custom
// container fields (see the package doc).
type InviteStore struct {
	mu           sync.Mutex
	emailInvites map[string]invite.EmailInvite
	links        map[string]invite.Link
}

// NewInviteStore returns an empty in-memory invite.Store.
func NewInviteStore() *InviteStore {
	return &InviteStore{
		emailInvites: map[string]invite.EmailInvite{},
		links:        map[string]invite.Link{},
	}
}

// CreateEmailInvite stores the invite under its ID and returns it unchanged.
func (s *InviteStore) CreateEmailInvite(_ context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailInvites[inv.ID] = inv
	return inv, nil
}

// FindEmailInviteByTokenHash scans for the invite whose TokenHash matches, or
// returns invite.ErrInviteNotFound. A linear scan is fine for a reference
// store; store/drops indexes the column.
func (s *InviteStore) FindEmailInviteByTokenHash(_ context.Context, tokenHash string) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inv := range s.emailInvites {
		if inv.TokenHash == tokenHash {
			return inv, nil
		}
	}
	return invite.EmailInvite{}, invite.ErrInviteNotFound
}

// FindEmailInvite returns the invite, or invite.ErrInviteNotFound.
func (s *InviteStore) FindEmailInvite(_ context.Context, id string) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.emailInvites[id]
	if !ok {
		return invite.EmailInvite{}, invite.ErrInviteNotFound
	}
	return inv, nil
}

// ListEmailInvites returns every invite in containerID. Order follows Go map
// iteration and is therefore randomised — sort the result if a test depends
// on it.
func (s *InviteStore) ListEmailInvites(_ context.Context, containerID string) ([]invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]invite.EmailInvite, 0)
	for _, inv := range s.emailInvites {
		if inv.ContainerID == containerID {
			out = append(out, inv)
		}
	}
	return out, nil
}

// DeleteEmailInvite removes the invite, or returns invite.ErrInviteNotFound.
func (s *InviteStore) DeleteEmailInvite(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.emailInvites[id]; !ok {
		return invite.ErrInviteNotFound
	}
	delete(s.emailInvites, id)
	return nil
}

// DeleteEmailInvitesFor removes every invite for (containerID, email).
// Deleting zero rows is not an error.
func (s *InviteStore) DeleteEmailInvitesFor(_ context.Context, containerID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, inv := range s.emailInvites {
		if inv.ContainerID == containerID && inv.Email == email {
			delete(s.emailInvites, id)
		}
	}
	return nil
}

// CreateLink stores the link under its ID and returns it unchanged.
func (s *InviteStore) CreateLink(_ context.Context, l invite.Link) (invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.links[l.ID] = l
	return l, nil
}

// FindLinkByCode scans for the link whose Code matches, or returns
// invite.ErrLinkNotFound. A linear scan is fine for a reference store;
// store/drops indexes the column.
func (s *InviteStore) FindLinkByCode(_ context.Context, code string) (invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.links {
		if l.Code == code {
			return l, nil
		}
	}
	return invite.Link{}, invite.ErrLinkNotFound
}

// FindLink returns the link, or invite.ErrLinkNotFound.
func (s *InviteStore) FindLink(_ context.Context, id string) (invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return invite.Link{}, invite.ErrLinkNotFound
	}
	return l, nil
}

// ListLinks returns every link in containerID, revoked or expired or not.
// Order follows Go map iteration and is therefore randomised — sort the
// result if a test depends on it.
func (s *InviteStore) ListLinks(_ context.Context, containerID string) ([]invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]invite.Link, 0)
	for _, l := range s.links {
		if l.ContainerID == containerID {
			out = append(out, l)
		}
	}
	return out, nil
}

// RevokeLink stamps RevokedAt with at, or returns invite.ErrLinkNotFound.
// Revoking an already-revoked link overwrites the timestamp.
func (s *InviteStore) RevokeLink(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return invite.ErrLinkNotFound
	}
	l.RevokedAt = &at
	s.links[id] = l
	return nil
}

// ConsumeLink checks that the link is unrevoked, unexpired at now, and below
// MaxUses, and increments UseCount if and only if all three hold — all under
// a single acquisition of mu, so no concurrent caller can observe or act on
// an intermediate state. See the atomicity requirement on [invite.Store];
// splitting this into a locked read followed by a separately-locked write
// would let two callers both pass the check before either writes, letting a
// MaxUses:1 link admit more than one user.
//
// A not-found id is reported as (false, invite.ErrLinkNotFound); every other
// failure to consume is (false, nil), per the interface doc.
func (s *InviteStore) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	if l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
		return false, nil
	}
	if l.MaxUses != 0 && l.UseCount >= l.MaxUses {
		return false, nil
	}

	l.UseCount++
	s.links[id] = l
	return true, nil
}

// PurgeExpired deletes every EmailInvite and Link expired strictly before
// before, and returns how many rows were removed in total. A Link with a nil
// ExpiresAt is never purged.
func (s *InviteStore) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for id, inv := range s.emailInvites {
		if inv.ExpiresAt.Before(before) {
			delete(s.emailInvites, id)
			n++
		}
	}
	for id, l := range s.links {
		if l.ExpiresAt != nil && l.ExpiresAt.Before(before) {
			delete(s.links, id)
			n++
		}
	}
	return n, nil
}
