package invitetest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
)

// The conflicts [refStore] reports on a create it refuses. [invite.Store]
// classifies no conflict-on-create at all — its sentinels cover not-found and
// the three redemption refusals — so these are deliberately not package
// sentinels, exactly like store/drops, which lets PostgreSQL's own unique
// violation through unwrapped on the same paths, and like store/memory, which
// answers with its own package-local errors. Nothing in the contract suite
// looks at them; the checks require only that the write failed.
var (
	errDuplicateTokenHash = errors.New("invitetest: token hash already exists")
	errDuplicateCode      = errors.New("invitetest: link code already exists")
	errDuplicatePair      = errors.New("invitetest: (container, email) already has a pending invite")
)

// refStore is a compliant [invite.Store] written for this package's own
// tests. It exists so the deliberately non-compliant doubles in
// negative_test.go can each be exactly ONE defect away from a correct store:
// every one of them embeds a *refStore and overrides a single method,
// reaching this type's maps directly, which is why it lives here rather than
// being replaced by store/memory's InviteStore (whose internals are
// unexported, and which is a backend under test by this suite rather than the
// fixture that defines what passing it looks like).
//
// Every method holds mu for its entire body, so no check-then-write in it can
// be split by a concurrent call — the shape [invite.Store.ConsumeLink]'s
// atomicity MUST names for an in-process store.
// TestTheReferenceStorePassesTheContract is what makes the negative controls
// mean anything: without it, a double failing a check would be evidence about
// the double's base, not about the defect injected on top of it.
type refStore struct {
	mu           sync.Mutex
	emailInvites map[string]invite.EmailInvite
	links        map[string]invite.Link
}

func newRefStore() *refStore {
	return &refStore{
		emailInvites: map[string]invite.EmailInvite{},
		links:        map[string]invite.Link{},
	}
}

var _ invite.Store = (*refStore)(nil)

// tokenHashTaken reports whether any invite already holds tokenHash. Callers
// hold mu.
func (s *refStore) tokenHashTaken(tokenHash string) bool {
	for _, inv := range s.emailInvites {
		if inv.TokenHash == tokenHash {
			return true
		}
	}
	return false
}

// pairTaken reports whether any invite already holds (containerID, email).
// Callers hold mu.
func (s *refStore) pairTaken(containerID, email string) bool {
	for _, inv := range s.emailInvites {
		if inv.ContainerID == containerID && inv.Email == email {
			return true
		}
	}
	return false
}

// codeTaken reports whether any link already holds code. Callers hold mu.
func (s *refStore) codeTaken(code string) bool {
	for _, l := range s.links {
		if l.Code == code {
			return true
		}
	}
	return false
}

func (s *refStore) CreateEmailInvite(_ context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenHashTaken(inv.TokenHash) {
		return invite.EmailInvite{}, errDuplicateTokenHash
	}
	if s.pairTaken(inv.ContainerID, inv.Email) {
		return invite.EmailInvite{}, errDuplicatePair
	}
	s.emailInvites[inv.ID] = inv
	return inv, nil
}

func (s *refStore) FindEmailInviteByTokenHash(_ context.Context, tokenHash string) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inv := range s.emailInvites {
		if inv.TokenHash == tokenHash {
			return inv, nil
		}
	}
	return invite.EmailInvite{}, invite.ErrInviteNotFound
}

func (s *refStore) FindEmailInvite(_ context.Context, id string) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.emailInvites[id]
	if !ok {
		return invite.EmailInvite{}, invite.ErrInviteNotFound
	}
	return inv, nil
}

func (s *refStore) ListEmailInvites(_ context.Context, containerID string) ([]invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []invite.EmailInvite
	for _, inv := range s.emailInvites {
		if inv.ContainerID == containerID {
			out = append(out, inv)
		}
	}
	return out, nil
}

func (s *refStore) DeleteEmailInvite(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.emailInvites[id]; !ok {
		return invite.ErrInviteNotFound
	}
	delete(s.emailInvites, id)
	return nil
}

func (s *refStore) DeleteEmailInvitesFor(_ context.Context, containerID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, inv := range s.emailInvites {
		if inv.ContainerID == containerID && inv.Email == email {
			delete(s.emailInvites, id)
		}
	}
	return nil
}

func (s *refStore) CreateLink(_ context.Context, l invite.Link) (invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codeTaken(l.Code) {
		return invite.Link{}, errDuplicateCode
	}
	s.links[l.ID] = l
	return l, nil
}

func (s *refStore) FindLinkByCode(_ context.Context, code string) (invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.links {
		if l.Code == code {
			return l, nil
		}
	}
	return invite.Link{}, invite.ErrLinkNotFound
}

func (s *refStore) FindLink(_ context.Context, id string) (invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return invite.Link{}, invite.ErrLinkNotFound
	}
	return l, nil
}

func (s *refStore) ListLinks(_ context.Context, containerID string) ([]invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []invite.Link
	for _, l := range s.links {
		if l.ContainerID == containerID {
			out = append(out, l)
		}
	}
	return out, nil
}

func (s *refStore) RevokeLink(_ context.Context, id string, at time.Time) error {
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

func (s *refStore) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	// now == ExpiresAt already counts as expired: ExpiresAt is when the link
	// stops being redeemable, so consumption succeeds only strictly before it.
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

func (s *refStore) PurgeExpired(_ context.Context, before time.Time) (int, error) {
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
