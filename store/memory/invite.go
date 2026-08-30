package memory

import (
	"context"
	"errors"
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
// are fixed shapes.
//
// It enforces all three uniqueness constraints [invite.Store] states on the
// record types: EmailInvite.TokenHash, EmailInvite's (ContainerID, Email)
// pair, and Link.Code. Each check happens under the same acquisition of mu as
// the write it guards, so two concurrent creates can never both pass it.
//
// It did NOT always. All three were deferred to store/drops — which has
// enforced them as UNIQUE constraints from the start (token_hash and code
// each on their own, container_id+email as a pair; see store/drops's
// InviteSchema) — on the reading that a collision is an application-level
// constraint the way a slug is, and this type's own doc used to say so. That
// reading does not survive the port's text. A shared TokenHash or Code
// defeats the single-winner property of [InviteStore.DeleteEmailInvite] and
// [InviteStore.ConsumeLink] with no atomicity defect at all: two concurrent
// redeemers resolve DIFFERENT colliding rows through
// FindEmailInviteByTokenHash or FindLinkByCode and each correctly, atomically
// wins the row it happened to pick, so a one-time token pays out twice and a
// MaxUses:1 link admits two people. A duplicated (ContainerID, Email) pair is
// what turns re-inviting an address into duplicating rather than replacing,
// leaving a second live token behind a revocation performed from a screen
// that shows one row. Deferring them meant a caller could develop here and
// meet the constraint for the first time in production against store/drops;
// closing them is what
// [github.com/bernardoforcillo/authlayer/invite/invitetest] tests both
// backends for. See [ErrTokenHashTaken], [ErrInviteEmailTaken] and
// [ErrLinkCodeTaken] for what each collision reports.
//
// One divergence from store/drops remains and is NOT a uniqueness constraint
// the port states: store/drops types an invite's and a link's id as a PRIMARY
// KEY, so re-using one is a unique violation there, while this store keys
// both maps by ID and a create under an id already present overwrites the row.
// [invite.Store] documents no id-collision contract and authlayer/invite has
// no sentinel for one (unlike auth.ErrIDTaken), so nothing here is entitled
// to invent one; the service mints a fresh UUIDv7 for every record, so the
// case does not arise in practice. It is recorded rather than closed
// silently.
type InviteStore struct {
	mu           sync.Mutex
	emailInvites map[string]invite.EmailInvite
	links        map[string]invite.Link
}

// ErrInviteEmailTaken reports that [InviteStore.CreateEmailInvite] would have
// stored a second pending invite for a (ContainerID, Email) pair that already
// has one — the uniqueness [invite.EmailInvite] requires of a backend, and
// what store/drops enforces as UNIQUE (container_id, email).
//
// The obligation is on the PAIR, not on the address: the same person invited
// to two different containers is two legitimate rows, and this error is never
// returned for that.
//
// Like [ErrTokenHashTaken] it is deliberately not one of authlayer/invite's
// sentinels. That package's errors cover not-found and the three reasons a
// redemption did not happen; it classifies no conflict-on-create at all, so
// there is nothing there to reuse and inventing a meaning for an existing
// sentinel would tell a caller something false. store/drops answers the same
// case with the driver's own pg.ErrUniqueViolation unwrapped.
var ErrInviteEmailTaken = errors.New("authlayer/store/memory: this container already has a pending invite for that address")

// ErrLinkCodeTaken reports that [InviteStore.CreateLink] would have stored a
// second link under a code another link already holds — the uniqueness
// [invite.Link] requires of a backend, and what store/drops enforces as
// UNIQUE (code).
//
// It is a backend-level error for the same reason [ErrInviteEmailTaken] is.
var ErrLinkCodeTaken = errors.New("authlayer/store/memory: link code already exists")

// NewInviteStore returns an empty in-memory invite.Store.
func NewInviteStore() *InviteStore {
	return &InviteStore{
		emailInvites: map[string]invite.EmailInvite{},
		links:        map[string]invite.Link{},
	}
}

// CreateEmailInvite stores the invite under its ID and returns it unchanged,
// or returns [ErrTokenHashTaken] if another invite already holds
// inv.TokenHash, or [ErrInviteEmailTaken] if the (ContainerID, Email) pair
// already has a pending invite. Both checks and the write happen under one
// acquisition of mu, so two concurrent calls contending for a hash or a pair
// cannot both pass: the second to reach the lock sees the first's row already
// present.
//
// The hash is checked first, so an invite that collides on both reports the
// collision that matters to the redemption path.
func (s *InviteStore) CreateEmailInvite(_ context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inviteHashTaken(inv.TokenHash) {
		return invite.EmailInvite{}, ErrTokenHashTaken
	}
	if s.pendingInviteFor(inv.ContainerID, inv.Email) {
		return invite.EmailInvite{}, ErrInviteEmailTaken
	}
	s.emailInvites[inv.ID] = inv
	return inv, nil
}

// inviteHashTaken reports whether any stored invite already holds tokenHash.
// Callers hold mu. A linear scan is fine for a reference store; store/drops
// has a UNIQUE index do the same job.
func (s *InviteStore) inviteHashTaken(tokenHash string) bool {
	for _, inv := range s.emailInvites {
		if inv.TokenHash == tokenHash {
			return true
		}
	}
	return false
}

// pendingInviteFor reports whether (containerID, email) already has a pending
// invite. Callers hold mu.
func (s *InviteStore) pendingInviteFor(containerID, email string) bool {
	for _, inv := range s.emailInvites {
		if inv.ContainerID == containerID && inv.Email == email {
			return true
		}
	}
	return false
}

// FindEmailInviteByTokenHash scans for the invite whose TokenHash matches, or
// returns invite.ErrInviteNotFound. At most one row can match, because
// [InviteStore.CreateEmailInvite] refuses a colliding hash. A linear scan is
// fine for a reference store; store/drops gets the same guarantee and an
// index for this lookup — the acceptance path every redeemed invitation runs
// — out of one UNIQUE constraint on token_hash.
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

// CreateLink stores the link under its ID and returns it unchanged, or
// returns [ErrLinkCodeTaken] if another link already holds l.Code. The check
// and the write happen under one acquisition of mu, so two concurrent calls
// for one code cannot both pass.
func (s *InviteStore) CreateLink(_ context.Context, l invite.Link) (invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.linkCodeTaken(l.Code) {
		return invite.Link{}, ErrLinkCodeTaken
	}
	s.links[l.ID] = l
	return l, nil
}

// linkCodeTaken reports whether any stored link already holds code. Callers
// hold mu. A linear scan is fine for a reference store; store/drops has a
// UNIQUE index do the same job.
func (s *InviteStore) linkCodeTaken(code string) bool {
	for _, l := range s.links {
		if l.Code == code {
			return true
		}
	}
	return false
}

// FindLinkByCode scans for the link whose Code matches, or returns
// invite.ErrLinkNotFound. At most one row can match, because
// [InviteStore.CreateLink] refuses a colliding code. A linear scan is fine
// for a reference store; store/drops gets the same guarantee, and an index,
// out of one UNIQUE constraint on code.
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

// ConsumeLink checks that the link is unrevoked, strictly unexpired at now,
// and below MaxUses, and increments UseCount if and only if all three hold —
// all under a single acquisition of mu, so no concurrent caller can observe
// or act on an intermediate state. See the atomicity requirement on
// [invite.Store]; splitting this into a locked read followed by a
// separately-locked write would let two callers both pass the check before
// either writes, letting a MaxUses:1 link admit more than one user.
//
// "Strictly unexpired" means the ExpiresAt instant itself already counts as
// expired: consumption succeeds only while now is strictly before ExpiresAt,
// never at or after it. That boundary is deliberately tighter than
// PurgeExpired's, which only removes rows strictly before its cutoff — so a
// link exactly at ExpiresAt survives one more PurgeExpired pass even though
// ConsumeLink already refuses it. ConsumeLink is a real-time gate that must
// never admit anyone at or past the deadline; PurgeExpired is housekeeping
// that can afford to lag by one instant. That asymmetry is intentional, not
// a bug to reconcile.
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
	// now == ExpiresAt counts as expired: valid strictly before, never at or
	// after (see the boundary note in the doc comment above).
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
// before, and returns how many rows were removed in total. A row whose
// ExpiresAt equals before exactly is left alone here — it is picked up on a
// later call once before has advanced past it — and a Link with a nil
// ExpiresAt is never purged. See ConsumeLink's doc for why its own boundary,
// at the expiry instant itself, is deliberately tighter than this one.
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
