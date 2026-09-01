package memory

import (
	"context"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// IdentityStore is a concurrency-safe in-memory auth.IdentityStore: the
// external ("sign in with Google/GitHub/…") identities of
// [github.com/bernardoforcillo/authlayer/auth.Service], and nothing else. It
// is wired with auth.WithIdentityStore and is entirely optional; an
// application offering no external sign-in never constructs one.
//
// It follows [AuthStore]'s discipline exactly, and for the same reason:
// every method holds mu for its entire body, so a check-then-write sequence
// can never be split by a concurrent call.
// [IdentityStore.DeleteIdentityIfNotLast] is where that stops being a
// generic concurrency-safety habit and becomes the point of the type — see
// its own doc, and auth.IdentityStore.DeleteIdentityIfNotLast's "It MUST be
// atomic" section, for the permanent, silent account lockout a split there
// produces.
//
// Unlike AuthStore it enforces EVERY uniqueness constraint its port declares
// rather than deferring any to store/drops. AuthStore defers Session.TokenHash
// and Verification.TokenHash on the grounds that a hash collision is an
// application-level concern; there is no equivalent here. The port has two
// uniqueness rules — Identity.ID and the (Provider, Subject) pair — and the
// second is the rule that keeps one external account from mapping to two
// local users, which is the same class of property as "one email, one
// account", the one constraint AuthStore does enforce in memory.
type IdentityStore struct {
	mu sync.Mutex
	// identities is keyed by Identity.ID. The (Provider, Subject) index that
	// CreateIdentity and FindIdentityByProviderSubject need is a linear scan
	// rather than a second map: a reference store trades speed for having
	// exactly one copy of the data and therefore no way for two indexes to
	// disagree, the same trade FindUserByEmail and FindSessionByHash already
	// make. store/drops indexes the columns.
	identities map[string]auth.Identity
}

// NewIdentityStore returns an empty in-memory auth.IdentityStore.
func NewIdentityStore() *IdentityStore {
	return &IdentityStore{identities: map[string]auth.Identity{}}
}

// CreateIdentity normalizes i.Email (see [auth.NormalizeEmail]), stores i
// under its ID, and returns what was stored. The id check, the
// (Provider, Subject) uniqueness scan and the write all happen under one
// acquisition of mu, so two concurrent calls for the same id or the same
// external account cannot both succeed: the second to reach the lock sees
// the first's row already present and returns auth.ErrIDTaken (checked
// first) or auth.ErrIdentityLinked (checked second), never overwriting it
// and never re-pointing an existing link at a different user.
//
// Provider and Subject are compared byte-for-byte — not folded, not
// normalized — matching auth.Identity.Provider's and Subject's docs. Email
// is the one field this method rewrites.
//
// Like [AuthStore.CreateUser] this checks before writing, which
// auth.Store.CreateUser's doc says a backend generally MUST NOT do, and it
// is compliant here for the identical reason: a Go map assignment has no
// independent failure mode, so there is no condition under which the scan
// above succeeds while the write below would independently fail, making
// check-then-write and write-then-classify indistinguishable against this
// specific backend. The enumeration-oracle half of that argument does not
// even arise here — ErrIdentityLinked answers a question about a provider
// subject the caller has already had asserted to them, not about whether an
// address is registered. A future change that gave this store's write path a
// failure mode of its own would invalidate the reasoning and require
// restructuring to write first.
func (s *IdentityStore) CreateIdentity(_ context.Context, i auth.Identity) (auth.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.identities[i.ID]; exists {
		return auth.Identity{}, auth.ErrIDTaken
	}
	for _, existing := range s.identities {
		if existing.Provider == i.Provider && existing.Subject == i.Subject {
			return auth.Identity{}, auth.ErrIdentityLinked
		}
	}
	i.Email = auth.NormalizeEmail(i.Email)
	s.identities[i.ID] = i
	return i, nil
}

// FindIdentityByProviderSubject scans for the identity whose Provider and
// Subject both match — byte-for-byte, neither folded nor normalized — or
// returns auth.ErrIdentityNotFound. A linear scan is fine for a reference
// store; store/drops indexes the columns.
//
// At most one row can match, because [IdentityStore.CreateIdentity] refuses
// to create a second: that is what makes "the hit IS the account" a safe
// first rung of the sign-in ladder rather than a coin flip over map
// iteration order.
func (s *IdentityStore) FindIdentityByProviderSubject(_ context.Context, provider, subject string) (auth.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, i := range s.identities {
		if i.Provider == provider && i.Subject == subject {
			return i, nil
		}
	}
	return auth.Identity{}, auth.ErrIdentityNotFound
}

// ListIdentitiesByUser returns every identity belonging to userID, and only
// that user's. A user with no identities yields an empty, non-nil slice and
// a nil error — but callers MUST NOT depend on which of empty or nil they
// get, because the port leaves that unspecified and a compliant backend may
// return the other. Order follows Go map iteration and is therefore
// randomised — sort the result if you depend on one.
func (s *IdentityStore) ListIdentitiesByUser(_ context.Context, userID string) ([]auth.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.Identity, 0)
	for _, i := range s.identities {
		if i.UserID == userID {
			out = append(out, i)
		}
	}
	return out, nil
}

// TouchIdentity stamps LastUsedAt with now on the identity, or returns
// auth.ErrIdentityNotFound when id matches no row. The find and the write
// happen under one acquisition of mu, matching every other mutating method
// in this package.
func (s *IdentityStore) TouchIdentity(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.identities[id]
	if !ok {
		return auth.ErrIdentityNotFound
	}
	i.LastUsedAt = &now
	s.identities[id] = i
	return nil
}

// DeleteIdentity removes the one row named by id, or returns
// auth.ErrIdentityNotFound when id matches no row. It touches nothing else.
//
// Unlike [IdentityStore.DeleteIdentityIfNotLast] it makes no reachability
// check at all, and will remove an account's last credential if asked — see
// auth.IdentityStore.DeleteIdentity for the two service callers that may ask
// and why neither is removing a way in the account relies on. The lookup and
// the delete share one acquisition of mu like every other method here, though
// nothing here is a check-then-act: there is no decision to split.
func (s *IdentityStore) DeleteIdentity(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.identities[id]; !ok {
		return auth.ErrIdentityNotFound
	}
	delete(s.identities, id)
	return nil
}

// DeleteIdentityIfNotLast removes every identity of userID at provider, but
// only when the account is still reachable afterwards — either another
// identity survives the delete or userHasOtherCredential is true. Otherwise it
// returns auth.ErrLastCredential and removes NOTHING. Returns
// auth.ErrIdentityNotFound when the user has no identity at that provider.
//
// The scan, the reachability decision and the delete all happen under ONE
// acquisition of mu. That is the whole contract of this method — see
// auth.IdentityStore.DeleteIdentityIfNotLast's "It MUST be atomic" section
// for what a split produces: two concurrent unlinks of a password-less
// user's last two identities each observe the other's row, each conclude the
// account stays reachable, and each delete, leaving an account with no
// credential of any kind and both requests reporting success. The lockout is
// permanent and silent. This is the same single-acquisition discipline
// [AuthStore.MarkRotated] and [AuthStore.CreateSuccessorSession] apply to
// their own check-and-write, and it is load-bearing here in exactly the way
// it is there — see this package's mandatory atomicity test and the
// deterministic split-lock control committed beside it.
//
// The survivor count is what remains AFTER the delete, not the user's total
// row count, and the delete takes every matching row rather than one of
// them. Nothing forbids a user holding two identities at the same provider,
// so a password-less user whose only two identities are both at provider P
// is refused: unlinking P would take both and leave nothing, even though the
// store holds two rows for them.
func (s *IdentityStore) DeleteIdentityIfNotLast(_ context.Context, userID, provider string, userHasOtherCredential bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var doomed []string
	survivors := 0
	for id, i := range s.identities {
		switch {
		case i.UserID != userID:
			// Another user's row. Never in scope, never counted.
		case i.Provider == provider:
			doomed = append(doomed, id)
		default:
			survivors++
		}
	}

	if len(doomed) == 0 {
		return auth.ErrIdentityNotFound
	}
	if survivors == 0 && !userHasOtherCredential {
		return auth.ErrLastCredential
	}
	for _, id := range doomed {
		delete(s.identities, id)
	}
	return nil
}
