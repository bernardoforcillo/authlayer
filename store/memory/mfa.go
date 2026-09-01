package memory

import (
	"context"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// MFAStore is a concurrency-safe in-memory auth.MFAStore: the TOTP factors
// and recovery codes of
// [github.com/bernardoforcillo/authlayer/auth.Service], and nothing else.
// It is wired with auth.WithMFAStore and is entirely optional; an
// application offering no second factor never constructs one.
//
// It follows [AuthStore]'s and [IdentityStore]'s discipline exactly, and
// for the same reason: every method holds mu for its entire body, so a
// check-then-write sequence can never be split by a concurrent call. Three
// of the eight methods are where that stops being a generic habit and
// becomes the point of the type — [MFAStore.ConfirmFactor],
// [MFAStore.AdvanceStep] and [MFAStore.ConsumeRecoveryCode] each carry a
// MUST on the port, and each of the three has a deterministic split-lock
// control committed beside the contract suite that proves the check bites.
//
// It stores what it is handed. The TOTP secret arrives already encrypted
// (auth.MFAFactor.SecretEnc) and the recovery codes already hashed
// (auth.RecoveryCode.CodeHash); this type encrypts nothing, hashes nothing,
// and has no way to recover either plaintext.
type MFAStore struct {
	mu sync.Mutex
	// factors is keyed by user id. That IS the port's "at most one factor
	// per user" rule — expressed as the data structure rather than checked
	// on the way in, which is the in-memory equivalent of store/drops'
	// PRIMARY KEY on the column.
	factors map[string]auth.MFAFactor
	// codes is keyed by recovery-code id. Finding a user's codes is a
	// linear scan rather than a second map: a reference store trades speed
	// for having exactly one copy of the data and therefore no way for two
	// indexes to disagree, the same trade FindUserByEmail and
	// FindIdentityByProviderSubject already make. store/drops indexes the
	// column.
	codes map[string]auth.RecoveryCode
	// devices is keyed by trusted-device id. Locating one by token hash, or
	// locating a user's, is a linear scan for the same reason codes is: one
	// copy of the data and therefore no way for two indexes to disagree.
	// store/drops indexes user_id and constrains token_hash UNIQUE; here
	// CreateTrustedDevice enforces that uniqueness under the same lock as
	// the write it guards. trusted.go holds this type's trusted-device half.
	devices map[string]auth.TrustedDevice
}

// NewMFAStore returns an empty in-memory auth.MFAStore.
func NewMFAStore() *MFAStore {
	return &MFAStore{
		factors: map[string]auth.MFAFactor{},
		codes:   map[string]auth.RecoveryCode{},
		devices: map[string]auth.TrustedDevice{},
	}
}

// UpsertFactor stores f as its user's one factor, REPLACING any existing
// row in full — every field, including the nil ConfirmedAt and LastStep a
// fresh enrolment carries.
//
// The replacement is a single map assignment rather than a merge, which is
// exactly what auth.MFAStore.UpsertFactor's MUST requires and not merely a
// convenient way to write it: keeping a previous ConfirmedAt would leave a
// brand-new secret already marked confirmed, so an enrolment the user
// abandoned half way would gate every later login with a secret no
// authenticator holds. Keeping a previous LastStep would refuse the new
// secret's first genuine code as a replay.
func (s *MFAStore) UpsertFactor(_ context.Context, f auth.MFAFactor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.factors[f.UserID] = f
	return nil
}

// FindFactor returns the user's factor, or auth.ErrFactorNotFound when
// they have none — which is the ordinary state of an account that has
// never enrolled, not a failure.
func (s *MFAStore) FindFactor(_ context.Context, userID string) (auth.MFAFactor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return auth.MFAFactor{}, auth.ErrFactorNotFound
	}
	return f, nil
}

// ConfirmFactor stamps ConfirmedAt with now if and only if it is still
// nil, reporting whether this call did it, and returns
// auth.ErrFactorNotFound when the user has no factor. An
// already-confirmed factor keeps its ORIGINAL stamp.
//
// The read, the decision and the write share one acquisition of mu, so
// exactly one of any number of concurrent callers can win. That matters
// because the winner is the caller that hands the user their recovery
// codes, and generating a set replaces the previous one: two winners means
// two sets shown and the second silently invalidating the first — on the
// one screen a user is most likely to double-submit.
func (s *MFAStore) ConfirmFactor(_ context.Context, userID string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return false, auth.ErrFactorNotFound
	}
	if f.ConfirmedAt != nil {
		return false, nil
	}
	f.ConfirmedAt = &now
	s.factors[userID] = f
	return true, nil
}

// AdvanceStep records step as the factor's most recent TOTP step if and
// only if it is strictly greater than the stored LastStep, reporting
// whether it did, and returns auth.ErrFactorNotFound when the user has no
// factor. A nil LastStep — the factor has authenticated nothing yet —
// accepts any step.
//
// This is the replay guard, and the comparison and the write share one
// acquisition of mu because that is the whole method. A split would let
// two concurrent presentations of the SAME code both read the old
// LastStep, both find their step greater, and both succeed — which is the
// replay this refuses, arriving as a race instead of a sequence, and an
// attacker replaying a captured code alongside the user's own submission
// is the natural shape of the attack rather than an exotic interleaving.
//
// It does not consider whether the factor is confirmed: that decision
// belongs to the service, which makes it before calling here.
func (s *MFAStore) AdvanceStep(_ context.Context, userID string, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return false, auth.ErrFactorNotFound
	}
	if f.LastStep != nil && step <= *f.LastStep {
		return false, nil
	}
	f.LastStep = &step
	s.factors[userID] = f
	return true, nil
}

// DeleteFactor removes the user's factor row and NOTHING else — their
// recovery codes stay exactly where they are — or returns
// auth.ErrFactorNotFound when there is no factor.
//
// See auth.MFAStore.DeleteFactor for why the cascade is the caller's
// decision and what that caller therefore owes: disabling MFA means
// clearing the recovery codes too, with ReplaceRecoveryCodes(ctx, userID,
// nil), because those are credentials in their own right.
func (s *MFAStore) DeleteFactor(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.factors[userID]; !ok {
		return auth.ErrFactorNotFound
	}
	delete(s.factors, userID)
	return nil
}

// ReplaceRecoveryCodes replaces the user's entire set with codes: every
// existing row of theirs is removed and every code is stored, under one
// acquisition of mu so no reader ever sees the account between the two
// halves. A nil or empty codes clears the set, which is how a caller
// revokes recovery codes without issuing new ones.
//
// Both refusals are decided BEFORE anything is removed, which is what
// makes a refused call write nothing: a code naming another user is
// auth.ErrRecoveryCodeUserMismatch, and an id repeated within the call or
// already held by another user's row is auth.ErrIDTaken. An id held by a
// row this call is itself removing is free to reuse — it is gone by the
// time the new set lands.
//
// Deciding before writing is what auth.Store.CreateUser's own doc says a
// backend generally MUST NOT do, and it is compliant here for the
// identical reason store/memory's other check-then-write methods are: a Go
// map assignment has no independent failure mode, so there is no condition
// under which these checks pass while the writes below would fail on their
// own. A future change that gave this store's write path a failure mode
// would invalidate the reasoning and require restructuring.
func (s *MFAStore) ReplaceRecoveryCodes(_ context.Context, userID string, codes []auth.RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[string]bool, len(codes))
	for _, c := range codes {
		if c.UserID != userID {
			return auth.ErrRecoveryCodeUserMismatch
		}
		if seen[c.ID] {
			return auth.ErrIDTaken
		}
		seen[c.ID] = true
		if existing, ok := s.codes[c.ID]; ok && existing.UserID != userID {
			return auth.ErrIDTaken
		}
	}

	for id, c := range s.codes {
		if c.UserID == userID {
			delete(s.codes, id)
		}
	}
	for _, c := range codes {
		s.codes[c.ID] = c
	}
	return nil
}

// ConsumeRecoveryCode burns the user's UNUSED code whose stored hash
// equals codeHash, stamping UsedAt with now, and reports whether this call
// burned it. A hash that matches no unused code of theirs — wrong, already
// spent, or no such user — is (false, nil), never an error: this is a
// credential check, and its only two honest answers are "burned it" and
// "did not".
//
// The scan and the stamp share one acquisition of mu, so of any number of
// concurrent consumers of one code exactly one is told it won — the
// property that makes the code single-use.
//
// Every row matching (userID, codeHash) is burned rather than the first
// one found. Nothing here can create two such rows, but the port requires
// it of an implementation that somehow holds them, and burning one of a
// duplicated pair would leave a live second copy of a code that has just
// been spent.
func (s *MFAStore) ConsumeRecoveryCode(_ context.Context, userID, codeHash string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	burnt := false
	for id, c := range s.codes {
		if c.UserID != userID || c.CodeHash != codeHash || c.UsedAt != nil {
			continue
		}
		c.UsedAt = &now
		s.codes[id] = c
		burnt = true
	}
	return burnt, nil
}

// ListRecoveryCodes returns every recovery code belonging to userID — used
// and unused alike — and only that user's. A user with none yields an
// empty, non-nil slice and a nil error, but callers MUST NOT depend on
// which of empty or nil they get: the port leaves that unspecified and
// store/drops returns the other. Order follows Go map iteration and is
// therefore randomised — sort the result if you depend on one.
func (s *MFAStore) ListRecoveryCodes(_ context.Context, userID string) ([]auth.RecoveryCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.RecoveryCode, 0)
	for _, c := range s.codes {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}
