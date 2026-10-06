// Package consent keeps the record of who agreed to what, and when: the
// "accepted the terms of service v3 on 12 March" a data controller must be
// able to demonstrate (GDPR Art. 7(1)) and a data subject must be able to
// withdraw as easily as they gave it (Art. 7(3)).
//
// A [Record] is one acceptance of one purpose at one version. Records are
// appended, never edited: accepting a new version ends the previous record
// with [EndSuperseded], withdrawing ends it with [EndWithdrawn], and the whole
// history stays readable with [Service.History]. [Service.Accepted] is the
// question an application asks before it acts: has this person accepted
// exactly this version of this purpose, and not withdrawn it?
//
// What a purpose or a version is, is yours: "terms", "marketing_email",
// "analytics"; "2026-03", "v3". This package compares them byte for byte and
// never parses them. It stores no IP address and no free text, because the
// proof of consent is the act, its time and its version, and every extra field
// is more personal data to protect.
//
// [Service.Erase] deletes a person's records. Art. 7(1) asks you to be able to
// demonstrate consent while you rely on it, and Art. 17 asks you to erase it
// when you stop; call Erase at the point your own retention rules say the
// proof is no longer needed.
package consent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/internal/uid"
)

// Why a record ended.
const (
	// EndWithdrawn: the person withdrew their consent.
	EndWithdrawn = "withdrawn"
	// EndSuperseded: the person accepted a newer version of the purpose.
	EndSuperseded = "superseded"
)

// Record is one acceptance.
type Record struct {
	// ID identifies the record, minted by the Service.
	ID string
	// SubjectID is the person, an opaque id from your user table.
	SubjectID string
	// Purpose is what was agreed to, e.g. "terms" or "marketing_email".
	Purpose string
	// Version is which text of it, e.g. "2026-03".
	Version string
	// Source says where it was given, e.g. "signup_form"; optional.
	Source string
	// GrantedAt is when the person accepted.
	GrantedAt time.Time
	// EndedAt is when the record stopped being current; nil while it is.
	EndedAt *time.Time
	// EndReason is [EndWithdrawn] or [EndSuperseded] once EndedAt is set.
	EndReason string
}

// Sentinel errors; compare with errors.Is.
var (
	// ErrInvalid: a required field is empty.
	ErrInvalid = errors.New("authlayer/consent: invalid argument")
	// ErrNotFound: the person has no current consent for the purpose.
	ErrNotFound = errors.New("authlayer/consent: not found")
	// ErrConflict: the person already has a current record for the purpose;
	// what [Store.Insert] answers a second concurrent grant with.
	ErrConflict = errors.New("authlayer/consent: a current record exists")
)

// Store is the persistence port. It authorizes and validates nothing.
type Store interface {
	// Insert stores r, or returns ErrConflict when the subject already has a
	// record for the same purpose that has not ended. The check and the write
	// MUST be one atomic step.
	Insert(ctx context.Context, r Record) error
	// Current returns the subject's record for purpose that has not ended,
	// or ErrNotFound. At most one exists.
	Current(ctx context.Context, subjectID, purpose string) (Record, error)
	// End stamps EndedAt = at and EndReason on the subject's current record
	// for purpose, and returns how many it ended (0 or 1).
	End(ctx context.Context, subjectID, purpose string, at time.Time, reason string) (int, error)
	// List returns every record of the subject, oldest first.
	List(ctx context.Context, subjectID string) ([]Record, error)
	// DeleteSubject deletes every record of the subject and returns how many.
	DeleteSubject(ctx context.Context, subjectID string) (int, error)
}

type config struct {
	clock func() time.Time
	idgen func() string
}

// Option customizes a Service.
type Option func(*config)

// WithRuntime takes the clock and id generator from a shared core.Runtime.
func WithRuntime(r core.Runtime) Option {
	return func(c *config) {
		if r.Clock != nil {
			c.clock = r.Clock
		}
		if r.IDs != nil {
			c.idgen = r.IDs
		}
	}
}

// Service records and answers consent over a Store. It caches nothing and is
// safe for concurrent use if its Store is.
type Service struct {
	store Store
	cfg   config
}

// New returns a Service over store.
func New(store Store, opts ...Option) *Service {
	cfg := config{clock: func() time.Time { return time.Now().UTC() }, idgen: uid.NewV7}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return &Service{store: store, cfg: cfg}
}

func (s *Service) now() time.Time { return s.cfg.clock().UTC().Truncate(time.Microsecond) }

// Grant records that subjectID accepted version of purpose, and returns the
// record. Accepting the version already current is a no-op that returns the
// existing record; accepting a different one ends the old record as
// superseded first. Errors: ErrInvalid, and the Store's.
func (s *Service) Grant(ctx context.Context, subjectID, purpose, version, source string) (Record, error) {
	switch {
	case subjectID == "":
		return Record{}, fmt.Errorf("%w: empty subject", ErrInvalid)
	case purpose == "":
		return Record{}, fmt.Errorf("%w: empty purpose", ErrInvalid)
	case version == "":
		return Record{}, fmt.Errorf("%w: empty version", ErrInvalid)
	}
	// Two attempts: the second only after losing a race to another grant.
	for range 2 {
		cur, err := s.store.Current(ctx, subjectID, purpose)
		switch {
		case err == nil && cur.Version == version:
			return cur, nil
		case err == nil:
			if _, err := s.store.End(ctx, subjectID, purpose, s.now(), EndSuperseded); err != nil {
				return Record{}, err
			}
		case !errors.Is(err, ErrNotFound):
			return Record{}, err
		}
		r := Record{ID: s.cfg.idgen(), SubjectID: subjectID, Purpose: purpose, Version: version,
			Source: source, GrantedAt: s.now()}
		switch err := s.store.Insert(ctx, r); {
		case err == nil:
			return r, nil
		case !errors.Is(err, ErrConflict):
			return Record{}, err
		}
	}
	return Record{}, ErrConflict
}

// Withdraw ends the subject's current consent for purpose. It is
// ErrNotFound when there is none, so a caller can tell a withdrawal from a
// no-op.
func (s *Service) Withdraw(ctx context.Context, subjectID, purpose string) error {
	if subjectID == "" || purpose == "" {
		return fmt.Errorf("%w: empty subject or purpose", ErrInvalid)
	}
	n, err := s.store.End(ctx, subjectID, purpose, s.now(), EndWithdrawn)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Current returns the subject's current record for purpose, or ErrNotFound.
func (s *Service) Current(ctx context.Context, subjectID, purpose string) (Record, error) {
	return s.store.Current(ctx, subjectID, purpose)
}

// Accepted reports whether the subject currently holds consent for exactly
// this version of purpose. A newer version in force, a withdrawal and no
// record at all all answer false.
func (s *Service) Accepted(ctx context.Context, subjectID, purpose, version string) (bool, error) {
	cur, err := s.store.Current(ctx, subjectID, purpose)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil && cur.Version == version, err
}

// History returns every record of the subject, oldest first: the proof of
// what they agreed to and when, and what an access request (Art. 15) returns.
func (s *Service) History(ctx context.Context, subjectID string) ([]Record, error) {
	return s.store.List(ctx, subjectID)
}

// Erase deletes every consent record of the subject and returns how many.
func (s *Service) Erase(ctx context.Context, subjectID string) (int, error) {
	if subjectID == "" {
		return 0, fmt.Errorf("%w: empty subject", ErrInvalid)
	}
	return s.store.DeleteSubject(ctx, subjectID)
}
