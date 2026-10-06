package memory

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/consent"
)

// ConsentStore is a concurrency-safe in-memory consent.Store.
type ConsentStore struct {
	mu      sync.Mutex
	records []consent.Record
}

// NewConsentStore returns an empty in-memory consent.Store.
func NewConsentStore() *ConsentStore { return &ConsentStore{} }

// Compile-time proof the memory store satisfies the port.
var _ consent.Store = (*ConsentStore)(nil)

func cloneConsent(r consent.Record) consent.Record {
	if r.EndedAt != nil {
		at := *r.EndedAt
		r.EndedAt = &at
	}
	return r
}

// Insert stores r.
func (s *ConsentStore) Insert(_ context.Context, r consent.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.EndedAt == nil {
		for _, o := range s.records {
			if o.SubjectID == r.SubjectID && o.Purpose == r.Purpose && o.EndedAt == nil {
				return consent.ErrConflict
			}
		}
	}
	s.records = append(s.records, cloneConsent(r))
	return nil
}

// Current returns the subject's record for purpose that has not ended.
func (s *ConsentStore) Current(_ context.Context, subjectID, purpose string) (consent.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.SubjectID == subjectID && r.Purpose == purpose && r.EndedAt == nil {
			return cloneConsent(r), nil
		}
	}
	return consent.Record{}, consent.ErrNotFound
}

// End stamps the subject's current record for purpose.
func (s *ConsentStore) End(_ context.Context, subjectID, purpose string, at time.Time, reason string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for i := range s.records {
		r := &s.records[i]
		if r.SubjectID == subjectID && r.Purpose == purpose && r.EndedAt == nil {
			stamp := at
			r.EndedAt, r.EndReason = &stamp, reason
			n++
		}
	}
	return n, nil
}

// List returns the subject's records, oldest first.
func (s *ConsentStore) List(_ context.Context, subjectID string) ([]consent.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []consent.Record
	for _, r := range s.records {
		if r.SubjectID == subjectID {
			out = append(out, cloneConsent(r))
		}
	}
	slices.SortStableFunc(out, func(a, b consent.Record) int { return a.GrantedAt.Compare(b.GrantedAt) })
	return out, nil
}

// DeleteSubject deletes every record of the subject.
func (s *ConsentStore) DeleteSubject(_ context.Context, subjectID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.records)
	s.records = slices.DeleteFunc(s.records, func(r consent.Record) bool { return r.SubjectID == subjectID })
	return before - len(s.records), nil
}
