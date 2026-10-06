package memory

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
)

// AuditStore is a concurrency-safe in-memory audit.Store and the reference
// implementation of the port. Every method holds mu for its whole body, so a
// check and the write it guards cannot be split — except Scan, which copies
// the matching events under mu and calls fn after releasing it, so fn may
// call the store.
type AuditStore struct {
	mu     sync.Mutex
	seq    int64
	events map[string]audit.Event
	seals  map[auditSealKey]audit.Seal
}

type auditSealKey struct {
	topic string
	day   string
}

// NewAuditStore returns an empty in-memory audit.Store.
func NewAuditStore() *AuditStore {
	return &AuditStore{events: map[string]audit.Event{}, seals: map[auditSealKey]audit.Seal{}}
}

// Compile-time proof the memory store satisfies the port.
var _ audit.Store = (*AuditStore)(nil)

func auditDayKey(t time.Time) string { return t.UTC().Format(time.DateOnly) }

func auditMidnight(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func cloneAuditEvent(e audit.Event) audit.Event {
	if e.CompletedAt != nil {
		at := *e.CompletedAt
		e.CompletedAt = &at
	}
	if e.ClientTime != nil {
		at := *e.ClientTime
		e.ClientTime = &at
	}
	e.Request = slices.Clone(e.Request)
	e.Changes = slices.Clone(e.Changes)
	return e
}

func cloneAuditSeal(s audit.Seal) audit.Seal {
	if s.PurgedAt != nil {
		at := *s.PurgedAt
		s.PurgedAt = &at
	}
	return s
}

func (s *AuditStore) matching(f audit.Filter) []audit.Event {
	var out []audit.Event
	for _, e := range s.events {
		if f.Match(e) {
			out = append(out, e)
		}
	}
	return out
}

// Insert stores e with the next Seq; an existing id returns the stored row,
// and a sealed (topic, day) is audit.ErrSealed.
func (s *AuditStore) Insert(_ context.Context, e audit.Event) (audit.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored, ok := s.events[e.ID]; ok {
		return cloneAuditEvent(stored), nil
	}
	if _, sealed := s.seals[auditSealKey{e.Topic, auditDayKey(e.OccurredAt)}]; sealed {
		return audit.Event{}, audit.ErrSealed
	}
	s.seq++
	e = cloneAuditEvent(e)
	e.Seq = s.seq
	s.events[e.ID] = e
	return cloneAuditEvent(e), nil
}

// Complete writes c onto the open event once; see audit.Store.
func (s *AuditStore) Complete(_ context.Context, id string, c audit.Closing) (audit.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.events[id]
	if !ok {
		return audit.Event{}, audit.ErrNotFound
	}
	if e.CompletedAt != nil {
		if audit.SameClosing(e, c) {
			return cloneAuditEvent(e), nil
		}
		return audit.Event{}, audit.ErrCompleted
	}
	at := c.At
	e.CompletedAt = &at
	e.Outcome, e.Code, e.Reason, e.DurationMS = c.Outcome, c.Code, c.Reason, c.DurationMS
	e.Changes = slices.Clone(c.Changes)
	if e.ContainerID == "" {
		e.ContainerID = c.ContainerID
	}
	if e.Resource == (audit.Resource{}) {
		e.Resource = c.Resource
	}
	s.events[id] = e
	return cloneAuditEvent(e), nil
}

// Get loads one event, or audit.ErrNotFound.
func (s *AuditStore) Get(_ context.Context, id string) (audit.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.events[id]
	if !ok {
		return audit.Event{}, audit.ErrNotFound
	}
	return cloneAuditEvent(e), nil
}

// List returns matching events, Seq descending, below page.Before.
func (s *AuditStore) List(_ context.Context, f audit.Filter, page audit.Page) ([]audit.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := page.Limit
	if limit <= 0 || limit > audit.MaxPageSize {
		limit = audit.MaxPageSize
	}
	matched := s.matching(f)
	slices.SortFunc(matched, func(a, b audit.Event) int { return cmp.Compare(b.Seq, a.Seq) })
	out := make([]audit.Event, 0, min(limit, len(matched)))
	for _, e := range matched {
		if page.Before > 0 && e.Seq >= page.Before {
			continue
		}
		out = append(out, cloneAuditEvent(e))
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// Count returns how many events match f.
func (s *AuditStore) Count(_ context.Context, f audit.Filter) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.matching(f)), nil
}

// Scan calls fn for every matching event, Seq ascending, outside the lock.
func (s *AuditStore) Scan(_ context.Context, f audit.Filter, fn func(audit.Event) error) error {
	s.mu.Lock()
	matched := s.matching(f)
	for i := range matched {
		matched[i] = cloneAuditEvent(matched[i])
	}
	s.mu.Unlock()
	slices.SortFunc(matched, func(a, b audit.Event) int { return cmp.Compare(a.Seq, b.Seq) })
	for _, e := range matched {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// OpenBefore returns open event ids older than before, oldest first.
func (s *AuditStore) OpenBefore(_ context.Context, before time.Time, limit int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var open []audit.Event
	for _, e := range s.events {
		if e.CompletedAt == nil && e.OccurredAt.Before(before) {
			open = append(open, e)
		}
	}
	slices.SortFunc(open, func(a, b audit.Event) int { return cmp.Compare(a.Seq, b.Seq) })
	if limit > 0 && len(open) > limit {
		open = open[:limit]
	}
	ids := make([]string, len(open))
	for i, e := range open {
		ids[i] = e.ID
	}
	return ids, nil
}

// LastSeal returns the topic's latest seal, or audit.ErrNotFound.
func (s *AuditStore) LastSeal(_ context.Context, topic string) (audit.Seal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var last audit.Seal
	found := false
	for k, sl := range s.seals {
		if k.topic == topic && (!found || sl.Day.After(last.Day)) {
			last, found = sl, true
		}
	}
	if !found {
		return audit.Seal{}, audit.ErrNotFound
	}
	return cloneAuditSeal(last), nil
}

// InsertSeal stores sl; an existing (topic, day) is audit.ErrSealExists.
func (s *AuditStore) InsertSeal(_ context.Context, sl audit.Seal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := auditSealKey{sl.Topic, auditDayKey(sl.Day)}
	if _, ok := s.seals[k]; ok {
		return audit.ErrSealExists
	}
	sl.Day = auditMidnight(sl.Day)
	s.seals[k] = cloneAuditSeal(sl)
	return nil
}

// Seals returns the topic's seals with Day in [from, to], ascending.
func (s *AuditStore) Seals(_ context.Context, topic string, from, to time.Time) ([]audit.Seal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	from, to = auditMidnight(from), auditMidnight(to)
	var out []audit.Seal
	for k, sl := range s.seals {
		if k.topic == topic && !sl.Day.Before(from) && !sl.Day.After(to) {
			out = append(out, cloneAuditSeal(sl))
		}
	}
	slices.SortFunc(out, func(a, b audit.Seal) int { return a.Day.Compare(b.Day) })
	return out, nil
}

// Purge deletes at most batch events of topic older than before, oldest
// first.
func (s *AuditStore) Purge(_ context.Context, topic string, before time.Time, batch int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var doomed []audit.Event
	for _, e := range s.events {
		if e.Topic == topic && e.OccurredAt.Before(before) {
			doomed = append(doomed, e)
		}
	}
	slices.SortFunc(doomed, func(a, b audit.Event) int { return cmp.Compare(a.Seq, b.Seq) })
	if batch > 0 && len(doomed) > batch {
		doomed = doomed[:batch]
	}
	for _, e := range doomed {
		delete(s.events, e.ID)
	}
	return len(doomed), nil
}

// MarkPurged stamps at on the topic's unpurged seals before before.
func (s *AuditStore) MarkPurged(_ context.Context, topic string, before, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sl := range s.seals {
		if k.topic == topic && sl.Day.Before(before) && sl.PurgedAt == nil {
			stamp := at
			sl.PurgedAt = &stamp
			s.seals[k] = sl
		}
	}
	return nil
}

// ScrubClientData clears IP and UserAgent on at most batch events of topic
// older than before, oldest first.
func (s *AuditStore) ScrubClientData(_ context.Context, topic string, before time.Time, batch int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var due []audit.Event
	for _, e := range s.events {
		if e.Topic == topic && e.OccurredAt.Before(before) && (e.IP != "" || e.UserAgent != "") {
			due = append(due, e)
		}
	}
	slices.SortFunc(due, func(a, b audit.Event) int { return cmp.Compare(a.Seq, b.Seq) })
	if batch > 0 && len(due) > batch {
		due = due[:batch]
	}
	for _, e := range due {
		e.IP, e.UserAgent = "", ""
		s.events[e.ID] = e
	}
	return len(due), nil
}

// AuditKeyStore is a concurrency-safe in-memory audit.KeyStore.
type AuditKeyStore struct {
	mu        sync.Mutex
	keys      map[string][]byte
	forgotten map[string]bool
}

// NewAuditKeyStore returns an empty in-memory audit.KeyStore.
func NewAuditKeyStore() *AuditKeyStore {
	return &AuditKeyStore{keys: map[string][]byte{}, forgotten: map[string]bool{}}
}

// Compile-time proof the memory key store satisfies the port.
var _ audit.KeyStore = (*AuditKeyStore)(nil)

// Key returns the subject's key, or audit.ErrNotFound.
func (s *AuditKeyStore) Key(_ context.Context, subject string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forgotten[subject] {
		return nil, audit.ErrForgotten
	}
	k, ok := s.keys[subject]
	if !ok {
		return nil, audit.ErrNotFound
	}
	return slices.Clone(k), nil
}

// PutKey stores key unless the subject has one, and returns the stored key.
func (s *AuditKeyStore) PutKey(_ context.Context, subject string, key []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forgotten[subject] {
		return nil, audit.ErrForgotten
	}
	if k, ok := s.keys[subject]; ok {
		return slices.Clone(k), nil
	}
	s.keys[subject] = slices.Clone(key)
	return slices.Clone(key), nil
}

// DeleteKey removes the subject's key and tombstones the subject.
func (s *AuditKeyStore) DeleteKey(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, subject)
	s.forgotten[subject] = true
	return nil
}
