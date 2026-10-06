package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/uid"
)

// DefaultRetention is how long a topic without its own Retention keeps its
// events.
const DefaultRetention = 365 * 24 * time.Hour

type config struct {
	clock            func() time.Time
	idgen            func() string
	topics           map[string]Topic
	defaultRetention time.Duration
	policy           Policy
	client           clientConfig
	keys             KeyStore
}

func defaultConfig() config {
	return config{
		clock:            func() time.Time { return time.Now().UTC() },
		idgen:            uid.NewV7,
		topics:           map[string]Topic{},
		defaultRetention: DefaultRetention,
		policy:           DefaultPolicy(),
		client:           clientConfig{v4: 24, v6: 48},
	}
}

// Option customizes a Service. Options are applied in order at construction
// and never afterwards.
type Option func(*config)

// WithTopics declares topics. Begin and Record refuse any other with
// ErrUnknownTopic, so a typo cannot open a topic nobody seals or purges.
// Calls accumulate; a later declaration of a key replaces the earlier one.
// A topic with an empty Key is ignored.
func WithTopics(topics ...Topic) Option {
	return func(c *config) {
		for _, t := range topics {
			if t.Key != "" {
				c.topics[t.Key] = t
			}
		}
	}
}

// WithDefaultRetention sets the retention of topics that declare none,
// DefaultRetention by default. A non-positive value is ignored.
func WithDefaultRetention(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.defaultRetention = d
		}
	}
}

// WithPolicy replaces the redaction policy, DefaultPolicy() by default.
func WithPolicy(p Policy) Option {
	return func(c *config) { c.policy = p }
}

// Service records, reads and maintains an audit log over one Store. It is
// safe for concurrent use if its Store is, and it caches nothing.
type Service struct {
	store Store
	cfg   config
	keys  []string
}

// Compile-time proof the Service is a Recorder.
var _ Recorder = (*Service)(nil)

// New returns a Service over store.
func New(store Store, opts ...Option) *Service {
	cfg := defaultConfig()
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	keys := make([]string, 0, len(cfg.topics))
	for k := range cfg.topics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return &Service{store: store, cfg: cfg, keys: keys}
}

// Topics returns the declared topics sorted by key, each with its effective
// retention.
func (s *Service) Topics() []Topic {
	out := make([]Topic, len(s.keys))
	for i, k := range s.keys {
		out[i] = Topic{Key: k, Retention: s.retention(k)}
	}
	return out
}

func (s *Service) retention(key string) time.Duration {
	if r := s.cfg.topics[key].Retention; r > 0 {
		return r
	}
	return s.cfg.defaultRetention
}

// now is the clock in UTC, truncated to what PostgreSQL stores.
func (s *Service) now() time.Time { return s.cfg.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) validate(e Event) error {
	if _, ok := s.cfg.topics[e.Topic]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownTopic, e.Topic)
	}
	switch {
	case e.Action == "":
		return fmt.Errorf("%w: empty action", ErrInvalidEvent)
	case e.Origin == "":
		return fmt.Errorf("%w: empty origin", ErrInvalidEvent)
	case e.Actor.Type == "":
		return fmt.Errorf("%w: empty actor type", ErrInvalidEvent)
	case e.Source != SourceServer && e.Source != SourceClient:
		return fmt.Errorf("%w: source %q", ErrInvalidEvent, e.Source)
	}
	return nil
}

// prepare stamps what the Service owns: id, time, redaction.
func (s *Service) prepare(e Event) Event {
	if e.ID == "" {
		e.ID = s.cfg.idgen()
	}
	e.Seq = 0
	e.OccurredAt = s.now()
	if e.ClientTime != nil {
		at := e.ClientTime.UTC().Truncate(time.Microsecond)
		e.ClientTime = &at
	}
	e.Request = Redact(e.Request, s.cfg.policy)
	s.minimizeClient(&e)
	return e
}

// insert stores e. A taken id is a retry of the same call only when the
// stored event has the same topic, action, origin and actor — and, for an
// event that is already over, the same outcome; anything else is another
// event under that id, refused rather than silently dropped.
func (s *Service) insert(ctx context.Context, e Event) (Event, error) {
	stored, err := s.store.Insert(ctx, e)
	if err != nil {
		return Event{}, err
	}
	if stored.Topic != e.Topic || stored.Action != e.Action || stored.Origin != e.Origin ||
		stored.Actor.Type != e.Actor.Type || stored.Actor.ID != e.Actor.ID ||
		(e.CompletedAt != nil && stored.Outcome != e.Outcome) {
		return Event{}, fmt.Errorf("%w: id %q belongs to another event", ErrInvalidEvent, e.ID)
	}
	return stored, nil
}

// Begin stores e as an open event before the action it describes runs, and
// returns the stored event. A caller that cannot store the event should not
// run the action: that is the whole point of beginning first.
//
// The Service stamps OccurredAt and, when e.ID is empty, a UUIDv7 id; it
// redacts Request with its Policy. Source defaults to SourceServer. A
// second Begin with the same id, topic, action, origin and actor returns the
// stored event and stores nothing; the same id on a different event is
// ErrInvalidEvent. An id generator that repeats ids therefore collapses
// events of the same shape. Errors: ErrUnknownTopic, ErrInvalidEvent
// (including an event that already has an Outcome — use Record), and the
// Store's.
func (s *Service) Begin(ctx context.Context, e Event) (Event, error) {
	if e.Source == "" {
		e.Source = SourceServer
	}
	if err := s.validate(e); err != nil {
		return Event{}, err
	}
	if e.Outcome != "" {
		return Event{}, fmt.Errorf("%w: Begin with an outcome; use Record", ErrInvalidEvent)
	}
	e = s.prepare(e)
	if err := s.pseudonymizeEvent(ctx, &e); err != nil {
		return Event{}, err
	}
	e.CompletedAt, e.Changes, e.Code, e.Reason, e.DurationMS = nil, nil, "", "", 0
	return s.insert(ctx, e)
}

// Complete writes the outcome of the open event id, once. The Diff of
// Before and After is stored redacted, so a changed secret still shows as a
// changed path whose values are withheld; Resource and ContainerID fill only
// the event's empty ones. An identical retry succeeds; a different second
// completion is ErrCompleted. Errors: ErrInvalidEvent, ErrNotFound,
// ErrCompleted, and the Store's.
func (s *Service) Complete(ctx context.Context, id string, c Completion) error {
	if id == "" {
		return fmt.Errorf("%w: empty id", ErrInvalidEvent)
	}
	if !c.Outcome.Valid() {
		return fmt.Errorf("%w: outcome %q", ErrInvalidEvent, c.Outcome)
	}
	var changes json.RawMessage
	if len(c.Before) > 0 || len(c.After) > 0 {
		changes = Redact(Diff(c.Before, c.After), s.cfg.policy)
	}
	if c.Resource.Type == ResourceUser && c.Resource.ID != "" && s.cfg.keys != nil {
		p, err := s.pseudonymFor(ctx, c.Resource.ID, true)
		if errors.Is(err, ErrForgotten) {
			p, err = ErasedPseudonym, nil
		}
		if err != nil {
			return err
		}
		c.Resource.ID = p
	}
	_, err := s.store.Complete(ctx, id, Closing{
		At: s.now(), Outcome: c.Outcome, Code: c.Code, Reason: c.Reason, Changes: changes,
		Resource: c.Resource, ContainerID: c.ContainerID, DurationMS: c.DurationMS,
	})
	return err
}

// Record stores an event that is already over — Outcome is required — in one
// step: CompletedAt equals OccurredAt, and Request and Changes are redacted.
// Otherwise it follows Begin.
func (s *Service) Record(ctx context.Context, e Event) (Event, error) {
	if e.Source == "" {
		e.Source = SourceServer
	}
	if err := s.validate(e); err != nil {
		return Event{}, err
	}
	if !e.Outcome.Valid() {
		return Event{}, fmt.Errorf("%w: outcome %q", ErrInvalidEvent, e.Outcome)
	}
	e = s.prepare(e)
	if err := s.pseudonymizeEvent(ctx, &e); err != nil {
		return Event{}, err
	}
	at := e.OccurredAt
	e.CompletedAt = &at
	e.Changes = Redact(e.Changes, s.cfg.policy)
	return s.insert(ctx, e)
}
