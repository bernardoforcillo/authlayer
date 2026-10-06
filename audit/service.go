package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
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
	case hasNUL(e.ID, e.Topic, e.Action, e.Origin, e.Procedure, e.Actor.Type, e.Actor.ID, e.Actor.Display,
		e.OnBehalfOf, e.SessionID, e.ContainerID, e.Resource.Type, e.Resource.ID, e.Code, e.Reason, e.IP, e.UserAgent):
		return fmt.Errorf("%w: a NUL character in a text field", ErrInvalidEvent)
	}
	return nil
}

// hasNUL reports whether any of ss holds a NUL character, which no
// PostgreSQL text or jsonb value can hold: refusing it here keeps every
// Store's behaviour the same.
func hasNUL(ss ...string) bool {
	for _, s := range ss {
		if strings.IndexByte(s, 0) >= 0 {
			return true
		}
	}
	return false
}

// jsonHasNUL reports whether a key or string of raw holds a NUL character.
// Unreadable JSON holds none: Redact has already replaced it.
func jsonHasNUL(raw json.RawMessage) bool {
	if bytes.IndexByte(raw, 0) < 0 && !bytes.Contains(raw, []byte(`\u0000`)) {
		return false
	}
	v, err := decodeJSON(raw)
	if err != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case string:
			return hasNUL(x)
		case []any:
			return slices.ContainsFunc(x, walk)
		case map[string]any:
			for k, child := range x {
				if hasNUL(k) || walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

func errNULInJSON(field string) error {
	return fmt.Errorf("%w: a NUL character in %s", ErrInvalidEvent, field)
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
// (including an event that already has an Outcome — use Record — and a NUL
// character in any text field or in Request, which PostgreSQL cannot store),
// and the Store's.
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
	if jsonHasNUL(e.Request) {
		return Event{}, errNULInJSON("Request")
	}
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
// completion is ErrCompleted. Errors: ErrInvalidEvent (a NUL character in a
// text field or the diff included), ErrNotFound, ErrCompleted, and the
// Store's.
func (s *Service) Complete(ctx context.Context, id string, c Completion) error {
	if id == "" {
		return fmt.Errorf("%w: empty id", ErrInvalidEvent)
	}
	if !c.Outcome.Valid() {
		return fmt.Errorf("%w: outcome %q", ErrInvalidEvent, c.Outcome)
	}
	if hasNUL(c.Code, c.Reason, c.Resource.Type, c.Resource.ID, c.ContainerID) {
		return fmt.Errorf("%w: a NUL character in a text field", ErrInvalidEvent)
	}
	var changes json.RawMessage
	if len(c.Before) > 0 || len(c.After) > 0 {
		changes = Redact(Diff(c.Before, c.After), s.cfg.policy)
	}
	if jsonHasNUL(changes) {
		return errNULInJSON("Changes")
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
	if jsonHasNUL(e.Request) {
		return Event{}, errNULInJSON("Request")
	}
	if jsonHasNUL(e.Changes) {
		return Event{}, errNULInJSON("Changes")
	}
	return s.insert(ctx, e)
}
