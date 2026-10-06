// Package audit records what the people and machines using an application
// do, one immutable event per action, and proves afterwards that nobody
// rewrote the record.
//
// # Recording
//
// An [Event] says who acted ([Event.Actor], and [Event.OnBehalfOf] when an
// operator acts as someone else), what they did ([Event.Topic],
// [Event.Action], [Event.Resource]), where ([Event.ContainerID]), with which
// input ([Event.Request], redacted by [Redact]) and how it ended
// ([Event.Outcome], and [Event.Changes], a redacted before→after [Diff]).
//
// Recording takes two phases so that an action never runs without leaving a
// trace: [Service.Begin] stores the event before the action runs and
// [Service.Complete] writes its outcome afterwards, exactly once. Code running
// inside the action adds to the event with [Annotate]. An event whose
// completion never arrives, because the process died mid-action, is closed by
// [Service.Reconcile] with [OutcomeUnknown]. [Service.Record] stores an event
// that is already over in one step.
//
// # Integrity
//
// A [Store] never rewrites an event, apart from clearing its IP address and
// user agent on retention ([Service.ScrubClientData]), and deletes one only
// through retention ([Service.ApplyRetention]). On top of that, [Service.Seal] chains every
// (topic, UTC day) into a hash chain and [Service.Verify] recomputes it: an
// altered, inserted or deleted event, or a deleted day, breaks the day it
// belongs to.
//
// # Storage
//
// [Store] is the persistence port. store/memory holds the reference
// implementation and store/drops the PostgreSQL one, whose triggers refuse
// every rewrite at the database.
// [github.com/bernardoforcillo/authlayer/audit/audittest] is the port's
// contract as an executable suite, and
// [github.com/bernardoforcillo/authlayer/audit/audithook] turns the lifecycle
// hooks of the other authlayer packages into events.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// Source says who reported an event.
type Source string

const (
	// SourceServer: the application observed the action itself.
	SourceServer Source = "server"
	// SourceClient: a client reported it. Kept apart from server events
	// because a client can omit or forge what it reports.
	SourceClient Source = "client"
)

// Outcome is how an action ended. An open event has none.
type Outcome string

const (
	// OutcomeOK: the action succeeded.
	OutcomeOK Outcome = "ok"
	// OutcomeDenied: the action was refused — unauthenticated, unauthorized
	// or wrong credentials.
	OutcomeDenied Outcome = "denied"
	// OutcomeFailed: the action was allowed and failed.
	OutcomeFailed Outcome = "failed"
	// OutcomeUnknown: the completion never arrived and [Service.Reconcile]
	// closed the event.
	OutcomeUnknown Outcome = "unknown"
)

// Valid reports whether o is one of the four outcomes.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeOK, OutcomeDenied, OutcomeFailed, OutcomeUnknown:
		return true
	}
	return false
}

// Actor types this package names. [Actor.Type] is a free string, so an
// application may add its own, a "super_admin" label for instance.
const (
	// ActorUser is a person.
	ActorUser = "user"
	// ActorServiceAccount is a non-human member acting with its own key.
	ActorServiceAccount = "service_account"
	// ActorAnonymous is a caller with no identity yet, such as a sign-in
	// attempt.
	ActorAnonymous = "anonymous"
	// ActorSystem is the application acting on its own: a job, a sweep.
	ActorSystem = "system"
	// ActorSubject is a scope subject whose kind the reporting package does
	// not know: a user or a service account.
	ActorSubject = "subject"
)

// ResourceUser is the resource type [Filter.Member] also matches: an event
// about a user (their sign-in, their removal) belongs to that user's trail.
const ResourceUser = "user"

// ReasonReconciled is the reason [Service.Reconcile] stamps on the events it
// closes.
const ReasonReconciled = "reconciled"

// Actor is who performed an action.
type Actor struct {
	// Type is one of the Actor* constants or an application value.
	// Required.
	Type string
	// ID is opaque to this package; empty for an anonymous actor.
	ID string
	// Display is an optional snapshot of a human-readable identity, such as
	// an email. The log never changes after the fact, so leave it empty when
	// the person must be removable from the record and resolve names when
	// reading instead.
	Display string
}

// Resource is what an action touched.
type Resource struct {
	// Type names the kind of resource, e.g. "menu".
	Type string
	// ID identifies it.
	ID string
}

// Event is one action. See the package doc for the model.
type Event struct {
	// ID identifies the event. [Service.Begin] and [Service.Record] mint a
	// UUIDv7 when it is empty; a caller sending the event over a network
	// sets it, so a retried call is a no-op instead of a second event.
	ID string
	// Seq is assigned by the [Store]: a total order over every event.
	Seq int64
	// OccurredAt is the Service clock when the event was stored, in UTC,
	// truncated to the microsecond. Callers cannot set it.
	OccurredAt time.Time
	// CompletedAt is when the outcome was written; nil while open.
	CompletedAt *time.Time
	// Topic groups events for filtering, retention and sealing. It must be
	// declared on the Service ([WithTopics]).
	Topic string
	// Action is "<noun>.<verb>", e.g. "menu.delete". Required.
	Action string
	// Source is SourceServer (the default) or SourceClient.
	Source Source
	// Origin names the reporting service, e.g. "backend". Required.
	Origin string
	// Procedure is the transport operation, e.g. an RPC's full name.
	Procedure string
	// Actor performed the action. Actor.Type is required.
	Actor Actor
	// OnBehalfOf is the user an impersonating actor acted as.
	OnBehalfOf string
	// SessionID is the actor's session, when there is one.
	SessionID string
	// ContainerID is the tenant acted upon: an organization, a workspace.
	ContainerID string
	// Resource is what the action touched.
	Resource Resource
	// Outcome is empty until the event is completed.
	Outcome Outcome
	// Code is the transport's error code, e.g. "permission_denied".
	Code string
	// Reason is a closed-vocabulary qualifier, e.g. "wrong_password".
	Reason string
	// Request is the action's input, redacted before it is stored.
	Request json.RawMessage
	// Changes is a redacted before→after [Diff].
	Changes json.RawMessage
	// IP is the actor's client address.
	IP string
	// UserAgent is the actor's client software.
	UserAgent string
	// ClientTime is the time a client reported, for SourceClient events.
	ClientTime *time.Time
	// DurationMS is how long the action took.
	DurationMS int64
}

// Topic is a group of events with its own retention.
type Topic struct {
	// Key names the topic, e.g. "auth".
	Key string
	// Retention is how long the topic keeps its events; zero means the
	// Service default ([WithDefaultRetention]).
	Retention time.Duration
	// ClientDataRetention is how long the topic keeps the IP address and
	// user agent of its events; after it [Service.ApplyRetention] clears
	// both and keeps the event. Zero means they live as long as the event.
	// A value longer than the topic's Retention has no effect.
	ClientDataRetention time.Duration
}

// Completion is what [Service.Complete] adds to an open event.
type Completion struct {
	// Outcome is required.
	Outcome Outcome
	// Code is the transport's error code.
	Code string
	// Reason is a closed-vocabulary qualifier.
	Reason string
	// Before is the touched resource's state before the action, as JSON.
	Before json.RawMessage
	// After is its state after the action. The Service stores the [Diff] of
	// both sides, redacted: a changed secret keeps its path, not its values.
	After json.RawMessage
	// Resource is applied only when the event's own is empty.
	Resource Resource
	// ContainerID is applied only when the event's own is empty.
	ContainerID string
	// DurationMS is how long the action took.
	DurationMS int64
}

// Closing is what [Store.Complete] writes: the completion columns of one
// event, already redacted and diffed.
type Closing struct {
	// At is the completion time.
	At time.Time
	// Outcome is how the action ended.
	Outcome Outcome
	// Code is the transport's error code.
	Code string
	// Reason is a closed-vocabulary qualifier.
	Reason string
	// Changes is the redacted diff.
	Changes json.RawMessage
	// Resource fills the event's resource only when that is empty.
	Resource Resource
	// ContainerID fills the event's container only when that is empty.
	ContainerID string
	// DurationMS is how long the action took.
	DurationMS int64
}

// SameClosing reports whether the completed event e already holds what c
// would write. [Store.Complete] uses it to tell an identical retry, which
// succeeds, from a conflicting one ([ErrCompleted]). At, Resource and
// ContainerID are not compared: a retry carries a new time, and the other
// two only ever fill gaps.
func SameClosing(e Event, c Closing) bool {
	return e.Outcome == c.Outcome && e.Code == c.Code && e.Reason == c.Reason &&
		e.DurationMS == c.DurationMS && EqualJSON(e.Changes, c.Changes)
}

// Seal is one link of a topic's hash chain: the digest of one UTC day.
type Seal struct {
	// Topic is the sealed topic.
	Topic string
	// Day is midnight UTC of the sealed day.
	Day time.Time
	// EventCount is how many events the day held.
	EventCount int64
	// FirstSeq is the first event's Seq; zero for an empty day.
	FirstSeq int64
	// LastSeq is the last event's Seq; zero for an empty day.
	LastSeq int64
	// EventsHash is the hex SHA-256 of the day's canonical events.
	EventsHash string
	// PrevHash is the previous day's SealHash, or "" for a topic's first
	// seal.
	PrevHash string
	// SealHash chains PrevHash, Topic, Day, EventCount and EventsHash.
	SealHash string
	// SealedAt is when the seal was written.
	SealedAt time.Time
	// PurgedAt is when retention deleted the day's events; the seal stays.
	PurgedAt *time.Time
}

// DayState is what [Service.Verify] found for one day.
type DayState string

const (
	// DayOK: the day's events hash to its seal, which links to the previous
	// day's.
	DayOK DayState = "ok"
	// DayMismatch: something no longer matches; DayStatus.Detail says what.
	DayMismatch DayState = "mismatch"
	// DayUnsealed: no seal covers the day yet.
	DayUnsealed DayState = "unsealed"
	// DayPurged: retention deleted the events; the seal still links.
	DayPurged DayState = "purged"
)

// DayStatus is the verification of one (topic, day).
type DayStatus struct {
	// Topic is the verified topic.
	Topic string
	// Day is midnight UTC.
	Day time.Time
	// State is the verdict.
	State DayState
	// Detail names the failed check on DayMismatch: "events_hash" (the
	// events changed), "seal_hash" (the seal changed) or "chain" (the seal
	// does not link to the previous day's).
	Detail string
}

// Filter selects events. Zero fields select everything and set fields
// combine with AND. [Filter.Match] is the reference semantics every [Store]
// follows.
type Filter struct {
	// Topics matches any of these topics.
	Topics []string
	// From is the inclusive lower bound of OccurredAt.
	From time.Time
	// To is the exclusive upper bound of OccurredAt.
	To time.Time
	// ContainerID matches the tenant.
	ContainerID string
	// Member matches the actor, the impersonated user, or a resource of
	// type ResourceUser: one person's whole trail.
	Member string
	// ActorID matches the actor only.
	ActorID string
	// Resource matches its non-empty fields.
	Resource Resource
	// Outcomes matches completed events with one of these outcomes; open
	// events never match a non-empty Outcomes.
	Outcomes []Outcome
	// Source matches the reporting side.
	Source Source
	// ActionPrefix matches actions starting with it, literally.
	ActionPrefix string
}

// Match reports whether e satisfies f.
func (f Filter) Match(e Event) bool {
	switch {
	case len(f.Topics) > 0 && !slices.Contains(f.Topics, e.Topic):
		return false
	case !f.From.IsZero() && e.OccurredAt.Before(f.From):
		return false
	case !f.To.IsZero() && !e.OccurredAt.Before(f.To):
		return false
	case f.ContainerID != "" && e.ContainerID != f.ContainerID:
		return false
	case f.Member != "" && e.Actor.ID != f.Member && e.OnBehalfOf != f.Member &&
		(e.Resource.Type != ResourceUser || e.Resource.ID != f.Member):
		return false
	case f.ActorID != "" && e.Actor.ID != f.ActorID:
		return false
	case f.Resource.Type != "" && e.Resource.Type != f.Resource.Type:
		return false
	case f.Resource.ID != "" && e.Resource.ID != f.Resource.ID:
		return false
	case len(f.Outcomes) > 0 && (e.Outcome == "" || !slices.Contains(f.Outcomes, e.Outcome)):
		return false
	case f.Source != "" && e.Source != f.Source:
		return false
	case f.ActionPrefix != "" && !strings.HasPrefix(e.Action, f.ActionPrefix):
		return false
	}
	return true
}

// MaxPageSize caps [Page.Limit].
const MaxPageSize = 500

// Page is one page of a newest-first listing.
type Page struct {
	// Before lists events whose Seq is strictly below it; zero starts at
	// the newest event.
	Before int64
	// Limit is the page size, from 1 to MaxPageSize.
	Limit int
}

// Sentinel errors returned by the Service and by Store implementations.
// Compare with errors.Is; the messages are not part of the API.
var (
	// ErrUnknownTopic: the event names a topic the Service was not
	// configured with.
	ErrUnknownTopic = errors.New("authlayer/audit: unknown topic")
	// ErrInvalidEvent: a required field is missing or a value is out of
	// range.
	ErrInvalidEvent = errors.New("authlayer/audit: invalid event")
	// ErrNotFound: no event, or no seal, matches.
	ErrNotFound = errors.New("authlayer/audit: not found")
	// ErrCompleted: the event is already completed with a different outcome.
	ErrCompleted = errors.New("authlayer/audit: event already completed differently")
	// ErrOpenEvents: a day still holds open events and cannot be sealed.
	ErrOpenEvents = errors.New("authlayer/audit: day still holds open events")
	// ErrSealed: the event's (topic, day) is already sealed.
	ErrSealed = errors.New("authlayer/audit: day is sealed")
	// ErrSealExists: a seal for that (topic, day) already exists.
	ErrSealExists = errors.New("authlayer/audit: seal already exists")
	// ErrExportTooLarge: more events match than the export allows.
	ErrExportTooLarge = errors.New("authlayer/audit: export exceeds the limit")
)

// Recorder records events: the in-process [*Service], or a client of a
// remote one. Interceptors and hook adapters depend on it.
type Recorder interface {
	// Begin stores an open event; see [Service.Begin].
	Begin(ctx context.Context, e Event) (Event, error)
	// Complete writes an open event's outcome once; see [Service.Complete].
	Complete(ctx context.Context, id string, c Completion) error
	// Record stores an event that is already over; see [Service.Record].
	Record(ctx context.Context, e Event) (Event, error)
}

// Store is the persistence port. It authorizes nothing and validates
// nothing the Service already validated; it stores what it is handed.
//
// The MUSTs below are normative, and
// [github.com/bernardoforcillo/authlayer/audit/audittest] exercises them as
// far as a sequential suite can (the atomicity of Insert's sealed-day check
// is not raced). Run that suite against a backend rather than trusting this
// comment.
type Store interface {
	// Insert stores e, assigning Seq from an increasing sequence, and
	// returns the stored row. An event whose ID already exists MUST NOT be
	// stored again: the stored row is returned unchanged. Seq is increasing,
	// not gapless — a backend may consume a value on a duplicate or refused
	// insert — so a gap in Seq is not evidence of a deletion; the seals are.
	// An event whose (Topic, UTC day of OccurredAt) is already sealed MUST be
	// refused with ErrSealed, and the check and the write MUST be one atomic
	// step.
	Insert(ctx context.Context, e Event) (Event, error)
	// Complete writes c onto the open event id and returns the stored row.
	// Resource and ContainerID fill only the event's empty ones. An unknown
	// id is ErrNotFound. On an already completed event it MUST return the
	// stored row and nil when SameClosing holds, and ErrCompleted otherwise,
	// leaving the row untouched.
	Complete(ctx context.Context, id string, c Closing) (Event, error)
	// Get loads one event, or ErrNotFound.
	Get(ctx context.Context, id string) (Event, error)
	// List returns events matching f, Seq descending, below page.Before
	// when it is positive, at most page.Limit (MaxPageSize when Limit is
	// not in 1..MaxPageSize).
	List(ctx context.Context, f Filter, page Page) ([]Event, error)
	// Count returns how many events match f.
	Count(ctx context.Context, f Filter) (int, error)
	// Scan calls fn for every event matching f in ascending Seq order and
	// returns the first error fn returns, unwrapped.
	Scan(ctx context.Context, f Filter, fn func(Event) error) error
	// OpenBefore returns the ids of open events with OccurredAt strictly
	// before before, oldest first, at most limit.
	OpenBefore(ctx context.Context, before time.Time, limit int) ([]string, error)
	// LastSeal returns the topic's latest seal, or ErrNotFound.
	LastSeal(ctx context.Context, topic string) (Seal, error)
	// InsertSeal stores s; a seal for the same (Topic, Day) is
	// ErrSealExists.
	InsertSeal(ctx context.Context, s Seal) error
	// Seals returns the topic's seals with Day in [from, to], ascending.
	Seals(ctx context.Context, topic string, from, to time.Time) ([]Seal, error)
	// Purge deletes, oldest first, at most batch events of topic with
	// OccurredAt strictly before before, and returns how many went. It is
	// the only way an event is ever deleted.
	Purge(ctx context.Context, topic string, before time.Time, batch int) (int, error)
	// MarkPurged stamps PurgedAt = at on the topic's seals with Day
	// strictly before before that have none yet.
	MarkPurged(ctx context.Context, topic string, before, at time.Time) error
	// ScrubClientData sets IP and UserAgent to "" on at most batch events of
	// topic with OccurredAt strictly before before that still hold either,
	// oldest first, and returns how many it cleared. It changes nothing else
	// and is the only way those two fields are ever rewritten; they are
	// outside the seals' hashes for that reason.
	ScrubClientData(ctx context.Context, topic string, before time.Time, batch int) (int, error)
}
