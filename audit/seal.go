package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const day = 24 * time.Hour

func startOfDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// canonicalEvent fixes the order and spelling of the fields a seal hashes.
// It is part of the stored format: changing it changes every hash.
//
// IP and UserAgent are deliberately NOT here. They are personal data that
// [Service.ScrubClientData] clears on its own, shorter schedule, and a seal
// that covered them would call every scrub a tampering. Everything else about
// an event stays tamper-evident.
type canonicalEvent struct {
	ID           string          `json:"id"`
	Seq          int64           `json:"seq"`
	OccurredAt   string          `json:"occurred_at"`
	CompletedAt  *string         `json:"completed_at"`
	Topic        string          `json:"topic"`
	Action       string          `json:"action"`
	Source       string          `json:"source"`
	Origin       string          `json:"origin"`
	Procedure    string          `json:"procedure"`
	ActorType    string          `json:"actor_type"`
	ActorID      string          `json:"actor_id"`
	ActorDisplay string          `json:"actor_display"`
	OnBehalfOf   string          `json:"on_behalf_of"`
	SessionID    string          `json:"session_id"`
	ContainerID  string          `json:"container_id"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Outcome      string          `json:"outcome"`
	Code         string          `json:"code"`
	Reason       string          `json:"reason"`
	Request      json.RawMessage `json:"request"`
	Changes      json.RawMessage `json:"changes"`
	ClientTime   *string         `json:"client_time"`
	DurationMS   int64           `json:"duration_ms"`
}

// errUnreadableEvent: a stored event's JSON no longer parses, which only a
// rewrite outside the Store can cause.
var errUnreadableEvent = errors.New("authlayer/audit: unreadable event")

func timeString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

func canonicalBytes(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	return canonicalJSON(raw)
}

func canonicalRow(e Event) ([]byte, error) {
	req, err := canonicalBytes(e.Request)
	if err != nil {
		return nil, err
	}
	chg, err := canonicalBytes(e.Changes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonicalEvent{
		ID: e.ID, Seq: e.Seq, OccurredAt: e.OccurredAt.UTC().Format(time.RFC3339Nano),
		CompletedAt: timeString(e.CompletedAt), Topic: e.Topic, Action: e.Action,
		Source: string(e.Source), Origin: e.Origin, Procedure: e.Procedure,
		ActorType: e.Actor.Type, ActorID: e.Actor.ID, ActorDisplay: e.Actor.Display,
		OnBehalfOf: e.OnBehalfOf, SessionID: e.SessionID, ContainerID: e.ContainerID,
		ResourceType: e.Resource.Type, ResourceID: e.Resource.ID,
		Outcome: string(e.Outcome), Code: e.Code, Reason: e.Reason, Request: req, Changes: chg,
		ClientTime: timeString(e.ClientTime), DurationMS: e.DurationMS,
	})
}

func sealHash(prev, topic string, d time.Time, count int64, eventsHash string) string {
	sum := sha256.Sum256([]byte(prev + "|" + topic + "|" + d.UTC().Format(time.DateOnly) + "|" +
		strconv.FormatInt(count, 10) + "|" + eventsHash))
	return hex.EncodeToString(sum[:])
}

type dayDigest struct {
	hash               string
	count, first, last int64
}

func (s *Service) digestDay(ctx context.Context, topic string, d time.Time) (dayDigest, error) {
	h := sha256.New()
	var dg dayDigest
	err := s.store.Scan(ctx, Filter{Topics: []string{topic}, From: d, To: d.Add(day)}, func(e Event) error {
		if e.CompletedAt == nil {
			return fmt.Errorf("%w: %s on %s", ErrOpenEvents, topic, d.Format(time.DateOnly))
		}
		row, err := canonicalRow(e)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", errUnreadableEvent, e.ID, err)
		}
		_, _ = h.Write(row)
		_, _ = h.Write([]byte{'\n'})
		if dg.count == 0 {
			dg.first = e.Seq
		}
		dg.last = e.Seq
		dg.count++
		return nil
	})
	if err != nil {
		return dayDigest{}, err
	}
	dg.hash = hex.EncodeToString(h.Sum(nil))
	return dg, nil
}

// Seal seals, for every declared topic, each UTC day that ended at or before
// until and has no seal yet, oldest first, and returns the new seals. Empty
// days are sealed too, so removing a whole day is detected. A topic's chain
// starts at the day of its first event, or at the last full day if it has
// none yet.
//
// A day still holding open events stops that topic with ErrOpenEvents (run
// Reconcile first); the other topics are sealed regardless and the errors
// are joined. Several replicas may run Seal at once: a day another replica
// sealed first is skipped, and the chain continues from its seal.
func (s *Service) Seal(ctx context.Context, until time.Time) ([]Seal, error) {
	var sealed []Seal
	var errs []error
	for _, topic := range s.keys {
		out, err := s.sealTopic(ctx, topic, until.UTC())
		sealed = append(sealed, out...)
		if err != nil {
			errs = append(errs, fmt.Errorf("seal %s: %w", topic, err))
		}
	}
	return sealed, errors.Join(errs...)
}

func (s *Service) sealTopic(ctx context.Context, topic string, until time.Time) ([]Seal, error) {
	next, prev, err := s.sealStart(ctx, topic, until)
	if err != nil {
		return nil, err
	}
	var out []Seal
	for !next.Add(day).After(until) {
		dg, err := s.digestDay(ctx, topic, next)
		if err != nil {
			return out, err
		}
		sl := Seal{Topic: topic, Day: next, EventCount: dg.count, FirstSeq: dg.first, LastSeq: dg.last,
			EventsHash: dg.hash, PrevHash: prev, SealedAt: s.now()}
		sl.SealHash = sealHash(prev, topic, next, dg.count, dg.hash)
		switch err := s.store.InsertSeal(ctx, sl); {
		case err == nil:
			out = append(out, sl)
			prev, next = sl.SealHash, next.Add(day)
		case errors.Is(err, ErrSealExists):
			last, lerr := s.store.LastSeal(ctx, topic)
			if lerr != nil {
				return out, lerr
			}
			prev, next = last.SealHash, startOfDay(last.Day).Add(day)
		default:
			return out, err
		}
	}
	return out, nil
}

// sealStart returns the first day to seal and the hash it links to.
func (s *Service) sealStart(ctx context.Context, topic string, until time.Time) (time.Time, string, error) {
	last, err := s.store.LastSeal(ctx, topic)
	switch {
	case err == nil:
		return startOfDay(last.Day).Add(day), last.SealHash, nil
	case !errors.Is(err, ErrNotFound):
		return time.Time{}, "", err
	}
	first, err := s.firstEventDay(ctx, topic)
	if err != nil {
		return time.Time{}, "", err
	}
	if first.IsZero() {
		first = startOfDay(until).Add(-day)
	}
	return first, "", nil
}

var errStopScan = errors.New("authlayer/audit: stop scan")

func (s *Service) firstEventDay(ctx context.Context, topic string) (time.Time, error) {
	var first time.Time
	err := s.store.Scan(ctx, Filter{Topics: []string{topic}}, func(e Event) error {
		first = startOfDay(e.OccurredAt)
		return errStopScan
	})
	if err != nil && !errors.Is(err, errStopScan) {
		return time.Time{}, err
	}
	return first, nil
}

// Verify checks each UTC day from from's day through to's day, both
// included, for topics (every declared topic when empty), and returns one
// DayStatus per day, topic by topic. A day without a seal is DayUnsealed; a
// seal that no longer hashes, that no longer links to the previous day's
// seal, or whose events no longer hash to it is DayMismatch with the failed
// check in Detail. A purged day is checked for its link and for the age it
// was purged at: a seal marked purged while PurgedAt - Day was still under
// the topic's current retention is DayMismatch "purged_early". Shortening a
// topic's retention is therefore safe; lengthening it makes the days purged
// under the shorter one read as purged_early, which is worth a review.
func (s *Service) Verify(ctx context.Context, topics []string, from, to time.Time) ([]DayStatus, error) {
	if len(topics) == 0 {
		topics = s.keys
	}
	from, to = startOfDay(from), startOfDay(to)
	var out []DayStatus
	for _, topic := range topics {
		seals, err := s.store.Seals(ctx, topic, from.Add(-day), to)
		if err != nil {
			return nil, err
		}
		byDay := make(map[string]Seal, len(seals))
		for _, sl := range seals {
			byDay[sl.Day.UTC().Format(time.DateOnly)] = sl
		}
		for d := from; !d.After(to); d = d.Add(day) {
			st := DayStatus{Topic: topic, Day: d}
			sl, ok := byDay[d.Format(time.DateOnly)]
			if !ok {
				st.State = DayUnsealed
				out = append(out, st)
				continue
			}
			var prev *Seal
			if p, ok := byDay[d.Add(-day).Format(time.DateOnly)]; ok {
				prev = &p
			}
			if st.State, st.Detail, err = s.checkSeal(ctx, sl, prev); err != nil {
				return nil, err
			}
			out = append(out, st)
		}
	}
	return out, nil
}

func (s *Service) checkSeal(ctx context.Context, sl Seal, prev *Seal) (DayState, string, error) {
	d := startOfDay(sl.Day)
	if sealHash(sl.PrevHash, sl.Topic, d, sl.EventCount, sl.EventsHash) != sl.SealHash {
		return DayMismatch, "seal_hash", nil
	}
	if prev != nil && prev.SealHash != sl.PrevHash {
		return DayMismatch, "chain", nil
	}
	if sl.PurgedAt != nil {
		// Retention purges a day only once the whole day is older than the
		// topic's retention, so an earlier stamp is a delete in disguise.
		if sl.PurgedAt.Sub(d) < s.retention(sl.Topic) {
			return DayMismatch, "purged_early", nil
		}
		return DayPurged, "", nil
	}
	dg, err := s.digestDay(ctx, sl.Topic, d)
	switch {
	case errors.Is(err, ErrOpenEvents), errors.Is(err, errUnreadableEvent):
		return DayMismatch, "events_hash", nil
	case err != nil:
		return "", "", err
	case dg.hash != sl.EventsHash || dg.count != sl.EventCount:
		return DayMismatch, "events_hash", nil
	}
	return DayOK, "", nil
}
