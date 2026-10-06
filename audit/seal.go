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

// PurgeClockSkew is how far a seal's PurgedAt may lie after the Service clock
// before [Service.Verify] calls it forged. Retention stamps the time it runs,
// so only the clock difference between the replica that purged and the one
// verifying can put an honest stamp in the future. The drops seals guard
// refuses a purged_at further ahead than its database clock by the same
// margin.
const PurgeClockSkew = 5 * time.Minute

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

// sealAttempts bounds how often Seal digests one day again after the store
// found the day changed under the digest (ErrSealStale).
const sealAttempts = 3

// Seal seals, for every declared topic, each UTC day that ended at or before
// until and has no seal yet, oldest first, and returns the new seals. Empty
// days are sealed too, so removing a whole day is detected. A topic's chain
// starts at the earliest UTC day any of its events occurred on, or at the
// last full day if it has none yet.
//
// until is capped at the start of the Service clock's current UTC day: a day
// that has not ended on this Service's clock is never sealed, whatever the
// caller passes. An event stamped just before midnight may still be on its
// way to the store when its day is sealed; the store then refuses the seal
// (ErrSealStale) and Seal digests the day again, up to three times. Passing
// a until a few minutes in the past, as a scheduled job naturally does,
// keeps such an event from being refused with ErrSealed instead.
//
// A day still holding open events stops that topic with ErrOpenEvents (run
// Reconcile first); the other topics are sealed regardless and the errors
// are joined. Several replicas may run Seal at once: a day another replica
// sealed first is skipped, and the chain continues from its seal.
func (s *Service) Seal(ctx context.Context, until time.Time) ([]Seal, error) {
	if today := startOfDay(s.now()); until.After(today) {
		until = today
	}
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
	for attempt := 1; !next.Add(day).After(until); {
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
			prev, next, attempt = sl.SealHash, next.Add(day), 1
		case errors.Is(err, ErrSealExists):
			last, lerr := s.store.LastSeal(ctx, topic)
			if lerr != nil {
				return out, lerr
			}
			prev, next, attempt = last.SealHash, startOfDay(last.Day).Add(day), 1
		case errors.Is(err, ErrSealStale) && attempt < sealAttempts:
			attempt++
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

// firstEventDay is the UTC day of the topic's earliest OccurredAt, or zero
// for a topic without events. Seq order is insert order, and replicas stamp
// OccurredAt before inserting, so the first event by Seq may not be the
// earliest: the second scan looks for anything dated before its day, which
// is normally nothing.
func (s *Service) firstEventDay(ctx context.Context, topic string) (time.Time, error) {
	var first time.Time
	err := s.store.Scan(ctx, Filter{Topics: []string{topic}}, func(e Event) error {
		first = e.OccurredAt
		return errStopScan
	})
	if err != nil && !errors.Is(err, errStopScan) {
		return time.Time{}, err
	}
	if first.IsZero() {
		return time.Time{}, nil
	}
	err = s.store.Scan(ctx, Filter{Topics: []string{topic}, To: startOfDay(first)}, func(e Event) error {
		if e.OccurredAt.Before(first) {
			first = e.OccurredAt
		}
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	return startOfDay(first), nil
}

// Verify checks each UTC day from from's day through to's day, both
// included, for topics (every declared topic when empty), and returns one
// DayStatus per day, topic by topic.
//
// A day without a seal is DayUnsealed, unless the topic has a seal both
// before and after it: a chain has no holes, so that day's seal was deleted
// and the day is DayMismatch "chain". A seal that no longer hashes, or whose
// first and last Seq no longer match its events, is "seal_hash"; one that
// does not link to the nearest earlier seal (or claims a predecessor that is
// missing) is "chain"; one whose events no longer hash to it is
// "events_hash". A purged day is checked for its link and for the age it was
// purged at, judged by this Service's clock: a seal marked purged while
// PurgedAt - Day was still under the topic's current retention, or whose
// PurgedAt lies after the Service clock by more than [PurgeClockSkew], is
// DayMismatch "purged_early". A day younger than its retention therefore
// never reads as purged, whatever was stamped. Shortening a
// topic's retention is therefore safe; lengthening it makes the days purged
// under the shorter one read as purged_early, which is worth a review.
func (s *Service) Verify(ctx context.Context, topics []string, from, to time.Time) ([]DayStatus, error) {
	if len(topics) == 0 {
		topics = s.keys
	}
	from, to = startOfDay(from), startOfDay(to)
	var out []DayStatus
	for _, topic := range topics {
		days, err := s.verifyTopic(ctx, topic, from, to)
		if err != nil {
			return nil, err
		}
		out = append(out, days...)
	}
	return out, nil
}

func (s *Service) verifyTopic(ctx context.Context, topic string, from, to time.Time) ([]DayStatus, error) {
	// The day before from is fetched too, so the first day's link is checked.
	seals, err := s.store.Seals(ctx, topic, from.Add(-day), to)
	if err != nil {
		return nil, err
	}
	var lastDay time.Time
	switch last, err := s.store.LastSeal(ctx, topic); {
	case err == nil:
		lastDay = startOfDay(last.Day)
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}
	// sealedBefore(i): whether the topic has a seal before the day whose
	// earlier fetched seals are seals[:i]. Only a day with none needs the
	// store again, once.
	var anyBeforeRange *bool
	sealedBefore := func(i int) (bool, error) {
		if i > 0 {
			return true, nil
		}
		if anyBeforeRange == nil {
			older, err := s.store.Seals(ctx, topic, time.Time{}, from.Add(-2*day))
			if err != nil {
				return false, err
			}
			found := len(older) > 0
			anyBeforeRange = &found
		}
		return *anyBeforeRange, nil
	}
	var out []DayStatus
	i := 0 // seals[:i] are before d
	for d := from; !d.After(to); d = d.Add(day) {
		for i < len(seals) && startOfDay(seals[i].Day).Before(d) {
			i++
		}
		st := DayStatus{Topic: topic, Day: d}
		if i < len(seals) && startOfDay(seals[i].Day).Equal(d) {
			var prev *Seal
			if i > 0 {
				prev = &seals[i-1]
			}
			if st.State, st.Detail, err = s.checkSeal(ctx, seals[i], prev); err != nil {
				return nil, err
			}
			out = append(out, st)
			continue
		}
		st.State = DayUnsealed
		if lastDay.After(d) {
			before, err := sealedBefore(i)
			if err != nil {
				return nil, err
			}
			if before {
				st.State, st.Detail = DayMismatch, "chain"
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// checkSeal verifies one seal against its nearest earlier fetched seal, prev,
// which is the day before unless that seal is missing. The fetched range
// always includes the day before, so a nil prev means no predecessor exists.
func (s *Service) checkSeal(ctx context.Context, sl Seal, prev *Seal) (DayState, string, error) {
	d := startOfDay(sl.Day)
	if sealHash(sl.PrevHash, sl.Topic, d, sl.EventCount, sl.EventsHash) != sl.SealHash {
		return DayMismatch, "seal_hash", nil
	}
	if (prev == nil && sl.PrevHash != "") || (prev != nil && prev.SealHash != sl.PrevHash) {
		return DayMismatch, "chain", nil
	}
	if sl.PurgedAt != nil {
		// Retention purges a day only once the whole day is older than the
		// topic's retention, and stamps the time it runs, so an earlier
		// stamp is a delete in disguise. A stamp later than this Service's
		// clock (beyond PurgeClockSkew) is forged: whoever wrote it could
		// otherwise date it far enough ahead to pass the age check, so the
		// age that counts is judged by Verify's own clock.
		if sl.PurgedAt.Sub(d) < s.retention(sl.Topic) || sl.PurgedAt.After(s.now().Add(PurgeClockSkew)) {
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
	case dg.first != sl.FirstSeq || dg.last != sl.LastSeq:
		// first_seq and last_seq are not in the seal hash (its format is
		// fixed), so they are checked against the events instead.
		return DayMismatch, "seal_hash", nil
	}
	return DayOK, "", nil
}
