package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// maintainBatch bounds one store round trip of Reconcile and ApplyRetention.
const maintainBatch = 500

// Reconcile closes, with OutcomeUnknown and ReasonReconciled, every open
// event that began more than olderThan ago, and returns how many it closed.
// It is how a process that died mid-action stops blocking Seal: pick an
// olderThan longer than any action can run. An event another replica
// completed in the meantime is skipped; a non-positive olderThan reconciles
// every open event.
func (s *Service) Reconcile(ctx context.Context, olderThan time.Duration) (int, error) {
	if olderThan < 0 {
		olderThan = 0
	}
	cutoff := s.now().Add(-olderThan)
	closed := 0
	for {
		ids, err := s.store.OpenBefore(ctx, cutoff, maintainBatch)
		if err != nil {
			return closed, err
		}
		progressed := false
		for _, id := range ids {
			_, err := s.store.Complete(ctx, id, Closing{At: s.now(), Outcome: OutcomeUnknown, Reason: ReasonReconciled})
			switch {
			case err == nil:
				closed++
				progressed = true
			case errors.Is(err, ErrCompleted), errors.Is(err, ErrNotFound):
				// another replica completed or purged it first
			default:
				return closed, fmt.Errorf("reconcile %s: %w", id, err)
			}
		}
		if len(ids) < maintainBatch || !progressed {
			return closed, ctx.Err()
		}
	}
}

// ApplyRetention deletes, per declared topic, the events older than the
// topic's retention and returns how many it deleted per topic. Only whole
// UTC days that are already sealed are purged, so an event is never deleted
// before the seal that covers it exists; a topic with no seal keeps
// everything. The seals of the purged days are marked purged first, then the
// events go, so [Service.Verify] never sees a day whose events vanished
// without the mark. The seals themselves stay forever.
func (s *Service) ApplyRetention(ctx context.Context) (map[string]int, error) {
	now := s.now()
	deleted := map[string]int{}
	var errs []error
	for _, topic := range s.keys {
		n, err := s.purgeTopic(ctx, topic, now)
		if n > 0 {
			deleted[topic] = n
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("retention %s: %w", topic, err))
		}
	}
	return deleted, errors.Join(errs...)
}

func (s *Service) purgeTopic(ctx context.Context, topic string, now time.Time) (int, error) {
	last, err := s.store.LastSeal(ctx, topic)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	cutoff := startOfDay(now.Add(-s.retention(topic)))
	if sealed := startOfDay(last.Day).Add(day); sealed.Before(cutoff) {
		cutoff = sealed
	}
	if err := s.store.MarkPurged(ctx, topic, cutoff, now); err != nil {
		return 0, err
	}
	total := 0
	for {
		n, err := s.store.Purge(ctx, topic, cutoff, maintainBatch)
		total += n
		if err != nil {
			return total, err
		}
		if n < maintainBatch {
			return total, nil
		}
	}
}
