package audit

import (
	"context"
	"fmt"
	"time"
)

// microBounds rounds f's time bounds to the microsecond every store keeps —
// From down, To up — so the window means the same on every store, whatever
// the caller's clock resolution.
func microBounds(f Filter) Filter {
	if !f.From.IsZero() {
		f.From = f.From.UTC().Truncate(time.Microsecond)
	}
	if !f.To.IsZero() {
		to := f.To.UTC()
		if t := to.Truncate(time.Microsecond); !t.Equal(to) {
			to = t.Add(time.Microsecond)
		}
		f.To = to
	}
	return f
}

// filterNUL refuses a Filter holding a NUL character, which no stored event
// can match and PostgreSQL cannot even receive.
func filterNUL(f Filter) error {
	bad := hasNUL(f.ContainerID, f.Member, f.ActorID, f.Resource.Type, f.Resource.ID, string(f.Source), f.ActionPrefix) ||
		hasNUL(f.Topics...)
	for _, o := range f.Outcomes {
		bad = bad || hasNUL(string(o))
	}
	if bad {
		return fmt.Errorf("%w: a NUL character in the filter", ErrInvalidEvent)
	}
	return nil
}

// Get loads one event, or ErrNotFound (also for an id holding a NUL
// character, which no event has).
func (s *Service) Get(ctx context.Context, id string) (Event, error) {
	if hasNUL(id) {
		return Event{}, ErrNotFound
	}
	return s.store.Get(ctx, id)
}

// List returns the events matching f, newest first, and the cursor of the
// next page: pass it as Page.Before. The cursor is zero when this page is the
// last one; a full page may still be followed by an empty one. A Limit
// outside 1..MaxPageSize means MaxPageSize. A NUL character in a Filter
// string is ErrInvalidEvent, here and in Export and Count.
func (s *Service) List(ctx context.Context, f Filter, page Page) ([]Event, int64, error) {
	if err := filterNUL(f); err != nil {
		return nil, 0, err
	}
	if page.Limit <= 0 || page.Limit > MaxPageSize {
		page.Limit = MaxPageSize
	}
	if page.Before < 0 {
		page.Before = 0
	}
	f, err := s.translateFilter(ctx, microBounds(f))
	if err != nil {
		return nil, 0, err
	}
	events, err := s.store.List(ctx, f, page)
	if err != nil {
		return nil, 0, err
	}
	var next int64
	if len(events) == page.Limit {
		next = events[len(events)-1].Seq
	}
	return events, next, nil
}

// Export calls yield for every event matching f, oldest first, and stops at
// the first error yield returns. When limit is positive and more events
// match, it returns ErrExportTooLarge before yielding anything.
func (s *Service) Export(ctx context.Context, f Filter, limit int, yield func(Event) error) error {
	if err := filterNUL(f); err != nil {
		return err
	}
	f, err := s.translateFilter(ctx, microBounds(f))
	if err != nil {
		return err
	}
	if limit > 0 {
		n, err := s.store.Count(ctx, f)
		if err != nil {
			return err
		}
		if n > limit {
			return fmt.Errorf("%w: %d events match, the limit is %d", ErrExportTooLarge, n, limit)
		}
	}
	return s.store.Scan(ctx, f, yield)
}

// Count returns how many events match f, with the same person-id translation
// as [Service.List].
func (s *Service) Count(ctx context.Context, f Filter) (int, error) {
	if err := filterNUL(f); err != nil {
		return 0, err
	}
	f, err := s.translateFilter(ctx, microBounds(f))
	if err != nil {
		return 0, err
	}
	return s.store.Count(ctx, f)
}
