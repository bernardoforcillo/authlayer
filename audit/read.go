package audit

import "context"

// Get loads one event, or ErrNotFound.
func (s *Service) Get(ctx context.Context, id string) (Event, error) {
	return s.store.Get(ctx, id)
}
