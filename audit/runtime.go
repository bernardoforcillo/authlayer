package audit

import "github.com/bernardoforcillo/authlayer/core"

// WithRuntime takes the clock and the id generator from a shared
// core.Runtime, as every authlayer Service does. Nil fields keep the
// defaults: time.Now().UTC() and UUIDv7.
func WithRuntime(r core.Runtime) Option {
	return func(c *config) {
		if r.Clock != nil {
			c.clock = r.Clock
		}
		if r.IDs != nil {
			c.idgen = r.IDs
		}
	}
}
