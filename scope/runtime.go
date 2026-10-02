package scope

import "github.com/bernardoforcillo/authlayer/core"

// WithRuntime applies a shared [core.Runtime]: its Clock and IDs replace the
// defaults, a nil field leaves the default in place. It is the one call that
// keeps every Service in a deployment on the same clock and id source; the
// per-field [WithClock] and [WithIDGenerator] remain for a single override.
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
