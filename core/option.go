package core

import "time"

// The helpers below are what every package's WithClock, WithIDGenerator,
// WithRuntime and WithHooks are built from, so the "a nil value is ignored"
// rule is written once.

// Override assigns v to *dst unless v is nil, and reports nothing: a nil
// clock or id generator means "keep the default".
func Override[T any](dst *func() T, v func() T) {
	if v != nil {
		*dst = v
	}
}

// Apply copies r's non-nil fields onto the clock and id-generator slots a
// package's config holds. A nil field leaves the slot as it was.
func (r Runtime) Apply(clock *func() time.Time, ids *func() string) {
	Override(clock, r.Clock)
	Override(ids, r.IDs)
}

// AppendNonNil appends the non-nil elements of src to dst. It is for hook
// lists, whose elements are interface values.
func AppendNonNil[T any](dst []T, src ...T) []T {
	for _, v := range src {
		if any(v) != nil {
			dst = append(dst, v)
		}
	}
	return dst
}
