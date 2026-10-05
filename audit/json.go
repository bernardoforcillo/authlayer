package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// errNotJSON: the input holds more than one JSON value.
var errNotJSON = errors.New("authlayer/audit: not a single JSON value")

// decodeJSON parses raw into Go values, keeping numbers as written so a
// round trip cannot change them.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errNotJSON
	}
	return v, nil
}

// canonicalJSON re-encodes raw with sorted object keys and no insignificant
// whitespace, keeping numbers as written.
func canonicalJSON(raw []byte) ([]byte, error) {
	v, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// EqualJSON reports whether a and b hold the same JSON value, ignoring key
// order and whitespace. Two empty inputs are equal, an empty and a non-empty
// one are not, and input that is not a single JSON value equals nothing.
func EqualJSON(a, b json.RawMessage) bool {
	emptyA, emptyB := len(bytes.TrimSpace(a)) == 0, len(bytes.TrimSpace(b)) == 0
	if emptyA || emptyB {
		return emptyA && emptyB
	}
	ca, err := canonicalJSON(a)
	if err != nil {
		return false
	}
	cb, err := canonicalJSON(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ca, cb)
}
