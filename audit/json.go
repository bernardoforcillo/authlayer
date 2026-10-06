package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
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
// order, whitespace and how numbers are spelled: 100, 1e2 and 100.0 are equal,
// as a database that normalizes JSON (PostgreSQL's jsonb) may rewrite one into
// another. Two empty inputs are equal, an empty and a non-empty one are not,
// and input that is not a single JSON value equals nothing.
func EqualJSON(a, b json.RawMessage) bool {
	emptyA, emptyB := len(bytes.TrimSpace(a)) == 0, len(bytes.TrimSpace(b)) == 0
	if emptyA || emptyB {
		return emptyA && emptyB
	}
	va, err := decodeJSON(a)
	if err != nil {
		return false
	}
	vb, err := decodeJSON(b)
	if err != nil {
		return false
	}
	return equalValue(va, vb)
}

func equalValue(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !equalValue(xv, yv) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalValue(x[i], y[i]) {
				return false
			}
		}
		return true
	case json.Number:
		y, ok := b.(json.Number)
		return ok && decimalKey(string(x)) == decimalKey(string(y))
	}
	return a == b // string, bool, nil
}

// decimalKey spells a JSON number canonically — sign, significant digits
// without leading or trailing zeros, and the exponent of the last one — so
// two spellings of one value have one key. It never builds the number, so a
// huge exponent costs nothing; one that overflows int64 keeps its spelling.
func decimalKey(n string) string {
	neg := strings.HasPrefix(n, "-")
	n = strings.TrimPrefix(n, "-")
	mant, exp := n, int64(0)
	if i := strings.IndexAny(n, "eE"); i >= 0 {
		e, err := strconv.ParseInt(strings.TrimPrefix(n[i+1:], "+"), 10, 64)
		if err != nil {
			return n
		}
		mant, exp = n[:i], e
	}
	digits := mant
	if i := strings.IndexByte(mant, '.'); i >= 0 {
		digits = mant[:i] + mant[i+1:]
		exp -= int64(len(mant) - i - 1)
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0"
	}
	trimmed := strings.TrimRight(digits, "0")
	exp += int64(len(digits) - len(trimmed))
	if neg {
		trimmed = "-" + trimmed
	}
	return trimmed + "e" + strconv.FormatInt(exp, 10)
}
