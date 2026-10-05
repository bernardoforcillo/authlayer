package audit

import (
	"bytes"
	"encoding/json"
)

// Diff compares two JSON documents leaf by leaf and returns the changed
// leaves as {"path": {"before": x, "after": y}}, or nil when nothing
// changed. Nested object keys join into a dotted path; arrays, scalars and
// empty objects are leaves. A side that is empty or null has no leaves, so a
// creation lists every leaf of after with a null before, and a deletion every
// leaf of before with a null after. Input that is not JSON returns
// {"redaction_error":true}. Diff does not redact: redact both sides first.
func Diff(before, after json.RawMessage) json.RawMessage {
	b, err := leaves(before)
	if err != nil {
		return redactionError
	}
	a, err := leaves(after)
	if err != nil {
		return redactionError
	}
	out := map[string]any{}
	for path, bv := range b {
		av, ok := a[path]
		switch {
		case !ok:
			out[path] = change(bv, nil)
		case !sameJSONValue(bv, av):
			out[path] = change(bv, av)
		}
	}
	for path, av := range a {
		if _, ok := b[path]; !ok {
			out[path] = change(nil, av)
		}
	}
	if len(out) == 0 {
		return nil
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return redactionError
	}
	return raw
}

func change(before, after any) map[string]any {
	return map[string]any{"before": before, "after": after}
}

func leaves(raw json.RawMessage) (map[string]any, error) {
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return out, nil
	}
	v, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}
	switch x := v.(type) {
	case nil:
		return out, nil
	case map[string]any:
		for k, child := range x {
			walkLeaves(k, child, out)
		}
		return out, nil
	default:
		out[""] = x
		return out, nil
	}
}

func walkLeaves(path string, v any, out map[string]any) {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		out[path] = v
		return
	}
	for k, child := range m {
		walkLeaves(path+"."+k, child, out)
	}
}

func sameJSONValue(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}
