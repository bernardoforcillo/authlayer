package memory

// table is one id-keyed collection inside a store. It carries no lock of its
// own: every store method already holds the store's single mutex for its whole
// body, which is what keeps a check-then-write across two tables atomic, so the
// table only removes the repeated lookup-and-classify code.
//
// Being a named map type, it still ranges, indexes and deletes like one.
type table[V any] map[string]V

// get returns the row under id, or notFound.
func (t table[V]) get(id string, notFound error) (V, error) {
	v, ok := t[id]
	if !ok {
		var zero V
		return zero, notFound
	}
	return v, nil
}

// insert stores v under id, or returns taken when id is already present.
func (t table[V]) insert(id string, v V, taken error) error {
	if _, ok := t[id]; ok {
		return taken
	}
	t[id] = v
	return nil
}

// update applies fn to the row under id and stores the result, or returns
// notFound.
func (t table[V]) update(id string, notFound error, fn func(*V)) error {
	v, ok := t[id]
	if !ok {
		return notFound
	}
	fn(&v)
	t[id] = v
	return nil
}

// remove deletes the row under id, or returns notFound.
func (t table[V]) remove(id string, notFound error) error {
	if _, ok := t[id]; !ok {
		return notFound
	}
	delete(t, id)
	return nil
}

// filter returns the rows keep accepts, in map-iteration order. No match is an
// empty non-nil slice.
func (t table[V]) filter(keep func(V) bool) []V {
	out := make([]V, 0)
	for _, v := range t {
		if keep(v) {
			out = append(out, v)
		}
	}
	return out
}
