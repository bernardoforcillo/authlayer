package uid

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewV7CanonicalFormat(t *testing.T) {
	id := NewV7()
	if len(id) != 36 {
		t.Fatalf("len = %d, want 36 (%q)", len(id), id)
	}
	for _, i := range []int{8, 13, 18, 23} {
		if id[i] != '-' {
			t.Fatalf("id[%d] = %q, want '-' (%q)", i, id[i], id)
		}
	}
	if _, err := hex.DecodeString(strings.ReplaceAll(id, "-", "")); err != nil {
		t.Fatalf("non-hex payload %q: %v", id, err)
	}
}

func TestNewV7VersionAndVariant(t *testing.T) {
	raw, err := hex.DecodeString(strings.ReplaceAll(NewV7(), "-", ""))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := raw[6] >> 4; got != 7 {
		t.Fatalf("version nibble = %d, want 7", got)
	}
	if got := raw[8] >> 6; got != 0b10 {
		t.Fatalf("variant bits = %02b, want 10", got)
	}
}

func TestNewV7IsUnique(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)
	for range n {
		id := NewV7()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %q within %d draws", id, n)
		}
		seen[id] = struct{}{}
	}
}

// The point of v7 over v4 is index locality: ids minted later must sort later.
// Same-millisecond ids may tie, so compare across a millisecond boundary.
//
// The first 13 characters (8 hex + '-' + 4 hex = 6 bytes) are the whole 48-bit
// millisecond timestamp, so this loop exits within a millisecond. Comparing
// only id[:8] would compare ms>>16 and spin for up to 65 seconds.
func TestNewV7IsTimeOrdered(t *testing.T) {
	first := NewV7()
	var second string
	for {
		second = NewV7()
		if second[:13] != first[:13] {
			break
		}
	}
	if second <= first {
		t.Fatalf("later id %q does not sort after earlier %q", second, first)
	}
}
