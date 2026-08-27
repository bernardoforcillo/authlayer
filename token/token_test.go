package token

import "testing"

// GenerateOpaque must draw fresh randomness every call.
func TestGenerateOpaqueDistinctValues(t *testing.T) {
	const n = 1000
	seenPlain := make(map[string]struct{}, n)
	seenHash := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		plain, hash, err := GenerateOpaque()
		if err != nil {
			t.Fatalf("GenerateOpaque: %v", err)
		}
		if _, dup := seenPlain[plain]; dup {
			t.Fatalf("duplicate plain %q within %d draws", plain, n)
		}
		if _, dup := seenHash[hash]; dup {
			t.Fatalf("duplicate hash %q within %d draws", hash, n)
		}
		seenPlain[plain] = struct{}{}
		seenHash[hash] = struct{}{}
	}
}

// The returned hash must be exactly HashOpaque(plain) — that is the contract
// callers rely on when they persist hash and later verify a presented token
// with HashOpaque.
func TestGenerateOpaqueHashMatchesPlain(t *testing.T) {
	plain, hash, err := GenerateOpaque()
	if err != nil {
		t.Fatalf("GenerateOpaque: %v", err)
	}
	if got := HashOpaque(plain); got != hash {
		t.Fatalf("HashOpaque(plain) = %q, want %q (the hash GenerateOpaque returned)", got, hash)
	}
}

// 32 random bytes hex-encode to 64 characters; sha256 hex-encodes to 64
// characters. Pin both so a change of size is caught.
func TestGenerateOpaqueLengths(t *testing.T) {
	plain, hash, err := GenerateOpaque()
	if err != nil {
		t.Fatalf("GenerateOpaque: %v", err)
	}
	if len(plain) != 64 {
		t.Fatalf("len(plain) = %d, want 64 (32 bytes hex-encoded)", len(plain))
	}
	if len(hash) != 64 {
		t.Fatalf("len(hash) = %d, want 64 (sha256 hex-encoded)", len(hash))
	}
}

// Known sha256("") test vector pins HashOpaque to the standard algorithm and
// encoding rather than some other digest or a non-hex encoding.
func TestHashOpaqueKnownVector(t *testing.T) {
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := HashOpaque(""); got != want {
		t.Fatalf("HashOpaque(\"\") = %q, want %q", got, want)
	}
}

// HashOpaque is a pure function: same input, same output, every call.
func TestHashOpaqueDeterministic(t *testing.T) {
	const plain = "some-opaque-token-value"
	first := HashOpaque(plain)
	second := HashOpaque(plain)
	if first != second {
		t.Fatalf("HashOpaque(%q) = %q then %q, want identical", plain, first, second)
	}
}
