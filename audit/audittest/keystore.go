package audittest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/bernardoforcillo/authlayer/audit"
)

// RunKeyStoreContract runs the checks of [audit.KeyStore] against an EMPTY
// store from newStore, called once per check.
func RunKeyStoreContract(t *testing.T, newStore func(t *testing.T) audit.KeyStore) {
	t.Helper()
	for _, c := range []struct {
		name string
		fn   func(t tb, ks audit.KeyStore)
	}{
		{"Key/UnknownIsErrNotFound", keyUnknown},
		{"PutKey/FirstWriteWinsAndIsReturned", keyFirstWins},
		{"PutKey/ConcurrentWritersAgree", keyConcurrent},
		{"DeleteKey/RemovesOnlyThatSubjectAndIsIdempotent", keyDelete},
	} {
		t.Run(c.name, func(t *testing.T) { c.fn(t, newStore(t)) })
	}
}

func keyUnknown(t tb, ks audit.KeyStore) {
	if _, err := ks.Key(context.Background(), "nobody"); !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("Key(unknown) err = %v, want ErrNotFound", err)
	}
}

func keyFirstWins(t tb, ks audit.KeyStore) {
	ctx := context.Background()
	first, second := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	got, err := ks.PutKey(ctx, "u1", first)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("first PutKey = %x, %v; want the key it stored", got, err)
	}
	got, err = ks.PutKey(ctx, "u1", second)
	if err != nil || !bytes.Equal(got, first) {
		t.Errorf("second PutKey = %x, %v; want the first key back", got, err)
	}
	if got, err := ks.Key(ctx, "u1"); err != nil || !bytes.Equal(got, first) {
		t.Errorf("Key = %x, %v; want the first key", got, err)
	}
}

func keyConcurrent(t tb, ks audit.KeyStore) {
	ctx := context.Background()
	const n = 8
	out := make([][]byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i], _ = ks.PutKey(ctx, "u1", bytes.Repeat([]byte{byte(i + 1)}, 32))
		}()
	}
	wg.Wait()
	for i := range out {
		if len(out[i]) == 0 || !bytes.Equal(out[i], out[0]) {
			t.Errorf("writer %d got %x, writer 0 got %x: they must agree", i, out[i], out[0])
		}
	}
}

func keyDelete(t tb, ks audit.KeyStore) {
	ctx := context.Background()
	for _, id := range []string{"u1", "u2"} {
		if _, err := ks.PutKey(ctx, id, []byte(id+"-key-padding-padding-padding!")); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := ks.DeleteKey(ctx, "u1"); err != nil {
			t.Fatalf("DeleteKey #%d: %v", i+1, err)
		}
	}
	if _, err := ks.Key(ctx, "u1"); !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("Key after delete err = %v, want ErrNotFound", err)
	}
	if _, err := ks.Key(ctx, "u2"); err != nil {
		t.Errorf("another subject's key was removed: %v", err)
	}
	if err := ks.DeleteKey(ctx, "never"); err != nil {
		t.Errorf("DeleteKey(unknown) = %v, want nil", err)
	}
}
