package core_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/core"
)

func TestRuntimeDefaultsAndFixed(t *testing.T) {
	var zero core.Runtime
	if zero.NewID() == "" || zero.Now().IsZero() {
		t.Fatal("zero Runtime must fall back to real defaults")
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := core.Fixed(at).Now(); !got.Equal(at) {
		t.Fatalf("Fixed.Now = %v", got)
	}
}

func TestHooksStopAtFirstError(t *testing.T) {
	boom := errors.New("boom")
	var calls []int
	h := core.Hooks[string]{
		core.HookFunc[string](func(context.Context, string) error { calls = append(calls, 1); return nil }),
		nil,
		core.HookFunc[string](func(context.Context, string) error { calls = append(calls, 2); return boom }),
		core.HookFunc[string](func(context.Context, string) error { calls = append(calls, 3); return nil }),
	}
	if err := h.Emit(context.Background(), "e"); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want [1 2]", calls)
	}
}
