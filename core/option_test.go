package core

import (
	"context"
	"testing"
	"time"
)

func TestOverrideIgnoresNil(t *testing.T) {
	clock := func() time.Time { return time.Unix(1, 0) }
	Override(&clock, nil)
	if clock().Unix() != 1 {
		t.Fatal("a nil override replaced the clock")
	}
	Override(&clock, func() time.Time { return time.Unix(2, 0) })
	if clock().Unix() != 2 {
		t.Fatal("a non-nil override was ignored")
	}
}

func TestRuntimeApplyCopiesOnlySetFields(t *testing.T) {
	clock := func() time.Time { return time.Unix(1, 0) }
	ids := func() string { return "old" }
	Runtime{IDs: func() string { return "new" }}.Apply(&clock, &ids)
	if clock().Unix() != 1 || ids() != "new" {
		t.Fatalf("clock=%d ids=%s, want the clock kept and the ids replaced", clock().Unix(), ids())
	}
}

func TestAppendNonNilDropsNilInterfaces(t *testing.T) {
	var none Hook[int]
	got := AppendNonNil([]Hook[int](nil), none, Hook[int](HookFunc[int](func(_ context.Context, _ int) error { return nil })), nil)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
}
