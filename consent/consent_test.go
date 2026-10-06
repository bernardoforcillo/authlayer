package consent_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/consent"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func newSvc() (*consent.Service, *time.Time) {
	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	return consent.New(memory.NewConsentStore(), consent.WithRuntime(core.Runtime{Clock: func() time.Time { return now }})), &now
}

func TestGrantSupersedeWithdrawLifecycle(t *testing.T) {
	svc, now := newSvc()
	ctx := context.Background()
	v1, err := svc.Grant(ctx, "u1", "terms", "v1", "signup")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := svc.Grant(ctx, "u1", "terms", "v1", "signup"); again.ID != v1.ID {
		t.Error("granting the current version again created a second record")
	}
	if ok, _ := svc.Accepted(ctx, "u1", "terms", "v1"); !ok {
		t.Error("v1 not accepted")
	}
	if ok, _ := svc.Accepted(ctx, "u1", "terms", "v2"); ok {
		t.Error("v2 reported accepted before it was")
	}

	*now = now.Add(time.Hour)
	v2, _ := svc.Grant(ctx, "u1", "terms", "v2", "banner")
	if ok, _ := svc.Accepted(ctx, "u1", "terms", "v1"); ok {
		t.Error("v1 still accepted after v2 superseded it")
	}
	*now = now.Add(time.Hour)
	if err := svc.Withdraw(ctx, "u1", "terms"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Withdraw(ctx, "u1", "terms"); !errors.Is(err, consent.ErrNotFound) {
		t.Errorf("second Withdraw err = %v, want ErrNotFound", err)
	}
	if ok, _ := svc.Accepted(ctx, "u1", "terms", "v2"); ok {
		t.Error("v2 accepted after withdrawal")
	}

	h, _ := svc.History(ctx, "u1")
	if len(h) != 2 || h[0].ID != v1.ID || h[0].EndReason != consent.EndSuperseded ||
		h[1].ID != v2.ID || h[1].EndReason != consent.EndWithdrawn || h[1].EndedAt == nil {
		t.Errorf("History = %+v", h)
	}
	if n, err := svc.Erase(ctx, "u1"); err != nil || n != 2 {
		t.Errorf("Erase = %d, %v; want 2", n, err)
	}
	if h, _ := svc.History(ctx, "u1"); len(h) != 0 {
		t.Errorf("History after Erase = %+v", h)
	}
}

func TestInvalidArguments(t *testing.T) {
	svc, _ := newSvc()
	ctx := context.Background()
	for _, args := range [][3]string{{"", "p", "v"}, {"u", "", "v"}, {"u", "p", ""}} {
		if _, err := svc.Grant(ctx, args[0], args[1], args[2], ""); !errors.Is(err, consent.ErrInvalid) {
			t.Errorf("Grant(%v) err = %v, want ErrInvalid", args, err)
		}
	}
	if _, err := svc.Erase(ctx, ""); !errors.Is(err, consent.ErrInvalid) {
		t.Errorf("Erase(\"\") err = %v", err)
	}
}
