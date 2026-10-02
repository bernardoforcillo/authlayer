package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bernardoforcillo/authlayer/auth"
)

func TestCustomSweeperRunsForEveryReason(t *testing.T) {
	ctx := context.Background()
	var got []auth.SweepReason
	svc, _ := newTestService(t, auth.WithSweeper(auth.SweeperFunc(
		func(_ context.Context, r auth.SweepReason, userID string) error {
			got = append(got, r)
			return nil
		})))

	u := mustSignUp(t, svc, "sweep@example.com", validPassword)
	if err := svc.LogoutAll(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	tok, ok, err := svc.RequestPasswordReset(ctx, "sweep@example.com", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("RequestPasswordReset ok=%v err=%v", ok, err)
	}
	if err := svc.ResetPassword(ctx, tok, validPassword+"x"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteAccount(ctx, u.ID, "", validPassword+"x"); err != nil {
		t.Fatal(err)
	}
	want := []auth.SweepReason{auth.SweepLoggedOutAll, auth.SweepPasswordReset, auth.SweepAccountRemoved}
	if len(got) != len(want) {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reasons = %v, want %v", got, want)
		}
	}
}

func TestFailingCustomSweeperFailsClosed(t *testing.T) {
	boom := errors.New("boom")
	svc, _ := newTestService(t, auth.WithSweeper(auth.SweeperFunc(
		func(context.Context, auth.SweepReason, string) error { return boom })))
	u := mustSignUp(t, svc, "sweep2@example.com", validPassword)
	if err := svc.LogoutAll(context.Background(), u.ID); !errors.Is(err, boom) {
		t.Fatalf("LogoutAll err = %v, want boom", err)
	}
}
