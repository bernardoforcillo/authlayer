package authlayer_test

import (
	"context"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func TestSharedRuntimeReachesModules(t *testing.T) {
	at := time.Date(2030, 5, 6, 7, 8, 9, 0, time.UTC)
	sh := authlayer.Shared{Runtime: core.Runtime{
		Clock: func() time.Time { return at },
		IDs:   func() string { return "fixed-id" },
	}}
	store := memory.NewAuthStore()
	svc := auth.New(store, sh.Auth(), auth.WithHasher(password.Bcrypt(4)))

	res, err := svc.SignUp(context.Background(), "a@example.com", "Correct-Horse-Battery-9")
	if err != nil || !res.Created {
		t.Fatalf("SignUp = %+v, %v", res, err)
	}
	if !res.User.CreatedAt.Equal(at) || res.User.ID != "fixed-id" {
		t.Fatalf("user = %+v, want the shared clock and id", res.User)
	}
	// The other modules' adapters exist and are usable as options.
	_, _, _ = sh.Scope(), sh.APIKey(), sh.OAuth()
}
