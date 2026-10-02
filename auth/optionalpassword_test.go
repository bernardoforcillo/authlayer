package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bernardoforcillo/authlayer/auth"
)

func TestSignUpEmptyPasswordRefusedByDefault(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.SignUp(context.Background(), "a@example.com", "")
	if !errors.Is(err, auth.ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
}

func TestSignUpPasswordOptional(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t, auth.WithPasswordRequired(false))

	res, err := svc.SignUp(ctx, "a@example.com", "")
	if err != nil || !res.Created || res.VerifyToken == "" {
		t.Fatalf("SignUp = %+v, %v", res, err)
	}
	u, err := store.FindUserByEmail(ctx, "a@example.com")
	if err != nil || u.PasswordHash != "" {
		t.Fatalf("stored user = %+v, %v; want empty PasswordHash", u, err)
	}
	if _, err := svc.Login(ctx, "a@example.com", "", "1.2.3.4", "ua"); err == nil {
		t.Fatal("Login succeeded on a passwordless account")
	}

	// A supplied password is still validated.
	if _, err := svc.SignUp(ctx, "b@example.com", "x"); !errors.Is(err, auth.ErrWeakPassword) {
		t.Fatalf("weak password err = %v, want ErrWeakPassword", err)
	}
}

func TestSetPassword(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t, auth.WithPasswordRequired(false))
	res, err := svc.SignUp(ctx, "a@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	id := res.User.ID

	if err := svc.SetPassword(ctx, id, "", "short"); !errors.Is(err, auth.ErrWeakPassword) {
		t.Fatalf("weak err = %v", err)
	}
	const pw = "Correct-Horse-Battery-9"
	if err := svc.SetPassword(ctx, id, "", pw); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if u, _ := store.FindUserByID(ctx, id); u.PasswordHash == "" {
		t.Fatal("password not stored")
	}
	// A second call must go through ChangePassword.
	if err := svc.SetPassword(ctx, id, "", pw+"x"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("second SetPassword err = %v, want ErrInvalidCredentials", err)
	}
	if err := svc.SetPassword(ctx, "missing", "", pw); err == nil {
		t.Fatal("SetPassword on unknown user succeeded")
	}
}
