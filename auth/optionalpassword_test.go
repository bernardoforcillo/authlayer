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

// byIDAuthenticator trusts a "user_id" field — a stand-in for a real
// method (SAML, SMS OTP) whose verification happens elsewhere.
type byIDAuthenticator struct{}

func (byIDAuthenticator) Name() auth.Method { return "by_id" }
func (byIDAuthenticator) Authenticate(_ context.Context, req auth.AuthRequest) (string, error) {
	if id := req.Fields["user_id"]; id != "" {
		return id, nil
	}
	return "", auth.ErrInvalidCredentials
}

func TestWithMethodsDisablesOthers(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, auth.WithMethods(auth.MethodMagicLink))

	if _, err := svc.Login(ctx, "a@example.com", "x", "1.2.3.4", "ua"); !errors.Is(err, auth.ErrMethodDisabled) {
		t.Fatalf("Login err = %v, want ErrMethodDisabled", err)
	}
	if _, err := svc.SignUp(ctx, "a@example.com", "Correct-Horse-Battery-9"); !errors.Is(err, auth.ErrMethodDisabled) {
		t.Fatalf("SignUp with password err = %v, want ErrMethodDisabled", err)
	}
	// Email-only SignUp and the enabled method still work.
	if res, err := svc.SignUp(ctx, "a@example.com", ""); err != nil || !res.Created {
		t.Fatalf("SignUp email-only = %+v, %v", res, err)
	}
	if _, ok, err := svc.RequestMagicLink(ctx, "a@example.com", "1.2.3.4"); err != nil || !ok {
		t.Fatalf("RequestMagicLink ok=%v err=%v", ok, err)
	}
	if _, err := svc.Authenticate(ctx, "by_id", auth.AuthRequest{IP: "1.2.3.4"}); !errors.Is(err, auth.ErrMethodDisabled) {
		t.Fatalf("Authenticate (unregistered) err = %v", err)
	}
}

func TestDelegates(t *testing.T) {
	ctx := context.Background()
	errBanned := errors.New("banned")
	errDomain := errors.New("domain")
	svc, _ := newTestService(t,
		auth.WithMethods(auth.MethodPassword, "by_id"),
		auth.WithAuthenticators(byIDAuthenticator{}),
		auth.WithSignUpPolicy(auth.SignUpPolicyFunc(func(_ context.Context, email string) error {
			if email != "ok@corp.example" {
				return errDomain
			}
			return nil
		})),
		auth.WithPasswordPolicy(auth.RulesPolicy{MinLength: 3}),
		auth.WithSessionGate(auth.SessionGateFunc(func(_ context.Context, u auth.UserBase, door string) error {
			if door == "by_id" {
				return errBanned
			}
			return nil
		})),
	)

	if _, err := svc.SignUp(ctx, "x@other.example", "abc"); !errors.Is(err, errDomain) {
		t.Fatalf("policy err = %v, want errDomain", err)
	}
	if _, err := svc.SignUp(ctx, "ok@corp.example", "ab"); !errors.Is(err, auth.ErrWeakPassword) {
		t.Fatalf("PasswordPolicy err = %v, want ErrWeakPassword", err)
	}
	res, err := svc.SignUp(ctx, "ok@corp.example", "abc")
	if err != nil || !res.Created {
		t.Fatalf("SignUp = %+v, %v", res, err)
	}
	if _, err := svc.Authenticate(ctx, "by_id", auth.AuthRequest{IP: "1.2.3.4", Fields: map[string]string{"user_id": res.User.ID}}); !errors.Is(err, errBanned) {
		t.Fatalf("gate err = %v, want errBanned", err)
	}
	if _, err := svc.Login(ctx, "ok@corp.example", "abc", "1.2.3.4", "ua"); err != nil {
		t.Fatalf("Login through an open gate: %v", err)
	}
}
