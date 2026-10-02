package passkey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth/passkey"
	"github.com/bernardoforcillo/authlayer/token"
)

var errNotFound = errors.New("not found")

type fake struct {
	challenges map[string]passkey.Challenge // by hash
	counter    uint32
	touched    bool
}

func newFake() *fake { return &fake{challenges: map[string]passkey.Challenge{}} }

func (f *fake) PutChallenge(_ context.Context, c passkey.Challenge) error {
	f.challenges[c.Hash] = c
	return nil
}
func (f *fake) FindChallenge(_ context.Context, h string) (passkey.Challenge, error) {
	c, ok := f.challenges[h]
	if !ok {
		return passkey.Challenge{}, errNotFound
	}
	return c, nil
}
func (f *fake) DeleteChallenge(_ context.Context, id string) error {
	for h, c := range f.challenges {
		if c.ID == id {
			delete(f.challenges, h)
		}
	}
	return nil
}
func (f *fake) Touch(context.Context, string, time.Time) error { f.touched = true; return nil }
func (f *fake) AdvanceSignCount(_ context.Context, _ string, n uint32, _ time.Time) (bool, error) {
	if n <= f.counter {
		return false, nil
	}
	f.counter = n
	return true, nil
}

var at = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func engine(f *fake) *passkey.Engine {
	return passkey.New(f, time.Minute, func() string { return "id" })
}

func TestChallengeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	e := engine(newFake())
	c, err := e.Begin(ctx, "login", nil, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Claim(ctx, c, "login", nil, at); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := e.Claim(ctx, c, "login", nil, at); !errors.Is(err, errNotFound) {
		t.Fatalf("second claim err = %v, want not found", err)
	}
}

func TestClaimRefusalsDoNotBurnTheChallenge(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	e := engine(f)
	owner := "u1"
	c, _ := e.Begin(ctx, "registration", &owner, at)

	if err := e.Claim(ctx, c, "login", nil, at); !errors.Is(err, passkey.ErrChallengeCeremony) {
		t.Fatalf("ceremony err = %v", err)
	}
	other := "u2"
	if err := e.Claim(ctx, c, "registration", &other, at); !errors.Is(err, passkey.ErrChallengeOwner) {
		t.Fatalf("owner err = %v", err)
	}
	if err := e.Claim(ctx, c, "registration", &owner, at.Add(time.Minute)); !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Fatalf("expired err = %v", err)
	}
	if _, ok := f.challenges[token.HashOpaque(c)]; !ok {
		t.Fatal("a refused claim burned the challenge")
	}
	if err := e.Claim(ctx, c, "registration", &owner, at); err != nil {
		t.Fatalf("rightful claim after refusals: %v", err)
	}
	// A login challenge has no owner, so it cannot satisfy an owner check.
	lc, _ := e.Begin(ctx, "login", nil, at)
	if err := e.Claim(ctx, lc, "login", &owner, at); !errors.Is(err, passkey.ErrChallengeOwner) {
		t.Fatalf("ownerless err = %v", err)
	}
}

func TestSignCount(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	e := engine(f)

	if err := e.CheckAssertion(ctx, "c", 0, 0, at); err != nil || !f.touched {
		t.Fatalf("counter-less: err=%v touched=%v", err, f.touched)
	}
	if err := e.CheckAssertion(ctx, "c", 0, 5, at); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if err := e.CheckAssertion(ctx, "c", 5, 5, at); !errors.Is(err, passkey.ErrCloned) {
		t.Fatalf("replayed counter err = %v, want ErrCloned", err)
	}
}
