package magiclink_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth/magiclink"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/token"
)

var errNotFound = errors.New("not found")

// fake is an in-memory Backend that records the order of calls.
type fake struct {
	accounts map[string]*magiclink.Account // by email
	links    map[string]magiclink.Link     // by token hash
	calls    []string
}

func newFake() *fake {
	return &fake{accounts: map[string]*magiclink.Account{}, links: map[string]magiclink.Link{}}
}

func (f *fake) rec(s string) { f.calls = append(f.calls, s) }

func (f *fake) FindByEmail(_ context.Context, e string) (magiclink.Account, bool, error) {
	f.rec("FindByEmail")
	a, ok := f.accounts[e]
	if !ok {
		return magiclink.Account{}, false, nil
	}
	return *a, true, nil
}
func (f *fake) FindByID(_ context.Context, id string) (magiclink.Account, error) {
	f.rec("FindByID")
	for _, a := range f.accounts {
		if a.ID == id {
			return *a, nil
		}
	}
	return magiclink.Account{}, errNotFound
}
func (f *fake) Create(_ context.Context, id, e string, _ time.Time) (magiclink.Account, error) {
	f.rec("Create")
	a := &magiclink.Account{ID: id, Email: e}
	f.accounts[e] = a
	return *a, nil
}
func (f *fake) DeleteLinks(_ context.Context, accountID string) error {
	f.rec("DeleteLinks")
	for h, l := range f.links {
		if l.AccountID == accountID {
			delete(f.links, h)
		}
	}
	return nil
}
func (f *fake) PutLink(_ context.Context, l magiclink.Link) error {
	f.rec("PutLink")
	l.Genuine = true
	f.links[l.TokenHash] = l
	return nil
}
func (f *fake) FindLink(_ context.Context, h string) (magiclink.Link, error) {
	f.rec("FindLink")
	l, ok := f.links[h]
	if !ok {
		return magiclink.Link{}, errNotFound
	}
	return l, nil
}
func (f *fake) DeleteLink(_ context.Context, id string) error {
	f.rec("DeleteLink")
	for h, l := range f.links {
		if l.ID == id {
			delete(f.links, h)
		}
	}
	return nil
}
func (f *fake) MarkVerified(_ context.Context, _, e string, _ time.Time) error {
	f.rec("MarkVerified")
	f.accounts[e].Verified = true
	return nil
}

var at = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func newEngine(f *fake, cfg magiclink.Config) (*magiclink.Engine, *time.Time) {
	now := at
	n := 0
	cfg.Runtime = core.Runtime{
		Clock: func() time.Time { return now },
		IDs:   func() string { n++; return fmt.Sprint("id", n) },
	}
	return magiclink.New(f, cfg), &now
}

func TestRequestAndRedeemRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.accounts["a@x.io"] = &magiclink.Account{ID: "u1", Email: "a@x.io"}
	e, _ := newEngine(f, magiclink.Config{})

	tok, ok, err := e.Request(ctx, "a@x.io")
	if err != nil || !ok || tok == "" {
		t.Fatalf("Request = %q %v %v", tok, ok, err)
	}
	acc, err := e.Redeem(ctx, tok)
	if err != nil || acc.ID != "u1" || !acc.Verified {
		t.Fatalf("Redeem = %+v, %v", acc, err)
	}
	// Single use: the link was burned.
	if _, err := e.Redeem(ctx, tok); !errors.Is(err, errNotFound) {
		t.Fatalf("second Redeem err = %v, want not found", err)
	}
}

func TestEveryRefusalLooksTheSame(t *testing.T) {
	ctx := context.Background()
	deny := core.RateLimiter(denyAll{})
	cases := map[string]struct {
		seed func(*fake)
		cfg  magiclink.Config
	}{
		"unknown, provisioning off": {func(*fake) {}, magiclink.Config{}},
		"anonymized": {func(f *fake) {
			f.accounts["a@x.io"] = &magiclink.Account{ID: "u1", Email: "a@x.io", Deleted: true}
		}, magiclink.Config{}},
		"address limiter denies": {func(f *fake) {
			f.accounts["a@x.io"] = &magiclink.Account{ID: "u1", Email: "a@x.io"}
		}, magiclink.Config{AddressLimiter: deny}},
	}
	for name, c := range cases {
		f := newFake()
		c.seed(f)
		e, _ := newEngine(f, c.cfg)
		tok, ok, err := e.Request(ctx, "a@x.io")
		if tok != "" || ok || err != nil {
			t.Errorf("%s: Request = %q %v %v, want (\"\", false, nil)", name, tok, ok, err)
		}
		if len(f.links) != 0 {
			t.Errorf("%s: a link was stored", name)
		}
	}
}

type denyAll struct{}

func (denyAll) Allow(context.Context, string) (bool, error) { return false, nil }

func TestProvisioningAndCallOrder(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	e, _ := newEngine(f, magiclink.Config{Provisioning: true})
	if _, ok, err := e.Request(ctx, "new@x.io"); err != nil || !ok {
		t.Fatalf("Request ok=%v err=%v", ok, err)
	}
	want := []string{"FindByEmail", "Create", "DeleteLinks", "PutLink"}
	if fmt.Sprint(f.calls) != fmt.Sprint(want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	if f.accounts["new@x.io"].Verified {
		t.Fatal("provisioned account must start unverified")
	}
}

func TestRedeemRefusals(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.accounts["a@x.io"] = &magiclink.Account{ID: "u1", Email: "a@x.io"}
	e, now := newEngine(f, magiclink.Config{TTL: time.Minute})

	tok, _, _ := e.Request(ctx, "a@x.io")
	*now = at.Add(time.Minute)
	if _, err := e.Redeem(ctx, tok); !errors.Is(err, magiclink.ErrExpired) {
		t.Fatalf("expired err = %v", err)
	}

	// A row that is not a magic link must not redeem, and must not be burned.
	plain, h, _ := token.GenerateOpaque()
	f.links[h] = magiclink.Link{ID: "x", AccountID: "u1", Email: "a@x.io", TokenHash: h, ExpiresAt: at.Add(time.Hour), Genuine: false}
	*now = at
	if _, err := e.Redeem(ctx, plain); !errors.Is(err, magiclink.ErrWrongPurpose) {
		t.Fatalf("purpose err = %v", err)
	}
	if _, still := f.links[h]; !still {
		t.Fatal("a non-magic-link token was burned")
	}

	// An anonymized account is refused after the link is burned.
	tok3, _, _ := e.Request(ctx, "a@x.io")
	f.accounts["a@x.io"].Deleted = true
	if _, err := e.Redeem(ctx, tok3); !errors.Is(err, magiclink.ErrAccountGone) {
		t.Fatalf("gone err = %v", err)
	}
}

func TestEngineSatisfiesFlow(t *testing.T) {
	var _ magiclink.Flow = (*magiclink.Engine)(nil)
	var _ magiclink.Factory = magiclink.NewFlow
}
