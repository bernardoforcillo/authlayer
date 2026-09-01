package auth

// This is the package's one INTERNAL test file. Every other test in
// auth/ is in package auth_test, deliberately, so it exercises the library
// the way an application does. The two things asserted here cannot be
// reached from outside: [Service.mfa] and [Service.mfaCipher] are the
// unexported guards that stand between an unconfigured Service and a nil
// dereference, and their whole job is to be the ONLY way the optional port
// and the cipher are ever read. A test that reached them through an
// exported entry point would be asserting that entry point's behaviour
// instead.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// stubMFAStore satisfies [MFAStore] and does nothing. It exists so the
// guards can be handed a non-nil port; no method of it is ever called.
type stubMFAStore struct{}

func (stubMFAStore) UpsertFactor(context.Context, MFAFactor) error { return nil }
func (stubMFAStore) FindFactor(context.Context, string) (MFAFactor, error) {
	return MFAFactor{}, ErrFactorNotFound
}
func (stubMFAStore) ConfirmFactor(context.Context, string, time.Time) (bool, error) {
	return false, nil
}
func (stubMFAStore) AdvanceStep(context.Context, string, int64) (bool, error) { return false, nil }
func (stubMFAStore) DeleteFactor(context.Context, string) error               { return nil }
func (stubMFAStore) ReplaceRecoveryCodes(context.Context, string, []RecoveryCode) error {
	return nil
}
func (stubMFAStore) ConsumeRecoveryCode(context.Context, string, string, time.Time) (bool, error) {
	return false, nil
}
func (stubMFAStore) ListRecoveryCodes(context.Context, string) ([]RecoveryCode, error) {
	return nil, nil
}

// stubCipher satisfies [Cipher] with an identity transform. It is a test
// double for wiring only — never a suggestion of what a real one looks
// like.
type stubCipher struct{}

func (stubCipher) Encrypt(plaintext string) (string, error)  { return plaintext, nil }
func (stubCipher) Decrypt(ciphertext string) (string, error) { return ciphertext, nil }

// TestMFAGuardsRefuseAnUnconfiguredService pins the fail-closed default
// for both optional pieces: a Service built with neither option resolves
// neither, and reports a typed refusal instead of handing back a nil
// interface for some later call to dereference.
func TestMFAGuardsRefuseAnUnconfiguredService(t *testing.T) {
	svc := New(nil)

	store, err := svc.mfa()
	if !errors.Is(err, ErrMFANotConfigured) {
		t.Fatalf("mfa() err = %v, want ErrMFANotConfigured", err)
	}
	if store != nil {
		t.Fatalf("mfa() returned a store alongside its refusal: %#v", store)
	}

	cipher, err := svc.mfaCipher()
	if !errors.Is(err, ErrMFACipherNotConfigured) {
		t.Fatalf("mfaCipher() err = %v, want ErrMFACipherNotConfigured", err)
	}
	if cipher != nil {
		t.Fatalf("mfaCipher() returned a cipher alongside its refusal: %#v", cipher)
	}
}

// A store without a cipher is the configuration that matters most: MFA
// looks wired, and enrolment must still refuse rather than write a
// plaintext secret. The two guards are independent, and this pins that
// they are.
func TestMFACipherGuardIsIndependentOfTheStore(t *testing.T) {
	svc := New(nil, WithMFAStore(stubMFAStore{}))

	if _, err := svc.mfa(); err != nil {
		t.Fatalf("mfa() with a store wired: %v", err)
	}
	if _, err := svc.mfaCipher(); !errors.Is(err, ErrMFACipherNotConfigured) {
		t.Fatalf("mfaCipher() err = %v, want ErrMFACipherNotConfigured — a wired store is not a wired cipher", err)
	}
}

// Both options honour a nil argument by leaving the default in place,
// matching every other Option in this package. A caller passing a nil
// store must not end up with a Service that thinks MFA is configured.
func TestMFAOptionsIgnoreNilArguments(t *testing.T) {
	svc := New(nil, WithMFAStore(nil), WithMFASecretCipher(nil))

	if _, err := svc.mfa(); !errors.Is(err, ErrMFANotConfigured) {
		t.Fatalf("WithMFAStore(nil) left the port configured: err = %v", err)
	}
	if _, err := svc.mfaCipher(); !errors.Is(err, ErrMFACipherNotConfigured) {
		t.Fatalf("WithMFASecretCipher(nil) left a cipher configured: err = %v", err)
	}
}

func TestMFAGuardsReturnWhatWasWired(t *testing.T) {
	store, cipher := stubMFAStore{}, stubCipher{}
	svc := New(nil, WithMFAStore(store), WithMFASecretCipher(cipher))

	got, err := svc.mfa()
	if err != nil {
		t.Fatalf("mfa(): %v", err)
	}
	if got != MFAStore(store) {
		t.Fatalf("mfa() returned %#v, want the wired store", got)
	}

	gotCipher, err := svc.mfaCipher()
	if err != nil {
		t.Fatalf("mfaCipher(): %v", err)
	}
	if gotCipher != Cipher(cipher) {
		t.Fatalf("mfaCipher() returned %#v, want the wired cipher", gotCipher)
	}
}
