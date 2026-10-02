package auth

import "context"

// SweepReason names the credential or account event that obliges every
// module holding per-user state to clear it. It is the single vocabulary the
// "sweep matrix" (see [Service.ChangePassword]) is written in: a module
// decides, per reason, whether it has something to revoke, and the Service
// calls every module for every reason — so a new module cannot be forgotten
// at one call site, which is exactly the defect the matrix exists to prevent.
type SweepReason string

const (
	// SweepPasswordChanged: [Service.ChangePassword] or [Service.SetPassword].
	SweepPasswordChanged SweepReason = "password_changed"
	// SweepPasswordReset: [Service.ResetPassword] — the strongest recovery
	// path, so it also drops externally linked identities.
	SweepPasswordReset SweepReason = "password_reset"
	// SweepMFADisabled: [Service.DisableMFA].
	SweepMFADisabled SweepReason = "mfa_disabled"
	// SweepLoggedOutAll: [Service.LogoutAll].
	SweepLoggedOutAll SweepReason = "logged_out_all"
	// SweepAccountRemoved: [Service.DeleteAccount] and
	// [Service.AnonymizeAccount]. Everything goes.
	SweepAccountRemoved SweepReason = "account_removed"
)

// Sweeper is a module's hook into the sweep matrix. Sweep must remove or
// revoke whatever per-user state the module keeps that could later
// authenticate (or re-authenticate) userID, for the given reason, and be
// idempotent. Returning an error aborts the surrounding operation, exactly
// as a failing built-in sweep does, so the operation fails closed.
//
// Built-in modules (trusted devices, linked identities, passkeys, MFA state)
// are swept by the Service itself; register your own with [WithSweeper].
type Sweeper interface {
	Sweep(ctx context.Context, reason SweepReason, userID string) error
}

// SweeperFunc adapts a function to [Sweeper].
type SweeperFunc func(ctx context.Context, reason SweepReason, userID string) error

// Sweep implements [Sweeper].
func (f SweeperFunc) Sweep(ctx context.Context, reason SweepReason, userID string) error {
	return f(ctx, reason, userID)
}

// WithSweeper registers a custom module's [Sweeper]. Custom sweepers run
// after the built-in ones, in registration order, for every [SweepReason].
func WithSweeper(sw Sweeper) Option {
	return func(c *config) {
		if sw != nil {
			c.sweepers = append(c.sweepers, sw)
		}
	}
}

// sweep is the one place the matrix is applied. The built-in plan per
// reason preserves what each call site did before the matrix became data.
func (s *Service) sweep(ctx context.Context, reason SweepReason, userID string) error {
	var plan []func(context.Context, string) error
	switch reason {
	case SweepAccountRemoved:
		plan = []func(context.Context, string) error{s.sweepIdentities, s.sweepCredentials, s.sweepTrustedDevices, s.sweepMFAState}
	case SweepPasswordReset:
		plan = []func(context.Context, string) error{s.sweepTrustedDevices, s.sweepIdentities}
	default:
		plan = []func(context.Context, string) error{s.sweepTrustedDevices}
	}
	for _, f := range plan {
		if err := f(ctx, userID); err != nil {
			return err
		}
	}
	for _, sw := range s.cfg.sweepers {
		if err := sw.Sweep(ctx, reason, userID); err != nil {
			return err
		}
	}
	return nil
}
