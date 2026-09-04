package oauth_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// cliClient creates a public device-code client with refresh.
func (f *fixture) cliClient(t *testing.T) oauth.Client {
	t.Helper()
	c, secret, err := f.svc.CreateClient(f.admin, oauth.ClientSpec{
		Name: "cli agent", Public: true, GrantTypes: []string{oauth.GrantDeviceCode, oauth.GrantRefreshToken},
	})
	if err != nil || secret != "" {
		t.Fatalf("CreateClient(cli): %v, secret %q", err, secret)
	}
	return c
}

var userCodeRE = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

func TestDeviceFlowEndToEnd(t *testing.T) {
	f := newFixture(t)
	c := f.cliClient(t)
	ctx := context.Background()

	dr, err := f.svc.BeginDeviceAuthorization(ctx, c.ID, "project:read")
	if err != nil {
		t.Fatalf("BeginDeviceAuthorization: %v", err)
	}
	if !userCodeRE.MatchString(dr.UserCode) || dr.DeviceCode == "" || dr.ExpiresIn != 600 || dr.Interval != 5 || dr.VerificationURI != "" {
		t.Fatalf("response = %+v", dr)
	}
	// The consent screen: the code typed sloppily still resolves.
	d, got, err := f.svc.DeviceByUserCode(ctx, " "+strings.ToLower(dr.UserCode)+" ")
	if err != nil || got.ID != c.ID || d.Scope != "project:read" || d.Status != oauth.DeviceStatusPending {
		t.Fatalf("DeviceByUserCode = %+v, %+v, %v", d, got, err)
	}
	// Pending until approved.
	if _, err := f.svc.PollDevice(ctx, c.ID, "", dr.DeviceCode); !errors.Is(err, oauth.ErrAuthorizationPending) {
		t.Fatalf("poll before approval err = %v, want ErrAuthorizationPending", err)
	}
	// Polling again inside the interval: slow down.
	if _, err := f.svc.PollDevice(ctx, c.ID, "", dr.DeviceCode); !errors.Is(err, oauth.ErrSlowDown) {
		t.Fatalf("fast poll err = %v, want ErrSlowDown", err)
	}
	f.clock.Advance(6 * time.Second)
	if _, err := f.svc.PollDevice(ctx, c.ID, "", dr.DeviceCode); !errors.Is(err, oauth.ErrAuthorizationPending) {
		t.Fatalf("poll after the interval err = %v, want ErrAuthorizationPending", err)
	}
	// Bob approves with a project:read cap.
	if err := f.svc.ApproveDevice(f.admin, dr.UserCode, oauth.Approval{Permissions: map[string][]access.Action{"project": {"read"}}}); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	if e, ok := f.lastEvent(oauth.DeviceApproved); !ok || e.ActorID != "bob" || e.ClientID != c.ID || e.GrantID == "" {
		t.Fatalf("DeviceApproved = %+v, %v", e, ok)
	}
	if _, _, err := f.svc.DeviceByUserCode(ctx, dr.UserCode); !errors.Is(err, oauth.ErrDeviceNotPending) {
		t.Fatalf("an approved code on the consent screen err = %v, want ErrDeviceNotPending", err)
	}
	// The poll mints — once.
	f.clock.Advance(6 * time.Second)
	resp, err := f.svc.PollDevice(ctx, c.ID, "", dr.DeviceCode)
	if err != nil || resp.AccessToken == "" || resp.RefreshToken == "" || resp.Scope != "project:read" {
		t.Fatalf("PollDevice = %+v, %v", resp, err)
	}
	f.clock.Advance(6 * time.Second)
	if _, err := f.svc.PollDevice(ctx, c.ID, "", dr.DeviceCode); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("second redemption err = %v, want ErrInvalidGrant", err)
	}
	p, err := f.svc.Authenticate(ctx, resp.AccessToken)
	if err != nil || p.Kind != apikey.KindDelegated || p.ID != "bob" || p.ClientID != c.ID {
		t.Fatalf("principal = %+v, %v", p, err)
	}
	agent := apikey.WithPrincipal(ctx, p)
	if !can(t, f.orgSvc, agent, "project", "read") || can(t, f.orgSvc, agent, "project", "delete") {
		t.Fatal("the agent reads and does not delete, though bob could")
	}
	if e, ok := f.lastEvent(oauth.TokenIssued); !ok || e.Detail != oauth.GrantDeviceCode {
		t.Fatalf("TokenIssued = %+v, %v", e, ok)
	}
	// Refresh works for the public client with no secret.
	if _, err := f.svc.Refresh(ctx, c.ID, "", resp.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
}

func TestDeviceDenialAndExpiry(t *testing.T) {
	f := newFixture(t)
	c := f.cliClient(t)
	ctx := context.Background()
	dr, err := f.svc.BeginDeviceAuthorization(ctx, c.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DenyDevice(f.admin, dr.UserCode); err != nil {
		t.Fatalf("DenyDevice: %v", err)
	}
	if err := f.svc.DenyDevice(f.admin, dr.UserCode); !errors.Is(err, oauth.ErrDeviceNotPending) {
		t.Fatalf("second denial err = %v", err)
	}
	if err := f.svc.ApproveDevice(f.admin, dr.UserCode, oauth.Approval{}); !errors.Is(err, oauth.ErrDeviceNotPending) {
		t.Fatalf("approval after denial err = %v", err)
	}
	if _, err := f.svc.PollDevice(ctx, c.ID, "", dr.DeviceCode); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatalf("poll after denial err = %v, want ErrAccessDenied", err)
	}
	if e, ok := f.lastEvent(oauth.DeviceDenied); !ok || e.ActorID != "bob" || e.ClientID != c.ID {
		t.Fatalf("DeviceDenied = %+v, %v", e, ok)
	}
	// Expiry.
	dr, err = f.svc.BeginDeviceAuthorization(ctx, c.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(11 * time.Minute)
	if _, _, err := f.svc.DeviceByUserCode(ctx, dr.UserCode); !errors.Is(err, oauth.ErrExpiredToken) {
		t.Fatalf("expired code on the consent screen err = %v", err)
	}
	if err := f.svc.ApproveDevice(f.admin, dr.UserCode, oauth.Approval{}); !errors.Is(err, oauth.ErrExpiredToken) {
		t.Fatalf("approving an expired code err = %v", err)
	}
	if _, err := f.svc.PollDevice(ctx, c.ID, "", dr.DeviceCode); !errors.Is(err, oauth.ErrExpiredToken) {
		t.Fatalf("polling an expired code err = %v, want ErrExpiredToken", err)
	}
	// Unknown codes.
	if _, _, err := f.svc.DeviceByUserCode(ctx, "BBBB-BBBB"); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("unknown user code err = %v", err)
	}
	if _, err := f.svc.PollDevice(ctx, c.ID, "", "nope"); !errors.Is(err, oauth.ErrInvalidGrant) || !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("unknown device code err = %v", err)
	}
}

func TestDeviceApprovalGuards(t *testing.T) {
	f := newFixture(t)
	c := f.cliClient(t)
	ctx := context.Background()
	dr, err := f.svc.BeginDeviceAuthorization(ctx, c.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	// carol (member) may not delegate project:read.
	if err := f.svc.ApproveDevice(f.member, dr.UserCode, oauth.Approval{Permissions: map[string][]access.Action{"project": {"read"}}}); !errors.Is(err, scope.ErrPrivilegeEscalation) {
		t.Fatalf("member delegating err = %v, want ErrPrivilegeEscalation", err)
	}
	// A refused approval leaves the authorization pending.
	if d, _, err := f.svc.DeviceByUserCode(ctx, dr.UserCode); err != nil || d.Status != oauth.DeviceStatusPending {
		t.Fatalf("after a refused approval: %+v, %v", d, err)
	}
	if err := f.svc.ApproveDevice(ctx, dr.UserCode, oauth.Approval{}); !errors.Is(err, scope.ErrSubjectMissing) {
		t.Fatalf("no subject err = %v", err)
	}
	// Client authentication at the poll: a confidential device client needs
	// its secret, and a client without the grant type is refused.
	conf, secret, err := f.svc.CreateClient(f.admin, oauth.ClientSpec{Name: "box", GrantTypes: []string{oauth.GrantDeviceCode}})
	if err != nil {
		t.Fatal(err)
	}
	cdr, err := f.svc.BeginDeviceAuthorization(ctx, conf.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.PollDevice(ctx, conf.ID, "", cdr.DeviceCode); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("confidential client polling without its secret err = %v", err)
	}
	if _, err := f.svc.PollDevice(ctx, conf.ID, secret, cdr.DeviceCode); !errors.Is(err, oauth.ErrAuthorizationPending) {
		t.Fatalf("confidential client polling with its secret err = %v", err)
	}
	// A device code presented by another client.
	if _, err := f.svc.PollDevice(ctx, c.ID, "", cdr.DeviceCode); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatalf("another client's device code err = %v", err)
	}
	cc, ccSecret := f.mustCC(t, f.ccSpec())
	if _, err := f.svc.BeginDeviceAuthorization(ctx, cc.ID, ""); !errors.Is(err, oauth.ErrUnauthorizedClient) {
		t.Fatalf("client without device_code err = %v", err)
	}
	if _, err := f.svc.PollDevice(ctx, cc.ID, ccSecret, "x"); !errors.Is(err, oauth.ErrUnauthorizedClient) {
		t.Fatalf("client without device_code polling err = %v", err)
	}
	// Scope and disabled client at Begin.
	if _, err := f.svc.BeginDeviceAuthorization(ctx, c.ID, "nope"); err != nil {
		t.Fatalf("a client with no scope list may request any scope without a map: %v", err)
	}
	if err := f.svc.DisableClient(f.admin, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginDeviceAuthorization(ctx, c.ID, ""); !errors.Is(err, oauth.ErrClientDisabled) {
		t.Fatalf("disabled client err = %v", err)
	}
	if _, _, err := f.svc.DeviceByUserCode(ctx, dr.UserCode); !errors.Is(err, oauth.ErrClientDisabled) {
		t.Fatalf("pending code of a disabled client err = %v", err)
	}
}

func TestLostApprovalRaceLeavesNoGrant(t *testing.T) {
	f := newFixture(t)
	c := f.cliClient(t)
	ctx := context.Background()
	dr, err := f.svc.BeginDeviceAuthorization(ctx, c.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate losing the compare-and-set: the row is denied between the
	// grant's creation and the transition. The memory store is
	// deterministic, so do it by hand: deny first through the store, then
	// approve through the service against a status the service believes is
	// pending — pendingDevice reads first, so use a store wrapper.
	d, _, err := f.svc.DeviceByUserCode(ctx, dr.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	racing := &denyBeforeTransition{OAuthStore: f.st, id: d.ID}
	svc := oauth.New(racing, f.orgSvc.Service, f.signer, oauth.WithIssuer(issuer), oauth.WithClock(f.clock.Now))
	if err := svc.ApproveDevice(f.admin, dr.UserCode, oauth.Approval{}); !errors.Is(err, oauth.ErrDeviceNotPending) {
		t.Fatalf("lost approval err = %v, want ErrDeviceNotPending", err)
	}
	grants, err := svc.ListGrants(f.admin)
	if err != nil || len(grants) != 0 {
		t.Fatalf("a lost approval left %d live grant(s): %v", len(grants), err)
	}
	if _, err := f.svc.PollDevice(ctx, c.ID, "", dr.DeviceCode); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatalf("poll after the race err = %v, want ErrAccessDenied", err)
	}
}

// denyBeforeTransition denies the authorization the moment the service
// tries to approve it, so the service's compare-and-set loses.
type denyBeforeTransition struct {
	*memory.OAuthStore
	id string
}

func (s *denyBeforeTransition) SetDeviceStatus(ctx context.Context, id string, from, to oauth.DeviceStatus, grantID string, now time.Time) (bool, error) {
	if id == s.id && to == oauth.DeviceStatusApproved {
		if _, err := s.OAuthStore.SetDeviceStatus(ctx, id, oauth.DeviceStatusPending, oauth.DeviceStatusDenied, "", now); err != nil {
			return false, err
		}
	}
	return s.OAuthStore.SetDeviceStatus(ctx, id, from, to, grantID, now)
}

func TestUserCodeHelpers(t *testing.T) {
	if got := oauth.FormatUserCode("BCDFGHJK"); got != "BCDF-GHJK" {
		t.Fatalf("FormatUserCode = %q", got)
	}
	if got := oauth.FormatUserCode("short"); got != "short" {
		t.Fatalf("FormatUserCode(short) = %q", got)
	}
	for in, want := range map[string]string{" bcdf-ghjk ": "BCDFGHJK", "BCDF GHJK": "BCDFGHJK", "bcdfghjk": "BCDFGHJK"} {
		if got := oauth.NormalizeUserCode(in); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
}
