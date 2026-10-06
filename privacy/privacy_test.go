package privacy_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/audit/audithook"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/consent"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/password"
	"github.com/bernardoforcillo/authlayer/privacy"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

const pw = "Correct-Horse-Battery-9"

type fixture struct {
	auth    *auth.Service
	orgs    *org.Service
	audit   *audit.Service
	consent *consent.Service
	keys    *memory.AuditKeyStore
	ex      privacy.Exporter
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{keys: memory.NewAuditKeyStore()}
	f.audit = audit.New(memory.NewAuditStore(), audit.WithSubjectKeys(f.keys),
		audit.WithIPMode(audit.IPTruncate), audit.WithTopics(audithook.Topics()...))
	f.consent = consent.New(memory.NewConsentStore())
	f.orgs = org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member](), org.WithHooks(audithook.Scope(f.audit)))
	f.auth = auth.New(memory.NewAuthStore(),
		auth.WithHasher(password.Bcrypt(4)),
		auth.WithJWT([][]byte{[]byte("0123456789abcdef0123456789abcdef")}, 15*time.Minute),
		auth.WithMFAStore(memory.NewMFAStore()), auth.WithIdentityStore(memory.NewIdentityStore()), auth.WithCredentialStore(memory.NewCredentialStore()),
		auth.WithHooks(audithook.Auth(f.audit)),
		auth.WithSweeper(privacy.ErasureSweeper(privacy.AuditForget(f.audit), privacy.ConsentErase(f.consent))))
	f.ex = privacy.Exporter{Sources: []privacy.Source{
		privacy.Account(f.auth), privacy.Memberships(f.orgs), privacy.Consents(f.consent), privacy.AuditTrail(f.audit, 100),
	}}
	return f
}

func TestExportGathersEverythingAndNoCredential(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	su, err := f.auth.SignUp(ctx, "alice@example.com", pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth.VerifyEmail(ctx, su.VerifyToken); err != nil {
		t.Fatal(err)
	}
	login, err := f.auth.Login(ctx, "alice@example.com", pw, "203.0.113.77", "agent/1")
	if err != nil {
		t.Fatal(err)
	}
	actx := org.WithSubject(ctx, su.User.ID)
	acme, err := f.orgs.CreateOrganization(actx, "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.orgs.AddMember(org.WithOrg(actx, acme.ID), "bob", org.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := f.consent.Grant(ctx, su.User.ID, "terms", "v1", "signup"); err != nil {
		t.Fatal(err)
	}

	b, err := f.ex.Export(ctx, su.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(b.SectionNames(), ","); got != "account,audit,consents,memberships" {
		t.Fatalf("sections = %s", got)
	}
	var buf bytes.Buffer
	if err := b.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`"alice@example.com"`, `"terms"`, `"auth.logged_in"`, `"container_id": "` + acme.ID, `"owner": true`, `"203.0.113.0"`} {
		if !strings.Contains(out, want) {
			t.Errorf("export lacks %s:\n%s", want, out)
		}
	}
	// Never a credential or someone else.
	for _, banned := range []string{"$2a$", "password_hash", "token_hash", "PasswordHash", "TokenHash", login.RefreshToken, "bob"} {
		if strings.Contains(out, banned) {
			t.Errorf("export leaks %q", banned)
		}
	}
	// The audit section names the person's own events and masks the other
	// person bob, whom one of them is about.
	if !strings.Contains(out, "user/(a person)") {
		t.Errorf("an event about bob should be masked:\n%s", out)
	}
}

func TestExportFailsLoudlyAndRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.ex.Export(ctx, ""); !errors.Is(err, privacy.ErrInvalid) {
		t.Errorf("empty subject err = %v", err)
	}
	boom := errors.New("boom")
	ex := privacy.Exporter{Sources: []privacy.Source{privacy.SourceFunc("x", func(context.Context, string) (any, error) { return nil, boom })}}
	if _, err := ex.Export(ctx, "u"); !errors.Is(err, boom) || !strings.Contains(err.Error(), "export x") {
		t.Errorf("failing source err = %v", err)
	}
	dup := privacy.SourceFunc("d", func(context.Context, string) (any, error) { return 1, nil })
	if _, err := (privacy.Exporter{Sources: []privacy.Source{dup, dup}}).Export(ctx, "u"); !errors.Is(err, privacy.ErrInvalid) {
		t.Errorf("duplicate source err = %v", err)
	}
	if _, err := f.ex.Export(ctx, "no-such-user"); err == nil {
		t.Error("exporting an unknown user succeeded")
	}
	exp := privacy.Exporter{Runtime: core.Fixed(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))}
	if b, _ := exp.Export(ctx, "u"); b.GeneratedAt.Year() != 2026 || b.Format != privacy.FormatVersion {
		t.Errorf("bundle = %+v", b)
	}
}

func TestDeleteAccountErasesAuditAndConsent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	su, _ := f.auth.SignUp(ctx, "carol@example.com", pw)
	if _, err := f.consent.Grant(ctx, su.User.ID, "terms", "v1", ""); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := f.audit.List(ctx, audit.Filter{Member: su.User.ID}, audit.Page{}); len(got) == 0 {
		t.Fatal("no trail before deletion")
	}
	if err := f.auth.DeleteAccount(ctx, su.User.ID, "", pw); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if got, _, _ := f.audit.List(ctx, audit.Filter{Member: su.User.ID}, audit.Page{}); len(got) != 0 {
		t.Errorf("trail after deletion = %d events, want unreachable", len(got))
	}
	if h, _ := f.consent.History(ctx, su.User.ID); len(h) != 0 {
		t.Errorf("consent history after deletion = %+v", h)
	}
	if _, err := f.keys.Key(ctx, su.User.ID); !errors.Is(err, audit.ErrForgotten) {
		t.Errorf("pseudonym key survived: %v", err)
	}
}
