// Package privacy answers the two requests a data subject can make of
// everything authlayer stores about them: "give me my data" (GDPR Arts. 15 and
// 20) and "erase me" (Art. 17).
//
// # Access and portability
//
// An [Exporter] gathers one JSON-serializable section per [Source] into a
// [Bundle], a structured, commonly used, machine-readable document:
//
//	ex := privacy.Exporter{Sources: []privacy.Source{
//	    privacy.Account(authSvc),   // the account, sessions, sign-in methods
//	    privacy.Memberships(orgSvc), // containers and roles
//	    privacy.Grants(oauthSvc),   // apps they connected
//	    privacy.Consents(consentSvc),
//	    privacy.AuditTrail(auditSvc, 10_000),
//	    privacy.SourceFunc("orders", loadOrders), // your own data
//	}}
//	bundle, err := ex.Export(ctx, userID)
//	err = bundle.WriteJSON(w)
//
// Sections carry what the person is entitled to see and never a credential:
// no password hash, no token or key hash, no passkey public key, no MFA
// secret. A source that fails fails the whole export — an access request
// answered with a silently missing section is worse than one that errors.
//
// The export performs no authorization: the caller must already have
// authenticated the person it names. Hand it only the id of the logged-in user,
// or of one a verified operator is acting for.
//
// # Erasure
//
// [ErasureSweeper] plugs the parts of this module that are not an account row
// — the audit log's pseudonym key, consent records, your own stores — into
// auth.WithSweeper, so deleting or anonymizing an account erases them too:
//
//	auth.WithSweeper(privacy.ErasureSweeper(
//	    privacy.AuditForget(auditSvc), privacy.ConsentErase(consentSvc)))
//
// Memberships are removed by authlayer.RemoveUserSweeper, as before.
package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/consent"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/scope"
)

// FormatVersion is the value of [Bundle.Format].
const FormatVersion = "authlayer.privacy/v1"

// Bundle is the export of one person's data.
type Bundle struct {
	// Format identifies the layout, so a reader can tell versions apart.
	Format string `json:"format"`
	// SubjectID is the person.
	SubjectID string `json:"subject_id"`
	// GeneratedAt is when the export was made, in UTC.
	GeneratedAt time.Time `json:"generated_at"`
	// Sections maps a source's name to what it returned.
	Sections map[string]any `json:"sections"`
}

// WriteJSON writes the bundle as indented JSON.
func (b Bundle) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// Source produces one section of an export.
type Source interface {
	// Name is the section's key in [Bundle.Sections]; unique per Exporter.
	Name() string
	// Export returns the person's data for this section, JSON-serializable.
	Export(ctx context.Context, subjectID string) (any, error)
}

// SourceFunc adapts a function to a [Source], for your own tables.
func SourceFunc(name string, fn func(ctx context.Context, subjectID string) (any, error)) Source {
	return funcSource{name, fn}
}

type funcSource struct {
	name string
	fn   func(context.Context, string) (any, error)
}

func (s funcSource) Name() string                                       { return s.name }
func (s funcSource) Export(ctx context.Context, id string) (any, error) { return s.fn(ctx, id) }

// ErrInvalid: an empty subject, or two sources with the same name.
var ErrInvalid = errors.New("authlayer/privacy: invalid argument")

// Exporter gathers sources into a bundle.
type Exporter struct {
	// Runtime supplies the clock; the zero value uses the wall clock.
	Runtime core.Runtime
	// Sources are run in order.
	Sources []Source
}

// Export runs every source for subjectID.
func (e Exporter) Export(ctx context.Context, subjectID string) (Bundle, error) {
	if subjectID == "" {
		return Bundle{}, fmt.Errorf("%w: empty subject", ErrInvalid)
	}
	b := Bundle{Format: FormatVersion, SubjectID: subjectID, GeneratedAt: e.Runtime.Now().UTC(),
		Sections: make(map[string]any, len(e.Sources))}
	for _, src := range e.Sources {
		if _, dup := b.Sections[src.Name()]; dup {
			return Bundle{}, fmt.Errorf("%w: two sources named %q", ErrInvalid, src.Name())
		}
		v, err := src.Export(ctx, subjectID)
		if err != nil {
			return Bundle{}, fmt.Errorf("privacy: export %s: %w", src.Name(), err)
		}
		b.Sections[src.Name()] = v
	}
	return b, nil
}

// SectionNames returns the bundle's section names, sorted.
func (b Bundle) SectionNames() []string {
	names := make([]string, 0, len(b.Sections))
	for n := range b.Sections {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ── account ─────────────────────────────────────────────────────────────────

// AccountReader is what [Account] needs of an *auth.Service.
type AccountReader interface {
	User(ctx context.Context, userID string) (auth.UserBase, error)
	ListSessions(ctx context.Context, userID string) ([]auth.Session, error)
	ListIdentities(ctx context.Context, userID string) ([]auth.Identity, error)
	ListPasskeys(ctx context.Context, userID string) ([]auth.Credential, error)
	ListTrustedDevices(ctx context.Context, userID string) ([]auth.TrustedDevice, error)
}

// AccountData is the "account" section.
type AccountData struct {
	ID              string         `json:"id"`
	Email           string         `json:"email"`
	EmailVerifiedAt *time.Time     `json:"email_verified_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	Sessions        []SessionData  `json:"sessions"`
	Identities      []IdentityData `json:"identities"`
	Passkeys        []PasskeyData  `json:"passkeys"`
	TrustedDevices  []DeviceData   `json:"trusted_devices"`
}

// SessionData is one sign-in session; the refresh token hash is not included.
type SessionData struct {
	ID        string     `json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	IP        string     `json:"ip,omitempty"`
	UserAgent string     `json:"user_agent,omitempty"`
	MFAAt     *time.Time `json:"mfa_at,omitempty"`
}

// IdentityData is one linked external account.
type IdentityData struct {
	Provider   string     `json:"provider"`
	Subject    string     `json:"subject"`
	Email      string     `json:"email,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// PasskeyData is one registered passkey; its public key is not included.
type PasskeyData struct {
	ID         string     `json:"id"`
	Label      string     `json:"label,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// DeviceData is one trusted device; its token hash is not included.
type DeviceData struct {
	ID         string     `json:"id"`
	Label      string     `json:"label,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Account exports the "account" section: the user record without its
// password hash, and the sessions, linked identities, passkeys and trusted
// devices that belong to it. A deployment without a store for one of those
// (an auth.Service with no identity, credential or MFA store) gets that list
// empty rather than failing.
func Account(r AccountReader) Source {
	return funcSource{"account", func(ctx context.Context, id string) (any, error) {
		u, err := r.User(ctx, id)
		if err != nil {
			return nil, err
		}
		d := AccountData{ID: u.ID, Email: u.Email, EmailVerifiedAt: u.EmailVerifiedAt, CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt, Sessions: []SessionData{}, Identities: []IdentityData{},
			Passkeys: []PasskeyData{}, TrustedDevices: []DeviceData{}}
		sessions, err := r.ListSessions(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, s := range sessions {
			d.Sessions = append(d.Sessions, SessionData{ID: s.ID, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
				RotatedAt: s.RotatedAt, IP: s.IP, UserAgent: s.UserAgent, MFAAt: s.MFAAt})
		}
		identities, err := r.ListIdentities(ctx, id)
		if err != nil && !errors.Is(err, auth.ErrOAuthNotConfigured) {
			return nil, err
		}
		for _, i := range identities {
			d.Identities = append(d.Identities, IdentityData{Provider: i.Provider, Subject: i.Subject, Email: i.Email,
				CreatedAt: i.CreatedAt, LastUsedAt: i.LastUsedAt})
		}
		passkeys, err := r.ListPasskeys(ctx, id)
		if err != nil && !errors.Is(err, auth.ErrPasskeysNotConfigured) {
			return nil, err
		}
		for _, p := range passkeys {
			d.Passkeys = append(d.Passkeys, PasskeyData{ID: p.ID, Label: p.Label, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt})
		}
		devices, err := r.ListTrustedDevices(ctx, id)
		if err != nil && !errors.Is(err, auth.ErrMFANotConfigured) {
			return nil, err
		}
		for _, v := range devices {
			d.TrustedDevices = append(d.TrustedDevices, DeviceData{ID: v.ID, Label: v.Label, CreatedAt: v.CreatedAt,
				ExpiresAt: v.ExpiresAt, LastUsedAt: v.LastUsedAt})
		}
		return d, nil
	}}
}

// ── memberships ─────────────────────────────────────────────────────────────

// MembershipLister is what [Memberships] needs: a scope.Service, or an
// org.Service or team.Service, which promote it.
type MembershipLister interface {
	Memberships(ctx context.Context, userID string) ([]scope.Membership, error)
}

// MembershipData is one entry of the "memberships" section.
type MembershipData struct {
	ContainerID string `json:"container_id"`
	Role        string `json:"role"`
	Owner       bool   `json:"owner"`
}

// Memberships exports a section of the containers the person belongs to and
// their role in each. Pass the section name when you export several scopes
// (organizations, teams); it defaults to "memberships".
func Memberships(l MembershipLister, name ...string) Source {
	n := "memberships"
	if len(name) > 0 && name[0] != "" {
		n = name[0]
	}
	return funcSource{n, func(ctx context.Context, id string) (any, error) {
		ms, err := l.Memberships(ctx, id)
		if err != nil {
			return nil, err
		}
		out := make([]MembershipData, 0, len(ms))
		for _, m := range ms {
			out = append(out, MembershipData{ContainerID: m.ContainerID, Role: m.RoleKey, Owner: m.Owner})
		}
		return out, nil
	}}
}

// ── oauth grants ────────────────────────────────────────────────────────────

// GrantLister is what [Grants] needs of an *oauth.Service.
type GrantLister interface {
	ListGrants(ctx context.Context) ([]oauth.Grant, error)
}

// GrantData is one app the person connected.
type GrantData struct {
	ID          string     `json:"id"`
	ClientID    string     `json:"client_id"`
	ContainerID string     `json:"container_id,omitempty"`
	Scope       string     `json:"scope"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// Grants exports the "oauth_grants" section: the live delegations the person
// made to clients. Revoked grants are not listed by oauth, so they are not
// exported.
func Grants(l GrantLister) Source {
	return funcSource{"oauth_grants", func(ctx context.Context, id string) (any, error) {
		gs, err := l.ListGrants(scope.WithSubject(ctx, id))
		if err != nil {
			return nil, err
		}
		out := make([]GrantData, 0, len(gs))
		for _, g := range gs {
			out = append(out, GrantData{ID: g.ID, ClientID: g.ClientID, ContainerID: g.ContainerID, Scope: g.Scope,
				CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt, LastUsedAt: g.LastUsedAt})
		}
		return out, nil
	}}
}

// ── consent ─────────────────────────────────────────────────────────────────

// ConsentData is one consent record.
type ConsentData struct {
	Purpose   string     `json:"purpose"`
	Version   string     `json:"version"`
	Source    string     `json:"source,omitempty"`
	GrantedAt time.Time  `json:"granted_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	EndReason string     `json:"end_reason,omitempty"`
}

// Consents exports the "consents" section: the person's full consent history.
func Consents(svc *consent.Service) Source {
	return funcSource{"consents", func(ctx context.Context, id string) (any, error) {
		rs, err := svc.History(ctx, id)
		if err != nil {
			return nil, err
		}
		out := make([]ConsentData, 0, len(rs))
		for _, r := range rs {
			out = append(out, ConsentData{Purpose: r.Purpose, Version: r.Version, Source: r.Source,
				GrantedAt: r.GrantedAt, EndedAt: r.EndedAt, EndReason: r.EndReason})
		}
		return out, nil
	}}
}

// ── audit trail ─────────────────────────────────────────────────────────────

// AuditEventData is one event of the person's trail. Another person an event
// is about is named only as "user/(a person)": an access request must not
// disclose someone else's identity (Art. 15(4)).
type AuditEventData struct {
	Time        time.Time `json:"time"`
	Topic       string    `json:"topic"`
	Action      string    `json:"action"`
	Outcome     string    `json:"outcome,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Resource    string    `json:"resource,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
	IP          string    `json:"ip,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	AsActor     bool      `json:"as_actor"`
}

// AuditTrail exports the "audit" section: the events the person performed, was
// acted as in, or was the subject of ([audit.Filter.Member]), oldest first.
// limit caps how many events it will export; more than limit is
// audit.ErrExportTooLarge, so an oversized trail is a visible failure rather
// than a truncated answer.
func AuditTrail(svc *audit.Service, limit int) Source {
	return funcSource{"audit", func(ctx context.Context, id string) (any, error) {
		out := []AuditEventData{}
		self := map[string]bool{id: true}
		if p, err := svc.Pseudonym(ctx, id); err == nil {
			self[p] = true
		}
		err := svc.Export(ctx, audit.Filter{Member: id}, limit, func(e audit.Event) error {
			res := ""
			if e.Resource.Type != "" {
				res = e.Resource.Type + "/" + e.Resource.ID
				if e.Resource.Type == audit.ResourceUser {
					res = audit.ResourceUser + "/(a person)"
					if self[e.Resource.ID] {
						res = audit.ResourceUser + "/" + id
					}
				}
			}
			out = append(out, AuditEventData{Time: e.OccurredAt, Topic: e.Topic, Action: e.Action,
				Outcome: string(e.Outcome), Reason: e.Reason, Resource: res, ContainerID: e.ContainerID,
				IP: e.IP, UserAgent: e.UserAgent, AsActor: self[e.Actor.ID]})
			return nil
		})
		return out, err
	}}
}

// ── erasure ─────────────────────────────────────────────────────────────────

// Eraser erases one module's data about a person.
type Eraser interface {
	// Name identifies the eraser in an error.
	Name() string
	// Erase removes the person's data; it must be idempotent so a retried
	// account deletion completes.
	Erase(ctx context.Context, subjectID string) error
}

// EraserFunc adapts a function to an [Eraser], for your own tables.
func EraserFunc(name string, fn func(ctx context.Context, subjectID string) error) Eraser {
	return funcEraser{name, fn}
}

type funcEraser struct {
	name string
	fn   func(context.Context, string) error
}

func (e funcEraser) Name() string                               { return e.name }
func (e funcEraser) Erase(ctx context.Context, id string) error { return e.fn(ctx, id) }

// AuditForget erases the person from the audit log by deleting their
// pseudonym key ([audit.Service.Forget]).
func AuditForget(svc *audit.Service) Eraser {
	return funcEraser{"audit", svc.Forget}
}

// ConsentErase deletes the person's consent records ([consent.Service.Erase]).
func ConsentErase(svc *consent.Service) Eraser {
	return funcEraser{"consent", func(ctx context.Context, id string) error { _, err := svc.Erase(ctx, id); return err }}
}

// ErasureSweeper returns an [auth.Sweeper] that runs the erasers when an
// account is deleted or anonymized, in order, and stops at the first failure,
// which fails the account removal closed. It acts on no other reason.
func ErasureSweeper(erasers ...Eraser) auth.Sweeper {
	return auth.SweeperFunc(func(ctx context.Context, reason auth.SweepReason, userID string) error {
		if reason != auth.SweepAccountRemoved && reason != auth.SweepAccountAnonymized {
			return nil
		}
		for _, e := range erasers {
			if err := e.Erase(ctx, userID); err != nil {
				return fmt.Errorf("privacy: erase %s: %w", e.Name(), err)
			}
		}
		return nil
	})
}
