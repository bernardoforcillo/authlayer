package dropsstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/invite"
)

func newInviteStore(fd *fakeDriver) *InviteStore {
	return NewInviteStore(pg.New(fd))
}

// ── schema / naming ─────────────────────────────────────────────────────────

func TestInviteSchemaDefaultTableNames(t *testing.T) {
	s := NewInviteSchema()
	if s.EmailInvites.Name() != "organization_invites" || s.Links.Name() != "organization_invite_links" {
		t.Fatalf("unexpected table names: %s %s", s.EmailInvites.Name(), s.Links.Name())
	}
}

func TestInviteSchemaHonoursCustomNames(t *testing.T) {
	s := NewInviteSchema(WithInviteNames(InviteNames{
		EmailInvites: "team_invites", Links: "team_invite_links",
	}))
	if s.EmailInvites.Name() != "team_invites" || s.Links.Name() != "team_invite_links" {
		t.Fatalf("custom names not applied: %s %s", s.EmailInvites.Name(), s.Links.Name())
	}
}

func TestInviteSchemaUserIDColumnsFollowTheOption(t *testing.T) {
	uuidSchema := NewInviteSchema()
	if got := uuidSchema.EmailInvites.Col("invited_by").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("invited_by type = %q, want uuid by default", got)
	}
	if got := uuidSchema.Links.Col("created_by").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("created_by type = %q, want uuid by default", got)
	}

	textSchema := NewInviteSchema(WithInviteTextUserIDs())
	if got := textSchema.EmailInvites.Col("invited_by").Type().TypeSQL(); got != "text" {
		t.Fatalf("invited_by type = %q, want text under WithInviteTextUserIDs", got)
	}
	if got := textSchema.Links.Col("created_by").Type().TypeSQL(); got != "text" {
		t.Fatalf("created_by type = %q, want text under WithInviteTextUserIDs", got)
	}
	// container_id is library-minted, so it must stay uuid regardless.
	if got := textSchema.EmailInvites.Col("container_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithInviteTextUserIDs leaked into container_id: %q", got)
	}
}

// The (container_id, email) unique constraint is load-bearing: it is what
// makes an ordinary re-invite of the same address a unique violation rather
// than an ambiguous second row.
func TestInviteSchemaEmailInvitesHaveContainerEmailUnique(t *testing.T) {
	s := NewInviteSchema()
	uniques := s.EmailInvites.CompositeUniques()
	cols, ok := uniques["organization_invites_container_email"]
	if !ok {
		t.Fatalf("email invites table missing UNIQUE constraint; have %v", uniques)
	}
	got := []string{cols[0].Name(), cols[1].Name()}
	want := []string{"container_id", "email"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unique constraint columns = %v, want %v", got, want)
	}
}

// The code unique constraint is load-bearing: FindLinkByCode depends on it
// for lookups to be unambiguous. invite.Link's own `drop:"code"` tag carries
// no "unique" option, so nothing declares this inline — it must be added at
// the table level, the same way as the composite ones.
func TestInviteSchemaLinksHaveCodeUnique(t *testing.T) {
	s := NewInviteSchema()
	uniques := s.Links.CompositeUniques()
	cols, ok := uniques["organization_invite_links_code"]
	if !ok {
		t.Fatalf("links table missing UNIQUE(code) constraint; have %v", uniques)
	}
	if len(cols) != 1 || cols[0].Name() != "code" {
		t.Fatalf("unique constraint columns = %v, want [code]", cols)
	}
}

// FindEmailInviteByTokenHash is the acceptance hot path — the lookup every
// redeemed invitation performs — and a plain (non-unique) index would only
// speed it up; UNIQUE additionally turns a hash collision or a
// token-generation bug into a loud constraint violation on write instead of
// an ambiguous multi-row match this lookup would otherwise silently resolve
// to whichever row came back first.
func TestInviteSchemaEmailInvitesHaveTokenHashUnique(t *testing.T) {
	s := NewInviteSchema()
	uniques := s.EmailInvites.CompositeUniques()
	cols, ok := uniques["organization_invites_token_hash"]
	if !ok {
		t.Fatalf("email invites table missing UNIQUE(token_hash) constraint; have %v", uniques)
	}
	if len(cols) != 1 || cols[0].Name() != "token_hash" {
		t.Fatalf("unique constraint columns = %v, want [token_hash]", cols)
	}
}

// drops' CreateTableIfNotExists writes column definitions only, so a
// multi-column (or, for token_hash/code, a "unique" option the struct tag
// does not carry) UNIQUE would never reach the database unless CreateSchema
// emits it itself. Assert the SQL, not the registry — the registry is what
// was already true before CreateSchema ran.
func TestInviteStoreCreateSchemaEmitsUniqueConstraints(t *testing.T) {
	fd := &fakeDriver{}
	st := newInviteStore(fd)
	if err := st.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}

	// 2 CREATE TABLE + 3 ALTER TABLE ADD CONSTRAINT (container_email,
	// token_hash on invites; code on links).
	if len(fd.execs) != 5 {
		t.Fatalf("CreateSchema issued %d statements, want 5:\n%s",
			len(fd.execs), strings.Join(fd.execs, "\n--\n"))
	}

	all := strings.Join(fd.execs, "\n--\n")
	want := []string{
		`ALTER TABLE "organization_invites" ADD CONSTRAINT "organization_invites_container_email" ` +
			`UNIQUE ("container_id", "email");`,
		`ALTER TABLE "organization_invites" ADD CONSTRAINT "organization_invites_token_hash" ` +
			`UNIQUE ("token_hash");`,
		`ALTER TABLE "organization_invite_links" ADD CONSTRAINT "organization_invite_links_code" ` +
			`UNIQUE ("code");`,
	}
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Fatalf("CreateSchema never emitted:\n%s\ngot:\n%s", w, all)
		}
	}

	// Re-running must be safe, so each ALTER is guarded rather than bare.
	for _, sql := range fd.execs {
		if strings.Contains(sql, "ALTER TABLE") && !strings.Contains(sql, "EXCEPTION") {
			t.Fatalf("unguarded ALTER, so CreateSchema is not re-runnable:\n%s", sql)
		}
	}
}

// ── EmailInvite CRUD ─────────────────────────────────────────────────────────

func TestCreateEmailInviteInsertsStampedInvite(t *testing.T) {
	fd := &fakeDriver{}
	st := newInviteStore(fd)

	now := time.Now().UTC()
	in := invite.EmailInvite{
		ID: "inv1", ContainerID: "acme", Email: "bob@example.com",
		RoleKey: "member", TokenHash: "hash1", InvitedBy: "alice",
		ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}
	got, err := st.CreateEmailInvite(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateEmailInvite: %v", err)
	}
	if got != in {
		t.Fatalf("CreateEmailInvite returned %+v, want %+v unchanged", got, in)
	}
	if len(fd.execs) != 1 || !strings.Contains(fd.execs[0], "INSERT") ||
		!strings.Contains(fd.execs[0], `"organization_invites"`) {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

func TestCreateEmailInvitePropagatesUniqueViolation(t *testing.T) {
	// No sentinel in invite.go covers a duplicate (container_id, email); the
	// service is expected to call DeleteEmailInvitesFor first (see
	// DeleteEmailInvitesFor's doc). The store must not swallow or
	// mis-translate the error it does not own.
	st := newInviteStore(&fakeDriver{execErr: pg.ErrUniqueViolation})
	_, err := st.CreateEmailInvite(context.Background(), invite.EmailInvite{ID: "inv1", ContainerID: "acme"})
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("CreateEmailInvite err = %v, want pg.ErrUniqueViolation propagated", err)
	}
}

func TestFindEmailInviteScansRow(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "container_id", "email", "role_key", "token_hash", "invited_by", "expires_at", "created_at"},
		data: [][]any{{"inv1", "acme", "bob@example.com", "member", "hash1", "alice", now, now}},
	}}
	st := newInviteStore(fd)

	got, err := st.FindEmailInvite(context.Background(), "inv1")
	if err != nil {
		t.Fatalf("FindEmailInvite: %v", err)
	}
	if got.ID != "inv1" || got.Email != "bob@example.com" || got.TokenHash != "hash1" || got.InvitedBy != "alice" {
		t.Fatalf("scanned invite = %+v", got)
	}
}

func TestFindEmailInviteNotFound(t *testing.T) {
	st := newInviteStore(&fakeDriver{}) // Query returns empty rows
	if _, err := st.FindEmailInvite(context.Background(), "nope"); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("err = %v, want ErrInviteNotFound", err)
	}
}

func TestFindEmailInviteByTokenHashScansRow(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "container_id", "email", "role_key", "token_hash", "invited_by", "expires_at", "created_at"},
		data: [][]any{{"inv1", "acme", "bob@example.com", "member", "hash-abc", "alice", now, now}},
	}}
	st := newInviteStore(fd)

	got, err := st.FindEmailInviteByTokenHash(context.Background(), "hash-abc")
	if err != nil {
		t.Fatalf("FindEmailInviteByTokenHash: %v", err)
	}
	if got.ID != "inv1" {
		t.Fatalf("FindEmailInviteByTokenHash returned id %q, want inv1", got.ID)
	}
	if !strings.Contains(fd.queries[0], `"organization_invites"."token_hash" =`) {
		t.Fatalf("query does not key on token_hash: %q", fd.queries[0])
	}
}

func TestFindEmailInviteByTokenHashNotFound(t *testing.T) {
	st := newInviteStore(&fakeDriver{})
	if _, err := st.FindEmailInviteByTokenHash(context.Background(), "nope"); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("err = %v, want ErrInviteNotFound", err)
	}
}

func TestListEmailInvitesQueriesByContainer(t *testing.T) {
	st := newInviteStore(&fakeDriver{})
	got, err := st.ListEmailInvites(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListEmailInvites: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d invites from an empty result, want 0", len(got))
	}
}

func TestDeleteEmailInviteAffectsRowsOrNotFound(t *testing.T) {
	st := newInviteStore(&fakeDriver{affected: 0})
	if err := st.DeleteEmailInvite(context.Background(), "inv1"); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("err = %v, want ErrInviteNotFound", err)
	}

	fd := &fakeDriver{affected: 1}
	st = newInviteStore(fd)
	if err := st.DeleteEmailInvite(context.Background(), "inv1"); err != nil {
		t.Fatalf("DeleteEmailInvite: %v", err)
	}
	if !strings.Contains(fd.execs[0], "DELETE") || !strings.Contains(fd.execs[0], `"organization_invites"`) {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

// Deleting zero rows must not be an error — see the method's doc.
func TestDeleteEmailInvitesForZeroMatchesIsNotError(t *testing.T) {
	fd := &fakeDriver{affected: 0}
	st := newInviteStore(fd)
	if err := st.DeleteEmailInvitesFor(context.Background(), "acme", "nobody@example.com"); err != nil {
		t.Fatalf("DeleteEmailInvitesFor: %v", err)
	}
	if !strings.Contains(fd.execs[0], `"organization_invites"."container_id" =`) ||
		!strings.Contains(fd.execs[0], `"organization_invites"."email" =`) {
		t.Fatalf("DELETE does not key on both container_id and email: %q", fd.execs[0])
	}
}

// ── Link CRUD ────────────────────────────────────────────────────────────────

func TestCreateLinkInsertsStampedLink(t *testing.T) {
	fd := &fakeDriver{}
	st := newInviteStore(fd)

	now := time.Now().UTC()
	l := invite.Link{
		ID: "link1", ContainerID: "acme", Code: "code-abc", RoleKey: "member",
		CreatedBy: "alice", MaxUses: 5, CreatedAt: now,
	}
	got, err := st.CreateLink(context.Background(), l)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if got != l {
		t.Fatalf("CreateLink returned %+v, want %+v unchanged", got, l)
	}
	if len(fd.execs) != 1 || !strings.Contains(fd.execs[0], "INSERT") ||
		!strings.Contains(fd.execs[0], `"organization_invite_links"`) {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

// Round-trips a link whose nullable columns are both present (ExpiresAt) and
// absent (RevokedAt nil), proving the store's read path — not just the bind
// path Task 1 already covers — handles a *time.Time column correctly.
func TestFindLinkScansRowWithNullableColumns(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "container_id", "code", "role_key", "created_by",
			"max_uses", "use_count", "expires_at", "revoked_at", "created_at"},
		data: [][]any{{"link1", "acme", "code-abc", "member", "alice",
			5, 2, &future, (*time.Time)(nil), now}},
	}}
	st := newInviteStore(fd)

	got, err := st.FindLink(context.Background(), "link1")
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.MaxUses != 5 || got.UseCount != 2 {
		t.Fatalf("scanned link = %+v, want MaxUses 5 UseCount 2", got)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(future) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, future)
	}
	if got.RevokedAt != nil {
		t.Fatalf("RevokedAt = %v, want nil", got.RevokedAt)
	}
}

func TestFindLinkNotFound(t *testing.T) {
	st := newInviteStore(&fakeDriver{})
	if _, err := st.FindLink(context.Background(), "nope"); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("err = %v, want ErrLinkNotFound", err)
	}
}

func TestFindLinkByCodeScansRow(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "container_id", "code", "role_key", "created_by",
			"max_uses", "use_count", "expires_at", "revoked_at", "created_at"},
		data: [][]any{{"link1", "acme", "code-abc", "member", "alice",
			5, 0, (*time.Time)(nil), (*time.Time)(nil), now}},
	}}
	st := newInviteStore(fd)

	got, err := st.FindLinkByCode(context.Background(), "code-abc")
	if err != nil {
		t.Fatalf("FindLinkByCode: %v", err)
	}
	if got.ID != "link1" {
		t.Fatalf("FindLinkByCode returned id %q, want link1", got.ID)
	}
	if !strings.Contains(fd.queries[0], `"organization_invite_links"."code" =`) {
		t.Fatalf("query does not key on code: %q", fd.queries[0])
	}
}

func TestFindLinkByCodeNotFound(t *testing.T) {
	st := newInviteStore(&fakeDriver{})
	if _, err := st.FindLinkByCode(context.Background(), "nope"); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("err = %v, want ErrLinkNotFound", err)
	}
}

func TestListLinksQueriesByContainer(t *testing.T) {
	st := newInviteStore(&fakeDriver{})
	got, err := st.ListLinks(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d links from an empty result, want 0", len(got))
	}
}

func TestRevokeLinkAffectsRowsOrNotFound(t *testing.T) {
	st := newInviteStore(&fakeDriver{affected: 0})
	if err := st.RevokeLink(context.Background(), "link1", time.Now()); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("err = %v, want ErrLinkNotFound", err)
	}

	fd := &fakeDriver{affected: 1}
	st = newInviteStore(fd)
	if err := st.RevokeLink(context.Background(), "link1", time.Now()); err != nil {
		t.Fatalf("RevokeLink: %v", err)
	}
	if !strings.Contains(fd.execs[0], `SET "revoked_at" =`) {
		t.Fatalf("UPDATE does not set revoked_at: %q", fd.execs[0])
	}
}

// ── ConsumeLink: the centre of this task ────────────────────────────────────

// consumeLinkExecSQL runs a successful ConsumeLink and returns the single SQL
// statement it issued, for the SQL-shape assertions below. Using affected:1
// keeps every one of these tests on the one-UPDATE happy path, independent of
// the zero-rows classification path exercised separately further down.
func consumeLinkExecSQL(t *testing.T) string {
	t.Helper()
	fd := &fakeDriver{affected: 1}
	st := newInviteStore(fd)
	ok, err := st.ConsumeLink(context.Background(), "link1", time.Now().UTC())
	if err != nil {
		t.Fatalf("ConsumeLink: %v", err)
	}
	if !ok {
		t.Fatal("ConsumeLink ok = false, want true when rows-affected > 0")
	}
	if len(fd.execs) != 1 {
		t.Fatalf("ConsumeLink issued %d execs, want exactly 1 (a single UPDATE)", len(fd.execs))
	}
	return fd.execs[0]
}

func TestConsumeLinkIsASingleUpdateOnTheLinksTable(t *testing.T) {
	sql := consumeLinkExecSQL(t)
	if !strings.HasPrefix(sql, `UPDATE "organization_invite_links"`) {
		t.Fatalf("exec does not open with UPDATE on the links table: %q", sql)
	}
	if !strings.Contains(sql, `"organization_invite_links"."id" = $`) {
		t.Fatalf("UPDATE does not target id: %q", sql)
	}
}

func TestConsumeLinkIncrementsUseCountByOne(t *testing.T) {
	sql := consumeLinkExecSQL(t)
	if !strings.Contains(sql, `SET "use_count" = (`) {
		t.Fatalf("UPDATE does not SET use_count via an expression: %q", sql)
	}
	if !strings.Contains(sql, `"use_count" + $`) {
		t.Fatalf("UPDATE does not increment use_count by a bound value: %q", sql)
	}
}

// A regression that drops this clause (e.g. "simplifying" the WHERE to just
// id = $1) would let ConsumeLink admit a revoked link.
func TestConsumeLinkGuardsOnRevokedAtIsNull(t *testing.T) {
	sql := consumeLinkExecSQL(t)
	if !strings.Contains(sql, `"revoked_at" IS NULL`) {
		t.Fatalf("UPDATE does not guard on revoked_at IS NULL: %q", sql)
	}
}

// A regression that drops this clause would let ConsumeLink admit an expired
// link. Both halves of the OR are checked independently so a half-dropped
// clause (e.g. losing just the "never expires" escape) still fails here.
func TestConsumeLinkGuardsOnTheExpiresAtWindow(t *testing.T) {
	sql := consumeLinkExecSQL(t)
	if !strings.Contains(sql, `"expires_at" IS NULL`) {
		t.Fatalf("UPDATE does not admit a never-expiring link (expires_at IS NULL): %q", sql)
	}
	if !strings.Contains(sql, `"expires_at" > $`) {
		t.Fatalf("UPDATE does not guard expires_at against now: %q", sql)
	}
}

// A regression that drops this clause would let ConsumeLink overshoot
// MaxUses under concurrency — the exact bug this task exists to prevent.
// Both halves of the OR are checked independently.
func TestConsumeLinkGuardsOnTheMaxUsesWindow(t *testing.T) {
	sql := consumeLinkExecSQL(t)
	if !strings.Contains(sql, `"max_uses" = $`) {
		t.Fatalf("UPDATE does not admit an unlimited (max_uses = 0) link: %q", sql)
	}
	if !strings.Contains(sql, `"use_count" < "organization_invite_links"."max_uses"`) {
		t.Fatalf("UPDATE does not guard use_count against max_uses: %q", sql)
	}
}

func TestConsumeLinkOkFalseWhenBlockedButFound(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{affected: 0, rows: &fakeRows{
		cols: []string{"id", "container_id", "code", "role_key", "created_by",
			"max_uses", "use_count", "expires_at", "revoked_at", "created_at"},
		data: [][]any{{"link1", "acme", "code-abc", "member", "alice",
			1, 1, (*time.Time)(nil), (*time.Time)(nil), now}},
	}}
	st := newInviteStore(fd)

	ok, err := st.ConsumeLink(context.Background(), "link1", now)
	if err != nil {
		t.Fatalf("ConsumeLink err = %v, want nil (link exists but is blocked)", err)
	}
	if ok {
		t.Fatal("ConsumeLink ok = true when the UPDATE affected zero rows")
	}
	if len(fd.execs) != 1 {
		t.Fatalf("issued %d execs, want 1 (the UPDATE)", len(fd.execs))
	}
	if len(fd.queries) != 1 {
		t.Fatalf("issued %d queries, want 1 (the classifying re-read)", len(fd.queries))
	}
}

func TestConsumeLinkNotFoundWhenNoRowsAtAll(t *testing.T) {
	fd := &fakeDriver{affected: 0} // Query returns empty rows -> FindLink -> ErrNoRows
	st := newInviteStore(fd)

	ok, err := st.ConsumeLink(context.Background(), "nonesuch", time.Now().UTC())
	if ok {
		t.Fatal("ConsumeLink ok = true for a nonexistent link")
	}
	if !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("ConsumeLink err = %v, want ErrLinkNotFound", err)
	}
}

func TestConsumeLinkPropagatesExecError(t *testing.T) {
	sentinel := errors.New("boom")
	st := newInviteStore(&fakeDriver{execErr: sentinel})
	ok, err := st.ConsumeLink(context.Background(), "link1", time.Now())
	if ok {
		t.Fatal("ConsumeLink ok = true despite an Exec error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the sentinel propagated", err)
	}
}

// ── PurgeExpired ─────────────────────────────────────────────────────────────

func TestPurgeExpiredIssuesScopedDeletesOnBothTables(t *testing.T) {
	fd := &fakeDriver{affected: 3}
	st := newInviteStore(fd)

	n, err := st.PurgeExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 6 { // 3 from each DELETE
		t.Fatalf("PurgeExpired = %d, want 6 (3 email invites + 3 links)", n)
	}
	if len(fd.execs) != 2 {
		t.Fatalf("PurgeExpired issued %d execs, want 2 (one DELETE per table)", len(fd.execs))
	}
	if !strings.Contains(fd.execs[0], `"organization_invites"`) || !strings.Contains(fd.execs[0], `"expires_at" <`) {
		t.Fatalf("email-invite DELETE unexpected: %q", fd.execs[0])
	}
	if !strings.Contains(fd.execs[1], `"organization_invite_links"`) ||
		!strings.Contains(fd.execs[1], `"expires_at" IS NOT NULL`) ||
		!strings.Contains(fd.execs[1], `"expires_at" <`) {
		t.Fatalf("link DELETE unexpected (must also require expires_at IS NOT NULL, so a nil ExpiresAt is never purged): %q", fd.execs[1])
	}
}
