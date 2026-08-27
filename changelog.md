# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once a 1.0 is cut. Until then, minor versions may break API.

## [Unreleased]

### Added

- **Per-action query guards** (`authlayer/scope`) — `Service.PermissionGuard`
  restricts a table's rows to the containers where the subject holds a specific
  `(resource, action)` grant, rather than to those they merely belong to. The
  container set is resolved through the same ladder `Can` uses, so a guard and
  an in-memory check agree for every container where the subject holds a
  membership whose role key resolves, and every known divergence denies rather
  than leaks. An empty set renders as a false predicate, a missing subject is
  `pg.ErrSubjectMissing`, a nil column is an error rather than a panic, and a
  store failure aborts the query instead of narrowing it to nothing.
- **`Service.ContainersWith`** (`authlayer/scope`) — the same answer as a plain
  `[]string`, exported so a hot path can hoist the id set out of the guard. A
  membership whose role key resolves to nothing denies its own container only,
  not the whole call. Like `HasPermission` it takes the user id as an argument
  and checks nothing about the caller, so do not expose it directly to end
  users.
- **`MemberStanding`** (`authlayer/scope`, re-exported as `org.MemberStanding`)
  — a flattened container/role/owner row, fetched by the drops store in a
  single join.
- **UUIDv7 identifiers** (`authlayer/internal/uid`) — a dependency-free RFC 9562
  generator, now the default for containers and custom roles. Time-ordered, so
  ids sort in creation order and a primary-key index stays dense.
  `WithIDGenerator` still overrides it.
- **Generic PostgreSQL store** (`authlayer/store/drops`) — `Store[C, M]` derives
  its columns from the `drop:` tags of the container and member types and takes
  its table names from `WithNames`, so a new scope instance needs no new store.
  `WithTextUserIDs` keeps the user-id columns — `user_id`, `owner_id`,
  `invited_by`, `created_by` — as `text` for consumers using only the RBAC half
  against a non-UUID user table. The ids authlayer mints for itself (`id`,
  `container_id`, `parent_id`) stay `uuid` either way. A container or member
  type missing a required `drop:` tag, or carrying an unsupported field type, is
  now rejected at construction with the type and the tag named, rather than
  nil-dereferencing at the first query.
- **Nested scopes** (`authlayer/scope`) — a container can now sit inside
  another (a team inside an organization, a project inside a team) via
  `WithParent(parent, inherit)` and `WithContainerResource(resource)`. The
  container type embeds the new `NestedBase` (adds the parent link on top of
  `ContainerBase`) and satisfies the new `Nested` interface; `ParentScope` is
  the narrow view a child needs of its parent — `*Service` satisfies it
  through the newly exported `Service.Standing`. An `Inheritance` function
  projects a subject's parent standing onto the child as grant *names*,
  recompiled against the child's own `Access` — never as bits, since a
  `Permission` is a bitset over one `Statements` space and a parent's bits
  mean nothing in a child's. `InheritElevation` (the default when `WithParent`
  is given no projection) confers standing on nobody but the truly elevated —
  the owner alone, under a default role set, since the built-in `admin` role
  is deliberately kept short of full permission; `InheritWhen` builds a
  projection conferring elevation on anyone whose parent standing grants a
  named capability, for "whoever may manage teams administers each team." `New`
  panics when `WithParent` is given a container type that does not embed
  `NestedBase` — the same construction-time-bug treatment
  `access.Access.NewRole` gives a mis-declared default role. **Nesting also
  changes `Service.CreateContainer`: on a parented scope it now performs a
  permission check against the parent (`<containerResource>:create`, or
  elevated parent standing) before creating anything, where the unparented
  form performs no check at all** — a caller wiring `WithParent` for the first
  time should expect this.
- **`Service.Standing`** (`authlayer/scope`) — exported: the same resolution
  `Can` performs (a subject's permissions in a container, and whether they are
  elevated there), reading nothing from the context and checking nothing about
  the caller, like `HasPermission`. Exists so a nested scope's parent can be
  asked through `ParentScope`; do not expose it directly to end users.
- **`Policy.MembersFromParent`** (`authlayer/scope`) — on by default; in a
  nested scope, refuses `AddMember` with the new `ErrNotParentMember` when the
  target holds no standing in the parent — you cannot be on a team without
  being in the organization that owns it. Effective only where `WithParent` is
  configured; the owner membership `CreateContainer` seeds is not checked
  separately, since creating a container in a parent already requires standing
  there.
- **`access.Access.Union`** — combines several permissions into the set
  granting every pair any of them grants. A permission from a foreign
  `Statements` is rejected rather than silently misread; the zero Permission is
  accepted and contributes nothing. Backs nested scopes, where a member's own
  role permissions merge with the grants projected from their parent standing.
- **`access.Permission.IsZero`** — reports whether a permission grants nothing
  at all, the counterpart to `IsFull`. Needed because a projection can return a
  non-empty grant map that still confers nothing
  (`map[string][]access.Action{"doc": nil}` validates and compiles) — "the map
  is non-empty" and "something was actually granted" are different questions,
  and standing resolution in a nested scope needs the second one.
- **`team`** (`authlayer/team`) — a nested "team" instance of the engine, teams
  living inside organizations. Mirrors `org`'s shape: `Team` / `Member`
  (embedding `NestedBase` / `MemberBase`), `NewAccess`, `New` (wires
  `WithParent`/`WithContainerResource` itself so a caller cannot forget
  either), `CreateTeam`, `WithTeam`/`TeamFrom`, and team-flavoured error
  aliases including `ErrNotParentMember`. `ParentStatements` names what the
  parent organization's `Access` must declare (`team:create`) for anyone but
  the org owner to create a team — merge it into `org.NewAccess`'s statements.
- **`invite`** (`authlayer/invite`) — a new package admitting a person who has
  no standing in a scope yet, by a credential rather than a direct
  `AddMember` call. `InviteByEmail` mints a one-time **bearer** token — it
  pays out at most once, but to whoever presents it: acceptance never compares
  the accepting subject to `EmailInvite.Email`, which is a delivery hint and
  an audit record, since authlayer stores no users and has no notion of a
  subject's verified address. Bind an invitation to its recipient in your own
  application if you need that, using `PreviewInvite` to read the invited
  address without consuming the token. Only the token's sha256 is persisted
  (`EmailInvite.TokenHash`), since the token is
  emailed once and never redisplayed to anyone, including the inviter — a
  database leak of the row cannot be replayed into admission. `CreateLink`
  mints a reusable link bounded by an explicit `MaxUses` (0 meaning
  unlimited) and `ExpiresAt` (nil meaning never); `Link.Code` is stored in
  clear, because a link's whole purpose is to be re-displayed on a "manage
  invite links" screen and a hash would make that impossible — a link's
  security instead comes from `MaxUses`, `ExpiresAt` and revocation, weighed
  atomically by `Store.ConsumeLink`. `AcceptInvite` and `JoinViaLink` redeem
  a credential and call the new `scope.Service.GrantMembership` (see below)
  to admit: both claim the credential atomically FIRST — `AcceptInvite` via
  the rows-affected-gated `Store.DeleteEmailInvite`, `JoinViaLink` via the
  atomic `Store.ConsumeLink` — and admit SECOND, so a failure after the claim
  burns the credential and admits no one (under-admission) rather than
  risking a credential paying out twice (over-admission); accepting is
  therefore not safe to retry with the same token. On a **nested** scope that
  matters more than it sounds: under the default `Policy.MembersFromParent`,
  `GrantMembership` returns `scope.ErrNotParentMember` for an invitee who does
  not already hold standing in the parent, deterministically — so a team
  invitation sent to someone not yet in the organization burns itself every
  time. Admit people to the parent first, or clear `MembersFromParent` for
  that scope. Delivery is entirely the
  caller's own responsibility: `InviteByEmail` returns the plain token
  exactly once, and authlayer knows no base URL and owns no transport;
  `WithNotifier` is optional sugar over calling a `Notifier` yourself right
  after. `ListLinks` keeps a link's `Code` in the result only when the caller
  holds `invite:create` — the same permission `CreateLink` requires, so a
  reader granted `invite:read` alone sees no code at all — AND is elevated or
  the link's role resolves to a permission set that is a `SubsetOf` their own
  current standing; everything else is blanked. Both halves are load-bearing,
  not cosmetic. The standing half exists because `invite:read` sits on the
  merged control-statement surface and so is granted to the built-in `admin`
  automatically (see the next entry), and `admin` is deliberately not
  `IsFull`; without it a non-elevated admin could read the owner's link code
  in clear, leave the container, and rejoin at the owner role through
  `JoinViaLink`, since `GrantMembership` runs no escalation check of its own.
  The capability half exists because a reader with `invite:read` and no
  `invite:create` could not have minted *any* link, so handing them a working
  code would make read imply admit and let them admit arbitrary third
  parties. `WithRecheckInviterOnAccept` (default
  `true`) re-runs the privilege-escalation guard against the inviter's
  CURRENT standing before `AcceptInvite`/`JoinViaLink` admit anyone, so a
  since-demoted or since-departed inviter's pending invitation stops paying
  out, at the cost that a pending invitation dies when its inviter leaves the
  container. `PurgeExpired` deletes every expired invite and link across
  every container the `Store` holds, for a cron; it performs no
  authorization and reads neither a subject nor a container from the
  context. `CreateLink` refuses a negative `maxUses` with
  `ErrInvalidMaxUses` rather than minting a link that can never be redeemed
  (0 still means unlimited). Seven new sentinel errors:
  `ErrInviteNotFound`, `ErrInviteExpired`, `ErrLinkNotFound`,
  `ErrLinkRevoked`, `ErrLinkExpired`, `ErrLinkExhausted`,
  `ErrInvalidMaxUses`.
  `store/memory` and `store/drops` each ship a reference `invite.Store`
  implementation, the latter with its own `CreateSchema`.
- **`scope.Service.GrantMembership`** (`authlayer/scope`) — admits a user to a
  container at a role, performing NO check that any actor is entitled to do
  so: no `member:create`, no privilege-escalation guard. It exists for
  invitation acceptance, where the person being admitted has no standing to
  check and the inviter is not present to have one — every actor-facing rule
  was already applied when the credential was minted. **This is a
  deliberately unchecked admission path**: it is only as safe as whatever
  decided to call it, must never be exposed to end users, and must never be
  reachable from a path a principal could reach without holding a credential
  minted for exactly this container and role — `invite.Service.ListLinks`'s
  redaction is what makes that true there, and anything else calling this
  owes the same care. Rules that are not about the actor still apply: a
  duplicate is `ErrAlreadyMember`, an unresolvable role is `ErrRoleNotFound`,
  and under `Policy.MembersFromParent` the user must already hold standing in
  the parent scope. It emits `MemberAdded`, so that event now has two sources
  rather than one — and on this path `Event.ActorID` is the **admitted** user,
  equal to `TargetID`, since the call reads no ctx subject and there is no
  actor to name (the inviter authorized it at mint time and is not present).
  An audit hook therefore cannot distinguish an invitation-based admission
  from a self-add on the event alone, and the invitation's `InvitedBy` never
  reaches the hook; record that attribution when the invitation is minted if
  you need it.
- **`invite` control statements** (`authlayer/scope`) — `ControlStatements`
  and `NewAccess` now declare the `invite` resource (`create`, `read`,
  `delete`) on every scope's merged permission surface, for the `invite`
  package's own mint/list/revoke checks; the engine itself checks none of
  it. **This widens the built-in `admin` role automatically**: `admin` is
  defined as "every declared pair except `<container>:delete`", so every
  `admin` — new and previously seeded — gains `invite:create`, `invite:read`
  and `invite:delete` the moment this version is adopted, with no code
  change required. An application that treats `admin`'s current grant set as
  fixed should account for that before upgrading.
- **`scope.Service.RolePermissions`** and **`scope.Service.Container`**
  (`authlayer/scope`) — two new exported primitives, added so `invite` (or
  any other package built on `scope`) can ask the engine's own questions
  instead of reconstructing an approximation of them. `RolePermissions`
  resolves a role key to its permission set exactly the way every
  permission check in the engine does — a code-defined role first, then a
  custom role loaded from the store — and answers a strictly larger question
  than `ListRoles`: `ListRoles` enumerates only the three hardcoded defaults
  plus a container's *stored* custom roles, so a code-defined role
  registered directly with `access.Access.NewRole` resolves through
  `RolePermissions` but is invisible to `ListRoles`, and approximating the
  former from the latter would silently treat such a role as nonexistent.
  `Container` loads a container by id, returning the whole record — it
  exists because `GrantMembership` returns only the new membership, not the
  container the invitee was just admitted to, and invitation acceptance
  needs to hand one back. Like `Standing` and `HasPermission`, neither reads
  anything from the context nor checks that the caller is entitled to ask —
  do not expose either directly to end users.

### Changed

- **BREAKING (grants): every `admin` silently gains `invite:*` on adoption.**
  `ControlStatements` now declares the `invite` resource, and the built-in
  `admin` role is derived from the merged surface as "every declared pair
  except `<container>:delete`" — so every `admin`, new and previously seeded,
  holds `invite:create`, `invite:read` and `invite:delete` the moment this
  version is adopted, with no code change and no migration to notice. Nothing
  in a running deployment announces it. An application that treats `admin`'s
  grant set as fixed should account for it before upgrading; define a custom
  role if `admin` must not mint invitations. Listed in full under **Added**
  (`invite` control statements), and repeated here because the widening lands
  on existing installations rather than only on new ones.
- **BREAKING (Store port): two new methods.** `ContainerStore` gains
  `ListUserContainers` and `MemberStore` gains `ListUserStandings`. Both ship
  implemented in `store/memory` and `store/drops`; a third-party Store must add
  them. `ListUserStandings` should be one join, not a query per container — it
  runs on every guarded query.
- **BREAKING (schema): id columns are now `uuid`.** Every id authlayer
  generates is a UUIDv7 and its column is typed `uuid` rather than `text`.
  `CreateSchema` on a fresh database needs nothing; on an existing one the old
  ids are 24 hex characters, too short for the 32 hex digits `uuid` requires,
  so widen before casting rather than casting directly — `ALTER TABLE <t>
  ALTER COLUMN <col> TYPE uuid USING lpad(<col>, 32, '0')::uuid` — and apply
  that to every column holding or referencing an id, not just the primary
  keys: `organization_members.container_id` and
  `organization_roles.container_id` need the same widen-and-cast, combined
  with the rename below rather than as a separate migration. The columns
  holding a user id are `uuid` by default too — `organizations.owner_id` as
  much as `organization_members.user_id`, since authlayer generates user ids
  as well; a non-UUID user table should pass `dropsstore.WithTextUserIDs()`
  instead of rewriting them.
- **BREAKING (schema): the membership and role container column is now
  `container_id`.** It follows `scope.MemberBase`'s own `drop:` tag; the
  hand-written schema previously called it `organization_id`. Migrate with
  `ALTER TABLE organization_members RENAME COLUMN organization_id TO
  container_id` and likewise for `organization_roles`.
- **BREAKING (schema): the roles UNIQUE constraint is renamed.** Its name is now
  derived from the roles table name, so `organization_roles_org_key` becomes
  `organization_roles_container_key` — and a second scope instance gets
  `<its_roles_table>_container_key` rather than colliding on the organization
  one. Immaterial if you let `CreateSchema` build the tables; if you own them,
  `ALTER TABLE organization_roles RENAME CONSTRAINT organization_roles_org_key
  TO organization_roles_container_key`.
- **BREAKING (API): `dropsstore.New` takes type parameters.**
  `dropsstore.New(db)` becomes
  `dropsstore.New[org.Organization, org.Member](db)`. `dropsstore.NewSchema`
  likewise. `Schema.Organizations` is now `Schema.Containers`.

### Fixed

- **`Can`/`Authorize` now deny zero actions even for an elevated actor.**
  `authorize()` only checked `Allows()` when the actor was not elevated, so
  `Can(ctx, resource)` called with no actions returned `true` for an owner, or
  for any role whose permissions were full — contradicting the readme's own
  "Zero actions denies — there is nothing to authorize" and disagreeing with
  `ContainersWith`, which already denied this case unconditionally. Zero
  actions is now denied before the elevated short-circuit runs, so `Can`
  returns `false` and `Authorize` returns `ErrForbidden` for an elevated actor
  too. This aligns `Can`/`Authorize` with the documented rule and with
  `access.Permission.Allows`, which has always treated zero actions the same
  way. A caller that relied on the old pass-through — asking an elevated actor
  "may you touch this resource at all?" via a zero-action call — now gets a
  denial, and must name at least one action.
- **`CreateSchema` now emits the composite constraints it declares.** drops'
  `CreateTableIfNotExists` writes column definitions only, so the members
  `PRIMARY KEY (container_id, user_id)` and the roles
  `UNIQUE (container_id, key)` lived in the in-memory table registry and never
  reached the database. Since the engine relies on the database to enforce both
  — it does not pre-check — a second `AddMember` inserted a duplicate row and
  returned `nil` instead of `ErrAlreadyMember`, and two custom roles could share
  a `(container, key)` with different permission sets. `CreateSchema` now
  follows each `CREATE TABLE` with idempotent `ALTER TABLE ... ADD CONSTRAINT`
  statements, so it stays safe to re-run. Databases created by an earlier
  version need the constraints added by hand — re-running `CreateSchema` does
  it, once any duplicate rows are cleared.

## [0.0.1] - 2026-07-25

Initial release. Milestone 1: scope RBAC — code-defined permission statements,
hybrid default + custom roles, permission checks, a privilege-escalation guard,
lifecycle hooks, and query-level guards. Authentication (credentials, sessions,
OAuth) is not part of this release.

### Added

- **Access-control engine** (`authlayer/access`) — the standard-library-only
  core. `Statements` compiles a `resource → actions` surface into stable bit
  indices; `Permission` is an immutable bitset over it with `Allows` (AND across
  actions), `IsFull`, and `SubsetOf`; `Access` binds statements to a registry of
  named `Role` values and builds permissions from grant maps. Undeclared grants
  fail closed and fail loudly — `NewRole` panics (a mis-declared code-defined
  role is a startup bug) while `Permission` returns an error (runtime and
  DB-sourced grants are validated, not trusted).
- **Name-based permission encoding** (`authlayer/access`) — `Permission.Encode`
  serialises grants as newline-separated `resource:action` tokens and
  `Access.Decode` re-resolves them against the statements in force at decode
  time. Adding, removing, or reordering resources therefore never
  re-interprets a permission persisted earlier: a deleted capability is dropped
  from stored roles and everything else keeps its meaning. A token without a
  `:` separator is treated as corruption and errors.
- **Generic scope engine** (`authlayer/scope`) — `Service[C, M]` over a
  caller-supplied container and member type. Embed `ContainerBase` /
  `MemberBase` to inherit the identity and audit fields the engine stamps and
  reads, and add your own columns alongside. A scope is any authorization
  boundary — an organization, a team, a project — with an owner and members
  holding exactly one role each.
- **Permission checks** (`authlayer/scope`) — `Authorize` (sentinel errors, so a
  handler can distinguish denied from not-a-member from no-such-container),
  `Can` (boolean; folds `ErrForbidden` and `ErrNotMember` into `false` while
  still surfacing real failures), and `HasPermission` (out-of-band, asking about
  a user who is not the context subject). Standing resolves per call with no
  caching, so a permission change takes effect immediately.
- **Hybrid roles** (`authlayer/scope`) — the `owner`, `admin` and `member`
  defaults are defined in code, derived from the merged statement surface (so
  they grow with the application's resources), reserved, and immutable at
  runtime. On top of them each container defines its own **custom roles** via
  `CreateRole` / `UpdateRole` / `DeleteRole` / `ListRoles`, persisted as encoded
  grants and invisible to every other container. `DeleteRole` refuses a role
  that still has members rather than cascading.
- **Membership management** (`authlayer/scope`) — `CreateContainer` (stamps base
  fields and seeds the owner's membership in one transaction), `AddMember`,
  `ChangeMemberRole`, `RemoveMember`, `LeaveContainer`, `ListMembers`, and
  `TransferOwnership` (owner-only; the recipient must already be a member).
- **Privilege-escalation guard** (`authlayer/scope`) — an actor may not grant a
  role exceeding their own permissions, mint or update a custom role with powers
  they lack, or remove a member more powerful than themselves. Implemented as
  `Permission.SubsetOf`; elevated actors are exempt. Reported as
  `ErrPrivilegeEscalation`.
- **Configurable policy** (`authlayer/scope`) — `Policy` bundles `Escalation`
  (`EscalationStrict` / `EscalationAllowEqual` / `EscalationOff`),
  `LastOwnerLocked` (the owner cannot be removed, demoted, or leave), and
  `OwnerBypass` (the owner holds full permissions regardless of their role key,
  so a mis-configured container stays recoverable). All three default on.
- **Lifecycle hooks** (`authlayer/scope`) — `Hook` / `HookFunc` observe eight
  `Event` kinds (`ContainerCreated`, `MemberAdded`, `MemberRoleChanged`,
  `MemberRemoved`, `RoleCreated`, `RoleUpdated`, `RoleDeleted`,
  `OwnershipTransferred`) for audit, webhooks, cache invalidation, or a
  transactional outbox. A hook returning an error aborts the operation, and for
  `CreateContainer` rolls the whole transaction back.
- **Context-carried subject and scope** (`authlayer/scope`) — `WithSubject` /
  `WithScope` and their accessors, built on drops' own `pg.WithSubject` /
  `pg.WithTenant` keys so one context drives both the in-memory decision and
  drops' query guards. A missing subject or scope is an error, never a silent
  allow.
- **Query-level filtering** (`authlayer/scope`) — `MembershipGuard` returns a
  drops `pg.Guard` that restricts a table's rows to the context subject's
  containers, mounted with `entity.AuthorizeWith`. Coarse, membership-level
  filtering; a missing subject fails closed.
- **Service options** (`authlayer/scope`) — `WithPolicy`, `WithHooks`
  (accumulating), `WithClock` (deterministic tests), and `WithIDGenerator`
  (swap the default 24-hex-char `crypto/rand` id for UUIDv7, ULIDs, or whatever
  the schema expects).
- **Store port** (`authlayer/scope`) — `Store[C, M]`, composed from
  `ContainerStore`, `MemberStore` and `RoleStore` so a backend or decorator can
  override a slice of it, plus `WithTx`. Stores are pure persistence: they
  authorize nothing and never interpret permission bytes, but owe the engine the
  documented sentinel error on each lookup miss.
- **Organization RBAC** (`authlayer/org`) — the ready-made instance of the
  engine with the container fixed to `Organization` (name + unique slug) and the
  member to `Member`, so callers get organization RBAC without writing a type
  parameter. Adds `CreateOrganization` and `WithOrg`, and re-exports the scope
  types, options, and errors under organization-flavoured names as aliases —
  `org.ErrOrgNotFound` *is* `scope.ErrContainerNotFound`.
- **In-memory store** (`authlayer/store/memory`) — a concurrency-safe, generic,
  zero-dependency `Store` for development, tests, and examples, and the
  reference implementation of the contract. `WithTx` approximates a transaction
  by snapshot-and-restore under a mutex.
- **PostgreSQL store** (`authlayer/store/drops`) — a drops-backed `org.Store`
  over three tables (`organizations`, `organization_members` with a composite
  `(organization_id, user_id)` primary key, and `organization_roles`). Unique
  constraints are load-bearing: they turn concurrent double-inserts into
  `ErrSlugTaken` / `ErrAlreadyMember` / `ErrRoleKeyTaken`. `CreateSchema` is a
  dev/test convenience (create-only, never alter); `Schema` exposes the tables
  for migrations and guards, and `MembershipGuard` fills in the junction for
  you. Real transactions via `WithTx`. No foreign key to a users table is
  declared — authlayer does not own one.
- **Sentinel errors** (`authlayer/scope`) — fourteen documented sentinels
  comparable with `errors.Is`, grouped for HTTP mapping: not-found, denied,
  conflict/invariant, and caller-bug.
- **Runnable example** (`examples/basic`) — a database-free tour of statements,
  default and custom roles, permission checks, and the escalation guard:
  `go run ./examples/basic`.
- **Integration test** (`store/drops`) — a live end-to-end test behind the
  `integration` build tag, so the default `go test ./...` stays database-free:
  `AUTHLAYER_TEST_DSN='postgres://…' go test -tags integration ./store/drops/`.
- **Documentation** — a doc comment on every exported symbol, package-level
  overviews for each package, and a `readme.md` documenting the full feature
  surface.

### Dependencies

- `github.com/bernardoforcillo/drops` v0.5.0
- `github.com/jackc/pgx/v5` v5.10.0 (PostgreSQL store only)
- Go 1.26+

[Unreleased]: https://github.com/bernardoforcillo/authlayer/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/bernardoforcillo/authlayer/releases/tag/v0.0.1
