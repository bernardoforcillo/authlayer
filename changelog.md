# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once a 1.0 is cut. Until then, minor versions may break API.

## [Unreleased]

### Added

- **UUIDv7 identifiers** (`authlayer/internal/uid`) — a dependency-free RFC 9562
  generator, now the default for containers and custom roles. Time-ordered, so
  ids sort in creation order and a primary-key index stays dense.
  `WithIDGenerator` still overrides it.
- **Generic PostgreSQL store** (`authlayer/store/drops`) — `Store[C, M]` derives
  its columns from the `drop:` tags of the container and member types and takes
  its table names from `WithNames`, so a new scope instance needs no new store.
  `WithTextUserIDs` keeps `user_id` columns as `text` for consumers using only
  the RBAC half against a non-UUID user table.

### Changed

- **BREAKING (schema): id columns are now `uuid`.** Every id authlayer
  generates is a UUIDv7 and its column is typed `uuid` rather than `text`.
  `CreateSchema` on a fresh database needs nothing; on an existing one the old
  ids are 24 hex characters, too short for the 32 hex digits `uuid` requires,
  so widen before casting rather than casting directly — `ALTER TABLE <t>
  ALTER COLUMN <col> TYPE uuid USING lpad(<col>, 32, '0')::uuid` — and apply
  that to every column holding or referencing an id, not just the primary
  keys: `organization_members.container_id` and
  `organization_roles.container_id` need the same widen-and-cast, combined
  with the rename below rather than as a separate migration. `user_id`
  columns are `uuid` by default too; a non-UUID user table should pass
  `dropsstore.WithTextUserIDs()` instead of rewriting them.
- **BREAKING (schema): the membership and role container column is now
  `container_id`.** It follows `scope.MemberBase`'s own `drop:` tag; the
  hand-written schema previously called it `organization_id`. Migrate with
  `ALTER TABLE organization_members RENAME COLUMN organization_id TO
  container_id` and likewise for `organization_roles`.
- **BREAKING (API): `dropsstore.New` takes type parameters.**
  `dropsstore.New(db)` becomes
  `dropsstore.New[org.Organization, org.Member](db)`. `dropsstore.NewSchema`
  likewise. `Schema.Organizations` is now `Schema.Containers`.

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
