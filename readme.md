# authlayer

Reusable authentication & authorization for Go, built on
[`drops`](https://github.com/bernardoforcillo/drops) — so you stop rewriting the
same authz logic in every project.

> **Status: early.** Milestone 1 ships **scope RBAC**: code-defined permission
> statements, hybrid default + custom roles, permission checks, a
> privilege-escalation guard, lifecycle hooks, and query-level guards.
> Authentication (credentials, sessions, OAuth) comes later.

```sh
go get github.com/bernardoforcillo/authlayer
```

Requires Go 1.26+. The `access` package is standard-library only; everything
else pulls in `drops` (and `pgx/v5` for the PostgreSQL store).

## Contents

- [The model](#the-model) · [Quick start](#quick-start)
- [Statements & permissions](#statements--permissions) · [Roles](#roles) ·
  [How a decision is made](#how-a-decision-is-made)
- [Context](#context) · [Checking permissions](#checking-permissions) ·
  [Managing members](#managing-members) · [Custom roles](#custom-roles)
- [Privilege escalation](#the-privilege-escalation-guard) ·
  [Policy](#policy) · [Hooks & events](#hooks--events) · [Options](#options)
- [Query-level filtering](#query-level-filtering) · [Storage](#storage) ·
  [Custom scopes](#custom-scopes) · [Nested scopes](#nested-scopes) ·
  [Invitations](#invitations) · [Errors](#errors) · [Packages](#packages)

## The model

- **Scopes.** A scope is an authorization boundary — an organization, a team, a
  project — with an owner and members. The engine is generic over the container
  and member types; `org` is the ready-made organization instance, and most
  callers never write a type parameter.
- **Statements.** You declare the permission surface in code as
  `resource → actions` (e.g. `member: [create, update, delete]`). Compiled to a
  bitset for O(1) checks; stored role permissions are serialised by *name*, so
  evolving the statement set never corrupts saved roles.
- **Hybrid roles.** `owner`, `admin` and `member` are defined in code and seeded
  automatically. On top of them, each container can define **custom roles** at
  runtime, persisted through the store.
- **One role per member.** No stacking — a member's effective permissions are
  always exactly one role's, which keeps them auditable. The owner and any role
  granting everything bypass fine-grained checks. A privilege-escalation guard
  stops anyone granting more than they hold.
- **Two enforcement points.** An in-memory decision (`Can` / `Authorize` /
  `HasPermission`) *and* a drops `pg.Guard` that filters rows at the database.
  Both read the acting subject and the active scope from the same `context`.
- **No user table.** authlayer stores no users and declares no foreign key to
  yours — a user id is a value it carries, never one it validates against a
  schema of its own. The one thing that does check it is PostgreSQL: the drops
  store types user-id columns `uuid` by default, because authlayer generates
  UUIDv7 user ids. Bring your own non-UUID ids with
  `dropsstore.WithTextUserIDs()`.

## Quick start

```go
ac := org.NewAccess(map[string][]access.Action{
    "project": {"create", "read", "update", "delete"}, // your app's resources
})
svc := org.New(ac, memory.New[org.Organization, org.Member]()) // swap for drops

ctx := org.WithSubject(context.Background(), "alice")
acme, _ := svc.CreateOrganization(ctx, "Acme", "acme") // alice becomes owner

alice := org.WithOrg(ctx, acme.ID)
svc.AddMember(alice, "bob", org.RoleAdmin)

bob := org.WithOrg(org.WithSubject(context.Background(), "bob"), acme.ID)
ok, _ := svc.Can(bob, org.ResourceMember, org.ActionCreate)       // true
ok, _  = svc.Can(bob, org.ResourceOrganization, org.ActionDelete) // false
```

A full, database-free tour is in [`examples/basic`](examples/basic/main.go):

```sh
go run ./examples/basic
```

## Statements & permissions

`access.Statements` is the permission surface — the complete set of things that
*can* be granted. Nothing outside it is grantable, so a typo denies rather than
silently allows.

```go
ac := org.NewAccess(map[string][]access.Action{
    "project": {"create", "read", "update", "delete"},
    "billing": {"read", "update"},
})
```

`org.NewAccess` merges your statements with the built-in **control statements**
the engine enforces on its own operations:

| Resource       | Actions                    | Checked by                             |
|----------------|----------------------------|----------------------------------------|
| `organization` | `update`, `delete`         | your handlers (declared, not enforced) |
| `member`       | `create`, `update`, `delete` | `AddMember`, `ChangeMemberRole`, `RemoveMember` |
| `role`         | `create`, `update`, `delete` | `CreateRole`, `UpdateRole`, `DeleteRole` |
| `invite`       | `create`, `read`, `delete` | the [`invite`](#invitations) package's own mint/list/revoke calls — the engine itself checks none of it |

`organization:update` / `organization:delete` are declared so your own "rename
the org" and "delete the org" handlers have something to check with `Authorize`,
and so `admin` can be defined as "everything except deleting the container".

An `access.Permission` is an immutable set of grants over those statements, held
as a bitset:

```go
p.Allows("project", "create", "update") // AND across actions; false if undeclared
p.IsFull()                              // grants every declared pair
p.SubsetOf(other)                       // backs the escalation guard
p.Encode()                              // "project:create\nproject:update"
```

**Encoding is by name, not bit index.** `Encode` writes newline-separated
`resource:action` tokens and `Access.Decode` re-resolves them against the
statements in force at decode time. Adding, removing, or reordering resources
therefore never re-interprets a permission persisted earlier — a capability you
delete is dropped from stored roles, and everything else keeps its meaning.

Grants that name an undeclared pair fail loudly, and *where* they fail depends on
where they came from: `Access.NewRole` panics (a mis-declared code-defined role
is a startup bug), while `Access.Permission` returns an error (runtime and
DB-sourced grants must be validated, not trusted).

The `access` package stands alone if you want just the engine:

```go
st := access.NewStatements(map[string][]access.Action{"doc": {"read", "write"}})
ac := access.New(st)
ac.NewRole("viewer", map[string][]access.Action{"doc": {"read"}})
viewer, _ := ac.Role("viewer")
viewer.Permissions.Allows("doc", "write") // false
```

## Roles

**Default roles** are code, identical in every container, and seeded by
`NewAccess`. They are derived from the merged statement surface, so they grow
automatically as your app declares more resources:

| Key      | Grants                                            | Notes |
|----------|---------------------------------------------------|-------|
| `owner`  | everything                                        | `IsFull`, so it bypasses fine-grained checks and the escalation guard |
| `admin`  | everything except `<container>:delete`            | not full, so the escalation guard still applies |
| `member` | nothing                                           | standing only: can list members and roles, change nothing |

They are reserved — a custom role may not reuse a default key, and none can be
updated or deleted at runtime.

**Custom roles** are per-container, defined at runtime, and stored as encoded
grants. A custom role in one container is invisible to every other, so two
tenants can both define an `editor` that means different things.

## How a decision is made

Every check resolves the actor's **standing** in a container:

1. Load the container → `ErrContainerNotFound` if absent.
2. If `OwnerBypass` is on and the actor owns it → **elevated**, full permissions.
   No membership lookup, no role resolution.
3. Load the membership → `ErrNotMember` if absent.
4. Resolve the role key: a code-defined default if the registry knows it,
   otherwise a custom role loaded from the store and decoded → `ErrRoleNotFound`
   if neither.
5. The actor is **elevated** if the resolved permission set is full.

An elevated actor passes every fine-grained check naming at least one action,
*and* the escalation guard. Everyone else must hold every requested
`(resource, action)` pair. A check naming no actions denies everyone, elevated
included — there is nothing to authorize.

Nothing is cached. Every check hits the store for the container, the membership,
and (for custom roles) the role record — so a permission change takes effect
immediately and there is no invalidation to get wrong. Wrap the `Store`, not the
`Service`, if you need fewer round trips.

## Context

The acting subject and the active scope travel on the `context`, not as
arguments, so one context drives both the in-memory decision and drops' query
guards. authlayer reuses drops' own keys (`pg.WithSubject` / `pg.WithTenant`).

```go
ctx = org.WithSubject(ctx, userID) // who is acting
ctx = org.WithOrg(ctx, orgID)      // which organization

userID, ok := org.SubjectFrom(ctx)
orgID,  ok := org.OrgFrom(ctx)
```

A missing subject is `ErrSubjectMissing`; a missing scope is `ErrOrgMissing`.
Neither is ever a silent allow. `CreateOrganization` is the one operation that
needs no scope — there is no organization yet.

## Checking permissions

```go
// Boolean form: folds "forbidden" and "not a member" into false.
ok, err := svc.Can(ctx, "project", org.ActionDelete)

// Error form: distinguishes 403-denied from 403-not-a-member from 404.
err := svc.Authorize(ctx, "project", org.ActionCreate, org.ActionUpdate)

// Out-of-band: ask about a user who is not the ctx subject.
ok, err := svc.HasPermission(ctx, orgID, "carol", map[string][]access.Action{
    "project": {"create"},
    "billing": {"read"},
})
```

- Multiple actions are an **AND**, not an OR. Zero actions denies — there is
  nothing to authorize.
- `Can` returning a non-nil error means the question could not be *answered*
  (missing context, store failure). That is not a denial; check `err` first.
- `HasPermission` reads nothing from the context and performs no check that the
  *caller* may ask, so keep it out of end-user-facing paths. An empty request map
  returns true for any member.

## Managing members

All of these read the actor and scope from the context.

| Call | Requires | Notes |
|---|---|---|
| `CreateOrganization(ctx, name, slug)` | subject only | caller becomes owner; no permission check — gate it upstream |
| `AddMember(ctx, userID, roleKey)` | `member:create` + escalation guard | `ErrAlreadyMember` on a duplicate |
| `ChangeMemberRole(ctx, userID, roleKey)` | `member:update` + escalation guard | owner cannot be demoted under `LastOwnerLocked` |
| `RemoveMember(ctx, userID)` | `member:delete` + escalation guard *on the target's role* | so two admins cannot evict each other |
| `LeaveContainer(ctx)` | membership only | owner cannot leave under `LastOwnerLocked` |
| `ListMembers(ctx)` | membership only | non-members get `ErrNotMember`, not an empty list |
| `TransferOwnership(ctx, userID)` | **owner only** | target must already be a member |

`TransferOwnership` moves `owner_id` and nothing else — neither membership's role
key changes, so the outgoing owner keeps whatever role they were stored with.
Demote them afterwards if you want that.

## Custom roles

```go
_, err := svc.CreateRole(ctx, "editor", "Editor", map[string][]access.Action{
    "project": {"create", "update"},
})
_, err  = svc.UpdateRole(ctx, "editor", "Editor", grants) // replaces wholesale
err      = svc.DeleteRole(ctx, "editor")
roles, _ := svc.ListRoles(ctx)
```

- `key` is what gets stored on memberships; `name` is a display label.
- `UpdateRole` **replaces** the grant set rather than merging, and takes effect
  immediately for every member holding the role — permissions are resolved per
  check, never copied onto the membership.
- `DeleteRole` refuses a role that still has members (`ErrRoleInUse`) rather than
  cascading and silently stripping them.
- Default roles are immutable (`ErrDefaultRole`).
- `ListRoles` returns the three defaults (`IsDefault: true`) followed by the
  container's custom roles, each with a resolved `access.Permission` — enough to
  drive a role editor without a second lookup.

## The privilege-escalation guard

Delegated administration must not be a ladder. Unless elevated, an actor may not:

- add a member with a role more powerful than their own,
- change a member to such a role,
- remove a member more powerful than themselves,
- create or update a custom role granting powers they lack.

The check is `granted.SubsetOf(actor)`, and a violation is
`ErrPrivilegeEscalation`. Owners and full-permission roles are exempt — for them
every set is trivially a subset.

```go
// bob is an admin: he cannot mint a role that can delete the organization.
_, err := svc.CreateRole(bob, "superadmin", "Super", map[string][]access.Action{
    org.ResourceOrganization: {org.ActionDelete},
})
errors.Is(err, org.ErrPrivilegeEscalation) // true
```

## Policy

```go
svc := org.New(ac, store, org.WithPolicy(org.Policy{
    Escalation:        scope.EscalationStrict,
    LastOwnerLocked:   true,
    MembersFromParent: true,
    OwnerBypass:       false, // the only deviation from the defaults
}))
```

| Field | Default | Effect |
|---|---|---|
| `Escalation` | `EscalationStrict` | `EscalationOff` disables the guard entirely. `EscalationAllowEqual` currently behaves like `Strict` — it is reserved for future "strictly-less" semantics. |
| `LastOwnerLocked` | `true` | Owner cannot be removed, demoted, or leave. Ownership still moves via `TransferOwnership`. |
| `MembersFromParent` | `true` | In a [nested scope](#nested-scopes), `AddMember` refuses a user with no standing in the parent (`ErrNotParentMember`). No effect without `WithParent`. |
| `OwnerBypass` | `true` | Owner gets full permissions regardless of their role key, so a mis-configured container is always recoverable. |

`WithPolicy` replaces the policy wholesale — it does not merge — so pass a fully
populated struct. The zero `Policy` is *not* the defaults.

`invite.Service` carries one policy knob of its own, configured separately
through its own `Option` rather than through `Policy`/`WithPolicy` — an
`invite.Service` and the `scope.Service` it wraps are configured
independently: `invite.WithRecheckInviterOnAccept` (default `true`) controls
whether accepting an invitation re-checks the inviter's *current* standing
before admitting anyone. See [Invitations](#invitations) for what that trades
away when turned off.

## Hooks & events

Hooks fire after a mutation is applied but before the call returns, for audit
trails, webhooks, cache invalidation, or a transactional outbox.

```go
svc := org.New(ac, store, org.WithHooks(scope.HookFunc(
    func(ctx context.Context, e scope.Event) error {
        return audit.Write(ctx, e.Kind, e.ContainerID, e.ActorID, e.TargetID)
    },
)))
```

| Kind | Emitted by | `TargetID` / `RoleKey` |
|---|---|---|
| `ContainerCreated` | `CreateOrganization` | — (`ActorID` is the new owner) |
| `MemberAdded` | `AddMember` | added user / their role |
| `MemberRoleChanged` | `ChangeMemberRole` | member / new role |
| `MemberRemoved` | `RemoveMember`, `LeaveContainer` | removed user (equals `ActorID` on a leave) |
| `RoleCreated` / `RoleUpdated` / `RoleDeleted` | the role calls | — / the role key |
| `OwnershipTransferred` | `TransferOwnership` | incoming owner (`ActorID` is the outgoing one) |

A hook returning an error **aborts the operation**. For `CreateOrganization` that
rolls back the whole transaction — container, owner membership, and all. For the
other operations the store change is already committed while the caller sees an
error, so keep non-retryable side effects out of hooks and return `nil` for
best-effort work like logging. Hooks run in registration order on the caller's
goroutine; the first error stops the chain.

## Options

| Option | Purpose |
|---|---|
| `WithPolicy(p)` | Replace the authorization policy. |
| `WithHooks(h...)` | Append lifecycle hooks (accumulates across calls). |
| `WithClock(fn)` | Timestamp source; default `time.Now().UTC()`. Inject a fixed clock for deterministic tests. |
| `WithIDGenerator(fn)` | Id source for containers and custom roles; default is UUIDv7 from `crypto/rand`. Swap in ULIDs or whatever your schema expects. |
| `WithParent(p, inherit)` | [Nest](#nested-scopes) this scope inside another, resolving standing through `p` and projecting it with `inherit`. |
| `WithContainerResource(res)` | Name this scope's own container resource, so a [nested](#nested-scopes) `CreateContainer` knows what `<res>:create` to check for in the parent. |

Options apply at construction and never after, so a `Service` is immutable once
built.

## Query-level filtering

In-memory checks answer "may this user do X?". A guard answers "which rows may
this user see?" — pushed into SQL so a `SELECT` can never return another
tenant's rows.

```go
projects.AuthorizeWith(st.MembershipGuard(projectsTbl.Col("organization_id")))
// SELECT ... WHERE "organization_id" IN (
//     SELECT "container_id" FROM "organization_members" WHERE "user_id" = $subject)
```

`st.MembershipGuard` is the drops store's convenience — it fills in the junction
table and its columns. The general form works against any membership table:

```go
guard := org.MembershipGuard(membersTbl,
    membersTbl.Col("user_id"), membersTbl.Col("container_id"),
    projectsTbl.Col("organization_id"))
```

The subject comes from the same context as the permission checks, and a missing
subject fails closed (`pg.ErrSubjectMissing`).

`MembershipGuard` is coarse: it asks only whether the subject is a member. To
filter by a specific permission, use `PermissionGuard`:

```go
projects.AuthorizeWith(svc.PermissionGuard(
    projectsTbl.Col("organization_id"), "project", org.ActionDelete))
// WHERE "organization_id" IN ($1, $2)   -- only the orgs granting project:delete
```

It resolves the container set through the same ladder `Can` uses, so the guard
and an in-memory check agree for every container where the subject holds a
membership whose role key resolves. Where they diverge — an unresolvable role
key, a missing container row, an owner with no membership row of their own —
the guard denies rather than leaks. A subject with no qualifying containers
renders as a false predicate — no rows, never all rows — a missing subject is
`pg.ErrSubjectMissing`, and a store failure aborts the query rather than
narrowing it to nothing.

The cost is one round trip per guarded query, plus one lookup per distinct
`(container, role key)` pair naming a custom role — a custom role belongs to one
container, so the same key in two containers is two lookups. The rendered `IN`
list also binds one parameter per qualifying container.
`svc.ContainersWith(ctx, userID, resource, actions...)` is the same answer as a
plain `[]string`, so a hot endpoint can hoist it:

```go
ids, err := svc.ContainersWith(ctx, userID, "project", org.ActionDelete)
```

`ContainersWith` takes the user id as an argument rather than from the context,
so — like `HasPermission` — it performs no check that the *caller* is entitled
to ask, and its answer enumerates that user's memberships and how privileged
they are in each. Do not expose it directly to end users. `PermissionGuard` is
the safe form: it reads the subject from the context.

**In a [nested scope](#nested-scopes), neither consults the parent.**
`ContainersWith` resolves membership-based standing only — it does not walk
the parent rung `Can` applies. An organization admin who can administer a team
purely through inheritance, holding no membership row of their own in that
team, gets no row for it here and no rows from a `PermissionGuard` built over
it, even though `Can`, `Authorize` and `Standing` all admit them in that same
container: `Can` says yes, the guard says no. That is a known gap, not a
deliberate rule — do not build a nested scope's row-level filtering on the
assumption that it mirrors `Can`.

Guards compose, so "rows I created, or rows in an organization where I may
delete projects" is:

```go
projects.AuthorizeWith(pg.AnyOf(
    pg.OwnerGuard{Owner: projectsTbl.Col("created_by")},
    svc.PermissionGuard(projectsTbl.Col("organization_id"), "project", org.ActionDelete),
))
```

## Storage

`scope.Store` is the persistence port: containers, members, roles, a
transaction, and the user-scoped lookups `ListUserContainers` and
`ListUserStandings` — the latter backing `PermissionGuard`. It is composed
from `ContainerStore`, `MemberStore` and `RoleStore`, so a backend or a
decorator (caching, metrics) can override a slice of it by embedding the rest.

A store is *pure persistence*. The engine stamps ids, owners and timestamps,
resolves roles, and runs every authorization check before calling in; the store
never authorizes anything and never interprets permission bytes. What it does
owe the engine is the right sentinel error when a lookup finds nothing —
`ErrNotMember` rather than a generic not-found — because the engine branches on
those. Each method's contract is documented on the interface.

### `store/memory`

An in-process, generic store backed by maps. Zero dependencies, concurrency
safe, and the reference implementation of the contract — use it for development,
tests, and examples. It does not enforce uniqueness of your own fields (a slug,
say), and its `WithTx` approximates a transaction by snapshot-and-restore under
a mutex.

### `store/drops`

The PostgreSQL store, generic over the container and member types:

```
organizations         id PK (uuid), name, slug UNIQUE, owner_id, created_at, updated_at
organization_members  (container_id, user_id) PK, role_key, joined_at
organization_roles    id PK, container_id, key, name, permissions BYTEA,
                      created_at, UNIQUE (container_id, key)
```

```go
db := pg.New(stdlib.New(sqlDB)) // sqlDB is a *sql.DB on a pgx connection
st := dropsstore.New[org.Organization, org.Member](db)
st.CreateSchema(ctx)            // or manage the tables with your migrations
svc := org.New(org.NewAccess(nil), st)
```

Columns are derived from the `drop:` tags on your types, so a different scope
needs only table names:

```go
teams := dropsstore.New[team.Team, team.Member](db, dropsstore.WithNames(
    dropsstore.Names{Containers: "teams", Members: "team_members", Roles: "team_roles"}))
```

Fields must be `string`, `time.Time`, `[]byte`, `int` or `int32` — or a named
type over `string`, `int` or `int32`. Anything else, a pointer included, panics
at construction with the column named; nullable columns are not supported yet.
A field with no `drop:` tag (or `drop:"-"`) is not persisted, and your container
type must tag `id`, `owner_id`, `created_at` and `updated_at` while your member
type must tag `container_id`, `user_id`, `role_key` and `joined_at` — embedding
`scope.ContainerBase` and `scope.MemberBase` does that for you, and a type that
misses one is rejected at construction rather than at the first query.

Ids authlayer generates are UUIDv7 and their columns are `uuid`. So are the
columns holding a user id — `owner_id` as much as `user_id` — since authlayer
generates user ids too. If you use only the RBAC half against an existing user
table whose ids are not UUIDs, pass `dropsstore.WithTextUserIDs()`: it retypes
every user-id column at once, and leaves the ids authlayer mints for itself
(`id`, `container_id`, `parent_id`) as `uuid`.

The unique constraints are load-bearing: they are what turn a concurrent
double-insert into `ErrSlugTaken`, `ErrAlreadyMember` or `ErrRoleKeyTaken`
instead of a duplicate row, because the engine does not pre-check any of the
three. `CreateSchema` emits them — including the composite
`PRIMARY KEY (container_id, user_id)` on the members table and
`UNIQUE (container_id, key)` on the roles table, which a `CREATE TABLE` cannot
carry — and keep them if you own these tables in your own migrations instead.
Every statement it issues is idempotent, so the call is safe to re-run, but it
only ever adds what is missing: a table that already exists with different
columns or constraints is left as it stands, so `CreateSchema` will not migrate
an existing schema forward. `st.Schema()` exposes the table definitions if you
would rather generate the DDL.

No foreign key to a users table is declared, because authlayer does not own one.

A live end-to-end test lives behind a build tag, so the default `go test ./...`
stays database-free:

```sh
AUTHLAYER_TEST_DSN='postgres://…?sslmode=disable' go test -tags integration ./store/drops/
```

## Custom scopes

`org` fixes the container type to `Organization` and the member type to `Member`.
For a different boundary — teams, projects, workspaces — or extra fields on a
membership, embed the bases in your own types and use `scope` directly:

```go
type Team struct {
    scope.ContainerBase        // id, owner_id, created_at, updated_at
    Name     string `drop:"name"`
    ParentID string `drop:"parent_id"`
}

type TeamMember struct {
    scope.MemberBase           // container_id, user_id, role_key, joined_at
    InvitedBy string `drop:"invited_by"`
}

ac  := scope.NewAccess("team", appStatements) // "team" is the container resource
svc := scope.New[Team, TeamMember](ac, teamStore)

team, _ := svc.CreateContainer(ctx, Team{Name: "Platform"})
```

The engine reads and stamps the base fields and leaves yours alone; drops
flattens the embedded struct when persisting. `org`'s source is short and is the
worked example of doing this.

If a scope's own standing should also be reachable *from* a parent container's
standing — rather than `ParentID` being just another field you happen to
store — don't roll it by hand; embed `scope.NestedBase` instead and see
[Nested scopes](#nested-scopes) below.

## Nested scopes

A scope can sit inside another — a team inside an organization, a project
inside a team — so that standing in the parent can confer standing in the
child. `team` is the worked example, teams nested one level inside `org`:

```go
orgSvc  := org.New(org.NewAccess(team.ParentStatements()), memory.New[org.Organization, org.Member]())
teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc)

ctx := org.WithSubject(context.Background(), "alice")
acme, _ := orgSvc.CreateOrganization(ctx, "Acme", "acme") // alice becomes owner

alice := org.WithOrg(ctx, acme.ID)
platform, _ := teamSvc.CreateTeam(alice, "Platform") // alice owns the org, so she owns the team too
```

`team.ParentStatements()` — merged into `org.NewAccess`'s statements above —
declares `team:create` on the *organization's* surface, so an organization
role (not only the owner) can be granted the right to create a team. Skipping
that merge is not a startup error: `CreateTeam` still works for the org owner,
since ownership always bypasses the check; every other member is refused with
nothing in the error to say why.

**Bits never cross a scope boundary.** An `access.Permission` is a bitset over
one package's `Statements`, so a parent's bits mean nothing in a child's
statement space — inheritance therefore never projects bits, only *grant
names*, which the child recompiles against its own `Access`.

The zero-config default confers standing on nobody but the truly elevated:
under `org.NewAccess`'s default roles that is the **owner alone**, via
ownership. The built-in `admin` role is deliberately kept short of full
permission (it excludes `organization:delete`, so the escalation guard still
applies to it), so a plain admin inherits nothing in a team by default. To
extend administration to whoever can manage teams — what most applications
actually want — declare that capability on the organization's own surface
(`team:update`, say — this is separate from, and in addition to,
`team.ParentStatements()`'s `team:create`) and install your own projection.
Both halves are required: the grant has to actually be on the organization's
surface, or the projection has nothing to find and confers standing on
nobody — silently, since an undeclared pair just reads as "not granted":

```go
statements := team.ParentStatements()
statements[team.ResourceTeam] = append(statements[team.ResourceTeam], team.ActionUpdate)
orgSvc := org.New(org.NewAccess(statements), memory.New[org.Organization, org.Member]())

teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc,
    scope.WithParent(orgSvc, scope.InheritWhen(team.ResourceTeam, team.ActionUpdate)))
```

Now any organization member holding `team:update` — an admin, by default,
since `org.NewAccess` grants every declared pair but `organization:delete` to
`admin` — administers every team in the organization without joining one.

`Policy.MembersFromParent` (on by default) requires a user being added to the
child to already hold standing in the parent: `AddMember` on a team refuses a
non-member of the organization with `ErrNotParentMember`, rather than the team
quietly acquiring members the organization has never heard of.

Nesting also changes `CreateContainer`: on a parented scope it performs a
permission check against the parent (`<containerResource>:create`, or elevated
parent standing) before creating anything, where the unparented form performs
no check at all — expect that difference the first time you wire
`WithParent`.

A nested check consults the parent's store before it ever looks at the
child's own membership, so a parent-store outage denies every non-owner check
in every nested container beneath it — even a subject whose own membership
would otherwise have sufficed. That is the correct trade-off (failing closed
beats guessing), but it is worth knowing before it surprises you in an
incident.

Parent chains must be acyclic. Two `*Service` values can't form one by
construction — a parent has to already exist before it can be named as one —
but `ParentScope` is an exported single-method interface, so a custom
implementation with a field wired up after construction (a late-bound parent)
can still build a cycle. Either way the engine does not detect it: configuring
one recurses until the goroutine's stack overflows, a fail-stop crash in your
own wiring rather than anything a request can trigger. Each level a check
climbs — resolving the parent's own standing, and its parent's, and so on —
costs one more store round trip.

## Invitations

`invite` admits a person who has no standing in a scope yet, without a direct
[`AddMember`](#managing-members) call: a one-time emailed token, or a reusable
link. Both end the same way, at the newly exported
`scope.Service.GrantMembership` — admitting the named user at the named role
while performing **no actor check of its own**, not even `member:create`, let
alone the escalation guard. Every actor-facing rule already ran when the
credential was minted, and the person accepting it has no standing yet to
check in the first place. `GrantMembership` is therefore only as safe as
whatever decided to call it: it must never be reachable except by presenting a
credential minted for exactly that container and role, which is exactly what
`AcceptInvite`, `JoinViaLink`, and `ListLinks`'s redaction (below) exist to
guarantee.

```go
svc := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member]())
isvc := invite.New(svc.Service, memory.NewInviteStore()) // org.Service embeds *scope.Service as .Service

ctx := org.WithSubject(context.Background(), "alice")
acme, _ := svc.CreateOrganization(ctx, "Acme", "acme") // alice becomes owner

owner := org.WithOrg(ctx, acme.ID)
_, token, _ := isvc.InviteByEmail(owner, "bob@example.com", org.RoleMember)
// deliver `token` yourself — authlayer knows no base URL and owns no transport

bob := org.WithSubject(context.Background(), "bob")
_, _ = isvc.AcceptInvite(bob, token) // bob is now a member of acme, holding org.RoleMember
```

A link works the same way, minus the email step — reusing `ctx`/`acme`/`isvc`
above:

```go
owner := org.WithOrg(ctx, acme.ID)
_, code, _ := isvc.CreateLink(owner, org.RoleMember, 5, nil) // up to 5 uses, never expires

carol := org.WithSubject(context.Background(), "carol")
_, _ = isvc.JoinViaLink(carol, code) // carol is now a member of acme, holding org.RoleMember
```

`store/memory`'s `NewInviteStore` is the dev/test `invite.Store`, exactly like
`memory.New` for `scope.Store`; `store/drops` ships the production one as
`dropsstore.NewInviteStore(db)`, with its own `CreateSchema`.

**Two artifacts, one hashed, one not.** An email invite (`EmailInvite`) is
delivered once and never redisplayed to anyone, including the inviter, so only
its sha256 is stored (`TokenHash`) — a database leak cannot be replayed into
admission, because an attacker who steals the row still cannot produce a token
that hashes to it. A link (`Link`) is the opposite: its whole purpose is to be
shown again, on a "manage invite links" screen, so `Code` is stored in clear —
hashing it would make redisplay impossible. A link's security therefore comes
from `MaxUses`, `ExpiresAt` and revocation rather than secrecy of storage,
which is why `Store.ConsumeLink` must weigh all three atomically before
admitting anyone.

**Delivery is your job.** `InviteByEmail` returns the plain token exactly
once, alongside the stored record; authlayer knows no base URL and owns no
transport, so turning that into an actual email — which link, which template,
which provider — is entirely the caller's own business. `WithNotifier` wires a
`Notifier` that `InviteByEmail` calls once the invite is persisted; it is
optional sugar over calling one yourself right after `InviteByEmail` returns,
and the default (nil) sends nothing at all.

**`ListLinks`'s redaction is the security core of this package.** `invite:read`
sits on the merged control-statement surface every `NewAccess` builds (see
[Statements & permissions](#statements--permissions)), so the built-in `admin`
role acquires it automatically — and `admin` is deliberately not `IsFull` (see
[Roles](#roles)), so it is normally subject to the privilege-escalation guard
everywhere else in this codebase. Without redaction that guard would be
worthless here: a non-elevated admin lists the links, reads the owner's `Code`
in clear, leaves the container, and rejoins at the owner role through
`JoinViaLink` — which admits via `GrantMembership`, a call that runs no
escalation check of its own, because the whole point of a link is to admit
someone who has no standing yet to check. Two calls, full escalation, and
every fine-grained check elsewhere in the codebase never touched. So a `Code`
survives in `ListLinks`' result only when **both** halves of the mint test hold
for the reader, because minting takes two things:

1. **The capability** — the reader must hold `invite:create`, the same
   permission `CreateLink` requires, resolved once for the whole list. A reader
   granted `invite:read` *without* `invite:create` could not have minted any
   link here, so they see no `Code` at all, whatever the roles involved.
   Splitting a resource's actions across roles is the entire product, and
   `CreateRole` will happily define an `auditor` granting only `invite:read`;
   without this half, such a read-only reader would silently acquire the power
   to admit arbitrary third parties, which is exactly what `invite:create`
   exists to gate.
2. **The standing** — the reader must be elevated, or the link's role must
   resolve to a permission set that is a `SubsetOf` their own current standing.
   That is the same test applied when the link was created, reapplied here
   because a role's grants (or the reader's own standing) can change
   afterwards.

The two are independent: the first bounds *whether* this principal mints at
all, the second bounds *how high*. Every other field stays populated, so a
management screen can still list a link and let its owner revoke it, even one
whose code it cannot show back.

**Claim first, admit second — in both flows.** Acceptance spans two stores
that may not share a database — the invite lives in `invite.Store`, the
membership in `scope.Store` — so there is no cross-store transaction. Both
`AcceptInvite` and `JoinViaLink` claim the credential atomically FIRST and
admit SECOND. `AcceptInvite` deletes the invite through the rows-affected-gated
`Store.DeleteEmailInvite`: of any two callers racing to delete the same id —
including the same token presented twice — at most one ever sees a nil error,
and only that caller proceeds to `GrantMembership`. `JoinViaLink` consumes a
use through the atomic `Store.ConsumeLink`, which folds the
revoked/expired/exhausted check and the increment into one step a concurrent
caller cannot split. In both, a failure AFTER the claim burns the credential
and admits no one — under-admission, the safe direction — at the cost that
accepting is not safe to retry with the same token: the invitee has to be
re-invited, or, for a link with uses left, try again. The reverse order — admit
first, claim second — was an earlier version of `AcceptInvite`, and it was a
Critical finding, not a style preference: while the invite row still existed,
the token stayed redeemable by *anyone* holding it, not merely by the original
caller retrying — two distinct subjects were demonstrably admitted from a
single invitation. A one-time credential must never pay out more than once; do
not "tidy" this ordering back during a later refactor. See `AcceptInvite`'s
and `JoinViaLink`'s own doc comments in `invite/service.go` for the full
argument, including the narrow, deliberately-accepted boundary imprecision
around `AcceptInvite`'s expiry check.

**On a nested scope, admit to the parent first.** The post-claim failure that
actually happens is not a store outage — it is `scope.ErrNotParentMember`.
Under the default `Policy.MembersFromParent`, `GrantMembership` refuses anyone
who does not *already* hold standing in the parent of a [nested](#nested-scopes)
scope, deterministically and every time. Since the credential is claimed first,
that burns it: a team invitation sent to someone who is not yet in the
organization fails, the token is spent, and re-presenting it gives
`ErrInviteNotFound`. Nothing in `invite` checks parent standing before the
claim. So add the invitee to the parent org — directly, or via a parent-scope
invitation they accept first — before they accept the child's, or clear
`MembersFromParent` for that scope if the child is meant to hold members the
parent has never heard of. It fails closed; nobody is over-admitted, the
invitation is simply gone.

**An email invite is a bearer credential.** `AcceptInvite` admits whoever
presents the token, at the invited role; it never compares the accepting
subject to `EmailInvite.Email`. "One-time" bounds how many times the token pays
out, not who it pays out to, so a forwarded or intercepted invitation email
admits whoever clicks it. That is not something authlayer can check for you:
it stores no users and has no notion of a subject's verified address (see
[The model](#the-model)), so `Email` is a delivery hint and an audit record
rather than an authorization test. If your application needs the invitation
bound to its recipient, enforce it yourself before calling `AcceptInvite` —
`PreviewInvite` reads the invited address out of a token without consuming it,
so compare that against the authenticated user's own verified address.

**An existing member is idempotent, but not symmetrically.** If the ctx
subject already has standing in the link's container, `JoinViaLink` returns
the container immediately and consumes nothing — no use taken, no redundant
membership write — checked before the escalation recheck or the use count, so
a member re-clicking an old invite link never costs it anything.
`AcceptInvite` instead folds a duplicate's `scope.ErrAlreadyMember` into
success after the token is already consumed: a member who already holds a
role *below* the one the invite grants gets no error and no promotion, and
nothing in the return value distinguishes "already had this role" from
"already had a lesser one". This never over-privileges — folding a duplicate
can only leave someone at or below what they already had — but it can
silently swallow an intended promotion. Check `scope.Service.Standing` first,
or route promotions through `ChangeMemberRole`, if your application needs to
tell the two apart.

**`RecheckInviterOnAccept`, on by default.** The privilege-escalation guard
already ran once, at mint time, against the inviter's standing as of that
moment — nothing about a stored token or link updates afterwards, so without a
recheck a credential keeps paying out at the power level its inviter held when
they minted it, even after that inviter is demoted or leaves the container
entirely. Enabled, the guard reruns against the inviter's CURRENT standing
before `AcceptInvite` or `JoinViaLink` admit anyone — before the claim, so a
refusal spends nothing: a demoted inviter's pending invitation now fails with
`scope.ErrPrivilegeEscalation`, and one from an inviter who has since left
fails with `scope.ErrNotMember`. The cost is durability: a pending invitation
now dies the moment its inviter's own standing can no longer support it,
including simply leaving the container. Turn it off with
`invite.WithRecheckInviterOnAccept(false)` if your application wants "who
invited me" to be provenance rather than an ongoing authorization the inviter
must keep backing.

**`PurgeExpired` is for a cron.** `Service.PurgeExpired(ctx, before)` deletes
every expired invite and link across every container the `Store` holds, and
returns how many rows were removed. It performs NO authorization check and
reads neither a subject nor a container from the context — there is no ctx
container to check against, since a single call spans every container the
store holds — so call it only from a trusted context, never from a
per-request handler wired to caller input: an unauthenticated caller who could
trigger it at will gets a cross-tenant denial-of-service knob even though it
cannot itself grant access.

**Two new `scope` primitives, exported to make this package possible.**
`RolePermissions(ctx, containerID, roleKey)` resolves a role key to its
permission set exactly the way every check in the engine does — a
code-defined role first, then a custom role loaded from the store — and is the
right way for another package to ask that question: `ListRoles` enumerates
only the three defaults plus a container's *stored* custom roles, so a
code-defined role registered directly with `access.Access.NewRole` (a
`viewer` role, say) resolves through `RolePermissions` but is invisible to
`ListRoles`, and approximating from the latter would silently treat such a
role as nonexistent. `Container(ctx, id)` loads a container by id, returning
the whole record — including any application-defined fields your container
type carries beyond `ContainerBase` — because `GrantMembership` returns only
the new membership, not the container the invitee was just admitted to, and
acceptance needs to hand one back. Like `Standing` and `HasPermission`, neither
reads anything from the context nor checks that the caller is entitled to
ask — do not expose either directly to end users.

## Errors

Compare with `errors.Is`, never by string. `org` re-exports these as *aliases*,
so `org.ErrOrgNotFound` **is** `scope.ErrContainerNotFound` and either name
matches.

| Error (`org` name if different) | Meaning | Suggested status |
|---|---|---|
| `ErrContainerNotFound` (`ErrOrgNotFound`) | No such container | 404 |
| `ErrRoleNotFound` | No default or custom role with that key | 404 |
| `ErrForbidden` | Member, but the role does not grant it | 403 |
| `ErrNotMember` | No membership in this container | 403 |
| `ErrOwnerOnly` | Reserved to the owner; no grant substitutes | 403 |
| `ErrPrivilegeEscalation` | Cannot grant what you do not hold | 403 |
| `ErrAlreadyMember` | That user is already a member | 409 |
| `ErrRoleKeyTaken` | Key collides with a default or existing role | 409 |
| `ErrConflict` (`ErrSlugTaken`) | Unique constraint on one of your fields | 409 |
| `ErrRoleInUse` | Role still assigned to members | 422 |
| `ErrDefaultRole` | Default roles cannot be modified at runtime | 422 |
| `ErrLastOwner` | Would remove or demote the owner | 422 |
| `ErrNotParentMember` | [Nested scope](#nested-scopes): `AddMember` target has no standing in the parent | 422 |
| `ErrSubjectMissing` | No subject on the context — a wiring bug | 500 |
| `ErrScopeMissing` (`ErrOrgMissing`) | No container on the context — a wiring bug | 500 |

`Can` already folds `ErrForbidden` and `ErrNotMember` into a plain `false`.

`invite` adds six sentinels of its own — not exported by `scope`, and not
aliased anywhere, since invitations are a separate package with its own
failure modes:

| Error | Meaning | Suggested status |
|---|---|---|
| `ErrInviteNotFound` | No email invite with that id or token hash | 404 |
| `ErrLinkNotFound` | No link with that id or code | 404 |
| `ErrInviteExpired` | The invite's `ExpiresAt` has passed | 410 |
| `ErrLinkRevoked` | The link's `RevokedAt` is set | 410 |
| `ErrLinkExpired` | The link's `ExpiresAt` has passed | 410 |
| `ErrLinkExhausted` | The link's `UseCount` has reached its `MaxUses` | 410 |

The first two are raised by the `Store` itself, on any lookup or delete that
matches no row. The other four describe *why a redemption did not happen*
rather than a lookup miss, and only the service layer raises them: a link's
`Store.ConsumeLink` folds all three of its own reasons into a single
`ok=false` — the check and the increment must be one atomic step, so asking
that step to also report which of three conditions applied would require a
second, separate read, which is exactly the race atomicity rules out — and
`JoinViaLink` re-reads the link afterwards to tell them apart.

## Packages

| Package | What it is |
|---|---|
| [`access`](access/) | The pure access-control engine — statements, permissions, roles. Standard library only. |
| [`scope`](scope/) | The generic RBAC engine: `Service`, `Store` port, policy, hooks, context helpers, guard. |
| [`org`](org/) | Organization RBAC — `scope` with the type parameters fixed and the names spelled "organization". |
| [`team`](team/) | Team RBAC nested inside `org` via `scope.WithParent` — the worked example of [nesting](#nested-scopes). |
| [`invite`](invite/) | [Invitations](#invitations) — email tokens and reusable links admitting a user with no standing yet, via `scope.Service.GrantMembership`. |
| [`store/memory`](store/memory/) | In-memory `Store` for dev, tests, and examples. |
| [`store/drops`](store/drops/) | PostgreSQL `Store` built on drops (composite-key membership). |
| [`examples/basic`](examples/basic/) | Runnable, database-free tour. |

Every exported symbol carries a doc comment; `go doc ./scope` is the reference.

## Roadmap

- Authentication: credentials, revocable server-side sessions, OAuth.

Released versions are recorded in [changelog.md](changelog.md).

## License

MIT — see [license.md](license.md).
