# Warden — Data model

Companion to [`../SPEC.md`](../SPEC.md) §6 and §9. PostgreSQL 15+.

## Conventions

- Primary keys are **ULID strings** with a type prefix (`usr_`, `rol_`, `grn_`). Sortable,
  URL-safe, leak no counts.
- Every tenant-scoped table has `tenant_id` (NOT NULL) and an RLS policy.
- `created_at`, `updated_at` are `timestamptz NOT NULL DEFAULT now()`.
- Soft delete via `deleted_at timestamptz` where recovery matters; hard delete elsewhere.
- Attribute bags are `JSONB` with GIN indexes where queried.
- All FKs are `ON DELETE RESTRICT` unless the child is meaningless without the parent.

## Entity relationship overview

```
tenant ─┬─ user ──┬─ identity ────── idp_connection
        │         ├─ credential
        │         ├─ session ──── refresh_token
        │         └─ group_member ── group ── group_member (nesting)
        │
        ├─ app_enrollment ── application ─┬─ resource_type ── action
        │                                 ├─ role_template
        │                                 └─ ui_element ── ui_binding
        │
        ├─ role ── role_inheritance
        │      └─ role_permission ── permission
        │
        ├─ grant  (subject|group → role @ scope, with conditions & validity)
        ├─ denial (explicit deny)
        ├─ resource_node (registered instances + hierarchy)
        └─ audit_event / decision_event
```

---

## Core tenancy and identity

```sql
CREATE TABLE tenant (
    id              text PRIMARY KEY,                    -- ten_...
    slug            citext UNIQUE NOT NULL,
    name            text NOT NULL,
    status          text NOT NULL DEFAULT 'active',      -- active|suspended|deleted
    settings        jsonb NOT NULL DEFAULT '{}',         -- password policy, MFA policy, ...
    permission_rev  bigint NOT NULL DEFAULT 1,           -- bumped on every authz-affecting write
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE TABLE app_user (                                  -- "user" is reserved in some tooling
    id              text PRIMARY KEY,                    -- usr_...
    tenant_id       text NOT NULL REFERENCES tenant(id),
    email           citext NOT NULL,
    email_verified  boolean NOT NULL DEFAULT false,
    display_name    text,
    status          text NOT NULL DEFAULT 'invited',     -- invited|active|suspended|deprovisioned
    attributes      jsonb NOT NULL DEFAULT '{}',         -- department, approval_limit, ...
    mfa_enforced    boolean NOT NULL DEFAULT false,
    last_login_at   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    UNIQUE (tenant_id, email)
);
CREATE INDEX ON app_user USING gin (attributes jsonb_path_ops);

CREATE TABLE credential (
    id              text PRIMARY KEY,
    user_id         text NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    type            text NOT NULL,                       -- password|totp|webauthn|recovery_code
    secret_hash     text NOT NULL,                       -- argon2id / encrypted seed / COSE key
    params          jsonb NOT NULL DEFAULT '{}',
    label           text,
    last_used_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz
);
CREATE UNIQUE INDEX ON credential (user_id) WHERE type = 'password';

CREATE TABLE idp_connection (
    id              text PRIMARY KEY,                    -- idp_...
    tenant_id       text NOT NULL REFERENCES tenant(id),
    kind            text NOT NULL,                       -- oidc|saml|local
    name            text NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    email_trusted   boolean NOT NULL DEFAULT false,      -- see SPEC §7.4.1 — dangerous
    jit_policy      text NOT NULL DEFAULT 'create',      -- create|link_only|deny_unknown
    domain_hints    text[] NOT NULL DEFAULT '{}',
    config          jsonb NOT NULL,                      -- endpoints, entity ids, certs (encrypted fields)
    mapping         jsonb NOT NULL DEFAULT '{}',         -- SPEC §7.5
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE identity (                                  -- a user's link to one external IdP
    id              text PRIMARY KEY,
    tenant_id       text NOT NULL REFERENCES tenant(id),
    user_id         text NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    connection_id   text NOT NULL REFERENCES idp_connection(id),
    external_subject text NOT NULL,
    raw_claims      jsonb NOT NULL DEFAULT '{}',         -- last seen, for debugging
    linked_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (connection_id, external_subject)
);

CREATE TABLE session (
    id              text PRIMARY KEY,                    -- ses_...
    tenant_id       text NOT NULL REFERENCES tenant(id),
    user_id         text NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    amr             text[] NOT NULL DEFAULT '{}',
    auth_time       timestamptz NOT NULL,
    ip              inet,
    user_agent      text,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz
);
CREATE INDEX ON session (user_id) WHERE revoked_at IS NULL;

CREATE TABLE refresh_token (
    id              text PRIMARY KEY,
    session_id      text NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    family_id       text NOT NULL,                       -- rotation family; reuse revokes all
    token_hash      bytea NOT NULL UNIQUE,
    client_id       text NOT NULL,
    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    revoked_at      timestamptz
);
CREATE INDEX ON refresh_token (family_id);
```

## Groups

```sql
CREATE TABLE group_ (
    id              text PRIMARY KEY,                    -- grp_...
    tenant_id       text NOT NULL REFERENCES tenant(id),
    key             citext NOT NULL,
    name            text NOT NULL,
    source          text NOT NULL DEFAULT 'local',       -- local|idp|scim
    connection_id   text REFERENCES idp_connection(id),
    attributes      jsonb NOT NULL DEFAULT '{}',
    UNIQUE (tenant_id, key)
);

CREATE TABLE group_member (
    group_id        text NOT NULL REFERENCES group_(id) ON DELETE CASCADE,
    member_user_id  text REFERENCES app_user(id) ON DELETE CASCADE,
    member_group_id text REFERENCES group_(id) ON DELETE CASCADE,   -- nesting
    source          text NOT NULL DEFAULT 'local',
    added_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(member_user_id, member_group_id) = 1)
);
CREATE UNIQUE INDEX ON group_member (group_id, member_user_id) WHERE member_user_id IS NOT NULL;
CREATE UNIQUE INDEX ON group_member (group_id, member_group_id) WHERE member_group_id IS NOT NULL;
```

## Applications and the permission surface

```sql
CREATE TABLE application (
    id              text PRIMARY KEY,                    -- app_...
    key             citext UNIQUE NOT NULL,              -- "billing"
    name            text NOT NULL,
    manifest_version integer NOT NULL DEFAULT 0,
    fail_mode       text NOT NULL DEFAULT 'closed',      -- closed|open_read|stale
    cache_mode      text NOT NULL DEFAULT 'cached',
    decision_log    text NOT NULL DEFAULT 'denies'       -- off|denies|sampled|all
);

CREATE TABLE environment (
    id              text PRIMARY KEY,
    application_id  text NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    name            text NOT NULL,                       -- dev|staging|prod
    UNIQUE (application_id, name)
);

CREATE TABLE app_enrollment (
    tenant_id       text NOT NULL REFERENCES tenant(id),
    application_id  text NOT NULL REFERENCES application(id),
    enrolled_at     timestamptz NOT NULL DEFAULT now(),
    settings        jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, application_id)
);

CREATE TABLE resource_type (
    id              text PRIMARY KEY,
    application_id  text NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    key             citext NOT NULL,                     -- "invoice"
    name            text NOT NULL,
    parent_type_id  text REFERENCES resource_type(id),   -- hierarchy declaration
    attribute_schema jsonb NOT NULL DEFAULT '{}',        -- JSON Schema for resource.attributes
    UNIQUE (application_id, key)
);

CREATE TABLE action (
    id              text PRIMARY KEY,
    resource_type_id text NOT NULL REFERENCES resource_type(id) ON DELETE CASCADE,
    key             citext NOT NULL,                     -- "approve"
    name            text NOT NULL,
    implies         text[] NOT NULL DEFAULT '{}',        -- other action keys
    UNIQUE (resource_type_id, key)
);

-- Materialized permission atoms: "billing.invoice:approve"
CREATE TABLE permission (
    id              text PRIMARY KEY,
    application_id  text NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    key             citext NOT NULL,                     -- app.resource:action
    resource_type_id text NOT NULL REFERENCES resource_type(id) ON DELETE CASCADE,
    action_id       text NOT NULL REFERENCES action(id) ON DELETE CASCADE,
    UNIQUE (application_id, key)
);
```

## Roles and grants

```sql
CREATE TABLE role (
    id              text PRIMARY KEY,                    -- rol_...
    tenant_id       text REFERENCES tenant(id),          -- NULL = global template / system role
    application_id  text REFERENCES application(id),
    key             citext NOT NULL,
    name            text NOT NULL,
    description     text,
    type            text NOT NULL,                       -- system|application_template|tenant_custom
    forked_from     text REFERENCES role(id),
    template_version integer,                            -- for drift detection
    constraints     jsonb NOT NULL DEFAULT '{}',         -- requires_mfa, SoD conflicts, max_assignees
    assignable_by   text[] NOT NULL DEFAULT '{}',
    immutable       boolean NOT NULL DEFAULT false,
    UNIQUE (tenant_id, application_id, key)
);

CREATE TABLE role_inheritance (
    role_id         text NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    parent_role_id  text NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, parent_role_id),
    CHECK (role_id <> parent_role_id)
    -- acyclicity enforced in the application layer + a recursive-CTE trigger
);

CREATE TABLE role_permission (
    role_id         text NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    permission_key  citext NOT NULL,                     -- may contain wildcards
    condition       text,                                -- CEL, optional
    PRIMARY KEY (role_id, permission_key)
);

-- The central assignment table.
CREATE TABLE grant_ (
    id              text PRIMARY KEY,                    -- grn_...
    tenant_id       text NOT NULL REFERENCES tenant(id),
    subject_user_id text REFERENCES app_user(id) ON DELETE CASCADE,
    subject_group_id text REFERENCES group_(id) ON DELETE CASCADE,
    role_id         text NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    scope_kind      text NOT NULL,                       -- tenant|application|environment|resource|subtree
    scope_ref       text NOT NULL,                       -- "ten_..","app:billing","billing.project:acme-2026"
    condition       text,                                -- CEL, optional
    valid_from      timestamptz NOT NULL DEFAULT now(),
    valid_until     timestamptz,
    granted_by      text REFERENCES app_user(id),
    reason          text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(subject_user_id, subject_group_id) = 1)
);
CREATE INDEX ON grant_ (tenant_id, subject_user_id) WHERE subject_user_id IS NOT NULL;
CREATE INDEX ON grant_ (tenant_id, subject_group_id) WHERE subject_group_id IS NOT NULL;
CREATE INDEX ON grant_ (tenant_id, scope_ref);
CREATE INDEX ON grant_ (valid_until) WHERE valid_until IS NOT NULL;   -- expiry worker

CREATE TABLE denial (
    id              text PRIMARY KEY,
    tenant_id       text NOT NULL REFERENCES tenant(id),
    subject_user_id text REFERENCES app_user(id) ON DELETE CASCADE,
    subject_group_id text REFERENCES group_(id) ON DELETE CASCADE,
    permission_key  citext NOT NULL,
    scope_kind      text NOT NULL,
    scope_ref       text NOT NULL,
    reason          text NOT NULL,                       -- required; see SPEC §9.7
    created_by      text NOT NULL REFERENCES app_user(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(subject_user_id, subject_group_id) = 1)
);
```

## Resource instances and hierarchy

Registered by applications so that subtree grants, `list-resources` and resource attributes
work. Applications that skip registration keep instance-level grants only.

```sql
CREATE TABLE resource_node (
    tenant_id       text NOT NULL REFERENCES tenant(id),
    ref             text NOT NULL,                       -- "billing.invoice:4711"
    resource_type_id text NOT NULL REFERENCES resource_type(id),
    parent_ref      text,
    path            ltree NOT NULL,                      -- materialized path for subtree queries
    attributes      jsonb NOT NULL DEFAULT '{}',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, ref)
);
CREATE INDEX ON resource_node USING gist (path);
CREATE INDEX ON resource_node USING gin (attributes jsonb_path_ops);
```

Subtree grants are answered with `path <@ :grant_path`, which is index-backed and cheap.

## UI elements

```sql
CREATE TABLE ui_element (
    id              text PRIMARY KEY,                    -- uie_...
    application_id  text NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    key             citext NOT NULL,                     -- "invoices.approve_button"
    label           text NOT NULL,
    description     text,
    surface         text NOT NULL DEFAULT 'web',
    path            text,                                -- "Invoices > Detail > Actions"
    suggested_permission citext,
    resource_type_id text REFERENCES resource_type(id),  -- non-null ⇒ resource-scoped
    default_mode    text NOT NULL DEFAULT 'hidden',      -- hidden|disabled|read_only
    status          text NOT NULL DEFAULT 'declared',    -- declared|discovered|deprecated
    first_seen_at   timestamptz,                         -- discovery mode
    UNIQUE (application_id, key)
);

CREATE TABLE ui_binding (
    id              text PRIMARY KEY,
    tenant_id       text NOT NULL REFERENCES tenant(id),
    ui_element_id   text NOT NULL REFERENCES ui_element(id) ON DELETE CASCADE,
    environment_id  text REFERENCES environment(id),     -- NULL = all environments
    requires        jsonb NOT NULL,                      -- {any_of|all_of: [{permission}|{role}]}
    mode            text NOT NULL DEFAULT 'hidden',
    condition       text,
    message         text,
    version         integer NOT NULL DEFAULT 1,
    updated_by      text REFERENCES app_user(id),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, ui_element_id, environment_id)
);
```

## Audit and decisions

```sql
CREATE TABLE audit_event (
    id              text PRIMARY KEY,
    tenant_id       text REFERENCES tenant(id),
    seq             bigserial,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    actor_user_id   text,
    actor_client_id text,
    impersonator_id text,
    action          text NOT NULL,                       -- "role.updated"
    target_type     text,
    target_id       text,
    before          jsonb,
    after           jsonb,
    reason          text,
    ip              inet,
    user_agent      text,
    request_id      text,
    prev_hash       bytea,
    hash            bytea NOT NULL                       -- sha256(prev_hash || canonical(row))
);
CREATE INDEX ON audit_event (tenant_id, occurred_at DESC);
CREATE INDEX ON audit_event (target_type, target_id);
-- append-only enforced by a BEFORE UPDATE/DELETE trigger that raises

CREATE TABLE decision_event (                            -- partitioned monthly, short retention
    id              text NOT NULL,
    tenant_id       text NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    subject_id      text NOT NULL,
    application_id  text NOT NULL,
    permission_key  citext NOT NULL,
    resource_ref    text,
    allowed         boolean NOT NULL,
    reason          text NOT NULL,
    matched_grant   text,
    latency_us      integer,
    degraded        boolean NOT NULL DEFAULT false,
    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);
```

## Row-level security

Applied to every tenant-scoped table:

```sql
ALTER TABLE app_user ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app_user
    USING (tenant_id = current_setting('warden.tenant_id', true));
```

The service sets `SET LOCAL warden.tenant_id = '...'` at the start of every tenant-scoped
transaction. Cross-tenant work (system administration, background jobs) uses a separate
database role with `BYPASSRLS` and is itself audited.

## Hot-path queries

**Effective roles for a subject at a scope** — one recursive CTE walking group nesting and
role inheritance:

```sql
WITH RECURSIVE my_groups AS (
    SELECT group_id FROM group_member WHERE member_user_id = $1
    UNION
    SELECT gm.group_id FROM group_member gm JOIN my_groups g ON gm.member_group_id = g.group_id
),
my_grants AS (
    SELECT * FROM grant_
    WHERE tenant_id = $2
      AND (subject_user_id = $1 OR subject_group_id IN (SELECT group_id FROM my_groups))
      AND valid_from <= now() AND (valid_until IS NULL OR valid_until > now())
),
role_closure AS (
    SELECT role_id, role_id AS effective FROM my_grants
    UNION
    SELECT rc.role_id, ri.parent_role_id FROM role_closure rc
    JOIN role_inheritance ri ON ri.role_id = rc.effective
)
SELECT DISTINCT effective FROM role_closure;
```

The result is memoized in Redis under `(tenant_id, permission_rev, user_id)` and invalidated
by the revision bump, so this query runs once per subject per policy change — not per check.

## Migrations

Forward-only, expand/contract, one file per change under `migrations/`. Rules:
never drop a column in the same release that stops writing it; add indexes `CONCURRENTLY`;
every migration must be runnable against a live cluster.
