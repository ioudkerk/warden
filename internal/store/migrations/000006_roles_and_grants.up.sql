-- Roles, grants and explicit denials: the tables the decision engine reads.
--
-- Two shapes of role coexist (SPEC §6.1). An application declares role templates
-- once, globally, and a tenant adopts or forks them; a tenant may also define its
-- own. That is why role.tenant_id is nullable — NULL means "belongs to every tenant"
-- — and it makes the row-level security policy on this table different from all the
-- others: a tenant-scoped connection must be able to READ a global template but must
-- never be able to CREATE one. USING and WITH CHECK therefore differ, which is the
-- one place in this schema where the fallback of reusing USING for writes would be
-- actively wrong.

-- ---------------------------------------------------------------------------------
-- role
-- ---------------------------------------------------------------------------------

CREATE TABLE role (
    id               text PRIMARY KEY CHECK (id LIKE 'rol\_%'),

    -- NULL: an application role template or a system role, visible to every tenant.
    -- Set: a role belonging to one tenant.
    tenant_id        text REFERENCES tenant(id),

    application_id   text REFERENCES application(id) ON DELETE CASCADE,
    key              citext NOT NULL,
    name             text NOT NULL,
    description      text,
    type             text NOT NULL,
    forked_from      text REFERENCES role(id),
    template_version integer,

    -- requires_mfa, separation_of_duties_conflicts, max_assignees (SPEC §9.3).
    constraints      jsonb NOT NULL DEFAULT '{}',

    assignable_by    text[] NOT NULL DEFAULT '{}',
    immutable        boolean NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT role_type_valid
        CHECK (type IN ('system', 'application_template', 'tenant_custom')),

    -- A tenant_custom role that belongs to no tenant, or a template that belongs to
    -- one, would each be a contradiction that the loader would have to guess about.
    CONSTRAINT role_scope_matches_type CHECK (
        (type = 'tenant_custom' AND tenant_id IS NOT NULL) OR
        (type IN ('system', 'application_template') AND tenant_id IS NULL)
    ),

    CONSTRAINT role_not_its_own_fork CHECK (forked_from IS DISTINCT FROM id)
);

-- A tenant may fork a template and keep the same key, so uniqueness is per owner.
-- NULLS NOT DISTINCT makes two global roles with the same key collide, which the
-- default NULL handling would otherwise permit.
CREATE UNIQUE INDEX role_owner_key_key
    ON role (tenant_id, application_id, key) NULLS NOT DISTINCT;
CREATE INDEX role_tenant_id_idx ON role (tenant_id);
CREATE INDEX role_application_id_idx ON role (application_id);

-- Lets the child tables below carry their own tenant_id and have Postgres enforce
-- that the two agree. id alone is already unique, so this adds no new restriction.
ALTER TABLE role ADD CONSTRAINT role_id_tenant_key UNIQUE (id, tenant_id);

CREATE TRIGGER role_set_updated_at BEFORE UPDATE ON role
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

COMMENT ON COLUMN role.tenant_id IS
    'NULL for an application template or system role, which every tenant can read but none can modify.';

-- ---------------------------------------------------------------------------------
-- role_inheritance
-- ---------------------------------------------------------------------------------

-- A DAG. Cycles and depth are rejected by the application layer, which has to walk
-- the graph anyway; the database rejects only the one-step cycle, which is the case
-- most likely to arrive from a careless edit.
CREATE TABLE role_inheritance (
    role_id        text NOT NULL,
    parent_role_id text NOT NULL,
    tenant_id      text REFERENCES tenant(id),

    PRIMARY KEY (role_id, parent_role_id),
    CONSTRAINT role_inheritance_no_self_reference CHECK (role_id <> parent_role_id),

    CONSTRAINT role_inheritance_role_fkey FOREIGN KEY (role_id, tenant_id)
        REFERENCES role (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX role_inheritance_parent_idx ON role_inheritance (parent_role_id);
CREATE INDEX role_inheritance_tenant_idx ON role_inheritance (tenant_id);

-- ---------------------------------------------------------------------------------
-- role_permission
-- ---------------------------------------------------------------------------------

CREATE TABLE role_permission (
    role_id        text NOT NULL,
    tenant_id      text REFERENCES tenant(id),

    -- May contain wildcards: billing.invoice:*, billing.*:read, billing.*:*.
    -- Wildcards are legal in a grant and never in a check (SPEC §9.2).
    permission_key citext NOT NULL,

    -- Optional CEL, narrowing this permission alone rather than the whole grant.
    condition      text,

    PRIMARY KEY (role_id, permission_key),

    CONSTRAINT role_permission_well_formed
        CHECK (permission_key ~ '^[^.:[:space:]]+\.(\*|[^.:*[:space:]]+):(\*|[^.:*[:space:]]+)$'),

    CONSTRAINT role_permission_role_fkey FOREIGN KEY (role_id, tenant_id)
        REFERENCES role (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX role_permission_tenant_idx ON role_permission (tenant_id);

-- ---------------------------------------------------------------------------------
-- grant_
-- ---------------------------------------------------------------------------------

CREATE TABLE grant_ (
    id               text PRIMARY KEY CHECK (id LIKE 'grn\_%'),
    tenant_id        text NOT NULL REFERENCES tenant(id),
    subject_user_id  text,
    subject_group_id text,
    role_id          text NOT NULL,

    scope_kind       text NOT NULL,
    scope_ref        text NOT NULL,

    condition        text,
    valid_from       timestamptz NOT NULL DEFAULT now(),
    valid_until      timestamptz,
    granted_by       text,
    reason           text,
    created_at       timestamptz NOT NULL DEFAULT now(),

    -- Declaration order. Where several grants could allow the same check, the
    -- earliest is the one reported as matched_grant — the corpus depends on this
    -- being deterministic, and a timestamp is not, since two grants can share one.
    seq              bigint GENERATED ALWAYS AS IDENTITY,

    CONSTRAINT grant_exactly_one_subject
        CHECK (num_nonnulls(subject_user_id, subject_group_id) = 1),
    CONSTRAINT grant_scope_kind_valid
        CHECK (scope_kind IN ('tenant', 'application', 'environment', 'resource', 'subtree')),
    CONSTRAINT grant_window_ordered
        CHECK (valid_until IS NULL OR valid_until > valid_from),

    CONSTRAINT grant_user_fkey FOREIGN KEY (subject_user_id, tenant_id)
        REFERENCES app_user (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT grant_group_fkey FOREIGN KEY (subject_group_id, tenant_id)
        REFERENCES group_ (id, tenant_id) ON DELETE CASCADE,

    -- A grant may reference a global template (tenant_id NULL on the role) or one of
    -- the tenant's own, so this is a plain reference rather than a composite one.
    CONSTRAINT grant_role_fkey FOREIGN KEY (role_id) REFERENCES role (id) ON DELETE CASCADE
);

CREATE INDEX grant_tenant_user_idx ON grant_ (tenant_id, subject_user_id)
    WHERE subject_user_id IS NOT NULL;
CREATE INDEX grant_tenant_group_idx ON grant_ (tenant_id, subject_group_id)
    WHERE subject_group_id IS NOT NULL;
CREATE INDEX grant_tenant_scope_idx ON grant_ (tenant_id, scope_ref);
CREATE INDEX grant_expiry_idx ON grant_ (valid_until) WHERE valid_until IS NOT NULL;

-- ---------------------------------------------------------------------------------
-- denial
-- ---------------------------------------------------------------------------------

CREATE TABLE denial (
    id               text PRIMARY KEY CHECK (id LIKE 'den\_%'),
    tenant_id        text NOT NULL REFERENCES tenant(id),
    subject_user_id  text,
    subject_group_id text,
    permission_key   citext NOT NULL,
    scope_kind       text NOT NULL,
    scope_ref        text NOT NULL,

    -- Required, not optional: SPEC §9.7 has the console demand a written
    -- justification for every explicit deny, and a deny with no recorded reason is
    -- the hardest kind of authorization decision to unpick a year later.
    reason           text NOT NULL CHECK (length(btrim(reason)) > 0),

    created_by       text,
    created_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT denial_exactly_one_subject
        CHECK (num_nonnulls(subject_user_id, subject_group_id) = 1),
    CONSTRAINT denial_scope_kind_valid
        CHECK (scope_kind IN ('tenant', 'application', 'environment', 'resource', 'subtree')),
    CONSTRAINT denial_permission_well_formed
        CHECK (permission_key ~ '^[^.:[:space:]]+\.(\*|[^.:*[:space:]]+):(\*|[^.:*[:space:]]+)$'),

    CONSTRAINT denial_user_fkey FOREIGN KEY (subject_user_id, tenant_id)
        REFERENCES app_user (id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT denial_group_fkey FOREIGN KEY (subject_group_id, tenant_id)
        REFERENCES group_ (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX denial_tenant_idx ON denial (tenant_id);

-- ---------------------------------------------------------------------------------
-- resource_node
-- ---------------------------------------------------------------------------------

-- Registered resource instances, so that subtree grants cascade and conditions can
-- read attributes the caller did not send (SPEC §9.5, §9.6). An application that does
-- not register its object graph loses the cascade and nothing else.
--
-- data-model.md specifies an ltree materialized path here. That is deferred: ltree
-- labels cannot hold arbitrary identifiers — 'INV/4711'::ltree is a syntax error —
-- and resource ids come from the application's own object space. Encoding ids into
-- valid labels is possible but it is a real design decision, not an implementation
-- detail, so ancestry is resolved with a recursive CTE over parent_ref until that
-- decision is made. Revisit at M7 with the encoding written down.
CREATE TABLE resource_node (
    tenant_id        text NOT NULL REFERENCES tenant(id),
    ref              text NOT NULL,
    resource_type_id text REFERENCES resource_type(id),
    parent_ref       text,
    attributes       jsonb NOT NULL DEFAULT '{}',
    updated_at       timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, ref),

    CONSTRAINT resource_node_not_its_own_parent CHECK (parent_ref IS DISTINCT FROM ref),
    CONSTRAINT resource_node_parent_fkey FOREIGN KEY (tenant_id, parent_ref)
        REFERENCES resource_node (tenant_id, ref) ON DELETE SET NULL (parent_ref)
);

CREATE INDEX resource_node_parent_idx ON resource_node (tenant_id, parent_ref)
    WHERE parent_ref IS NOT NULL;
CREATE INDEX resource_node_attributes_idx ON resource_node USING gin (attributes jsonb_path_ops);

CREATE TRIGGER resource_node_set_updated_at BEFORE UPDATE ON resource_node
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

-- ---------------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------------

-- role, role_inheritance and role_permission each permit a NULL tenant_id meaning
-- "global". A tenant-scoped connection may read those rows and may not write them,
-- so USING and WITH CHECK differ here — the only place in this schema where they do.
ALTER TABLE role ENABLE ROW LEVEL SECURITY;
ALTER TABLE role FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON role
    USING (tenant_id IS NULL OR tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE role_inheritance ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_inheritance FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON role_inheritance
    USING (tenant_id IS NULL OR tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE role_permission ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_permission FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON role_permission
    USING (tenant_id IS NULL OR tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE grant_ ENABLE ROW LEVEL SECURITY;
ALTER TABLE grant_ FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON grant_
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE denial ENABLE ROW LEVEL SECURITY;
ALTER TABLE denial FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON denial
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE resource_node ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_node FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON resource_node
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('role',             true, NULL),
    ('role_inheritance', true, NULL),
    ('role_permission',  true, NULL),
    ('grant_',           true, NULL),
    ('denial',           true, NULL),
    ('resource_node',    true, NULL);
