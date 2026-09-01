-- Applications and the permission surface.
--
-- Applications are defined globally — an app declares its resources, actions and UI
-- elements once — and enrolled per tenant (SPEC §6.1). Nothing in this migration is
-- tenant-scoped except app_enrollment, which is the join.

-- ---------------------------------------------------------------------------------
-- application
-- ---------------------------------------------------------------------------------

CREATE TABLE application (
    id               text PRIMARY KEY CHECK (id LIKE 'app\_%'),
    key              citext NOT NULL,
    name             text NOT NULL,

    -- Incremented by each accepted `warden sync`; the console shows manifest history
    -- and diffs against it (SPEC §15.2).
    manifest_version integer NOT NULL DEFAULT 0,

    -- What the SDK does when the PDP is unreachable (SPEC §10.6). Defaults to
    -- closed: an application that has expressed no preference denies rather than
    -- allows.
    fail_mode        text NOT NULL DEFAULT 'closed',

    cache_mode       text NOT NULL DEFAULT 'cached',
    decision_log     text NOT NULL DEFAULT 'denies',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT application_fail_mode_valid
        CHECK (fail_mode IN ('closed', 'open_read', 'stale')),
    CONSTRAINT application_cache_mode_valid
        CHECK (cache_mode IN ('remote', 'cached', 'embedded')),
    CONSTRAINT application_decision_log_valid
        CHECK (decision_log IN ('off', 'denies', 'sampled', 'all')),

    -- The key is the first segment of every permission this application owns
    -- ("billing" in billing.invoice:approve). A dot or a colon in it would make the
    -- permission string ambiguous to parse.
    CONSTRAINT application_key_has_no_separators
        CHECK (key !~ '[.:*[:space:]]' AND length(key) > 0)
);

CREATE UNIQUE INDEX application_key_key ON application (key);

CREATE TRIGGER application_set_updated_at BEFORE UPDATE ON application
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

COMMENT ON COLUMN application.fail_mode IS
    'PDP unreachable behaviour: closed denies, open_read allows previously-allowed reads, stale serves expired cache entries (SPEC §10.6).';

-- ---------------------------------------------------------------------------------
-- environment
-- ---------------------------------------------------------------------------------

CREATE TABLE environment (
    id             text PRIMARY KEY CHECK (id LIKE 'env\_%'),
    application_id text NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    name           text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT environment_name_valid CHECK (name IN ('dev', 'staging', 'prod'))
);

CREATE UNIQUE INDEX environment_application_name_key ON environment (application_id, name);

COMMENT ON TABLE environment IS
    'A slice of an application''s configuration. UI bindings are environment-scoped so a change is testable in staging and promoted (SPEC §11.3).';

-- ---------------------------------------------------------------------------------
-- app_enrollment
-- ---------------------------------------------------------------------------------

CREATE TABLE app_enrollment (
    tenant_id      text NOT NULL REFERENCES tenant(id),
    application_id text NOT NULL REFERENCES application(id),
    enrolled_at    timestamptz NOT NULL DEFAULT now(),
    settings       jsonb NOT NULL DEFAULT '{}',

    PRIMARY KEY (tenant_id, application_id)
);

CREATE INDEX app_enrollment_application_idx ON app_enrollment (application_id);

COMMENT ON TABLE app_enrollment IS
    'A tenant using an application. Enrolling inherits the application''s role templates as a starting point (SPEC §6.1).';

-- ---------------------------------------------------------------------------------
-- resource_type
-- ---------------------------------------------------------------------------------

CREATE TABLE resource_type (
    id               text PRIMARY KEY CHECK (id LIKE 'rst\_%'),
    application_id   text NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    key              citext NOT NULL,
    name             text NOT NULL,

    -- Declares the hierarchy: invoice.parent = project means a grant on a project
    -- cascades to its invoices (SPEC §9.5). An application that does not want to
    -- mirror its object graph leaves this null and loses only the cascade.
    parent_type_id   text REFERENCES resource_type(id),

    -- JSON Schema for resource.attributes, so a condition referencing an attribute
    -- the application never sends can be caught at sync time rather than denying in
    -- production.
    attribute_schema jsonb NOT NULL DEFAULT '{}',

    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT resource_type_key_has_no_separators
        CHECK (key !~ '[.:*[:space:]]' AND length(key) > 0),
    CONSTRAINT resource_type_not_own_parent CHECK (parent_type_id IS DISTINCT FROM id)
);

CREATE UNIQUE INDEX resource_type_application_key_key ON resource_type (application_id, key);
CREATE INDEX resource_type_parent_idx ON resource_type (parent_type_id)
    WHERE parent_type_id IS NOT NULL;

CREATE TRIGGER resource_type_set_updated_at BEFORE UPDATE ON resource_type
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

-- ---------------------------------------------------------------------------------
-- action
-- ---------------------------------------------------------------------------------

CREATE TABLE action (
    id               text PRIMARY KEY CHECK (id LIKE 'act\_%'),
    resource_type_id text NOT NULL REFERENCES resource_type(id) ON DELETE CASCADE,
    key              citext NOT NULL,
    name             text NOT NULL,

    -- Other action keys on the same resource type: manage implies read, write,
    -- delete. Expanded into the materialized closure at grant time, never at check
    -- time (SPEC §9.2), so the hot path never walks this.
    implies          text[] NOT NULL DEFAULT '{}',

    created_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT action_key_has_no_separators
        CHECK (key !~ '[.:*[:space:]]' AND length(key) > 0),
    CONSTRAINT action_does_not_imply_itself CHECK (NOT (key::text = ANY (implies)))
);

CREATE UNIQUE INDEX action_resource_type_key_key ON action (resource_type_id, key);

-- ---------------------------------------------------------------------------------
-- permission
-- ---------------------------------------------------------------------------------

-- The materialized permission atom: one row per (resource type, action) pair, keyed
-- by the string applications actually write, "billing.invoice:approve". Materializing
-- it means a check does a single indexed lookup instead of parsing and joining.
CREATE TABLE permission (
    id               text PRIMARY KEY CHECK (id LIKE 'prm\_%'),
    application_id   text NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    key              citext NOT NULL,
    resource_type_id text NOT NULL REFERENCES resource_type(id) ON DELETE CASCADE,
    action_id        text NOT NULL REFERENCES action(id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL DEFAULT now(),

    -- app.resource:action, with no wildcards. Wildcards are legal in grants and
    -- never in the permission surface itself (SPEC §9.2).
    CONSTRAINT permission_key_well_formed
        CHECK (key ~ '^[^.:*[:space:]]+\.[^.:*[:space:]]+:[^.:*[:space:]]+$')
);

CREATE UNIQUE INDEX permission_application_key_key ON permission (application_id, key);

-- A check resolves a permission string with no application context, so the global
-- lookup is the one that matters on the hot path.
CREATE UNIQUE INDEX permission_key_key ON permission (key);
CREATE UNIQUE INDEX permission_resource_action_key ON permission (resource_type_id, action_id);

COMMENT ON TABLE permission IS
    'The atom of authorization: app.resource:action. Materialized from resource_type × action at sync time (SPEC §9.2).';
