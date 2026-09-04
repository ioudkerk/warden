-- UI element binding (SPEC §11): the mapping between a component and the permission
-- required to see it, held on the server and editable by an administrator.
--
-- This is the feature that makes Warden more than an identity server. A developer
-- gives a component a stable key and never touches it again; which roles see it, and
-- whether "not allowed" means hidden, disabled or read-only, is administered at
-- runtime.
--
-- It is emphatically not a security boundary (SPEC §2.3). Hiding a button is a UX
-- decision, and the action behind it is still checked server-side. The schema cannot
-- enforce that, but the naming can avoid implying otherwise: nothing here is called a
-- permission or a grant.

-- ---------------------------------------------------------------------------------
-- ui_element — what an application declares
-- ---------------------------------------------------------------------------------

-- Global, like the rest of an application's declared surface: an application says
-- once that it has an "approve invoice" button, and every tenant that enrolls sees
-- it in the console.
CREATE TABLE ui_element (
    id                   text PRIMARY KEY CHECK (id LIKE 'uie\_%'),
    application_id       text NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    key                  citext NOT NULL,
    label                text NOT NULL,
    description          text,

    -- web, mobile, cli. One application may have several surfaces with the same
    -- element key meaning different things.
    surface              text NOT NULL DEFAULT 'web',

    -- Where a human would find it: "Invoices > Detail > Actions". For the console's
    -- tree, so an administrator binding an element knows what they are looking at.
    path                 text,

    -- What the developer thinks it needs. A suggestion, not a rule: the binding is
    -- what decides, and an administrator may bind it to something else entirely.
    suggested_permission citext,

    -- Non-null means the element must be evaluated per object, so it cannot be
    -- answered by the eager bundle and is returned in `deferred` instead.
    resource_type_id     text REFERENCES resource_type(id),

    -- What happens before an administrator has bound anything, so an application is
    -- functional the moment it is enrolled (SPEC §11.2).
    default_mode         text NOT NULL DEFAULT 'hidden',

    -- declared: from a manifest. discovered: reported by discovery mode (SPEC §11.5)
    -- and awaiting promotion. deprecated: still bound, no longer declared.
    status               text NOT NULL DEFAULT 'declared',
    first_seen_at        timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ui_element_default_mode_valid
        CHECK (default_mode IN ('hidden', 'disabled', 'read_only')),
    CONSTRAINT ui_element_status_valid
        CHECK (status IN ('declared', 'discovered', 'deprecated')),
    CONSTRAINT ui_element_key_well_formed
        CHECK (key ~ '^[a-z0-9][a-z0-9_.-]*$' AND length(key) > 0)
);

CREATE UNIQUE INDEX ui_element_application_key_key ON ui_element (application_id, key);
CREATE INDEX ui_element_status_idx ON ui_element (status) WHERE status <> 'declared';

CREATE TRIGGER ui_element_set_updated_at BEFORE UPDATE ON ui_element
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

COMMENT ON COLUMN ui_element.default_mode IS
    'Applies until an administrator binds the element, so an application works the moment it is enrolled (SPEC §11.2).';
COMMENT ON COLUMN ui_element.resource_type_id IS
    'Non-null means per-object evaluation: the element is returned in the bundle''s deferred list and resolved through POST /v1/ui/resolve.';

-- ---------------------------------------------------------------------------------
-- ui_binding — what an administrator decides
-- ---------------------------------------------------------------------------------

CREATE TABLE ui_binding (
    id             text PRIMARY KEY CHECK (id LIKE 'uib\_%'),
    tenant_id      text NOT NULL REFERENCES tenant(id),
    ui_element_id  text NOT NULL REFERENCES ui_element(id) ON DELETE CASCADE,

    -- NULL means every environment. Bindings are environment-scoped so a change is
    -- testable in staging and promoted (SPEC §11.3).
    environment_id text REFERENCES environment(id),

    -- {"any_of": [{"permission": "..."}, {"role": "..."}]} or {"all_of": [...]}.
    requires       jsonb NOT NULL,

    -- What "not allowed" looks like: not rendered, rendered but inert, or rendered
    -- read-only. A distinct decision from whether the subject qualifies.
    mode           text NOT NULL DEFAULT 'hidden',

    -- Optional CEL, evaluated with the same context as any other condition.
    condition      text,

    -- Shown as a tooltip when the mode is disabled. "Only pending invoices can be
    -- approved" is a better interface than a button that does nothing.
    message        text,

    version        integer NOT NULL DEFAULT 1,
    updated_by     text,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ui_binding_mode_valid CHECK (mode IN ('hidden', 'disabled', 'read_only')),

    -- A requires clause that is neither any_of nor all_of would silently match
    -- nothing, which reads as "the administrator hid it" rather than "the binding is
    -- malformed".
    CONSTRAINT ui_binding_requires_well_formed CHECK (
        (requires ? 'any_of' AND jsonb_typeof(requires -> 'any_of') = 'array') OR
        (requires ? 'all_of' AND jsonb_typeof(requires -> 'all_of') = 'array')
    ),

    CONSTRAINT ui_binding_user_fkey FOREIGN KEY (updated_by, tenant_id)
        REFERENCES app_user (id, tenant_id) ON DELETE SET NULL (updated_by)
);

-- One binding per element per environment. NULLS NOT DISTINCT so two "all
-- environments" bindings for the same element collide rather than both applying with
-- whichever the query happens to return first.
CREATE UNIQUE INDEX ui_binding_scope_key
    ON ui_binding (tenant_id, ui_element_id, environment_id) NULLS NOT DISTINCT;
CREATE INDEX ui_binding_tenant_idx ON ui_binding (tenant_id);

CREATE TRIGGER ui_binding_set_updated_at BEFORE UPDATE ON ui_binding
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

ALTER TABLE ui_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE ui_binding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ui_binding
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

-- Administering the UI surface is itself something to authorize.
INSERT INTO resource_type (id, application_id, key, name) VALUES
    ('rst_warden_ui', 'app_warden', 'ui', 'UI element binding');
INSERT INTO action (id, resource_type_id, key, name, implies) VALUES
    ('act_warden_ui_read', 'rst_warden_ui', 'read', 'View UI element bindings', '{}'),
    ('act_warden_ui_bind', 'rst_warden_ui', 'bind', 'Change what a UI element requires', '{read}');
INSERT INTO permission (id, application_id, key, resource_type_id, action_id) VALUES
    ('prm_warden_ui_read', 'app_warden', 'warden.ui:read', 'rst_warden_ui', 'act_warden_ui_read'),
    ('prm_warden_ui_bind', 'app_warden', 'warden.ui:bind', 'rst_warden_ui', 'act_warden_ui_bind');

-- The administrator role gains it; deciding which staff see which button is
-- day-to-day administration rather than an owner-only act.
INSERT INTO role_permission (role_id, tenant_id, permission_key) VALUES
    ('rol_tenant_admin', NULL, 'warden.ui:bind'),
    ('rol_tenant_auditor', NULL, 'warden.ui:read'),
    ('rol_system_support', NULL, 'warden.ui:read');

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('ui_binding', true, NULL),
    ('ui_element', false,
     'Part of an application''s declared surface, published once and adopted by every tenant (SPEC §6.1). What a tenant decides about an element is the binding, and that is tenant-scoped.');
