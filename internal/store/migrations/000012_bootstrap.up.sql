-- Bootstrap: signing keys, the one-time setup token, and the deployment-level roles
-- of SPEC §6.3.
--
-- The theme is that a deployment starts with no usable credential. `warden init`
-- creates the first owner and prints a single-use URL; there is no default password
-- to forget to change, because there is no default password (SPEC §20.2).

-- ---------------------------------------------------------------------------------
-- signing_key
-- ---------------------------------------------------------------------------------

-- The keys Warden signs tokens with. Deployment-level, not tenant-scoped: every
-- tenant's tokens are signed by the same issuer.
CREATE TABLE signing_key (
    id            text PRIMARY KEY CHECK (id LIKE 'key\_%'),

    -- The JWKS key id. Relying parties select a key by this, so it is published and
    -- must never be reused for different material.
    kid           text NOT NULL,

    algorithm     text NOT NULL,

    -- PEM, and deliberately not encrypted: this is the half the world is meant to
    -- have.
    public_key    text NOT NULL,

    -- Envelope ciphertext from internal/secrets. A database copy without the KEK does
    -- not yield the ability to mint tokens, which is the whole point of SPEC §17's
    -- envelope encryption and the first thing in Warden that genuinely needs it.
    private_key   bytea NOT NULL,

    -- Which KEK wrapped it. Derivable from the envelope header, but stored so that
    -- "which keys still need rewrapping?" is an indexed query during a rotation
    -- rather than a scan that decrypts.
    kek_id        text NOT NULL,

    -- active: signs new tokens. previous: still published in JWKS so tokens signed
    -- before the rotation keep verifying (SPEC §17). retired: published no longer.
    status        text NOT NULL DEFAULT 'active',

    created_at    timestamptz NOT NULL DEFAULT now(),
    activated_at  timestamptz,
    retired_at    timestamptz,
    expires_at    timestamptz,

    CONSTRAINT signing_key_algorithm_valid CHECK (algorithm IN ('RS256', 'ES256')),
    CONSTRAINT signing_key_status_valid CHECK (status IN ('active', 'previous', 'retired'))
);

CREATE UNIQUE INDEX signing_key_kid_key ON signing_key (kid);

-- Exactly one active key. Two would make "which key signs this token?" ambiguous, and
-- the ambiguity would only surface as intermittent verification failures at whichever
-- relying party cached the other one.
CREATE UNIQUE INDEX signing_key_one_active ON signing_key ((status)) WHERE status = 'active';

CREATE INDEX signing_key_kek_idx ON signing_key (kek_id);

COMMENT ON TABLE signing_key IS
    'Token signing keys. Private halves are envelope-encrypted under the KEK (SPEC §17); a database copy alone cannot mint tokens.';

-- ---------------------------------------------------------------------------------
-- setup_token
-- ---------------------------------------------------------------------------------

-- The single-use credential `warden init` prints. It exists so that a deployment can
-- be handed to its first owner without ever having had a password.
CREATE TABLE setup_token (
    id           text PRIMARY KEY CHECK (id LIKE 'stk\_%'),
    tenant_id    text NOT NULL REFERENCES tenant(id),
    user_id      text NOT NULL,

    -- SHA-256 of the token. The token itself is printed once and never stored, so
    -- reading the database does not hand over the deployment.
    token_hash   bytea NOT NULL,

    -- Short by default. A setup link that stays valid for a week is a password with
    -- extra steps.
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT setup_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32),

    CONSTRAINT setup_token_user_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES app_user (id, tenant_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX setup_token_hash_key ON setup_token (token_hash);
CREATE INDEX setup_token_user_idx ON setup_token (user_id);

-- ---------------------------------------------------------------------------------
-- Deployment-level permissions and the system roles of SPEC §6.3
-- ---------------------------------------------------------------------------------

INSERT INTO resource_type (id, application_id, key, name) VALUES
    ('rst_warden_tenant',      'app_warden', 'tenant',      'Tenant'),
    ('rst_warden_application', 'app_warden', 'application', 'Application'),
    ('rst_warden_deployment',  'app_warden', 'deployment',  'Deployment');

INSERT INTO action (id, resource_type_id, key, name, implies) VALUES
    ('act_warden_tenant_read',        'rst_warden_tenant',      'read',   'View tenants', '{}'),
    ('act_warden_tenant_manage',      'rst_warden_tenant',      'manage', 'Create and suspend tenants', '{read}'),
    ('act_warden_application_read',   'rst_warden_application', 'read',   'View applications', '{}'),
    ('act_warden_application_manage', 'rst_warden_application', 'manage', 'Publish application manifests', '{read}'),
    ('act_warden_deployment_read',    'rst_warden_deployment',  'read',   'View deployment health and configuration', '{}'),
    ('act_warden_deployment_manage',  'rst_warden_deployment',  'manage', 'Rotate keys and change deployment settings', '{read}');

INSERT INTO permission (id, application_id, key, resource_type_id, action_id) VALUES
    ('prm_warden_tenant_read',        'app_warden', 'warden.tenant:read',        'rst_warden_tenant',      'act_warden_tenant_read'),
    ('prm_warden_tenant_manage',      'app_warden', 'warden.tenant:manage',      'rst_warden_tenant',      'act_warden_tenant_manage'),
    ('prm_warden_application_read',   'app_warden', 'warden.application:read',   'rst_warden_application', 'act_warden_application_read'),
    ('prm_warden_application_manage', 'app_warden', 'warden.application:manage', 'rst_warden_application', 'act_warden_application_manage'),
    ('prm_warden_deployment_read',    'app_warden', 'warden.deployment:read',    'rst_warden_deployment',  'act_warden_deployment_read'),
    ('prm_warden_deployment_manage',  'app_warden', 'warden.deployment:manage',  'rst_warden_deployment',  'act_warden_deployment_manage');

-- SPEC §6.3 writes these with a colon — system:owner. A colon separates a resource
-- from an action in a permission, so the keys use a dot, matching tenant.owner.
INSERT INTO role (id, tenant_id, application_id, key, name, description, type, immutable) VALUES
    ('rol_system_owner',    NULL, 'app_warden', 'system.owner',    'Deployment Owner',
     'Full control of the deployment, including key rotation and every tenant.', 'system', true),
    ('rol_system_operator', NULL, 'app_warden', 'system.operator', 'Deployment Operator',
     'Runs the deployment: creates tenants, publishes application manifests.', 'system', true),
    ('rol_system_auditor',  NULL, 'app_warden', 'system.auditor',  'Deployment Auditor',
     'Reads the audit log across every tenant. Changes nothing.', 'system', true),
    ('rol_system_support',  NULL, 'app_warden', 'system.support',  'Deployment Support',
     'Read-only across tenants. SPEC §6.3 additionally requires an approved support session with a reason and an expiry; that gate is not built yet, so this role is declared and should not be assigned until it is.', 'system', true);

INSERT INTO role_permission (role_id, tenant_id, permission_key) VALUES
    ('rol_system_owner', NULL, 'warden.tenant:manage'),
    ('rol_system_owner', NULL, 'warden.application:manage'),
    ('rol_system_owner', NULL, 'warden.deployment:manage'),
    ('rol_system_owner', NULL, 'warden.role:assign_any'),
    ('rol_system_owner', NULL, 'warden.audit:read'),

    ('rol_system_operator', NULL, 'warden.tenant:manage'),
    ('rol_system_operator', NULL, 'warden.application:manage'),
    ('rol_system_operator', NULL, 'warden.deployment:read'),
    ('rol_system_operator', NULL, 'warden.role:assign'),

    ('rol_system_auditor', NULL, 'warden.audit:read'),

    ('rol_system_support', NULL, 'warden.tenant:read'),
    ('rol_system_support', NULL, 'warden.application:read'),
    ('rol_system_support', NULL, 'warden.deployment:read');

-- ---------------------------------------------------------------------------------
-- Reserved slugs
-- ---------------------------------------------------------------------------------

-- 'system' names the deployment's own tenant. A customer tenant taking that slug
-- would make the deployment's administrators indistinguishable from one customer's,
-- which is the kind of confusion that is discovered late and fixed expensively.
ALTER TABLE tenant ADD CONSTRAINT tenant_slug_not_reserved
    CHECK (id = 'ten_system' OR slug NOT IN ('system', 'warden', 'admin', 'internal'));

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('signing_key', false,
     'Deployment-level: one issuer signs every tenant''s tokens. Holds no tenant data.'),
    ('setup_token', false,
     'Resolving a setup token to its user necessarily happens before any tenant scope exists, as with service_account. Single-use, short-lived, and read through the system pool only.');
