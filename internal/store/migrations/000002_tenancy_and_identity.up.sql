-- Tenancy and identity: the tenant boundary, users, their credentials, their links
-- to external identity providers, and their sessions.
--
-- Row-level security is NOT enabled here. It is added by the next migration, along
-- with the connection wrapper that sets warden.tenant_id and the sweep that proves
-- isolation holds (task M0-6). Until then, tenant scoping rests on application-level
-- filtering alone.

-- ---------------------------------------------------------------------------------
-- tenant
-- ---------------------------------------------------------------------------------

CREATE TABLE tenant (
    id              text PRIMARY KEY CHECK (id LIKE 'ten\_%'),
    slug            citext NOT NULL,
    name            text NOT NULL,
    status          text NOT NULL DEFAULT 'active',
    settings        jsonb NOT NULL DEFAULT '{}',

    -- Bumped by every write that can change an authorization outcome. It is the
    -- basis of the consistency token (SPEC §10.5) and the cache key of every
    -- memoized role resolution, so it is a bigint rather than an int: at one bump
    -- per millisecond it still has 290 million years of headroom.
    permission_rev  bigint NOT NULL DEFAULT 1,

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,

    CONSTRAINT tenant_status_valid CHECK (status IN ('active', 'suspended', 'deleted'))
);

-- Slugs appear in URLs and login hints, so uniqueness must survive a soft delete
-- being reversed; the constraint covers live and deleted rows alike.
CREATE UNIQUE INDEX tenant_slug_key ON tenant (slug);

CREATE TRIGGER tenant_set_updated_at BEFORE UPDATE ON tenant
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

COMMENT ON TABLE tenant IS 'An isolated customer space. The isolation boundary for users, roles and assignments (SPEC §6).';
COMMENT ON COLUMN tenant.permission_rev IS 'Incremented on every authorization-affecting write; the consistency token (SPEC §10.5).';

-- ---------------------------------------------------------------------------------
-- app_user
-- ---------------------------------------------------------------------------------

-- Named app_user because "user" is reserved in Postgres and in a good deal of
-- tooling; writing quoted "user" everywhere is worse than a prefix.
CREATE TABLE app_user (
    id              text PRIMARY KEY CHECK (id LIKE 'usr\_%'),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    email           citext NOT NULL,
    email_verified  boolean NOT NULL DEFAULT false,
    display_name    text,
    status          text NOT NULL DEFAULT 'invited',

    -- Mapped from IdP claims (SPEC §7.5) and readable from condition expressions as
    -- subject.attributes.* (SPEC §9.6).
    attributes      jsonb NOT NULL DEFAULT '{}',

    mfa_enforced    boolean NOT NULL DEFAULT false,
    last_login_at   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,

    CONSTRAINT app_user_status_valid
        CHECK (status IN ('invited', 'active', 'suspended', 'deprovisioned'))
);

-- A subject exists within exactly one tenant (SPEC §6.2), so email is unique per
-- tenant and not globally. citext makes the comparison case-insensitive, which is
-- what stops Alice@example.com and alice@example.com becoming two accounts.
CREATE UNIQUE INDEX app_user_tenant_email_key ON app_user (tenant_id, email);

-- Redundant against the primary key, but it is what lets a child table carry its own
-- tenant_id and have Postgres enforce that the two agree. See credential below.
ALTER TABLE app_user ADD CONSTRAINT app_user_id_tenant_key UNIQUE (id, tenant_id);
CREATE INDEX app_user_tenant_id_idx ON app_user (tenant_id);
CREATE INDEX app_user_attributes_idx ON app_user USING gin (attributes jsonb_path_ops);

CREATE TRIGGER app_user_set_updated_at BEFORE UPDATE ON app_user
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

COMMENT ON COLUMN app_user.status IS
    'invited → active → suspended → deprovisioned (SPEC §7.6). Anything but active denies every decision.';

-- ---------------------------------------------------------------------------------
-- credential
-- ---------------------------------------------------------------------------------

CREATE TABLE credential (
    id              text PRIMARY KEY CHECK (id LIKE 'crd\_%'),
    user_id         text NOT NULL,

    -- Denormalized from app_user. A credential is only reachable through its user,
    -- so this column is redundant for querying — it exists so that row-level
    -- security is a column comparison rather than a subquery against the parent.
    -- An RLS policy containing EXISTS runs per row and would put a join on the
    -- authentication path. The composite foreign key below makes the denormalization
    -- safe: Postgres, not application code, guarantees the two tenants agree.
    tenant_id       text NOT NULL REFERENCES tenant(id),

    type            text NOT NULL,

    -- An Argon2id PHC string, an encrypted TOTP seed, or a COSE public key. Never a
    -- reversible encoding of a password.
    secret_hash     text NOT NULL,

    params          jsonb NOT NULL DEFAULT '{}',
    label           text,
    last_used_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,

    CONSTRAINT credential_type_valid
        CHECK (type IN ('password', 'totp', 'webauthn', 'recovery_code')),

    CONSTRAINT credential_user_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES app_user (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX credential_tenant_id_idx ON credential (tenant_id);

-- One password per user; any number of second factors and recovery codes.
CREATE UNIQUE INDEX credential_one_password_per_user
    ON credential (user_id) WHERE type = 'password';
CREATE INDEX credential_user_id_type_idx ON credential (user_id, type);

-- ---------------------------------------------------------------------------------
-- idp_connection
-- ---------------------------------------------------------------------------------

CREATE TABLE idp_connection (
    id              text PRIMARY KEY CHECK (id LIKE 'idp\_%'),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    kind            text NOT NULL,
    name            text NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,

    -- Defaults to false, and the console warns loudly when it is enabled. With an
    -- upstream provider that does not verify email addresses, trusting the asserted
    -- address is an account-takeover primitive (SPEC §7.4.1, threat 2 in §17.1).
    email_trusted   boolean NOT NULL DEFAULT false,

    jit_policy      text NOT NULL DEFAULT 'create',
    domain_hints    text[] NOT NULL DEFAULT '{}',

    -- Endpoints, entity ids and certificates. Secret members (client_secret, SP
    -- decryption key) are stored as envelope ciphertext from internal/secrets, never
    -- as plaintext JSON.
    config          jsonb NOT NULL,

    mapping         jsonb NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT idp_connection_kind_valid CHECK (kind IN ('oidc', 'saml', 'local')),
    CONSTRAINT idp_connection_jit_policy_valid
        CHECK (jit_policy IN ('create', 'link_only', 'deny_unknown'))
);

CREATE UNIQUE INDEX idp_connection_tenant_name_key ON idp_connection (tenant_id, name);
CREATE INDEX idp_connection_tenant_id_idx ON idp_connection (tenant_id);

COMMENT ON COLUMN idp_connection.email_trusted IS
    'Allows linking a federated login to a local account by email. A known account-takeover vector when the upstream IdP does not verify addresses (SPEC §7.4.1). Defaults to false.';

-- ---------------------------------------------------------------------------------
-- identity
-- ---------------------------------------------------------------------------------

CREATE TABLE identity (
    id                text PRIMARY KEY CHECK (id LIKE 'idn\_%'),
    tenant_id         text NOT NULL REFERENCES tenant(id),
    user_id           text NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    connection_id     text NOT NULL REFERENCES idp_connection(id),
    external_subject  text NOT NULL,

    -- The claims as last seen. Kept for debugging a mapping that is not producing
    -- the groups an administrator expects; not read during a decision.
    raw_claims        jsonb NOT NULL DEFAULT '{}',

    linked_at         timestamptz NOT NULL DEFAULT now()
);

-- Step 1 of the linking rules (SPEC §7.4.1): an external subject maps to exactly one
-- local user, per connection.
CREATE UNIQUE INDEX identity_connection_subject_key
    ON identity (connection_id, external_subject);
CREATE INDEX identity_user_id_idx ON identity (user_id);
CREATE INDEX identity_tenant_id_idx ON identity (tenant_id);

-- ---------------------------------------------------------------------------------
-- session
-- ---------------------------------------------------------------------------------

CREATE TABLE session (
    id              text PRIMARY KEY CHECK (id LIKE 'ses\_%'),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    user_id         text NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,

    -- Authentication methods used, as an OIDC amr claim: pwd, otp, webauthn,
    -- impersonation.
    amr             text[] NOT NULL DEFAULT '{}',

    auth_time       timestamptz NOT NULL,
    ip              inet,
    user_agent      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz
);

-- The "active sessions" list and "log out everywhere" both walk this.
CREATE INDEX session_user_active_idx ON session (user_id) WHERE revoked_at IS NULL;
CREATE INDEX session_tenant_id_idx ON session (tenant_id);
CREATE INDEX session_expires_at_idx ON session (expires_at) WHERE revoked_at IS NULL;

-- Supports refresh_token's composite foreign key; see credential above.
ALTER TABLE session ADD CONSTRAINT session_id_tenant_key UNIQUE (id, tenant_id);

COMMENT ON TABLE session IS
    'The browser-level SSO artifact (sid). Survives token refresh; the target of "log out everywhere". Mirrored from Redis for the active-sessions UI (SPEC §8.3).';

-- ---------------------------------------------------------------------------------
-- refresh_token
-- ---------------------------------------------------------------------------------

CREATE TABLE refresh_token (
    id              text PRIMARY KEY CHECK (id LIKE 'rft\_%'),
    session_id      text NOT NULL,

    -- Denormalized from session for row-level security; see credential above.
    tenant_id       text NOT NULL REFERENCES tenant(id),

    -- Rotation family. Presenting an already-consumed token revokes the entire
    -- family and raises a security event (SPEC §8.3, threat 7 in §17.1).
    family_id       text NOT NULL,

    -- SHA-256 of the token. Stored as bytea rather than text so a length check is
    -- meaningful and no encoding ambiguity can make two hashes compare unequal.
    token_hash      bytea NOT NULL,

    client_id       text NOT NULL,
    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    revoked_at      timestamptz,

    CONSTRAINT refresh_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32),

    CONSTRAINT refresh_token_session_fkey FOREIGN KEY (session_id, tenant_id)
        REFERENCES session (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX refresh_token_tenant_id_idx ON refresh_token (tenant_id);

CREATE UNIQUE INDEX refresh_token_hash_key ON refresh_token (token_hash);
CREATE INDEX refresh_token_family_idx ON refresh_token (family_id);
CREATE INDEX refresh_token_session_idx ON refresh_token (session_id);
CREATE INDEX refresh_token_expires_at_idx ON refresh_token (expires_at)
    WHERE revoked_at IS NULL AND consumed_at IS NULL;
