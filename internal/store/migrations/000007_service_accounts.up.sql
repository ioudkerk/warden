-- Service accounts: the credential an application uses to ask Warden questions.
--
-- Without this, /v1/authz/check is open to anyone who can reach the port. That is
-- worse than it first appears: the endpoint takes a subject id, so an unauthenticated
-- caller could ask about any user, and the answers describe the policy — which roles
-- exist, which grants bite, which conditions fail. Authorization answers are
-- themselves sensitive.
--
-- A service account belongs to a tenant, and the tenant it belongs to is the only one
-- it can ask about. That is enforced in the API layer rather than left to the caller
-- to get right.

CREATE TABLE service_account (
    id           text PRIMARY KEY CHECK (id LIKE 'svc\_%'),
    tenant_id    text NOT NULL REFERENCES tenant(id),
    name         text NOT NULL,

    -- SHA-256 of the token. The token itself is shown once at creation and never
    -- stored, so a database copy does not hand over the ability to impersonate the
    -- application (SPEC §8.4).
    token_hash   bytea NOT NULL,

    -- The application whose questions this account may ask. NULL means any.
    application_id text REFERENCES application(id) ON DELETE CASCADE,

    disabled_at  timestamptz,
    expires_at   timestamptz,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT service_account_hash_is_sha256 CHECK (octet_length(token_hash) = 32)
);

-- The lookup on every request: by hash, to find the account. Unique so two accounts
-- cannot share a token.
CREATE UNIQUE INDEX service_account_token_hash_key ON service_account (token_hash);
CREATE INDEX service_account_tenant_idx ON service_account (tenant_id);
CREATE UNIQUE INDEX service_account_tenant_name_key ON service_account (tenant_id, name);

-- Not tenant-scoped in the row-level-security sense: authentication has to find the
-- account *before* it knows which tenant to scope to, which is the one lookup that
-- cannot itself be inside a tenant scope. It is therefore read through the system
-- pool only, and the registry records that.
INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('service_account', false,
     'Authentication resolves a token to a tenant, so this lookup necessarily runs before a tenant scope exists. Read through the system pool only; every row names the tenant it authenticates for.');
