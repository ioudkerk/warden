-- The device authorization grant (RFC 8628, SPEC §7.7): how a thing with no browser
-- gets a token.
--
-- A television, a CLI, a printer. The device asks for two codes, shows the human-typable
-- one on its screen, and polls; the person opens a browser somewhere else, signs in and
-- approves; the next poll returns tokens. Two credentials with very different jobs, which
-- is why they are two columns rather than one:
--
--   * the device code is a machine credential, full entropy, never shown to a person;
--   * the user code is typed by hand, so it is short, and its shortness is exactly why
--     the verification endpoint has to rate-limit guesses (§5.1).
--
-- Not folded into oauth_session, which holds fosite's serialized requests keyed by a
-- signature. This has a state machine — pending, approved, denied, redeemed — a polling
-- interval and an approving session, and modelling that as a serialized blob would put
-- the transitions somewhere they cannot be constrained.

CREATE TABLE device_authorization (
    id              text PRIMARY KEY CHECK (id LIKE 'dev\_%'),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    client_id       text NOT NULL REFERENCES oauth_client(id) ON DELETE CASCADE,

    -- Hashed, both of them, like every other credential in the schema. The user code is
    -- short enough to be typed, which makes it weak enough to be worth hashing anyway:
    -- a database copy should not hand over a set of authorizations waiting to be claimed.
    device_code_hash bytea NOT NULL,
    user_code_hash   bytea NOT NULL,

    requested_scope    text[] NOT NULL DEFAULT '{}',
    granted_scope      text[] NOT NULL DEFAULT '{}',
    requested_audience text[] NOT NULL DEFAULT '{}',
    granted_audience   text[] NOT NULL DEFAULT '{}',

    -- pending  — shown on the device, nobody has answered yet
    -- approved — a person signed in and said yes; the next poll gets tokens
    -- denied   — a person said no, which is not the same as never having answered
    -- redeemed — the tokens have been issued; a second presentation is a replay
    status          text NOT NULL DEFAULT 'pending',

    -- Who approved it, and from which browser session. The session is what ties the
    -- issued tokens to a logout: without it, signing out would leave a television
    -- holding a live refresh token.
    subject         text NOT NULL DEFAULT '',
    session_id      text,

    -- The minimum gap between polls, in seconds, as RFC 8628 §3.2's `interval`.
    interval_seconds integer NOT NULL DEFAULT 5,
    last_polled_at  timestamptz,

    approved_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,

    CONSTRAINT device_authorization_status_valid
        CHECK (status IN ('pending', 'approved', 'denied', 'redeemed')),
    CONSTRAINT device_authorization_device_hash_is_sha256
        CHECK (octet_length(device_code_hash) = 32),
    CONSTRAINT device_authorization_user_hash_is_sha256
        CHECK (octet_length(user_code_hash) = 32),
    -- An approved row names the person who approved it. Without this, "approved" could
    -- mean "approved by nobody", and the grant would issue a token with no subject.
    CONSTRAINT device_authorization_approved_has_subject
        CHECK (status <> 'approved' OR (subject <> '' AND session_id IS NOT NULL)),
    CONSTRAINT device_authorization_interval_positive
        CHECK (interval_seconds > 0)
);

-- Unique across the deployment, not per tenant. Both codes are presented with nothing
-- else attached — the device polls with a device code, the person types a user code —
-- so a collision between two tenants would be a collision at the one moment it matters.
CREATE UNIQUE INDEX device_authorization_device_code_key
    ON device_authorization (device_code_hash);
CREATE UNIQUE INDEX device_authorization_user_code_key
    ON device_authorization (user_code_hash);

CREATE INDEX device_authorization_tenant_idx ON device_authorization (tenant_id);
CREATE INDEX device_authorization_expiry_idx ON device_authorization (expires_at);

COMMENT ON TABLE device_authorization IS
    'RFC 8628 device grant state (SPEC §7.7). One row per device authorization, from the device''s request to the moment its tokens are issued.';
COMMENT ON COLUMN device_authorization.user_code_hash IS
    'SHA-256 of the code a person types. Short by necessity, so the verification endpoint rate-limits guesses (RFC 8628 §5.1).';

-- ---------------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------------
--
-- Tenant-scoped with no exception, and it works out because both lookups have a tenant
-- before they need one: the device polls with a client_id, which resolves to a tenant the
-- same way every token request does, and the person verifying a code is signed in, so
-- their session says which tenant they are in.

ALTER TABLE device_authorization ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_authorization FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_authorization
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('device_authorization', true, NULL);
