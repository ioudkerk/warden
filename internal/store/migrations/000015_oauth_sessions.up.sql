-- Storage for the OpenID Provider (SPEC §7.7): the short-lived artifacts fosite needs
-- to keep between one request and the next.
--
-- One table for several kinds — authorization codes, access tokens, PKCE challenges,
-- OIDC sessions, pushed authorization requests, client-assertion identifiers — because
-- they are the same shape. Each is a serialized request keyed by a signature, with a
-- lifetime. Six tables would differ only in the value of `kind`.
--
-- **Refresh tokens are deliberately absent from this table.** They live in
-- refresh_token, which M1-5 built with the family rotation and reuse detection SPEC §8.3
-- requires. fosite's refresh storage is implemented against that table instead, so there
-- is one row per refresh token carrying both the protocol payload and the family state.
-- Two parallel systems would have meant rotation without family revocation, which is the
-- half that actually defends against a stolen token.

CREATE TABLE oauth_session (
    -- fosite's key. It is the *signature* half of a token, not the token: fosite splits
    -- what it issues into a public part and a signature, hands the whole thing to the
    -- client, and gives the server only the signature to store. Hashed here anyway, on
    -- the same principle as every other credential in the schema — a database copy
    -- should not be a set of working tokens.
    signature_hash  bytea NOT NULL,

    kind            text NOT NULL,
    tenant_id       text NOT NULL REFERENCES tenant(id),

    -- fosite's own request id, which ties an access token to the authorization code it
    -- came from. Revocation by request id is how a detected reuse reaches every
    -- artifact of one exchange.
    request_id      text NOT NULL,

    client_id       text NOT NULL REFERENCES oauth_client(id) ON DELETE CASCADE,

    -- The end user, empty for client-credentials and for the artifacts that precede
    -- authentication.
    subject         text NOT NULL DEFAULT '',

    -- The Warden session (sid) this artifact belongs to, so that ending a session ends
    -- the tokens issued through it. Null for flows with no browser session behind them.
    session_id      text,

    requested_scope     text[] NOT NULL DEFAULT '{}',
    granted_scope       text[] NOT NULL DEFAULT '{}',
    requested_audience  text[] NOT NULL DEFAULT '{}',
    granted_audience    text[] NOT NULL DEFAULT '{}',

    -- The request form and the fosite session, as fosite serializes them.
    form            jsonb NOT NULL DEFAULT '{}',
    session_data    jsonb NOT NULL DEFAULT '{}',

    -- An authorization code that has been exchanged is deactivated, not deleted.
    -- fosite has to tell "never existed" from "already used" in order to detect a
    -- replayed code, and a deleted row answers the first when the truth is the second.
    active          boolean NOT NULL DEFAULT true,

    requested_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,

    CONSTRAINT oauth_session_hash_is_sha256 CHECK (octet_length(signature_hash) = 32),
    CONSTRAINT oauth_session_kind_valid CHECK (
        kind IN ('authorize_code', 'access_token', 'pkce', 'openid', 'par',
                 'client_assertion')),

    -- Signatures are unique within a kind, not across kinds: the same value could in
    -- principle be produced for an access token and a code, and they are different
    -- artifacts.
    PRIMARY KEY (kind, signature_hash)
);

CREATE INDEX oauth_session_request_idx ON oauth_session (request_id);
CREATE INDEX oauth_session_tenant_idx ON oauth_session (tenant_id);
CREATE INDEX oauth_session_session_idx ON oauth_session (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX oauth_session_expiry_idx ON oauth_session (expires_at);

COMMENT ON TABLE oauth_session IS
    'Short-lived OpenID Provider artifacts (SPEC §7.7). Refresh tokens are NOT here; they live in refresh_token, which carries the family rotation of SPEC §8.3.';
COMMENT ON COLUMN oauth_session.active IS
    'False once an authorization code has been exchanged. Deactivated rather than deleted so that a replayed code is distinguishable from an unknown one.';

-- ---------------------------------------------------------------------------------
-- refresh_token gains what fosite needs
-- ---------------------------------------------------------------------------------
--
-- Rather than a second refresh-token table. fosite needs to store and rehydrate a
-- serialized request; Warden needs the family, the session and the consumed/revoked
-- state it already has. One row carries both, so the two cannot disagree about whether
-- a token has been used — which is the question the whole of M1-5 turns on.

ALTER TABLE refresh_token
    ADD COLUMN request_id   text,
    ADD COLUMN subject      text NOT NULL DEFAULT '',
    ADD COLUMN granted_scope text[] NOT NULL DEFAULT '{}',
    ADD COLUMN granted_audience text[] NOT NULL DEFAULT '{}',
    ADD COLUMN form         jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN session_data jsonb NOT NULL DEFAULT '{}';

CREATE INDEX refresh_token_request_idx ON refresh_token (request_id) WHERE request_id IS NOT NULL;

COMMENT ON COLUMN refresh_token.request_id IS
    'fosite''s request id, tying this token to the exchange that produced it. Null for tokens issued through the internal API rather than the token endpoint.';

-- ---------------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------------

ALTER TABLE oauth_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_session FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_session
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('oauth_session', true, NULL);
