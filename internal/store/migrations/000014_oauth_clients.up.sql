-- OAuth 2.0 / OIDC clients: the applications Warden issues tokens to (SPEC §7.7).
--
-- Not to be confused with `application`, which is a different thing wearing a similar
-- name. An application declares a permission surface — resource types, actions, roles —
-- and is global, enrolled per tenant. An oauth_client is a thing that performs an
-- authorization code flow and receives tokens. One application may have several
-- clients (a web front end, a mobile app, a CLI), and a client need not correspond to
-- any application at all.

CREATE TABLE oauth_client (
    -- The protocol client_id, and deliberately opaque rather than a chosen name.
    --
    -- The token endpoint receives a client_id and nothing else, so client ids have to be
    -- unique across the whole deployment before any tenant scope exists — two tenants
    -- each naming a client "billing-web" would be indistinguishable at exactly the
    -- moment it matters. Generated ids sidestep that, and they also stop a client id
    -- from leaking a customer's name to anybody who sees an authorize URL.
    id              text PRIMARY KEY CHECK (id LIKE 'oac\_%'),

    tenant_id       text NOT NULL REFERENCES tenant(id),

    -- The human handle, unique within the tenant. This is what an administrator types
    -- and what the console lists; it never appears in a protocol message.
    key             text NOT NULL,
    name            text NOT NULL,

    -- A public client cannot keep a secret: a single-page app or a mobile binary ships
    -- to the user's device. RFC 8252 and OAuth 2.1 both require PKCE for these, which
    -- is enforced below rather than documented.
    public          boolean NOT NULL DEFAULT true,

    -- Argon2id PHC string, never a reversible encoding. NULL for public clients, and
    -- the constraint below makes the two agree.
    secret_hash     text,

    -- Exact-match allowlist (SPEC §17, "open redirect"). No wildcards, ever: the
    -- comparison is string equality, so there is no pattern syntax to get wrong.
    redirect_uris   text[] NOT NULL DEFAULT '{}',

    grant_types     text[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    response_types  text[] NOT NULL DEFAULT '{code}',
    scopes          text[] NOT NULL DEFAULT '{openid,profile,email}',

    -- The "aud" of tokens issued to this client. Empty means the client id itself.
    audiences       text[] NOT NULL DEFAULT '{}',

    token_endpoint_auth_method text NOT NULL DEFAULT 'none',

    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',

    -- Confidential clients may opt out; public ones may not (see the constraint).
    require_pkce    boolean NOT NULL DEFAULT true,

    disabled_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- A public client with a secret is a contradiction that would otherwise be
    -- discovered by an auditor rather than by the database.
    CONSTRAINT oauth_client_secret_matches_kind CHECK (
        (public AND secret_hash IS NULL) OR (NOT public AND secret_hash IS NOT NULL)),

    -- PKCE is not optional for a client that cannot hold a secret. Without it, an
    -- attacker who intercepts the redirect owns the code.
    CONSTRAINT oauth_client_public_requires_pkce CHECK (NOT public OR require_pkce),

    -- SPEC §7.7: "Implicit grant and the resource-owner password grant are not
    -- implemented." M1-6's exit condition sharpens that to *absent, not disabled*, and
    -- this is what makes it structural. A deployment cannot enable them by editing a
    -- row, because the row will not exist; nor can a future handler quietly start
    -- honouring one, because no client can be configured to ask.
    CONSTRAINT oauth_client_no_forbidden_grants CHECK (
        NOT (grant_types && ARRAY['implicit', 'password', 'client_credentials_jwt'])),
    CONSTRAINT oauth_client_no_forbidden_response_types CHECK (
        NOT (response_types && ARRAY['token', 'id_token token', 'code token',
                                     'code id_token token'])),

    CONSTRAINT oauth_client_auth_method_valid CHECK (
        token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post',
                                       'private_key_jwt')),

    -- A public client authenticates with nothing; a confidential one must not claim to.
    CONSTRAINT oauth_client_auth_method_matches_kind CHECK (
        (public AND token_endpoint_auth_method = 'none') OR
        (NOT public AND token_endpoint_auth_method <> 'none')),

    -- A client doing the code flow with nowhere to send the code is misconfigured in a
    -- way that only shows up at the first login attempt.
    CONSTRAINT oauth_client_code_flow_needs_redirect CHECK (
        NOT ('authorization_code' = ANY (grant_types)) OR cardinality(redirect_uris) > 0)
);

CREATE UNIQUE INDEX oauth_client_tenant_key_key ON oauth_client (tenant_id, key);
CREATE INDEX oauth_client_tenant_id_idx ON oauth_client (tenant_id);

CREATE TRIGGER oauth_client_set_updated_at BEFORE UPDATE ON oauth_client
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

COMMENT ON TABLE oauth_client IS
    'An OAuth 2.0 / OIDC client (SPEC §7.7). Distinct from `application`, which declares a permission surface.';
COMMENT ON COLUMN oauth_client.id IS
    'The protocol client_id. Opaque and deployment-unique: the token endpoint resolves it before any tenant scope exists.';
COMMENT ON COLUMN oauth_client.redirect_uris IS
    'Exact-match allowlist. No wildcards — the comparison is string equality (SPEC §17).';

-- ---------------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------------

ALTER TABLE oauth_client ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_client FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_client
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('oauth_client', true, NULL);
