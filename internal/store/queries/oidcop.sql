-- OAuth 2.0 / OIDC clients (internal/oidcop).
--
-- One query here runs on the system pool and the rest are tenant-scoped, for the same
-- reason refresh tokens split that way: the token endpoint receives a client_id and
-- nothing else, so the tenant has to be resolved before a tenant scope can exist. That
-- single column read opens the scope; everything after it runs under row-level
-- security, and oauth_client stays registered as tenant-scoped.

-- Resolves a client id to its tenant. System pool; see the header.
-- name: OAuthClientTenant :one
SELECT tenant_id FROM oauth_client WHERE id = @id;

-- name: OAuthClientByID :one
SELECT id, tenant_id, key, name, public, secret_hash, redirect_uris, grant_types,
       response_types, scopes, audiences, token_endpoint_auth_method,
       post_logout_redirect_uris, require_pkce, disabled_at, created_at
  FROM oauth_client
 WHERE tenant_id = @tenant_id AND id = @id;

-- name: OAuthClientByKey :one
SELECT id, tenant_id, key, name, public, secret_hash, redirect_uris, grant_types,
       response_types, scopes, audiences, token_endpoint_auth_method,
       post_logout_redirect_uris, require_pkce, disabled_at, created_at
  FROM oauth_client
 WHERE tenant_id = @tenant_id AND key = @key;

-- name: ListOAuthClients :many
SELECT id, tenant_id, key, name, public, redirect_uris, grant_types, scopes,
       require_pkce, disabled_at, created_at
  FROM oauth_client
 WHERE tenant_id = @tenant_id
 ORDER BY key;

-- name: InsertOAuthClient :exec
INSERT INTO oauth_client (id, tenant_id, key, name, public, secret_hash, redirect_uris,
                          grant_types, response_types, scopes, audiences,
                          token_endpoint_auth_method, post_logout_redirect_uris,
                          require_pkce)
VALUES (@id, @tenant_id, @key, @name, @public, @secret_hash, @redirect_uris,
        @grant_types, @response_types, @scopes, @audiences,
        @token_endpoint_auth_method, @post_logout_redirect_uris, @require_pkce);

-- Rotates a confidential client's secret. The old one stops working immediately;
-- SPEC §8.4's overlap window is for service accounts, which are a different credential
-- with a different rotation story.
-- name: SetOAuthClientSecret :execrows
UPDATE oauth_client SET secret_hash = @secret_hash
 WHERE tenant_id = @tenant_id AND id = @id AND NOT public;

-- name: SetOAuthClientDisabled :execrows
UPDATE oauth_client SET disabled_at = @disabled_at
 WHERE tenant_id = @tenant_id AND id = @id;

-- name: DeleteOAuthClient :execrows
DELETE FROM oauth_client WHERE tenant_id = @tenant_id AND id = @id;
