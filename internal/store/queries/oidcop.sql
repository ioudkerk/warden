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

-- ---------------------------------------------------------------------------------
-- Provider storage (the fosite adapter)
-- ---------------------------------------------------------------------------------

-- name: InsertOAuthSession :exec
INSERT INTO oauth_session (signature_hash, kind, tenant_id, request_id, client_id,
                           subject, session_id, requested_scope, granted_scope,
                           requested_audience, granted_audience, form, session_data,
                           requested_at, expires_at)
VALUES (@signature_hash, @kind, @tenant_id, @request_id, @client_id,
        @subject, @session_id, @requested_scope, @granted_scope,
        @requested_audience, @granted_audience, @form, @session_data,
        @requested_at, @expires_at);

-- Returns the row whether or not it is still active. fosite has to distinguish "never
-- existed" from "already used" — the second is a replayed authorization code and must
-- revoke everything descended from it — so `active` is returned rather than filtered on.
-- name: OAuthSessionBySignature :one
SELECT signature_hash, kind, tenant_id, request_id, client_id, subject, session_id,
       requested_scope, granted_scope, requested_audience, granted_audience,
       form, session_data, active, requested_at, expires_at
  FROM oauth_session
 WHERE kind = @kind AND signature_hash = @signature_hash;

-- Resolves an artifact to its tenant. System pool: a signature arrives with no tenant,
-- the same way a client_id and a refresh token do.
-- name: OAuthSessionTenant :one
SELECT tenant_id FROM oauth_session WHERE kind = @kind AND signature_hash = @signature_hash;

-- name: DeactivateOAuthSession :execrows
UPDATE oauth_session SET active = false
 WHERE kind = @kind AND signature_hash = @signature_hash AND active;

-- name: DeleteOAuthSession :execrows
DELETE FROM oauth_session WHERE kind = @kind AND signature_hash = @signature_hash;

-- Everything issued in one exchange. This is what a detected authorization-code replay
-- revokes: fosite hands back the request id and expects every descendant to die.
-- name: DeleteOAuthSessionsByRequest :execrows
DELETE FROM oauth_session WHERE tenant_id = @tenant_id AND request_id = @request_id;

-- name: DeleteOAuthSessionsForSession :execrows
DELETE FROM oauth_session WHERE tenant_id = @tenant_id AND session_id = @session_id;

-- name: DeleteExpiredOAuthSessions :execrows
DELETE FROM oauth_session WHERE expires_at < @before;

-- ---------------------------------------------------------------------------------
-- Refresh tokens, as the provider sees them
-- ---------------------------------------------------------------------------------
--
-- These read and write refresh_token rather than oauth_session, so that a token has one
-- row carrying both its protocol payload and the family state SPEC §8.3 turns on.

-- name: InsertProviderRefreshToken :exec
INSERT INTO refresh_token (id, session_id, tenant_id, family_id, token_hash, client_id,
                           request_id, subject, granted_scope, granted_audience,
                           form, session_data, issued_at, expires_at)
VALUES (@id, @session_id, @tenant_id, @family_id, @token_hash, @client_id,
        @request_id, @subject, @granted_scope, @granted_audience,
        @form, @session_data, @issued_at, @expires_at);

-- name: ProviderRefreshTokenByHash :one
SELECT rt.id, rt.session_id, rt.tenant_id, rt.family_id, rt.client_id, rt.request_id,
       rt.subject, rt.granted_scope, rt.granted_audience, rt.form, rt.session_data,
       rt.issued_at, rt.expires_at, rt.consumed_at, rt.revoked_at
  FROM refresh_token rt
 WHERE rt.tenant_id = @tenant_id AND rt.token_hash = @token_hash;

-- name: RefreshTokenFamilyByRequest :one
SELECT tenant_id, family_id, session_id, client_id, subject
  FROM refresh_token
 WHERE tenant_id = @tenant_id AND request_id = @request_id
 ORDER BY issued_at DESC
 LIMIT 1;

-- ---------------------------------------------------------------------------------
-- Userinfo (SPEC §7.7)
-- ---------------------------------------------------------------------------------

-- The claims the userinfo endpoint may release, in one read.
--
-- status comes back with them rather than being filtered in the WHERE clause: a token
-- belonging to a suspended user must be refused, and refusing needs to know that the
-- user exists and is suspended — filtering here would make that indistinguishable from
-- a subject that was never real.
-- name: UserProfile :one
SELECT id,
       email::text AS email,
       email_verified,
       coalesce(display_name, '')::text AS display_name,
       status,
       attributes,
       updated_at
  FROM app_user
 WHERE tenant_id = @tenant_id AND id = @id AND deleted_at IS NULL;
