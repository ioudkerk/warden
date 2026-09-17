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
       post_logout_redirect_uris, token_attributes, token_claims, require_pkce,
       disabled_at, created_at
  FROM oauth_client
 WHERE tenant_id = @tenant_id AND id = @id;

-- name: OAuthClientByKey :one
SELECT id, tenant_id, key, name, public, secret_hash, redirect_uris, grant_types,
       response_types, scopes, audiences, token_endpoint_auth_method,
       post_logout_redirect_uris, token_attributes, token_claims, require_pkce,
       disabled_at, created_at
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
                          token_attributes, token_claims, require_pkce)
VALUES (@id, @tenant_id, @key, @name, @public, @secret_hash, @redirect_uris,
        @grant_types, @response_types, @scopes, @audiences,
        @token_endpoint_auth_method, @post_logout_redirect_uris,
        @token_attributes, @token_claims, @require_pkce);

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

-- ---------------------------------------------------------------------------------
-- The device authorization grant (RFC 8628)
-- ---------------------------------------------------------------------------------

-- name: InsertDeviceAuthorization :exec
INSERT INTO device_authorization (id, tenant_id, client_id, device_code_hash, user_code_hash,
                                  requested_scope, requested_audience, interval_seconds,
                                  expires_at)
VALUES (@id, @tenant_id, @client_id, @device_code_hash, @user_code_hash,
        @requested_scope, @requested_audience, @interval_seconds, @expires_at);

-- The row a device's poll is about. Returned whatever its status: "pending", "denied"
-- and "already redeemed" are three different answers the grant has to give, and filtering
-- here would collapse them into "no such code".
-- name: DeviceAuthorizationByDeviceCode :one
SELECT id, tenant_id, client_id, requested_scope, granted_scope, requested_audience,
       granted_audience, status, subject, session_id, interval_seconds, last_polled_at,
       approved_at, created_at, expires_at
  FROM device_authorization
 WHERE tenant_id = @tenant_id AND device_code_hash = @device_code_hash;

-- name: DeviceAuthorizationByUserCode :one
SELECT id, tenant_id, client_id, requested_scope, granted_scope, requested_audience,
       granted_audience, status, subject, session_id, interval_seconds, last_polled_at,
       approved_at, created_at, expires_at
  FROM device_authorization
 WHERE tenant_id = @tenant_id AND user_code_hash = @user_code_hash;

-- Records that the device asked. The value it overwrites is the one the read in the same
-- transaction returned, which is what "are you polling too fast?" is answered from — so
-- the read and this write belong together, and the caller runs them that way.
-- name: TouchDeviceAuthorizationPoll :exec
UPDATE device_authorization
   SET last_polled_at = @at
 WHERE tenant_id = @tenant_id AND id = @id;

-- name: ApproveDeviceAuthorization :execrows
UPDATE device_authorization
   SET status = 'approved', subject = @subject, session_id = @session_id,
       granted_scope = @granted_scope, granted_audience = @granted_audience,
       approved_at = @at
 WHERE tenant_id = @tenant_id AND id = @id AND status = 'pending';

-- name: DenyDeviceAuthorization :execrows
UPDATE device_authorization
   SET status = 'denied'
 WHERE tenant_id = @tenant_id AND id = @id AND status = 'pending';

-- Single use, enforced by the WHERE clause rather than by the caller: two polls arriving
-- together must not both issue tokens, and the row that changes no rows is the loser.
-- name: RedeemDeviceAuthorization :execrows
UPDATE device_authorization
   SET status = 'redeemed'
 WHERE tenant_id = @tenant_id AND device_code_hash = @device_code_hash AND status = 'approved';

-- name: DeleteExpiredDeviceAuthorizations :execrows
DELETE FROM device_authorization WHERE expires_at < @before;

-- Resolves a user code to its tenant. System pool, and for the same reason the client
-- and refresh-token lookups are: the person typing a code has not signed in yet, so
-- there is no tenant scope to read it under, and which tenant to authenticate them
-- against is precisely what the code has to answer.
-- name: DeviceAuthorizationTenant :one
SELECT tenant_id FROM device_authorization WHERE user_code_hash = @user_code_hash;

-- ---------------------------------------------------------------------------------
-- Access token claim assembly (SPEC §8.2)
-- ---------------------------------------------------------------------------------

-- The tenant-wide roles a user holds, directly or through a group.
--
-- Tenant-wide only, as §8.2 requires: a resource-scoped role says nothing without the
-- resource it is scoped to, and a token cannot carry the scope. Grants outside their
-- validity window are excluded, because a token that claims a role the user does not
-- currently hold is worse than one that omits it.
--
-- The recursion walks group nesting outward, so a member of a nested group holds the
-- outer group's roles too — the same rule the decision engine applies (SPEC §9.4).
-- name: TokenClaimRoles :many
WITH RECURSIVE membership AS (
    SELECT base.group_id
      FROM group_member base
     WHERE base.tenant_id = @tenant_id AND base.member_user_id = @user_id
    UNION
    SELECT gm.group_id
      FROM group_member gm
      JOIN membership ms ON gm.member_group_id = ms.group_id
     WHERE gm.tenant_id = @tenant_id
)
SELECT DISTINCT r.key
  FROM grant_ g
  JOIN role r ON r.id = g.role_id
 WHERE g.tenant_id = @tenant_id
   AND g.scope_kind = 'tenant'
   AND (g.valid_from IS NULL OR g.valid_from <= now())
   AND (g.valid_until IS NULL OR g.valid_until > now())
   AND (g.subject_user_id = @user_id
        OR g.subject_group_id IN (SELECT group_id FROM membership))
 ORDER BY r.key;

-- The groups a user belongs to, nesting walked outward.
-- name: TokenClaimGroups :many
WITH RECURSIVE membership AS (
    SELECT base.group_id
      FROM group_member base
     WHERE base.tenant_id = @tenant_id AND base.member_user_id = @user_id
    UNION
    SELECT gm.group_id
      FROM group_member gm
      JOIN membership ms ON gm.member_group_id = ms.group_id
     WHERE gm.tenant_id = @tenant_id
)
SELECT g.key
  FROM group_ g
  JOIN membership ms ON ms.group_id = g.id
 WHERE g.tenant_id = @tenant_id
 ORDER BY g.key;

-- The subject's own facts, and the tenant revision the token is issued against.
-- name: TokenClaimSubject :one
SELECT u.status, u.attributes, t.permission_rev
  FROM app_user u
  JOIN tenant t ON t.id = u.tenant_id
 WHERE u.tenant_id = @tenant_id AND u.id = @user_id AND u.deleted_at IS NULL;
