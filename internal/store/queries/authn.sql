-- Local credentials (internal/authn).
--
-- Two of these run on the system pool and the rest are tenant-scoped, and the split is
-- not arbitrary. Resolving a setup token to its user necessarily happens before any
-- tenant scope exists — the token is all the caller has — which is why setup_token is
-- registered as a deliberate exception to row-level security alongside
-- service_account. Everything reached by (tenant, email) goes through the tenant pool,
-- where RLS is the thing keeping one tenant's credentials out of another's login.

-- ---------------------------------------------------------------------------------
-- Authentication
-- ---------------------------------------------------------------------------------

-- The row a password login needs, in one query.
--
-- A LEFT JOIN rather than an inner one, so that a user who exists but has no password
-- credential — invited and never redeemed, or federated only — is distinguishable here
-- from a user who does not exist at all. The caller must NOT let that distinction reach
-- the response: it is needed to decide whether to record a failed attempt against a
-- real account, and SPEC §7.2 requires both cases to answer identically.
-- name: PasswordCredentialByEmail :one
SELECT u.id            AS user_id,
       u.status        AS user_status,
       u.mfa_enforced,
       c.id            AS credential_id,
       c.secret_hash,
       c.expires_at    AS credential_expires_at
  FROM app_user u
  LEFT JOIN credential c
    ON c.user_id = u.id AND c.tenant_id = u.tenant_id AND c.type = 'password'
 WHERE u.tenant_id = @tenant_id AND u.email = @email AND u.deleted_at IS NULL;

-- Records that a credential was used. Deliberately not in the same transaction as the
-- verification: a successful login must not fail because this write contended, and an
-- unsuccessful one must not be distinguishable by having skipped it.
-- name: TouchCredential :exec
UPDATE credential SET last_used_at = now() WHERE id = @id;

-- ---------------------------------------------------------------------------------
-- Setting a password
-- ---------------------------------------------------------------------------------

-- Writes the one password credential a user may have.
--
-- ON CONFLICT targets credential_one_password_per_user, the partial unique index that
-- enforces "at most one password per user". Doing it as an upsert rather than
-- delete-then-insert means a password change cannot leave a user with no credential if
-- it fails between the two statements.
-- name: UpsertPasswordCredential :exec
INSERT INTO credential (id, user_id, tenant_id, type, secret_hash, params, label)
VALUES (@id, @user_id, @tenant_id, 'password', @secret_hash, @params, @label)
ON CONFLICT (user_id) WHERE type = 'password'
DO UPDATE SET secret_hash = EXCLUDED.secret_hash,
              params      = EXCLUDED.params,
              created_at  = now(),
              last_used_at = NULL;

-- name: UserForPasswordChange :one
SELECT id, status, email FROM app_user
 WHERE tenant_id = @tenant_id AND id = @id AND deleted_at IS NULL;

-- name: UserIDByEmail :one
SELECT id FROM app_user
 WHERE tenant_id = @tenant_id AND email = @email AND deleted_at IS NULL;

-- Moves a user from 'invited' to 'active'. Redeeming a setup token or an invitation is
-- the moment that happens: before it the account has no credential and can do nothing,
-- which is the property SPEC §20.2 is after.
-- name: ActivateUser :exec
UPDATE app_user SET status = 'active'
 WHERE tenant_id = @tenant_id AND id = @id AND status = 'invited';

-- ---------------------------------------------------------------------------------
-- Per-tenant password policy (SPEC §7.2)
-- ---------------------------------------------------------------------------------

-- Stored inside tenant.settings rather than in columns of its own. The policy is read
-- once per password change, never on the decision path, and it will grow fields —
-- history depth, expiry, dictionary choice — that would otherwise each be a migration.
-- name: TenantPasswordPolicy :one
SELECT (settings -> 'password_policy')::jsonb AS policy FROM tenant WHERE id = @tenant_id;

-- jsonb_strip_nulls keeps a cleared field from being stored as an explicit null, which
-- would read back as "configured, to nothing" rather than "not configured".
-- name: SetTenantPasswordPolicy :exec
UPDATE tenant
   SET settings = jsonb_strip_nulls(
                    coalesce(settings, '{}'::jsonb) || jsonb_build_object('password_policy', @policy::jsonb))
 WHERE id = @tenant_id;

-- ---------------------------------------------------------------------------------
-- Setup tokens (system pool: see the header)
-- ---------------------------------------------------------------------------------

-- name: SetupTokenByHash :one
SELECT id, tenant_id, user_id, expires_at, consumed_at
  FROM setup_token WHERE token_hash = @token_hash;

-- Marks a token used. The WHERE clause repeats the unconsumed check that the caller
-- already made, so that two simultaneous redemptions of the same link cannot both
-- succeed: the second updates zero rows and the caller treats that as a replay. The
-- check and the write being one statement is what makes it a race the database
-- settles rather than one the application hopes not to lose.
-- name: ConsumeSetupToken :execrows
UPDATE setup_token SET consumed_at = now()
 WHERE id = @id AND consumed_at IS NULL;

-- Redemption invalidates every other outstanding token for the same user
-- (docs/design-email.md §8). Two live setup links is one more than anyone needs.
-- name: InvalidateOtherSetupTokens :execrows
UPDATE setup_token SET consumed_at = now()
 WHERE user_id = @user_id AND id <> @id AND consumed_at IS NULL;
