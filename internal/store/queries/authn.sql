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

-- ---------------------------------------------------------------------------------
-- Sessions (SPEC §8.3)
-- ---------------------------------------------------------------------------------
--
-- Redis holds the authoritative session record; these rows are the mirror the spec
-- asks for, and they serve two purposes Redis cannot. They are what the
-- active-sessions UI lists, and they are how "revoke everything for this user" finds
-- the keys to delete — Redis can answer "is this session valid?" in one lookup but
-- cannot enumerate a user's sessions without a scan.

-- name: InsertSession :exec
INSERT INTO session (id, tenant_id, user_id, amr, auth_time, ip, user_agent, expires_at)
VALUES (@id, @tenant_id, @user_id, @amr, @auth_time, @ip, @user_agent, @expires_at);

-- ip is coalesced to text on the way out. The column is inet, which pgx will not scan
-- into a *string in binary format; and the empty string is a better "no address" than
-- a null here, because every caller renders this into a list for a person to read and
-- would have to unwrap the pointer to the same effect.
-- name: SessionByID :one
SELECT id, tenant_id, user_id, amr, auth_time, coalesce(ip::text, '')::text AS ip, user_agent,
       created_at, expires_at, revoked_at
  FROM session
 WHERE tenant_id = @tenant_id AND id = @id;

-- The active-sessions list. Revoked and expired rows are excluded rather than shown
-- greyed out: this feeds a "these are your signed-in devices" screen, and a list that
-- includes sessions the user cannot act on is a list they will misread.
-- name: ActiveSessionsForUser :many
SELECT id, tenant_id, user_id, amr, auth_time, coalesce(ip::text, '')::text AS ip, user_agent,
       created_at, expires_at
  FROM session
 WHERE tenant_id = @tenant_id AND user_id = @user_id
   AND revoked_at IS NULL AND expires_at > now()
 ORDER BY created_at DESC;

-- name: RevokeSession :execrows
UPDATE session SET revoked_at = now()
 WHERE tenant_id = @tenant_id AND id = @id AND revoked_at IS NULL;

-- Returns the ids it revoked, so the caller knows which cache keys to delete without
-- a second query. RETURNING rather than select-then-update keeps the two from
-- disagreeing when a session is created between them.
-- name: RevokeAllSessionsForUser :many
UPDATE session SET revoked_at = now()
 WHERE tenant_id = @tenant_id AND user_id = @user_id AND revoked_at IS NULL
RETURNING id;

-- Sessions whose absolute lifetime has passed are of no further interest to anyone;
-- the row is kept only long enough for the UI to be honest about recent activity.
-- name: DeleteExpiredSessions :execrows
DELETE FROM session WHERE expires_at < @before;

-- ---------------------------------------------------------------------------------
-- Refresh tokens (SPEC §8.3, threat 7 of §17.1)
-- ---------------------------------------------------------------------------------
--
-- A family is the chain of tokens descended from one login. Rotation consumes the
-- presented token and issues its successor into the same family; presenting a token
-- that has already been consumed means two parties hold one, which is theft until
-- proven otherwise, and the answer is to revoke the whole family.
--
-- These run at SERIALIZABLE. The check "has this token been consumed?" and the write
-- "consume it" must be one indivisible step, or two simultaneous presentations of the
-- same token both read "not consumed" and both succeed — which is precisely the
-- situation reuse detection exists to notice. M0-7 built store.Isolation for this.

-- name: InsertRefreshToken :exec
INSERT INTO refresh_token (id, session_id, tenant_id, family_id, token_hash, client_id,
                           issued_at, expires_at)
VALUES (@id, @session_id, @tenant_id, @family_id, @token_hash, @client_id,
        @issued_at, @expires_at);

-- Everything rotation needs to decide, in one row.
--
-- consumed_at and revoked_at are returned rather than filtered on, because "this token
-- exists and has already been used" and "there is no such token" demand opposite
-- responses: the first is a security event, the second is an ordinary expired-session
-- refusal. A WHERE clause that excluded consumed rows would make them indistinguishable
-- and reuse detection impossible.
-- Resolves a presented token to its tenant, and nothing else.
--
-- This one runs on the system pool, and it is the only refresh-token query that does.
-- A client presents a token and no tenant — there is no tenant scope to establish until
-- the token has been resolved — which is the same chicken-and-egg service_account and
-- setup_token have. They solved it by being registered as row-level-security
-- exceptions; refresh_token does not, because it does not have to: this single column
-- read is enough to open the scope, and every other statement below then runs under
-- RLS like any tenant data. The atomicity that matters is in the rotation transaction,
-- not between it and this lookup: a token cannot change tenant.
-- name: RefreshTokenTenantByHash :one
SELECT tenant_id FROM refresh_token WHERE token_hash = @token_hash;

-- name: RefreshTokenByHash :one
SELECT rt.id, rt.session_id, rt.tenant_id, rt.family_id, rt.client_id,
       rt.issued_at, rt.expires_at, rt.consumed_at, rt.revoked_at,
       s.user_id, s.revoked_at AS session_revoked_at, s.expires_at AS session_expires_at,
       -- When the family began, which is what the absolute lifetime is measured from.
       -- Read rather than inferred from the presented token's own dates: inferring it
       -- means reconstructing one timestamp from two others and a configured duration,
       -- and it silently produces the wrong answer the moment either duration changes.
       -- family_id is indexed, so this is a lookup rather than a scan.
       (SELECT min(f.issued_at) FROM refresh_token f
         WHERE f.tenant_id = rt.tenant_id AND f.family_id = rt.family_id)::timestamptz
         AS family_started_at
  FROM refresh_token rt
  JOIN session s ON s.id = rt.session_id AND s.tenant_id = rt.tenant_id
 WHERE rt.token_hash = @token_hash;

-- Consumes a token, but only if it is still unconsumed. The row count is what settles
-- a race: the loser updates nothing and is treated as a replay.
-- name: ConsumeRefreshToken :execrows
UPDATE refresh_token SET consumed_at = @at::timestamptz
 WHERE id = @id AND consumed_at IS NULL AND revoked_at IS NULL;

-- Kills every token descended from one login. Consumed tokens are revoked too, so that
-- a later replay of an earlier link in the chain is refused rather than merely noticed
-- a second time.
-- name: RevokeRefreshTokenFamily :execrows
UPDATE refresh_token SET revoked_at = now()
 WHERE tenant_id = @tenant_id AND family_id = @family_id AND revoked_at IS NULL;

-- name: RevokeRefreshTokensForSession :execrows
UPDATE refresh_token SET revoked_at = now()
 WHERE tenant_id = @tenant_id AND session_id = @session_id AND revoked_at IS NULL;

-- Every refresh token a user holds, reached through their sessions.
--
-- Through sessions rather than through refresh_token.subject, because subject was added in
-- M1-6 and the tokens M1-5 issues do not carry it — filtering on it would silently miss
-- exactly the tokens that predate the column. Every refresh token has a session: the
-- foreign key says so, and "log this person out everywhere" depends on it.
-- name: RevokeRefreshTokensForUser :execrows
UPDATE refresh_token rt SET revoked_at = now()
 WHERE rt.tenant_id = @tenant_id
   AND rt.revoked_at IS NULL
   AND rt.session_id IN (
       SELECT s.id FROM session s
        WHERE s.tenant_id = @tenant_id AND s.user_id = @user_id
   );

-- name: CountRefreshTokensInFamily :one
SELECT count(*) FROM refresh_token
 WHERE tenant_id = @tenant_id AND family_id = @family_id;

-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM refresh_token WHERE expires_at < @before;

-- One member of a family, for the security event a revocation raises: it needs the
-- session and the subject, and every member carries the same ones.
-- name: RefreshTokenFamilyMember :one
SELECT id, session_id, client_id, subject
  FROM refresh_token
 WHERE tenant_id = @tenant_id AND family_id = @family_id
 ORDER BY issued_at
 LIMIT 1;

-- ---------------------------------------------------------------------------------
-- Second factors (SPEC §7.1)
-- ---------------------------------------------------------------------------------

-- name: InsertSecondFactor :exec
INSERT INTO credential (id, user_id, tenant_id, type, secret_hash, params, label)
VALUES (@id, @user_id, @tenant_id, @type, @secret_hash, @params, @label);

-- Every second factor a user holds, whatever its state. Confirmation is a field on
-- params rather than a filter here: an unconfirmed enrolment has to be distinguishable
-- from no enrolment at all, or a second attempt could not replace the first.
-- name: SecondFactorsForUser :many
SELECT id, type, secret_hash, params, label, last_used_at, created_at
  FROM credential
 WHERE tenant_id = @tenant_id AND user_id = @user_id AND type = ANY(@types::text[])
 ORDER BY created_at;

-- name: SecondFactorByID :one
SELECT id, type, secret_hash, params, label, last_used_at, created_at
  FROM credential
 WHERE tenant_id = @tenant_id AND user_id = @user_id AND id = @id;

-- name: UpdateSecondFactorParams :execrows
UPDATE credential SET params = @params, last_used_at = @last_used_at
 WHERE tenant_id = @tenant_id AND id = @id;

-- name: DeleteSecondFactor :execrows
DELETE FROM credential
 WHERE tenant_id = @tenant_id AND user_id = @user_id AND id = @id
   AND type <> 'password';

-- Removes every credential of one kind. Re-enrolling replaces rather than accumulates:
-- a user who sets up a new authenticator is not asking to keep the old one.
-- name: DeleteSecondFactorsOfType :execrows
DELETE FROM credential
 WHERE tenant_id = @tenant_id AND user_id = @user_id AND type = @type;

-- name: CountConfirmedSecondFactors :one
SELECT count(*)
  FROM credential
 WHERE tenant_id = @tenant_id AND user_id = @user_id
   AND type = ANY(@types::text[])
   AND params ? 'confirmed_at';

-- name: SetUserMFAEnforced :execrows
UPDATE app_user SET mfa_enforced = @mfa_enforced
 WHERE tenant_id = @tenant_id AND id = @id;

-- A recovery code is found by its hash, not by walking a user's credentials.
--
-- The codes are high-entropy random values, so SHA-256 is the right function here for the
-- same reason it is right for a service-account token: there is nothing to stretch. That
-- is what makes the lookup a single indexed read instead of ten Argon2id comparisons.
-- name: RecoveryCodeByHash :one
SELECT id, params
  FROM credential
 WHERE tenant_id = @tenant_id AND user_id = @user_id
   AND type = 'recovery_code' AND secret_hash = @secret_hash;

-- name: CountUnusedRecoveryCodes :one
SELECT count(*)
  FROM credential
 WHERE tenant_id = @tenant_id AND user_id = @user_id
   AND type = 'recovery_code' AND NOT (params ? 'used_at');

-- ---------------------------------------------------------------------------------
-- Email delivery (docs/design-email.md §5)
-- ---------------------------------------------------------------------------------

-- name: EnqueueEmail :exec
INSERT INTO outbound_email (id, tenant_id, to_address, template, locale, payload)
VALUES (@id, @tenant_id, @to_address, @template, @locale, @payload);

-- Claims a batch for one worker.
--
-- FOR UPDATE SKIP LOCKED is what lets several workers drain the queue without any message
-- being sent twice: a row another worker is holding is stepped over rather than waited for.
-- Suppressed addresses are filtered here rather than at send time, so a suppressed message
-- is never claimed at all.
-- name: ClaimOutboundEmail :many
WITH claimed AS (
    SELECT e.id
      FROM outbound_email e
     WHERE e.status = 'pending'
       AND e.next_attempt_at <= now()
     ORDER BY e.next_attempt_at
     LIMIT @batch_size
       FOR UPDATE SKIP LOCKED
)
SELECT e.id, e.tenant_id, e.to_address, e.template, e.locale, e.payload, e.attempts,
       -- Cast, or sqlc types a computed column as interface{}: the same reason the UI
       -- binding query casts its coalesced columns.
       (s.address IS NOT NULL)::boolean AS suppressed
  FROM outbound_email e
  JOIN claimed c ON c.id = e.id
  LEFT JOIN email_suppression s ON s.address = e.to_address;

-- name: MarkEmailSent :exec
UPDATE outbound_email
   SET status = 'sent', sent_at = now(), attempts = attempts + 1, last_error = NULL
 WHERE id = @id;

-- A transient failure: try again later, with the backoff the caller computed.
-- name: MarkEmailRetrying :exec
UPDATE outbound_email
   SET attempts = attempts + 1, next_attempt_at = @next_attempt_at, last_error = @last_error
 WHERE id = @id;

-- A permanent failure, or one that has run out of attempts.
-- name: MarkEmailFailed :exec
UPDATE outbound_email
   SET status = 'failed', attempts = attempts + 1, last_error = @last_error
 WHERE id = @id;

-- name: MarkEmailSuppressed :exec
UPDATE outbound_email
   SET status = 'suppressed', last_error = 'the recipient address is suppressed'
 WHERE id = @id;

-- name: SuppressEmailAddress :exec
INSERT INTO email_suppression (address, reason, last_bounce_at, note)
VALUES (@address, @reason, now(), @note)
ON CONFLICT (address) DO UPDATE
   SET reason = EXCLUDED.reason, last_bounce_at = now(), note = EXCLUDED.note;

-- name: EmailQueueDepth :one
SELECT count(*) FROM outbound_email WHERE status = 'pending';

-- name: DeleteSentEmails :execrows
DELETE FROM outbound_email WHERE status IN ('sent', 'failed', 'suppressed') AND created_at < @before;
