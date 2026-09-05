-- Token signing keys (internal/keys).

-- The previously active key becomes 'previous' rather than 'retired': tokens it
-- signed are still in circulation and must keep verifying until they expire, which is
-- what the JWKS overlap window in SPEC §17 is for.
-- name: RetireActiveSigningKey :exec
UPDATE signing_key SET status = 'previous', retired_at = now() WHERE status = 'active';

-- name: InsertSigningKey :exec
INSERT INTO signing_key (id, kid, algorithm, public_key, private_key, kek_id,
                         status, created_at, activated_at, expires_at)
VALUES (@id, @kid, @algorithm, @public_key, @private_key, @kek_id,
        'active', @created_at, @created_at, @expires_at);

-- name: ActiveSigningKey :one
SELECT id, kid, algorithm, private_key FROM signing_key WHERE status = 'active';

-- The keys a relying party should accept: the active one and any still within the
-- overlap window (SPEC §17).
-- name: PublicSigningKeys :many
SELECT kid, algorithm, public_key, status
  FROM signing_key
 WHERE status IN ('active', 'previous')
 ORDER BY status, created_at DESC;
