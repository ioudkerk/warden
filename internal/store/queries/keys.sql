-- Token signing keys (internal/keys).

-- The previously active key becomes 'previous' rather than 'retired': tokens it
-- signed are still in circulation and must keep verifying until they expire, which is
-- what the JWKS overlap window in SPEC §17 is for.
--
-- retired_at is supplied rather than taken from now() so that it is the same instant
-- as the incoming key's activated_at — a key stops signing exactly when its successor
-- starts — and so that it is on the same clock as the overlap cutoff. Two clocks here
-- is not a rounding difference: it decides whether the key that has just stopped
-- signing is inside its overlap window or already outside it.
-- name: RetireActiveSigningKey :exec
UPDATE signing_key SET status = 'previous', retired_at = @retired_at::timestamptz
 WHERE status = 'active';

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

-- The active key's metadata, without its private half. The rotation scheduler asks
-- "is the current key due?" far more often than anything asks to sign, and opening a
-- sealed private key to answer that would put a KEK decryption on a timer.
-- name: ActiveSigningKeyMeta :one
SELECT id, kid, algorithm, created_at, expires_at FROM signing_key WHERE status = 'active';

-- Drops keys out of JWKS once the overlap window has passed. The cutoff is computed
-- by the caller from security.key_overlap_window rather than embedded here, so that
-- shortening the window takes effect on the next sweep instead of on the next
-- migration.
-- name: RetireOverlappedSigningKeys :execrows
UPDATE signing_key
   SET status = 'retired'
 WHERE status = 'previous'
   AND retired_at IS NOT NULL
   AND retired_at < @cutoff::timestamptz;

-- name: ListSigningKeys :many
SELECT id, kid, algorithm, status, created_at, activated_at, retired_at, expires_at
  FROM signing_key
 ORDER BY created_at DESC;

-- Serialises rotation across replicas. A transaction-scoped advisory lock is released
-- by commit or rollback, including the rollback a crashed connection causes, so a
-- process that dies mid-rotation does not leave the lock held. Without it, every
-- replica noticing the same due date at the same moment would each generate a key and
-- all but one would fail on signing_key_one_active — correct, but noisy, and it burns
-- an RSA keygen per replica to achieve nothing.
-- name: TryLockKeyRotation :one
SELECT pg_try_advisory_xact_lock(@lock_key::bigint);
