-- The administrative audit log (internal/audit).
--
-- `before` and `after` are json, not jsonb, and the generated []byte must stay []byte:
-- the entry hash is taken over the exact bytes written, and a parsed round trip
-- reorders object keys, so every entry would fail its own verification. Migration
-- 000009 carries the full account.

-- Serialises appenders. Two transactions that both read the same head would write two
-- entries claiming the same predecessor, which verification reports as tampering
-- forever after. A row lock is not enough — FOR UPDATE on an empty table locks
-- nothing — so this is an advisory lock, held for the transaction.
-- name: LockAuditChain :exec
SELECT pg_advisory_xact_lock($1);

-- name: AuditChainHead :one
SELECT hash FROM audit_event ORDER BY seq DESC LIMIT 1;

-- name: AppendAuditEvent :exec
INSERT INTO audit_event (
    id, tenant_id, occurred_at, actor_user_id, actor_client_id, impersonator_id,
    action, target_type, target_id, before, after, reason, ip, user_agent,
    request_id, prev_hash, hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17);

-- Reads the entire log in sequence order, so it must run on the system pool: the
-- chain spans tenants, and a connection that could see only some entries would
-- compute a different chain and report tampering that had not happened.
-- name: AuditEventsInOrder :many
SELECT seq, id, tenant_id, occurred_at, actor_user_id, actor_client_id,
       impersonator_id, action, target_type, target_id, before, after,
       reason, ip, user_agent, request_id, prev_hash, hash
  FROM audit_event
 ORDER BY seq;

-- name: RecentAuditEvents :many
SELECT occurred_at, action, coalesce(target_type,'') AS target_type,
       coalesce(target_id,'') AS target_id, coalesce(tenant_id,'') AS tenant_id,
       coalesce(reason,'') AS reason
  FROM audit_event
 WHERE (sqlc.narg(tenant_id)::text IS NULL OR tenant_id = sqlc.narg(tenant_id)::text)
 ORDER BY seq DESC
 LIMIT sqlc.arg(row_limit);
