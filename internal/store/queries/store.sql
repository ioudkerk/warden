-- The tenant scope itself (internal/store).

-- Establishes the row-level security scope for a transaction.
--
-- set_config with is_local=true is the parameterizable form of SET LOCAL. SET LOCAL
-- itself takes no bind parameters, so using it here would mean interpolating a tenant
-- id into SQL text — on the one statement whose whole purpose is to establish a
-- security boundary. is_local also ties the setting to the transaction, so it cannot
-- leak to the next user of a pooled connection.
-- name: SetTenantScope :exec
SELECT set_config('warden.tenant_id', $1, true);

