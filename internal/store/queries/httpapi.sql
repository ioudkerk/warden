-- The HTTP surface (internal/httpapi).

-- Resolves a bearer token to a service account. This runs on the system pool, and
-- necessarily so: it has to find which tenant the token belongs to before a tenant
-- scope can exist. service_account is registered as a deliberate exception to
-- row-level security for exactly this reason.
-- name: ServiceAccountByTokenHash :one
SELECT id, tenant_id, name, token_hash, disabled_at, expires_at, may_explain
  FROM service_account
 WHERE token_hash = $1;

-- SPEC §16.2 makes the decision log level per application; with one decision endpoint
-- and no application in the request, the caller takes the strictest level across the
-- tenant's enrolled applications.
-- name: TenantDecisionLogLevels :many
SELECT DISTINCT a.decision_log
  FROM application a
  JOIN app_enrollment e ON e.application_id = a.id
 WHERE e.tenant_id = $1;

-- An application's declared elements together with whatever binding applies in this
-- tenant and environment. An environment-specific binding wins over the one that
-- applies to all environments, which is what makes a change testable in staging
-- before it is promoted (SPEC §11.3).
-- name: UIElementsWithBindings :many
SELECT e.key, e.label, e.default_mode,
       coalesce(e.suggested_permission, '')::text AS suggested_permission,
       (e.resource_type_id IS NOT NULL)::boolean AS resource_scoped,
       b.requires,
       -- ui_binding.mode is NOT NULL and constrained to hidden/disabled/read_only, so
       -- the empty string this produces means "no binding matched the lateral join"
       -- and nothing else. sqlc types a left-joined column from its declaration and
       -- would otherwise call it non-null, which a NULL scan turns into a run-time
       -- error on the first unbound element.
       coalesce(b.mode, '')::text AS mode,
       coalesce(b.condition, '')::text AS condition,
       coalesce(b.message, '')::text AS message,
       coalesce(b.version, 0)::int AS version
  FROM ui_element e
  JOIN application a ON a.id = e.application_id
  LEFT JOIN LATERAL (
      SELECT ub.requires, ub.mode, ub.condition, ub.message, ub.version
        FROM ui_binding ub
        LEFT JOIN environment env ON env.id = ub.environment_id
       WHERE ub.ui_element_id = e.id
         AND (ub.environment_id IS NULL OR env.name = @environment)
       ORDER BY (ub.environment_id IS NOT NULL) DESC
       LIMIT 1
  ) b ON true
 WHERE a.key = @application AND e.surface = @surface AND e.status <> 'deprecated'
 ORDER BY e.key;
