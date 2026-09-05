-- The decision engine's model loader (internal/authz/loader.go).
--
-- Every tenant-scoped query below names the tenant explicitly. Row-level security
-- would filter them anyway on the tenant-scoped pool, but SPEC §6.2 puts RLS behind
-- application-level filtering rather than in place of it — and the privilege-
-- escalation guard runs these same queries through the system pool, where RLS does
-- not apply and these predicates are the only thing keeping one tenant's roles out
-- of another's decision.

-- name: TenantRevision :one
SELECT permission_rev FROM tenant WHERE id = $1;

-- The permission surface is global: an application declares it once (SPEC §6.1).
-- name: PermissionSurface :many
SELECT key FROM permission;

-- name: ModelSubjects :many
SELECT id, status, attributes
  FROM app_user
 WHERE tenant_id = $1 AND deleted_at IS NULL;

-- Group membership walks nesting outward, so a member of a nested group holds the
-- outer group's roles too (SPEC §9.4).
-- name: ModelGroupMembership :many
WITH RECURSIVE membership AS (
    SELECT base.member_user_id AS user_id, base.group_id
      FROM group_member base
     WHERE base.member_user_id IS NOT NULL AND base.tenant_id = $1
    UNION
    SELECT ms.user_id, gm.group_id
      FROM group_member gm
      JOIN membership ms ON gm.member_group_id = ms.group_id
     WHERE gm.tenant_id = $1
)
SELECT membership.user_id, membership.group_id FROM membership;

-- name: ModelRoles :many
SELECT id, key, constraints
  FROM role
 WHERE tenant_id = sqlc.arg(tenant_id)::text OR tenant_id IS NULL;

-- name: ModelRolePermissions :many
SELECT role_id, permission_key, condition
  FROM role_permission
 WHERE tenant_id = sqlc.arg(tenant_id)::text OR tenant_id IS NULL;

-- name: ModelRoleInheritance :many
SELECT role_id, parent_role_id
  FROM role_inheritance
 WHERE tenant_id = sqlc.arg(tenant_id)::text OR tenant_id IS NULL;

-- Action implication is expanded at load, never during a check (SPEC §9.2).
-- name: ModelActionImplications :many
SELECT app.key AS app_key, rt.key AS type_key, a.key AS action_key, a.implies
  FROM action a
  JOIN resource_type rt ON rt.id = a.resource_type_id
  JOIN application app ON app.id = rt.application_id;

-- Ordered by seq because candidate order is declaration order: when several grants
-- could allow the same check, the earliest is the one reported as matched_grant.
-- The conformance corpus pins this (conformance/README.md).
-- name: ModelGrants :many
SELECT id, seq, subject_user_id, subject_group_id, role_id,
       scope_kind, scope_ref, condition, valid_from, valid_until
  FROM grant_
 WHERE tenant_id = $1
 ORDER BY seq;

-- name: ModelDenials :many
SELECT id, subject_user_id, subject_group_id, permission_key, scope_kind, scope_ref
  FROM denial
 WHERE tenant_id = $1;

-- name: ModelResources :many
SELECT ref, parent_ref, attributes
  FROM resource_node
 WHERE tenant_id = $1;
