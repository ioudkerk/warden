-- Administrative provisioning (internal/provision).
--
-- Everything here runs on the system pool: it is cross-tenant by nature (creating a
-- tenant, publishing a global application surface) or runs before a tenant scope can
-- exist. Row-level security therefore does not filter any of it, which is why each
-- statement names its tenant explicitly and why every caller writes an audit entry in
-- the same transaction.

-- ---------------------------------------------------------------------------------
-- Application manifest (warden apply)
-- ---------------------------------------------------------------------------------

-- name: ApplicationExists :one
SELECT EXISTS (SELECT 1 FROM application WHERE id = $1);

-- name: UpsertApplication :exec
INSERT INTO application (id, key, name, manifest_version, fail_mode, cache_mode, decision_log)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name, manifest_version = EXCLUDED.manifest_version,
    fail_mode = EXCLUDED.fail_mode, cache_mode = EXCLUDED.cache_mode,
    decision_log = EXCLUDED.decision_log;

-- name: UpsertEnvironment :exec
INSERT INTO environment (id, application_id, name) VALUES ($1, $2, $3)
ON CONFLICT (application_id, name) DO NOTHING;

-- name: UpsertResourceType :exec
INSERT INTO resource_type (id, application_id, key, name, attribute_schema)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (application_id, key) DO UPDATE SET
    name = EXCLUDED.name, attribute_schema = EXCLUDED.attribute_schema;

-- Set in a second pass, so a type may name a parent declared after it.
-- name: SetResourceTypeParent :exec
UPDATE resource_type SET parent_type_id = $1 WHERE id = $2;

-- name: UpsertAction :exec
INSERT INTO action (id, resource_type_id, key, name, implies) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (resource_type_id, key) DO UPDATE SET
    name = EXCLUDED.name, implies = EXCLUDED.implies;

-- name: InsertPermission :exec
INSERT INTO permission (id, application_id, key, resource_type_id, action_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (application_id, key) DO NOTHING;

-- Role templates ship with an application and carry no tenant (SPEC §9.3).
-- name: UpsertTemplateRole :exec
INSERT INTO role (id, tenant_id, application_id, key, name, description, type,
                  template_version, constraints)
VALUES ($1, NULL, $2, $3, $4, $5, 'application_template', $6, $7)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name, description = EXCLUDED.description,
    template_version = EXCLUDED.template_version, constraints = EXCLUDED.constraints;

-- name: DeleteRolePermissions :exec
DELETE FROM role_permission WHERE role_id = $1;

-- name: InsertRolePermission :exec
INSERT INTO role_permission (role_id, tenant_id, permission_key) VALUES ($1, NULL, $2);

-- name: DeleteRoleInheritance :exec
DELETE FROM role_inheritance WHERE role_id = $1;

-- name: InsertRoleInheritance :exec
INSERT INTO role_inheritance (role_id, parent_role_id, tenant_id) VALUES ($1, $2, NULL)
ON CONFLICT DO NOTHING;

-- Elements are upserted, never deleted. One removed from a manifest is deprecated
-- instead, because a tenant may have bound it and dropping the row would take their
-- binding with it — silently changing what their staff can see as a side effect of
-- someone else's refactor.
-- name: UpsertUIElement :exec
INSERT INTO ui_element (id, application_id, key, label, description, surface, path,
                        suggested_permission, resource_type_id, default_mode, status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'declared')
ON CONFLICT (application_id, key) DO UPDATE SET
    label = EXCLUDED.label, description = EXCLUDED.description,
    surface = EXCLUDED.surface, path = EXCLUDED.path,
    suggested_permission = EXCLUDED.suggested_permission,
    resource_type_id = EXCLUDED.resource_type_id,
    default_mode = EXCLUDED.default_mode, status = 'declared';

-- name: DeclaredUIElementKeys :many
SELECT key FROM ui_element WHERE application_id = $1 AND status = 'declared';

-- name: DeprecateUIElement :exec
UPDATE ui_element SET status = 'deprecated' WHERE application_id = $1 AND key = $2;

-- ---------------------------------------------------------------------------------
-- Revisions
-- ---------------------------------------------------------------------------------

-- A change to the global permission surface can change any tenant's decisions, so
-- every tenant's revision moves and every cached model is rebuilt (SPEC §10.5).
-- name: BumpEveryTenantRevision :exec
UPDATE tenant SET permission_rev = permission_rev + 1;

-- name: BumpTenantRevision :exec
UPDATE tenant SET permission_rev = permission_rev + 1 WHERE id = $1;

-- ---------------------------------------------------------------------------------
-- Tenancy
-- ---------------------------------------------------------------------------------

-- name: TenantExists :one
SELECT EXISTS (SELECT 1 FROM tenant WHERE id = $1);

-- name: InsertTenant :exec
INSERT INTO tenant (id, slug, name) VALUES ($1, $2, $3);

-- name: EnrolTenantInEveryApplication :exec
INSERT INTO app_enrollment (tenant_id, application_id)
SELECT $1, id FROM application ON CONFLICT DO NOTHING;

-- name: InsertUser :exec
INSERT INTO app_user (id, tenant_id, email, status, attributes)
VALUES ($1, $2, $3, $4, $5);

-- name: InsertUserWithoutAttributes :exec
INSERT INTO app_user (id, tenant_id, email, status) VALUES ($1, $2, $3, $4);

-- The token is never stored, only its SHA-256, so a copy of the database does not
-- confer the ability to impersonate the application.
-- name: InsertServiceAccount :exec
INSERT INTO service_account (id, tenant_id, name, token_hash, may_explain)
VALUES ($1, $2, $3, $4, $5);

-- name: InsertSetupToken :exec
INSERT INTO setup_token (id, tenant_id, user_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- ---------------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------------

-- name: InsertGrant :exec
INSERT INTO grant_ (id, tenant_id, subject_user_id, subject_group_id, role_id,
                    scope_kind, scope_ref, condition, valid_from, valid_until, reason)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'0001-01-01T00:00:00Z',$9,$10);

-- name: SetGrantGrantedBy :exec
UPDATE grant_ SET granted_by = $1 WHERE id = $2;

-- The deployment's first owner, granted by warden init before any administrator
-- exists to be recorded as the assigner.
-- name: InsertBootstrapGrant :exec
INSERT INTO grant_ (id, tenant_id, subject_user_id, role_id, scope_kind, scope_ref,
                    valid_from, reason)
VALUES ($1, $2, $3, 'rol_system_owner', $4, $2, '0001-01-01T00:00:00Z',
        'the deployment''s first owner, created by warden init');

-- Read before deleting: an audit entry saying only "a grant was revoked" cannot
-- answer the question anyone actually asks a year later, which is what it granted.
-- name: GrantBeingRevoked :one
SELECT r.key, g.scope_kind, g.scope_ref, g.subject_user_id, g.subject_group_id
  FROM grant_ g JOIN role r ON r.id = g.role_id
 WHERE g.id = $1 AND g.tenant_id = $2;

-- name: DeleteGrant :exec
DELETE FROM grant_ WHERE id = $1 AND tenant_id = $2;

-- ---------------------------------------------------------------------------------
-- Resources and UI bindings
-- ---------------------------------------------------------------------------------

-- name: UpsertResourceNode :exec
INSERT INTO resource_node (tenant_id, ref, parent_ref, attributes) VALUES ($1,$2,$3,$4)
ON CONFLICT (tenant_id, ref) DO UPDATE SET
    parent_ref = EXCLUDED.parent_ref, attributes = EXCLUDED.attributes;

-- name: UIElementExists :one
SELECT EXISTS (SELECT 1 FROM ui_element WHERE id = $1);

-- name: EnvironmentID :one
SELECT e.id FROM environment e JOIN application a ON a.id = e.application_id
 WHERE a.key = $1 AND e.name = $2;

-- name: UpsertUIBinding :exec
INSERT INTO ui_binding (id, tenant_id, ui_element_id, environment_id,
                        requires, mode, message, updated_by, version)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1)
ON CONFLICT (tenant_id, ui_element_id, environment_id) DO UPDATE SET
    requires = EXCLUDED.requires, mode = EXCLUDED.mode,
    message = EXCLUDED.message, updated_by = EXCLUDED.updated_by,
    version = ui_binding.version + 1;
