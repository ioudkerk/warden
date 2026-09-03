-- Warden's own permission surface, and the system roles built from it.
--
-- Until now every permission belonged to some application a customer registered.
-- Administering Warden is itself something that needs authorizing — who may hand out
-- a role, who may write an explicit deny — and SPEC §17.1 names privilege escalation
-- through role assignment as a threat to mitigate explicitly. That mitigation needs a
-- permission to name, so Warden declares its own surface the same way any application
-- does, rather than special-casing administration in code.
--
-- The application key is reserved: a customer application called "warden" would let
-- its manifest redefine these permissions.

INSERT INTO application (id, key, name, manifest_version, fail_mode, cache_mode, decision_log)
VALUES ('app_warden', 'warden', 'Warden', 1, 'closed', 'cached', 'all');

-- decision_log is 'all' for this application alone: administrative decisions are low
-- volume and high consequence, which inverts the usual trade.

INSERT INTO resource_type (id, application_id, key, name) VALUES
    ('rst_warden_role',    'app_warden', 'role',    'Role'),
    ('rst_warden_denial',  'app_warden', 'denial',  'Explicit denial'),
    ('rst_warden_user',    'app_warden', 'user',    'User'),
    ('rst_warden_group',   'app_warden', 'group',   'Group'),
    ('rst_warden_audit',   'app_warden', 'audit',   'Audit log');

INSERT INTO action (id, resource_type_id, key, name, implies) VALUES
    ('act_warden_role_assign',     'rst_warden_role',   'assign',     'Assign a role', '{}'),
    -- The escape hatch of SPEC §17.1. Holding it permits assigning a role whose
    -- permissions the assigner does not hold, which is the whole of the escalation
    -- the guard exists to prevent — so it is a separate, deliberately granted
    -- permission and never implied by anything.
    ('act_warden_role_assign_any', 'rst_warden_role',   'assign_any', 'Assign any role regardless of what the assigner holds', '{}'),
    ('act_warden_role_manage',     'rst_warden_role',   'manage',     'Create and edit roles', '{assign}'),
    ('act_warden_denial_create',   'rst_warden_denial', 'create',     'Write an explicit denial', '{}'),
    ('act_warden_user_manage',     'rst_warden_user',   'manage',     'Create and edit users', '{}'),
    ('act_warden_group_manage',    'rst_warden_group',  'manage',     'Create and edit groups', '{}'),
    ('act_warden_audit_read',      'rst_warden_audit',  'read',       'Read the audit log', '{}');

INSERT INTO permission (id, application_id, key, resource_type_id, action_id) VALUES
    ('prm_warden_role_assign',     'app_warden', 'warden.role:assign',     'rst_warden_role',   'act_warden_role_assign'),
    ('prm_warden_role_assign_any', 'app_warden', 'warden.role:assign_any', 'rst_warden_role',   'act_warden_role_assign_any'),
    ('prm_warden_role_manage',     'app_warden', 'warden.role:manage',     'rst_warden_role',   'act_warden_role_manage'),
    ('prm_warden_denial_create',   'app_warden', 'warden.denial:create',   'rst_warden_denial', 'act_warden_denial_create'),
    ('prm_warden_user_manage',     'app_warden', 'warden.user:manage',     'rst_warden_user',   'act_warden_user_manage'),
    ('prm_warden_group_manage',    'app_warden', 'warden.group:manage',    'rst_warden_group',  'act_warden_group_manage'),
    ('prm_warden_audit_read',      'app_warden', 'warden.audit:read',      'rst_warden_audit',  'act_warden_audit_read');

-- ---------------------------------------------------------------------------------
-- System roles (SPEC §9.3)
-- ---------------------------------------------------------------------------------
--
-- Immutable and present in every tenant. type = 'system', which the existing
-- constraint requires to carry a NULL tenant_id, so they are global templates like
-- any application's — the difference is that no tenant may fork or edit them.

INSERT INTO role (id, tenant_id, application_id, key, name, description, type, immutable) VALUES
    ('rol_tenant_owner',   NULL, 'app_warden', 'tenant.owner',   'Tenant Owner',
     'Full administrative control, including assigning roles the owner does not hold.', 'system', true),
    ('rol_tenant_admin',   NULL, 'app_warden', 'tenant.admin',   'Tenant Administrator',
     'Administers users, groups and role assignments, but may only assign what they hold themselves.', 'system', true),
    ('rol_tenant_auditor', NULL, 'app_warden', 'tenant.auditor', 'Tenant Auditor',
     'Reads the audit log. Changes nothing.', 'system', true),
    ('rol_tenant_member',  NULL, 'app_warden', 'tenant.member',  'Tenant Member',
     'Membership with no administrative permission of its own.', 'system', true);

INSERT INTO role_permission (role_id, tenant_id, permission_key) VALUES
    -- The owner holds assign_any, which is what makes them the only subject who can
    -- widen the set of permissions in circulation.
    ('rol_tenant_owner', NULL, 'warden.role:assign_any'),
    ('rol_tenant_owner', NULL, 'warden.role:manage'),
    ('rol_tenant_owner', NULL, 'warden.denial:create'),
    ('rol_tenant_owner', NULL, 'warden.user:manage'),
    ('rol_tenant_owner', NULL, 'warden.group:manage'),
    ('rol_tenant_owner', NULL, 'warden.audit:read'),

    -- The administrator can assign, but only what they already hold. That is the
    -- ordinary case, and the reason the guard is not merely advisory: an
    -- administrator is expected to delegate, and expected not to be able to
    -- manufacture authority they were not given.
    ('rol_tenant_admin', NULL, 'warden.role:assign'),
    ('rol_tenant_admin', NULL, 'warden.user:manage'),
    ('rol_tenant_admin', NULL, 'warden.group:manage'),
    ('rol_tenant_admin', NULL, 'warden.audit:read'),

    ('rol_tenant_auditor', NULL, 'warden.audit:read');

-- tenant.member deliberately holds nothing.

-- The owner is an administrator and more.
INSERT INTO role_inheritance (role_id, parent_role_id, tenant_id) VALUES
    ('rol_tenant_owner', 'rol_tenant_admin', NULL);

-- An immutable role must not be silently editable. The application layer checks this
-- too, but a constraint holds when the application layer is bypassed.
CREATE OR REPLACE FUNCTION warden_role_immutable() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.immutable THEN
        RAISE EXCEPTION 'role % is immutable and cannot be % ', OLD.key, lower(TG_OP)
            USING HINT = 'Fork it into a tenant role instead.';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER role_immutable_no_update BEFORE UPDATE ON role
    FOR EACH ROW EXECUTE FUNCTION warden_role_immutable();
CREATE TRIGGER role_immutable_no_delete BEFORE DELETE ON role
    FOR EACH ROW EXECUTE FUNCTION warden_role_immutable();

-- Every tenant is enrolled in the warden application, so its permissions resolve.
INSERT INTO app_enrollment (tenant_id, application_id)
SELECT id, 'app_warden' FROM tenant ON CONFLICT DO NOTHING;
