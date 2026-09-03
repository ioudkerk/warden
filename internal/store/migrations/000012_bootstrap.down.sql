DELETE FROM tenant_isolation_registry WHERE table_name IN ('signing_key', 'setup_token');
ALTER TABLE tenant DROP CONSTRAINT IF EXISTS tenant_slug_not_reserved;

DELETE FROM role_permission WHERE role_id LIKE 'rol_system_%';
UPDATE role SET immutable = false WHERE id LIKE 'rol_system_%';
DELETE FROM role WHERE id LIKE 'rol_system_%';

DELETE FROM permission WHERE id IN (
    'prm_warden_tenant_read', 'prm_warden_tenant_manage',
    'prm_warden_application_read', 'prm_warden_application_manage',
    'prm_warden_deployment_read', 'prm_warden_deployment_manage');
DELETE FROM action WHERE resource_type_id IN
    ('rst_warden_tenant', 'rst_warden_application', 'rst_warden_deployment');
DELETE FROM resource_type WHERE id IN
    ('rst_warden_tenant', 'rst_warden_application', 'rst_warden_deployment');

DROP TABLE IF EXISTS setup_token;
DROP TABLE IF EXISTS signing_key;
