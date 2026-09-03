DROP TRIGGER IF EXISTS role_immutable_no_delete ON role;
DROP TRIGGER IF EXISTS role_immutable_no_update ON role;
DROP FUNCTION IF EXISTS warden_role_immutable();

DELETE FROM app_enrollment WHERE application_id = 'app_warden';
DELETE FROM role_inheritance WHERE role_id LIKE 'rol_tenant_%';
DELETE FROM role_permission WHERE role_id LIKE 'rol_tenant_%';
UPDATE role SET immutable = false WHERE id LIKE 'rol_tenant_%';
DELETE FROM role WHERE id LIKE 'rol_tenant_%';
DELETE FROM permission WHERE application_id = 'app_warden';
DELETE FROM action WHERE resource_type_id LIKE 'rst_warden_%';
DELETE FROM resource_type WHERE application_id = 'app_warden';
DELETE FROM application WHERE id = 'app_warden';
