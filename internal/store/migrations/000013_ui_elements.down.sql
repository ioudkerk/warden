DELETE FROM tenant_isolation_registry WHERE table_name IN ('ui_binding', 'ui_element');
DELETE FROM role_permission WHERE permission_key IN ('warden.ui:bind', 'warden.ui:read');
DELETE FROM permission WHERE id IN ('prm_warden_ui_read', 'prm_warden_ui_bind');
DELETE FROM action WHERE resource_type_id = 'rst_warden_ui';
DELETE FROM resource_type WHERE id = 'rst_warden_ui';
DROP POLICY IF EXISTS tenant_isolation ON ui_binding;
DROP TABLE IF EXISTS ui_binding;
DROP TABLE IF EXISTS ui_element;
