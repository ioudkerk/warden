DROP POLICY IF EXISTS tenant_isolation ON resource_node;
DROP POLICY IF EXISTS tenant_isolation ON denial;
DROP POLICY IF EXISTS tenant_isolation ON grant_;
DROP POLICY IF EXISTS tenant_isolation ON role_permission;
DROP POLICY IF EXISTS tenant_isolation ON role_inheritance;
DROP POLICY IF EXISTS tenant_isolation ON role;

DELETE FROM tenant_isolation_registry
 WHERE table_name IN ('role', 'role_inheritance', 'role_permission', 'grant_', 'denial', 'resource_node');

DROP TABLE IF EXISTS resource_node;
DROP TABLE IF EXISTS denial;
DROP TABLE IF EXISTS grant_;
DROP TABLE IF EXISTS role_permission;
DROP TABLE IF EXISTS role_inheritance;
DROP TABLE IF EXISTS role;
