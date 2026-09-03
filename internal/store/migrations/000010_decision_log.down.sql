DELETE FROM tenant_isolation_registry WHERE table_name = 'decision_event';
DROP POLICY IF EXISTS tenant_isolation ON decision_event;
DROP TABLE IF EXISTS decision_event;
DROP FUNCTION IF EXISTS warden_create_decision_partition(date);
DROP FUNCTION IF EXISTS warden_protect_partition(text);
