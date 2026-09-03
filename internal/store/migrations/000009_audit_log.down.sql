DELETE FROM tenant_isolation_registry WHERE table_name = 'audit_event';
DROP TRIGGER IF EXISTS audit_event_no_truncate ON audit_event;
DROP TRIGGER IF EXISTS audit_event_no_delete ON audit_event;
DROP TRIGGER IF EXISTS audit_event_no_update ON audit_event;
DROP TABLE IF EXISTS audit_event;
DROP FUNCTION IF EXISTS warden_audit_append_only();
