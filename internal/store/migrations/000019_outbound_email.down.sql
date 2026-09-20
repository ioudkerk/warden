DELETE FROM tenant_isolation_registry WHERE table_name IN ('outbound_email', 'email_suppression');
DROP TABLE IF EXISTS email_suppression;
DROP TABLE IF EXISTS outbound_email;
