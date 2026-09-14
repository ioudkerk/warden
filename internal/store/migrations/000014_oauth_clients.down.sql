DELETE FROM tenant_isolation_registry WHERE table_name = 'oauth_client';
DROP TABLE IF EXISTS oauth_client;
