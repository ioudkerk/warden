DELETE FROM tenant_isolation_registry WHERE table_name = 'oauth_session';
DROP TABLE IF EXISTS oauth_session;

DROP INDEX IF EXISTS refresh_token_request_idx;
ALTER TABLE refresh_token
    DROP COLUMN IF EXISTS request_id,
    DROP COLUMN IF EXISTS subject,
    DROP COLUMN IF EXISTS granted_scope,
    DROP COLUMN IF EXISTS granted_audience,
    DROP COLUMN IF EXISTS form,
    DROP COLUMN IF EXISTS session_data;
