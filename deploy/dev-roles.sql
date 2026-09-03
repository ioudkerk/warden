-- The two roles from roles.sql, for the local development database only.
--
-- Kept separate because it is idempotent and uses throwaway passwords: `make dev-up`
-- starts a Postgres whose superuser owns everything, and this adds the unprivileged
-- application role that makes row-level security actually apply. Run it again after
-- anything that recreates the schema — the integration tests do, and recreating a
-- schema destroys the grants on it.
--
-- For a real deployment use roles.sql, not this.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warden_system') THEN
        CREATE ROLE warden_system LOGIN PASSWORD 'system-pw' BYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warden_app') THEN
        CREATE ROLE warden_app LOGIN PASSWORD 'app-pw';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO warden_app, warden_system;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO warden_app, warden_system;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO warden_app, warden_system;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO warden_app, warden_system;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO warden_app, warden_system;
