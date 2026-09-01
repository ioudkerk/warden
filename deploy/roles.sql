-- Database roles for a Warden deployment. Run once, as a superuser, against the
-- database Warden will use. Substitute real passwords, or use whatever
-- authentication your cluster is configured for.
--
-- Warden needs two roles, and the separation is what makes tenant isolation real.
--
--   warden_app     serves requests. Subject to row-level security, always. Every
--                  query it runs is confined to the tenant its transaction declared.
--
--   warden_system  runs migrations, `warden init`, and the cross-tenant background
--                  jobs (assignment expiry, audit shipping). Holds BYPASSRLS,
--                  because those jobs are inherently cross-tenant, and SPEC §6.2
--                  requires that such work be audited precisely because it is not
--                  constrained by the database.
--
-- Warden verifies at startup that the role behind `database.url` cannot bypass
-- row-level security, and refuses to serve production traffic if it can. A single
-- role pointed at both settings is therefore not a shortcut — it will not start.

-- ---------------------------------------------------------------------------------

CREATE ROLE warden_system LOGIN PASSWORD 'change-me' BYPASSRLS;
CREATE ROLE warden_app LOGIN PASSWORD 'change-me';

-- warden_system owns the schema, so migrations can alter it.
ALTER DATABASE warden OWNER TO warden_system;
\connect warden
ALTER SCHEMA public OWNER TO warden_system;

-- warden_app reads and writes data but never changes the schema. It is deliberately
-- not the owner: FORCE ROW LEVEL SECURITY means ownership would not exempt it
-- anyway, but keeping DDL out of the request-serving role is worth having on its own.
GRANT USAGE ON SCHEMA public TO warden_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO warden_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO warden_app;

-- And on everything a future migration creates.
ALTER DEFAULT PRIVILEGES FOR ROLE warden_system IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO warden_app;
ALTER DEFAULT PRIVILEGES FOR ROLE warden_system IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO warden_app;

-- ---------------------------------------------------------------------------------
-- Then configure Warden:
--
--   database:
--     url:        postgres://warden_app@host/warden?sslmode=verify-full
--     system_url: postgres://warden_system@host/warden?sslmode=verify-full
--
-- system_url is optional. Without it Warden serves tenant traffic normally, but
-- migrations, bootstrap and cross-tenant jobs are unavailable and say so.
