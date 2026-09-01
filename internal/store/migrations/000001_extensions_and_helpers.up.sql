-- Extensions and helpers every later migration depends on.
--
-- Migrations are forward-only and follow expand/contract (SPEC §19, §20.2): never
-- drop a column in the same release that stops writing it, and every migration must
-- be runnable against a live cluster. Indexes added to an existing table in a later
-- release use CREATE INDEX CONCURRENTLY; the initial creation below does not, because
-- there is no live cluster to block.

-- Case-insensitive text, used for every natural key an operator types: email
-- addresses, tenant slugs, role keys, permission keys. Comparing these
-- case-sensitively is a source of duplicate accounts and of grants that silently do
-- not match.
CREATE EXTENSION IF NOT EXISTS citext;

-- Keeps updated_at honest. A column maintained only by application code drifts the
-- first time a row is touched by a migration, a backfill or psql.
CREATE OR REPLACE FUNCTION warden_set_updated_at() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION warden_set_updated_at() IS
    'BEFORE UPDATE trigger: stamps updated_at with the transaction timestamp.';
