DROP FUNCTION IF EXISTS warden_set_updated_at();

-- citext is deliberately left in place. Dropping an extension another database
-- object might depend on is not a safe rollback, and the extension is harmless.
