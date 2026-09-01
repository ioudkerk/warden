-- Row-level security: tenant isolation enforced by the database.
--
-- SPEC §6.2 calls this defence in depth behind application-level filtering, and
-- §17.1 lists tenant crossing as a named threat. The point is that a query which
-- forgets its WHERE clause returns nothing rather than everything.
--
-- Three decisions are load-bearing here.
--
-- 1. FORCE ROW LEVEL SECURITY, not just ENABLE.
--    ENABLE alone exempts the table's owner. Warden's migrations run as the owner,
--    and a deployment that also *serves traffic* as the owner would have row-level
--    security switched on and doing nothing, with no symptom at all. FORCE removes
--    that failure mode: the policy applies to everyone, owner included, and the only
--    way past it is the BYPASSRLS attribute, which is explicit and greppable.
--
-- 2. A policy FOR ALL, with USING and WITH CHECK stated separately.
--    USING decides which rows are visible and which may be updated or deleted.
--    WITH CHECK decides which rows a statement may write. For a policy that does not
--    name WITH CHECK, Postgres reuses the USING expression for writes, so the two
--    clauses below are equivalent to writing USING alone — they are spelled out
--    because a reader should not have to know that fallback to be sure that writes
--    are constrained.
--
--    What would be a real hole is a policy scoped to one command, FOR SELECT say:
--    that governs reads and leaves INSERT unconstrained, letting a tenant write rows
--    it cannot read. The test in internal/store asserts every policy is FOR ALL, and
--    a behavioural test attempts a cross-tenant INSERT and UPDATE directly.
--
-- 3. current_setting(..., true).
--    The second argument makes a missing setting return NULL instead of raising.
--    NULL never equals anything, so a connection that has not declared its tenant
--    sees no rows anywhere. Unset means denied, which is the correct default for a
--    variable whose absence would otherwise mean "unrestricted".

-- ---------------------------------------------------------------------------------
-- The tenant table itself
-- ---------------------------------------------------------------------------------

-- Keyed on id rather than tenant_id: a tenant-scoped connection sees exactly one
-- tenant row, its own.
ALTER TABLE tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant
    USING (id = current_setting('warden.tenant_id', true))
    WITH CHECK (id = current_setting('warden.tenant_id', true));

-- ---------------------------------------------------------------------------------
-- Everything carrying tenant_id
-- ---------------------------------------------------------------------------------

ALTER TABLE app_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_user FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app_user
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON credential
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE idp_connection ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp_connection FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idp_connection
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE session ENABLE ROW LEVEL SECURITY;
ALTER TABLE session FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON session
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE refresh_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_token FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON refresh_token
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE group_ ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_ FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON group_
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE group_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_member FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON group_member
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

ALTER TABLE app_enrollment ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_enrollment FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app_enrollment
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

-- ---------------------------------------------------------------------------------
-- Deliberately not protected
-- ---------------------------------------------------------------------------------
--
-- application, environment, resource_type, action and permission are global by
-- design (SPEC §6.1): an application declares its resources, actions and UI elements
-- once and is then enrolled per tenant. They carry no tenant_id and no policy.
--
-- Which tenants use which application is app_enrollment, and that IS protected — so
-- a tenant-scoped connection can see that the "billing" application exists, but not
-- who else has enrolled in it.
--
-- The registry below records that judgement in the database, so the isolation test
-- can assert against a stated intention rather than against whatever happens to be
-- configured. A new table must be classified here or the test fails: forgetting to
-- protect a table is exactly the mistake this is guarding against, and it is silent.

CREATE TABLE tenant_isolation_registry (
    table_name  text PRIMARY KEY,
    tenant_scoped boolean NOT NULL,
    -- Why a table is global. Required for global tables so the exemption is a
    -- decision on the record rather than an oversight.
    rationale   text,

    CONSTRAINT tenant_isolation_registry_global_needs_rationale
        CHECK (tenant_scoped OR rationale IS NOT NULL)
);

COMMENT ON TABLE tenant_isolation_registry IS
    'Declares, per table, whether it holds tenant-scoped data. The isolation test in internal/store cross-checks this against pg_class, so a new table cannot silently escape row-level security.';

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('tenant',         true,  NULL),
    ('app_user',       true,  NULL),
    ('credential',     true,  NULL),
    ('idp_connection', true,  NULL),
    ('identity',       true,  NULL),
    ('session',        true,  NULL),
    ('refresh_token',  true,  NULL),
    ('group_',         true,  NULL),
    ('group_member',   true,  NULL),
    ('app_enrollment', true,  NULL),
    ('application',    false, 'Applications are declared globally and enrolled per tenant (SPEC §6.1). The enrollment is what is tenant-scoped.'),
    ('environment',    false, 'Belongs to an application, which is global.'),
    ('resource_type',  false, 'Part of an application''s declared permission surface, which is global.'),
    ('action',         false, 'Part of an application''s declared permission surface, which is global.'),
    ('permission',     false, 'The materialized permission atoms of a global application surface.'),
    ('schema_migrations', false, 'golang-migrate bookkeeping.'),
    ('tenant_isolation_registry', false, 'This registry itself; it describes the schema, not any tenant.');
