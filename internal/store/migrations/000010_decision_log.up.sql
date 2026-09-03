-- The decision log (SPEC §16.2).
--
-- Unlike the audit log this is high volume — one row per authorization decision, at
-- the rate the PDP answers them — so it is configurable per application and written
-- through a buffered sink that never blocks a decision. An authorization service that
-- slows down or fails because its logging backend is unhappy has turned an
-- observability feature into an availability incident.
--
-- Partitioned by month from the start. Converting a large populated table to a
-- partitioned one later means a rewrite under a lock, and this is the table most
-- likely to be large.

CREATE TABLE decision_event (
    id              text NOT NULL,
    tenant_id       text NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),

    subject_id      text NOT NULL,
    application_id  text,
    permission_key  citext NOT NULL,
    resource_ref    text,

    allowed         boolean NOT NULL,
    reason          text NOT NULL,
    matched_grant   text,

    -- How long the decision took, for the latency budget of SPEC §18.
    latency_us      integer,

    -- Set when the answer came from a degraded path: a stale cache entry served
    -- under fail_mode=stale (SPEC §10.6). A decision made on old data must be
    -- distinguishable afterwards from one made on current data.
    degraded        boolean NOT NULL DEFAULT false,

    -- The revision the decision was evaluated against, so a disputed decision can be
    -- reproduced against the policy as it stood rather than as it stands.
    revision        bigint,

    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);

-- A default partition means a decision is never lost because nobody created next
-- month's partition. Rows landing here are a signal that partition maintenance has
-- stopped, not a failure. It is protected below, with the rest.
CREATE TABLE decision_event_default PARTITION OF decision_event DEFAULT;

CREATE INDEX decision_event_tenant_time_idx ON decision_event (tenant_id, occurred_at DESC);
CREATE INDEX decision_event_subject_idx ON decision_event (tenant_id, subject_id, occurred_at DESC);
CREATE INDEX decision_event_denials_idx ON decision_event (tenant_id, reason, occurred_at DESC)
    WHERE NOT allowed;

-- Applies the tenant policy to a partition.
--
-- This is not belt and braces. A partitioned table's policies are applied when the
-- query names the parent, and NOT when it names a partition directly: with the parent
-- protected and the partitions bare, `SELECT * FROM decision_event` correctly returns
-- one tenant's rows while `SELECT * FROM decision_event_2026_09` returns everyone's.
-- The partition is an ordinary table with an ordinary grant, so any role that can read
-- the parent can name it.
-- Idempotent, because a maintenance function that fails when run twice will
-- eventually be run twice.
CREATE OR REPLACE FUNCTION warden_protect_partition(partition_name text)
    RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', partition_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', partition_name);

    IF NOT EXISTS (
        SELECT 1 FROM pg_policy p
          JOIN pg_class c ON c.oid = p.polrelid
         WHERE c.relname = partition_name AND p.polname = 'tenant_isolation'
    ) THEN
        EXECUTE format($p$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = current_setting('warden.tenant_id', true))
                WITH CHECK (tenant_id = current_setting('warden.tenant_id', true))
        $p$, partition_name);
    END IF;
END;
$$;

-- Creates the partition covering a given month, if it is not already there, and
-- protects it. The worker role calls this ahead of time; it is idempotent so calling
-- it repeatedly, or late, is harmless.
CREATE OR REPLACE FUNCTION warden_create_decision_partition(month date)
    RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    start_at date := date_trunc('month', month)::date;
    end_at   date := (date_trunc('month', month) + interval '1 month')::date;
    name     text := format('decision_event_%s', to_char(start_at, 'YYYY_MM'));
BEGIN
    IF to_regclass('public.' || name) IS NOT NULL THEN
        RETURN name;
    END IF;
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF decision_event FOR VALUES FROM (%L) TO (%L)',
        name, start_at, end_at);
    -- Creating a partition without protecting it would open the hole this function
    -- exists to keep closed, on a schedule, months after anyone looked.
    PERFORM warden_protect_partition(name);
    RETURN name;
END;
$$;

COMMENT ON FUNCTION warden_create_decision_partition(date) IS
    'Creates the monthly partition covering the given date. Idempotent; called ahead of time by the worker role.';

SELECT warden_create_decision_partition(current_date);
SELECT warden_create_decision_partition((current_date + interval '1 month')::date);

COMMENT ON TABLE decision_event IS
    'One row per authorization decision, at the level the application configured (SPEC §16.2). Written through a buffered sink that never blocks a decision.';

-- Tenant-scoped: a decision log records who asked what about which object, which is
-- among the more revealing things Warden holds.
ALTER TABLE decision_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_event FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON decision_event
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

-- And every partition, including the default and the two created above.
SELECT warden_protect_partition(c.relname)
  FROM pg_class c
  JOIN pg_inherits i ON i.inhrelid = c.oid
 WHERE i.inhparent = 'decision_event'::regclass;

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped) VALUES
    ('decision_event', true);
