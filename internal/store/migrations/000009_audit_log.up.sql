-- The administrative audit log (SPEC §16.1).
--
-- Append-only and hash-chained: each entry's hash covers the previous entry's hash
-- and its own content, so removing or altering any entry breaks verification of every
-- entry after it. That is what makes the log evidence rather than a convenience —
-- an attacker who reaches the database can still delete rows, but cannot do so
-- without leaving the chain broken.
--
-- Append-only is enforced by a trigger rather than by convention, because the value
-- of the property is precisely that it holds when someone does not want it to.

CREATE TABLE audit_event (
    id              text PRIMARY KEY CHECK (id LIKE 'aud\_%'),

    -- Chain position. A single global chain rather than one per tenant: verifying
    -- one sequence is simpler than verifying many, and administrative writes are
    -- low volume, so the serialisation costs nothing that matters.
    seq             bigint GENERATED ALWAYS AS IDENTITY,

    -- NULL for deployment-level actions that belong to no tenant.
    tenant_id       text REFERENCES tenant(id),

    occurred_at     timestamptz NOT NULL DEFAULT now(),

    -- Who. One of these is set, or none for an action taken by the system itself.
    actor_user_id   text,
    actor_client_id text,
    -- Set when the action happened while impersonating (SPEC §14.3), so an audit
    -- entry names both identities rather than only the one that appeared to act.
    impersonator_id text,

    action          text NOT NULL,
    target_type     text,
    target_id       text,

    -- The change, as it was. Secret values must be redacted before they reach here:
    -- an audit log that records a client secret has turned a compliance control into
    -- a second copy of the credential store.
    --
    -- json, not jsonb, and that is load-bearing. jsonb is a parsed representation: it
    -- reorders object keys by length before byte order, and reformats separators. The
    -- hash is taken over the bytes written, so a jsonb round trip returns different
    -- bytes and every entry fails its own verification — which is exactly what
    -- happened on the first run of `warden audit -verify`. json stores an exact copy
    -- of the input text.
    --
    -- The cost is no GIN index on the diff. The log is queried by tenant, time and
    -- target, all of which are indexed above; searching inside a diff is a job for
    -- the export path (SPEC §16.1), not for this table.
    before          json,
    after           json,

    -- Required for the actions that demand a justification (SPEC §9.7, §14.3).
    reason          text,

    ip              inet,
    user_agent      text,
    request_id      text,

    prev_hash       bytea,
    hash            bytea NOT NULL,

    CONSTRAINT audit_event_hash_is_sha256 CHECK (octet_length(hash) = 32),
    CONSTRAINT audit_event_prev_hash_is_sha256
        CHECK (prev_hash IS NULL OR octet_length(prev_hash) = 32)
);

CREATE INDEX audit_event_tenant_time_idx ON audit_event (tenant_id, occurred_at DESC);
CREATE INDEX audit_event_target_idx ON audit_event (target_type, target_id);
CREATE INDEX audit_event_action_idx ON audit_event (action, occurred_at DESC);
CREATE UNIQUE INDEX audit_event_seq_key ON audit_event (seq);

-- Append-only, enforced. A log that can be edited records what someone was willing to
-- leave behind, which is a different thing from what happened.
CREATE OR REPLACE FUNCTION warden_audit_append_only() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_event is append-only: % is not permitted', TG_OP
        USING HINT = 'Correct a mistaken entry by appending a correcting one.';
END;
$$;

CREATE TRIGGER audit_event_no_update BEFORE UPDATE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION warden_audit_append_only();
CREATE TRIGGER audit_event_no_delete BEFORE DELETE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION warden_audit_append_only();
CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION warden_audit_append_only();

COMMENT ON TABLE audit_event IS
    'Append-only, hash-chained record of every administrative mutation (SPEC §16.1). Enforced by trigger; verify the chain with `warden audit verify`.';

-- Not tenant-scoped in the row-level-security sense. The chain spans tenants, so
-- verifying it requires reading all of it, and a tenant-scoped connection reading a
-- subset would compute a different chain and report tampering that had not happened.
-- Reading it is a system-pool operation; the per-tenant audit view of the console
-- will filter on tenant_id above that.
INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('audit_event', false,
     'The hash chain spans every tenant, so verification must read the whole sequence; a tenant-scoped connection would see a subset and compute a broken chain. Read through the system pool, filtered by tenant_id above it.');
