-- Groups. A set of subjects that receives role assignments exactly like a user does
-- (SPEC §9.4), and the mechanism by which an upstream directory's structure becomes
-- Warden's.

-- Named group_ because GROUP is a reserved word.
CREATE TABLE group_ (
    id              text PRIMARY KEY CHECK (id LIKE 'grp\_%'),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    key             citext NOT NULL,
    name            text NOT NULL,

    -- local: managed in Warden. idp: projected from a connection's claim on every
    -- login, and replaced wholesale each time, so an upstream removal takes effect
    -- at next login. scim: pushed by a directory (v2).
    source          text NOT NULL DEFAULT 'local',

    connection_id   text REFERENCES idp_connection(id),
    attributes      jsonb NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT group_source_valid CHECK (source IN ('local', 'idp', 'scim')),

    -- An IdP-sourced group without a connection could never be refreshed, and a
    -- local group with one would be silently overwritten at the next login.
    CONSTRAINT group_connection_matches_source CHECK (
        (source = 'local' AND connection_id IS NULL) OR
        (source IN ('idp', 'scim') AND connection_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX group_tenant_key_key ON group_ (tenant_id, key);
CREATE INDEX group_tenant_id_idx ON group_ (tenant_id);
CREATE INDEX group_connection_idx ON group_ (connection_id) WHERE connection_id IS NOT NULL;

-- Supports group_member's composite foreign keys.
ALTER TABLE group_ ADD CONSTRAINT group_id_tenant_key UNIQUE (id, tenant_id);

CREATE TRIGGER group_set_updated_at BEFORE UPDATE ON group_
    FOR EACH ROW EXECUTE FUNCTION warden_set_updated_at();

-- Membership. A row holds either a user or a nested group, never both and never
-- neither — nesting forms a DAG whose depth is capped in the application layer
-- (SPEC §9.4).
CREATE TABLE group_member (
    group_id        text NOT NULL,
    member_user_id  text,
    member_group_id text,

    -- Denormalized so row-level security is a column comparison. The three composite
    -- foreign keys below make it more than a convenience: they are what forbids a
    -- membership row that spans two tenants, which is otherwise the easiest way to
    -- accidentally leak a subject across the isolation boundary.
    tenant_id       text NOT NULL REFERENCES tenant(id),

    source          text NOT NULL DEFAULT 'local',
    added_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT group_member_exactly_one_member
        CHECK (num_nonnulls(member_user_id, member_group_id) = 1),
    CONSTRAINT group_member_source_valid CHECK (source IN ('local', 'idp', 'scim')),

    -- A group containing itself is the shortest possible cycle, and the one most
    -- likely to arrive from a mis-mapped IdP claim. Longer cycles are rejected by
    -- the application layer, which has to walk the graph anyway.
    CONSTRAINT group_member_no_self_nesting CHECK (member_group_id IS DISTINCT FROM group_id),

    CONSTRAINT group_member_group_fkey FOREIGN KEY (group_id, tenant_id)
        REFERENCES group_ (id, tenant_id) ON DELETE CASCADE,

    -- MATCH SIMPLE: when the member column is NULL the constraint is satisfied, which
    -- is what allows one nullable column per membership kind.
    CONSTRAINT group_member_user_fkey FOREIGN KEY (member_user_id, tenant_id)
        REFERENCES app_user (id, tenant_id) ON DELETE CASCADE,

    CONSTRAINT group_member_nested_group_fkey FOREIGN KEY (member_group_id, tenant_id)
        REFERENCES group_ (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX group_member_tenant_id_idx ON group_member (tenant_id);

CREATE UNIQUE INDEX group_member_user_key
    ON group_member (group_id, member_user_id) WHERE member_user_id IS NOT NULL;
CREATE UNIQUE INDEX group_member_group_key
    ON group_member (group_id, member_group_id) WHERE member_group_id IS NOT NULL;

-- The recursive CTE that resolves a subject's groups walks upward from the member,
-- so this is the index it needs (SPEC data-model, "hot-path queries").
CREATE INDEX group_member_by_user_idx
    ON group_member (member_user_id) WHERE member_user_id IS NOT NULL;
CREATE INDEX group_member_by_group_idx
    ON group_member (member_group_id) WHERE member_group_id IS NOT NULL;
