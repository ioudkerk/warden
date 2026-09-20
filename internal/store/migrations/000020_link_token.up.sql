-- The links Warden emails (docs/design-email.md §8, SPEC §7.1, §7.2).
--
-- Four flows, one shape. A magic link, a password reset, an email verification and an
-- invitation are all the same object: a high-entropy value sent to an address, good once,
-- for a bounded time. Four tables would differ only in a lifetime and a name, and the
-- properties that matter — hashed at rest, single use, consumed in the transaction that
-- acts on it — would then have four implementations to keep in step.
--
-- Deliberately separate from setup_token, which is the deployment's own bootstrap: that one
-- exists before any tenant does, has a different lifetime story and is created by a
-- different path. Merging them would mean one table whose rows mean two things.

CREATE TABLE link_token (
    id           text PRIMARY KEY CHECK (id LIKE 'lnk\_%'),

    kind         text NOT NULL,

    tenant_id    text NOT NULL REFERENCES tenant(id),
    user_id      text NOT NULL,

    -- SHA-256 of the token. The token is in exactly one place — the message that was
    -- sent — so a copy of this database does not let anybody sign in as anybody.
    --
    -- Not Argon2id, and the reason is the same one recovery codes and service-account
    -- tokens follow: there is nothing to stretch in 256 bits from crypto/rand, and the
    -- lookup has to be a single indexed read because the token arrives with nothing else
    -- attached to narrow the search.
    token_hash   bytea NOT NULL,

    -- The address being proved, for verify_email: it may differ from the user's current
    -- one, which is the whole point of verifying a change.
    address      citext,

    expires_at   timestamptz NOT NULL,

    -- Set in the same transaction that acts on the token, so a replayed link loses the
    -- race rather than being handled twice.
    consumed_at  timestamptz,

    -- Where the request came from, for the record. A burst of resets from one address is
    -- a signal, and it is only visible if it was written down.
    requested_ip text,

    created_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT link_token_kind_valid
        CHECK (kind IN ('magic_link', 'password_reset', 'verify_email', 'invitation')),
    CONSTRAINT link_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32),

    CONSTRAINT link_token_user_fkey FOREIGN KEY (user_id, tenant_id)
        REFERENCES app_user (id, tenant_id) ON DELETE CASCADE
);

-- Unique across the deployment. The token arrives in a URL with nothing else attached, so
-- it is the whole of the lookup key and a collision between two tenants would be a
-- collision at the one moment it matters.
CREATE UNIQUE INDEX link_token_hash_key ON link_token (token_hash);

-- Redemption invalidates every other outstanding token of the same kind for that user
-- (§8), which is this index.
CREATE INDEX link_token_user_kind_idx ON link_token (tenant_id, user_id, kind)
    WHERE consumed_at IS NULL;
CREATE INDEX link_token_expiry_idx ON link_token (expires_at);

COMMENT ON TABLE link_token IS
    'Single-use emailed links (docs/design-email.md §8). Hashed at rest; consumed in the transaction that acts on them, so a replay loses the race.';

-- ---------------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------------
--
-- Registered as a deliberate exception, on exactly the grounds setup_token is: a link
-- token arrives as a bare value in a URL, so resolving it to a user necessarily happens
-- before any tenant scope can exist. Every read is a single hash lookup through the system
-- pool, and the row it returns is what establishes the scope for everything after it.

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('link_token', false,
     'A link token arrives as a bare value in a URL, so resolving it to its user happens before any tenant scope exists — the same reason setup_token and service_account are exceptions. Read by hash through the system pool only, single use, short-lived.');
