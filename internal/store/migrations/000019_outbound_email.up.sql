-- Email delivery (docs/design-email.md §5, §6).
--
-- Sending is asynchronous and durable, which is the opposite of the decision log's choice
-- and for the opposite reason: a dropped decision record is an observability gap, while a
-- dropped password-reset email is a person who cannot get into their account.
--
-- The row is written in the *same transaction* as the state it describes, so a reset token
-- and the intent to email it commit together. Neither can exist without the other — no
-- token nobody was told about, and no message promising a link that was never stored.

CREATE TABLE outbound_email (
    id              text PRIMARY KEY CHECK (id LIKE 'eml\_%'),

    -- Null for a message that belongs to the deployment rather than to a tenant: the
    -- first owner's setup link is sent before any tenant exists. A null row is invisible
    -- to every tenant-scoped connection and visible to the worker, which is what the
    -- row-level security policy below arranges.
    tenant_id       text REFERENCES tenant(id),

    to_address      citext NOT NULL,
    template        text NOT NULL,
    locale          text NOT NULL DEFAULT 'en',

    -- What the template needs, and deliberately **not the token**. The token lives in its
    -- own table and is read at send time, so a queue row is not a second copy of a
    -- credential with a different retention and a different set of eyes on it.
    payload         jsonb NOT NULL DEFAULT '{}',

    status          text NOT NULL DEFAULT 'pending',
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),

    -- The reason a send failed, for an operator. Never the body: it contains a credential.
    last_error      text,

    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,

    CONSTRAINT outbound_email_status_valid
        CHECK (status IN ('pending', 'sent', 'failed', 'suppressed')),
    CONSTRAINT outbound_email_attempts_sane
        CHECK (attempts >= 0)
);

-- The worker's claim query orders by next_attempt_at among pending rows, so the index
-- covers exactly that and nothing else.
CREATE INDEX outbound_email_pending_idx
    ON outbound_email (next_attempt_at)
    WHERE status = 'pending';
CREATE INDEX outbound_email_tenant_idx ON outbound_email (tenant_id);

COMMENT ON COLUMN outbound_email.payload IS
    'Template data. Never the token: that is read from its own table at send time, so this row is not a second copy of a credential.';

-- ---------------------------------------------------------------------------------
-- Suppression
-- ---------------------------------------------------------------------------------
--
-- Delivering repeatedly to an address that hard-bounces is how a sending domain gets
-- blocked, and then nobody's reset arrives. Suppression is per *deployment* rather than
-- per tenant: a bounce is a property of the address, and the sending reputation being
-- protected is shared between every tenant on the deployment.

CREATE TABLE email_suppression (
    address         citext PRIMARY KEY,
    reason          text NOT NULL,
    suppressed_at   timestamptz NOT NULL DEFAULT now(),
    last_bounce_at  timestamptz,
    note            text,

    CONSTRAINT email_suppression_reason_valid
        CHECK (reason IN ('hard_bounce', 'complaint', 'manual'))
);

COMMENT ON TABLE email_suppression IS
    'Addresses that must not be sent to (docs/design-email.md §6). Deployment-wide, because a bounce is a property of the address and the sending reputation is shared.';

-- ---------------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------------
--
-- outbound_email is tenant-scoped: a queued message names an address and a template, and
-- one tenant's queue is not another's business. The worker reads it through the system
-- pool, which is the same arrangement the decision log uses and for the same reason —
-- draining a queue is deployment work, not tenant work.
--
-- email_suppression is deliberately *not* registered: it is deployment-wide by design, and
-- registering it as tenant-scoped would be claiming a property it does not have.

ALTER TABLE outbound_email ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbound_email FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON outbound_email
    USING (tenant_id = current_setting('warden.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('warden.tenant_id', true));

INSERT INTO tenant_isolation_registry (table_name, tenant_scoped, rationale) VALUES
    ('outbound_email', true, NULL),
    ('email_suppression', false,
     'Deployment-wide by design: a bounce is a property of the address, and the sending reputation it protects is shared by every tenant.');
