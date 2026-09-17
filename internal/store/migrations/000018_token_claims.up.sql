-- Which authorization facts a client's access tokens may carry (SPEC §8.2).
--
-- Empty by default, and the default is the decision. Warden is the policy decision point:
-- "may this person do this?" is answered by /v1/authz/check against a model an
-- administrator can change, not by an application reading a role list out of a JWT it was
-- handed ten minutes ago. Putting roles in the token is how other identity servers work,
-- and it is a different product — the app ends up deciding, the decision is invisible to
-- the audit log, and a permission change does not take effect until the token expires.
--
-- The claims stay available because there is one case they are right for: a third-party
-- resource server that speaks JWT and will never call the decision API. That is a
-- deliberate concession a tenant makes per client, not the path everybody is put on.
--
-- Three things follow from the empty default:
--   * a token is ~400 bytes whether the subject has three groups or five thousand, so the
--     4 KB cap of §8.2 stops being something most deployments ever meet;
--   * a person's group and role membership stops travelling to every resource server and
--     into every access log along the way;
--   * the roles a token would have asserted cannot go stale, because they are not there.
ALTER TABLE oauth_client
    ADD COLUMN token_claims text[] NOT NULL DEFAULT '{}';

-- A closed vocabulary, so a typo is a failed write rather than a claim that silently
-- never appears.
ALTER TABLE oauth_client
    ADD CONSTRAINT oauth_client_token_claims_valid
    CHECK (token_claims <@ ARRAY['roles', 'groups']);

COMMENT ON COLUMN oauth_client.token_claims IS
    'Authorization facts this client''s access tokens may carry in wd (SPEC §8.2): any of roles, groups. Empty means none, which is the default — Warden decides, the token does not.';
