-- Whether a service account may ask for a derivation.
--
-- SPEC §10.3 limits explanations to tenant admins and non-production environments,
-- because a derivation describes the policy: which grants exist, which reach which
-- objects, which attribute each condition compares. An ordinary application does not
-- need that to enforce anything, and handing it out by default would make the most
-- revealing endpoint the easiest one to reach.
--
-- Defaults to false. An account that needs it — a support tool, the console's
-- simulator (SPEC §14.2) — is marked deliberately.
ALTER TABLE service_account ADD COLUMN may_explain boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN service_account.may_explain IS
    'Permits POST /v1/authz/explain in production. Derivations leak policy structure (SPEC §10.3).';
