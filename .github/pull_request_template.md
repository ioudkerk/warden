## What this changes

<!-- What the change does, and why it is needed. Link the issue if there is one. -->

## Milestone / task

<!-- e.g. M0-4, or "none — drive-by fix". See docs/tasks.md. -->

## How it was verified

<!--
Say what you actually ran, not what could be run. If a behaviour is not covered by a
test, say so and why.
-->

- [ ] `make ci` passes locally

## Checklist

- [ ] Commits are signed off (`git commit -s`) — see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Behaviour changes are covered by tests that would fail without the change
- [ ] A change to authorization semantics adds or updates a case in `conformance/`
- [ ] No new path where something ambiguous resolves toward "allowed"
- [ ] No credential, key or token can reach a log, error, audit record or explanation
- [ ] Tenant-scoped changes have a case proving a foreign `tenant_id` cannot reach the data
- [ ] Documentation and `SPEC.md` updated where the change makes them wrong
- [ ] New dependencies justified in the description

## Security impact

<!--
If this touches authentication, authorization, tokens, sessions, federation, secrets
or tenant isolation: what could an attacker do before this change that they cannot
after it — or the reverse. Write "none" if there genuinely is none.
-->
