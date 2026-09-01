# Security policy

Warden is an identity and authorization service. A vulnerability here is a
vulnerability in every application that trusts it, so we would much rather hear about
a suspected problem than not.

## Reporting a vulnerability

**Do not open a public issue.** Report privately, by either:

- GitHub's private vulnerability reporting — the **Report a vulnerability** button
  under the repository's Security tab; or
- email to **security@warden.example** *(placeholder: replace with the real address
  before this repository is made public — see task M0-3)*.

Please include: what you found, the version or commit, how to reproduce it, and what
an attacker gains. A proof of concept helps enormously. If you need encryption, say
so in a first message and we will send a key.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement that a human has read your report | 2 working days |
| Initial assessment, with a severity and a rough timeline | 7 calendar days |
| Fix released, or a written explanation of the delay | 90 days |

We will keep you updated as the fix progresses, credit you in the advisory unless you
prefer otherwise, and let you know before we publish. We ask that you give us those
90 days before public disclosure, and that you do not access, modify or exfiltrate
other people's data while testing.

We do not currently run a paid bug bounty.

## What is in scope

The server, the SDKs, the console, the deployment manifests in `deploy/`, and the
documentation where it recommends something insecure. Findings in a dependency should
usually go to that project; tell us as well if Warden's use of it makes the impact
worse.

### Of particular interest

These are the failures that would matter most, and the ones the threat model
(`docs/threat-model.md`) is built around:

- **Authorization bypass** — any path where `check` returns allow without a grant
  that justifies it, or where an explicit deny is not honoured.
- **Tenant crossing** — reaching another tenant's users, roles, grants or audit log,
  whether through the API, the console, or a gap in row-level security.
- **Privilege escalation through role assignment** — assigning a role carrying
  permissions the assigner does not hold.
- **Token and session flaws** — signature confusion, `kid` handling, audience or
  issuer confusion, refresh-token replay that does not revoke the family.
- **Federation flaws** — SAML signature wrapping or XXE, OIDC `state`/`nonce`
  handling, account takeover through an unverified federated email.
- **Stale permissions after revocation** beyond the bounds documented in SPEC §10.5.
- **Secret exposure** — a credential, key or token reaching a log, an error message,
  an audit record, or a decision explanation.

## What is out of scope

- **UI element binding is not a security boundary.** Warden lets an administrator
  hide or disable a button (SPEC §11), and that is a UX control. A report that a
  hidden button's endpoint is still reachable is working as designed — unless the
  endpoint itself is missing its server-side check, which very much is a finding.
- Findings that require an already-compromised host, database or KEK.
- Missing hardening headers with no demonstrated impact, output from an automated
  scanner with no analysis, denial of service by brute volume, or social
  engineering of maintainers.
- The example configurations under `deploy/` and `examples/`, which are documented as
  development-only and use throwaway credentials.

## Supported versions

Until 1.0, only the latest release receives fixes. From 1.0, the current minor
release and the one before it, for six months.

## How we handle a report

Fixes are developed privately, released as a new patch version for every supported
release line, and published as a GitHub Security Advisory with a CVE. Releases are
signed and carry an SBOM (SPEC §17); the advisory names the affected versions, the
fix, and any mitigation available without upgrading.
