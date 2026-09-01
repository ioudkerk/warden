# ADR-0003 — Project shape and license

**Status:** Accepted (license choice needs ratification — see Decision)
**Date:** 2026-08-31

## Context

SPEC §23 Q2 asked whether Warden is a product to sell, an internal platform, or open source.
The answer changes three things concretely:

- **Tenancy depth.** An internal platform can collapse §6 to a single tenant and drop the
  `system` tenant, per-tenant IdP connections and tenant-custom role forking. A public
  project cannot.
- **Console scope.** With no hosted alternative, the console is the *only* administration
  surface. Every management API call needs a UI, and §14.2's simulator stops being a nice
  extra and becomes the support channel.
- **Licensing, governance and release engineering.** Signed releases, an SBOM, a security
  policy with a disclosure address, and a contribution process are table stakes for a public
  identity project — they are optional inside a company.

## Decision

**Warden is an open source project.** Consequently:

1. Multi-tenancy is built as specified in §6. No simplification.
2. The console (§14) is a v1 deliverable at full scope, including the simulator.
3. The **recommended license is Apache-2.0** — permissive so applications can depend on the
   SDKs without friction, with an explicit patent grant, which matters for an auth product.
   *This specific choice is the one piece still open; it is cheap to change before the first
   public commit and expensive afterwards.* Alternatives if a source-available posture is
   wanted later: BSL 1.1 on the server with Apache-2.0 SDKs, the Sentry/Cockroach pattern.
4. The SDKs (`warden-sdk`, `@warden/browser`, `@warden/react`) carry the same license as the
   server, so no dual-license bookkeeping.
5. Security posture is public: `SECURITY.md` with a disclosure address and an SLA, a
   published threat model (§17.1), CVE handling, and signed + attested releases (§17,
   SLSA level 2).
6. "Warden" remains a placeholder (§23 Q9). **Trademark clearance is now a blocker for the
   first public release**, not for the first commit — going public raises the cost of a
   rename sharply, so clear the name before the repo is published, not before 1.0.

## Consequences

- Added at M0: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), issue and PR templates.
- **Inbound contributions use the DCO, not a CLA.** A CLA requires a legal entity to
  receive the granted rights, and this project has none; the DCO gets the same
  assurance that a contributor may submit their work without asking anyone to sign
  anything. Apache-2.0 §5 already covers the inbound licence grant. Recorded in
  `CONTRIBUTING.md`.
- Release engineering (signing, SBOM, attestation) moves from M8 into CI at M0 in skeleton
  form, because retrofitting provenance to an already-published artifact history is
  worthless.
- The reference application (`examples/`) doubles as the onboarding path for outside
  contributors and gets weighted accordingly in M3/M5.
- No licensing or entitlement machinery in the codebase.
