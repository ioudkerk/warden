# ADR-0004 — Cross-tenant identity: no `person` entity in v1

**Status:** Accepted
**Date:** 2026-09-04

## Context

SPEC §6.2 says a subject exists within exactly one tenant, and that one human across
several tenants is modelled as "one `person` with several `user` records linked by a
verified email or an external `idp_subject`". It then marks as *(open)* whether v1
exposes that linkage at all.

The open part is larger than the wording suggests. `docs/data-model.md` contains no
`person` table, and the implemented schema has none: `app_user` is unique on
`(tenant_id, email)` and nothing above it. So the question is not only whether to
*expose* the linkage but whether to *store* it, and that has to be settled before M1
creates the first login flow that would need it.

The thing that makes this worth a decision rather than a default is that
`app_user.tenant_id` is `NOT NULL` and every isolation guarantee in the system is built
on it. A `person` is by construction the one entity that spans tenants.

## What actually needs cross-tenant identity

Working backwards from the roadmap, three things:

1. **A login page that asks "which organisation?"** when one address exists in
   several tenants. Needed the moment a second tenant shares a user — plausibly at
   M1, certainly by M4 with federation.
2. **GDPR export and erasure per subject** (§16.4), which must find every record of a
   person across the deployment.
3. **"Is this the same human?" in support and audit contexts** — the console's user
   view (M6).

None of them is a decision-path concern. Authorization evaluation is single-tenant by
design and stays so under every option.

## Options

### A. A `person` table, populated from the start
A row per human; `app_user.person_id` links to it. Linking on a verified email or a
matching `(connection_id, external_subject)`.

- Cross-tenant questions become a single indexed lookup.
- Erasure has one authoritative starting point.
- Cost: a cross-tenant foreign key on the most security-sensitive table in the schema.
  Every query joining through it is a query where a missing predicate crosses a tenant
  boundary — which is threat 5 of §17.1, and the one the row-level security work exists
  to make structurally difficult. `person` cannot be tenant-scoped, by definition, so
  it is an exemption from the isolation model rather than a participant in it.
- Requires deciding the linking rule *now*, before federation exists to inform it. Get
  it wrong and two humans share a `person` row, which is an account-takeover primitive
  wearing a data-modelling costume.

### B. No stored entity; derive the linkage when asked
Answer cross-tenant questions from what already exists: `identity` (unique on
`(connection_id, external_subject)`) and `app_user.email` where `email_verified`.

- Nothing spans tenants in the schema. The isolation model stays uniform: every table
  is either tenant-scoped with a policy, or global with a written rationale.
- The linking rule lives in one function, changeable without a migration, and can be
  informed by real federation behaviour rather than guessed at now.
- Cost: cross-tenant questions are a scan or an index lookup per candidate, not a join.
  At §18's scale — a million users — an index on `app_user (email) WHERE
  email_verified` answers "which tenants is this address in?" in one lookup; it is a
  cross-tenant read, so it runs on the system pool and is audited.
- Cost: no stable identifier for a human. An erasure request is a search, and two
  searches a year apart can return different sets if an address changed.

### C. Defer entirely
Say nothing, build nothing, and let M1 decide under pressure.

- The option that produces a `person` table designed in an afternoon during login work.

## Decision

**B.** v1 stores no `person` entity. Cross-tenant identity is derived, through a single
documented function, from verified email and federated subject.

The reasoning is mostly about where the risk sits. A cross-tenant foreign key on
`app_user` is a permanent structural exemption from the isolation model, added to serve
features that do not exist yet, with a linking rule guessed before federation is built.
Deriving the answer costs a lookup and keeps the schema's central invariant — *every
table is either tenant-scoped or globally justified* — intact and mechanically
checkable, which the isolation test already relies on.

The asymmetry decides it: **adding `person` later is an additive migration and a
backfill; removing it later is not.** Nothing about option B forecloses option A.

Concretely for v1:

1. No `person` table, and no `app_user.person_id`.
2. A `LinkedAccounts(ctx, email)` helper in the identity layer, on the system pool,
   audited as the cross-tenant read it is. It is the *only* sanctioned way to ask the
   question, so the linking rule has one home.
3. The linking rule is: **a verified email match, or a shared
   `(connection_id, external_subject)`.** An unverified address links nothing — the
   same rule as §7.4.1's `email_trusted` default, and for the same reason.
4. The login page's tenant picker (M1) uses it. Nothing on the decision path does.
5. GDPR export and erasure (§16.4) use it, and their documentation states plainly that
   the result is a point-in-time search rather than a lookup of a stored identity.

## Consequences

- §6.2's *(open)* marker is resolved, and its description of `person` becomes a
  statement of the conceptual model rather than of the schema. SPEC §6.2 is updated to
  say so.
- The isolation test's invariant holds without an exception: no table both carries
  tenant data and escapes a policy.
- An address change breaks the linkage silently. A human who changes their email in
  one tenant and not another stops being recognisably the same person. This is
  acceptable at v1 — the feature it degrades is a login-page convenience — and it is
  the strongest argument for revisiting.
- **Revisit at M4 or M6**, whichever first needs the linkage to be stable rather than
  derived. Federation will have supplied real data on how often the two rules agree,
  which is the input this decision is currently missing.
- If the answer becomes yes: add `person` and `app_user.person_id` (nullable),
  backfill by running the existing rule, and make it authoritative only once the
  backfill is verified. The derivation function becomes the backfill, which is a
  reason to keep it in one place.
