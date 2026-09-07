# Warden — Task breakdown

**Derived from:** [`../SPEC.md`](../SPEC.md) §22 roadmap.
**Decided:** server is Go ([ADR-0001](adr/0001-server-language.md)); project is open source
([ADR-0003](adr/0003-project-shape-and-license.md)).

The roadmap in SPEC §22 gives milestones and week ranges. This document turns M0–M3 into
tasks a person can pick up, and keeps M4–M8 at story grain until the milestone before them
lands. Each task states its **exit condition** — the thing that must be demonstrably true,
not "the code is written".

Conventions used below:
- **[B]** blocks the rest of its milestone. Do these first.
- **[P]** parallelisable with its siblings.
- A task with no dependency listed depends only on M0 being complete.

---

## Repository layout (settled at M0-1, everything else assumes it)

```
cmd/warden/              # single binary, --role={auth,pdp,mgmt,worker,all}
internal/
  config/                # env + file config, validation, no silent defaults for secrets
  secrets/               # Secret type, KEK resolution, AES-256-GCM envelope encryption
  store/                 # postgres access, sqlc-generated queries, RLS session handling
    schema.sql           # committed pg_dump of the migrated schema; CI diffs it
    migrations/          # golang-migrate, forward-only, expand/contract
  tenant/  user/  group/ # domain packages
  authn/                 # local credentials, TOTP, WebAuthn, sessions
  oidcop/                # Warden as OpenID Provider (fosite)
  federation/            # Warden as OIDC RP and SAML SP
  authz/                 # THE PDP: resolver, closure, scope match, CEL, explain
  uibind/                # UI elements, bindings, bundle assembly
  mgmtapi/  authzapi/    # HTTP surfaces
  audit/                 # hash-chained admin log + decision sink
  events/                # change stream, revision counter, Redis fan-out
conformance/             # language-neutral YAML corpus + Go runner  ← written before the PDP
  reference/             # a plain transcription of §10.2, so the corpus has a second
                         # implementation to disagree with. NOT the PDP.
sdk/python/              # warden-sdk
sdk/js/                  # @warden/browser, @warden/react
console/                 # React SPA (Vite)
testing/                 # mock OIDC OP, mock SAML IdP, hostile SAML fixture corpus
bench/                   # k6 scenarios + regression gates
deploy/                  # docker-compose, Helm chart
```

---

## M0 — Foundations (SPEC §22 M0)

**Milestone exit:** `docker compose up` yields a running `warden --role=all` that passes
`/readyz`, a bootstrapped system tenant with no default credentials, and a conformance runner
that executes an (initially tiny) corpus in CI across three toolchains.

### M0-1 [B] Repository scaffolding and toolchains
**Status: done.**
Go module at 1.23, the layout above, `Makefile` / `Taskfile` targets (`build test lint
migrate up down`), `golangci-lint` config, `.editorconfig`, Node and Python workspace stubs.
**Exit:** `make build test lint` is green on a clean clone with only Go, Node and Python 3.10+ installed.

### M0-2 [B] CI pipeline
**Status: done.**
GitHub Actions: Go build/test/lint/race, Python and Node stubs, Postgres + Redis services,
migration up/down round-trip, `govulncheck` + `pip-audit` + `npm audit`, SBOM generation and
release signing in skeleton form (per ADR-0003 consequence 2).
**Exit:** a PR with a deliberate race, a deliberate lint error, and an irreversible migration
each fail CI for the right reason.

### M0-3 [B] Open-source project files
**Status: done.**
`LICENSE` (Apache-2.0 pending ratification — ADR-0003 item 3), `SECURITY.md` with a
disclosure address and response SLA, `CONTRIBUTING.md` (three toolchains, DCO decision),
`CODE_OF_CONDUCT.md`, issue/PR templates, `README` status update.
**Exit:** files present; the DCO-vs-CLA question has an answer recorded in `CONTRIBUTING.md`.
**Note:** trademark clearance on the name "Warden" (§23 Q9) must land before the repo is
made public. Track it here; it does not block private development.

### M0-4 [B] Configuration and secrets
**Status: done.**
Precedence file → env → flags; typed config struct with validation at startup; envelope
encryption (AES-256-GCM) with a KEK from env / file / KMS per §17; **a missing or malformed
secret is a startup error, never a default** (§12.5 applied to the server too).
**Exit:** starting with a missing KEK exits non-zero with an actionable message; a unit test
asserts no config field silently defaults to an insecure value.

### M0-5 Migrations and the core schema
**Status: done.** Verified against Postgres 15.19 and 16.15.
`golang-migrate`, forward-only, expand/contract. Tables from
[`data-model.md`](data-model.md): `tenant`, `user`, `credential`, `identity`, `session`,
`refresh_token`, `group`, `group_member`, `application`, `app_enrollment`, `resource_type`,
`action`, `permission`. Depends on M0-4.
**Exit:** up and down migrate cleanly against Postgres 15 and 16; schema dump is committed
and diffed in CI.

### M0-6 Row-level security harness
**Status: done.** 19 tests; the table list is discovered from `pg_class` and cross-checked against a registry in the schema.
RLS policies (`tenant_id = current_setting('warden.tenant_id')`) plus the connection wrapper
that sets the GUC per transaction, and the escape hatch for system-tenant queries.
**Exit:** a test that opens a connection with tenant A's GUC and runs `SELECT *` on every
tenant-scoped table returns zero of tenant B's rows — table list generated from the schema so
new tables cannot be forgotten.

### M0-7 Store layer and query generation
**Status: done.**
`sqlc` wiring, connection pooling, transaction helper, retry classification for
serialization failures.

Every query in the server is now generated from [`internal/store/queries`](../internal/store/queries)
into `internal/store/db` — 57 of them, across the model loader, provisioning, the HTTP
surface, the audit log and the signing keys. One deliberate exception remains and is
documented where it lives: `store.describeRole` reads the PostgreSQL catalog rather
than Warden's schema, and sqlc's catalog is built from the migrations, so generating it
would mean pointing code generation at a live database and breaking M0-1's promise that
a clean clone needs only Go, Node and Python.

Two type mappings are load-bearing and worth knowing about before editing
[`sqlc.yaml`](../sqlc.yaml): `jsonb` becomes `dbtypes.JSONMap`, a named map type that
stays assignable from a plain `map[string]any`; and `audit_event.before/after` are
`json`, not `jsonb`, so they generate as `[]byte` and the hash chain still verifies over
the exact bytes written.

[`retry.go`](../internal/store/retry.go) classifies the two SQLSTATEs PostgreSQL defines
as transient — `40001` serialization failure and `40P01` deadlock — and reissues those
transactions with jittered backoff, three attempts by default. Nothing else is retried:
a unique violation reissued three times is three identical failures and a bug that took
three times as long to find.

Two things worth knowing before using it. `InTenant`/`InSystem` take variadic
`TxOption`s, so `store.Isolation(pgx.Serializable)` is available for the code that will
need it — **M1-5**'s refresh-token reuse detection is the case the option exists for, and
it is safe to ask for precisely because the retry loop is now underneath it. And a retry
re-runs the whole callback, so anything a callback does *outside* the database must not
be there; the convention is that such values are produced before the transaction opens,
which is why a retried `CreateServiceAccount` does not mint a second token.

Retries are counted in `warden_store_transaction_retries_total{code}` and, when the
budget runs out, `warden_store_transaction_retries_exhausted_total{code}`. Without those
a retry is invisible — the transaction succeeds and the caller never knows — so rising
lock contention would show up only as latency nobody can explain.

**Exit:** met. `make sqlc-check` regenerates and fails on a diff, wired into `make lint`
and called out as its own CI step. `TestDeadlockIsRetried` provokes a real lock cycle
between two transactions and asserts both commit; it fails loudly if the ordering stops
deadlocking, so it cannot quietly decay into a test that proves nothing.

### M0-8 [B] Conformance corpus format and runner ★
**Status: done.** 10 cases, 87 checks, validated by a reference evaluator (`conformance/reference`).
**The highest-leverage task in M0.** SPEC §21 names this the single most important test asset
and no schema for it exists yet. Define the YAML case format —
`(model, assignments, check, expected)` including scopes, conditions, denials and expected
`reason` codes — write the Go runner, and seed the corpus with SPEC §9.9's worked example.
Depends on M0-1.
**Exit:** `go test ./conformance/...` executes the §9.9 fixture end to end and fails loudly if
a case's expected `reason` changes. The format is documented in `conformance/README.md` well
enough that the Python SDK can implement a runner against it without asking questions.

### M0-9 Bootstrap (`warden init`)
**Status: done.**
Creates the system tenant, generates the signing keypair with a `kid`, creates the first
owner, prints a one-time setup URL. **No default credentials, ever** (§20.2).
**Exit:** a fresh database plus `warden init` yields exactly one usable one-time URL; running
it twice is refused; grep of the codebase finds no hardcoded credential.

### M0-10 [P] Health, metrics, structured logging
**Status: done.**
`/healthz`, `/readyz` (checks Postgres and Redis), `/metrics`, structured JSON logs with a
request id, OpenTelemetry tracer setup.
**Exit:** `/readyz` returns 503 with a named failing dependency when Postgres is stopped.

### M0-11 [P] Local development environment
`docker-compose.yml` with Postgres, Redis, Mailpit and Warden; a seed command producing a
demo tenant and the `billing` app from `examples/warden.yaml`.
**Exit:** clean clone → `docker compose up` → a seeded, reachable server in under two minutes.

### M0-12 [P] Missing design artifacts named by the spec but not yet written
**Status: done.**
- `docs/threat-model.md` — required by §17 as a release gate, referenced but absent.
- `docs/design-email.md` — M1 needs verification, magic links, invitations and resets;
  provider abstraction (SMTP + pluggable), templating, i18n hooks, bounce handling and
  rate limits are unspecified.
- Resolve the cross-tenant **`person`** linkage (§6.2, marked *(open)*): today `user` is
  unique on `(tenant_id, email)` and no `person` table exists. Decide whether v1 has the
  table at all, and record it as ADR-0004.
**Exit:** three documents merged; §6.2's *(open)* marker removed or narrowed. — Done:
[`docs/threat-model.md`](threat-model.md), [`docs/design-email.md`](design-email.md),
[ADR-0004](adr/0004-cross-tenant-person.md); §6.2's marker is resolved.

---

## M1 — Identity (SPEC §22 M1)

**Milestone exit:** an application logs a user in and out using a stock off-the-shelf OIDC
library, with no Warden-specific client code.

| # | Task | Exit condition |
| --- | --- | --- |
| M1-1 [B] | Signing key management: generation, `kid` rotation on a schedule, JWKS with current + previous | Rotation leaves tokens signed by the previous key verifiable for the full overlap window |
| M1-2 [B] | Local credentials: Argon2id (`m=64MiB,t=3,p=2`), rehash on parameter change, per-tenant password policy, breached-password k-anonymity dataset | Timing test shows unknown-user and wrong-password responses are indistinguishable (§7.2) |
| M1-3 | Lockout and rate limiting: exponential backoff per (account, IP), global per-account cap, 429 + `Retry-After` | Enumeration test across login, reset and invite endpoints finds no oracle |
| M1-4 | Sessions in Redis with a Postgres mirror; `sid`; revoke one / revoke all | `POST /v1/users/{id}/revoke-all` invalidates within 1 s |
| M1-5 | Refresh tokens: opaque 256-bit, hashed, rotating, **reuse detection revokes the family** and raises a security event | Replaying a rotated token kills the family and emits `security.refresh_token_reuse` |
| M1-6 [B] | OIDC OP endpoints via fosite: authorize (PKCE required for public clients), token, userinfo, JWKS, introspect, revoke, logout, PAR, device | Certification-style conformance checks pass; implicit and ROPC grants are absent, not disabled |
| M1-7 | Access-token claim assembly per §8.2 including `wd.perm_rev`, with the **4 KB cap** dropping `wd.groups` then `wd.attrs` and setting `wd.truncated` | A user with 5 000 groups still gets a valid, verifiable, sub-4 KB token |
| M1-8 | TOTP, recovery codes, WebAuthn as second factor | Enrolment and step-up flows; recovery invalidates all sessions (§7.2) |
| M1-9 | Magic link and email delivery, per the M0-12 email design | Links are single-use, 15-minute, hashed at rest |
| M1-10 | User lifecycle `invited → active → suspended → deprovisioned → deleted` | Suspension kills sessions and refresh tokens immediately |

---

## M2 — RBAC core (SPEC §22 M2)

**Milestone exit:** `check` answers correctly for every case in the conformance corpus, and
the corpus covers all of §9.

| # | Task | Exit condition |
| --- | --- | --- |
| M2-1 [B] | Schema: `role`, `role_inheritance`, `role_permission`, `grant`, `denial` | Cycle rejection at write time; depth cap 8 enforced |
| M2-2 [B] | Permission surface: application manifest ingestion, `implies` closure expanded **at grant time**, `unknown_permission` warning events | A typo'd permission in a check denies *and* emits the warning (§9.2) |
| M2-3 [B] | Role resolver: direct + transitive group assignments, inheritance DAG expansion, memoized on `(tenant_rev, subject_id)` and `(tenant_rev, role_id)` | Recursive-CTE query plan reviewed; 50-role subject resolves within the §18 budget |
| M2-4 [B] | Scope matching: tenant / app / environment / instance / subtree | Every scope form in §9.5 has corpus cases including near-miss negatives |
| M2-5 | Explicit denies with precedence `deny > allow > implicit deny`, admin-only, justification required, always audited | Property test: an explicit deny always wins, whatever the grant set |
| M2-6 [B] | `POST /v1/authz/check` and `/batch-check` (1 000 per call) | §18 latency targets met on the reference hardware |
| M2-7 | **Status: done (explain, filter).** `/effective-permissions`, `/explain` with the §10.3 derivation shape | `explain` is refused in prod for non-admins (it leaks policy structure) |
| M2-8 | **Status: done.** Decision log: `off`/`denies`/`sampled`/`all`, buffered async sink that never blocks the decision path | Sink saturation drops records and increments a metric; it never adds latency |
| M2-9 | Groups: local and IdP-sourced, nesting DAG, assignments | IdP group membership is *replaced* per login (§9.4) |
| M2-10 [B] | **Status: done.** **Privilege-escalation guard**: a subject may not assign a role containing permissions they lack, absent `tenant.role:assign_any` (§17.1 threat 3) | Dedicated test suite; this is a named threat, not a nice-to-have |
| M2-11 | Multi-tenant isolation sweep: every management endpoint × foreign `tenant_id` ⇒ 404 | Endpoint list is generated from the router, so a new endpoint cannot skip the sweep |
| M2-12 | **Status: done.** Admin audit log: append-only, hash-chained `prev_hash`, before/after diff | Tampering with any row breaks verification of the chain |

---

## M3 — Python SDK + FastAPI (SPEC §22 M3, overlaps M2)

**Milestone exit:** the reference application is fully protected end to end.

| # | Task | Exit condition |
| --- | --- | --- |
| M3-1 [B] | Package skeleton, typing, sync + async parity | `mypy --strict` clean; every public sync method has an async twin |
| M3-2 [B] | Token verification: JWKS fetch, cache, rotation, `iss`/`aud`/`exp`/`nbf`, clock skew — fully offline | No network call on the happy path after warm-up |
| M3-3 [B] | `check` / `batch_check` / `filter` against the M2 API | Same results as the server for every corpus case |
| M3-4 [B] | **Python conformance runner** against the M0-8 corpus | Python and Go agree on all cases — this is what makes the SDK trustworthy |
| M3-5 | Caching: `remote` / `cached` / `embedded`; cache key **includes the resource-attribute hash and tenant revision** (ADR-0002 consequence) | A changed attribute value cannot hit a stale entry |
| M3-6 | Change-stream subscription (SSE) with reconnect and backoff | Propagation p95 < 1 s end to end |
| M3-7 | `fail_mode` `closed` / `open_read` / `stale` + circuit breaker with exposed state | Default `closed`; a misconfigured SDK fails at startup, never allows at runtime (§12.5) |
| M3-8 [P] | FastAPI integration: dependencies, router guard, principal injection | Reference app protected with it |
| M3-9 [P] | Django integration: middleware, `@permission_required` replacement, DRF permission class, template tag | |
| M3-10 [P] | Flask integration: extension + decorator | |
| M3-11 | Resource registration and hierarchy push | Bulk sync of 10 000 nodes within a documented budget |
| M3-12 | `warden doctor`: config, connectivity, clock skew, manifest drift | Detects each of the four failure classes in a test |
| M3-13 | Observability: OTel `warden.check` spans, Prometheus metrics per §12.1 | An app's trace shows the check span inline |
| M3-14 | Reference application (FastAPI + React), doubling as contributor onboarding (ADR-0003) | Acceptance test for M3 and M5 |

---

## M4–M8 — story grain, decomposed at the milestone before each

- **M4 Federation.** OIDC RP connections; SAML SP with the §17 XML defences (DTD/XXE off,
  parse-then-verify against signature wrapping) and the **hostile-assertion fixture corpus**;
  claim/attribute/group mapping; identity linking with `email_trusted=false` default;
  connection test harness. Mock OIDC OP and SAML IdP in `testing/` are prerequisites.
  *Open:* §23 Q4 — whether SAML ships here or one milestone later. Decide before M4 starts;
  it is roughly a third of the milestone.
- **M5 UI binding + React SDK.** *Server half done:* ui_element/ui_binding, manifest
  sync, GET /v1/ui/bundle, POST /v1/ui/resolve, and `warden ui`. Remaining: discovery
  mode, the unprotected-endpoint detector, and the browser/React packages. Element declarations, bindings, UI bundle with ETag,
  per-frame batched `/ui/resolve`, `@warden/browser`, `@warden/react`, `<Guard>` with
  fail-closed loading, discovery mode (refused in prod), and the **unprotected-endpoint
  detector** (§11.6) — the genuinely novel safety feature, do not let it slip.
- **M6 Console.** All §14 sections. The **simulator** (§14.2) is the support channel for an
  open-source project with no hosted alternative — weight it accordingly.
- **M7 Fine-grained + conditions.** Resource hierarchy, CEL with fuel limit and 2 ms
  deadline, missing attribute ⇒ deny, time-boxed elevation, `list-resources`, consistency
  tokens, change stream. *Open:* §23 Q3 and Q6.
- **M8 Hardening → 1.0.** Helm chart, k6 load tests with regression gates, external
  penetration test, SBOM/signing/attestation promoted from M0 skeletons, docs site,
  backup/restore and `warden export`. *Open:* §23 Q5, Q8.

---

## Critical path

```
M0-1 → M0-2 → M0-4 → M0-5 → M0-6 → M0-8 ★ → M2-1 → M2-3 → M2-6 → M3-3 → M3-4
                                 ↘ M0-9 → M1-1 → M1-6 → M1-7 ↗
```

M0-8 (the conformance corpus) sits on the critical path deliberately: it is written **before**
the PDP so that the server and every SDK are built against one executable definition of the
semantics, and so ADR-0001 stays reversible at a known cost.
