# Warden — threat model

**Status:** Living document. SPEC §17 makes it a release gate, and §17.1 names seven
threats that must be mitigated explicitly. This records what each mitigation actually
is, and — more usefully — what is not yet mitigated.

A threat model that only lists solved problems is a marketing document. The
**Outstanding** column is the point of this one.

---

## 1. What is worth attacking

| Asset | Why it is worth taking | Where it lives |
| --- | --- | --- |
| **Authorization decisions** | The product. An attacker who can turn a deny into an allow owns every application that trusts Warden. | `internal/authz`, `grant_`, `role_permission` |
| **The signing key** | Mints tokens for any subject in any tenant. The single highest-value item. | `signing_key.private_key`, sealed under the KEK |
| **The KEK** | Opens the signing key and every stored IdP credential. | Outside the database, by construction (`env:` / `file:` / KMS) |
| **Service-account tokens** | Ask about any subject; answers describe the policy. | `service_account.token_hash` |
| **Tenant data** | One customer's users, roles and grants, visible to another. | Every table with `tenant_id` |
| **The audit log** | The record of what was done. Valuable to *erase*, not to read. | `audit_event`, hash-chained |
| **The decision log** | Who asked what about which object — among the more revealing things Warden holds. | `decision_event` |

## 2. Trust boundaries

```
   ┌── untrusted ───────────────────────────────────────────────┐
   │  Anyone who can reach the listener                         │
   └────────────────────────┬───────────────────────────────────┘
                            │  ① bearer token
   ┌── semi-trusted ────────▼───────────────────────────────────┐
   │  An authenticated service account, scoped to ONE tenant    │
   └────────────────────────┬───────────────────────────────────┘
                            │  ② warden.tenant_id, set per transaction
   ┌── enforced by Postgres ▼───────────────────────────────────┐
   │  warden_app: row-level security applies. No DDL.           │
   └────────────────────────┬───────────────────────────────────┘
                            │  ③ a deliberate, audited crossing
   ┌── trusted ─────────────▼───────────────────────────────────┐
   │  warden_system: BYPASSRLS. Migrations, bootstrap, jobs.    │
   └────────────────────────────────────────────────────────────┘
```

The boundaries that carry weight are ② and ③. ② is enforced by the database rather
than by application code remembering to filter, and ③ is a different database role
rather than a flag, so crossing it requires credentials an attacker at ① does not
have.

**The metrics listener is a fourth boundary**, on its own port. Its series describe
denial rates and per-route traffic. It is unauthenticated by design and must not be
exposed alongside the API.

---

## 3. The seven named threats (SPEC §17.1)

### T1 — Confused deputy via UI-only enforcement

An application hides a button and does not check the permission behind it.

| | |
| --- | --- |
| **Mitigated** | Nothing yet, beyond documentation. `examples/demo-app/README.md` states the rule; `SECURITY.md` puts it explicitly out of scope so a report of "the hidden button's endpoint is reachable" is not treated as a finding. |
| **Outstanding** | The unprotected-endpoint detector of §11.6 — the genuinely novel part — needs the decision telemetry to notice that a UI element's suggested permission is never checked server-side. `decision_event` now records enough to build it. **M5.** |

### T2 — Account takeover via unverified federated email

An upstream IdP that does not verify addresses asserts `victim@example.com`; Warden
links it to an existing account.

| | |
| --- | --- |
| **Mitigated** | `idp_connection.email_trusted` defaults to `false`, enforced by the schema, with the reason in a `COMMENT ON COLUMN`. Linking rule 2 of §7.4.1 is gated on it. |
| **Outstanding** | Federation itself (M4). The console must warn loudly when the flag is enabled — the default is worth little if the toggle is unremarkable. The hostile-assertion corpus in `testing/` does not exist yet. |

### T3 — Privilege escalation via role assignment

An administrator assigns a role conferring permissions they do not hold.

| | |
| --- | --- |
| **Mitigated** | `internal/authz.CanAssign`, and it checks more than the obvious. Containment over the **expanded** permission set; **scope**, so an assigner holding a permission on one project cannot grant it tenant-wide; **validity**, so a four-hour elevation cannot create a permanent grant; and **conditions**, where a conditionally-held permission cannot be delegated unconditionally. `warden.role:assign_any` is the documented escape hatch and bypasses containment only. The guard cannot be omitted by accident: `Grant` refuses when no actor is named. Refusals are audited. |
| **Outstanding** | `assignable_by` (§9.3) and separation-of-duties conflicts are stored but not enforced. Time-boxed elevation with an approval step (§9.8) is not built. |

### T4 — Stale permissions after revocation

A revoked role keeps working because something cached it.

| | |
| --- | --- |
| **Mitigated** | Model caching is keyed on `tenant.permission_rev`, not a TTL: every authorization-affecting write bumps it, so a cached model is valid exactly until the next such write. Verified end to end — granting a role changed a running server's answers with no restart. |
| **Outstanding** | The change stream of §10.5 (`subject.invalidated`, p95 < 1 s) does not exist, so an **SDK's** cache is still bounded only by its TTL. Short access-token lifetimes are enforced (5–15 min) but no tokens are issued yet. **M7.** |

### T5 — Tenant crossing

One tenant reads or writes another's data.

| | |
| --- | --- |
| **Mitigated** | Row-level security **enabled and forced** on every tenant-scoped table — `FORCE` matters, because `ENABLE` alone exempts the owner and a deployment serving traffic as the owner would have isolation switched on and doing nothing. Scope is set with `set_config(..., is_local => true)` so it cannot outlive its transaction or leak to the next user of a pooled connection. Unset means denied. Warden **refuses to start** in production on a role that can bypass RLS. The model loader filters by tenant explicitly as well, since §6.2 puts RLS *behind* application-level filtering. Child tables carry a denormalized `tenant_id` held true by composite foreign keys. At the API, a service-account token can only ask about its own tenant, and a foreign subject id returns `subject_not_found` — indistinguishable from one that never existed. |
| **Verified by** | A sweep whose table list is discovered from `pg_class` and cross-checked against a registry in the schema, so a new table cannot silently escape. Regressions confirmed to fail the suite: `FORCE` removed, a policy removed, a `FOR SELECT`-only policy, an unprotected partition. |
| **Outstanding** | The §17.1 sweep of *every management endpoint* with a foreign `tenant_id` is trivial today (three endpoints, and the crossing case is tested) but must become systematic as the management API grows — generated from the router, not hand-written. **M2-11.** |

> **A hole found and closed while writing the decision log.** A partitioned table's
> policies apply when a query names the parent and **not** when it names a partition
> directly. With `decision_event` protected and its partitions bare,
> `SELECT * FROM decision_event` correctly returned one tenant's rows while
> `SELECT * FROM decision_event_2026_09` returned everyone's. Every partition is now
> protected, and the function that creates next month's partition protects it in the
> same call — otherwise the hole reopens on a schedule, months after anyone looked.

### T6 — SAML signature wrapping and XXE

| | |
| --- | --- |
| **Mitigated** | Nothing. There is no SAML code. |
| **Outstanding** | All of it. **M4**, and the fixture corpus of known-malicious assertions is a prerequisite rather than a follow-up. Parse-then-verify, verifying the exact element used; DTD and external entities disabled; assertion `ID` replay protection. |

### T7 — Refresh token theft

| | |
| --- | --- |
| **Mitigated** | The schema is ready: opaque, hashed at rest (`octet_length = 32` enforced), with a `family_id` for reuse detection. |
| **Outstanding** | The rotation and reuse-detection logic. **M1.** |

---

## 4. Threats not in §17.1 that this work surfaced

### T8 — Forging or erasing the audit record

An attacker with database access edits or deletes what they did.

**Mitigated.** Append-only by trigger; hash-chained, so an edit or a deletion breaks
verification of everything after it. `warden audit -verify` exits non-zero. Appends
take an advisory lock, because `FOR UPDATE` on an empty table locks nothing and the
first writers to a fresh log would otherwise fork the chain — a self-inflicted false
positive in the one place a false positive destroys trust in every true one.

**Outstanding, and deliberately documented rather than papered over:** truncating the
log **from the end** leaves every surviving entry verifying. Detecting that needs the
head hash published outside this database — the signed archive of §16.1, or an
external witness. There is a test named for this limitation so it is not mistaken for
coverage.

### T9 — The decision API as an oracle

`/v1/authz/check` takes a subject id and returns whether they may do something. An
unauthenticated one is a policy-disclosure endpoint.

**Mitigated.** Every decision request requires a service-account token. All
authentication failures return a byte-identical body, so an attacker cannot
distinguish "no such token" from "expired" from "disabled" — asserted by a test.
Responses carry `Cache-Control: no-store`, since an intermediary caching an
authorization decision would serve one subject's answer to another. `/v1/authz/explain`
is refused in production without `may_explain`, because a derivation describes the
policy itself.

**Outstanding:** no rate limiting anywhere (§17 requires per-IP and per-client limits).
`batch-check` is capped at 1000, which bounds amplification but not request rate.

### T10 — A credential shipped in the product

**Mitigated.** Tested behaviourally rather than by grep: a migrated but uninitialised
database must contain zero rows in every table that could hold something to
authenticate with, and zero accounts and zero grants. A grep can be fooled by a
credential assembled at runtime; a row count cannot. `warden init` prints a single-use
URL, stored only as a SHA-256, expiring in thirty minutes, and refuses to run twice —
a second init would mint a fresh setup URL for an existing owner, which is a password
reset with no authentication in front of it.

### T11 — Secrets escaping into somewhere they are retained longer

Logs, error messages, audit entries, traces.

**Mitigated.** `secrets.Secret` redacts through every formatting, serialization and
logging path — `%s %v %+v %#v %q %x`, JSON, YAML, `slog`, nested in structs and behind
pointers — with tests asserting each. Connection-string parse failures are reported
without echoing the string. The audit log records a service account's name and never
its token. Span attributes carry subject, permission and reason but **not** the
resource id, because a trace exporter is often a third party with different retention
rules. `/readyz` reports `unreachable` and nothing more, since it is unauthenticated
and a connection error names hosts and users.

**Outstanding:** no automated check that a *new* log call cannot receive a secret. The
`Secret` type makes the safe path the default, but a caller who writes
`log.Info("dsn", "value", cfg.Database.URL.Expose())` defeats it.

### T12 — A request id used to forge a log line

**Mitigated.** Caller-supplied ids are bounded at 64 characters and stripped to an
alphanumeric alphabet before being echoed into a response header or a log line.
Verified against a CRLF injection attempt.

---

## 5. What an attacker at each position can do today

| Position | Can | Cannot |
| --- | --- | --- |
| **Network, no credential** | Reach `/healthz`, `/readyz`. Learn that Warden is running and whether its dependencies are up. | Ask any authorization question. Learn any tenant's identifiers. |
| **A valid service-account token** | Ask anything about **its own** tenant, including about subjects it invents. Learn allow/deny and a reason code. | Reach another tenant. Obtain a derivation in production without `may_explain`. Change anything — there is no write API. |
| **`warden_app` database credential** | Read and write **within a declared tenant scope**. | Read another tenant. Write across the boundary. Read a partition to escape a policy. Change the schema. Open a signing key without the KEK. |
| **`warden_system` credential** | Everything, across every tenant. | Forge or erase audit history undetectably. Open a signing key or an IdP secret without the KEK. |
| **Database backup, no KEK** | Read every tenant's roles, grants and decision history. | Mint a token. Recover an IdP client secret. Recover a setup token or any service-account token. |

That fourth row is the honest limit of the current design: **a stolen backup discloses
policy, and the KEK is what stops it also conferring authority.** Encrypting the
grants themselves would defeat the query patterns the PDP depends on. Anyone relying
on Warden should treat a backup as containing the shape of their access model.

---

## 6. Assumptions

Recorded because a threat model is only valid while its assumptions hold.

1. **The KEK is not in the database.** `security.kek` reads from an environment
   variable, a file, or a KMS. Backing it up alongside the database defeats every
   at-rest protection here.
2. **`warden_app` and `warden_system` are distinct roles.** Warden refuses to start in
   production otherwise, but a deployment that sets `environment: dev` in production
   silences that.
3. **TLS terminates before Warden or at it.** Nothing here protects a bearer token in
   flight.
4. **The database is not shared with untrusted tenants of another system.** RLS is
   keyed on a session variable; anything that can `SET` it can move between tenants.
5. **Applications check server-side.** UI binding is a UX control (§2.3).

---

## 7. Review

This document is updated when a mitigation lands or an assumption changes, and is
reviewed in full before each release, per §17. An external penetration test is a 1.0
gate (M8) and has not happened.

Report a suspected vulnerability privately — see [SECURITY.md](../SECURITY.md).
