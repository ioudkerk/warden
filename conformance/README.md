# Conformance corpus

A language-neutral corpus of `(model, assignments, check, expected)` cases that
defines what Warden decides. It is executed against the server **and** against every
SDK's embedded evaluator.

SPEC §21 calls this the single most important test asset in the project, for two
reasons. It is what makes "the Python SDK and the Go server agree" a tested claim
rather than an assumption. And it is what keeps
[ADR-0001](../docs/adr/0001-server-language.md) reversible: a port in either
direction is mechanical only if the semantics are written down somewhere executable.

```
README.md          this document — the format specification
corpus.go          case types and the loader
validate.go        case validation: an invalid case must never quietly pass
runner.go          the harness: Evaluator, Decider, Run, Compare
cases/             the corpus
reference/         a reference evaluator, used to validate the corpus
```

```bash
make conformance    # or: go test ./conformance/...
```

## Why there is a reference evaluator

`reference/` is a deliberately plain transcription of SPEC §10.2 — no database, no
caching, no memoization, no regard for the latency targets. It is **not the PDP**.

It exists because a corpus validated only by the thing it is meant to test proves
nothing. Two independent implementations agreeing on all 87 checks is evidence; one
implementation agreeing with expectations written by the same person on the same
afternoon is not. When the real PDP lands in M2 it runs against this same corpus, and
any divergence is a bug in one of the two — which is the differential test this
package exists to make possible.

## Writing a runner in another language

Implement two things:

1. **A loader** for the format below. Reject unknown fields; a typo in a case file
   must be an error, or a case will assert less than its author believed.
2. **An evaluator** that, given a case's `model`, answers each `check` with
   `(allowed, reason, matched_grant)`.

Then assert that every check's answer equals its `expect` exactly. The Go runner is
in `runner.go`; the Python one is task M3-4.

Two rules that are easy to miss and that make results non-portable if broken:

- **Candidate order is declaration order.** When several grants could allow the same
  check, the one that produced the allow is the one declared earliest in the case
  file. Only that grant's id may be reported as `matched_grant`.
- **Deny reason precedence is normative**, not advisory. See below.

## Case format

One case per file, in `cases/`. A case is a complete authorization world plus the
checks that must hold against it.

```yaml
suite: scopes                 # required, unique across the corpus; names the subtest
spec: "§9.5"                  # required; the SPEC.md section this case pins down
description: >                # required; what the case proves, in prose
  ...
now: "2026-08-21T14:00:00Z"   # optional; evaluation time for checks that do not override it

model: { ... }
checks: [ ... ]
```

A case that carries a validity window on any grant **must** set `now`, at the case or
on every check. A corpus whose result depends on when the suite happens to run is not
a corpus.

### `model.applications`

Declares the permission surface. A permission not declared here denies with
`unknown_permission` (SPEC §9.2).

```yaml
applications:
  - key: billing
    resource_types:
      - key: project
        actions: [read, manage]        # shorthand: a list of action keys
      - key: invoice
        parent: project                # enables subtree cascade (SPEC §9.5)
        actions:
          - key: read
          - key: manage
            implies: [read, approve]   # expanded at load, never during a check
          - key: approve
```

`implies` is transitive and must name actions on the same resource type.

### `model.roles`

```yaml
roles:
  - key: billing.approver
    inherits: [billing.viewer]         # a DAG; cycles are rejected at load
    permissions:
      - billing.invoice:approve
      - billing.*:read                 # wildcards are legal here, never in a check
    requires_mfa: false                # SPEC §9.3 role constraint
```

A role's effective permissions are its own, plus everything it inherits transitively,
plus the `implies` closure of every action it names.

### `model.tenants`

```yaml
tenants:
  - key: acme
    users:
      - key: maria
        status: active                 # invited | active | suspended | deprovisioned
        attributes: { department: finance, approval_limit: 50000 }

    groups:
      - key: g_finance
        members: [maria, g_emea]       # users or other groups; nesting is a DAG

    resources:
      - ref: billing.invoice:4711      # app.type:id
        parent: billing.project:acme-2026
        attributes: { amount: 30000, status: pending }

    grants:
      - id: grn_maria_approver         # optional; needed only to assert matched_grant
        subject: { user: maria }       # exactly one of user or group
        role: billing.approver
        scope: billing.project:acme-2026/**
        condition: "resource.attributes.amount <= 50000"   # CEL, optional
        valid_from: "2026-08-21T10:00:00Z"                 # optional, inclusive
        valid_until: "2026-08-21T14:00:00Z"                # optional, exclusive

    denials:
      - id: den_contractor_void
        subject: { user: contractor }
        permission: billing.invoice:void
        scope: tenant
        reason: A contractor may never void an invoice.    # required (SPEC §9.7)
```

### Scope forms

| Form | Covers |
| --- | --- |
| `tenant` | Everything in the tenant, across applications. |
| `app:billing` | Any permission of that application. |
| `app:billing/env:prod` | That application, but only when the check declares `environment: prod`. A check naming no environment is **not** covered. |
| `billing.project:acme-2026` | Exactly that object. Does **not** cascade to children. |
| `billing.project:acme-2026/**` | That object and its registered descendants. |

An instance or subtree scope cannot satisfy a check that names no resource. A subtree
scope reaches only resources whose ancestry is registered under `resources` — an
application that does not mirror its object graph loses the cascade and nothing else
(SPEC §9.5).

### `checks`

```yaml
checks:
  - name: approve an in-scope invoice under the limit    # required, unique in the case
    tenant: acme
    subject: maria
    permission: billing.invoice:approve                  # concrete; no wildcards
    resource: billing.invoice:4711                       # optional
    attributes: { amount: 10 }                           # optional; overrides registered
    environment: prod                                    # optional
    context: { ip: "10.1.2.3", amr: [pwd, otp] }         # optional
    now: "2026-08-21T12:00:00Z"                          # optional; overrides the case
    expect:
      allowed: true
      reason: grant_matched
      matched_grant: grn_maria_approver                  # optional
```

`expect.reason` is required, always. A case that pins only `allowed` passes when an
implementation denies for entirely the wrong cause, which is the failure this corpus
exists to catch.

`matched_grant` may be asserted only on an allow, and only in a case where exactly
one grant can match — otherwise the assertion is really about candidate ordering.

## Conditions

CEL (SPEC §9.6), evaluated against:

```
subject.id, subject.email, subject.roles, subject.groups, subject.attributes.*
resource.type, resource.id, resource.attributes.*
action
context.ip, context.time, context.request.*
environment.name
```

`context.time` defaults to the check's evaluation time when the caller supplies none.
`inCidr` is available as a string member function: `context.ip.inCidr("10.0.0.0/8")`.

**Resource attributes come from two places, in this order** (SPEC §9.6): attributes
passed inline on the check win over attributes registered on the instance, because
the application is the source of truth for its own objects.

**An attribute that cannot be resolved denies with `missing_attribute`**, never
silently as false. This is the single most important condition rule: a policy that
reads `resource.attributes.amount` on an object with no amount must not be treated as
having no opinion.

## Deny reason precedence — normative

Several things can be wrong with one check. Implementations must report the *same*
reason, or the corpus is not portable between them. In order:

| # | Reason | When |
| --- | --- | --- |
| 1 | `subject_not_found` | No such subject in the tenant. |
| 2 | `subject_inactive` | The subject exists but is not `active` (SPEC §7.6). |
| 3 | `unknown_permission` | The permission is not in any application's declared surface. Checked before any grant, so a typo reads as a typo. |
| 4 | `explicit_deny` | An explicit deny matches the permission and covers the scope. Beats every allow (SPEC §9.7). |
| 5 | `missing_attribute` | A candidate's condition read an unresolvable attribute. |
| 6 | `mfa_required` | A candidate's role requires MFA and the context shows no second factor. |
| 7 | `condition_failed` | A candidate matched but its condition was false. |
| 8 | `grant_expired` | A grant gives the permission and covers the scope, but the clock is outside its validity window. |
| 9 | `out_of_scope` | A grant gives the permission but at a scope that does not reach the request. |
| 10 | `no_grant` | Nothing gives the permission at all. |

Rows 5–7 apply to candidates that reached condition evaluation; among several failing
candidates the highest row wins. Rows 8–10 are the "how close did you get" ordering:
a grant that exists but expired is a more useful answer than "no grant", and one that
exists but is out of scope is more useful still than silence.

`grant_matched` is the only reason that accompanies an allow.

`degraded_fail_closed` from `docs/api.md` never appears here: it describes an SDK
whose PDP was unreachable (SPEC §10.6), not a decision the model produced.

## Adding a case

1. Write it. Give the file a number, `suite` a unique name, and `spec` the section it
   pins down.
2. State what it proves in `description`. A case that does not say what it is for
   cannot be reviewed, and validation rejects an empty description.
3. Include the near-misses. A case proving a subtree grant cascades is worth much
   less without the sibling it must not reach.
4. `make conformance`. Then change one expectation and confirm it fails — if it does
   not, the case is not asserting what you think.

Any change to authorization semantics needs a case here. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
