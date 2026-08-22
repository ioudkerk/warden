# Warden — Specification

**Version:** 0.1 (draft)
**Date:** 2026-08-21
**Status:** Pre-implementation. Sections marked *(open)* need a decision before the milestone that depends on them.

---

## Table of contents

1. [Summary](#1-summary)
2. [Goals and non-goals](#2-goals-and-non-goals)
3. [Personas and primary use cases](#3-personas-and-primary-use-cases)
4. [Glossary](#4-glossary)
5. [System architecture](#5-system-architecture)
6. [Tenancy and organization model](#6-tenancy-and-organization-model)
7. [Identity and authentication](#7-identity-and-authentication)
8. [Tokens, sessions and claims](#8-tokens-sessions-and-claims)
9. [The authorization model](#9-the-authorization-model)
10. [The decision engine (PDP)](#10-the-decision-engine-pdp)
11. [UI element binding — the "extra powers"](#11-ui-element-binding--the-extra-powers)
12. [Backend SDKs](#12-backend-sdks)
13. [Frontend SDK](#13-frontend-sdk)
14. [Admin console](#14-admin-console)
15. [Management API and IaC](#15-management-api-and-iac)
16. [Audit, observability and compliance](#16-audit-observability-and-compliance)
17. [Security requirements](#17-security-requirements)
18. [Performance and scale targets](#18-performance-and-scale-targets)
19. [Technology choices](#19-technology-choices)
20. [Deployment and operations](#20-deployment-and-operations)
21. [Testing strategy](#21-testing-strategy)
22. [Roadmap](#22-roadmap)
23. [Open questions](#23-open-questions)

---

## 1. Summary

Warden is a self-hostable **identity and access platform**. It merges two products that are
normally separate:

- an **identity server** (authentication, federation, token issuance, user lifecycle), and
- a **centralized authorization service** (RBAC + fine-grained permissions, evaluated at
  runtime by a policy decision point).

The differentiator is that authorization is not a byproduct of authentication — it is the
main product. Applications do not embed their own role tables. They **declare** their
resources, actions and UI surface to Warden, and then **ask** Warden what the current
subject may do. Administrators change roles, permissions and UI visibility from a console,
without a code deploy.

A single Warden deployment serves many applications and many tenants at once.

### The one-paragraph pitch

> Point every one of your apps at Warden. Users sign in once — with a password, with Google
> or Entra ID over OIDC, or with a corporate SAML IdP. Your backend calls
> `warden.check(user, "invoice:approve", invoice_id)` instead of maintaining `if user.role ==
> "admin"`. Your frontend wraps a button in `<Guard element="invoices.approve_button">` and
> an administrator — not a developer — decides which roles see that button.

---

## 2. Goals and non-goals

### 2.1 Goals

| # | Goal |
| --- | --- |
| G1 | Authenticate users through **local credentials**, **OIDC** (as a relying party) and **SAML 2.0** (as a service provider), with the same resulting identity. |
| G2 | Act as a standards-compliant **OIDC provider** so applications integrate with off-the-shelf libraries. |
| G3 | Model **RBAC** centrally: roles, permissions, role hierarchies, group-derived roles, and scoped assignments. |
| G4 | Support **fine-grained / resource-level** authorization (per-object, not just per-endpoint), with optional attribute conditions. |
| G5 | Answer authorization questions with **sub-10 ms p99** as seen from the SDK, at high volume. |
| G6 | Provide backend SDKs (**Python → Node.js → Go**) with idiomatic middleware and decorators. |
| G7 | Provide a **frontend SDK** (React first) that binds components to server-defined permissions. |
| G8 | Let each application **declare its own authorization surface** (resources, actions, roles, UI elements) as code, and sync it to the server. |
| G9 | Be **multi-tenant**: one deployment, many customer organizations, isolated data and isolated role models. |
| G10 | Produce a **complete audit trail** of both administrative changes and authorization decisions. |
| G11 | Be **self-hostable** with a single binary + PostgreSQL, and horizontally scalable beyond that. |

### 2.2 Non-goals (for v1)

- Not a general-purpose policy language platform. Warden ships a constrained condition
  language, not arbitrary Rego/Cedar authoring. *(Reconsider at v2.)*
- Not an API gateway. It integrates with gateways, it does not replace them.
- No customer-facing consumer features (social login walls, marketing analytics, progressive
  profiling).
- No secrets management, no machine-to-machine PKI beyond OAuth client credentials.
- Frontend SDKs other than React are v2 (Vue, Svelte, Angular). A framework-agnostic core is
  built in v1 so this stays cheap.
- SCIM provisioning is v2 (see §7.6).

### 2.3 Explicit anti-goals

- **UI binding is not a security boundary.** Hiding a button is a UX decision. Every action
  behind that button MUST still be checked server-side. The SDKs are designed to make the
  server-side check the path of least resistance, and the docs must say this on every page.

---

## 3. Personas and primary use cases

| Persona | Needs |
| --- | --- |
| **Platform engineer** | Deploys and operates Warden, configures IdP connections, manages upgrades. |
| **Application developer** | Integrates an app: declares resources/actions/UI elements, wires the SDK, writes checks. |
| **Tenant administrator** | A customer's own admin. Invites users, creates custom roles, assigns them, decides what their staff can see. |
| **Support / auditor** | Reads audit logs, answers "why could this user do that?". |
| **End user** | Signs in, possibly with SSO, and sees only what they're entitled to. |

### 3.1 Core user stories

1. *As an application developer*, I declare in `warden.yaml` that my app has a resource
   `invoice` with actions `read, create, approve, void`, run `warden sync`, and those
   permissions appear in the console.
2. *As a tenant administrator*, I create a role `Finance Approver` that inherits `Finance
   Viewer` and adds `invoice:approve`, then assign it to a group synced from Entra ID.
3. *As an application developer*, I wrap an "Approve" button in `<Guard
   element="invoices.approve_button">` and never touch it again — visibility is now
   administered.
4. *As a tenant administrator*, I grant a contractor `invoice:read` **only on invoices in
   project `acme-2026`**, expiring in 30 days.
5. *As an auditor*, I ask "who could approve invoice 4711 on 2026-07-01?" and get an answer
   with the derivation path.
6. *As an end user*, I sign in via my company's SAML IdP and land in the app with the right
   roles already applied.

---

## 4. Glossary

| Term | Meaning |
| --- | --- |
| **Tenant** (a.k.a. Organization) | An isolated customer space. Owns users, roles, assignments, settings. |
| **Application** | A registered software system protected by Warden. Owns resource types, actions, roles templates and UI elements. |
| **Environment** | A slice of an application's configuration: `dev`, `staging`, `prod`. Config is promoted between them. |
| **Subject** | The actor in a decision: a user, a service account, or an API client. |
| **Resource type** | A kind of object an application protects, e.g. `invoice`, `project`. |
| **Resource instance** | A concrete object, addressed as `invoice:4711`. |
| **Action** | A verb on a resource type: `read`, `approve`. |
| **Permission** | `app.resource:action`, e.g. `billing.invoice:approve`. The atom of authorization. |
| **Role** | A named bundle of permissions, optionally inheriting other roles. |
| **Group** | A set of subjects. Can come from an IdP claim, or be managed locally. |
| **Assignment** | A binding of (subject or group) → role, within a **scope**. |
| **Scope** | Where an assignment applies: tenant-wide, on an application, or on a resource instance (and its descendants). |
| **PDP** | Policy Decision Point — the component that answers "allowed?". |
| **PEP** | Policy Enforcement Point — the SDK code in your app that asks and enforces. |
| **PIP** | Policy Information Point — the source of attributes used in conditions. |
| **UI element** | A named, addressable piece of an application's interface that can be bound to a permission. |
| **Decision bundle** | A precomputed, signed set of a subject's effective permissions/UI state, cached client-side. |
| **Consistency token** | An opaque cursor proving a decision was made against data at least as fresh as a given write. |

---

## 5. System architecture

### 5.1 Components

```
                             ┌──────────────────────────────┐
   Browser ────────────────► │  Admin Console (React SPA)   │
                             └──────────────┬───────────────┘
                                            │ Management API (HTTPS)
                                            ▼
 ┌────────────────┐   OIDC/SAML   ┌────────────────────────────────────────────┐
 │ External IdPs  │ ◄───────────► │            WARDEN SERVER                   │
 │ Entra, Okta,   │               │                                            │
 │ Google, ADFS   │               │  ┌──────────────┐  ┌────────────────────┐  │
 └────────────────┘               │  │ Auth service │  │ Management service │  │
                                  │  │ (OIDC OP,    │  │ (tenants, apps,    │  │
                                  │  │  SAML SP,    │  │  roles, users,     │  │
                                  │  │  local, MFA) │  │  UI elements)      │  │
 ┌────────────────┐               │  └──────┬───────┘  └─────────┬──────────┘  │
 │  Your backend  │  Decision API │         │                    │             │
 │  + Warden SDK  │ ◄────────────►│  ┌──────▼────────────────────▼──────────┐  │
 └───────┬────────┘               │  │        Authorization core            │  │
         │                        │  │  PDP · role resolver · condition eval│  │
         │                        │  └──────┬────────────────────┬──────────┘  │
 ┌───────▼────────┐   UI bundle   │         │                    │             │
 │ Your React app │ ◄────────────►│  ┌──────▼──────┐   ┌─────────▼─────────┐   │
 │  + Warden SDK  │               │  │ Audit sink  │   │  Sync / events    │   │
 └────────────────┘               │  └─────────────┘   └───────────────────┘   │
                                  └──────────────┬─────────────────────────────┘
                                                 │
                              ┌──────────────────┼──────────────────┐
                              ▼                  ▼                  ▼
                        ┌──────────┐      ┌───────────┐      ┌─────────────┐
                        │ Postgres │      │   Redis   │      │ Object store│
                        │ (system  │      │ (sessions,│      │ (audit cold │
                        │ of record)│     │  cache,   │      │  storage)   │
                        └──────────┘      │  pub/sub) │      └─────────────┘
                                          └───────────┘
```

### 5.2 Services (deployable units)

Warden ships as **one binary with selectable roles**, so a small deployment runs a single
process and a large one splits the tiers:

| Role flag | Responsibility | Scales on |
| --- | --- | --- |
| `--role=auth` | Login flows, OIDC OP endpoints, SAML ACS, token issuance, session store. | Logins/sec |
| `--role=pdp` | `/v1/authz/*` decision endpoints, bundle generation. Read-only against a replica. | Checks/sec |
| `--role=mgmt` | Management API, admin console static assets, config sync. | Low |
| `--role=worker` | Async jobs: audit shipping, IdP group sync, assignment expiry, webhooks. | Job volume |
| `--role=all` | All of the above (default; the single-binary story). | — |

### 5.3 Request paths

**Login (OIDC federation)**
1. App redirects to `GET /oauth2/authorize` on Warden.
2. Warden shows the tenant's login page; user picks "Continue with Acme SSO".
3. Warden performs the authorization-code + PKCE dance against the upstream IdP.
4. Warden maps the upstream identity to a local `user` (link-or-create per §7.4), applies
   claim→group and group→role mappings.
5. Warden redirects back to the app with its own authorization code.
6. App exchanges the code at `POST /oauth2/token` for Warden's tokens.

**Authorization check (hot path)**
1. Backend receives a request with a Warden access token.
2. SDK validates the JWT locally against cached JWKS (no network call).
3. SDK consults its **local decision cache**. Hit → answer in microseconds.
4. Miss → `POST /v1/authz/check` (or `/batch-check`), server evaluates, SDK caches with the
   returned TTL and consistency token.
5. Invalidation arrives via the SDK's change stream (SSE/websocket) or cache TTL.

---

## 6. Tenancy and organization model

### 6.1 Hierarchy

```
Deployment
└── Tenant (organization)          ← isolation boundary; own users, roles, IdPs
    ├── Users, Service accounts, Groups
    ├── Role definitions (custom) + adopted application role templates
    ├── Identity provider connections (local / OIDC / SAML)
    └── Application enrollments
        └── Environment (dev | staging | prod)
```

Applications are **defined globally** (an app declares its resources, actions and UI
elements once) and are **enrolled per tenant**. A tenant enrolling an app inherits the app's
role templates as a starting point and may fork/extend them.

### 6.2 Isolation rules

- Every row in every tenant-scoped table carries `tenant_id`. Postgres **row-level security**
  is enabled with `tenant_id = current_setting('warden.tenant_id')`; the application sets it
  per connection/transaction. This is defence-in-depth behind application-level filtering.
- A subject exists within exactly one tenant. Cross-tenant identity (one human, several
  tenants) is modelled as **one `person` with several `user` records linked by a verified
  email or an external `idp_subject`** — this keeps decision evaluation single-tenant and
  simple. *(open: whether v1 exposes the `person` linkage in the UI at all.)*
- Tenant deletion is a soft delete with a configurable retention window, then a hard purge
  job.

### 6.3 Deployment-level (super) administration

A reserved `system` tenant holds deployment operators. Its roles are fixed and not editable:
`system:owner`, `system:operator`, `system:auditor`, `system:support` (read-only, requires
an approved support session with a reason and an expiry, all logged).

---

## 7. Identity and authentication

### 7.1 Supported authentication methods

| Method | Role Warden plays | v1 |
| --- | --- | --- |
| Local username/password | Credential store | ✅ |
| TOTP second factor | Authenticator | ✅ |
| WebAuthn / passkeys | Authenticator | ✅ (second factor), passwordless in v1.1 |
| Recovery codes | Authenticator | ✅ |
| Magic link (email) | Authenticator | ✅ |
| OIDC federation | Relying party to an upstream OP | ✅ |
| SAML 2.0 federation | Service provider to an upstream IdP | ✅ |
| LDAP / Active Directory bind | Credential verifier | v2 |
| OIDC provider (to your apps) | OpenID Provider | ✅ |
| SAML IdP (to your apps) | Identity provider | v2 |

### 7.2 Local authentication

- **Password hashing:** Argon2id, parameters `m=64 MiB, t=3, p=2` (tunable), rehash on login
  when parameters change.
- **Password policy:** per-tenant, expressed as minimum length (default 12), optional
  character-class rules (off by default, per NIST 800-63B), mandatory check against a
  breached-password list (local k-anonymity dataset; no external calls by default).
- **Lockout:** exponential backoff per (account, IP) pair plus a global per-account cap.
  Never leak whether an account exists — identical response and timing for unknown users.
- **Registration:** invitation-only, self-service with email verification, or disabled —
  per-tenant setting.
- **Recovery:** single-use, 15-minute, hashed-at-rest reset tokens; recovery invalidates all
  sessions and refresh tokens by default.

### 7.3 OIDC federation (Warden as RP)

Per-tenant connections with:

- Discovery via `.well-known/openid-configuration` or explicit endpoints.
- `client_id`, `client_secret` (encrypted at rest) or `private_key_jwt`.
- Authorization code flow with **PKCE mandatory**, `state` and `nonce` verified.
- Scope list, default `openid profile email`.
- **Claim mapping** to Warden's user profile (see §7.5).
- **Group source:** a claim path (e.g. `groups`, `roles`, `resource_access.myapp.roles`) that
  is projected into Warden groups on each login.
- **JIT provisioning** policy: `create`, `link-only`, `deny-unknown`.
- Optional **domain hint**: `acme.com` → auto-route to this connection at the login page.
- Back-channel logout (`backchannel_logout_uri`) and RP-initiated logout support.

### 7.4 SAML 2.0 federation (Warden as SP)

- Metadata import by URL or XML upload; metadata is refreshed on a schedule and on demand.
- SP metadata published at `/saml/{connection_id}/metadata`.
- Bindings: HTTP-Redirect and HTTP-POST for AuthnRequest; HTTP-POST for Response.
- **Signature verification is mandatory** on Response and/or Assertion; encrypted assertions
  supported (SP decryption key in the keystore).
- Clock skew tolerance configurable (default 120 s); `NotBefore` / `NotOnOrAfter`,
  `Audience`, `Recipient`, `InResponseTo` and `Destination` all validated.
- **Replay protection**: assertion `ID` stored in Redis with the assertion lifetime as TTL.
- Attribute mapping to profile fields and to groups (multi-valued attributes supported).
- Support for `NameID` formats `emailAddress`, `persistent`, `transient`, `unspecified`.
- IdP-initiated SSO supported but **off by default**, with a per-connection allowlist of
  relay-state targets, because it is a CSRF-shaped risk.
- SLO (Single Logout) supported where the IdP does; otherwise local logout only, clearly
  surfaced in the UI.

#### 7.4.1 Identity linking rules

When a federated login arrives:

1. Look up an existing `identity` by `(connection_id, external_subject)`. Found → that user.
2. Else, if the connection is marked **email-trusted** and the asserted email is verified,
   look up a local user with that email. Found → link the identity (audited) and continue.
3. Else, act per the connection's JIT policy: create the user, or reject with a clear error.

Rule 2 is a known account-takeover vector if the upstream IdP does not verify emails;
`email_trusted` defaults to **false** and the console warns loudly when enabling it.

### 7.5 Claim / attribute mapping

A connection carries a declarative mapping:

```yaml
mapping:
  email:        { from: "email", required: true }
  email_verified: { from: "email_verified", default: false }
  display_name: { from: "name", fallback: ["preferred_username", "email"] }
  given_name:   { from: "given_name" }
  locale:       { from: "locale", default: "en" }
  attributes:                       # arbitrary attributes usable in conditions
    department: { from: "department" }
    cost_center: { from: "extension_costCenter" }
  groups:
    from: "groups"
    transform: [lowercase, strip_prefix("CN=")]
    match: exact                    # exact | regex | prefix
```

Mapped attributes land in `user.attributes` (JSONB) and become available to condition
expressions as `subject.attributes.*`.

### 7.6 Provisioning and lifecycle

- **JIT** on login (above) is the v1 default.
- **SCIM 2.0** inbound (`/scim/v2/Users`, `/scim/v2/Groups`) is v2 — necessary for
  deprovisioning to be timely rather than login-triggered.
- **Lifecycle states:** `invited → active → suspended → deprovisioned → deleted`. Suspension
  and deprovisioning kill sessions and refresh tokens immediately and cause all decisions to
  return deny within the cache TTL (see §10.5).
- **Scheduled group sync** (v2) for IdPs that support directory queries.

### 7.7 Warden as an OIDC provider

Endpoints published under the issuer `https://<host>/`:

| Endpoint | Notes |
| --- | --- |
| `/.well-known/openid-configuration` | Discovery |
| `/.well-known/jwks.json` | Signing keys, with `kid` rotation |
| `/oauth2/authorize` | Code flow; **PKCE required for public clients** |
| `/oauth2/token` | `authorization_code`, `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:token-exchange` |
| `/oauth2/userinfo` | Profile claims |
| `/oauth2/introspect` | RFC 7662, client-authenticated |
| `/oauth2/revoke` | RFC 7009 |
| `/oauth2/logout` | RP-initiated logout, RFC-compliant |
| `/oauth2/par` | Pushed Authorization Requests (RFC 9126) |
| `/oauth2/device` | Device authorization grant, for CLIs |

Implicit grant and the resource-owner password grant are **not** implemented.

---

## 8. Tokens, sessions and claims

### 8.1 The central design tension

The naive approach is to stuff every permission into the access token. That breaks in three
ways: tokens grow past header limits for users with many resource-scoped grants; revocation
becomes impossible until expiry; and resource-instance grants are unbounded in number.

**Decision:** access tokens carry *identity and coarse role context*; fine-grained decisions
come from the PDP with SDK-side caching. See [ADR-0002](docs/adr/0002-token-vs-pdp.md).

### 8.2 Access token

Format: JWT, `RS256` by default (`ES256` selectable), 5–15 minute lifetime (default 10).

```json
{
  "iss": "https://warden.acme.com/",
  "sub": "usr_01HZX8Y3K2QW",
  "aud": ["billing-api"],
  "exp": 1755800000,
  "iat": 1755799400,
  "jti": "tok_01HZX8Y41M",
  "tid": "ten_01HZW0ACME",
  "sid": "ses_01HZX8XA9B",
  "scope": "openid profile email",
  "azp": "billing-web",
  "amr": ["pwd", "otp"],
  "auth_time": 1755799400,
  "wd": {
    "roles": ["finance.viewer", "billing.approver"],
    "groups": ["g_finance", "g_emea"],
    "perm_rev": 184,
    "attrs": { "department": "finance" }
  }
}
```

- `wd.roles` — tenant-wide role slugs only. Resource-scoped roles are **not** included.
- `wd.perm_rev` — the tenant's permission revision at issuance; SDKs use it to detect a
  stale local cache.
- `wd.attrs` — a small, allowlisted set of attributes (configurable per application) so that
  the most common conditions can be evaluated without a PDP round trip.
- Token size budget: **hard cap 4 KB**; the issuer drops `wd.groups` then `wd.attrs` and sets
  `wd.truncated: true` rather than emitting an oversized token.

### 8.3 Refresh token and sessions

- Refresh tokens are opaque, 256-bit, hashed at rest, **rotating**, with reuse detection: a
  replayed token revokes the whole family and raises a security event.
- Absolute lifetime (default 30 days) and idle lifetime (default 7 days), per application.
- A **session** (`sid`) is the browser-level SSO artifact. It survives token refresh and is
  what "log out everywhere" targets. Sessions are stored in Redis with a Postgres mirror for
  the "active sessions" UI.
- `POST /v1/sessions/{id}/revoke` and `POST /v1/users/{id}/revoke-all` propagate within one
  second via the change stream (§10.5).

### 8.4 Service accounts and machine identity

- Service accounts are subjects with `client_credentials` grants, per-tenant, with their own
  role assignments.
- Secrets are shown once, hashed at rest, rotatable with an overlap window, and expirable.
- `private_key_jwt` client auth supported for high-assurance clients.
- **Token exchange** (RFC 8693) supports the delegation case: service A holds a user token
  and needs a downstream token for service B with a narrowed audience, preserving `sub` as
  `act` (actor) claim so audits show "B acting on behalf of user U via A".

---

## 9. The authorization model

### 9.1 Layers

Warden evaluates in four layers, from coarse to fine. Later layers narrow, never widen,
except where an explicit grant adds a permission.

```
1. Membership   — is the subject an active member of the tenant?
2. RBAC         — do the subject's roles (direct, group-derived, inherited) grant the permission?
3. Scope        — does a grant apply at the requested scope (tenant / app / resource instance)?
4. Conditions   — do the ABAC conditions attached to the grant hold in this context?
```

### 9.2 Permissions

A permission is `<application>.<resource_type>:<action>`, e.g. `billing.invoice:approve`.

- Wildcards allowed in **grants**, never in checks: `billing.invoice:*`, `billing.*:read`,
  `billing.*:*`.
- Applications declare their permission surface; unknown permissions in a check return
  `deny` **and** emit a `unknown_permission` warning event (so typos surface in staging
  rather than silently denying in production).
- Actions may declare an `implies` list: `manage` implies `read, write, delete`. Implication
  is expanded at grant time into the materialized closure, not at check time.

### 9.3 Roles

```yaml
role:
  key: finance.approver
  name: Finance Approver
  description: Can approve invoices up to their limit
  type: application_template | tenant_custom | system
  inherits: [finance.viewer]
  permissions:
    - billing.invoice:read
    - billing.invoice:approve
  assignable_by: [tenant.admin, finance.manager]   # who may hand this out
  max_assignees: null
  constraints:
    requires_mfa: true                              # step-up needed to *use* this role
    separation_of_duties_conflicts: [finance.payer] # cannot hold both
```

- **Inheritance** is a DAG; cycles are rejected at write time. Depth is capped (default 8).
- **Role templates** ship with an application; a tenant may adopt them as-is or fork a copy.
  Forked roles do not auto-update; the console shows a drift indicator when the template
  changes.
- **System roles** (`tenant.owner`, `tenant.admin`, `tenant.member`, `tenant.auditor`) are
  immutable and always present.
- **Separation of duties**: conflicting-role pairs block assignment (static SoD) and
  optionally block simultaneous activation (dynamic SoD, v2).

### 9.4 Groups

- Sources: `local` (managed in Warden) or `idp` (projected from a connection's claim).
- Groups can nest (DAG, depth-capped).
- Groups receive role assignments exactly like users do.
- IdP-sourced group membership is **replaced** on each login for that connection, so removals
  upstream take effect at next login (and immediately with SCIM in v2).

### 9.5 Scopes and assignments

An assignment is the tuple:

```
(subject | group)  →  role  @  scope  [conditions]  [valid_from, valid_until]
```

Scope forms:

| Scope | Written as | Meaning |
| --- | --- | --- |
| Tenant | `tenant:ten_01HZW0ACME` | Everywhere in the tenant |
| Application | `app:billing` | Only within one application |
| Environment | `app:billing/env:prod` | One environment of one application |
| Resource instance | `billing.project:acme-2026` | That object |
| Resource subtree | `billing.project:acme-2026/**` | That object and its descendants |

**Resource hierarchy.** Applications may declare parent/child relationships between resource
types (`invoice.parent = project`, `project.parent = org_unit`). Warden stores an instance
hierarchy (`resource_nodes` table, materialized path) so a grant on a project cascades to its
invoices. Applications push hierarchy changes through `POST /v1/resources` or a bulk sync;
apps that do not want to mirror their object graph simply don't declare parents and lose only
the cascade feature.

### 9.6 Conditions (ABAC layer)

Conditions are **CEL** (Common Expression Language) expressions attached to an assignment or
to a role's permission entry. They are pure, side-effect-free, and evaluated with a fuel
limit and a 2 ms deadline.

Available context:

```
subject.id, subject.email, subject.roles, subject.groups, subject.attributes.*
resource.type, resource.id, resource.attributes.*
action
context.ip, context.time, context.request.*   # caller-supplied
environment.name
```

Examples:

```cel
resource.attributes.amount <= subject.attributes.approval_limit
subject.attributes.department == resource.attributes.department
context.time.getHours("UTC") >= 8 && context.time.getHours("UTC") < 20
context.ip.inCidr("10.0.0.0/8")
resource.attributes.status in ["draft", "pending"]
```

**Attribute sourcing (PIP).** `resource.attributes` come from, in order:
1. attributes passed inline in the check request (fastest, app is the source of truth);
2. attributes previously registered for that resource instance via `POST /v1/resources`;
3. an optional per-application **attribute webhook** the PDP may call (with a strict 200 ms
   timeout and a fail-closed default). *(open: whether the webhook lands in v1 or v1.1.)*

If a condition references an attribute that cannot be resolved, the result is **deny** with
`reason: "missing_attribute"`, never silently true.

### 9.7 Deny rules

RBAC is allow-by-default-nothing (implicit deny). On top, an **explicit deny** exists for
exceptions ("this contractor may never see salary data").

Precedence: `explicit deny > explicit allow > implicit deny`. Denies are tenant-admin-only,
always audited, and the console requires a written justification. They cannot be created by
application templates.

### 9.8 Delegation

- A role's `assignable_by` list defines who can hand it out. A tenant admin may delegate
  "can manage roles for the EMEA group" without granting full admin.
- **Time-boxed elevation**: a subject may request a role for N hours with an optional
  approval step; expiry is enforced by `valid_until` and a worker that emits change events.
- All delegation is audited with requester, approver, reason and duration.

### 9.9 Worked example

```
Tenant: ACME
Application: billing (resources: project ⟶ invoice)

Roles:
  billing.viewer            → billing.invoice:read, billing.project:read
  billing.approver ⊃ viewer → billing.invoice:approve
  billing.admin ⊃ approver  → billing.invoice:void, billing.project:manage

Assignments:
  group g_finance → billing.viewer @ tenant:ACME
  user  maria     → billing.approver @ billing.project:acme-2026/**
                    condition: resource.attributes.amount <= 50000
  user  contractor→ DENY billing.invoice:void @ tenant:ACME

Checks:
  maria, billing.invoice:approve, invoice:4711 (project acme-2026, amount 30000) → ALLOW
  maria, billing.invoice:approve, invoice:9002 (project other,      amount 30000) → DENY (scope)
  maria, billing.invoice:approve, invoice:4712 (project acme-2026, amount 90000) → DENY (condition)
  maria, billing.invoice:read,    invoice:9002                                    → ALLOW (group role, tenant-wide)
```

---

## 10. The decision engine (PDP)

### 10.1 API surface

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/authz/check` | One decision. |
| `POST /v1/authz/batch-check` | Up to 1000 decisions in one round trip. |
| `POST /v1/authz/filter` | Given a list of resource ids and one action, return the allowed subset. |
| `POST /v1/authz/list-resources` | Given a subject + action + resource type, return the accessible ids (paginated; requires hierarchy/instance grants to be registered). |
| `GET /v1/authz/effective-permissions` | The subject's full expanded permission set at a scope. |
| `POST /v1/authz/explain` | Same as check but returns the full derivation, for debugging and audit. |
| `GET /v1/authz/bundle` | The subject's cacheable decision bundle (see §10.4). |

### 10.2 Evaluation algorithm

```
check(subject, permission, resource?, context) -> Decision

1.  Resolve subject → (tenant, status). If not active → DENY(subject_inactive).
2.  Resolve the effective role set:
      direct assignments
      ∪ assignments of every group the subject belongs to (transitively)
      filtered to those whose scope covers the requested resource
      filtered to those valid at now()
3.  Expand roles through the inheritance DAG → permission set (memoized per role version).
4.  If an explicit DENY matches (permission, scope) → DENY(explicit_deny).
5.  Find candidate ALLOW grants matching the permission (including wildcards).
    None → DENY(no_grant).
6.  For each candidate, evaluate conditions with the assembled context.
    First candidate whose conditions hold → ALLOW(grant_id).
7.  If all candidates fail conditions → DENY(condition_failed, [failed conditions]).
8.  Emit a decision log record (sampled per §16.2) and return with a consistency token.
```

Step 2–3 are the expensive part and are memoized: the tuple `(tenant_rev, subject_id)` keys a
resolved-role cache; `(tenant_rev, role_id)` keys a permission-closure cache.

### 10.3 Response shape

```json
{
  "allowed": false,
  "reason": "condition_failed",
  "decision_id": "dec_01HZX9M1",
  "consistency_token": "zt_00000000000184",
  "cache": { "ttl_seconds": 60, "cacheable": true },
  "explain": {
    "matched_grants": [
      { "grant_id": "grn_01HZ", "role": "billing.approver",
        "scope": "billing.project:acme-2026/**",
        "conditions": [
          { "expr": "resource.attributes.amount <= subject.attributes.approval_limit",
            "result": false,
            "values": { "resource.attributes.amount": 90000,
                        "subject.attributes.approval_limit": 50000 } }
        ] }
    ]
  }
}
```

`explain` is returned only for `/explain`, for tenant admins, or when the application is in a
non-prod environment — it leaks policy structure.

### 10.4 Decision bundles and SDK caching

Three caching modes, chosen per application:

| Mode | How | Latency | Freshness | When |
| --- | --- | --- | --- | --- |
| `remote` | Every check hits the PDP. | 2–10 ms | Immediate | Low volume, strictest freshness. |
| `cached` (default) | Per-decision LRU in the SDK with server-supplied TTL + change-stream invalidation. | ~0 on hit | ≤ TTL, usually < 1 s | Most apps. |
| `embedded` | The SDK pulls a **policy bundle** (roles, grants for this subject or for the whole tenant) and evaluates locally. | < 100 µs | ≤ sync interval | Very high volume, or PDP-outage tolerance required. |

A **decision bundle** is a signed, compressed document:

```json
{
  "subject": "usr_01HZX8Y3K2QW",
  "tenant": "ten_01HZW0ACME",
  "revision": 184,
  "issued_at": "2026-08-21T18:03:00Z",
  "expires_at": "2026-08-21T18:08:00Z",
  "permissions": ["billing.invoice:read", "billing.project:read"],
  "scoped": [
    { "permission": "billing.invoice:approve",
      "scope": "billing.project:acme-2026/**",
      "condition_id": "cnd_amount_limit" }
  ],
  "conditions": { "cnd_amount_limit": "resource.attributes.amount <= 50000" },
  "ui": { "invoices.approve_button": "visible", "invoices.void_button": "hidden" },
  "signature": "..."
}
```

Bundles are signed with the same keys as tokens so a client can verify integrity, and are
**never** trusted as the sole enforcement — the backend still checks.

### 10.5 Consistency and invalidation

Warden adopts a **Zanzibar-style consistency token** (`zt_<revision>`):

- Every write that affects authorization increments a per-tenant `permission_revision`.
- Writes return the new token. A caller may pass `min_consistency: "zt_...184"` on a check to
  demand evaluation against data at least that fresh ("read your own writes" after granting a
  role in the admin UI).
- Default consistency is `minimize_latency` — may serve from a replica within the staleness
  bound (default 3 s, configurable, hard maximum 30 s).
- **Change stream**: SDKs may hold an SSE connection to `GET /v1/events/stream?tenant=...`
  receiving `{type: "permissions.changed", tenant, revision}` and
  `{type: "subject.invalidated", subject_id}`. On receipt the SDK drops the affected cache
  entries. Target end-to-end propagation: **p95 < 1 s**.
- Revocation of a subject (suspend, delete, session kill) publishes `subject.invalidated`
  and is additionally enforced by short access-token lifetimes.

### 10.6 Failure modes

Per-application `fail_mode`:

- `closed` (default) — PDP unreachable ⇒ deny. Correct for most.
- `open_read` — deny writes, allow reads that were previously allowed in cache.
- `stale` — serve expired cache entries up to `max_stale` (default 5 min), emit a warning
  metric, and mark decisions `degraded: true` in the audit log.

The SDK exposes circuit-breaker state so apps can surface a banner ("permissions may be
stale").

---

## 11. UI element binding — the "extra powers"

This is the feature that makes Warden more than an identity server: **the mapping between a
UI component and the permission required to see it lives on the server and is editable by
administrators.**

### 11.1 Concept

1. A developer gives a component a stable **element key**: `invoices.approve_button`.
2. The element is **declared** in the app's manifest (with a human label, a description, a
   screenshot/anchor hint, and a *suggested* permission).
3. `warden sync` pushes the declaration; the element appears in the console under a tree of
   the app's UI surface.
4. A tenant administrator **binds** the element: required permission(s), or required
   role(s), plus a mode (`hidden` / `disabled` / `read_only`) and optional conditions.
5. At runtime the frontend SDK fetches the **UI bundle** for the current subject and the
   `<Guard>` component renders accordingly.

### 11.2 Element declaration (in the app repo)

```yaml
# warden.yaml
application: billing
version: 3
ui:
  elements:
    - key: invoices.approve_button
      label: "Approve invoice button"
      description: "Primary action on the invoice detail page"
      surface: "web"
      path: "Invoices > Detail > Actions"
      suggests:
        permission: billing.invoice:approve
        resource_type: billing.invoice     # element is evaluated per-object
      default_mode: hidden
    - key: invoices.void_button
      label: "Void invoice button"
      suggests: { permission: billing.invoice:void }
      default_mode: disabled
    - key: nav.reports
      label: "Reports navigation item"
      suggests: { permission: billing.report:read }
```

`default_*` values apply until an administrator overrides them, so an app is functional the
moment it is enrolled.

### 11.3 Binding (in the console or via API)

```json
PUT /v1/apps/billing/ui-elements/invoices.approve_button/binding
{
  "tenant_id": "ten_01HZW0ACME",
  "environment": "prod",
  "requires": {
    "any_of": [
      { "permission": "billing.invoice:approve" },
      { "role": "tenant.owner" }
    ]
  },
  "mode": "disabled",
  "condition": "resource.attributes.status == 'pending'",
  "message": "Only pending invoices can be approved",
  "resource_scoped": true
}
```

- `mode` decides what "not allowed" looks like: `hidden` (not rendered), `disabled`
  (rendered, non-interactive, with `message` as a tooltip), or `read_only`.
- `resource_scoped: true` means the element must be evaluated per resource instance, and the
  React `<Guard>` requires a `resource` prop; using it without one is a development-time
  error.
- Bindings are versioned and environment-scoped, so a change is testable in staging and
  promoted.

### 11.4 The UI bundle

```
GET /v1/ui/bundle?application=billing&environment=prod&surface=web
Authorization: Bearer <access token>

200 OK
{
  "revision": 184,
  "expires_at": "2026-08-21T18:08:00Z",
  "elements": {
    "invoices.approve_button": { "mode": "allow" },
    "invoices.void_button":    { "mode": "disabled", "message": "Requires the Void permission" },
    "nav.reports":             { "mode": "hidden" }
  },
  "deferred": ["invoices.approve_button"],
  "etag": "W/\"184-usr_01HZX8Y3K2QW\""
}
```

- Non-resource-scoped elements are resolved eagerly and returned in `elements`.
- Resource-scoped elements are listed in `deferred`; the SDK resolves them per object with a
  **batched** call to `POST /v1/ui/resolve` (coalesced per animation frame), so a table of
  200 rows produces one request, not 200.
- `ETag` + `If-None-Match` makes the poll cheap; the SDK also listens on the change stream.

### 11.5 Discovery mode (developer experience)

In non-production environments the React SDK can run in **discovery mode**: any `<Guard>`
whose element key is not yet declared is reported to Warden (debounced, batched) and appears
in the console under "Undeclared elements", with the page path and component name. A
developer or admin promotes it to a real element with one click, which also emits the YAML
snippet to paste into `warden.yaml`. This closes the loop between "I wrapped a component"
and "it exists in the admin console" without forcing manifest edits first.

Discovery mode is refused outright when the environment is `prod`.

### 11.6 The mandatory caveat

Every `<Guard>` in the docs is shown next to its server-side counterpart:

```tsx
<Guard element="invoices.approve_button" resource={{ type: "billing.invoice", id }}>
  <ApproveButton onClick={approve} />
</Guard>
```

```python
@router.post("/invoices/{invoice_id}/approve")
@warden.require("billing.invoice:approve", resource=("billing.invoice", "invoice_id"))
async def approve(invoice_id: str): ...
```

The console shows a warning on any UI element whose suggested permission is **never checked
server-side** (detected from decision telemetry): *"This button is hidden from unauthorized
users, but the endpoint behind it appears unprotected."* That check is a genuinely novel
safety feature and should be built in v1.

---

## 12. Backend SDKs

Full Python design: [`docs/sdk-backend-python.md`](docs/sdk-backend-python.md).

### 12.1 Shared contract (all languages)

Every backend SDK provides the same seven capabilities:

1. **Token verification** — JWKS fetch + cache + rotation, `iss`/`aud`/`exp`/`nbf`
   validation, clock-skew tolerance, offline.
2. **`check(subject, permission, resource=None, context=None) -> Decision`**
3. **`batch_check([...])` / `filter(resources, permission)`**
4. **Caching layer** with the three modes of §10.4, plus change-stream subscription.
5. **Framework integration** — middleware, decorators, dependency-injection helpers.
6. **Resource registration** — push resource instances, attributes and hierarchy.
7. **Observability** — structured logs, OpenTelemetry spans (`warden.check`), Prometheus
   metrics (`warden_check_duration_seconds`, `warden_cache_hits_total`,
   `warden_pdp_errors_total`).

### 12.2 Python SDK (v1)

Package `warden-sdk`, Python 3.10+, sync and async APIs, fully typed, zero required
dependencies beyond `httpx`, `pyjwt[crypto]` and `cel-python` (embedded mode only).

```python
from warden import Warden

warden = Warden(
    issuer="https://warden.acme.com",
    application="billing",
    client_id="billing-api",
    client_secret=os.environ["WARDEN_CLIENT_SECRET"],
    cache_mode="cached",
    fail_mode="closed",
)

principal = warden.verify_token(bearer_token)     # -> Principal
if warden.check(principal, "billing.invoice:approve",
                resource=("billing.invoice", invoice.id),
                attributes={"amount": invoice.amount}).allowed:
    ...
```

Integrations shipped in v1: **FastAPI** (dependencies + router guard), **Django** (middleware
+ `@permission_required` replacement + DRF permission class), **Flask** (extension +
decorator). `httpx`/`requests` are the only transport.

### 12.3 Node.js SDK (v1.1)

`@warden/node`, ESM + CJS, TypeScript-first. Express/Fastify/NestJS middleware, Next.js
route handler and server-component helpers.

### 12.4 Go SDK (v1.2)

`github.com/<org>/warden-go`. `net/http` middleware, gRPC interceptor, `context.Context`
propagation of the principal, generics-based `Filter[T]`.

### 12.5 Cross-cutting SDK rules

- **Never** silently allow. A missing configuration is a startup error, not a runtime allow.
- The principal is immutable and carries the raw claims for escape hatches.
- Every SDK ships a `warden doctor` command that validates config, connectivity, clock skew
  and manifest drift.
- Semantic versioning; the wire protocol is versioned separately (`/v1/`) and SDKs declare
  the protocol range they support.

---

## 13. Frontend SDK

Full design: [`docs/sdk-frontend-react.md`](docs/sdk-frontend-react.md).

### 13.1 Packages

| Package | Contents |
| --- | --- |
| `@warden/browser` | Framework-agnostic core: OIDC PKCE client, token storage, silent refresh, bundle fetching + caching, change-stream subscription, batching. |
| `@warden/react` | `WardenProvider`, `<Guard>`, `<Authenticated>`, `usePermission`, `useUIElement`, `useWarden`. |
| `@warden/vue`, `@warden/svelte`, `@warden/angular` | v2, thin wrappers over the core. |

### 13.2 The headline API

```tsx
<WardenProvider config={{ issuer, clientId, application: "billing", environment: "prod" }}>
  <App />
</WardenProvider>

// Simplest form — permission stated in code
<Guard permission="billing.invoice:void">
  <VoidButton />
</Guard>

// The powerful form — element declared in code, permission decided by an admin
<Guard element="invoices.approve_button" resource={{ type: "billing.invoice", id: invoice.id }}>
  <ApproveButton />
</Guard>

// Modes come from the server binding; a fallback can still be supplied
<Guard element="nav.reports" fallback={<UpsellBanner />}>
  <ReportsNavItem />
</Guard>
```

`<Guard>` resolves in this order: server binding for `element` → explicit `permission` prop →
`default_mode` from the manifest → `hidden`.

### 13.3 Rendering semantics

| Server mode | Rendering |
| --- | --- |
| `allow` | Children rendered normally. |
| `hidden` | `fallback` if given, otherwise nothing. |
| `disabled` | Children rendered inside a wrapper that sets `aria-disabled`, blocks pointer/keyboard activation, and shows `message` as a tooltip. |
| `read_only` | Children rendered inside a context that sets `readOnly` on form controls (opt-in via `useGuardState()` for custom components). |
| *loading* | `loading` prop if given; otherwise children are withheld (fail-closed) — never flash a forbidden control. |

### 13.4 Token handling in the browser

- Authorization code + PKCE, no client secret, no implicit flow.
- Access tokens are held **in memory only**. Refresh uses either a rotating refresh token in
  a `Secure; HttpOnly; SameSite=Lax` cookie set by a BFF, or silent iframe/`prompt=none`
  renewal — the SDK supports both and the docs recommend the **BFF pattern** for anything
  handling sensitive data.
- `localStorage` is never used for tokens. The SDK refuses to start if configured otherwise.
- The UI bundle *may* be cached in `sessionStorage` (it is not a credential), keyed by
  subject + revision, to avoid a flash of missing UI on reload.

### 13.5 SSR and Next.js

Server components call `getUIBundle()` on the server with the user's session, so the first
paint is already correct. The provider is hydrated with that bundle to avoid a client
re-fetch. A `middleware.ts` helper protects route segments.

---

## 14. Admin console

A React SPA served by the `mgmt` role, itself protected by Warden (dogfooding).

### 14.1 Sections

| Section | Contents |
| --- | --- |
| **Overview** | Tenant health, login volume, top denials, recent admin changes. |
| **Users** | List/search, profile, identities, sessions, assignments, "effective permissions" viewer, impersonation (§14.3). |
| **Groups** | Local and IdP-sourced groups, membership, assignments. |
| **Roles** | Role editor with inheritance graph, permission picker, drift-from-template indicator, SoD conflicts, "who has this role". |
| **Applications** | Enrollment, environments, manifest history/diff, clients & secrets, fail mode, cache mode. |
| **UI elements** | Tree of declared elements per surface, bindings editor, undeclared-element inbox, unprotected-endpoint warnings. |
| **Authentication** | Local policy, MFA policy, OIDC/SAML connections with a test harness. |
| **Audit** | Filterable log, saved views, export. |
| **Simulator** | The killer admin tool — see below. |

### 14.2 The simulator

Pick a subject (or a hypothetical one: "a user with roles X and Y in group Z"), a permission,
and a resource. The console shows allow/deny **with the full derivation tree**: which
assignment matched, through which group, which role inheritance path, which condition passed
or failed and with what values. Also runs in reverse: "who can do `billing.invoice:void` on
this invoice?"

Every support conversation that begins "why can't this user…" ends here.

### 14.3 Impersonation

- Requires a dedicated permission, a stated reason, and an expiry (max 60 min).
- The impersonated token carries `act: {sub: <admin>}` and `amr: ["impersonation"]`; apps can
  detect and display a banner via a documented claim.
- Every request made during impersonation is tagged in the audit log with both identities.
- Tenant setting to forbid impersonation entirely.

### 14.4 Accessibility and i18n

WCAG 2.2 AA for the console and for all SDK-rendered UI (the `disabled` wrapper in
particular). Console strings are externalized; English ships in v1, the framework supports
more.

---

## 15. Management API and IaC

### 15.1 API

Everything the console does is a documented REST call under `/v1/`, OpenAPI 3.1 published at
`/v1/openapi.json`. Authentication via service-account tokens with management permissions.
Conventions: cursor pagination, `Idempotency-Key` on POST, RFC 9457 problem details for
errors, `If-Match`/ETag optimistic concurrency on mutable resources.

### 15.2 Declarative configuration

The `warden` CLI reads `warden.yaml` and synchronizes an application's declaration —
resource types, actions, role templates, UI elements — with a **plan/apply** workflow:

```bash
warden plan   --env staging     # diff, exit 2 if changes
warden apply  --env staging
warden promote --from staging --to prod --only ui-bindings
```

Declared objects are managed; anything an administrator created in the console is left alone
unless `--prune` is passed. This keeps GitOps and click-ops coexisting.

A **Terraform provider** is a v1.2 deliverable, built on the same API.

### 15.3 Webhooks

Outbound events: `user.created`, `user.suspended`, `assignment.created`,
`assignment.expired`, `role.updated`, `permissions.changed`, `login.failed`,
`security.refresh_token_reuse`. HMAC-SHA256 signed with a per-endpoint secret, timestamped,
retried with exponential backoff for 24 h, with a dead-letter view in the console.

---

## 16. Audit, observability and compliance

### 16.1 Administrative audit log

Append-only, hash-chained (each entry stores `prev_hash`, so tampering is detectable),
covering every mutation: who, what, before/after diff, tenant, IP, user agent, request id,
reason (where required), and whether it happened under impersonation. Retention is
configurable per tenant; cold entries are archived to object storage in a signed, verifiable
format.

### 16.2 Decision log

High-volume and therefore configurable per application:

| Level | What is recorded |
| --- | --- |
| `off` | Nothing. |
| `denies` (default) | All deny decisions, with reason. |
| `sampled` | All denies + N% of allows. |
| `all` | Everything. |

Records go to a buffered async sink (never blocking the decision path) and can be exported to
stdout JSON, a webhook, Kafka, or S3/Parquet.

### 16.3 Metrics and tracing

Prometheus metrics on every service (`warden_check_duration_seconds`,
`warden_login_total{method,result}`, `warden_token_issued_total`,
`warden_change_propagation_seconds`, `warden_cache_hit_ratio`). OpenTelemetry traces with
context propagated from the SDK, so an app's trace shows the `warden.check` span inline.

### 16.4 Compliance posture

Designed to support SOC 2 and ISO 27001 evidence collection: immutable audit, access reviews
(v2: scheduled certification campaigns where a manager confirms or revokes each report's
roles), data residency by deployment, GDPR data export and erasure endpoints per subject.

---

## 17. Security requirements

| Area | Requirement |
| --- | --- |
| Transport | TLS 1.2+ only; HSTS; secure cookie flags. |
| Passwords | Argon2id; never logged; constant-time comparison. |
| Secrets at rest | Envelope encryption (AES-256-GCM) with a KEK from the environment, a KMS, or a file; key rotation supported. |
| Token signing | Asymmetric only; keys rotated on a schedule (default 90 days) with an overlap window; JWKS publishes current + previous. |
| CSRF | State + nonce + PKCE on all browser flows; `SameSite` cookies; double-submit for console mutations. |
| Clickjacking | `frame-ancestors 'none'` on all Warden-served UI. |
| Open redirect | Strict allowlist of `redirect_uri` values, exact match including path; no wildcards in production. |
| SSRF | IdP discovery/metadata fetches go through an egress allowlist with private-range blocking, size limits and timeouts. |
| XML | SAML parsing with DTD and external entities disabled; XML signature wrapping defences (canonical parse-then-verify, verify the exact element that is used). |
| Rate limits | Per-IP and per-account on login, token, and reset endpoints; per-client on decision endpoints; 429 with `Retry-After`. |
| Enumeration | Uniform responses and timing on login, reset and invite endpoints. |
| Input | Strict schema validation; parameterized SQL exclusively; output encoding in the console. |
| Dependencies | SBOM published per release; `govulncheck`/`pip-audit`/`npm audit` in CI; releases signed and attested (SLSA level 2 target). |
| Testing | Threat model per §17.1 maintained in `docs/threat-model.md`; external penetration test before 1.0. |

### 17.1 Named threats to mitigate explicitly

1. **Confused deputy via UI-only enforcement** — mitigated by §11.6's unprotected-endpoint
   detector and by documentation.
2. **Account takeover via unverified federated email** — mitigated by `email_trusted=false`
   default (§7.4.1).
3. **Privilege escalation via role assignment** — a subject may never assign a role
   containing permissions they do not themselves hold, unless they hold
   `tenant.role:assign_any`. Enforced server-side, tested explicitly.
4. **Stale permissions after revocation** — short tokens + change stream + `min_consistency`.
5. **Tenant crossing** — RLS plus a test suite that runs every management endpoint with a
   foreign `tenant_id` and asserts 404.
6. **SAML signature wrapping / XXE** — see the XML row above; fixture corpus of known
   malicious assertions in the test suite.
7. **Refresh token theft** — rotation with reuse detection revoking the family.

---

## 18. Performance and scale targets

Targets for v1, measured on 4 vCPU / 8 GiB per PDP instance:

| Metric | Target |
| --- | --- |
| `check` p50 / p99, SDK cache hit | < 50 µs / < 200 µs |
| `check` p50 / p99, PDP round trip (same region) | < 3 ms / < 10 ms |
| `batch-check` of 100, p99 | < 25 ms |
| Throughput per PDP instance | ≥ 5 000 checks/s |
| Login p99 (local) | < 400 ms |
| Token issuance p99 | < 100 ms |
| Change propagation to SDK caches, p95 | < 1 s |
| Bundle generation for a subject with 50 grants | < 30 ms |

Scale assumptions for capacity planning: 1 000 tenants, 1 000 000 users, 10 000 roles,
50 000 000 assignments, 100 000 000 registered resource instances.

Benchmarks live in `bench/` and run in CI on every release with regression gates.

---

## 19. Technology choices

| Layer | Choice | Rationale |
| --- | --- | --- |
| Server | **Go 1.23+** | Single static binary (the self-host story), strong concurrency for the PDP hot path, mature OIDC/SAML libraries, low memory per connection. |
| Datastore | **PostgreSQL 15+** | Recursive CTEs for role/resource graphs, JSONB for attributes, RLS for tenant isolation, ubiquitous. |
| Cache / pubsub | **Redis 7** (or Valkey) | Sessions, decision cache, replay protection, change-stream fan-out. Optional: single-node deployments run an in-process cache. |
| Condition language | **CEL** (`cel-go`) | Sandboxed, non-Turing-complete, bounded evaluation, ports exist for Python/JS/Java. |
| Console & frontend SDK | **TypeScript + React 18/19**, Vite | Matches the target audience of the frontend SDK. |
| API style | REST/JSON + OpenAPI 3.1; **gRPC** for the decision API in v1.2 | REST for reach, gRPC for the hot path later. |
| Migrations | `golang-migrate`, forward-only, expand/contract | Zero-downtime upgrades. |
| Container | Distroless image, non-root, read-only rootfs | Baseline hardening. |

*(open: Go for the server is the recommendation, not a decision the user has ratified. If the
team is Python-only, a FastAPI + SQLAlchemy server is viable for v1 at the cost of the
single-binary story and roughly 3–5× the PDP hardware. See
[ADR-0001](docs/adr/0001-server-language.md).)*

---

## 20. Deployment and operations

### 20.1 Topologies

1. **Single container** — `warden --role=all` + Postgres + Redis. Docker Compose provided.
   Suitable to ~50 req/s of checks.
2. **Kubernetes** — Helm chart with separate Deployments per role, HPA on the PDP by CPU and
   check latency, PodDisruptionBudgets, and a `warden-migrate` Job as a pre-upgrade hook.
3. **Multi-region** — writes to a primary region, PDP read replicas per region, change stream
   fanned out over Redis replication or NATS. Decisions are served locally with the staleness
   bound of §10.5.

### 20.2 Operational concerns

- **Health**: `/healthz` (liveness), `/readyz` (dependencies), `/metrics`.
- **Zero-downtime upgrades**: expand/contract migrations; the API version in the path plus a
  documented two-release deprecation window.
- **Backup/restore**: documented `pg_dump` procedure plus a `warden export` producing a
  portable, encrypted archive of tenant config for migration between deployments.
- **Disaster recovery**: RPO 5 min (WAL shipping), RTO 30 min, restore drill documented and
  exercised each release.
- **Bootstrap**: `warden init` creates the system tenant, the first owner, signing keys, and
  prints a one-time setup URL. No default credentials, ever.

---

## 21. Testing strategy

| Layer | Approach |
| --- | --- |
| Unit | Table-driven tests for the evaluation algorithm; every §9.9-style scenario is a fixture. |
| **Conformance suite** | A language-agnostic YAML corpus of `(model, assignments, check, expected)` cases, executed against the server *and* against every SDK's embedded evaluator. Guarantees identical semantics across Python/Node/Go. This is the single most important test asset in the project. |
| Property-based | Invariants: adding a role never removes a permission; an explicit deny always wins; scope narrowing is monotone. |
| Integration | Dockerized Postgres/Redis; full login flows against **mock IdPs** (a small OIDC OP and SAML IdP shipped in `testing/`), including hostile SAML fixtures. |
| Multi-tenant isolation | Automated sweep: every endpoint × foreign tenant ⇒ 404. |
| Frontend | React Testing Library for `<Guard>` semantics; Playwright end-to-end covering login → bundle → guarded render → server-side denial. |
| Load | k6 scenarios per §18 with regression gates in CI. |
| Security | SAST, dependency scanning, and the threat-model checklist as a release gate. |

---

## 22. Roadmap

### M0 — Foundations (weeks 1–3)
Repo, CI, migrations, tenant/user/application data model, config, bootstrap, health, the
conformance-suite harness (empty but wired).

### M1 — Identity (weeks 4–8)
Local auth with Argon2id, TOTP, sessions, OIDC provider endpoints (authorize, token,
userinfo, JWKS, introspect, revoke, logout), refresh rotation with reuse detection, email
delivery.
*Exit:* an app can log a user in and out with a stock OIDC library.

### M2 — RBAC core (weeks 9–14)
Permissions, roles, inheritance, groups, assignments, scopes, `check`/`batch-check`,
effective-permissions, `explain`, decision log, conformance cases.
*Exit:* `warden.check()` answers correctly for every fixture in the corpus.

### M3 — Python SDK + FastAPI (weeks 13–17, overlaps M2)
Token verification, check/batch/filter, caching modes, FastAPI + Django + Flask integrations,
`warden doctor`, documentation with runnable examples.
*Exit:* a reference application is fully protected end to end.

### M4 — Federation (weeks 15–21)
OIDC RP connections, SAML SP connections, claim/attribute/group mapping, identity linking,
connection test harness in the console.
*Exit:* login through Entra ID (OIDC), Okta (SAML) and Google verified against real tenants.

### M5 — UI binding + React SDK (weeks 18–24)
UI element declarations, bindings, UI bundle, batching, `@warden/browser`,
`@warden/react`, `<Guard>`, discovery mode, unprotected-endpoint detector.
*Exit:* an administrator hides a button in production without a deploy.

### M6 — Console (weeks 20–28)
All sections of §14, with the simulator and the audit viewer.

### M7 — Fine-grained + conditions (weeks 26–32)
Resource registration and hierarchy, CEL conditions, explicit denies, time-boxed elevation,
`list-resources`, consistency tokens and the change stream.

### M8 — Hardening → 1.0 (weeks 30–36)
Helm chart, load tests against §18, penetration test, SBOM/signing, documentation site,
migration/backup tooling.

### Post-1.0
Node SDK (1.1) → Go SDK + Terraform provider + gRPC decision API (1.2) → SCIM, LDAP, access
reviews, SAML IdP mode, Vue/Svelte/Angular SDKs (2.0).

---

## 23. Open questions

| # | Question | Blocks |
| --- | --- | --- |
| Q1 | Server language: Go (recommended) or Python? | M0 |
| Q2 | Is this a product to sell, an internal platform, or open source? Changes tenancy, licensing and the admin console's depth. | M0 |
| Q3 | Do target applications already have a resource hierarchy they can mirror, or must v1 work with instance-level grants only? | M7 |
| Q4 | Is SAML needed at launch, or can it follow OIDC by one milestone? It is roughly a third of M4. | M4 |
| Q5 | Multi-region from day one, or single-region for 1.0? | M8 |
| Q6 | Should the attribute webhook (PIP) ship in v1, or are inline attributes sufficient? | M7 |
| Q7 | Does the product need to be an *upstream* SAML IdP (apps that only speak SAML), or is OIDC-to-apps enough? | Post-1.0 |
| Q8 | Data residency requirements — do any target customers require EU-only storage? | M8 |
| Q9 | Naming: "Warden" is a placeholder. Trademark clearance needed before any public release. | Pre-1.0 |
