# Warden — HTTP API reference (draft)

Companion to [`../SPEC.md`](../SPEC.md). All paths are relative to the issuer, e.g.
`https://warden.acme.com`. OpenAPI 3.1 is published at `/v1/openapi.json`.

## Conventions

| Topic | Rule |
| --- | --- |
| Auth | `Authorization: Bearer <token>`. User tokens for user-context calls, service-account tokens for management and decision calls. |
| Tenant | Taken from the token's `tid`. Deployment operators may pass `X-Warden-Tenant` if their token carries `system:operator`. |
| Errors | RFC 9457 problem details: `{"type","title","status","detail","instance","errors":[...]}`. |
| Idempotency | `Idempotency-Key` header honored on all POSTs that create; replays return the original response for 24 h. |
| Pagination | Cursor based: `?limit=50&cursor=...`, response `{"data":[...],"next_cursor":"...","has_more":true}`. |
| Concurrency | `ETag` on mutable resources; `If-Match` required for `PUT`/`PATCH` in strict mode. |
| Versioning | Path-versioned (`/v1/`). Additive changes are not breaking; removals get a two-release deprecation window announced via the `Sunset` header. |
| Rate limits | `X-RateLimit-Limit`, `-Remaining`, `-Reset`; `429` with `Retry-After`. |

---

## 1. OIDC / OAuth 2.0 endpoints

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | Discovery document. |
| GET | `/.well-known/jwks.json` | Signing keys (current + previous `kid`). |
| GET | `/oauth2/authorize` | Code flow. PKCE `S256` required for public clients. |
| POST | `/oauth2/par` | Pushed authorization request (RFC 9126). |
| POST | `/oauth2/token` | Grants: `authorization_code`, `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:token-exchange`. |
| GET | `/oauth2/userinfo` | Profile claims for the bearer. |
| POST | `/oauth2/introspect` | RFC 7662. Client-authenticated. |
| POST | `/oauth2/revoke` | RFC 7009. |
| GET | `/oauth2/logout` | RP-initiated logout with `id_token_hint` + `post_logout_redirect_uri`. |
| POST | `/oauth2/device` · `/oauth2/device/token` | Device grant, for CLIs. |

### SAML

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/saml/{connection_id}/metadata` | SP metadata for the upstream IdP. |
| POST | `/saml/{connection_id}/acs` | Assertion Consumer Service. |
| GET/POST | `/saml/{connection_id}/slo` | Single Logout. |

---

## 2. Authorization API (the hot path)

### `POST /v1/authz/check`

```json
{
  "subject": { "id": "usr_01HZX8Y3K2QW" },
  "permission": "billing.invoice:approve",
  "resource": {
    "type": "billing.invoice",
    "id": "4711",
    "attributes": { "amount": 30000, "status": "pending", "project": "acme-2026" }
  },
  "context": { "ip": "203.0.113.4", "request_id": "req_9f2" },
  "min_consistency": "zt_00000000000184",
  "explain": false
}
```

`subject` may instead be `{"token": "<access token>"}` — the PDP validates it and derives the
subject, which is what SDKs do when they have not yet parsed the token themselves.

**200**

```json
{
  "allowed": true,
  "reason": "grant_matched",
  "decision_id": "dec_01HZX9M1",
  "matched_grant": "grn_01HZ",
  "consistency_token": "zt_00000000000184",
  "cache": { "cacheable": true, "ttl_seconds": 60 }
}
```

Deny reasons: `subject_inactive`, `subject_not_found`, `no_grant`, `out_of_scope`,
`condition_failed`, `explicit_deny`, `grant_expired`, `unknown_permission`,
`missing_attribute`, `mfa_required`, `degraded_fail_closed`.

### `POST /v1/authz/batch-check`

Up to 1000 items. Shared `subject` and `context` may be hoisted to the top level.

```json
{
  "subject": { "id": "usr_01HZX8Y3K2QW" },
  "checks": [
    { "ref": "a", "permission": "billing.invoice:read",    "resource": {"type":"billing.invoice","id":"4711"} },
    { "ref": "b", "permission": "billing.invoice:approve", "resource": {"type":"billing.invoice","id":"4711"} }
  ]
}
```

Response: `{"results": {"a": {"allowed": true, ...}, "b": {"allowed": false, ...}}}`.

### `POST /v1/authz/filter`

Given many resources and one permission, return the allowed subset — the "which rows may
this user see" case, without N round trips.

```json
{ "subject": {"id":"usr_01H"}, "permission": "billing.invoice:read",
  "resources": [{"type":"billing.invoice","id":"4711"}, {"type":"billing.invoice","id":"4712"}] }
→ { "allowed": ["4711"], "denied": ["4712"] }
```

### `POST /v1/authz/list-resources`

The inverse: enumerate what a subject can act on. Requires registered resource instances.
Paginated, capped, and explicitly documented as *not* a substitute for database filtering
when the result set is large — it returns ids for the app to intersect with its own query.

### `GET /v1/authz/effective-permissions?subject_id=&scope=`

Fully expanded permission set at a scope, with the derivation for each entry.

### `POST /v1/authz/explain`

Identical body to `check`, always returns the full derivation tree (SPEC §10.3). Restricted
to tenant admins and non-production environments.

### `GET /v1/authz/bundle?application=&environment=`

Signed decision bundle for the bearer (SPEC §10.4). Supports `If-None-Match`.

### `GET /v1/events/stream?application=`

`text/event-stream`. Events:

```
event: permissions.changed
data: {"tenant":"ten_01HZW0ACME","revision":185}

event: subject.invalidated
data: {"tenant":"ten_01HZW0ACME","subject_id":"usr_01HZX8Y3K2QW","reason":"suspended"}
```

Clients reconnect with `Last-Event-ID`; the server replays up to 5 minutes of events, or
sends `resync` if the gap is larger.

---

## 3. UI element API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/ui/bundle` | Resolved UI state for the bearer (SPEC §11.4). |
| POST | `/v1/ui/resolve` | Batch-resolve resource-scoped elements. |
| GET | `/v1/apps/{app}/ui-elements` | List declared elements. |
| PUT | `/v1/apps/{app}/ui-elements/{key}` | Declare/update an element (usually via `warden sync`). |
| PUT | `/v1/apps/{app}/ui-elements/{key}/binding` | Create/replace the tenant binding. |
| DELETE | `/v1/apps/{app}/ui-elements/{key}/binding` | Revert to the manifest default. |
| POST | `/v1/apps/{app}/ui-elements/discovered` | Discovery-mode reporting (non-prod only). |

### `POST /v1/ui/resolve`

```json
{ "application": "billing", "environment": "prod",
  "items": [
    { "ref": "r1", "element": "invoices.approve_button",
      "resource": {"type":"billing.invoice","id":"4711","attributes":{"status":"pending"}} },
    { "ref": "r2", "element": "invoices.approve_button",
      "resource": {"type":"billing.invoice","id":"4712","attributes":{"status":"paid"}} }
  ] }
→ { "results": { "r1": {"mode":"allow"},
                 "r2": {"mode":"disabled","message":"Only pending invoices can be approved"} } }
```

---

## 4. Management API

### Tenants

`GET|POST /v1/tenants` · `GET|PATCH|DELETE /v1/tenants/{id}` ·
`GET|PUT /v1/tenants/{id}/settings`

### Users

| Method | Path |
| --- | --- |
| GET/POST | `/v1/users` (filter by email, status, group, role) |
| GET/PATCH/DELETE | `/v1/users/{id}` |
| POST | `/v1/users/{id}/suspend` · `/reactivate` · `/deprovision` |
| POST | `/v1/users/{id}/revoke-sessions` |
| POST | `/v1/users/invite` |
| GET | `/v1/users/{id}/identities` · `DELETE /v1/users/{id}/identities/{identity_id}` |
| GET | `/v1/users/{id}/sessions` |
| GET | `/v1/users/{id}/grants` |
| GET | `/v1/users/{id}/effective-permissions` |

### Groups

`GET|POST /v1/groups` · `GET|PATCH|DELETE /v1/groups/{id}` ·
`POST|DELETE /v1/groups/{id}/members`

### Roles

| Method | Path |
| --- | --- |
| GET/POST | `/v1/roles` |
| GET/PATCH/DELETE | `/v1/roles/{id}` |
| POST | `/v1/roles/{id}/fork` (adopt an application template as a tenant custom role) |
| GET/PUT | `/v1/roles/{id}/permissions` |
| GET/PUT | `/v1/roles/{id}/inherits` |
| GET | `/v1/roles/{id}/assignees` |
| GET | `/v1/roles/{id}/drift` (differences from the template it was forked from) |

### Grants and denials

```
POST /v1/grants
{
  "subject": { "user_id": "usr_01H" },       // or {"group_id": "grp_01H"}
  "role_id": "rol_billing_approver",
  "scope": { "kind": "subtree", "ref": "billing.project:acme-2026" },
  "condition": "resource.attributes.amount <= 50000",
  "valid_until": "2026-09-20T00:00:00Z",
  "reason": "Q3 approval coverage"
}
→ 201 { "id": "grn_01HZ", "consistency_token": "zt_00000000000185" }
```

`DELETE /v1/grants/{id}` · `GET /v1/grants?subject_id=&role_id=&scope_ref=`
`POST|DELETE /v1/denials` (requires `reason`, tenant-admin only)

### Applications

`GET|POST /v1/apps` · `GET|PATCH /v1/apps/{key}` ·
`POST /v1/apps/{key}/manifest` (plan/apply sync; `?dry_run=true` returns the diff) ·
`GET /v1/apps/{key}/manifest/history` ·
`GET|POST /v1/apps/{key}/clients` · `POST /v1/apps/{key}/clients/{id}/rotate-secret` ·
`POST|DELETE /v1/tenants/{id}/enrollments`

### Resources

`POST /v1/resources` (upsert one or many instances with parent + attributes) ·
`POST /v1/resources/bulk` (NDJSON stream, for backfills) ·
`DELETE /v1/resources/{ref}` · `GET /v1/resources/{ref}`

### Identity providers

`GET|POST /v1/connections` · `GET|PATCH|DELETE /v1/connections/{id}` ·
`POST /v1/connections/{id}/test` (runs a live round trip and returns the mapped profile
without creating a user) · `POST /v1/connections/import-metadata`

### Audit

`GET /v1/audit/events` (filters: actor, action, target, time range, impersonation) ·
`POST /v1/audit/export` (async job → signed download) ·
`GET /v1/audit/verify?from=&to=` (verifies the hash chain)

### Webhooks

`GET|POST /v1/webhooks` · `GET|PATCH|DELETE /v1/webhooks/{id}` ·
`POST /v1/webhooks/{id}/test` · `GET /v1/webhooks/{id}/deliveries`

---

## 5. Error catalogue (selection)

| Status | `type` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Schema violation; `errors[]` lists field paths. |
| 401 | `invalid_token` | Missing/expired/malformed bearer. |
| 403 | `insufficient_permission` | The caller lacks the management permission; names the permission required. |
| 404 | `not_found` | Includes cross-tenant access (never 403 — that would confirm existence). |
| 409 | `conflict` | ETag mismatch, duplicate key, role cycle, SoD violation. |
| 422 | `policy_invalid` | CEL failed to compile; returns position and message. |
| 429 | `rate_limited` | With `Retry-After`. |
| 503 | `dependency_unavailable` | Database or cache down; decision endpoints apply `fail_mode`. |
