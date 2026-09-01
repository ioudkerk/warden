# Deployment

| File | Purpose |
| --- | --- |
| `warden-server.example.yaml` | Annotated server configuration. Copy, edit, and pass with `-config` or `WARDEN_CONFIG`. |
| `roles.sql` | The two database roles Warden needs. Run once, as a superuser. |
| `docker-compose.yml` | Local development dependencies: Postgres, Redis and Mailpit. `make dev-up`. |

A Helm chart for the Kubernetes topology of SPEC §20.1 arrives with M8.

## Getting a key-encryption key

Warden encrypts IdP client secrets and other stored credentials with a KEK you
supply. It never generates one: a key invented at startup would be different on the
next restart, silently orphaning everything encrypted under the previous one.

```bash
export WARDEN_KEK="$(openssl rand -base64 32)"   # or: make kek
```

Then point the server at it with `security.kek: env:WARDEN_KEK`, or store the key in
a file and use `file:/etc/warden/kek`. Back the key up somewhere separate from the
database — losing it means losing every encrypted value.

## Two database roles, and why

Warden needs `warden_app` (serves requests, subject to row-level security) and
`warden_system` (migrations, bootstrap and cross-tenant jobs, holds `BYPASSRLS`). Run
[`roles.sql`](roles.sql) once, then point `database.url` at the first and
`database.system_url` at the second.

The separation is what makes tenant isolation enforceable rather than aspirational. A
request-serving role that can bypass row-level security leaves the boundary defined in
the schema and absent in fact — and nothing about a running system would show it:
every query succeeds, every test passes. **Warden therefore verifies this at startup
and refuses to serve production traffic on a role that can bypass**, naming the role
and pointing at this file. Outside production it warns loudly and continues, because
one role and no ambitions is a reasonable way to run on a laptop.

`database.system_url` is optional. Without it Warden serves tenant traffic normally
and reports that migrations, bootstrap and cross-tenant jobs are unavailable, rather
than running them through a connection that cannot see the rows.

## Checking a configuration before deploying

```bash
warden config          # resolves file + environment + flags, validates, prints
```

Everything it prints is safe to paste into an issue: secrets redact themselves. A
missing or malformed setting is reported with the flag and environment variable that
would fix it, and every problem is reported in one pass.
