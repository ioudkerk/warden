# Deployment

| File | Purpose |
| --- | --- |
| `warden-server.example.yaml` | Annotated server configuration. Copy, edit, and pass with `-config` or `WARDEN_CONFIG`. |
| `roles.sql` | The two database roles Warden needs. Run once, as a superuser. |
| `dev-roles.sql` | The same two roles with development passwords. Applied automatically by the compose Postgres on first boot. |
| `docker-compose.yml` | The whole local stack: Postgres, Redis, Mailpit, migrations, seed and server. `make dev`. |
| `../Dockerfile` | The server image. Multi-stage, built at the ADR-0001 Go floor, distroless and non-root. |

A Helm chart for the Kubernetes topology of SPEC §20.1 arrives with M8.

## Running the whole thing locally

```bash
make dev              # or: docker compose -f deploy/docker-compose.yml up -d --wait
make dev-logs-seed    # the owner's one-time setup URL and the demo application's token
```

That brings up the dependencies, migrates, publishes `examples/warden.yaml`, seeds SPEC
§9.9's worked example, and serves it on <http://localhost:8080>. Roughly twenty seconds
on a warm machine, most of it building the image. Mail goes to Mailpit on
<http://localhost:8025> and leaves nothing on the network.

Two things it does **not** do, because they are the habits that leak into real
deployments:

**No credential is baked in.** The key-encryption key is generated once, on your
machine, into the `warden-state` volume — Warden never invents one at startup, because a
key that differs on the next boot silently orphans everything encrypted under the last
one. The first owner has no password: `warden seed` prints a single-use setup URL, once,
and only into the seed container's logs. This is the same guarantee `warden init` gives
(SPEC §20.2), not a development-only shortcut around it.

**Nothing runs as production.** Every Warden service sets `WARDEN_ENVIRONMENT=dev`
explicitly, and `warden seed` refuses to run in production at all — it creates subjects
with predictable identifiers and standing grants, which is the situation `warden init`
exists to prevent. Both ways of getting it wrong fail closed: leaving the variable unset
falls back to the `prod` default and is refused, and setting it to an empty string is
rejected by configuration validation.

Bringing the stack up again is safe: the manifest is reapplied, the tenant is left
alone, and the KEK is not regenerated. To start over, `make dev-reset` — which deletes
the database **and** the KEK together, because dropping either one alone leaves a key
that opens nothing or a database nothing can open.

### Working on the server itself

Rebuilding an image on every edit is a poor loop. Run the dependencies in containers and
Warden from source:

```bash
make dev-setup                                     # Postgres, Redis, Mailpit, migrations, roles

export WARDEN_KEK="$(make -s kek)"
export WARDEN_SECURITY_KEK=env:WARDEN_KEK
export WARDEN_ENVIRONMENT=dev
export WARDEN_ISSUER=http://localhost:8080
export WARDEN_CACHE_URL=redis://localhost:6379/0
export WARDEN_DATABASE_URL="postgres://warden_app:app-pw@localhost:5432/warden?sslmode=disable"
export WARDEN_DATABASE_SYSTEM_URL="postgres://warden_system:system-pw@localhost:5432/warden?sslmode=disable"

go run ./cmd/warden seed
go run ./cmd/warden serve
```

`warden config` prints the resolved configuration and reports every problem in one pass,
which is the quickest way to find whichever variable is missing. Keep `WARDEN_KEK` for
the life of the database: a new one cannot open the signing key the last one sealed.

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
