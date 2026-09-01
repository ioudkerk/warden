# Migrations

`golang-migrate`, forward-only, expand/contract. One numbered pair of files per
change: `NNNNNN_name.up.sql` and `NNNNNN_name.down.sql`.

```bash
make migrate-up                     # apply everything pending
make migrate-down                   # roll back one step
make migrate-redo                   # roll everything back and re-apply
make migrate-new NAME=add_widgets   # create the next numbered pair
make schema-dump                    # regenerate ../schema.sql after a change
```

`DATABASE_URL` defaults to the local development database from `make dev-up`.

## Rules

1. **Forward only.** A released migration is never edited. Fix a mistake with a new
   migration, because someone has already applied the old one.

2. **Expand then contract, across releases.** Never drop or rename a column in the
   same release that stops writing it — during a rolling deploy, old and new
   instances run at once, and the old ones are still reading it. Add the new column,
   ship code that writes both, backfill, ship code that reads the new one, and only
   then drop the old column in a later release.

3. **Every migration must be runnable against a live cluster.** No `ACCESS EXCLUSIVE`
   lock held while a table is rewritten, no `ALTER TYPE`. Add indexes to existing
   tables with `CREATE INDEX CONCURRENTLY` — which cannot run inside a transaction,
   so such a migration needs its own file and the `x-no-transaction` note below.

4. **Every up has a real down.** CI rolls every migration back, checks that nothing
   but `schema_migrations` survives, and re-applies. A down migration that quietly
   forgets a table makes the next `up` fail on an object that already exists, usually
   on someone else's machine.

5. **CHECK constraints, not enum types.** `ALTER TYPE ... ADD VALUE` cannot run in a
   transaction and a value can never be removed, which makes enums close to
   unmigratable. A CHECK constraint on a `text` column enforces the same thing and
   can be replaced in one statement.

6. **Regenerate the schema dump.** `../schema.sql` is committed and CI fails if it
   does not match the migrations. It is the reviewable artefact: a migration whose
   effect is not what its author intended shows up as a diff in the pull request.

## Concurrent index creation

`CREATE INDEX CONCURRENTLY` cannot run inside a transaction. Postgres opens an
implicit one around a multi-statement request, so such an index must be the **only
statement in its migration file** — including the down migration, which needs
`DROP INDEX CONCURRENTLY`.

No migration needs this yet: the ones below run against an empty cluster, where a
plain `CREATE INDEX` blocks nothing. The first index added to a populated table does.

## What is here

| Migration | Contents | Task |
| --- | --- | --- |
| `000001_extensions_and_helpers` | `citext`, the `updated_at` trigger function | M0-5 |
| `000002_tenancy_and_identity` | `tenant`, `app_user`, `credential`, `idp_connection`, `identity`, `session`, `refresh_token` | M0-5 |
| `000003_groups` | `group_`, `group_member` | M0-5 |
| `000004_applications_and_permissions` | `application`, `environment`, `app_enrollment`, `resource_type`, `action`, `permission` | M0-5 |

Still to come: row-level security policies (M0-6), roles and grants (M2-1), resource
instances and hierarchy (M7), UI elements and bindings (M5), audit and decision events
(M2-12, M2-8).

> **Row-level security is not enabled yet.** The tables above carry `tenant_id` and are
> ready for it, but the policies and the connection wrapper that sets
> `warden.tenant_id` arrive with task M0-6. Until then, tenant scoping rests on
> application-level filtering alone. Do not deploy this schema.

## Naming

Two tables carry a trailing underscore — `group_`, and later `grant_` — because GROUP
and GRANT are reserved words. `app_user` is spelled out for the same reason. Quoting
`"user"` at every call site is worse than a prefix.
