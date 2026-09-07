# Warden

**Identity and fine-grained authorization for multiple applications.**

Warden is an identity provider *and* a centralized authorization service. It does what an
identity server does — authenticate users via local credentials, OIDC or SAML, and issue
standard tokens — and then goes further: it owns the **RBAC model of every application you
run**, answers authorization questions at runtime, and drives which UI elements a user is
allowed to see.

Teams integrate through two SDK families:

- **Backend SDKs** (Python first, then Node.js and Go) — validate tokens, ask for
  authorization decisions, protect routes and service methods.
- **Frontend SDK** (React first) — wrap any component, bind it to a permission that is
  configured *server-side*, and let administrators decide at runtime who sees it.

## Status

Pre-implementation, entering M0. The authoritative document is [`SPEC.md`](./SPEC.md).

Decided: the server is **Go** ([ADR-0001](./docs/adr/0001-server-language.md)) and the
project is **open source** ([ADR-0003](./docs/adr/0003-project-shape-and-license.md)).
Work is broken down in [`docs/tasks.md`](./docs/tasks.md).

## Documents

| Document | Contents |
| --- | --- |
| [SPEC.md](./SPEC.md) | Full product and technical specification |
| [docs/data-model.md](./docs/data-model.md) | Entities, relational schema, migrations |
| [docs/api.md](./docs/api.md) | HTTP API reference (auth, authz, management) |
| [docs/sdk-backend-python.md](./docs/sdk-backend-python.md) | Python SDK design |
| [docs/sdk-frontend-react.md](./docs/sdk-frontend-react.md) | React SDK and UI element binding |
| [docs/tasks.md](./docs/tasks.md) | Milestone task breakdown with exit conditions |
| [docs/threat-model.md](./docs/threat-model.md) | Threats, what mitigates each, and what does not yet |
| [docs/design-email.md](./docs/design-email.md) | Email delivery: providers, templates, bounces, enumeration |
| [docs/adr/](./docs/adr/) | Architecture decision records |

## Try it

```bash
git clone <repo> && cd warden
make dev                  # the whole stack, seeded and serving on :8080
make dev-logs-seed        # the one-time owner setup URL and a demo API token
```

About twenty seconds to a running server carrying [SPEC §9.9](./SPEC.md)'s worked
example: two users, three invoices, and grants that differ by scope and by a condition
on the invoice amount. Ask it something:

```bash
curl -s localhost:8080/v1/authz/check -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "subject":  {"id": "usr_maria_acme"},
    "permission": "billing.invoice:approve",
    "resource": {"type": "billing.invoice", "id": "4712"},
    "context":  {"amr": ["pwd", "otp"]},
    "environment": "dev"}'
# {"allowed":false,"reason":"condition_failed", ...}   — 90 000 is over her limit
```

No credential is created anywhere in that: the first owner's password does not exist
until someone opens the one-time setup URL, and `warden seed` refuses to run in
production. See [deploy/README.md](./deploy/README.md).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). `make build test lint` should be green on a
clean clone; `make help` lists every target. Vulnerabilities go to
[SECURITY.md](./SECURITY.md), never to a public issue.

## License

[Apache-2.0](./LICENSE). See
[ADR-0003](./docs/adr/0003-project-shape-and-license.md) for why, and note that the
name "Warden" is still a placeholder pending trademark clearance (SPEC §23 Q9).
