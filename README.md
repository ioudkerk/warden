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

Pre-implementation. The authoritative document is [`SPEC.md`](./SPEC.md).

## Documents

| Document | Contents |
| --- | --- |
| [SPEC.md](./SPEC.md) | Full product and technical specification |
| [docs/data-model.md](./docs/data-model.md) | Entities, relational schema, migrations |
| [docs/api.md](./docs/api.md) | HTTP API reference (auth, authz, management) |
| [docs/sdk-backend-python.md](./docs/sdk-backend-python.md) | Python SDK design |
| [docs/sdk-frontend-react.md](./docs/sdk-frontend-react.md) | React SDK and UI element binding |
| [docs/adr/](./docs/adr/) | Architecture decision records |

## License

TBD.
