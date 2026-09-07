# Contributing to Warden

Thank you for considering it. This document covers the practical things: how to get a
working checkout, what the review bar is, and how contributions are licensed.

## Sign-off: we use the DCO, not a CLA

Every commit must carry a `Signed-off-by` line certifying the
[Developer Certificate of Origin](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it for you.

**Why the DCO.** A CLA asks contributors to grant rights to a legal entity, which
means there has to be one and that it is trusted to hold them. Warden is an
Apache-2.0 project without a corporate owner (see
[ADR-0003](docs/adr/0003-project-shape-and-license.md)); a DCO gets the same
assurance that you have the right to submit your work, without asking you to sign
anything or asking us to become someone's counterparty. Apache-2.0's §5 already
covers the inbound licence grant.

Contributions are licensed under [Apache-2.0](LICENSE), the same terms as the
project. You keep the copyright in your work.

## Getting set up

You need three toolchains. Warden is a Go server with a Python SDK and a
TypeScript console and browser SDK, so this is unavoidable — but you only need the
one your change touches.

| Tool | Version | Needed for |
| --- | --- | --- |
| Go | 1.23+ (pinned: see `.tool-versions`) | the server, the CLI, the conformance runner |
| Node | 20+ | the console and the browser/React SDKs |
| Python | 3.10+ | the Python SDK |
| Docker | any recent | Postgres, Redis and Mailpit for integration tests |

With [asdf](https://asdf-vm.com) or [mise](https://mise.jdx.dev), `.tool-versions`
pins Go and Node. macOS ships Python 3.9, which is too old; the Makefile looks for a
3.10+ interpreter rather than assuming `python3` is new enough.

```bash
git clone <repo> && cd warden
make build test lint      # should be green on a clean clone
make dev                  # the whole stack, seeded and serving on :8080
make dev-logs-seed        # the owner's one-time setup URL and the demo app's token
```

`make dev` brings up Postgres, Redis and Mailpit, migrates, publishes
`examples/warden.yaml` and seeds SPEC §9.9's worked example — the same invoices as
`conformance/cases/001-worked-example.yaml` and the demo application, so the
specification, the corpus and the running server tell one story. Then:

```bash
curl -s localhost:8080/readyz
```

`make help` lists every target. Development tools (golangci-lint, migrate, sqlc,
govulncheck) install themselves into `./bin` at versions pinned in the Makefile, so a
tool upgrade is a reviewable commit rather than a surprise on your machine.

### Running the server from source

Rebuilding an image on every edit is a poor loop, so run the dependencies in containers
and Warden from source. [`deploy/README.md`](deploy/README.md) has the environment it
needs; `warden config` validates it and reports every problem in one pass.

```bash
make dev-setup                           # dependencies, migrations, database roles
export WARDEN_KEK="$(make -s kek)"       # 32 random bytes, base64
warden config -config deploy/warden-server.example.yaml
```

## Where things live

The layout and what each milestone delivers are in
[`docs/tasks.md`](docs/tasks.md). The specification is [`SPEC.md`](SPEC.md), and it is
authoritative: if the code and the spec disagree, that is a bug in one of them, and
the pull request should say which.

## The review bar

Warden is infrastructure that other people's security depends on. Concretely:

1. **A change to authorization semantics needs a conformance case.** The corpus in
   `conformance/` is the language-neutral definition of what Warden decides, and it
   is executed against the server *and* every SDK. A behaviour change that is not
   expressed there will drift between implementations. This is the single most
   important test asset in the project (SPEC §21).

2. **Never silently allow.** A missing configuration is a startup error. An
   unresolvable attribute is a deny. An unreachable PDP is a deny unless the
   application opted into another `fail_mode`. If your change adds a path where
   something ambiguous resolves toward "allowed", it needs a very good argument.

3. **Secrets do not travel.** Credentials, keys and tokens must not reach a log, an
   error message, an audit record or a decision explanation. Use
   `internal/secrets.Secret`, which redacts through every formatting, serialization
   and logging path — there are tests asserting exactly that, and they are worth
   extending rather than working around.

4. **Multi-tenant isolation is tested, not assumed.** Anything touching tenant-scoped
   data needs a case proving a foreign `tenant_id` cannot reach it.

5. **Tests describe behaviour, not implementation.** A test name should say what must
   be true. If a test would still pass with the security control removed, it is not
   testing the control.

6. **Explain the why.** A comment should say why the code is the way it is, especially
   where the safe choice is the surprising one. Most of the constraints in this
   codebase trace back to a numbered section of the spec — cite it.

## Pull requests

- Branch from `main`. Keep the change focused; a refactor and a behaviour change in
  one pull request are hard to review and harder to revert.
- `make ci` must pass locally before you push — it runs exactly what CI runs.
- Write the commit message for someone reading `git log` in two years. What changed,
  and why it needed to.
- New dependencies deserve a sentence of justification in the description. The server
  is meant to ship as one static binary; every dependency is attack surface that
  self-hosters inherit.
- Security-relevant changes should say so explicitly, and say what an attacker could
  do before the change that they cannot after it.

If you are planning something large, open an issue first. It is much cheaper to
disagree about an approach in an issue than in a finished branch.

## Reporting a vulnerability

Not here — see [SECURITY.md](SECURITY.md). Please do not open a public issue for a
suspected vulnerability.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
