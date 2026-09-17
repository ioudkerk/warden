# Warden — Task breakdown

**Derived from:** [`../SPEC.md`](../SPEC.md) §22 roadmap.
**Decided:** server is Go ([ADR-0001](adr/0001-server-language.md)); project is open source
([ADR-0003](adr/0003-project-shape-and-license.md)).

The roadmap in SPEC §22 gives milestones and week ranges. This document turns M0–M3 into
tasks a person can pick up, and keeps M4–M8 at story grain until the milestone before them
lands. Each task states its **exit condition** — the thing that must be demonstrably true,
not "the code is written".

Conventions used below:
- **[B]** blocks the rest of its milestone. Do these first.
- **[P]** parallelisable with its siblings.
- A task with no dependency listed depends only on M0 being complete.

---

## Repository layout (settled at M0-1, everything else assumes it)

```
cmd/warden/              # single binary, --role={auth,pdp,mgmt,worker,all}
internal/
  config/                # env + file config, validation, no silent defaults for secrets
  secrets/               # Secret type, KEK resolution, AES-256-GCM envelope encryption
  store/                 # postgres access, sqlc-generated queries, RLS session handling
    schema.sql           # committed pg_dump of the migrated schema; CI diffs it
    migrations/          # golang-migrate, forward-only, expand/contract
  tenant/  user/  group/ # domain packages
  authn/                 # local credentials, TOTP, WebAuthn, sessions
  oidcop/                # Warden as OpenID Provider (fosite)
  federation/            # Warden as OIDC RP and SAML SP
  authz/                 # THE PDP: resolver, closure, scope match, CEL, explain
  uibind/                # UI elements, bindings, bundle assembly
  mgmtapi/  authzapi/    # HTTP surfaces
  audit/                 # hash-chained admin log + decision sink
  events/                # change stream, revision counter, Redis fan-out
conformance/             # language-neutral YAML corpus + Go runner  ← written before the PDP
  reference/             # a plain transcription of §10.2, so the corpus has a second
                         # implementation to disagree with. NOT the PDP.
sdk/python/              # warden-sdk
sdk/js/                  # @warden/browser, @warden/react
console/                 # React SPA (Vite)
testing/                 # mock OIDC OP, mock SAML IdP, hostile SAML fixture corpus
bench/                   # k6 scenarios + regression gates
deploy/                  # docker-compose, Helm chart
```

---

## M0 — Foundations (SPEC §22 M0)

**Milestone exit:** `docker compose up` yields a running `warden --role=all` that passes
`/readyz`, a bootstrapped system tenant with no default credentials, and a conformance runner
that executes the corpus in CI.

> **Corrected during M0.** This line originally asked for the corpus to run "across three
> toolchains", and it was wrong twice over. No task in M0 was ever written to deliver it —
> M0-8's own exit stops at Go and hands the Python runner to **M3-4** by name — so the
> milestone line, not the task, was the one out of date. And three is not the right number:
> only Go and Python ever evaluate policy. `@warden/browser` fetches a bundle and asks the
> server (SPEC §13, [`sdk-frontend-react.md`](sdk-frontend-react.md)), so there is no JS
> evaluator for a corpus to run against, and no such task exists anywhere in M0–M8. Node is
> in CI for the console and the browser SDK.
>
> What M0 does deliver is the harder half of the claim: two *independent* implementations
> checked against each other on every case — the PDP and the plain transcription of §10.2 in
> `conformance/reference/`. What is still unproven is that the format is portable across
> languages, and M3-4 is where that gets tested. It sits on the critical path for this
> reason, and should be taken early in M3 rather than mid-milestone: the moment to discover
> that the YAML has a Go-shaped assumption in it is while the format is still cheap to
> change.

### M0-1 [B] Repository scaffolding and toolchains
**Status: done.**
Go module at 1.23, the layout above, `Makefile` / `Taskfile` targets (`build test lint
migrate up down`), `golangci-lint` config, `.editorconfig`, Node and Python workspace stubs.
**Exit:** `make build test lint` is green on a clean clone with only Go, Node and Python 3.10+ installed.

### M0-2 [B] CI pipeline
**Status: done.**
GitHub Actions: Go build/test/lint/race, Python and Node stubs, Postgres + Redis services,
migration up/down round-trip, `govulncheck` + `pip-audit` + `npm audit`, SBOM generation and
release signing in skeleton form (per ADR-0003 consequence 2).
**Exit:** a PR with a deliberate race, a deliberate lint error, and an irreversible migration
each fail CI for the right reason.

### M0-3 [B] Open-source project files
**Status: done.**
`LICENSE` (Apache-2.0 pending ratification — ADR-0003 item 3), `SECURITY.md` with a
disclosure address and response SLA, `CONTRIBUTING.md` (three toolchains, DCO decision),
`CODE_OF_CONDUCT.md`, issue/PR templates, `README` status update.
**Exit:** files present; the DCO-vs-CLA question has an answer recorded in `CONTRIBUTING.md`.
**Note:** trademark clearance on the name "Warden" (§23 Q9) must land before the repo is
made public. Track it here; it does not block private development.

### M0-4 [B] Configuration and secrets
**Status: done.**
Precedence file → env → flags; typed config struct with validation at startup; envelope
encryption (AES-256-GCM) with a KEK from env / file / KMS per §17; **a missing or malformed
secret is a startup error, never a default** (§12.5 applied to the server too).
**Exit:** starting with a missing KEK exits non-zero with an actionable message; a unit test
asserts no config field silently defaults to an insecure value.

### M0-5 Migrations and the core schema
**Status: done.** Verified against Postgres 15.19 and 16.15.
`golang-migrate`, forward-only, expand/contract. Tables from
[`data-model.md`](data-model.md): `tenant`, `user`, `credential`, `identity`, `session`,
`refresh_token`, `group`, `group_member`, `application`, `app_enrollment`, `resource_type`,
`action`, `permission`. Depends on M0-4.
**Exit:** up and down migrate cleanly against Postgres 15 and 16; schema dump is committed
and diffed in CI.

### M0-6 Row-level security harness
**Status: done.** 19 tests; the table list is discovered from `pg_class` and cross-checked against a registry in the schema.
RLS policies (`tenant_id = current_setting('warden.tenant_id')`) plus the connection wrapper
that sets the GUC per transaction, and the escape hatch for system-tenant queries.
**Exit:** a test that opens a connection with tenant A's GUC and runs `SELECT *` on every
tenant-scoped table returns zero of tenant B's rows — table list generated from the schema so
new tables cannot be forgotten.

### M0-7 Store layer and query generation
**Status: done.**
`sqlc` wiring, connection pooling, transaction helper, retry classification for
serialization failures.

Every query in the server is now generated from [`internal/store/queries`](../internal/store/queries)
into `internal/store/db` — 57 of them, across the model loader, provisioning, the HTTP
surface, the audit log and the signing keys. One deliberate exception remains and is
documented where it lives: `store.describeRole` reads the PostgreSQL catalog rather
than Warden's schema, and sqlc's catalog is built from the migrations, so generating it
would mean pointing code generation at a live database and breaking M0-1's promise that
a clean clone needs only Go, Node and Python.

Two type mappings are load-bearing and worth knowing about before editing
[`sqlc.yaml`](../sqlc.yaml): `jsonb` becomes `dbtypes.JSONMap`, a named map type that
stays assignable from a plain `map[string]any`; and `audit_event.before/after` are
`json`, not `jsonb`, so they generate as `[]byte` and the hash chain still verifies over
the exact bytes written.

[`retry.go`](../internal/store/retry.go) classifies the two SQLSTATEs PostgreSQL defines
as transient — `40001` serialization failure and `40P01` deadlock — and reissues those
transactions with jittered backoff, three attempts by default. Nothing else is retried:
a unique violation reissued three times is three identical failures and a bug that took
three times as long to find.

Two things worth knowing before using it. `InTenant`/`InSystem` take variadic
`TxOption`s, so `store.Isolation(pgx.Serializable)` is available for the code that will
need it — **M1-5**'s refresh-token reuse detection is the case the option exists for, and
it is safe to ask for precisely because the retry loop is now underneath it. And a retry
re-runs the whole callback, so anything a callback does *outside* the database must not
be there; the convention is that such values are produced before the transaction opens,
which is why a retried `CreateServiceAccount` does not mint a second token.

Retries are counted in `warden_store_transaction_retries_total{code}` and, when the
budget runs out, `warden_store_transaction_retries_exhausted_total{code}`. Without those
a retry is invisible — the transaction succeeds and the caller never knows — so rising
lock contention would show up only as latency nobody can explain.

**Exit:** met. `make sqlc-check` regenerates and fails on a diff, wired into `make lint`
and called out as its own CI step. `TestDeadlockIsRetried` provokes a real lock cycle
between two transactions and asserts both commit; it fails loudly if the ordering stops
deadlocking, so it cannot quietly decay into a test that proves nothing.

### M0-8 [B] Conformance corpus format and runner ★
**Status: done.** 10 cases, 87 checks, validated by a reference evaluator (`conformance/reference`).
**The highest-leverage task in M0.** SPEC §21 names this the single most important test asset
and no schema for it exists yet. Define the YAML case format —
`(model, assignments, check, expected)` including scopes, conditions, denials and expected
`reason` codes — write the Go runner, and seed the corpus with SPEC §9.9's worked example.
Depends on M0-1.
**Exit:** `go test ./conformance/...` executes the §9.9 fixture end to end and fails loudly if
a case's expected `reason` changes. The format is documented in `conformance/README.md` well
enough that the Python SDK can implement a runner against it without asking questions.

### M0-9 Bootstrap (`warden init`)
**Status: done.**
Creates the system tenant, generates the signing keypair with a `kid`, creates the first
owner, prints a one-time setup URL. **No default credentials, ever** (§20.2).
**Exit:** a fresh database plus `warden init` yields exactly one usable one-time URL; running
it twice is refused; grep of the codebase finds no hardcoded credential.

### M0-10 [P] Health, metrics, structured logging
**Status: done.**
`/healthz`, `/readyz` (checks Postgres and Redis), `/metrics`, structured JSON logs with a
request id, OpenTelemetry tracer setup.
**Exit:** `/readyz` returns 503 with a named failing dependency when Postgres is stopped.

### M0-11 [P] Local development environment
**Status: done.**
`docker-compose.yml` with Postgres, Redis, Mailpit and Warden; a seed command producing a
demo tenant and the `billing` app from `examples/warden.yaml`.

`make dev` (or plain `docker compose up`) brings up the dependencies, migrates with the
same pinned golang-migrate the Makefile and CI use, runs `warden seed`, and serves. The
image is multi-stage, built at the ADR-0001 Go floor — so the floor is a claim something
exercises rather than only a line in `go.mod` — and ships distroless and non-root.

`warden seed` publishes the manifest and creates SPEC §9.9's worked example: tenant
`acme`, Maria with an approval limit and Bob without one, the three invoices, and grants
that differ by scope and by condition. It is the same fixture as
`conformance/cases/001-worked-example.yaml` and `examples/demo-app`, on purpose — the
specification, the corpus and the running server should tell one story. UI bindings are
derived from each element's `suggests` rather than listed in the seed, so an element
added to the manifest is seeded without anyone remembering to.

Two properties it holds rather than merely documents:

- **No credential is created anywhere.** The KEK is generated once into a named volume
  (never regenerated — a new one cannot open the signing key the last one sealed), and
  the first owner's password does not exist until someone opens the one-time setup URL
  that seeding prints into the log. Same guarantee as M0-9, not a development-only path
  around it.
- **Seeding is refused in production**, and both ways of getting the environment wrong
  fail closed. `cmd/warden/seed_test.go` covers this; it also asserts the refusal happens
  before the store is opened, so the check cannot drift below the connection.

**Exit:** met. From no image, no build cache and no volumes, `make dev` reaches a seeded
server answering `/readyz` in about 20 seconds on a warm machine — the two-minute budget
assumed a slower path. Re-running is safe: the manifest is reapplied, the tenant left
alone, the KEK untouched.

### M0-12 [P] Missing design artifacts named by the spec but not yet written
**Status: done.**
- `docs/threat-model.md` — required by §17 as a release gate, referenced but absent.
- `docs/design-email.md` — M1 needs verification, magic links, invitations and resets;
  provider abstraction (SMTP + pluggable), templating, i18n hooks, bounce handling and
  rate limits are unspecified.
- Resolve the cross-tenant **`person`** linkage (§6.2, marked *(open)*): today `user` is
  unique on `(tenant_id, email)` and no `person` table exists. Decide whether v1 has the
  table at all, and record it as ADR-0004.
**Exit:** three documents merged; §6.2's *(open)* marker removed or narrowed. — Done:
[`docs/threat-model.md`](threat-model.md), [`docs/design-email.md`](design-email.md),
[ADR-0004](adr/0004-cross-tenant-person.md); §6.2's marker is resolved.

---

## M1 — Identity (SPEC §22 M1)

**Milestone exit:** an application logs a user in and out using a stock off-the-shelf OIDC
library, with no Warden-specific client code.

| # | Task | Exit condition |
| --- | --- | --- |
| M1-1 [B] | **Status: done.** Signing key management: generation, `kid` rotation on a schedule, JWKS with current + previous | Met. `TestRotationKeepsPreviousTokensVerifiableForTheOverlapWindow` signs, rotates, and verifies the pre-rotation token against published JWKS across the window, then asserts it stops verifying after it |
| M1-2 [B] | **Status: done.** Local credentials: Argon2id (`m=64MiB,t=3,p=2`), rehash on parameter change, per-tenant password policy, breached-password k-anonymity dataset | Met. `TestUnknownUserAndWrongPasswordTakeTheSameTime` measures both paths against the cost of one Argon2id hash; they differ by under 1% of it, and the test fails loudly if either path skips the hash |
| M1-3 | **Core done; the sweep waits on M1-9.** Lockout and rate limiting: exponential backoff per (account, IP), global per-account cap, 429 + `Retry-After` | **Done:** `authn.Lockout` — both counters, the doubling backoff, the cap, shared across replicas through the cache tier, with the enumeration property tested (an unknown address is limited identically to a real one); `429` + `Retry-After` on the login endpoint, and on the device verification page, which is where RFC 8628 §5.1 requires it. **Remaining:** the enumeration sweep across login, reset and invite — reset and invite arrive in M1-9, so it cannot be complete before then |
| M1-4 | **Status: done.** Sessions in Redis with a Postgres mirror; `sid`; revoke one / revoke all | Met, by a factor of 600. `TestRevokeAllPropagatesToAnotherReplicaWithinOneSecond` revokes on one replica and polls an independent one: visible in **1.65 ms** against the 1 s budget |
| M1-5 | **Status: done.** Refresh tokens: opaque 256-bit, hashed, rotating, **reuse detection revokes the family** and raises a security event | Met. `TestReplayingARotatedTokenKillsTheFamily` builds a chain three deep, replays the first token, and asserts all three are dead, the session is ended, and exactly one `security.refresh_token_reuse` is written with the family, session and token count on it |
| M1-6 [B] | **Status: done.** OIDC OP endpoints via fosite: authorize (PKCE required for public clients), token, userinfo, JWKS, introspect, revoke, logout, PAR, device | Met, in four commits. Every endpoint is served and every one is exercised end to end through HTTP: the authorization code flow with PKCE, the token endpoint, userinfo, introspection, revocation, RP-initiated logout, pushed authorization requests, and the device grant — which is hand-written, because fosite v0.49 implements no part of RFC 8628. The conformance checks pass, and implicit and ROPC are absent at all four surfaces: no factory composes them, no client row can name them, the discovery document does not offer them, and both endpoints refuse them |
| M1-7 | **Status: done.** Access-token claim assembly per §8.2 including `wd.perm_rev`, with the **4 KB cap** dropping `wd.groups` then `wd.attrs` and setting `wd.truncated` | Met, and §8.2 amended: the authorization facts are now a per-client grant, empty by default, because Warden is the decision point and a role list in a JWT is that decision made stale and unrevocable. `TestAUserWithFiveThousandGroupsGetsAUsableToken` builds five thousand memberships and, for a client that opted in, gets a **645-byte** token that verifies against published JWKS and says `wd.truncated`. For the default client the same five thousand memberships produce **586 bytes** with nothing dropped and no membership walk at all |
| M1-8 | **In progress (TOTP and recovery codes done; WebAuthn next).** TOTP, recovery codes, WebAuthn as second factor | Enrolment and step-up flows work end to end: a password alone now reaches `/login/verify` and authorizes nothing, and `amr` comes back `["pwd","otp","mfa"]`. A recovery code signs in and ends every other session and refresh token (§7.2). Verified against the deployment with an independently written TOTP client, which is what proves the implementation interoperates rather than merely agreeing with itself |
| M1-9 | Magic link and email delivery, per the M0-12 email design | Links are single-use, 15-minute, hashed at rest |
| M1-10 | User lifecycle `invited → active → suspended → deprovisioned → deleted` | Suspension kills sessions and refresh tokens immediately |

### Notes from M1-6, part 1: the client registry

M1-6 is four commits, not one. This is the first: the client registry everything else
needs.

**"Absent, not disabled" is a schema constraint.** The exit condition asks for the
implicit and resource-owner-password grants to be absent rather than switched off, and a
constant somebody could change does not meet that bar. `oauth_client_no_forbidden_grants`
and `oauth_client_no_forbidden_response_types` make a client that asks for them
*unrepresentable*: no console, no migration and no future handler can enable one, because
the row will not store. The registry refuses them earlier with a message that explains
why; the constraint is what makes it true. Six more constraints encode the rest — a public
client may not hold a secret, may not opt out of PKCE, and a client doing the code flow
must have somewhere to send the code.

**Client ids are generated, not chosen.** The token endpoint receives a `client_id` and
nothing else, so ids must be unique across the deployment before any tenant scope exists —
two tenants each naming a client `billing-web` would be indistinguishable at exactly the
moment it matters. Opaque ids also stop an authorize URL leaking a customer's name. The
chosen handle lives in `key`, unique per tenant, and never appears in a protocol message.

**`oauth_client` is not `application`.** They are different concepts wearing similar
names: an application declares a permission surface and is global with per-tenant
enrollment; a client performs a login and receives tokens. One application may have
several clients.

**Redirect URIs are validated at registration**, not only at request time. The comparison
at request time is string equality (SPEC §17), so a registered wildcard would simply never
match — a silent failure discovered during a login. Wildcards, fragments, schemeless and
non-loopback `http` are refused with the reason. Loopback `http` is allowed, per
RFC 8252 §8.3.

**`authn.DecoyHash` is now shared, and its caching is a security property.** The token
endpoint must not answer faster for an unknown `client_id` than for a real one, so an
unknown client is verified against a decoy exactly as an unknown user is. Generating a
fresh decoy per call would hash twice — once to build it, once to verify — making the miss
reliably *slower* than the hit and just as good an oracle. It is cached per parameter set.

**Dependency cost, measured.** fosite v0.49.0 takes the module count from 44 to 87 and the
binary from 41 MB to 44 MB. The extra modules arrive through one import chain:

```
internal/oidcop → ory/fosite → ory/x/otelx → ory/x/logrusx → gobuffalo/pop/v6/logging
```

Module *presence* is a poor measure of what that costs, and an early draft of this note
used it and was wrong as a result — it claimed a full ORM was being linked. What is
actually compiled in from each module:

| module | linked packages | source lines |
| --- | --- | --- |
| `gobuffalo/pop` | 1 | 27 — an integer enum and its `String()`, nothing more |
| `zipkin-go` | 1 | 670 |
| `sirupsen/logrus` | 1 | 4,890 |
| `dgraph-io/ristretto` | 3 | 8,520 |
| `ory/x` | 4 | 2,301 |
| `pkg/errors` | 1 | 1,785 |

So the real additions worth knowing about are `logrus` and `ristretto`, about 13k lines
between them, reached through Ory's logging and tracing helpers. `gobuffalo/pop` is a
27-line constants file that `ory/x/logrusx` imports to satisfy pop's logger-level type; no
ORM, no drivers, no SQL, and no further dependencies.

Accepted, because SPEC §19 and this task both name fosite, because the measured cost is
modest, and because `govulncheck` does reachability analysis so unreachable code in those
modules should not become a triage queue. What remains true regardless: the **SBOM required
by SPEC §17 lists modules, not reachable packages**, so all 43 will appear there. That
should not be a surprise at release time, and the table above is what to answer with.

Every fosite release from v0.45 onward carries this chain; only v0.44.0 (2023) is clean,
which is not a sensible pin for a security component.

### Notes from M1-3 (core)

**Two counters, because they answer different attacks.** The (account, IP) counter slows
somebody guessing one account from one place and costs them doubling time; the per-account
counter is the backstop against a distributed attempt, where each source looks innocent
and only the account sees the volume. The account cap is deliberately generous and expires
by itself, because it is also the lever for locking a real person out on purpose.

**It counts what was presented, not what exists.** An attempt against an address with no
account increments exactly as one against a real user. Anything else is an enumeration
oracle — an attacker who is *never* rate-limited has learned the address is unknown — and
it would have undone M1-2's timing work at the layer above it.
`TestAnUnknownAddressIsLimitedIdentically` is the guard.

**Counters live in the cache tier, not in the process.** A per-process counter multiplies
the effective limit by the replica count, which is the quietest possible way to not have
rate limiting. `TestTheCounterIsSharedAcrossReplicas` alternates failures between two
limiters over one cache and asserts they add up. The pepper that keys the identifier hash
must be derived from the KEK for the same reason: a per-process pepper gives each replica
its own key space.

**Identifiers are HMAC'd into cache keys.** The addresses people fail to log in as are
worth as much to an attacker as a user list, and HMAC rather than a bare hash means
someone holding the cache cannot confirm a guessed address by hashing it themselves.

**An off-by-one the test caught.** `FreeAttempts: 3` granted four free attempts: the delay
was computed from failures *past* the allowance rather than *at* it, so the third failure —
the one that should impose the first delay — imposed none. Reverting the `+1` still fails
`TestTheFirstFewFailuresCostNothing`.

**`cache.Increment` is atomic, and that is the point.** Two simultaneous wrong passwords
that both read 3 and both write 4 have counted one attempt, so an attacker with any
concurrency raises the effective limit by it. Redis does INCR and EXPIRE in one pipeline;
the in-process backend holds its mutex across the read and the write.

### Notes from M1-8: the second factor

**TOTP is written here rather than imported, and WebAuthn will not be.** The whole of
RFC 6238 is an HMAC, a counter and a truncation — sixty lines — and the RFC publishes test
vectors that prove an implementation correct. A dependency for that is a supply-chain
surface and a transitive tree to audit in exchange for less code than would configure it.
`TestTOTPMatchesRFC6238` and `TestHOTPMatchesRFC4226` run the published tables; breaking the
truncation offset by one bit fails both. WebAuthn is the opposite case — CBOR, COSE and
attestation formats — and gets a library.

**A password is no longer a login.** Between the two steps there is a *pending* record: a
short-lived entry in the cache under a random identifier, with the browser holding the
identifier. Deliberately not a session, because a half-authenticated session is the thing
another piece of code eventually mistakes for a real one; and deliberately not a signed
cookie, because a signed cookie cannot be withdrawn. The test that matters is not that the
code is checked — it is that the cookies left after the password step authorize *nothing*.
Removing the step-up makes that test fail on the redirect, not on the code.

**An enrolment is not a factor until it is proved.** Somebody who opens the page, scans the
QR code and closes the tab has changed nothing: the secret is stored, the account is not
protected by it, and only a correct code from the device turns it on. The alternative locks
people out of their own accounts on a mis-click. For the same reason, requiring a factor for
an account that has none is refused where it is set rather than discovered at the next
login.

**A code is spent when it is used.** RFC 6238 §5.2 requires it and the reason is concrete:
a code lives thirty seconds, so anybody who watched it typed has the rest of that window
unless the first use consumes the counter. The spent counter goes in the credential's
params. It cost a test-fixture change to notice — confirming an enrolment and signing in a
second later was correctly refused, because the confirmation had already spent that code.

**A recovery code is a password-equivalent credential.** Shown once, hashed at rest — SHA-256,
because there is nothing for Argon2id to stretch in 160 random bits, which is the same
reasoning service-account tokens follow — single use, and looked up by hash so a wrong guess
costs one indexed read rather than ten comparisons. Using one ends every session and every
refresh token, as §7.2 requires, and that lives in `afterRecovery` rather than in the caller:
a caller that forgets loses the property silently. `RefreshTokens.RevokeAllForUser` reaches
the tokens through sessions rather than through `refresh_token.subject`, because that column
arrived with M1-6 and filtering on it would miss every token M1-5 issues.

**The race worth testing.** A redeemed recovery code revokes everything and then creates the
session it just authenticated. The revocation marker and the new session are written moments
apart, and a session whose auth time does not beat the marker would be dead on arrival —
so the test signs in with a recovery code and then *uses* the resulting session.

**Still to come in M1-8:** WebAuthn as a second factor.

### Notes from M1-7, revisited: the token says who you are, not what you may do

The first cut of M1-7 implemented SPEC §8.2 as written: `wd.roles`, `wd.groups` and
`wd.attrs` in every access token. Reviewing it against the rest of the product, §8.2 was
the odd one out, and the spec has been changed rather than the code left to contradict it.

**The argument.** Warden is the policy decision point: "may this person do this?" is
answered at `/v1/authz/check`, against a model an administrator can edit, with the answer in
the decision log and revocable the moment the model changes. A role list inside a JWT is the
same question answered once, up to fifteen minutes before anybody reads it, where no
revocation reaches it and no audit records that it was used. That is how an identity server
that is *not* a PDP works — the application decides — and it is a different product.

The rest of the spec already had better answers for every case §8.2's claims were meant to
serve. §10.4's decision bundle is the sanctioned way to evaluate locally: signed, with a
TTL and change-stream invalidation. §11's UI bundle is how a front end hides a button, and
it is what makes the element-to-permission binding editable by an administrator instead of
compiled into the app. `wd.roles` was a third channel, redundant with both and revocable
like neither. Warden itself never read it: the decision API authenticates service accounts
with `wsk_` tokens, so those claims were only ever for somebody else to authorize on.

**So the default is inverted.** A token carries identity, the protocol claims, the
authentication context, and `wd.perm_rev` — which stays because it is what lets a reader
notice that its cached model is older than the token in its hand. The authorization facts
are a per-client grant (`token_claims`, `token_attributes`), empty by default, for the one
case that needs them: a third-party resource server that speaks JWT and will never call the
decision API.

**What it costs and what it saves.** With nothing granted, claim assembly is one query — the
subject's status and the tenant revision, both needed regardless — and the two recursive
membership walks never run. A user with five thousand group memberships gets the same
586-byte token as a user with none, and the 4 KB cap becomes something most deployments
never meet. It is still there, still tested, and still fires for a client that opted in:
five thousand groups with `token_claims: [roles, groups]` comes out at 645 bytes with
`wd.truncated` set.

**The closed vocabulary is deliberate.** `token_claims` is constrained to `roles` and
`groups` by a check constraint, so a typo is a failed write rather than a claim that
silently never appears — the same reasoning as the forbidden-grants constraint in M1-6.

### Notes from M1-7: the access token

**The access token was opaque and §8.2 says it is a JWT.** That is the whole change, and
it changes who trusts whom: a resource server verifies a signature instead of asking
Warden. The authorization code and the refresh token stay opaque — they are redeemed here
and nobody else needs to read them — so fosite is composed with its JWT strategy for access
tokens wrapping the HMAC strategy for everything else.

**Claims are assembled at issuance, not when the session is created.** A session lasts
thirty days and a token ten minutes. Freezing the claims with the session would mean a
refresh a week later described the roles the user had when they signed in — while
`wd.perm_rev` said the token was current, which is worse than saying nothing. The seam is
`GenerateAccessToken`, the only place with a context, the request and the moment of
issuance at once. `TestARefreshedTokenDescribesTheUserNow` grants a role after the session
begins and asserts the refreshed token knows about it.

**The cap is enforced by measuring the token, not by estimating it.** SPEC §8.2 caps the
*token* at 4 KB, and between the claims and the token lie base64, a header and a signature
whose length depends on the algorithm. So the issuer generates, measures, and gives
something up if it does not fit: groups first, then attributes, then a refusal. The extra
signature is paid only by the tokens that need one — a user with three groups signs once, a
user with five thousand signs twice. Five thousand groups came out at 645 bytes in the
fixture and 1163 against the deployment.

**Roles and `perm_rev` are never dropped.** Roles are what is left when everything else
goes, and without `perm_rev` an SDK cannot tell that its cached model predates the token —
which is the one thing that makes local evaluation safe at all. When even those do not fit,
the request is refused rather than answered with an oversized or a silently empty token. It
takes roughly two hundred roles on one user to reach that.

**`wd.attrs` is an allowlist on the client, and the specification says application.** The
deviation is deliberate and recorded: an access token is issued to a *client*, a client
need not correspond to an application at all — migration 000014 says so at length — and
there is no link between the two tables to read an allowlist through. The client is what
receives the token, so its registration decides what the token discloses. Empty by default,
because attributes are arbitrary tenant data and the failure mode of a denylist is that the
next attribute somebody adds is disclosed to every client until it is noticed.

**Suspension is now checked at issuance**, which closes what the security review recorded
as latent. The status check lives in claim assembly rather than at any one endpoint, because
that is the single place every grant passes through on the way to a token — and a JWT
access token cannot be recalled once signed, so "refuse to mint" is the only enforcement
that works. `TestASuspendedUserGetsNoFurtherTokens` suspends a user mid-session and asserts
the refresh is refused.

**One deviation from RFC 9068 that could not be fixed here.** §2.1 asks for `typ: at+jwt`
so an access token cannot be mistaken for an id token. fosite's signer merges header extras
with `assign`, which skips any key already present, and it sets `typ: JWT` itself — so the
value cannot be overridden without replacing the signer. The exposure is bounded: an id
token's `aud` is the client, an access token's is the resource server, and a resource server
that checks `aud` — which it must do anyway — already refuses the other one.

**The assembled claims are deliberately not serialized.** They are rebuilt on every
issuance, so storing them would put a copy of the user's group list in every access-token
row and every refresh-token row, and the copy would be stale the moment the roles changed.

### Security review of M0 and M1-1…M1-6

A review of everything implemented so far, run before starting M1-7. Four defects were
found and fixed; each has a regression test that fails when the fix is reverted.

**One root cause produced the two worst ones: two pieces of code reading the same request
and disagreeing.** Every endpoint that authenticates a client has to answer two questions —
which tenant is this, and which client is this. Warden answered the first at the edge,
because the storage needs a scope before fosite runs. fosite answered the second, from
whichever credential it prefers. Their precedence was opposite: fosite takes HTTP Basic
over the form body, `tenantForClientRequest` took the form body over Basic.

1. **Cross-tenant token issuance through the device grant (critical).** A confidential
   client of tenant B posted Basic credentials for itself and a form `client_id` naming a
   client of tenant A. The device authorization was written into tenant A, where a tenant A
   user was shown "Connect <the rival's name>?", approved it, and the rival collected an id
   token for `sub: usr_maria_acme, tid: ten_acme` — a user who is not its own. Confirmed
   end to end before the fix.

2. **Introspection authorized an identity nobody proved (high).** fosite's introspection
   endpoint takes a bearer token over Basic credentials: when a token is present it
   authenticates *that* and never reads the header. Warden read the header first to decide
   who was asking. So a caller could put a valid token of their own in the body, claim in
   Basic to be a client they are not — with a secret that is simply wrong — and have the
   forged identity decide what they were allowed to see. It disclosed another client's
   token's `sub`, `sid`, `scope`, `exp` and `client_id`.

The fix is in two layers, and the second is the one that matters. The edge now follows
fosite's precedence, which makes the common case right. And `Storage.requireClientInScope`
refuses to write any artifact into a tenant that is not its client's — enforced where the
row is written rather than by keeping two parsers in step for ever. Reverting only the
precedence leaves the device and client-credentials attacks blocked by the storage guard.

3. **Pushed authorization requests were not bound to the authenticating client (medium).**
   This one is fosite's: `NewPushedAuthorizeRequest` authenticates the client and then
   rebuilds the request with `newAuthorizeRequest`, which loads whatever `client_id` the
   body names — overwriting the client that authenticated. Any client holding its own
   credentials could mint `request_uri` values bound to another client, including a
   confidential one whose secret it does not have. RFC 9126 §2 requires the opposite.
   Nothing is stolen by it — the code still goes to the victim client's registered redirect
   URI and still needs that client's secret — but the attacker chooses the parameters of a
   request the victim client will be asked to complete. The endpoint now authenticates the
   client itself and refuses a request naming a different one.

4. **HSTS was missing entirely (medium).** SPEC §17's transport row asks for it and nothing
   set it. Now sent on every response when the issuer is https, and deliberately not when
   it is not: a development deployment that sent HSTS would pin the developer's browser to
   https for localhost across every other project on the machine.

**Two things are recorded as known and not fixed here.** Suspension is not enforced on a
live session or at token issuance — `Sessions.Validate` checks expiry and the revocation
marker but not the user's status, so the plan's revoke-on-transition (M1-10) is the only
thing that will stop a suspended user's existing cookie from minting fresh tokens. It is
not exploitable today, because nothing can suspend a user yet; when M1-10 lands, a status
check at issuance should back the revocation up, so a missed revocation fails closed. And
the audit log is a hash chain with no external anchor: it detects an edit, not a rewrite,
because anybody who can write the table can recompute every hash. Publishing the head
periodically is what closes that, and it belongs with M2-12.

**Checked and found sound**, so that the absence of findings is not mistaken for absence of
review: no dynamic SQL anywhere, every query parameterized through sqlc; the tenant scope
set with `set_config(..., is_local => true)`, itself parameterized; all 39 system-pool call
sites, each either a one-column scope resolution or genuinely deployment-global; constant-
time comparison in the three places that compare a secret; the decoy-hash timing property;
envelope encryption (fresh DEK per value, the version-and-key-id header as additional
authenticated data, caller-supplied AAD binding a ciphertext to its row, deliberately vague
decryption errors, and `KEK.Bytes()` copying so that `newGCM`'s defensive zeroing cannot
destroy the live key); the audit chain's length-prefixed canonical form and its advisory-lock
serialisation; every authenticated endpoint taking the tenant from the caller rather than
from input; and the configuration's production restrictions — https issuer, distinct
database roles, Redis, a 5–15 minute access-token bound, and a key overlap window no shorter
than the token lifetime.

### Notes from M1-6, part 4c: the device grant, and the conformance checks

**fosite implements no part of RFC 8628.** Not a disabled handler — the string
`device_code` does not appear anywhere in v0.49. So the grant is hand-written, and the
one thing worth copying from it is *where* it was written: as a `fosite.TokenEndpointHandler`
plugged into the same pipeline as the others, so it inherits client authentication, the
token strategies and the error rendering rather than reimplementing them. Three error
values had to be defined (`authorization_pending`, `slow_down`, `expired_token`) because
fosite has no reason to carry them; a device's client library switches on exactly those
names to decide whether to keep waiting.

**Two codes, because they are handed to two different parties.** The device code is a
machine credential at full entropy. The user code is typed by a person off a screen, so it
is eight characters from a twenty-letter alphabet with no vowels and none of the pairs
people mistype — about thirty-four bits, which is plenty against a person and nothing
against a script. Both are hashed at rest, and the verification page is rate-limited
through M1-3's limiter, which is what RFC 8628 §5.1 actually requires.

**The code comes before the password, and it has to.** Signing in needs a tenant, and
before a code is typed nothing says which tenant the person belongs to — the deployment is
multi-tenant and an email address is unique only within one. So `/device` resolves the
typed code to its tenant on the system pool, the same shape as resolving a client id or a
refresh token, and *that* is what the login page authenticates against. An unresolvable
code does not fail: it authenticates against a tenant that does not exist, where the
credential check does its usual constant work and answers exactly as a wrong password
does. Otherwise the login form would be an oracle for which user codes exist, and a code
short enough to type is short enough to enumerate.

**Signing out stops a device that was approved and never polled.** The grant re-validates
the approving session on every poll, so an approval is only as alive as the session that
made it. Without it, "sign out everywhere" would quietly mean "everywhere except the
television in the other room" — `TestSigningOutStopsAnApprovedDevice` hands over tokens
when that check is removed.

**The single-use rule needed a test that actually races.** A sequential replay is caught
earlier, by the status the row already carries, so the first version of the test passed
with the `WHERE status = 'approved'` guard removed — it was not testing what it claimed.
Releasing eight polls from a barrier does test it: without the guard, several of them are
issued tokens from one approval.

**The tenant-isolation registry caught the new table on its own.** `TestTenantListIsStable`
failed the moment `device_authorization` existed, and `TestTenantIsolation` failed until it
was seeded — which is exactly the M0-6 machinery working: a new tenant-scoped table cannot
be added without the isolation suite noticing.

**A live run found a device holding a credential it could never use.** A client registered
for the device grant alone asked for `offline_access` and was handed a refresh token —
which fosite's refresh handler then refuses, because the client does not hold the
`refresh_token` grant. Useless, and invisible until somebody built a refresh loop around
it. The grant now applies the same two conditions fosite's authorization code handler
does: the scope *and* the client's registration.

**The conformance checks found a real one.** fosite enforces PKCE inside
`NewAuthorizeResponse`, which runs *after* the login — so an authorization request with no
`code_challenge` sent the user to type a password and only then failed. The authorization
endpoint now applies the policy itself, before the session check, reading both answers
from the configuration fosite enforces so there is no second copy of the rule. What
changed is when the answer is given, not what it is.

The rest of the checks are the ones a certification suite makes: every endpoint the
discovery document advertises exists; the required metadata fields are present and the
issuer matches character for character; JWKS publishes no private key member (`d`, `p`,
`q`, `dp`, `dq`, `qi`, `k`); the id token carries `iss`, `sub`, `aud`, `exp`, `iat`, is not
signed with `alg=none`, echoes the `nonce` and names exactly the client that asked; token
and userinfo responses say `no-store`; an authorization error travels back to the client
with its `state`; and the excluded grants are refused at every surface a client can
observe.

### Notes from M1-6, part 4b: logout and pushed authorization requests

**Pushed authorization requests were stored but could not be used.** fosite deletes the
`request_uri` row *while parsing the authorization request* and, when it finds one,
returns immediately without reading the query string at all — so whatever
`GetPARSession` leaves at its zero value is simply gone. Only the generic `Request`
fields survived the round trip, which meant the redirect URI, the response type and the
state all arrived empty: an authorization request with no response type and nowhere to
send the answer. They are now read back out of the stored form, and the redirect URI is
re-matched against the client's registered list rather than parsed and trusted.
`TestThePushedAuthorizationRequestFlow` redirects to `""` without the fix.

**The login round trip would have burned the one-shot reference.** A pushed request that
arrives with no session used to be resolved by fosite — consuming the row — and only then
sent to the login page, so the browser came back holding a reference to something that no
longer existed. The session check now happens *before* fosite for pushed requests, and
only for those. Nothing is skipped by going early: a pushed request was fully validated
when it was pushed, which is the point of pushing it. The alternative, re-storing the row
with a longer life so a human has time to type a password, would have widened a window
RFC 9126 deliberately keeps at a minute.

**Logging out has to end everything the session issued.** Nothing in fosite's storage
consults a Warden session — a refresh token is valid because its own row says so — so a
logout that only dropped the cookie would leave a thirty-day credential working, and the
client holding it could sign the user straight back in. `Storage.EndSession` revokes the
refresh tokens, deletes the session's `oauth_session` rows and then revokes the session,
in that order: the longest-lived credential dies first, so a failure halfway leaves the
user signed in with dead tokens rather than signed out with a live one. Removing either
half fails `TestLogoutEndsEverythingTheSessionIssued` on a different line.

**A GET can be caused by any page on the internet, so logout asks first.** An `<img>` tag
pointing at `/oauth2/logout` would otherwise sign a user out from anywhere. Two things
make a request trustworthy enough to act on without asking: a form post carrying the CSRF
token, or an `id_token_hint` that verifies against the published keys *and* names the very
session the browser is presenting. Anything else renders a confirmation page. A forged
hint therefore costs an attacker a click they cannot make.

**The hint's signature is checked; its expiry deliberately is not.** RP-Initiated Logout §2
says an expired id token is still a valid hint, and insisting otherwise would mean a client
could not log a user out with the token it was handed ten minutes ago. A 24-hour age bound
stands in, so an id token recovered from a log file a year later is not a way to target a
session. An unverifiable hint is treated as no hint rather than as an error: refusing would
make a key rotation look like a broken provider to every client still holding an older
token.

**`post_logout_redirect_uri` is matched exactly against the client's registered list, and
a failure is answered directly rather than by redirect** — this endpoint is reached with a
session cookie attached, which is the worst place to have an open redirect. When an
`id_token_hint` and a `client_id` name different clients the request is refused outright:
that is how somebody would try to borrow another client's allowlist.

### Notes from M1-6, part 4a: userinfo, introspection and revocation

**Part 4 is landing in three commits, not one.** The endpoints split cleanly by what they
need: these three need only fosite; logout and PAR need a browser and a session; and the
device grant needs a protocol fosite does not implement at all — there is no RFC 8628
handler anywhere in v0.49, so it is a hand-written grant rather than a factory to compose.
Recorded because the original plan said "part 4" and this is a change to it.

**Client secrets could not be verified at all, and no test had noticed.** `Client` carried
a comment saying the provider was configured with an Argon2id hasher "See newSecretHasher"
— and `newSecretHasher` did not exist. fosite's default is bcrypt, so every confidential
client failed authentication at every endpoint with "client credentials are invalid",
while public clients kept working. Part 3 used only a public client, so the whole flow
passed. The first confidential client in a test found it in one run. `oidcop.NewSecretHasher`
now delegates to `internal/authn`, and one `authn.Params` value is threaded from the
registry to the provider so the two cannot drift.

**A refresh token is accepted at userinfo unless you check the token *use*.** fosite's
introspection tries the access-token validator first and falls back to the refresh-token
one, so a refresh token presented as a bearer credential validates — as a refresh token,
successfully. Without the `use != fosite.AccessToken` check, `TestUserinfoRefusesARefreshToken`
gets a full profile back from a thirty-day credential meant only for the token endpoint.

**Introspection is authorized, not merely authenticated.** RFC 7662 requires the caller to
authenticate; it leaves who may ask about *which* token to the implementation, and "any
authenticated client" is a token scanner with a login page. A caller qualifies three ways:
the token was issued to it, it is named in the token's audience by client id, or the
token's audience includes something the caller is registered to serve — the last being the
ordinary case, since a resource server is not the client that obtained the token. Anything
else is answered `{"active": false}`, which §2.2 requires to be indistinguishable from an
expired token.

**Revocation is not reuse, and the audit log says so.** fosite calls the same storage
method for both — a replayed token and a client politely calling RFC 7009 — and nothing in
the arguments distinguishes them. The revocation endpoint marks the context, and
`RevokeFamilyOnRequest` records `oauth.refresh_token_revoked` instead of raising
`security.refresh_token_reuse`. An alarm that fires on correct behaviour is one an operator
learns to ignore. It also leaves the browser session alone: revoking a grant is not signing
out, which is what `/oauth2/logout` is for.

**The discovery document advertised `client_credentials` and nothing served it.** The
provider composed no such handler, so a client following the metadata would have built
against a grant that answers `unsupported_grant_type`. The factory is now composed — SPEC
§7.7 lists the grant at the token endpoint — which leaves one wrinkle worth knowing: fosite
validates the requested scopes against the client's allowlist and then grants none of them,
because in every other grant a person decided. Here there is no person, so the token
endpoint grants them itself for this grant alone; without that the grant issues a token
with no scopes, which every resource server would refuse.

**`sid` and `tid` now reach introspection too.** fosite's response writer copies whatever a
session offers through `ExtraClaimsSession`, and `openid.DefaultSession` does not implement
it — so the two identifiers were in the id token and nowhere else. A resource server can
now tie an introspected token to the session that issued it.

### Notes from M1-6, part 3

The authorization code flow works end to end. `TestTheAuthorizationCodeFlow` walks every
step a stock OIDC library performs — authorize, login page, password, redirect, code,
exchange — with nothing but HTTP between the test and the server, and the same sequence
was driven against the running deployment with `curl` alone.

**The tenant is established at the edge, before fosite sees anything.** fosite's storage
interfaces take a signature and nothing else; there is no tenant parameter anywhere in
them. Both endpoints resolve the client to its tenant and put it in the context, so every
storage call afterwards has a scope without re-resolving one, and one tenant's codes
cannot be redeemed in another's exchange.

**An unknown client or an unregistered redirect_uri is refused directly, never by
redirect.** Redirecting an error to a URI no registered client has vouched for is how an
authorization endpoint becomes an open redirect, and the victim is mid-login.
`safeReturnTo` applies the same rule to the login page's own destination: only a relative
path under `/oauth2/authorize`, so an absolute, protocol-relative or backslash-prefixed
value is refused.

**There is no consent screen, deliberately.** Every client here is one the tenant's own
administrator registered, so consent is implied by registration. A third-party client —
registered by somebody other than the resource owner — would need one, and nothing in the
model distinguishes those yet. Recorded because it is a gap, not an oversight.

**Cookies.** `__Host-` prefixed in production, which is a browser-enforced guarantee that
a sibling subdomain cannot set or overwrite the session; a different name in development,
where the prefix's mandatory Secure attribute cannot be satisfied over http, so a cookie
set in development is never mistaken for one carrying the guarantees. `SameSite=Lax` on
the session, because the authorization endpoint is reached by a top-level navigation from
the client's site and `Strict` would withhold the cookie on exactly that request;
`SameSite=Strict` on the CSRF cookie, which no cross-site navigation legitimately needs.

**One theft, one alarm — found on a live run.** The first end-to-end run produced *two*
`security.refresh_token_reuse` rows for a single replay. `GetRefreshTokenSession` returned
`ErrInactiveToken` for both consumed and revoked tokens, so the legitimate client's
collateral token sent fosite into reuse handling a second time. Two independent fixes now
hold it — the storage returns `ErrNotFound` for revoked-but-unconsumed, and `RevokeFamily`
classifies a revocation that changed no rows as a repeat. Either alone is sufficient;
`TestOneTheftRaisesOneAlarm` reports three alarms when both are removed.

**`sid` and `tid` reach the id token through `Extra`**, which fosite flattens to the top
level rather than nesting under `ext`. Without `sid` a relying party cannot tie a token to
the session that issued it, and back-channel logout has nothing to target.

### Notes from M1-6, part 2

**"Absent, not disabled" now holds at both ends.** The schema makes a client that *asks*
for the implicit or resource-owner-password grant unrepresentable; the provider composes
no handler that could serve one. fosite dispatches on the handlers it was given, so a
grant with no handler is refused by the provider itself rather than by a flag.
`TestTheProviderComposesNoForbiddenGrant` presents both at the token endpoint and asserts
they are not merely rejected but unrecognised.

**Refresh tokens are not stored twice.** fosite manages refresh tokens itself, and letting
it would have produced rotation *without* family revocation — the half that actually
defends against a stolen token. Instead fosite's `RefreshTokenStorage` is implemented
against M1-5's `refresh_token` table: `GetRefreshTokenSession` returns
`fosite.ErrInactiveToken` for a consumed token, which is the signal fosite's refresh
handler tests for, and the revocation hooks delegate to `authn.RefreshTokens.RevokeFamily`
so the family dies and `security.refresh_token_reuse` is raised exactly as before. One row
per token carries both the protocol payload and the family state, so the two cannot
disagree about whether a token has been used.

Everything else — codes, access tokens, PKCE challenges, OIDC sessions, PAR, client
assertion identifiers — shares one `oauth_session` table, because they are the same shape:
a serialized request keyed by a signature, with a lifetime. Signatures are hashed before
storage, on the same principle as every other credential: a copy of the database is not a
working set of tokens.

**An authorization code is deactivated, never deleted.** fosite has to distinguish "never
existed" from "already used" — the second is a replay that must revoke the whole exchange —
and a deleted row answers the first when the truth is the second. Same reasoning as
refresh tokens, and the storage returns the request *alongside*
`ErrInvalidatedAuthorizeCode` so fosite can revoke what descended from it.

**The provider's HMAC secret is derived from the KEK.** It keys every code and token
signature, so it has to be identical on every replica and stable across restarts; an
operator asked to generate and distribute one more secret eventually will not.
`secrets.Keyring.Derive` is HKDF with a purpose string, so the value fosite holds is not
the key that opens the signing keys, and two purposes cannot collide.

**A test that looked like a finding and was not.** The first PKCE tests asserted against
`NewAuthorizeRequest` and failed, which read like missing enforcement. fosite runs the
PKCE handler in `NewAuthorizeResponse`, where the code is minted — the enforcement was
never absent, the test was probing the wrong stage. Worth recording because the failure
mode is convincing: a test at the wrong layer reports a security hole that is not there,
and the temptation is to "fix" the implementation.

**A real bug the same tests found.** `request.GetRequestedAudience()` returns nil when
unset, and a nil slice reaches Postgres as NULL rather than the column's empty-array
default — so storing an authorization code failed with a not-null violation, which fosite
reported as `server_error` and which *masked* the PKCE check entirely. This is the second
appearance of the same class (the client registry had it too), and both are now normalised
at the boundary.

### Notes from M1-5

**The bug this task existed to avoid, found in the implementation of it.** Reuse
detection revoked the family and then returned `ErrTokenReuse` from inside the
transaction — and `pgx.BeginTxFunc` rolls back on any error, so the revocation was
discarded every time. The detection reported a theft and left the whole family live. The
signal now travels out of the callback in a variable, the callback returns nil so the
revocation commits, and the error is returned by the caller. Re-introducing the early
return makes `TestReplayingARotatedTokenKillsTheFamily` fail with "the live token still
rotates after the family was revoked", zero security events, and the session still valid.

**SERIALIZABLE is the load-bearing part**, and this is the case M0-7 built
`store.Isolation` for by name. "Has this token been consumed?" and "consume it" must be
indivisible, or two simultaneous presentations both read *not consumed*, both succeed, and
the chain silently forks into two live tokens that know nothing of each other — which is
the exact state reuse detection exists to notice, arrived at without noticing it.
`TestConcurrentRotationsOfOneTokenElectOneWinner` runs four at once and asserts one winner.

**Every replay is recorded; only the first is an alarm.** The first attempt at this ordered
revocation ahead of reuse, so that a dead family answered "invalid" and said nothing more.
That suppressed the event flood and destroyed the signal with it: somebody retrying a stolen
token for an hour became indistinguishable from an ordinary expired-token refusal. The fix
is to classify the record rather than discard it. A consumed token presented again always
revokes the family — idempotent, so it is a no-op UPDATE against one already dead — and
always writes an audit entry:

| Presentation | Action | Level |
| --- | --- | --- |
| Consumed token, family still live | `security.refresh_token_reuse` | error — alert on this |
| Consumed token, family already revoked | `security.refresh_token_reuse_repeat` | warn — evidence, not news |
| Revoked but never consumed | none | the legitimate client's collateral token |

An alert keyed on the first action fires once per incident; a query over both shows how hard
somebody tried. `warden_refresh_token_reuse_total{outcome}` carries the same split, with both
series pre-seeded so an alert never evaluates against nothing. The session revocation runs on
repeats too — kill first, classify second, because an earlier attempt may have failed.
`TestAReplayAgainstADeadFamilyIsStillRecorded` retries five times against a dead family and
asserts one alarm and five repeats; restoring the old ordering makes it fail with "0 of 5
retries were recorded".

The third row matters as much as the first two: the token the legitimate client was still
holding when the family died was never consumed, so it is not evidence of anything, and
recording it would bury the presentations that are.

**Reuse ends the session too.** Somebody holding a stolen refresh token very probably holds
the session cookie as well; revoking the family alone would log the thief out of refresh
while leaving their browser working.

**No grace window — settled, not merely deferred.** A common mitigation for the
double-refresh false positive is to let the immediately-previous token be re-presented for a
few seconds and return the same successor. There is none here, and that was raised as an open
question and then decided: once a token has been rotated it cannot be used, full stop. A
client that retries a refresh after a network timeout logs its user out, and that is the
correct trade — the alternative is a window in which a stolen token is honoured, which is
exactly what reuse detection exists to close. Do not reintroduce one without revisiting
SPEC §8.3.

**Where the tenant comes from.** A client presents a token and no tenant, the same
chicken-and-egg that `service_account` and `setup_token` solved by being registered as
row-level-security exceptions. `refresh_token` does not need one: a single-column read on
the system pool resolves the tenant, and every other statement then runs under RLS like any
tenant data. The registry stays honest.

**Also here:** an hourly purge worker for both mirrors. Neither session rows nor spent
tokens are removed by anything else, and a deployment issuing tokens for a year accumulates
a row per refresh per user per device. Rows are kept 30 days past expiry, because "which
devices was this account signed in from last week?" is an incident question.

### Notes from M1-4

**Nothing caches a session in process, and that is the whole design.** Redis is
authoritative for validity, Postgres is the mirror SPEC §8.3 asks for, and every
validation reads the cache tier. There is no propagation step, which is why the exit
condition — a second — is met in under two milliseconds. The test asserts the margin as
well as the budget: if it ever starts reporting hundreds of milliseconds, someone has
added a local session cache and quietly turned a guarantee into a promise about a TTL.

**Revoke-all uses a marker, not an enumeration.** Deleting the sessions a query found
leaves a race — a login committing between the enumeration and the delete produces a
session the revocation never saw. Instead `warden:revoked-before:{tenant}:{user}` records
the instant, and a session whose `auth_time` precedes it is refused wherever it is
presented. Deleting the individual keys afterwards is housekeeping. The Postgres mirror
still earns its place: Redis can answer "is this session valid?" in one lookup but cannot
enumerate a user's sessions without a scan, and the active-sessions UI needs the list.

**A tenant-crossing bug, found by its own test.** Session cache keys are named by sid
alone, and `Revoke` deleted the key *before* checking who the session belonged to — so any
tenant could end any other tenant's session by id. The Postgres update was correctly
tenant-scoped, which is exactly why it was easy to miss: the mirror said no rows changed
while the session was already gone from the cache. `TestSessionEndpointsAreTenantScoped`
caught it; `Sessions.belongsToTenant` is the fix, and removing it makes that test fail
again. Scoping handlers to the caller's tenant is necessary and was assumed sufficient.

**The cache tier grew primitives.** `cache.Cache` had only Ping/Backend/Close; it now has
Get/GetMany/Set/Delete/Expire, implemented for both backends. The in-process backend
evaluates expiry on read rather than running a sweeper goroutine, and copies values in and
out so the two backends do not differ on whether a caller may mutate what it read.

**A sharp edge worth knowing.** The Go tests and the compose stack share one Postgres, and
the test fixtures drop and recreate the `public` schema — which erases
`schema_migrations` while leaving the tables. The next `docker compose up` then fails with
`relation "tenant" already exists`. `make dev-reset-db` is the fix, and it is needed after
running the integration tests against a live dev stack.

### Notes from M1-2

**The timing property is a function, not a layer.** `authn.Authenticate` is one function
rather than "look the user up" plus "verify the password" because the moment those are
separable, a caller can skip the second when the first finds nothing — and that difference
is tens of milliseconds of 64 MiB hashing, measurable across a network by anyone who wants
a list of which addresses have accounts. Every failure path verifies against a **decoy
hash**: a real Argon2id hash of a random string, generated once under the current
parameters. The test asserts two things, and the second is the one with teeth: that the two
medians are close, *and* that both exceed half the cost of one hash. Injecting the obvious
bug — return early when there is no credential — moves the unknown-user median from 7.4 ms
to 0.7 ms and the test names the consequence in its failure message.

One imperfection is documented rather than hidden: a tenant whose stored hashes still carry
*older* parameters verifies faster than the decoy, so a timing difference exists between
the raising of parameters and the population having logged in once. It is bounded by the
rehash-on-login rollout.

**The length floor decides what the breach corpus is for.** With `min_length` at 12,
"123456" and "qwerty" are refused on length and never reach the corpus at all; the entries
that earn their place are the ones that clear twelve characters and are still in every
wordlist. The built-in list is weighted accordingly. It is also **generated** rather than
hand-written, and that was not the original plan: the hand-written version held
`Password1234` but not `password1234`, which a real `warden init` → redeem run accepted.
The unit tests had not caught it because they only asserted entries somebody had already
thought of. `TestEmbeddedSetCatchesTheObviousTwelveCharacterCases` is the regression test.

For real coverage, `security.breached_password_file` takes a Have I Been Pwned download.
It is binary-searched in place — the full corpus is tens of gigabytes — and validated at
startup, because a file in the wrong format loads happily and answers "not breached" to
everything, which is a mandatory check silently doing nothing.

**`warden init` now has a second half.** `setup_token` was written by M0-9 and read by
nothing, so the one-time URL it printed could not be redeemed and a bootstrapped deployment
had no way in. `warden password redeem -token …` closes that: it sets the password,
activates the user from `invited`, and burns every other outstanding link for them. A
rejected password leaves the link usable — burning a one-time bootstrap link because the
first guess was too short would be unrecoverable — and concurrent redemptions elect exactly
one winner, settled by the row count of a single `UPDATE … WHERE consumed_at IS NULL`.

Passwords are read from standard input only, never a flag or an environment variable:
arguments show up in `ps` and shell history, and environment variables are readable from
`/proc`.

**Known gap.** NIST 800-63B also recommends rejecting context-specific words — the user's
own address, the service name. The SPEC enumerates length, composition and the breach
corpus, so that is what was built; the contextual check is not implemented and is not
covered by any task yet.

### Notes from M1-1

Three things are worth knowing before touching key rotation.

**The overlap window is its own setting.** `security.key_overlap_window` (default 24 h) is
how long a rotated-out key stays in JWKS, and it is separate from
`security.key_rotation_interval` because they answer different questions: one is how often
a key is replaced, the other is how long the replaced one keeps verifying. Validation
refuses a window shorter than `security.access_token_ttl` — that combination mints tokens
that outlive the key that verifies them, and the symptom is a burst of invalid-signature
errors at whichever relying party had not refetched JWKS. It also refuses a window at least
as long as the rotation interval, which would mean keys are never actually retired.

**Scheduling runs on one clock.** `signing_key.expires_at` is when a key stops signing;
`retired_at + overlap` is when it leaves JWKS. Both, and the sweep's cutoff, come from
[`keys.Manager`](../internal/keys/manager.go)'s injectable clock rather than from `now()` in
the database. Mixing the two is not a rounding difference: `RetireActiveSigningKey` used to
stamp `retired_at` from `now()`, and against a manager whose clock said anything else the
key it had just demoted was already outside its own overlap window and swept on the next
JWKS read. `retired_at` is now supplied, and it is the same instant as the incoming key's
`activated_at` — a key stops signing exactly when its successor starts.

**Rotation is safe on every replica.** It takes a transaction-scoped advisory lock, so the
losers of a race return `ErrRotationHeld` rather than colliding on `signing_key_one_active`;
`TestConcurrentRotationsProduceOneKey` runs four at once and asserts exactly one key is
produced. The worker (`--role=worker`) checks hourly, which is far more often than a 90-day
interval needs — what the frequency buys is the overlap sweep, so a key leaves JWKS within
an hour of its window closing rather than whenever the next rotation happens to come round.
`GET /.well-known/jwks.json` sweeps too, so the published document is correct even in a
deployment running no worker at all.

`warden keys list|show|rotate [-force]` is the operator surface; `-force` is the
suspected-compromise path, and it says in as many words that the previous key keeps
verifying until the window closes.

---

## M2 — RBAC core (SPEC §22 M2)

**Milestone exit:** `check` answers correctly for every case in the conformance corpus, and
the corpus covers all of §9.

| # | Task | Exit condition |
| --- | --- | --- |
| M2-1 [B] | Schema: `role`, `role_inheritance`, `role_permission`, `grant`, `denial` | Cycle rejection at write time; depth cap 8 enforced |
| M2-2 [B] | Permission surface: application manifest ingestion, `implies` closure expanded **at grant time**, `unknown_permission` warning events | A typo'd permission in a check denies *and* emits the warning (§9.2) |
| M2-3 [B] | Role resolver: direct + transitive group assignments, inheritance DAG expansion, memoized on `(tenant_rev, subject_id)` and `(tenant_rev, role_id)` | Recursive-CTE query plan reviewed; 50-role subject resolves within the §18 budget |
| M2-4 [B] | Scope matching: tenant / app / environment / instance / subtree | Every scope form in §9.5 has corpus cases including near-miss negatives |
| M2-5 | Explicit denies with precedence `deny > allow > implicit deny`, admin-only, justification required, always audited | Property test: an explicit deny always wins, whatever the grant set |
| M2-6 [B] | `POST /v1/authz/check` and `/batch-check` (1 000 per call) | §18 latency targets met on the reference hardware |
| M2-7 | **Status: done (explain, filter).** `/effective-permissions`, `/explain` with the §10.3 derivation shape | `explain` is refused in prod for non-admins (it leaks policy structure) |
| M2-8 | **Status: done.** Decision log: `off`/`denies`/`sampled`/`all`, buffered async sink that never blocks the decision path | Sink saturation drops records and increments a metric; it never adds latency |
| M2-9 | Groups: local and IdP-sourced, nesting DAG, assignments | IdP group membership is *replaced* per login (§9.4) |
| M2-10 [B] | **Status: done.** **Privilege-escalation guard**: a subject may not assign a role containing permissions they lack, absent `tenant.role:assign_any` (§17.1 threat 3) | Dedicated test suite; this is a named threat, not a nice-to-have |
| M2-11 | Multi-tenant isolation sweep: every management endpoint × foreign `tenant_id` ⇒ 404 | Endpoint list is generated from the router, so a new endpoint cannot skip the sweep |
| M2-12 | **Status: done.** Admin audit log: append-only, hash-chained `prev_hash`, before/after diff | Tampering with any row breaks verification of the chain |

---

## M3 — Python SDK + FastAPI (SPEC §22 M3, overlaps M2)

**Milestone exit:** the reference application is fully protected end to end.

| # | Task | Exit condition |
| --- | --- | --- |
| M3-1 [B] | Package skeleton, typing, sync + async parity | `mypy --strict` clean; every public sync method has an async twin |
| M3-2 [B] | Token verification: JWKS fetch, cache, rotation, `iss`/`aud`/`exp`/`nbf`, clock skew — fully offline | No network call on the happy path after warm-up |
| M3-3 [B] | `check` / `batch_check` / `filter` against the M2 API | Same results as the server for every corpus case |
| M3-4 [B] | **Python conformance runner** against the M0-8 corpus. **Take this early in M3**, not mid-milestone: it is the first test that the corpus format is portable at all, and a format problem is cheap now and expensive once M3-3 and M3-5 are written against it | Python and Go agree on all cases — this is what makes the SDK trustworthy, and what M0's exit note defers to |
| M3-5 | Caching: `remote` / `cached` / `embedded`; cache key **includes the resource-attribute hash and tenant revision** (ADR-0002 consequence) | A changed attribute value cannot hit a stale entry |
| M3-6 | Change-stream subscription (SSE) with reconnect and backoff | Propagation p95 < 1 s end to end |
| M3-7 | `fail_mode` `closed` / `open_read` / `stale` + circuit breaker with exposed state | Default `closed`; a misconfigured SDK fails at startup, never allows at runtime (§12.5) |
| M3-8 [P] | FastAPI integration: dependencies, router guard, principal injection | Reference app protected with it |
| M3-9 [P] | Django integration: middleware, `@permission_required` replacement, DRF permission class, template tag | |
| M3-10 [P] | Flask integration: extension + decorator | |
| M3-11 | Resource registration and hierarchy push | Bulk sync of 10 000 nodes within a documented budget |
| M3-12 | `warden doctor`: config, connectivity, clock skew, manifest drift | Detects each of the four failure classes in a test |
| M3-13 | Observability: OTel `warden.check` spans, Prometheus metrics per §12.1 | An app's trace shows the check span inline |
| M3-14 | Reference application (FastAPI + React), doubling as contributor onboarding (ADR-0003) | Acceptance test for M3 and M5 |

---

## M4–M8 — story grain, decomposed at the milestone before each

- **M4 Federation.** OIDC RP connections; SAML SP with the §17 XML defences (DTD/XXE off,
  parse-then-verify against signature wrapping) and the **hostile-assertion fixture corpus**;
  claim/attribute/group mapping; identity linking with `email_trusted=false` default;
  connection test harness. Mock OIDC OP and SAML IdP in `testing/` are prerequisites.
  *Open:* §23 Q4 — whether SAML ships here or one milestone later. Decide before M4 starts;
  it is roughly a third of the milestone.
- **M5 UI binding + React SDK.** *Server half done:* ui_element/ui_binding, manifest
  sync, GET /v1/ui/bundle, POST /v1/ui/resolve, and `warden ui`. Remaining: discovery
  mode, the unprotected-endpoint detector, and the browser/React packages. Element declarations, bindings, UI bundle with ETag,
  per-frame batched `/ui/resolve`, `@warden/browser`, `@warden/react`, `<Guard>` with
  fail-closed loading, discovery mode (refused in prod), and the **unprotected-endpoint
  detector** (§11.6) — the genuinely novel safety feature, do not let it slip.
- **M6 Console.** All §14 sections. The **simulator** (§14.2) is the support channel for an
  open-source project with no hosted alternative — weight it accordingly.
- **M7 Fine-grained + conditions.** Resource hierarchy, CEL with fuel limit and 2 ms
  deadline, missing attribute ⇒ deny, time-boxed elevation, `list-resources`, consistency
  tokens, change stream. *Open:* §23 Q3 and Q6.
- **M8 Hardening → 1.0.** Helm chart, k6 load tests with regression gates, external
  penetration test, SBOM/signing/attestation promoted from M0 skeletons, docs site,
  backup/restore and `warden export`. *Open:* §23 Q5, Q8.

---

## Critical path

```
M0-1 → M0-2 → M0-4 → M0-5 → M0-6 → M0-8 ★ → M2-1 → M2-3 → M2-6 → M3-3 → M3-4
                                 ↘ M0-9 → M1-1 → M1-6 → M1-7 ↗
```

M0-8 (the conformance corpus) sits on the critical path deliberately: it is written **before**
the PDP so that the server and every SDK are built against one executable definition of the
semantics, and so ADR-0001 stays reversible at a known cost.
