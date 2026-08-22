# Warden — Python backend SDK design

Package: `warden-sdk` · Python 3.10+ · fully typed (`py.typed`) · sync **and** async.
Companion to [`../SPEC.md`](../SPEC.md) §12.

## Design principles

1. **Fail closed, loudly.** A missing or invalid configuration raises at import/startup, not
   at the first check. There is no code path where an error yields "allowed".
2. **The fast path is local.** Token verification never hits the network after JWKS is warm;
   checks hit an in-process cache first.
3. **Framework-native.** A FastAPI user should write FastAPI, not adapter glue.
4. **One mental model across languages.** The same method names, the same `Decision` shape,
   the same conformance corpus as the Node and Go SDKs.
5. **No magic globals.** A `Warden` instance is explicit and injectable; a module-level
   convenience singleton exists but is opt-in.

## Installation

```bash
pip install warden-sdk                 # core
pip install "warden-sdk[fastapi]"      # + FastAPI integration
pip install "warden-sdk[django]"       # + Django/DRF integration
pip install "warden-sdk[embedded]"     # + cel-python for local evaluation
```

## Client

```python
from warden import Warden, CacheMode, FailMode

warden = Warden(
    issuer="https://warden.acme.com",
    application="billing",
    environment="prod",
    client_id="billing-api",
    client_secret=os.environ["WARDEN_CLIENT_SECRET"],   # or private_key_jwt=...
    audience="billing-api",
    cache_mode=CacheMode.CACHED,        # REMOTE | CACHED | EMBEDDED
    fail_mode=FailMode.CLOSED,          # CLOSED | OPEN_READ | STALE
    cache_max_entries=50_000,
    max_stale=timedelta(minutes=5),
    change_stream=True,                 # subscribe to SSE invalidations
    timeout=timedelta(seconds=2),
    retries=2,                          # idempotent calls only
)
```

Every option is also readable from the environment (`WARDEN_ISSUER`,
`WARDEN_CLIENT_SECRET`, …) so twelve-factor deployments need no code.

`AsyncWarden` mirrors the API with `await`. Both share the cache implementation; a process
may hold one of each.

## Core types

```python
@dataclass(frozen=True)
class Principal:
    id: str
    tenant_id: str
    email: str | None
    session_id: str | None
    roles: tuple[str, ...]
    groups: tuple[str, ...]
    attributes: Mapping[str, Any]
    amr: tuple[str, ...]
    claims: Mapping[str, Any]          # raw, for escape hatches
    impersonator_id: str | None

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    decision_id: str | None
    matched_grant: str | None
    from_cache: bool
    degraded: bool                     # served under fail_mode=STALE
    explain: Explain | None

    def __bool__(self) -> bool: ...    # so `if decision:` reads naturally
    def raise_for_denied(self) -> None:  # raises PermissionDenied
```

## Token verification

```python
principal = warden.verify_token(bearer)          # raises InvalidToken on failure
```

- JWKS cached in-process, refreshed on unknown `kid` (rate-limited to once per 5 min to
  prevent a forged-`kid` DoS).
- Validates `iss`, `aud`, `exp`, `nbf`, `iat`, signature algorithm allowlist (`RS256`,
  `ES256` — never `none`, never HMAC).
- Configurable `leeway` (default 30 s) for clock skew.
- Optional `require_amr={"otp"}` / `max_auth_age` for step-up enforcement.

## Checks

```python
d = warden.check(principal, "billing.invoice:approve")

d = warden.check(
    principal,
    "billing.invoice:approve",
    resource=Resource("billing.invoice", invoice.id, attributes={"amount": invoice.amount,
                                                                "status": invoice.status}),
    context={"ip": request.client.host},
)

# Batch — one round trip
results = warden.batch_check(principal, [
    ("billing.invoice:read", Resource("billing.invoice", i.id)) for i in invoices
])

# Filter — "which of these may they see?"
visible = warden.filter(principal, "billing.invoice:read",
                        [Resource("billing.invoice", i.id) for i in invoices])

# Assertion style
warden.require(principal, "billing.invoice:void", resource=...)   # raises PermissionDenied
```

### Read-your-own-writes

```python
res = warden.grants.create(user_id=..., role_id=..., scope=...)
warden.check(principal, "...", min_consistency=res.consistency_token)
```

## Caching

- Key: `(subject_id, permission, resource_ref, hash(relevant context), tenant_rev)`.
- TTL comes from the server response; the SDK never invents a longer one.
- LRU with a configurable entry cap and an optional Redis second tier for multi-process
  deployments (`cache_backend=RedisCache(...)`).
- Invalidation: SSE change stream (background thread / asyncio task) drops entries on
  `permissions.changed` (whole tenant) and `subject.invalidated` (one subject).
- `warden.cache.stats()` exposes hits, misses, evictions, staleness for dashboards.

Checks carrying **inline resource attributes** are cached against a hash of those attributes,
so changing an invoice's amount naturally produces a different key rather than a stale allow.

## Embedded mode

With `cache_mode=EMBEDDED`, the SDK pulls the tenant's policy bundle on an interval and
evaluates locally with `cel-python`. Semantics are guaranteed identical to the server by the
shared conformance corpus, which runs in the SDK's CI. Bundle signature is verified against
JWKS before use; a bundle that fails verification is discarded and the SDK falls back to
`CACHED` with a loud warning.

## Framework integrations

### FastAPI

```python
from fastapi import Depends, FastAPI
from warden.fastapi import WardenMiddleware, get_principal, requires

app = FastAPI()
app.add_middleware(WardenMiddleware, warden=warden)     # populates request.state.principal

@app.post("/invoices/{invoice_id}/approve",
          dependencies=[Depends(requires("billing.invoice:approve",
                                         resource=("billing.invoice", "invoice_id")))])
async def approve(invoice_id: str, principal: Principal = Depends(get_principal)):
    ...
```

The `resource=` tuple names a path/query parameter, so the resource id is resolved from the
request without boilerplate. For attributes that require a database read:

```python
@app.post("/invoices/{invoice_id}/approve")
async def approve(invoice_id: str, principal: Principal = Depends(get_principal)):
    invoice = await repo.get(invoice_id)
    await warden.require(principal, "billing.invoice:approve",
                         resource=Resource("billing.invoice", invoice.id,
                                           attributes={"amount": invoice.amount}))
```

A router-level guard (`WardenRouter(default_permission=...)`) covers the "everything under
this prefix needs X" case.

### Django

```python
# settings.py
MIDDLEWARE = [..., "warden.django.WardenMiddleware"]
WARDEN = {"ISSUER": ..., "APPLICATION": "billing", "CLIENT_ID": ..., "CLIENT_SECRET": ...}

# views.py
from warden.django import require_permission

@require_permission("billing.invoice:approve", resource=("billing.invoice", "invoice_id"))
def approve(request, invoice_id): ...

# DRF
from warden.django.drf import WardenPermission
class InvoiceViewSet(ModelViewSet):
    permission_classes = [WardenPermission]
    warden_permissions = {"list": "billing.invoice:read", "approve": "billing.invoice:approve"}

# templates
{% load warden %}
{% if_permission "billing.invoice:void" invoice %}<button>Void</button>{% endif_permission %}
```

A `QuerySet` helper mirrors `filter()` for the list case:

```python
Invoice.objects.warden_filter(request.principal, "billing.invoice:read", field="id")
```

which fetches the allowed id set once and applies `.filter(id__in=...)`, with a documented
warning about result-set size.

### Flask

```python
from warden.flask import WardenExtension, require_permission
WardenExtension(app, warden=warden)

@app.post("/invoices/<invoice_id>/approve")
@require_permission("billing.invoice:approve", resource=("billing.invoice", "invoice_id"))
def approve(invoice_id): ...
```

## Resource registration

```python
warden.resources.upsert(
    Resource("billing.invoice", invoice.id,
             parent=("billing.project", invoice.project_id),
             attributes={"amount": invoice.amount, "status": invoice.status}),
)
warden.resources.bulk_upsert(iter_of_resources)     # NDJSON streaming, for backfills
```

A SQLAlchemy event-listener helper (`warden.contrib.sqlalchemy.track(Invoice, ...)`) mirrors
inserts/updates automatically for teams that want it.

## Errors

```
WardenError
├── ConfigurationError        # raised at startup
├── InvalidToken
├── PermissionDenied          # carries .permission, .reason, .decision_id
├── PDPUnavailable            # only surfaces under fail_mode=CLOSED
└── ConflictError
```

`PermissionDenied` renders as a 403 with a problem-details body in every integration, and
includes `decision_id` so a support engineer can look the decision up in the console.

## Observability

- OpenTelemetry spans: `warden.verify_token`, `warden.check` (attributes: permission,
  resource type, allowed, cache hit), `warden.batch_check`.
- Prometheus: `warden_check_duration_seconds{result,cached}`, `warden_cache_hits_total`,
  `warden_pdp_errors_total{kind}`, `warden_change_stream_connected`.
- Structured logs with `decision_id` correlation; denials logged at INFO, PDP errors at
  ERROR. Never logs tokens or secrets — a redaction filter is installed by default.

## Testing support

```python
from warden.testing import FakeWarden

warden = FakeWarden(allow=["billing.invoice:read"])       # deny by default
warden.allow("billing.invoice:approve", resource="billing.invoice:4711")
assert warden.check(principal, "billing.invoice:void").allowed is False
assert warden.calls == [...]                              # assert what was checked
```

`FakeWarden` implements the same protocol, so tests never hit the network, and
`warden.testing.principal(roles=[...])` builds signed test tokens.

## `warden doctor`

```
$ python -m warden doctor
✓ Configuration valid
✓ Issuer reachable (43 ms)
✓ JWKS fetched, 2 keys, next rotation 2026-11-02
✓ Client credentials accepted
✓ Clock skew 0.2 s (limit 30 s)
✗ Manifest drift: 2 permissions declared locally are not on the server
    billing.invoice:export, billing.report:schedule
  → run `warden apply --env prod`
✓ Change stream connected
```
