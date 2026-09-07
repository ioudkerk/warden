# Demo application — FastAPI

An invoice service protected by Warden, server-rendered so you can watch the UI
change without a browser console.

Two files matter: `warden_client.py` is everything Warden-specific and is what the
Python SDK (SPEC §12.2, M3) will replace; `main.py` is the application and mentions no
role, no permission holder and no visibility rule.

## What to look for

**Nothing in `main.py` says who may approve an invoice.** It says approving is
`billing.invoice:approve`, and asks.

**Nothing in the templates decides which controls exist.** Each names an element key
declared in `../warden.yaml`. Whether it renders — and whether "no" means hidden,
greyed out or read-only — comes back from Warden. An administrator changes that with
`warden ui` and neither file moves.

**Three calls build a page.** `POST /v1/authz/filter` for which rows are visible,
`GET /v1/ui/bundle` for the chrome, and one batched `POST /v1/ui/resolve` for the
per-row controls. A table of 200 rows with two buttons each is one request, not 400.

**The buttons are not the enforcement.** `POST /invoices/{id}/approve` asks again.
Hiding a control is a UX decision (SPEC §2.3); posting the URL with no button gets a
403 with Warden's reason.

**Warden being unreachable denies.** `WardenUnavailable` is an exception, not a falsy
result, so a caller who forgets to check fails rather than continues.

## Running it

From the repository root, bring up a seeded Warden and take the demo application's
token out of the seed log:

```bash
make dev
make dev-logs-seed          # prints the setup URL and the service-account token
```

The seed creates exactly the fixture this application expects — the `billing`
manifest, tenant `acme`, Maria with an approval limit of 50 000, Bob without one, and
SPEC §9.9's invoices. Then:

```bash
cd examples/demo-app
python3 -m venv .venv && .venv/bin/pip install fastapi 'uvicorn[standard]' jinja2 python-multipart

export WARDEN_URL=http://localhost:8080
export WARDEN_TOKEN=wsk_...          # from `make dev-logs-seed`
export MARIA_ID=usr_maria_acme BOB_ID=usr_bob_acme
.venv/bin/uvicorn main:app --port 8000
```

Open <http://localhost:8000>, sign in as either user.

The subject ids are stable because `warden seed` derives them from the email and the
tenant slug, which is convenient here and is also why seeding is refused in production:
predictable identifiers with standing grants are what `warden init` exists to prevent.

## What each user sees, and why

| | Maria | Bob |
| --- | --- | --- |
| Invoices listed | all she may read | all he may read |
| Approve on 4711 (30 000) | **active** | disabled |
| Approve on 4712 (90 000) | disabled — over her 50 000 limit | disabled |
| Approve on 9002 (other project) | disabled — outside her subtree | disabled |
| Void | hidden | hidden |

Maria's approver grant is scoped to one project and carries a CEL condition on the
amount, and `billing.approver` declares `requires_mfa`. Her session's `amr` says she
used a second factor; Bob's does not. Every difference above follows from those facts
and none of them is in the application.

## Change the interface without a deploy

With the app running, in another terminal:

```bash
# Reports is hidden for Bob — he has no billing.report:read.
warden ui -tenant acme -application billing -element nav.reports \
  -requires '{"any_of":[{"role":"billing.viewer"}]}' -mode hidden

# Reload as Bob. The tab is there now.

warden ui -tenant acme -application billing -element nav.reports \
  -requires '{"any_of":[{"permission":"billing.report:schedule"}]}' \
  -mode disabled -message "Ask an administrator for reporting access"

# Reload again. Visible, greyed out, with the tooltip.
```

Nothing restarted. The bundle is cached against the tenant's permission revision,
which a binding change bumps.

## The "why?" link

Every row links to a derivation from `POST /v1/authz/explain` — which grants were
considered, what became of each, and the values every condition read:

```
grant grn_ZVC8xbNTExU  role=billing.approver  scope=billing.project:acme-2026/**
  → condition_failed
     resource.attributes.amount <= subject.attributes.approval_limit  =>  false
       resource.attributes.amount = 90000
       subject.attributes.approval_limit = 50000
```

This is restricted in production to a service account marked `may_explain`, because a
derivation describes the policy itself (SPEC §10.3). The demo's token has it.

## What this demo still fakes

- **Authentication.** Warden issues no tokens until M1, so the app passes a subject id
  from its own session and states the session's `amr` itself. With M1 the `amr` is a
  claim on the access token, which a client cannot assert about itself.
- **Caching.** Every page makes live calls. The SDK's decision cache and change-stream
  invalidation are M3; this is what the uncached shape looks like.
- **`<Guard>`.** The React SDK (M5) consumes the same bundle. Here the server renders
  it, which shows the same decisions with less machinery.
