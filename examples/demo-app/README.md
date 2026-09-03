# Demo application

A small invoice service that asks Warden what its users may do. Standard library
only — no SDK, because the point is that the integration is a JSON POST.

```bash
# Warden must be running with a tenant, an application and some grants; see below.
export WARDEN_TOKEN="$(warden token -tenant acme -name billing-api)"
export MARIA_ID=usr_maria_acme
export BOB_ID=usr_bob_acme
python3 app.py
```

```bash
curl -s localhost:8000/invoices -H 'X-Demo-User: bob'
curl -s localhost:8000/invoices/4711 -H 'X-Demo-User: maria'
curl -s -X POST localhost:8000/invoices/4711/approve -H 'X-Demo-User: maria'
curl -s -X POST localhost:8000/invoices/4712/approve -H 'X-Demo-User: maria'
```

## What to notice

**Nothing in `app.py` says who may approve an invoice.** It says only that approving
is `billing.invoice:approve`. Which roles carry that permission, under what
conditions, and on which projects, lives in Warden — change a grant and the app's
behaviour changes with no deploy.

**The app keeps its own authentication.** Warden does not issue tokens until M1, and
does not need to here: the app passes the subject id it already trusts and asks only
the authorization question. ADR-0002 separates identity from decisions on purpose, so
adding real tokens later changes the `subject` field of the call and nothing else.

**The list view uses `batch-check`.** One question per row would be N round trips.

**`GET /invoices/{id}` returns a `may` object** — what this user could do next. That
is the same data the React `<Guard>` component will consume in M5; today the app asks
for it explicitly.

**Warden being unreachable denies.** An authorization service that cannot answer is
not permission to proceed. The SDK will do this properly with circuit breakers and the
`fail_mode` of SPEC §10.6; doing it by hand is the one thing an integration must not
get wrong.

## Setting Warden up for this

```bash
warden apply  -f ../warden.yaml
warden tenant -slug acme -name "ACME Corp"
MARIA=$(warden user -tenant acme -email maria@acme.test \
          -attributes '{"department":"finance","approval_limit":50000}')
BOB=$(warden user -tenant acme -email bob@acme.test)

warden resource -tenant acme -ref billing.project:acme-2026
warden resource -tenant acme -ref billing.invoice:4711 -parent billing.project:acme-2026 \
  -attributes '{"amount":30000,"status":"pending"}'

warden grant -tenant acme -user "$BOB"   -role billing.viewer
warden grant -tenant acme -user "$MARIA" -role billing.viewer
warden grant -tenant acme -user "$MARIA" -role billing.approver \
  -scope 'billing.project:acme-2026/**' \
  -condition 'resource.attributes.amount <= subject.attributes.approval_limit'
```

Note `billing.approver` in `../warden.yaml` declares `requires_mfa: true`, so a check
with no second factor in `context.amr` denies with `mfa_required`. That is why the
demo's users carry an `amr` list.
