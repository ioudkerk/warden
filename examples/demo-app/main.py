"""An invoice service protected by Warden.

Two things are worth watching for while reading this.

**Nothing here says who may approve an invoice.** It says that approving is
`billing.invoice:approve`, and asks. Which roles carry that, under what conditions and
on which projects is administered in Warden and changes without a deploy.

**Nothing here decides which buttons exist either.** Each control names an element key
declared in `warden.yaml`; whether it renders, and whether "no" means hidden, greyed
out or read-only, comes back in the UI bundle. An administrator changes that with
`warden ui` and this file does not move.

The app keeps its own authentication. Warden does not issue tokens until M1 and does
not need to here: the app passes the subject id it already trusts and asks only the
authorization question. ADR-0002 separates the two on purpose.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from warden_client import HIDDEN, Element, Warden, WardenUnavailable

app = FastAPI(title="ACME Invoices")
templates = Jinja2Templates(directory="templates")

warden = Warden(
    base_url=os.environ.get("WARDEN_URL", "http://127.0.0.1:8099"),
    token=os.environ["WARDEN_TOKEN"],
    application="billing",
    environment=os.environ.get("WARDEN_ENVIRONMENT", "prod"),
)

# The app's own accounts. In a real service this is your existing users and sessions;
# the only Warden-specific part is `subject`. `amr` is what the session's login
# actually proved — Warden uses it for roles that require a second factor, and once
# Warden issues tokens it becomes a claim rather than something the app asserts.
USERS: dict[str, dict[str, Any]] = {
    "maria": {"subject": os.environ["MARIA_ID"], "name": "Maria (finance approver)", "amr": ["pwd", "otp"]},
    "bob": {"subject": os.environ["BOB_ID"], "name": "Bob (viewer)", "amr": ["pwd"]},
}

INVOICES: dict[str, dict[str, Any]] = {
    "4711": {"project": "acme-2026", "amount": 30000, "status": "pending", "supplier": "Northwind Ltd"},
    "4712": {"project": "acme-2026", "amount": 90000, "status": "pending", "supplier": "Globex SA"},
    "9002": {"project": "other", "amount": 30000, "status": "pending", "supplier": "Initech BV"},
}


def current_user(who: str | None = Cookie(default=None)) -> dict[str, Any]:
    if who not in USERS:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return USERS[who]


@app.exception_handler(WardenUnavailable)
async def warden_unavailable(request: Request, exc: WardenUnavailable) -> HTMLResponse:
    """Warden being unreachable denies, and says so.

    An authorization service that cannot answer is not permission to proceed. Showing
    a page that explains the outage beats rendering an interface built from guesses.
    """
    return templates.TemplateResponse(
        request=request, name="unavailable.html", context={"detail": str(exc)}, status_code=503
    )


@app.get("/login", response_class=HTMLResponse)
def login(request: Request) -> Any:
    return templates.TemplateResponse(request=request, name="login.html", context={"users": USERS})


@app.post("/login")
def do_login(who: str = Form(...)) -> RedirectResponse:
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("who", who, httponly=True, samesite="lax")
    return response


@app.get("/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("who")
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: dict[str, Any] = Depends(current_user)) -> Any:
    """The list view: one filter call, one bundle call, one resolve call."""
    subject, amr = user["subject"], user["amr"]

    # Which invoices may this user see at all? One call, not one per row.
    visible = warden.filter(subject, "billing.invoice:read", "billing.invoice", list(INVOICES))

    # What should the chrome look like? Everything Warden can answer without an object.
    chrome, deferred = warden.ui_bundle(subject, amr=amr)

    # And the per-row controls, all in one round trip.
    items = [
        (f"{element}:{invoice_id}", element, ("billing.invoice", invoice_id))
        for invoice_id in visible
        for element in deferred
    ]
    per_row = warden.ui_resolve(subject, items, amr=amr)

    rows = [
        {
            "id": invoice_id,
            **INVOICES[invoice_id],
            "elements": {element: per_row.get(f"{element}:{invoice_id}", HIDDEN) for element in deferred},
        }
        for invoice_id in visible
    ]

    return templates.TemplateResponse(
        request=request,
        name="invoices.html",
        context={
            "user": user,
            "rows": rows,
            "chrome": chrome,
            "hidden_count": len(INVOICES) - len(visible),
        },
    )


@app.get("/invoices/{invoice_id}", response_class=HTMLResponse)
def detail(request: Request, invoice_id: str, user: dict[str, Any] = Depends(current_user)) -> Any:
    if invoice_id not in INVOICES:
        raise HTTPException(status_code=404, detail="no such invoice")
    subject, amr = user["subject"], user["amr"]

    # The read check is an enforcement point, not a rendering hint: a user who guesses
    # a URL gets a 403 even though the list view would never have shown them the row.
    decision = warden.check(subject, "billing.invoice:read", ("billing.invoice", invoice_id), context={"amr": amr})
    if not decision.allowed:
        return templates.TemplateResponse(
            request=request, name="forbidden.html",
            context={"reason": decision.reason, "what": f"read invoice {invoice_id}"},
            status_code=403,
        )

    chrome, deferred = warden.ui_bundle(subject, amr=amr)
    per_row = warden.ui_resolve(
        subject,
        [(element, element, ("billing.invoice", invoice_id)) for element in deferred],
        amr=amr,
    )

    return templates.TemplateResponse(
        request=request,
        name="detail.html",
        context={
            "user": user,
            "invoice": {"id": invoice_id, **INVOICES[invoice_id]},
            "chrome": chrome,
            "elements": {element: per_row.get(element, HIDDEN) for element in deferred},
        },
    )


@app.post("/invoices/{invoice_id}/approve")
def approve(request: Request, invoice_id: str, user: dict[str, Any] = Depends(current_user)) -> Any:
    """The enforcement point.

    This is the check that matters. The approve button being hidden or greyed out is a
    UX decision (SPEC §2.3); a user who posts this URL directly is stopped here, by
    the same question asked again.
    """
    if invoice_id not in INVOICES:
        raise HTTPException(status_code=404, detail="no such invoice")

    decision = warden.check(
        user["subject"],
        "billing.invoice:approve",
        ("billing.invoice", invoice_id),
        context={"amr": user["amr"]},
    )
    if not decision.allowed:
        return templates.TemplateResponse(
            request=request, name="forbidden.html",
            context={"reason": decision.reason, "what": f"approve invoice {invoice_id}"},
            status_code=403,
        )

    INVOICES[invoice_id]["status"] = "approved"
    return RedirectResponse(f"/invoices/{invoice_id}", status_code=303)


@app.get("/why/{invoice_id}", response_class=HTMLResponse)
def why(request: Request, invoice_id: str, user: dict[str, Any] = Depends(current_user)) -> Any:
    """The derivation behind a decision — the support tool, in miniature.

    Restricted in production to a service account marked may_explain, because a
    derivation describes the policy itself (SPEC §10.3).
    """
    decision = warden.check(
        user["subject"], "billing.invoice:approve", ("billing.invoice", invoice_id),
        context={"amr": user["amr"]}, explain=True,
    )
    return templates.TemplateResponse(
        request=request, name="why.html",
        context={"user": user, "invoice_id": invoice_id, "decision": decision},
    )


def element_or_hidden(elements: dict[str, Element], key: str) -> Element:
    return elements.get(key, HIDDEN)


templates.env.globals["element"] = element_or_hidden
