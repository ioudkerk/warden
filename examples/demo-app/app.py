"""A small invoice service that asks Warden what its users may do.

This is what integrating with Warden looks like today, before the SDKs exist
(warden-sdk is M3): a JSON POST to /v1/authz/check. The SDK will add caching, batching
and a change-stream subscription, and it will not change the shape of the question.

Two things are worth noticing in the code below.

The app keeps its own authentication. Warden does not issue tokens until M1, and it
does not need to for this: the app passes the subject id it already trusts, and asks
Warden only the authorization question. ADR-0002 separates the two deliberately, so
adding real tokens later changes the call's `subject` field and nothing else.

Nothing in this file says who may approve an invoice. It says only that approving is
`billing.invoice:approve`. Which roles hold that, under what conditions, and on which
projects, is administered in Warden and can change without redeploying this app.
"""

import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

WARDEN = os.environ.get("WARDEN_URL", "http://localhost:8080")
TOKEN = os.environ["WARDEN_TOKEN"]

# The app's own user table. In a real service this is your existing accounts and
# sessions; the only Warden-specific part is the subject id.
USERS = {
    "maria": {"subject": os.environ["MARIA_ID"], "amr": ["pwd", "otp"]},
    "bob": {"subject": os.environ["BOB_ID"], "amr": ["pwd"]},
}

INVOICES = {
    "4711": {"project": "acme-2026", "amount": 30000, "status": "pending"},
    "4712": {"project": "acme-2026", "amount": 90000, "status": "pending"},
    "9002": {"project": "other", "amount": 30000, "status": "pending"},
}


def check(subject, permission, resource_id=None, amr=None):
    """Ask Warden one question. This is the whole integration."""
    body = {"subject": {"id": subject}, "permission": permission}
    if resource_id:
        body["resource"] = {"type": "billing.invoice", "id": resource_id}
    if amr:
        body["context"] = {"amr": amr}

    request = urllib.request.Request(
        f"{WARDEN}/v1/authz/check",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        # Warden refusing to answer is not permission to proceed. Failing closed is
        # the default the SDK will implement properly (SPEC §10.6); doing it by hand
        # here is the one thing an integration must not get wrong.
        return {"allowed": False, "reason": f"warden_error_{e.code}"}
    except urllib.error.URLError as e:
        return {"allowed": False, "reason": f"warden_unreachable: {e.reason}"}


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, body):
        payload = json.dumps(body, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _user(self):
        """The app's own authentication, standing in for a real session."""
        return USERS.get(self.headers.get("X-Demo-User", ""))

    def do_GET(self):
        user = self._user()
        if not user:
            return self._json(401, {"error": "send X-Demo-User: maria or bob"})

        if self.path == "/invoices":
            # One question per invoice would be N round trips. batch-check asks them
            # all at once, which is what a list view needs.
            decisions = self._batch(user, "billing.invoice:read", list(INVOICES))
            visible = {
                invoice_id: INVOICES[invoice_id]
                for invoice_id, d in decisions.items()
                if d["allowed"]
            }
            return self._json(200, {"invoices": visible})

        if self.path.startswith("/invoices/"):
            invoice_id = self.path.split("/")[-1]
            if invoice_id not in INVOICES:
                return self._json(404, {"error": "no such invoice"})
            decision = check(user["subject"], "billing.invoice:read", invoice_id)
            if not decision["allowed"]:
                return self._json(403, {"error": "forbidden", "reason": decision["reason"]})
            # The UI hint: what this user may do with this invoice. Warden decides;
            # the frontend renders. This is what <Guard> will consume in M5.
            actions = self._batch(
                user,
                None,
                [invoice_id],
                permissions=["billing.invoice:approve", "billing.invoice:void"],
            )
            return self._json(200, {"invoice": INVOICES[invoice_id], "may": actions})

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        user = self._user()
        if not user:
            return self._json(401, {"error": "send X-Demo-User: maria or bob"})
        if not self.path.endswith("/approve"):
            return self._json(404, {"error": "not found"})

        invoice_id = self.path.split("/")[-2]
        if invoice_id not in INVOICES:
            return self._json(404, {"error": "no such invoice"})

        # The server-side check. This is the one that matters: hiding a button is a
        # UX decision, and every action behind it is still checked here (SPEC §2.3).
        decision = check(user["subject"], "billing.invoice:approve", invoice_id, user["amr"])
        if not decision["allowed"]:
            return self._json(403, {"error": "forbidden", "reason": decision["reason"]})

        INVOICES[invoice_id]["status"] = "approved"
        return self._json(200, {"invoice": INVOICES[invoice_id], "approved_by": decision["matched_grant"]})

    def _batch(self, user, permission, invoice_ids, permissions=None):
        checks = []
        for invoice_id in invoice_ids:
            for p in permissions or [permission]:
                checks.append({
                    "ref": f"{p}:{invoice_id}" if permissions else invoice_id,
                    "permission": p,
                    "resource": {"type": "billing.invoice", "id": invoice_id},
                })
        body = {
            "subject": {"id": user["subject"]},
            "context": {"amr": user["amr"]},
            "checks": checks,
        }
        request = urllib.request.Request(
            f"{WARDEN}/v1/authz/batch-check",
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                results = json.load(response)["results"]
        except urllib.error.URLError:
            return {c["ref"]: {"allowed": False, "reason": "warden_unreachable"} for c in checks}

        if permissions:
            return {
                p: results[f"{p}:{invoice_ids[0]}"]["allowed"]
                for p in permissions
            }
        return results

    def log_message(self, *args):
        pass  # quiet


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"invoice service on http://localhost:{port}, asking Warden at {WARDEN}")
    HTTPServer(("", port), Handler).serve_forever()
