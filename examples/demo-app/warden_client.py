"""A minimal Warden client.

This is what the Python SDK (SPEC §12.2, milestone M3) will replace. It is kept
separate from the application so the boundary is obvious: everything below is
Warden-specific, and nothing above it is.

The SDK will add local decision caching, a change-stream subscription that
invalidates it, circuit breaking and the per-application `fail_mode` of SPEC §10.6.
None of that changes the shape of the questions asked here.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


class WardenUnavailable(Exception):
    """Warden could not be reached or refused to answer.

    Deliberately an exception rather than a falsy result. An authorization service
    that cannot answer is not permission to proceed, and a caller that forgets to
    check a boolean should fail rather than continue.
    """


@dataclass
class Decision:
    allowed: bool
    reason: str
    matched_grant: str | None = None
    explain: dict[str, Any] | None = None


@dataclass
class Element:
    """How one UI element should render, as Warden resolved it."""

    mode: str  # allow | hidden | disabled | read_only
    message: str = ""

    @property
    def visible(self) -> bool:
        return self.mode != "hidden"

    @property
    def interactive(self) -> bool:
        return self.mode == "allow"

    @property
    def read_only(self) -> bool:
        return self.mode == "read_only"


# An element Warden has not been asked about renders as hidden. Failing closed is the
# only safe default for something that decides whether a control appears.
HIDDEN = Element(mode="hidden")


@dataclass
class Warden:
    base_url: str
    token: str
    application: str
    environment: str = "prod"
    timeout: float = 5.0
    _session_headers: dict[str, str] = field(default_factory=dict)

    # --- transport ---------------------------------------------------------------

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {self.token}", **self._session_headers}
        if data is not None:
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = json.load(e).get("detail", "")
            except Exception:  # noqa: BLE001 - the body may be anything on an error
                pass
            raise WardenUnavailable(f"warden returned {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise WardenUnavailable(f"warden unreachable: {e.reason}") from e
        except OSError as e:
            # A read timeout arrives here rather than as a URLError: urllib only wraps
            # failures from opening the connection, not from reading the response. A
            # hung authorization service has to fail closed exactly like a missing one.
            raise WardenUnavailable(f"warden unreachable: {e}") from e

    # --- authorization -----------------------------------------------------------

    def check(
        self,
        subject: str,
        permission: str,
        resource: tuple[str, str] | None = None,
        *,
        attributes: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        explain: bool = False,
    ) -> Decision:
        """Ask one question. The call every enforcement point makes."""
        body: dict[str, Any] = {"subject": {"id": subject}, "permission": permission}
        if resource is not None:
            body["resource"] = {"type": resource[0], "id": resource[1]}
            if attributes:
                body["resource"]["attributes"] = attributes
        if context:
            body["context"] = context
        if self.environment:
            body["environment"] = self.environment

        path = "/v1/authz/explain" if explain else "/v1/authz/check"
        d = self._request("POST", path, body)
        return Decision(
            allowed=d["allowed"],
            reason=d["reason"],
            matched_grant=d.get("matched_grant"),
            explain=d.get("explain"),
        )

    def filter(
        self,
        subject: str,
        permission: str,
        resource_type: str,
        ids: list[str],
        *,
        context: dict[str, Any] | None = None,
    ) -> list[str]:
        """Return the subset of ids the subject may act on.

        The list-view call. Asking per row would be N round trips, and asking with
        batch-check would return a map to post-process.
        """
        if not ids:
            return []
        body: dict[str, Any] = {
            "subject": {"id": subject},
            "permission": permission,
            "resources": [{"type": resource_type, "id": i} for i in ids],
        }
        if context:
            body["context"] = context
        if self.environment:
            body["environment"] = self.environment
        return self._request("POST", "/v1/authz/filter", body)["allowed"]

    # --- UI binding ---------------------------------------------------------------

    def ui_bundle(self, subject: str, *, amr: list[str] | None = None) -> tuple[dict[str, Element], list[str]]:
        """What the interface should look like for this subject.

        Returns the elements Warden could answer eagerly, and the keys of those that
        need an object — which are resolved per row by `ui_resolve`.
        """
        query = f"?subject={subject}&application={self.application}&environment={self.environment}"
        for method in amr or []:
            query += f"&amr={method}"
        d = self._request("GET", f"/v1/ui/bundle{query}")
        elements = {
            key: Element(mode=v["mode"], message=v.get("message", ""))
            for key, v in d["elements"].items()
        }
        return elements, d.get("deferred", [])

    def ui_resolve(
        self,
        subject: str,
        items: list[tuple[str, str, tuple[str, str] | None]],
        *,
        amr: list[str] | None = None,
    ) -> dict[str, Element]:
        """Resolve resource-scoped elements for specific objects, in one call.

        `items` is (ref, element_key, resource). A table of 200 rows with two buttons
        each is 400 questions; asking them one at a time is what makes a list view
        slow enough that somebody caches the answers badly.
        """
        if not items:
            return {}
        payload: list[dict[str, Any]] = []
        for ref, element, resource in items:
            entry: dict[str, Any] = {"ref": ref, "element": element}
            if resource is not None:
                entry["resource"] = {"type": resource[0], "id": resource[1]}
            payload.append(entry)

        body: dict[str, Any] = {
            "subject": {"id": subject},
            "application": self.application,
            "environment": self.environment,
            "items": payload,
        }
        if amr:
            body["context"] = {"amr": amr}
        results = self._request("POST", "/v1/ui/resolve", body)["results"]
        return {
            ref: Element(mode=v["mode"], message=v.get("message", ""))
            for ref, v in results.items()
        }
