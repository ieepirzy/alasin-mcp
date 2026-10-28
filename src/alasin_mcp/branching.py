# SPDX-License-Identifier: Apache-2.0
"""Branch creation, pluggable per tenant (``branch_creation``).

- ``api`` (default): the server's Forgejo account creates the branch.
- ``webhook``: for deployments where only another service may create
  branches. The server POSTs a signed request to a configured URL, then polls
  Forgejo until the branch exists, within a bounded time.

Webhook request: ``POST <url>`` with a JSON body
``{"tenant", "repo", "branch", "from_ref", "session_id", "subject"}`` and

- ``X-Alasin-Timestamp``: Unix seconds;
- ``X-Alasin-Signature``: ``sha256=`` + hex HMAC-SHA256 over
  ``"<timestamp>." + <raw body>`` with the tenant's webhook secret.

The receiver should check the signature, reject stale timestamps, and answer
2xx once it has accepted the request. On a refusal it may answer a JSON body
``{"error": "<reason>"}``; the reason reaches the model, so it can correct
the request.

Register another strategy by implementing ``BranchCreator`` and adding it to
``Services.branch_creators`` under a name tenants can select.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Protocol

import anyio
import httpx

from .auth import Principal
from .config import TenantConfig
from .forgejo import ForgejoClient
from .validation import RepoRef


class BranchCreationError(Exception):
    """Branch creation failed. Safe to show the model."""


@dataclass(frozen=True)
class BranchRequest:
    tenant: TenantConfig
    principal: Principal
    session_id: str
    repo: RepoRef
    branch: str
    from_ref: str


class BranchCreator(Protocol):
    async def create(self, request: BranchRequest, client: ForgejoClient) -> str | None:
        """Create the branch; return its head commit SHA when known."""
        ...


class ApiBranchCreator:
    async def create(self, request: BranchRequest, client: ForgejoClient) -> str | None:
        created = await client.create_branch(request.repo, request.branch, request.from_ref)
        return (created.get("commit") or {}).get("id")


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


_REASON_MAX = 300


def refusal_reason(resp: httpx.Response) -> str | None:
    """The receiver's ``error`` text, single-line and bounded, or None."""
    try:
        payload = resp.json()
    except ValueError:
        return None
    reason = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(reason, str):
        return None
    reason = " ".join("".join(c if c.isprintable() else " " for c in reason).split())
    return reason[:_REASON_MAX] or None


class WebhookBranchCreator:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self._transport = transport

    async def create(self, request: BranchRequest, client: ForgejoClient) -> str | None:
        hook = request.tenant.branch_webhook
        if hook is None:
            raise BranchCreationError("branch_creation=webhook but no webhook is configured")
        body = json.dumps(
            {
                "tenant": request.tenant.id,
                "repo": request.repo.full_name,
                "branch": request.branch,
                "from_ref": request.from_ref,
                "session_id": request.session_id,
                "subject": request.principal.subject,
            },
            separators=(",", ":"),
        ).encode()
        timestamp = str(int(time.time()))
        # Re-read on every call, so the secret rotates without a restart.
        secret = hook.secret.resolve()
        headers = {
            "Content-Type": "application/json",
            "X-Alasin-Timestamp": timestamp,
            "X-Alasin-Signature": sign(secret, timestamp, body),
        }
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=False,
            transport=self._transport,
        ) as http:
            resp = await http.post(hook.url, content=body, headers=headers)
        if not 200 <= resp.status_code < 300:
            message = f"the branch creation service refused the request ({resp.status_code})"
            reason = refusal_reason(resp) if 400 <= resp.status_code < 500 else None
            raise BranchCreationError(f"{message}: {reason}" if reason else message)
        deadline = time.monotonic() + hook.timeout_seconds
        while True:
            branch = await client.branch(request.repo, request.branch)
            if branch is not None:
                return (branch.get("commit") or {}).get("id")
            if time.monotonic() >= deadline:
                raise BranchCreationError(
                    f"branch '{request.branch}' was requested but did not appear within "
                    f"{hook.timeout_seconds:g} s"
                )
            await anyio.sleep(hook.poll_interval_seconds)
