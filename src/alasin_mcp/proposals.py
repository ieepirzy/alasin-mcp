# SPDX-License-Identifier: Apache-2.0
"""Proposing a work branch upstream (``propose_change``).

Where a tenant's Forgejo is a staging copy of another forge, a separate
service turns one of its branches into a pull request there. The server POSTs
a signed request to the tenant's ``proposals.url``, signed exactly like a
branch webhook (branching.py): ``X-Alasin-Timestamp`` and
``X-Alasin-Signature`` over ``"<timestamp>." + <raw body>``.

Request body: ``{"tenant", "repo", "branch", "title", "body"}``. The receiver
names the branch's owner from its own records, never from this body.

Answers:

- **201** ``{"pull_request", "commit", "owner_sub"}``: proposed;
- **422** ``{"refused": [reason, ...]}``: the receiver's own checks refused
  the branch, and the reasons reach the model so it can correct the branch;
- anything else: ``{"error": reason}``, which reaches the model bounded.

Status: ``POST <url>/status`` with ``{"tenant", "repo", "branch"}``, signed the
same way though it only reads (the body names the branch). **200**
``{"proposed": false}`` or ``{"proposed": true, "pull_request", "number",
"state", "draft", "head_sha", "review", "checks"}``.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from .branching import refusal_reason, sign
from .config import ProposalsConfig

_REASONS_MAX = 20
_REASON_MAX = 300


class ProposalError(Exception):
    """Proposing failed. Safe to show the model."""


def _clean(text: Any) -> str:
    text = " ".join("".join(c if c.isprintable() else " " for c in str(text)).split())
    return text[:_REASON_MAX]


def _signed(cfg: ProposalsConfig, payload: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    # Re-read on every call, so the secret rotates without a restart.
    return raw, {
        "Content-Type": "application/json",
        "X-Alasin-Timestamp": timestamp,
        "X-Alasin-Signature": sign(cfg.secret.resolve(), timestamp, raw),
    }


# The status fields passed on, each a short string, int or bool.
_STATUS_KEYS = ("pull_request", "number", "state", "draft", "head_sha", "review", "checks")


async def status(
    cfg: ProposalsConfig,
    tenant_id: str,
    repo: str,
    branch: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """The branch's upstream pull request, read only. Raises ProposalError
    when the service can't say (not running, refusing, malformed)."""
    raw, headers = _signed(cfg, {"tenant": tenant_id, "repo": repo, "branch": branch})
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False, transport=transport
        ) as http:
            resp = await http.post(cfg.url.rstrip("/") + "/status", content=raw, headers=headers)
    except httpx.TransportError:
        raise ProposalError("the proposal service is not running") from None
    if resp.status_code != 200:
        reason = refusal_reason(resp)
        message = f"the proposal service answered {resp.status_code}"
        raise ProposalError(f"{message}: {reason}" if reason else message)
    try:
        out = resp.json()
    except ValueError:
        out = None
    if not isinstance(out, dict) or not isinstance(out.get("proposed"), bool):
        raise ProposalError("the proposal service sent an unreadable status")
    result: dict[str, Any] = {"proposed": out["proposed"]}
    for key in _STATUS_KEYS:
        v = out.get(key)
        if isinstance(v, bool | int):
            result[key] = v
        elif isinstance(v, str):
            result[key] = _clean(v)
    return result


async def propose(
    cfg: ProposalsConfig,
    tenant_id: str,
    repo: str,
    branch: str,
    title: str,
    body: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    payload = {"tenant": tenant_id, "repo": repo, "branch": branch, "title": title, "body": body}
    raw, headers = _signed(cfg, payload)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(cfg.timeout_seconds, connect=5.0),
            follow_redirects=False,
            transport=transport,
        ) as http:
            resp = await http.post(cfg.url, content=raw, headers=headers)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        raise ProposalError(
            "the proposal service is not running, so branches can't be proposed upstream yet; "
            "the branch is safe as it is: ask an administrator to switch the return path on"
        ) from None
    except httpx.TimeoutException:
        raise ProposalError(
            "the proposal service did not answer in time; check the branch's pull request "
            "upstream before trying again"
        ) from None
    if resp.status_code == 201:
        try:
            out = resp.json()
        except ValueError:
            out = None
        if not isinstance(out, dict) or not isinstance(out.get("pull_request"), str):
            raise ProposalError("the proposal service answered 201 without a pull request")
        return {
            "proposed": True,
            "pull_request": out["pull_request"],
            "commit": str(out.get("commit") or ""),
            "owner_sub": str(out.get("owner_sub") or ""),
        }
    if resp.status_code == 422:
        try:
            reasons = resp.json().get("refused")
        except (ValueError, AttributeError):
            reasons = None
        if isinstance(reasons, list) and reasons:
            return {
                "proposed": False,
                "refused": [_clean(r) for r in reasons[:_REASONS_MAX]],
            }
    message = f"the proposal service refused the request ({resp.status_code})"
    reason = refusal_reason(resp) if resp.status_code < 500 or resp.status_code == 503 else None
    raise ProposalError(f"{message}: {reason}" if reason else message)
