# SPDX-License-Identifier: Apache-2.0
"""Plain git over HTTPS: git's smart HTTP, forwarded to Forgejo per credential.

``git_access`` (tools.py) gives the caller a URL for one branch with a
short-lived credential in it. A git client sends that credential as HTTP
Basic auth (the password; the user name is ignored). This module serves
exactly git's smart HTTP routes under ``/git/<owner>/<repo>.git/``:

- ``GET info/refs?service=git-upload-pack|git-receive-pack``
- ``POST git-upload-pack`` (clone, fetch)
- ``POST git-receive-pack`` (push)

and forwards each to the tenant's Forgejo with the tenant's service token,
never the caller's credential. Nothing else is served: no dumb HTTP, no LFS.

A push is checked before anything reaches Forgejo. The command list that
opens the request (``<old> <new> <ref>``) must update only the credential's
branch: no other ref, no tag, no new branch, no deletion. A refused push is
answered in git's own report-status format, so the client prints the reason
(`` ! [remote rejected] ... (<reason>)``). Forgejo's branch protection still
decides what the push may change (the lane's file patterns, force pushes).
A read-only credential (``access="read"``, no branch) is refused every
receive-pack route before anything is forwarded.

Each push writes an audit attempt event before it is forwarded (refused if
the audit can't be written) and an outcome event after. A clone or fetch is
recorded once, at its ``info/refs`` request, which every git fetch starts
with: one event per fetch, not one per negotiation round.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import re
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import anyio
import httpx
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response, StreamingResponse

from . import validation
from .audit import AuditUnavailable, new_event, redact, who
from .auth import Principal
from .limits import RateLimited
from .store import GitToken
from .tenancy import UnknownTenant

if TYPE_CHECKING:
    from .tools import Services

log = logging.getLogger("alasin_mcp.git")

GIT_PREFIX = "/git/"
_ROUTE = re.compile(
    r"^/git/(?P<owner>[^/]+)/(?P<name>[^/]+)\.git/"
    r"(?P<rest>info/refs|git-upload-pack|git-receive-pack)$"
)
_SERVICES = frozenset({"git-upload-pack", "git-receive-pack"})
ZERO_SHA = re.compile(r"0{40}|0{64}")
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_PKT_LEN = re.compile(rb"[0-9a-f]{4}")
# The command list of one push: a few lines per ref. Far more than any real
# push to one branch needs, and a bound on what is buffered before the check.
MAX_COMMAND_BYTES = 64 * 1024
MAX_PKT = 65520
# Request headers passed on to Forgejo; everything else (Authorization,
# cookies, forwarding headers) stays here.
_FORWARD_REQUEST = ("content-type", "content-encoding", "accept", "git-protocol", "user-agent")
_FORWARD_RESPONSE = ("content-type", "cache-control", "expires", "pragma")
_TIMEOUT = httpx.Timeout(300.0, connect=10.0, pool=10.0)
# Failed credential checks one client address may make per minute.
AUTH_FAILURES_PER_MINUTE = 30
# At most one audited git-upload-pack POST per credential in this many seconds.
FETCH_AUDIT_WINDOW = 60.0


class ProtocolError(ValueError):
    """A malformed or unsupported request."""


@dataclass(frozen=True)
class RefCommand:
    old: str
    new: str
    ref: str


@dataclass(frozen=True)
class PushHead:
    """The opening of a receive-pack request, up to (not including) the pack."""

    commands: tuple[RefCommand, ...]
    capabilities: frozenset[str]
    length: int  # bytes of the request taken by the command list


def parse_push_head(buf: bytes) -> PushHead | None:
    """Parse the command list at the start of a receive-pack request.

    Returns None while ``buf`` holds only part of it (read more and call
    again); raises ProtocolError on anything malformed or unsupported.
    """
    pos = 0
    commands: list[RefCommand] = []
    caps: frozenset[str] = frozenset()
    while True:
        if len(buf) - pos < 4:
            if len(buf) > MAX_COMMAND_BYTES:
                raise ProtocolError("the push's command list is too long")
            return None
        if not _PKT_LEN.fullmatch(buf[pos : pos + 4]):
            raise ProtocolError("malformed pkt-line length")
        size = int(buf[pos : pos + 4], 16)
        if size == 0:  # flush: end of the command list
            if not commands:
                raise ProtocolError("the push names no refs")
            return PushHead(tuple(commands), caps, pos + 4)
        if size < 4 or size > MAX_PKT:
            raise ProtocolError("unsupported pkt-line")
        if pos + size > MAX_COMMAND_BYTES:
            raise ProtocolError("the push's command list is too long")
        if len(buf) < pos + size:
            return None
        line = buf[pos + 4 : pos + size]
        pos += size
        if line.endswith(b"\n"):
            line = line[:-1]
        if line.startswith(b"shallow "):
            raise ProtocolError("pushes from a shallow clone are not supported")
        if line.startswith(b"push-cert"):
            raise ProtocolError("signed pushes are not supported")
        if not commands:
            line, _, raw_caps = line.partition(b"\0")
            caps = frozenset(raw_caps.decode("ascii", "replace").split())
        elif b"\0" in line:
            raise ProtocolError("malformed ref command")
        parts = line.split(b" ")
        if len(parts) != 3:
            raise ProtocolError("malformed ref command")
        try:
            old, new, ref = (p.decode("ascii") for p in parts)
        except UnicodeDecodeError:
            raise ProtocolError("malformed ref command") from None
        if not _SHA.fullmatch(old) or not _SHA.fullmatch(new):
            raise ProtocolError("malformed object id in ref command")
        commands.append(RefCommand(old, new, ref))


# Capabilities a push may ask for, by name (the part before any '='). git
# matches "name=value" as well as "name", so anything else, push-options in
# particular (Forgejo applies options such as repo.private on post-receive,
# as the service account), is refused rather than filtered.
ALLOWED_CAPABILITIES = frozenset(
    {
        "report-status",
        "report-status-v2",
        "side-band-64k",
        "side-band",
        "quiet",
        "atomic",
        "ofs-delta",
        "agent",
        "object-format",
        "session-id",
    }
)


def refusal(head: PushHead, branch: str) -> str | None:
    """Why this push may not go through, or None."""
    want = f"refs/heads/{branch}"
    for cap in head.capabilities:
        name = cap.partition("=")[0]
        if name not in ALLOWED_CAPABILITIES:
            return f"the '{name[:40]}' capability is not supported (push options included)"
    for c in head.commands:
        if c.ref != want:
            return f"only {want} may be pushed with this access"
        if ZERO_SHA.fullmatch(c.new):
            return "branches can't be deleted"
        if ZERO_SHA.fullmatch(c.old):
            return "the branch must exist first: ask for git access again"
    return None


def pkt(data: bytes) -> bytes:
    return f"{len(data) + 4:04x}".encode() + data


def report_refused(head: PushHead, reason: str) -> bytes:
    """A receive-pack result refusing every ref, in the client's chosen format."""
    report = pkt(b"unpack ok\n")
    for c in head.commands:
        report += pkt(f"ng {c.ref} {reason}\n".encode())
    report += b"0000"
    caps = head.capabilities
    if "side-band-64k" in caps or "side-band" in caps:
        step = 65515 if "side-band-64k" in caps else 995
        out = pkt(b"\x02" + f"alasin: push refused: {reason}\n".encode())
        for i in range(0, len(report), step):
            out += pkt(b"\x01" + report[i : i + step])
        return out + b"0000"
    return report


def credential(request: Request) -> str | None:
    """The password of HTTP Basic auth, which is where git puts our token."""
    raw = request.headers.get("authorization", "")
    scheme, _, value = raw.partition(" ")
    if scheme.lower() != "basic" or not value:
        return None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode()
    except (binascii.Error, UnicodeDecodeError):
        return None
    _, sep, password = decoded.partition(":")
    return password if sep and password else None


def _unauthorized(message: str = "authentication required") -> Response:
    return PlainTextResponse(
        message + "\n", status_code=401, headers={"WWW-Authenticate": 'Basic realm="alasin"'}
    )


class GitProxy:
    """The ``/git/`` routes (app.py mounts ``handle``)."""

    def __init__(self, services: Services):
        self.services = services
        # One push at a time per (tenant, person, repo, branch): minting more
        # credentials for the same branch doesn't get around it.
        self._pushing: set[tuple[str, str, str, str]] = set()
        self._lock = threading.Lock()
        # Failed credential checks per client address, so guessing costs
        # something before the hash and the database lookup. Successful
        # requests don't count: claude.ai sandboxes share egress addresses.
        self._failures: dict[str, tuple[float, float]] = {}
        # When each credential last had a git-upload-pack POST audited
        # (protocol v2 fetches skip info/refs; see _fetch_audit_due).
        self._fetch_audited: dict[str, float] = {}

    def _failed(self, ip: str, now: float) -> bool:
        """Count a failed credential check from ``ip``; return whether the
        address is now over its budget (answer 429 rather than 401). Only
        failures count and only failures are throttled: a valid credential
        from the same (shared) address always gets through."""
        rate = float(AUTH_FAILURES_PER_MINUTE)
        with self._lock:
            tokens, last = self._failures.get(ip, (rate, now))
            tokens = min(rate, tokens + (now - last) * rate / 60)
            over = tokens < 1.0
            self._failures[ip] = (max(tokens - 1.0, 0.0), now)
            if len(self._failures) > 10_000:  # bound memory: drop the oldest half
                for k in sorted(self._failures, key=lambda k: self._failures[k][1])[:5_000]:
                    del self._failures[k]
        return over

    def _fetch_audit_due(self, token_sha: str, now: float) -> bool:
        """Whether this git-upload-pack POST gets its own audit event: the first
        per credential in each FETCH_AUDIT_WINDOW. A protocol v2 client can fetch
        with POSTs alone (ls-refs, fetch), never calling info/refs; one event per
        window records every such fetch without one event per negotiation round."""
        with self._lock:
            last = self._fetch_audited.get(token_sha)
            if last is not None and now - last < FETCH_AUDIT_WINDOW:
                return False
            self._fetch_audited[token_sha] = now
            if len(self._fetch_audited) > 10_000:
                cutoff = now - FETCH_AUDIT_WINDOW
                self._fetch_audited = {k: v for k, v in self._fetch_audited.items() if v > cutoff}
            return True

    async def handle(self, request: Request) -> Response:
        m = _ROUTE.match(request.url.path)
        if m is None:
            return PlainTextResponse("not found\n", status_code=404)
        rest = m.group("rest")
        if rest == "info/refs":
            # Exactly one service, read the same way here as the upstream will:
            # Starlette and Go disagree on which of two repeated values counts.
            services = request.query_params.getlist("service")
            if request.method != "GET" or len(services) != 1 or services[0] not in _SERVICES:
                return PlainTextResponse("only git's smart HTTP is served\n", status_code=403)
            service = services[0]
        elif request.method != "POST":
            return PlainTextResponse("method not allowed\n", status_code=405)
        else:
            service = rest
        try:
            repo = validation.repo(f"{m.group('owner')}/{m.group('name')}")
        except validation.InvalidInput:
            return PlainTextResponse("not found\n", status_code=404)
        now = time.monotonic()
        token = credential(request)
        # Always looked up (a SHA-256 and a primary-key read): a valid
        # credential is never held back by others' failures at a shared address.
        grant = self.services.store.get_git_token(token) if token else None
        if grant is None:
            ip = self.services.client_ip.client_ip(request) or "unknown"
            if token and self._failed(ip, now):
                return PlainTextResponse("too many failed attempts; wait a minute\n", 429)
            return _unauthorized(
                "authentication required: ask Claude for git access again (it expires)"
                if token
                else "authentication required"
            )
        if grant.repo.casefold() != repo.full_name.casefold():
            return PlainTextResponse("this access is for another repository\n", status_code=403)
        principal = Principal(tenant=grant.tenant, subject=grant.subject)
        try:
            tenant = self.services.resolver.resolve(principal)
        except UnknownTenant:
            return _unauthorized()
        cfg = tenant.git_access
        from .tools import repo_allowed  # noqa: PLC0415 - tools imports this module

        if cfg is None or not repo_allowed(tenant, repo.full_name):
            return PlainTextResponse("git access is not available here\n", status_code=403)
        if grant.read_only and service == "git-receive-pack":
            return PlainTextResponse(
                "read-only access: call git_access with access='write' to push\n", 403
            )
        try:
            # Per person, apart from the tool calls' own per-tenant bucket.
            self.services.limiter.check(
                f"git\0{tenant.id}\0{grant.subject}", cfg.requests_per_minute
            )
        except RateLimited as e:
            return PlainTextResponse(f"{e}\n", status_code=429)
        # Never the client's query string: only the validated service.
        upstream = f"{tenant.forgejo_url}/{grant.repo}.git/{rest}"
        if rest == "info/refs":
            upstream += f"?service={service}"
        ctx = _Context(self.services, tenant, grant, request, upstream, cfg.max_push_bytes)
        if rest == "info/refs":
            if service == "git-upload-pack":
                return await ctx.forward_audited("git_fetch", request.stream())
            return await ctx.forward(request.stream())
        if service == "git-upload-pack":
            assert token is not None
            if self._fetch_audit_due(hashlib.sha256(token.encode()).hexdigest(), now):
                return await ctx.forward_audited("git_fetch", request.stream())
            return await ctx.forward(request.stream())
        # The branch must still be this person's: ownership can move (a
        # restored state, a re-registered branch) after the credential was made.
        owner = self.services.store.branch_owner(tenant.id, grant.repo, grant.branch)
        if owner != grant.subject:
            return PlainTextResponse("this branch is no longer yours to push\n", 403)
        key = (tenant.id, grant.subject, grant.repo.casefold(), grant.branch)
        with self._lock:
            if key in self._pushing:
                return PlainTextResponse("a push to this branch is already running\n", 429)
            self._pushing.add(key)

        def release() -> None:
            with self._lock:
                self._pushing.discard(key)

        try:
            response = await ctx.push(release)
        except BaseException:
            release()
            raise
        return response


class _BodyTooLarge(Exception):
    pass


class _Finishing(StreamingResponse):
    """A streamed response whose ``finish`` always runs, even when the client
    disconnected before the body was iterated (Starlette never starts the
    iterator then, so a ``finally`` inside it would not run)."""

    def __init__(
        self,
        content: AsyncIterator[bytes],
        finish: Callable[[], Awaitable[None]],
        **kw: Any,
    ):
        super().__init__(content, **kw)
        self._finish = finish
        self._finished = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            await self.finish()

    async def finish(self) -> None:
        if not self._finished:
            self._finished = True
            await self._finish()


class _Context:
    def __init__(
        self,
        services: Services,
        tenant: Any,
        grant: GitToken,
        request: Request,
        upstream: str,
        max_bytes: int,
    ):
        self.services = services
        self.tenant = tenant
        self.grant = grant
        self.request = request
        self.upstream = upstream
        self.max_bytes = max_bytes
        principal = Principal(
            tenant=grant.tenant, subject=grant.subject, idp_subject=grant.idp_subject
        )
        self.event = new_event(
            tenant=grant.tenant,
            **who(principal),
            client_ip=services.client_ip.client_ip(request),
            session_id=grant.session_id,
            repo=grant.repo,
            branch=grant.branch,
        )

    def _headers(self) -> dict[str, str]:
        out = {k: v for k in _FORWARD_REQUEST if (v := self.request.headers.get(k)) is not None}
        # Forgejo takes a token as the Basic user name; the caller's own
        # credential never leaves this server.
        token = self.tenant.service_token.resolve()
        out["authorization"] = "Basic " + base64.b64encode(f"{token}:".encode()).decode()
        return out

    async def _emit(self, event: dict[str, Any], *, required: bool) -> None:
        try:
            await anyio.to_thread.run_sync(self.services.audit_sink.emit, redact(event))
        except Exception as e:
            if required:
                raise AuditUnavailable("the audit trail is unavailable") from e
            log.exception("git audit outcome event could not be recorded")

    async def forward(self, body: AsyncIterator[bytes], on_done: Any = None) -> Response:
        http = httpx.AsyncClient(
            timeout=_TIMEOUT, follow_redirects=False, transport=self.services.transport
        )
        try:
            req = http.build_request(
                self.request.method, self.upstream, headers=self._headers(), content=body
            )
            resp = await http.send(req, stream=True)
        except _BodyTooLarge:
            await http.aclose()
            if on_done is not None:
                await on_done(413)
            return PlainTextResponse("the push is too large\n", status_code=413)
        except httpx.HTTPError as e:
            await http.aclose()
            if on_done is not None:
                await on_done(502)
            log.warning("git upstream unreachable: %s", type(e).__name__)
            return PlainTextResponse("Forgejo is unreachable\n", status_code=502)
        headers = {k: v for k in _FORWARD_RESPONSE if (v := resp.headers.get(k)) is not None}
        state = {"ok": False}

        async def stream() -> AsyncIterator[bytes]:
            async for chunk in resp.aiter_raw():
                yield chunk
            state["ok"] = True

        async def finish() -> None:
            # Runs once, however the response ends: streamed in full, cut
            # off, or never started because the client had already gone.
            with anyio.CancelScope(shield=True):
                try:
                    await resp.aclose()
                    await http.aclose()
                finally:
                    if on_done is not None:
                        await on_done(resp.status_code if state["ok"] else 499)

        return _Finishing(stream(), finish, status_code=resp.status_code, headers=headers)

    async def forward_audited(self, action: str, body: AsyncIterator[bytes]) -> Response:
        async def done(status: int) -> None:
            outcome = "ok" if 200 <= status < 300 else "error"
            await self._emit(
                {**self.event, "phase": "outcome", "action": action, "status": status,
                 "outcome": outcome},
                required=False,
            )  # fmt: skip

        return await self.forward(body, done)

    async def push(self, release: Callable[[], None]) -> Response:
        """Check and forward one push. ``release`` frees the branch's push slot;
        it is called exactly once, when the push is over (answered, refused,
        or the client went away)."""
        try:
            response = await self._push(release)
        except BaseException:
            release()
            raise
        if not isinstance(response, _Finishing):
            release()
        return response

    async def _push(self, release: Callable[[], None]) -> Response:
        length = self.request.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > self.max_bytes:
            return PlainTextResponse("the push is too large\n", status_code=413)
        if self.request.headers.get("content-encoding", "identity") not in ("identity", ""):
            return PlainTextResponse("compressed push requests are not supported\n", 415)
        chunks = self.request.stream()
        buf = b""
        head: PushHead | None = None
        try:
            async for chunk in chunks:
                buf += chunk
                head = parse_push_head(buf)
                if head is not None:
                    break
                if len(buf) > MAX_COMMAND_BYTES:
                    raise ProtocolError("the push's command list is too long")
            if head is None:
                head = parse_push_head(buf)
            if head is None:
                raise ProtocolError("the push request ended early")
        except ProtocolError as e:
            await self._drain(chunks, len(buf))
            return PlainTextResponse(f"{e}\n", status_code=400)
        refs = [{"old_sha": c.old, "new_sha": c.new} for c in head.commands]
        reason = refusal(head, self.grant.branch)
        if reason is not None:
            await self._drain(chunks, len(buf))
            await self._emit(
                {**self.event, "phase": "outcome", "action": "git_push", "refs": refs,
                 "outcome": "error", "error": reason, "error_kind": "policy"},
                required=False,
            )  # fmt: skip
            if not head.capabilities & {"report-status", "report-status-v2"}:
                return PlainTextResponse(f"push refused: {reason}\n", status_code=403)
            return Response(
                report_refused(head, reason),
                media_type="application/x-git-receive-pack-result",
                headers={"cache-control": "no-cache"},
            )
        try:
            await self._emit(
                {**self.event, "phase": "attempt", "action": "git_push", "refs": refs},
                required=True,
            )
        except AuditUnavailable:
            await self._drain(chunks, len(buf))
            return PlainTextResponse("the audit trail is unavailable; nothing was pushed\n", 503)

        max_bytes = self.max_bytes

        async def body() -> AsyncIterator[bytes]:
            total = len(buf)
            yield buf
            async for chunk in chunks:
                total += len(chunk)
                if total > max_bytes:
                    raise _BodyTooLarge
                yield chunk

        async def done(status: int) -> None:
            outcome = "ok" if 200 <= status < 300 else "error"
            try:
                await self._emit(
                    {**self.event, "phase": "outcome", "action": "git_push", "refs": refs,
                     "status": status, "outcome": outcome},
                    required=False,
                )  # fmt: skip
            finally:
                release()

        return await self.forward(body(), done)

    async def _drain(self, chunks: AsyncIterator[bytes], seen: int) -> None:
        """Read what is left of the request (bounded) so the client gets our answer."""
        total = seen
        try:
            async for chunk in chunks:
                total += len(chunk)
                if total > self.max_bytes:
                    return
        except Exception:  # noqa: BLE001 - the client went away; nothing to drain
            return
