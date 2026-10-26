# SPDX-License-Identifier: Apache-2.0
"""Test harness: run the app on a local port and call it as an MCP client."""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio
import httpx
import httpx2
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from opentelemetry import context as otel_context
from opentelemetry import propagate
from starlette.applications import Starlette

from alasin_mcp.config import SecretRef, TenantConfig

CALL_TIMEOUT = 20.0


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def serve(app: Starlette) -> Iterator[str]:
    """Run ``app`` under uvicorn in a thread; yield its /mcp URL."""
    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError("test server did not start")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@dataclass
class ToolResult:
    is_error: bool
    data: dict[str, Any] | None
    text: str


async def call_tool(
    url: str,
    token: str | None,
    tool: str,
    arguments: dict[str, Any],
    meta: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> ToolResult:
    hdrs = dict(headers or {})
    if token is not None:
        hdrs["Authorization"] = f"Bearer {token}"
    # The SDK client injects the current span's traceparent into _meta
    # (SEP-414), replacing any given here; so run the call inside that trace.
    token_ctx = None
    if meta and "traceparent" in meta:
        token_ctx = otel_context.attach(propagate.extract(meta))
    try:
        with anyio.fail_after(CALL_TIMEOUT):
            async with httpx2.AsyncClient(headers=hdrs, timeout=CALL_TIMEOUT) as http:
                async with streamable_http_client(url, http_client=http) as (read, write, *_):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        r = await session.call_tool(tool, arguments, meta=meta)  # type: ignore[arg-type]
    finally:
        if token_ctx is not None:
            otel_context.detach(token_ctx)
    text = "".join(getattr(c, "text", "") for c in r.content)
    data = r.structured_content
    if data is None and not r.is_error:
        data = json.loads(text)
    return ToolResult(bool(r.is_error), data, text)


async def list_tools(url: str, token: str) -> list[Any]:
    with anyio.fail_after(CALL_TIMEOUT):
        async with httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, timeout=CALL_TIMEOUT
        ) as http:
            async with streamable_http_client(url, http_client=http) as (read, write, *_):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return list((await session.list_tools()).tools)


def tenant(tid: str, url: str, env: str, **kw: Any) -> TenantConfig:
    kw.setdefault("repos", ("*/*",))
    return TenantConfig(id=tid, forgejo_url=url, service_token=SecretRef(env=env), **kw)


# -- a fake Forgejo for unit and isolation tests -------------------------------------------


@dataclass
class FakeRepo:
    default_branch: str = "main"
    branches: dict[str, dict[str, bytes]] = field(default_factory=dict)
    protected: set[str] = field(default_factory=set)
    commits: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Recorded:
    host: str
    method: str
    path: str
    token: str
    body: Any


class FakeForgejo:
    """Several Forgejo hosts behind one httpx transport, recording every request."""

    def __init__(self) -> None:
        self.hosts: dict[str, dict[str, Any]] = {}
        self.requests: list[Recorded] = []

    def add_host(self, host: str, token: str, login: str, repos: dict[str, FakeRepo]) -> None:
        self.hosts[host] = {"token": token, "login": login, "repos": repos}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        token = auth.removeprefix("token ")
        body: Any = json.loads(request.content) if request.content else None
        path = request.url.path
        self.requests.append(Recorded(request.url.host, request.method, path, token, body))
        host = self.hosts.get(request.url.host)
        if host is None:
            return httpx.Response(502, json={"message": "unknown host"})
        if token != host["token"]:
            return httpx.Response(401, json={"message": "bad token"})
        prefix = "/api/v1"
        if not path.startswith(prefix):
            return httpx.Response(404, json={"message": "not found"})
        parts = path[len(prefix) :].strip("/").split("/")
        repos: dict[str, FakeRepo] = host["repos"]
        if parts == ["user"]:
            return httpx.Response(
                200, json={"login": host["login"], "full_name": "", "email": "bot@example.com"}
            )
        if parts == ["user", "repos"]:
            page = int(request.url.params.get("page", "1"))
            items = [
                {"full_name": k, "default_branch": v.default_branch, "description": ""}
                for k, v in repos.items()
            ]
            return httpx.Response(200, json=items if page == 1 else [])
        if len(parts) < 3 or parts[0] != "repos":
            return httpx.Response(404, json={"message": "not found"})
        full = f"{parts[1]}/{parts[2]}"
        repo = repos.get(full)
        if repo is None:
            return httpx.Response(404, json={"message": "repo not found"})
        rest = parts[3:]
        ref = request.url.params.get("ref") or repo.default_branch
        if not rest:
            return httpx.Response(
                200, json={"full_name": full, "default_branch": repo.default_branch}
            )
        if rest == ["branches"] and request.method == "GET":
            page = int(request.url.params.get("page", "1"))
            items = [
                {"name": b, "protected": b in repo.protected, "commit": {"id": "0" * 40}}
                for b in repo.branches
            ]
            return httpx.Response(200, json=items if page == 1 else [])
        if rest == ["branches"] and request.method == "POST":
            new, old = body["new_branch_name"], body["old_ref_name"]
            repo.branches[new] = dict(repo.branches[old])
            return httpx.Response(201, json={"name": new, "commit": {"id": "1" * 40}})
        if rest[0] == "branches" and request.method == "GET":
            name = "/".join(rest[1:])
            if name not in repo.branches:
                return httpx.Response(404, json={"message": "no branch"})
            return httpx.Response(
                200,
                json={
                    "name": name,
                    "protected": name in repo.protected,
                    "user_can_push": name not in repo.protected,
                },
            )
        if rest == ["contents"] and request.method == "POST":
            files = repo.branches[body["branch"]]
            for op in body["files"]:
                files[op["path"]] = base64.b64decode(op["content"])
            sha = f"{len(repo.commits):040d}"
            author = body.get("author") or {"name": host["login"], "email": "bot@example.com"}
            committer = body.get("committer") or author
            repo.commits.append(body)
            return httpx.Response(
                201, json={"commit": {"sha": sha, "author": author, "committer": committer}}
            )
        if rest[0] == "contents" and request.method == "GET":
            files = repo.branches.get(ref, {})
            p = "/".join(rest[1:])
            if p in files:
                data = files[p]
                return httpx.Response(
                    200,
                    json={
                        "type": "file",
                        "path": p,
                        "name": p.rsplit("/", 1)[-1],
                        "sha": f"sha-{p}",
                        "size": len(data),
                        "content": base64.b64encode(data).decode(),
                    },
                )
            children = [k for k in files if k.startswith(p + "/") or not p]
            if children:
                return httpx.Response(
                    200,
                    json=[{"name": c, "path": c, "type": "file", "size": 1} for c in children],
                )
            return httpx.Response(404, json={"message": "not found"})
        if rest[0] == "raw":
            files = repo.branches.get(ref, {})
            p = "/".join(rest[1:])
            if p in files:
                return httpx.Response(200, content=files[p])
            return httpx.Response(404, json={"message": "not found"})
        if rest[0] == "compare":
            return httpx.Response(200, json={"commits": [], "files": [], "total_commits": 0})
        return httpx.Response(404, json={"message": "unhandled"})
