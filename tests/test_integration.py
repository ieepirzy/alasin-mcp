# SPDX-License-Identifier: Apache-2.0
"""End to end against a real Forgejo (tests/forgejo.py): MCP client → server → Forgejo."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest

from alasin_mcp.app import build_app
from alasin_mcp.audit import MemoryAuditSink
from alasin_mcp.auth import Principal
from alasin_mcp.config import AuthMode, AuthorSource, TenantConfig
from alasin_mcp.credentials import ModeRouter, ServiceAccountProvider
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.tenancy import StaticTenantResolver
from alasin_mcp.tools import Services
from tests import forgejo as fj
from tests.harness import call_tool, serve, tenant

pytestmark = [pytest.mark.anyio, pytest.mark.forgejo, pytest.mark.timeout(240)]

TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


@pytest.fixture(scope="module")
def forgejo() -> Iterator[fj.Forgejo]:
    name, instance = fj.start()
    try:
        yield instance
    finally:
        fj.stop(name)


class Recording(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.inner = httpx.AsyncHTTPTransport()
        self.seen: list[tuple[str, str, str]] = []
        self.methods: list[tuple[str, str]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "").removeprefix("token ")
        self.seen.append((request.url.netloc.decode(), request.url.path, auth))
        self.methods.append((request.method, request.url.path))
        return await self.inner.handle_async_request(request)


class StaticPrincipalVerifier:
    """Maps fixed client tokens to full principals (with name/email claims)."""

    def __init__(self, table: dict[str, Principal]):
        self.table = table

    async def verify(self, token: str) -> Principal | None:
        return self.table.get(token)


@contextmanager
def server(
    forgejo: fj.Forgejo, monkeypatch: pytest.MonkeyPatch, **tenant_kw: Any
) -> Iterator[tuple[str, Recording, MemoryAuditSink]]:
    monkeypatch.setenv("IT_BOT_TOKEN", forgejo.bot_token)
    monkeypatch.setenv("IT_ADMIN_TOKEN", forgejo.admin_token)
    tenant_kw.setdefault("repos", ("acme/site",))
    tenants: list[TenantConfig] = [
        tenant("a", forgejo.url, "IT_BOT_TOKEN", **tenant_kw),
        tenant("b", forgejo.alt_url, "IT_ADMIN_TOKEN", repos=("root/*",)),
    ]
    rec, audit = Recording(), MemoryAuditSink()
    services = Services(
        resolver=StaticTenantResolver(tenants),
        credentials=ModeRouter({AuthMode.SERVICE_ACCOUNT: ServiceAccountProvider()}),
        store=Store(":memory:", LocalKeyWrapper(os.urandom(32))),
        audit_sink=audit,
        transport=rec,
    )
    verifier = StaticPrincipalVerifier(
        {
            "tok-a": Principal("a", "gateway", "Jane Doe", "jane@example.com", email_verified=True),
            "tok-b": Principal("b", "gateway"),
        }
    )
    with serve(build_app(services, verifier)) as url:
        yield url, rec, audit


async def ok(url: str, tool: str, args: dict[str, Any], **kw: Any) -> dict[str, Any]:
    r = await call_tool(url, kw.pop("token", "tok-a"), tool, args, **kw)
    assert not r.is_error, r.text
    assert r.data is not None
    return r.data


async def err(url: str, tool: str, args: dict[str, Any], token: str = "tok-a") -> str:
    r = await call_tool(url, token, tool, args)
    assert r.is_error, r.data
    return r.text


async def test_full_change_flow(forgejo, monkeypatch, spans) -> None:
    with server(forgejo, monkeypatch) as (url, rec, audit):
        s = await ok(url, "begin_change", {"intent": "new copy"}, meta={"traceparent": TRACEPARENT})
        sid = s["session_id"]
        # The session's trace is minted by the server; the client's traceparent
        # is linked, not adopted, so a client can't choose the Trace-Id trailer.
        client_trace = "0af7651916cd43dd8448eb211c80319c"
        assert s["trace_id"] != client_trace
        begin = [x for x in spans.get_finished_spans() if x.name == "alasin.begin_change"]
        assert begin[-1].parent is None
        assert [format(link.context.trace_id, "032x") for link in begin[-1].links] == [client_trace]
        repos = await ok(url, "list_repos", {"session_id": sid})
        assert [r["repo"] for r in repos["repos"]] == ["acme/site"]  # acme/other not allowlisted
        base = {"session_id": sid, "repo": "acme/site"}
        br = await ok(url, "list_branches", base)
        assert br["default_branch"] == "main"
        assert {"main", "frozen"} <= {b["name"] for b in br["branches"]}
        root = await ok(url, "list_folder", base)
        assert {"index.html", "css"} <= {e["name"] for e in root["entries"]}
        f = await ok(url, "read_file", {**base, "path": "index.html"})
        assert f["content"] == "<h1>Hi</h1>\n" and f["encoding"] == "utf-8"
        await ok(url, "create_branch", {**base, "branch": "lane/copy"})
        c = await ok(
            url,
            "commit_files",
            {
                **base,
                "branch": "lane/copy",
                "message": "Update the headline",
                "files": [
                    {"path": "index.html", "content": "<h1>Hello</h1>\n"},
                    {"path": "about/index.html", "content": "<p>About</p>\n"},
                ],
            },
        )
        assert {x["path"]: x["operation"] for x in c["files"]} == {
            "index.html": "update",
            "about/index.html": "create",
        }
        assert c["trace_id"] == s["trace_id"]
        # Service-account mode by default: the bot authors and commits.
        assert c["author"] == c["committer"] == "Alasin Bot <alasin-bot@example.com>"
        d = await ok(url, "diff_branch", {**base, "branch": "lane/copy"})
        assert d["base"] == "main" and len(d["commits"]) == 1
        message = d["commits"][0]["message"]
        assert "Co-Authored-By: Claude <noreply@anthropic.com>" in message
        assert f"Trace-Id: {s['trace_id']}" in message
        assert f"Alasin-Session: {sid}" in message
        diffs = {x["path"]: x["diff"] for x in d["files"]}
        assert "-<h1>Hi</h1>" in diffs["index.html"] and "+<h1>Hello</h1>" in diffs["index.html"]
        assert "+<p>About</p>" in diffs["about/index.html"]
        # Reading the branch shows the commit.
        f2 = await ok(url, "read_file", {**base, "path": "index.html", "ref": "lane/copy"})
        assert f2["content"] == "<h1>Hello</h1>\n"
        # Unchanged content is not committed again.
        text = await err(
            url,
            "commit_files",
            {
                **base,
                "branch": "lane/copy",
                "message": "again",
                "files": [{"path": "index.html", "content": "<h1>Hello</h1>\n"}],
            },
        )
        assert "no changes" in text
    # Every Forgejo request went to tenant A's host with the bot token.
    assert rec.seen and all(
        h == f"127.0.0.1:{forgejo.port}" and t == forgejo.bot_token for h, _, t in rec.seen
    )
    events = [e for e in audit.events if e["tool"] == "commit_files" and e.get("outcome") == "ok"]
    assert events[0]["commit"] == c["commit"]
    assert events[0]["branch"] == "lane/copy" and events[0]["repo"] == "acme/site"
    assert events[0]["trace_id"] == s["trace_id"]
    recorded = events[0]["arguments"]["files"]
    assert all("content" not in f and f["content_sha256"] for f in recorded)
    # One work session is one trace.
    tool_spans = [x for x in spans.get_finished_spans() if x.name.startswith("alasin.")]
    assert tool_spans and {format(x.context.trace_id, "032x") for x in tool_spans} == {
        s["trace_id"]
    }


async def test_writes_to_default_and_protected_branches_are_refused(forgejo, monkeypatch) -> None:
    with server(forgejo, monkeypatch) as (url, rec, _):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        base = {"session_id": sid, "repo": "acme/site"}
        files = [{"path": "x.txt", "content": "x"}]
        for branch in ("main", "refs/heads/main", "master", "release/1"):
            assert "branch" in await err(url, "create_branch", {**base, "branch": branch})
        text = await err(
            url, "commit_files", {**base, "branch": "main", "message": "m", "files": files}
        )
        assert "default branch" in text
        text = await err(
            url, "commit_files", {**base, "branch": "frozen", "message": "m", "files": files}
        )
        assert "protected in Forgejo" in text
        posts = [p for m, p in rec.methods if m == "POST"]
        assert posts == [], posts


async def test_forgejo_protected_file_patterns_are_the_real_gate(forgejo, monkeypatch) -> None:
    with server(forgejo, monkeypatch) as (url, _, audit):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        base = {"session_id": sid, "repo": "acme/site"}
        await ok(url, "create_branch", {**base, "branch": "lane/schema"})
        text = await err(
            url,
            "commit_files",
            {
                **base,
                "branch": "lane/schema",
                "message": "sneak a migration in",
                "files": [{"path": "schema/001.sql", "content": "drop table x;"}],
            },
        )
        assert "403" in text and "protected" in text
        assert audit.events[-1]["outcome"] == "error"


async def test_author_from_token_claims(forgejo, monkeypatch) -> None:
    with server(forgejo, monkeypatch, author_source=AuthorSource.TOKEN_CLAIMS) as (url, _, _a):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        base = {"session_id": sid, "repo": "acme/site"}
        await ok(url, "create_branch", {**base, "branch": "lane/claims"})
        c = await ok(
            url,
            "commit_files",
            {
                **base,
                "branch": "lane/claims",
                "message": "m",
                "files": [{"path": "c.txt", "content": "c"}],
            },
        )
        assert c["author"] == "Jane Doe <jane@example.com>"
        assert c["committer"] == "Alasin Bot <alasin-bot@example.com>"


async def test_author_argument_needs_opt_in(forgejo, monkeypatch) -> None:
    args = {
        "branch": "lane/arg",
        "message": "m",
        "files": [{"path": "d.txt", "content": "d"}],
        "author_name": "Some One",
        "author_email": "some@example.com",
    }
    with server(forgejo, monkeypatch) as (url, _, _a):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        base = {"session_id": sid, "repo": "acme/site"}
        await ok(url, "create_branch", {**base, "branch": "lane/arg"})
        assert "does not accept" in await err(url, "commit_files", {**base, **args})
    with server(forgejo, monkeypatch, author_source=AuthorSource.TOOL_ARGUMENT) as (url, _, _a):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        base = {"session_id": sid, "repo": "acme/site"}
        c = await ok(url, "commit_files", {**base, **args})
        assert c["author"] == "Some One <some@example.com>"
        assert c["committer"] == "Alasin Bot <alasin-bot@example.com>"


async def test_tenant_a_cannot_reach_tenant_b_on_a_real_instance(forgejo, monkeypatch) -> None:
    """B's repo (root/private) exists on the same Forgejo, under B's host name and token."""
    with server(forgejo, monkeypatch) as (url, rec, _):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        for tool, extra in (
            ("list_branches", {}),
            ("read_file", {"path": "README.md"}),
            ("list_folder", {}),
            ("diff_branch", {"branch": "main"}),
            ("create_branch", {"branch": "lane/x"}),
        ):
            for repo in ("root/private", f"localhost:{forgejo.port}/root/private"):
                await err(url, tool, {"session_id": sid, "repo": repo, **extra})
        # B itself can read its repo, through its own host name and token.
        b_sid = (await ok(url, "begin_change", {}, token="tok-b"))["session_id"]
        f = await ok(
            url,
            "read_file",
            {"session_id": b_sid, "repo": "root/private", "path": "README.md"},
            token="tok-b",
        )
        assert "private" in f["content"]
    a_side = [x for x in rec.seen if x[2] == forgejo.bot_token]
    b_side = [x for x in rec.seen if x[2] == forgejo.admin_token]
    assert all(h == f"127.0.0.1:{forgejo.port}" for h, _, _ in a_side)
    assert all(h == f"localhost:{forgejo.port}" for h, _, _ in b_side)
    assert not any("private" in p for _, p, _ in a_side)


async def test_ci_workflow_paths_refused_on_a_real_instance(forgejo, monkeypatch) -> None:
    with server(forgejo, monkeypatch) as (url, rec, _):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        base = {"session_id": sid, "repo": "acme/site"}
        await ok(url, "create_branch", {**base, "branch": "lane/ci"})
        text = await err(
            url,
            "commit_files",
            {
                **base,
                "branch": "lane/ci",
                "message": "add a workflow",
                "files": [{"path": ".forgejo/workflows/x.yml", "content": "on: push\n"}],
            },
        )
        assert "CI workflow" in text
        assert not [p for m, p in rec.methods if m == "POST" and p.endswith("/contents")]
