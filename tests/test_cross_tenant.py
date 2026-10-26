# SPDX-License-Identifier: Apache-2.0
"""Cross-tenant isolation.

Two tenants, each with its own Forgejo host and service token. Every test
here holds a valid token for tenant A and tries to reach tenant B: B's
repository named in an argument, B's host smuggled into an argument, B's
work session, B's cached data, B's stored token. Any request that reaches
B's host, or carries B's token, fails the suite.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import anyio
import pytest

from alasin_mcp.app import build_app
from alasin_mcp.audit import MemoryAuditSink
from alasin_mcp.auth import StaticTokenVerifier
from alasin_mcp.config import AuthMode
from alasin_mcp.credentials import ModeRouter, ServiceAccountProvider
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.tenancy import StaticTenantResolver
from alasin_mcp.tools import TOOL_NAMES, Services
from tests.harness import FakeForgejo, FakeRepo, call_tool, serve, tenant

pytestmark = pytest.mark.anyio

A_HOST, B_HOST = "forgejo-a.example.com", "forgejo-b.example.com"
A_FORGEJO_TOKEN, B_FORGEJO_TOKEN = "forgejo-token-a", "forgejo-token-b"
A_CLIENT, B_CLIENT = "client-token-a", "client-token-b"


@dataclass
class World:
    url: str
    fake: FakeForgejo
    services: Services
    audit: MemoryAuditSink

    def assert_no_b_traffic(self) -> None:
        for r in self.fake.requests:
            if r.token == B_FORGEJO_TOKEN:
                assert r.host == B_HOST
        a_side = [r for r in self.fake.requests if r.token == A_FORGEJO_TOKEN]
        assert all(r.host == A_HOST for r in a_side), a_side

    def b_requests(self) -> list[Any]:
        return [r for r in self.fake.requests if r.host == B_HOST or r.token == B_FORGEJO_TOKEN]


def _repo() -> FakeRepo:
    return FakeRepo(branches={"main": {"README.md": b"hello\n"}})


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("TEST_TOKEN_A", A_FORGEJO_TOKEN)
    monkeypatch.setenv("TEST_TOKEN_B", B_FORGEJO_TOKEN)
    fake = FakeForgejo()
    fake.add_host(A_HOST, A_FORGEJO_TOKEN, "bot-a", {"acme/site": _repo()})
    fake.add_host(B_HOST, B_FORGEJO_TOKEN, "bot-b", {"beta/secret": _repo(), "acme/site": _repo()})
    tenants = [
        tenant("tenant-a", f"https://{A_HOST}", "TEST_TOKEN_A"),
        tenant("tenant-b", f"https://{B_HOST}", "TEST_TOKEN_B"),
    ]
    audit = MemoryAuditSink()
    services = Services(
        resolver=StaticTenantResolver(tenants),
        credentials=ModeRouter({AuthMode.SERVICE_ACCOUNT: ServiceAccountProvider()}),
        store=Store(":memory:", LocalKeyWrapper(os.urandom(32))),
        audit_sink=audit,
        transport=fake.transport(),
    )
    verifier = StaticTokenVerifier(
        [(A_CLIENT, "tenant-a", "gateway"), (B_CLIENT, "tenant-b", "gateway")]
    )
    with serve(build_app(services, verifier)) as url:
        yield World(url, fake, services, audit)


async def _session(url: str, token: str) -> str:
    r = await call_tool(url, token, "begin_change", {"intent": "test"})
    assert not r.is_error, r.text
    assert r.data is not None
    return r.data["session_id"]


# Arguments that try to steer a call at tenant B. Each is fed to every tool.
HOSTILE_REPOS = [
    "beta/secret",
    f"https://{B_HOST}/beta/secret",
    f"{B_HOST}/beta/secret",
    "../../beta/secret",
    "beta/secret/../../x",
    "//forgejo-b.example.com/beta/secret",
]


def _args_for(tool: str, session_id: str, repo: str) -> dict[str, Any]:
    base: dict[str, Any] = {"session_id": session_id, "repo": repo}
    return {
        "begin_change": {"intent": f"work on {repo} at https://{B_HOST}"},
        "list_repos": {"session_id": session_id},
        "list_branches": base,
        "list_folder": {**base, "path": "", "ref": "main"},
        "read_file": {**base, "path": "README.md", "ref": "main"},
        "diff_branch": {**base, "branch": "main"},
        "create_branch": {**base, "branch": "feature-x"},
        "commit_files": {
            **base,
            "branch": "feature-x",
            "message": "x",
            "files": [{"path": "a.txt", "content": "x"}],
        },
    }[tool]


@pytest.mark.parametrize("tool", TOOL_NAMES)
@pytest.mark.parametrize("repo", HOSTILE_REPOS)
async def test_tenant_a_never_reaches_tenant_b(world: World, tool: str, repo: str) -> None:
    sid = await _session(world.url, A_CLIENT)
    await call_tool(world.url, A_CLIENT, tool, _args_for(tool, sid, repo))
    world.assert_no_b_traffic()
    assert world.b_requests() == []


async def test_same_repo_name_resolves_to_own_tenant(world: World) -> None:
    """acme/site exists on both hosts; A's call must read A's copy."""
    sid = await _session(world.url, A_CLIENT)
    r = await call_tool(
        world.url,
        A_CLIENT,
        "read_file",
        {"session_id": sid, "repo": "acme/site", "path": "README.md"},
    )
    assert not r.is_error, r.text
    assert {x.host for x in world.fake.requests} == {A_HOST}


async def test_session_of_tenant_b_is_refused_for_tenant_a(world: World) -> None:
    b_sid = await _session(world.url, B_CLIENT)
    r = await call_tool(world.url, A_CLIENT, "list_repos", {"session_id": b_sid})
    assert r.is_error
    assert "unknown or expired session_id" in r.text
    assert world.fake.requests == []


async def test_session_of_another_subject_is_refused(world: World) -> None:
    sid = await _session(world.url, A_CLIENT)
    s = world.services.store
    assert s.get_session("tenant-a", "gateway", sid) is not None
    assert s.get_session("tenant-a", "someone-else", sid) is None
    assert s.get_session("tenant-b", "gateway", sid) is None


async def test_concurrent_calls_keep_their_tenant(world: World) -> None:
    """Interleaved calls from A and B on one process: each reaches only its own host."""
    a_sid = await _session(world.url, A_CLIENT)
    b_sid = await _session(world.url, B_CLIENT)
    results: dict[str, list[Any]] = {"a": [], "b": []}

    async def run(who: str, token: str, sid: str, repo: str) -> None:
        r = await call_tool(
            world.url, token, "read_file", {"session_id": sid, "repo": repo, "path": "README.md"}
        )
        results[who].append(r)

    async with anyio.create_task_group() as tg:
        for _ in range(8):
            tg.start_soon(run, "a", A_CLIENT, a_sid, "acme/site")
            tg.start_soon(run, "b", B_CLIENT, b_sid, "beta/secret")
    assert all(not r.is_error for r in results["a"] + results["b"])
    for r in world.fake.requests:
        expected = A_FORGEJO_TOKEN if r.host == A_HOST else B_FORGEJO_TOKEN
        assert r.token == expected
    a_paths = {r.path for r in world.fake.requests if r.host == A_HOST}
    assert all("beta" not in p for p in a_paths)


async def test_cache_entries_are_keyed_by_tenant_and_subject(world: World) -> None:
    a_sid = await _session(world.url, A_CLIENT)
    b_sid = await _session(world.url, B_CLIENT)
    for token, sid in ((A_CLIENT, a_sid), (B_CLIENT, b_sid)):
        r = await call_tool(
            world.url, token, "list_branches", {"session_id": sid, "repo": "acme/site"}
        )
        assert not r.is_error, r.text
    keys = world.services.cache.keys()
    assert ("tenant-a", "gateway", "repo", "acme/site") in keys
    assert ("tenant-b", "gateway", "repo", "acme/site") in keys
    # Both tenants looked up acme/site; each must have hit its own host once.
    hits = [(r.host, r.path) for r in world.fake.requests if r.path.endswith("/acme/site")]
    assert sorted(hits) == sorted(
        [(A_HOST, "/api/v1/repos/acme/site"), (B_HOST, "/api/v1/repos/acme/site")]
    )


async def test_audit_events_carry_the_callers_tenant(world: World) -> None:
    sid = await _session(world.url, A_CLIENT)
    await call_tool(
        world.url, A_CLIENT, "list_branches", {"session_id": sid, "repo": "beta/secret"}
    )
    assert world.audit.events
    assert {e["tenant"] for e in world.audit.events} == {"tenant-a"}


async def test_unauthenticated_and_unknown_tokens_get_401(world: World) -> None:
    import httpx

    async with httpx.AsyncClient(timeout=10) as http:
        for headers in ({}, {"Authorization": "Bearer nope"}, {"Authorization": "token x"}):
            resp = await http.post(world.url, headers=headers, json={})
            assert resp.status_code == 401
    assert world.fake.requests == []


async def test_spoofed_principal_headers_are_ignored(world: World) -> None:
    """Headers naming a tenant or subject change nothing."""
    sid = await _session(world.url, A_CLIENT)
    r = await call_tool(
        world.url,
        A_CLIENT,
        "list_repos",
        {"session_id": sid},
        headers={"X-Tenant": "tenant-b", "X-Forwarded-User": "admin"},
    )
    assert not r.is_error
    assert r.data is not None
    assert [x["repo"] for x in r.data["repos"]] == ["acme/site"]
    world.assert_no_b_traffic()


# -- stored tokens (user-delegated mode) ----------------------------------------------------

B_STORED = "b-delegated-access-token"


@pytest.fixture
def delegated_world(monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    from alasin_mcp.config import OAuthAppConfig, SecretRef
    from alasin_mcp.credentials import UserDelegatedProvider

    monkeypatch.setenv("TEST_OAUTH_SECRET", "s")
    fake = FakeForgejo()
    fake.add_host(A_HOST, "a-delegated", "alice", {"acme/site": _repo()})
    fake.add_host(B_HOST, B_STORED, "bob", {"beta/secret": _repo()})

    def oauth(host: str) -> OAuthAppConfig:
        return OAuthAppConfig(
            client_id="cid",
            client_secret=SecretRef(env="TEST_OAUTH_SECRET"),
            redirect_uri=f"https://{host}/cb",
        )

    tenants = [
        tenant("tenant-a", f"https://{A_HOST}", "UNUSED", auth_mode=AuthMode.USER_DELEGATED,
               oauth=oauth(A_HOST)),
        tenant("tenant-b", f"https://{B_HOST}", "UNUSED", auth_mode=AuthMode.USER_DELEGATED,
               oauth=oauth(B_HOST)),
    ]  # fmt: skip
    store = Store(":memory:", LocalKeyWrapper(os.urandom(32)))
    # B's principal has a token; A's principal uses the very same subject string.
    store.put_token("tenant-b", "gateway", {"access_token": B_STORED, "expires_at": 0})
    provider = UserDelegatedProvider(store, {t.id: t for t in tenants}.__getitem__)
    services = Services(
        resolver=StaticTenantResolver(tenants),
        credentials=ModeRouter({AuthMode.USER_DELEGATED: provider}),
        store=store,
        audit_sink=MemoryAuditSink(),
        transport=fake.transport(),
    )

    class WithEmail:
        async def verify(self, token: str):
            from alasin_mcp.auth import Principal

            t = {A_CLIENT: "tenant-a", B_CLIENT: "tenant-b"}.get(token)
            return Principal(t, "gateway", None, "same@example.com") if t else None

    with serve(build_app(services, WithEmail())) as url:
        yield World(url, fake, services, services.audit_sink)  # type: ignore[arg-type]


@pytest.mark.parametrize("tool", [t for t in TOOL_NAMES if t != "begin_change"])
async def test_tenant_a_never_uses_tenant_bs_stored_token(
    delegated_world: World, tool: str
) -> None:
    w = delegated_world
    sid = await _session(w.url, A_CLIENT)
    r = await call_tool(w.url, A_CLIENT, tool, _args_for(tool, sid, "beta/secret"))
    assert r.is_error
    # A has no token of its own: it is sent to A's Forgejo to authorize.
    assert f"https://{A_HOST}/login/oauth/authorize?" in r.text
    assert B_HOST not in r.text
    assert w.fake.requests == []
    assert w.services.store.get_token("tenant-b", "gateway") == {
        "access_token": B_STORED,
        "expires_at": 0,
    }
    # And B itself still works with its own stored token.
    b_sid = await _session(w.url, B_CLIENT)
    ok = await call_tool(
        w.url, B_CLIENT, "list_branches", {"session_id": b_sid, "repo": "beta/secret"}
    )
    assert not ok.is_error, ok.text
    assert {(x.host, x.token) for x in w.fake.requests} == {(B_HOST, B_STORED)}
