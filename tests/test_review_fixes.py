# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the first review round. Each fails without its fix."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from starlette.requests import Request

from alasin_mcp import validation
from alasin_mcp.app import build_app
from alasin_mcp.audit import (
    AuditUnavailable,
    FanoutAuditSink,
    JsonlAuditSink,
    MemoryAuditSink,
)
from alasin_mcp.auth import (
    PRINCIPAL_SCOPE_KEY,
    BearerAuthMiddleware,
    Principal,
    StaticTokenVerifier,
)
from alasin_mcp.config import (
    AuthMode,
    AuthorSource,
    BranchWebhookConfig,
    ConfigError,
    OAuthAppConfig,
    SecretRef,
    TenantConfig,
    parse,
)
from alasin_mcp.credentials import (
    AuthorizationRequired,
    CredentialError,
    ModeRouter,
    UserDelegatedProvider,
)
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.tools import Call, Services
from tests.harness import (
    FakeForgejo,
    FakeRepo,
    call_tool,
    fake_services,
    free_port,
    serve,
    tenant,
)

pytestmark = pytest.mark.anyio

HOST = "forgejo.example.com"
FORGEJO_TOKEN = "forgejo-token"


class StaticPrincipals:
    def __init__(self, table: dict[str, Principal]):
        self.table = table

    async def verify(self, token: str) -> Principal | None:
        return self.table.get(token)


GATEWAY = Principal("t", "gateway", via_gateway=True)
DIRECT = Principal("t", "direct-user", "Direct", "direct@example.com", email_verified=True)
PRINCIPALS = {"gw": GATEWAY, "direct": DIRECT}


def _fake() -> FakeForgejo:
    fake = FakeForgejo()
    fake.add_host(
        HOST,
        FORGEJO_TOKEN,
        "bot",
        {"acme/site": FakeRepo(branches={"main": {"README.md": b"hi\n"}, "work": {}})},
    )
    return fake


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_FORGEJO", FORGEJO_TOKEN)


def _tenant(**kw: Any) -> TenantConfig:
    return tenant("t", f"https://{HOST}", "TEST_FORGEJO", **kw)


class Running:
    def __init__(self, url: str, fake: FakeForgejo, services: Services):
        self.url, self.fake, self.services = url, fake, services

    def posts(self, suffix: str) -> list[Any]:
        return [r for r in self.fake.requests if r.method == "POST" and r.path.endswith(suffix)]


def running(fake: FakeForgejo, sink: Any = None, **tenant_kw: Any) -> Iterator[Running]:
    services = fake_services(fake, [_tenant(**tenant_kw)], sink)
    with serve(build_app(services, StaticPrincipals(PRINCIPALS))) as url:
        yield Running(url, fake, services)


async def _sid(url: str, token: str = "gw") -> str:
    r = await call_tool(url, token, "begin_change", {})
    assert not r.is_error, r.text
    assert r.data is not None
    return r.data["session_id"]


def _commit(sid: str, path: str = "a.txt", branch: str = "work", **kw: Any) -> dict[str, Any]:
    return {
        "session_id": sid,
        "repo": "acme/site",
        "branch": branch,
        "message": "m",
        "files": [{"path": path, "content": "x"}],
        **kw,
    }


# -- 1. audit fails closed ------------------------------------------------------------------


class FailingSink:
    def __init__(self, fail_phase: str):
        self.fail_phase = fail_phase
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        if event.get("phase") == self.fail_phase:
            raise OSError("disk full")
        self.events.append(event)


async def test_write_is_refused_when_the_attempt_cannot_be_audited() -> None:
    for r in running(_fake(), FailingSink("attempt")):
        sid = await _sid(r.url)
        res = await call_tool(r.url, "gw", "commit_files", _commit(sid))
        assert res.is_error and "audit trail is unavailable" in res.text
        assert r.posts("/contents") == []
        res = await call_tool(
            r.url, "gw", "create_branch", {"session_id": sid, "repo": "acme/site", "branch": "n"}
        )
        assert res.is_error
        assert r.posts("/branches") == []


async def test_failed_outcome_event_does_not_turn_a_landed_commit_into_an_error() -> None:
    sink = FailingSink("outcome")
    for r in running(_fake(), sink):
        sid = await _sid(r.url)
        res = await call_tool(r.url, "gw", "commit_files", _commit(sid))
        assert not res.is_error, res.text
        assert len(r.posts("/contents")) == 1
        attempts = [e for e in sink.events if e.get("phase") == "attempt"]
        assert attempts and attempts[-1]["action"] == "commit_files"


def test_fanout_tries_every_sink_then_raises() -> None:
    first, second = FailingSink("outcome"), MemoryAuditSink()
    fan = FanoutAuditSink([first, second])
    with pytest.raises(AuditUnavailable):
        fan.emit({"phase": "outcome", "tenant": "t"})
    assert second.events == [{"phase": "outcome", "tenant": "t"}]


def test_fanout_best_effort_sink_never_refuses() -> None:
    # Fail closed on the local JSONL write only: a broken stderr copy must not
    # refuse a write the durable record holds.
    required, broken = MemoryAuditSink(), FailingSink("attempt")
    FanoutAuditSink([required], best_effort=[broken]).emit({"phase": "attempt", "tenant": "t"})
    assert required.events == [{"phase": "attempt", "tenant": "t"}]


def test_fanout_required_sink_still_refuses_beside_a_working_best_effort() -> None:
    copy = MemoryAuditSink()
    fan = FanoutAuditSink([FailingSink("attempt")], best_effort=[copy])
    with pytest.raises(AuditUnavailable):
        fan.emit({"phase": "attempt", "tenant": "t"})
    assert copy.events == [{"phase": "attempt", "tenant": "t"}]


def test_jsonl_sink_fsyncs_the_line_and_each_new_directory_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[str] = []
    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        synced.append(os.readlink(f"/proc/self/fd/{fd}"))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    sink = JsonlAuditSink(str(tmp_path))
    sink.emit({"tenant": "t", "n": 1})
    [day_file] = list((tmp_path / "t").glob("audit-*.jsonl"))
    # The line, then the tenant folder (new file), then the root (new folder).
    assert synced == [str(day_file), str(tmp_path / "t"), str(tmp_path)]
    synced.clear()
    sink.emit({"tenant": "t", "n": 2})
    # An append to an existing file adds no directory entry.
    assert synced == [str(day_file)]
    assert [json.loads(x)["n"] for x in day_file.read_text().splitlines()] == [1, 2]


def test_jsonl_sink_raises_when_the_line_cannot_be_made_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fsync(fd: int) -> None:
        raise OSError("EIO")

    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(OSError):
        JsonlAuditSink(str(tmp_path)).emit({"tenant": "t"})


def _peer_request(peer: str, headers: dict[str, str] | None = None) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "headers": raw, "client": (peer, 1234)})


def test_client_ip_header_is_believed_only_from_a_trusted_proxy() -> None:
    from alasin_mcp.clientip import ClientIpPolicy

    policy = ClientIpPolicy.from_config("CF-Connecting-IP", ["10.244.0.0/16"])
    tunnel = _peer_request("10.244.3.7", {"CF-Connecting-IP": "203.0.113.9"})
    assert policy.client_ip(tunnel) == "203.0.113.9"
    # Anyone else cannot choose the recorded address.
    outsider = _peer_request("192.0.2.1", {"CF-Connecting-IP": "203.0.113.9"})
    assert policy.client_ip(outsider) == "192.0.2.1"
    # A trusted proxy with no header, or garbage: the peer, never the raw value.
    assert policy.client_ip(_peer_request("10.244.3.7")) == "10.244.3.7"
    bad = _peer_request("10.244.3.7", {"CF-Connecting-IP": "1.2.3.4, 5.6.7.8"})
    assert policy.client_ip(bad) == "10.244.3.7"
    # Unconfigured: the peer.
    assert ClientIpPolicy().client_ip(tunnel) == "10.244.3.7"


def test_audit_dir_is_created_at_startup_and_its_entry_made_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[str] = []
    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        synced.append(os.readlink(f"/proc/self/fd/{fd}"))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    target = tmp_path / "state" / "audit"
    (tmp_path / "state").mkdir()
    JsonlAuditSink(str(target)).ensure_dir()
    assert target.is_dir()
    assert synced == [str(tmp_path / "state")]
    synced.clear()
    JsonlAuditSink(str(target)).ensure_dir()  # already there: nothing to sync
    assert synced == []


async def test_cancelled_call_still_records_its_outcome() -> None:
    sink = MemoryAuditSink()
    services = fake_services(_fake(), [_tenant()], sink)
    request = Request(
        {
            "type": "http",
            "headers": [],
            "client": ("192.0.2.7", 1234),
            PRINCIPAL_SCOPE_KEY: GATEWAY,
        }
    )
    ctx: Any = SimpleNamespace(request_context=SimpleNamespace(request=request, meta=None))

    async def body(call: Call) -> dict[str, Any]:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await services.call(ctx, "begin_change", {}, None, body)
    assert sink.events[-1]["outcome"] == "error"
    assert sink.events[-1]["error_kind"] == "cancelled"
    # 10: the client address is recorded.
    assert sink.events[-1]["client_ip"] == "192.0.2.7"


# -- 2. CI workflow folders --------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [".forgejo/workflows/x.yml", ".gitea/workflows/x.yml", ".github/workflows/x.yml",
     ".GitHub/workflows/x.yml"],
)  # fmt: skip
async def test_ci_folders_are_refused_by_default(path: str) -> None:
    for r in running(_fake()):
        sid = await _sid(r.url)
        res = await call_tool(r.url, "gw", "commit_files", _commit(sid, path))
        assert res.is_error and "CI workflow" in res.text
        assert r.posts("/contents") == []


async def test_ci_folders_allowed_with_opt_in() -> None:
    for r in running(_fake(), allow_ci_paths=True):
        sid = await _sid(r.url)
        res = await call_tool(r.url, "gw", "commit_files", _commit(sid, ".forgejo/w.yml"))
        assert not res.is_error, res.text


# -- 3. trusted author header ------------------------------------------------------------------

HEADER = "x-upstream-author"


async def test_author_header_only_from_the_gateway() -> None:
    kw = {"author_source": AuthorSource.TRUSTED_HEADER, "author_header": HEADER}
    for r in running(_fake(), **kw):
        hdr = {HEADER: "Jane Doe <jane@example.com>"}
        sid = await _sid(r.url, "direct")
        res = await call_tool(r.url, "direct", "commit_files", _commit(sid), headers=hdr)
        assert res.is_error and "only from the configured gateway" in res.text
        assert r.posts("/contents") == []
        sid = await _sid(r.url, "gw")
        res = await call_tool(r.url, "gw", "commit_files", _commit(sid), headers=hdr)
        assert not res.is_error, res.text
        assert r.posts("/contents")[-1].body["author"]["email"] == "jane@example.com"


def test_trusted_header_needs_a_gateway_credential_at_load() -> None:
    raw: dict[str, Any] = {
        "auth": {"static": [{"token_env": "T", "tenant": "t", "subject": "s"}]},
        "tenants": [
            {
                "id": "t",
                "forgejo_url": f"https://{HOST}",
                "service_token_env": "F",
                "author_source": "trusted_header",
                "author_header": HEADER,
            }
        ],
    }
    with pytest.raises(ConfigError, match="gateway = true"):
        parse(raw)
    raw["auth"]["static"][0]["gateway"] = True
    assert parse(raw).static_credentials[0].gateway


async def test_static_gateway_flag_reaches_the_principal() -> None:
    from alasin_mcp.config import StaticCredential

    os.environ["TEST_GW"] = "gw-secret"
    v = StaticTokenVerifier.from_config(
        (StaticCredential(SecretRef(env="TEST_GW"), "t", "gateway", gateway=True),)
    )
    p = await v.verify("gw-secret")
    assert p is not None and p.via_gateway
    plain = await StaticTokenVerifier([("x", "t", "s")]).verify("x")
    assert plain is not None and not plain.via_gateway


# -- 4. OAuth refresh race ------------------------------------------------------------------------

ALICE = Principal("t", "alice", "Alice", "alice@example.com", email_verified=True)


class RotatingOAuth:
    """Each refresh token works once; a second use is invalid_grant."""

    def __init__(self, status: int = 200):
        self.status = status
        self.valid = {"r0"}
        self.issued = 0
        self.lock = threading.Lock()

    async def handle(self, request: httpx.Request) -> httpx.Response:
        # Yield to the event loop so concurrent refreshes really interleave.
        await asyncio.sleep(0.05)
        from urllib.parse import parse_qs

        form = parse_qs(request.content.decode())
        if self.status != 200:
            return httpx.Response(self.status, text="upstream down")
        with self.lock:
            rt = form["refresh_token"][0]
            if rt not in self.valid:
                return httpx.Response(400, json={"error": "invalid_grant"})
            self.valid.discard(rt)
            self.issued += 1
            new = f"r{self.issued}"
            self.valid.add(new)
        return httpx.Response(
            200,
            json={"access_token": f"a{self.issued}", "refresh_token": new, "expires_in": 3600},
        )


def _delegated(oauth: RotatingOAuth) -> tuple[UserDelegatedProvider, Store, TenantConfig]:
    os.environ["TEST_OAUTH_SECRET"] = "s"
    t = TenantConfig(
        id="t",
        forgejo_url=f"https://{HOST}",
        auth_mode=AuthMode.USER_DELEGATED,
        oauth=OAuthAppConfig("cid", SecretRef(env="TEST_OAUTH_SECRET"), "https://x/cb"),
    )
    store = Store(":memory:", LocalKeyWrapper(os.urandom(32)))
    store.put_token(
        "t", "alice", {"access_token": "a0", "refresh_token": "r0", "expires_at": time.time() - 1}
    )
    return (
        UserDelegatedProvider(store, {"t": t}.__getitem__, httpx.MockTransport(oauth.handle)),
        store,
        t,
    )


async def test_concurrent_refreshes_do_not_wipe_the_token() -> None:
    oauth = RotatingOAuth()
    p, store, t = _delegated(oauth)
    results = await asyncio.gather(
        *[p.credential(t, ALICE, None) for _ in range(4)], return_exceptions=True
    )
    assert all(not isinstance(r, BaseException) for r in results), results
    assert {r.token for r in results if not isinstance(r, BaseException)} == {"a1"}
    assert oauth.issued == 1
    assert store.get_token("t", "alice")["access_token"] == "a1"  # type: ignore[index]


async def test_upstream_error_keeps_the_grant() -> None:
    p, store, t = _delegated(RotatingOAuth(status=503))
    with pytest.raises(CredentialError) as e:
        await p.credential(t, ALICE, None)
    assert not isinstance(e.value, AuthorizationRequired)
    assert store.get_token("t", "alice") is not None


async def test_invalid_grant_drops_the_stale_token() -> None:
    oauth = RotatingOAuth()
    oauth.valid.clear()
    p, store, t = _delegated(oauth)
    with pytest.raises(AuthorizationRequired):
        await p.credential(t, ALICE, None)
    assert store.get_token("t", "alice") is None


# -- 5. branch names that read like other refs ----------------------------------------------------


@pytest.mark.parametrize(
    "name", ["refs/heads/refs/heads/main", "heads/main", "refs/tags/v1", "refs/heads/heads/x"]
)
def test_ref_shaped_branch_names_rejected(name: str) -> None:
    with pytest.raises(validation.InvalidInput):
        validation.branch(name)


# -- 6. diff filenames from Forgejo are validated -------------------------------------------------


async def test_diff_skips_unsafe_filenames_from_forgejo() -> None:
    fake = _fake()
    repo = fake.hosts[HOST]["repos"]["acme/site"]
    repo.compare = {
        "commits": [{"sha": "c1", "parents": [{"sha": "base"}], "commit": {"message": "m"}}],
        "files": [
            {"filename": "../../../other/secret/raw/x", "status": "modified"},
            {"filename": "README.md", "status": "modified"},
        ],
    }
    for r in running(fake):
        sid = await _sid(r.url)
        res = await call_tool(
            r.url, "gw", "diff_branch", {"session_id": sid, "repo": "acme/site", "branch": "work"}
        )
        assert not res.is_error, res.text
        assert res.data is not None
        notes = {f["path"]: f.get("note") for f in res.data["files"]}
        assert "skipped" in str(notes["../../../other/secret/raw/x"])
        raw_paths = [x.path for x in fake.requests if "/raw/" in x.path]
        assert raw_paths and all(p.startswith("/api/v1/repos/acme/site/raw/") for p in raw_paths)
        assert not any("other" in p for p in raw_paths)


# -- 7. verified email --------------------------------------------------------------------------


async def test_delegated_binding_needs_verified_email_claim() -> None:
    p, _, t = _delegated(RotatingOAuth())
    unverified = Principal("t", "bob", "Bob", "bob@example.com", email_verified=False)
    with pytest.raises(CredentialError, match="email_verified"):
        p.authorization_url(t, unverified)


async def test_delegated_binding_needs_verified_forgejo_email() -> None:
    os.environ["TEST_OAUTH_SECRET"] = "s"

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": "x", "expires_in": 60})
        if request.url.path == "/api/v1/user/emails":
            return httpx.Response(200, json=[{"email": "alice@example.com", "verified": False}])
        return httpx.Response(200, json={"login": "alice", "email": "alice@example.com"})

    t = TenantConfig(
        id="t",
        forgejo_url=f"https://{HOST}",
        auth_mode=AuthMode.USER_DELEGATED,
        oauth=OAuthAppConfig("cid", SecretRef(env="TEST_OAUTH_SECRET"), "https://x/cb"),
    )
    store = Store(":memory:", LocalKeyWrapper(os.urandom(32)))
    p = UserDelegatedProvider(store, {"t": t}.__getitem__, httpx.MockTransport(handle))
    state = parse_state(p.authorization_url(t, ALICE))
    with pytest.raises(CredentialError, match="does not match"):
        await p.complete(state, "code")
    assert store.get_token("t", "alice") is None


def parse_state(url: str) -> str:
    from urllib.parse import parse_qs, urlparse

    return parse_qs(urlparse(url).query)["state"][0]


async def test_token_claims_author_needs_verified_email() -> None:
    principals = {
        "u": Principal("t", "u", "U", "u@example.com", email_verified=False),
        "v": Principal("t", "v", "V", "v@example.com", email_verified=True),
    }
    fake = _fake()
    services = fake_services(fake, [_tenant(author_source=AuthorSource.TOKEN_CLAIMS)])
    with serve(build_app(services, StaticPrincipals(principals))) as url:
        sid = await _sid(url, "u")
        res = await call_tool(url, "u", "commit_files", _commit(sid))
        assert res.is_error and "email_verified" in res.text
        sid = await _sid(url, "v")
        res = await call_tool(url, "v", "commit_files", _commit(sid))
        assert not res.is_error, res.text


# -- 8. OAuth state stays out of audit and spans ------------------------------------------------


async def test_authorization_links_not_logged(spans) -> None:
    os.environ["TEST_OAUTH_SECRET"] = "s"
    t = TenantConfig(
        id="t",
        forgejo_url=f"https://{HOST}",
        auth_mode=AuthMode.USER_DELEGATED,
        oauth=OAuthAppConfig("cid", SecretRef(env="TEST_OAUTH_SECRET"), "https://x/cb"),
        repos=("*/*",),
    )
    store = Store(":memory:", LocalKeyWrapper(os.urandom(32)))
    sink = MemoryAuditSink()
    services = Services(
        resolver=__import__("alasin_mcp.tenancy", fromlist=["x"]).StaticTenantResolver([t]),
        credentials=ModeRouter(
            {AuthMode.USER_DELEGATED: UserDelegatedProvider(store, {"t": t}.__getitem__)}
        ),
        store=store,
        audit_sink=sink,
    )
    with serve(build_app(services, StaticPrincipals({"a": ALICE}))) as url:
        sid = await _sid(url, "a")
        res = await call_tool(url, "a", "list_repos", {"session_id": sid})
    assert res.is_error and "state=" in res.text  # the caller does get the link
    logged = json.dumps(sink.events)
    assert "state=" not in logged and "/login/oauth/authorize" not in logged
    for s in spans.get_finished_spans():
        assert "state=" not in (s.status.description or "")


# -- 10. smaller items --------------------------------------------------------------------------


async def test_oauth_callback_rejects_malformed_token_responses() -> None:
    os.environ["TEST_OAUTH_SECRET"] = "s"
    for reply in (
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, json={"access_token": "x", "expires_in": "soon"}),
        httpx.Response(200, json=["not", "an", "object"]),
    ):
        t = TenantConfig(
            id="t",
            forgejo_url=f"https://{HOST}",
            auth_mode=AuthMode.USER_DELEGATED,
            oauth=OAuthAppConfig("cid", SecretRef(env="TEST_OAUTH_SECRET"), "https://x/cb"),
        )
        store = Store(":memory:", LocalKeyWrapper(os.urandom(32)))
        p = UserDelegatedProvider(
            store, {"t": t}.__getitem__, httpx.MockTransport(lambda _r, reply=reply: reply)
        )
        state = parse_state(p.authorization_url(t, ALICE))
        with pytest.raises(CredentialError):
            await p.complete(state, "code")


async def test_oversized_body_rejected_before_auth() -> None:
    services = fake_services(_fake(), [_tenant()])
    app = build_app(services, StaticPrincipals(PRINCIPALS), max_request_bytes=1000)
    with serve(app) as url:
        async with httpx.AsyncClient(timeout=10) as http:
            resp = await http.post(url, content=b"x" * 2000)
    assert resp.status_code == 413


async def test_websocket_scopes_are_rejected() -> None:
    called = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        called.append(scope["type"])

    sent: list[dict[str, Any]] = []

    async def send(msg: Any) -> None:
        sent.append(msg)

    async def receive() -> dict[str, Any]:
        return {}

    mw = BearerAuthMiddleware(inner, StaticPrincipals({}))
    await mw({"type": "websocket", "path": "/mcp", "headers": []}, receive, send)
    assert called == [] and sent[0]["type"] == "websocket.close"
    await mw({"type": "lifespan"}, receive, send)
    assert called == ["lifespan"]


@pytest.mark.parametrize("path", [".GIT/config", "a/.Git/HEAD"])
def test_git_folder_any_case_rejected(path: str) -> None:
    with pytest.raises(validation.InvalidInput):
        validation.file_path(path)


async def test_read_file_with_withheld_content_is_flagged() -> None:
    fake = _fake()
    fake.hosts[HOST]["repos"]["acme/site"].null_content.add("README.md")
    for r in running(fake):
        sid = await _sid(r.url)
        res = await call_tool(
            r.url, "gw", "read_file", {"session_id": sid, "repo": "acme/site", "path": "README.md"}
        )
        assert not res.is_error and res.data is not None
        assert res.data["truncated"] is True and res.data["content"] == ""


# -- branch creation by webhook --------------------------------------------------------------------

HOOK_SECRET = "hook-secret"


class HookServer:
    """A stub branch-creation service: checks the signature, then creates the branch."""

    def __init__(
        self,
        fake: FakeForgejo,
        create: bool = True,
        delay: float = 0.3,
        refuse: tuple[int, bytes] | None = None,
    ):
        self.fake, self.create, self.delay, self.refuse = fake, create, delay, refuse
        self.received: list[dict[str, Any]] = []
        port = free_port()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                ts = self.headers["X-Alasin-Timestamp"]
                expected = (
                    "sha256="
                    + hmac.new(
                        HOOK_SECRET.encode(), ts.encode() + b"." + body, hashlib.sha256
                    ).hexdigest()
                )
                if not hmac.compare_digest(expected, self.headers["X-Alasin-Signature"]):
                    self.send_response(401)
                    self.end_headers()
                    return
                payload = json.loads(body)
                outer.received.append(payload)
                if outer.refuse is not None:
                    status, content = outer.refuse
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                if outer.create:

                    def later() -> None:
                        time.sleep(outer.delay)
                        repo = outer.fake.hosts[HOST]["repos"][payload["repo"]]
                        repo.branches[payload["branch"]] = dict(repo.branches[payload["from_ref"]])

                    threading.Thread(target=later, daemon=True).start()
                self.send_response(202)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{port}/branches"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()


def _hook_tenant_kw(url: str, secret_env: str = "TEST_HOOK", timeout: float = 5) -> dict:
    return {
        "branch_creation": "webhook",
        "branch_webhook": BranchWebhookConfig(
            url=url,
            secret=SecretRef(env=secret_env),
            timeout_seconds=timeout,
            poll_interval_seconds=0.1,
        ),
    }


async def test_webhook_branch_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_HOOK", HOOK_SECRET)
    fake = _fake()
    hook = HookServer(fake)
    try:
        for r in running(fake, **_hook_tenant_kw(hook.url)):
            sid = await _sid(r.url)
            res = await call_tool(
                r.url,
                "gw",
                "create_branch",
                {"session_id": sid, "repo": "acme/site", "branch": "lane/new"},
            )
            assert not res.is_error, res.text
            assert hook.received == [
                {
                    "tenant": "t",
                    "repo": "acme/site",
                    "branch": "lane/new",
                    "from_ref": "main",
                    "session_id": sid,
                    "subject": "gateway",
                }
            ]
            # The server itself never called Forgejo's branch-creation API.
            assert r.posts("/branches") == []
    finally:
        hook.close()


async def test_webhook_wrong_secret_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_HOOK", "not-the-secret")
    fake = _fake()
    hook = HookServer(fake)
    try:
        for r in running(fake, **_hook_tenant_kw(hook.url)):
            sid = await _sid(r.url)
            res = await call_tool(
                r.url,
                "gw",
                "create_branch",
                {"session_id": sid, "repo": "acme/site", "branch": "b"},
            )
            assert res.is_error and "refused the request (401)" in res.text
    finally:
        hook.close()


async def test_webhook_sends_the_repo_as_forgejo_spells_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_HOOK", HOOK_SECRET)
    fake = _fake()
    # Stored in mixed case, so lowercasing what was typed is not enough.
    fake.hosts[HOST]["repos"]["Acme/Shop"] = FakeRepo(branches={"main": {"a.txt": b"a\n"}})
    hook = HookServer(fake)
    try:
        for r in running(fake, **_hook_tenant_kw(hook.url)):
            sid = await _sid(r.url)
            res = await call_tool(
                r.url,
                "gw",
                "create_branch",
                {"session_id": sid, "repo": "acme/SHOP", "branch": "lane/new"},
            )
            assert not res.is_error, res.text
            assert [p["repo"] for p in hook.received] == ["Acme/Shop"]
    finally:
        hook.close()


async def test_webhook_refusal_reason_reaches_the_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_HOOK", HOOK_SECRET)
    fake = _fake()
    reason = "branch must match lane/[a-z0-9][a-z0-9-]{0,62}"
    hook = HookServer(fake, refuse=(400, json.dumps({"error": reason + "\n" + "x" * 400}).encode()))
    try:
        for r in running(fake, **_hook_tenant_kw(hook.url)):
            sid = await _sid(r.url)
            res = await call_tool(
                r.url,
                "gw",
                "create_branch",
                {"session_id": sid, "repo": "acme/site", "branch": "lane/Fix_Copy"},
            )
            assert res.is_error
            assert f"refused the request (400): {reason} x" in res.text
            assert "x" * 300 not in res.text
    finally:
        hook.close()


async def test_webhook_server_error_body_is_not_passed_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_HOOK", HOOK_SECRET)
    fake = _fake()
    hook = HookServer(fake, refuse=(500, b'{"error": "internal detail"}'))
    try:
        for r in running(fake, **_hook_tenant_kw(hook.url)):
            sid = await _sid(r.url)
            res = await call_tool(
                r.url,
                "gw",
                "create_branch",
                {"session_id": sid, "repo": "acme/site", "branch": "lane/new"},
            )
            assert res.is_error and "refused the request (500)" in res.text
            assert "internal detail" not in res.text
    finally:
        hook.close()


async def test_webhook_branch_that_never_appears_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_HOOK", HOOK_SECRET)
    fake = _fake()
    hook = HookServer(fake, create=False)
    try:
        for r in running(fake, **_hook_tenant_kw(hook.url, timeout=1)):
            sid = await _sid(r.url)
            started = time.monotonic()
            res = await call_tool(
                r.url,
                "gw",
                "create_branch",
                {"session_id": sid, "repo": "acme/site", "branch": "b"},
            )
            assert res.is_error and "did not appear within 1 s" in res.text
            assert time.monotonic() - started < 10
    finally:
        hook.close()


def test_webhook_config_validation() -> None:
    base: dict[str, Any] = {
        "auth": {"static": [{"token_env": "T", "tenant": "t", "subject": "s"}]},
        "tenants": [
            {
                "id": "t",
                "forgejo_url": f"https://{HOST}",
                "service_token_env": "F",
                "branch_creation": "webhook",
            }
        ],
    }
    with pytest.raises(ConfigError, match="branch_webhook"):
        parse(base)
    base["tenants"][0]["branch_webhook"] = {
        "url": "https://hooks.example.com/branches",
        "secret_file": "/run/secrets/hook",
    }
    cfg = parse(base)
    assert cfg.tenants[0].branch_webhook is not None
    base["tenants"][0]["branch_webhook"]["secret"] = "inline"
    with pytest.raises(ConfigError):
        parse(base)
