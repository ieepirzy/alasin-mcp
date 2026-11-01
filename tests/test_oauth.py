# SPDX-License-Identifier: Apache-2.0
"""The OAuth front door: a client signs in through origo and reaches /mcp,
while static bearers keep working beside it."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from alasin_mcp.app import build_app
from alasin_mcp.audit import MemoryAuditSink
from alasin_mcp.auth import StaticTokenVerifier
from alasin_mcp.config import (
    PUBLIC_REGISTRATION_ACK,
    AuthMode,
    ConfigError,
    OAuthClientConfig,
    OAuthServerConfig,
    SecretRef,
    parse,
)
from alasin_mcp.credentials import ModeRouter, ServiceAccountProvider
from alasin_mcp.oauth import OrigoFrontDoor, front_door
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.tenancy import StaticTenantResolver
from alasin_mcp.tools import Services
from tests.harness import call_tool, free_port, list_tools, serve, tenant

pytestmark = pytest.mark.anyio

CLIENT, SECRET, REDIRECT = "connector", "connector-secret", "http://localhost/cb"


def _oauth_cfg(**kw: Any) -> OAuthServerConfig:
    return OAuthServerConfig(
        tenant="t",
        clients=(OAuthClientConfig(CLIENT, SecretRef(env="TEST_OAUTH"), (REDIRECT,)),),
        auto_approve=True,
        # The approve-only page these tests drive; per-person sign-in is in
        # test_people.py.
        allow_unauthenticated_consent=True,
        storage_path="",
        **kw,
    )


@contextmanager
def running(sink: Any = None) -> Iterator[str]:
    """The app with a static bearer ``tok`` and the origo front door; yields the base URL.

    With ``sink``, the front door audits sign-ins to it."""
    services = Services(
        resolver=StaticTenantResolver([tenant("t", "https://forgejo.example.com", "UNUSED")]),
        credentials=ModeRouter({AuthMode.SERVICE_ACCOUNT: ServiceAccountProvider()}),
        store=Store(":memory:", LocalKeyWrapper(os.urandom(32))),
        audit_sink=MemoryAuditSink(),
    )
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    door = OrigoFrontDoor(_oauth_cfg(), base, "/mcp", sink)
    app = build_app(services, StaticTokenVerifier([("tok", "t", "s")]), oauth=door)
    with serve(app, port) as url:
        assert url == base + "/mcp"
        yield base


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OAUTH", SECRET)


async def _sign_in(base: str, secret: str = SECRET) -> str:
    """The authorization-code + PKCE flow a connector runs; returns the access token."""
    tok = await _exchange(base, secret)
    assert tok.status_code == 200, tok.text
    return tok.json()["access_token"]


async def _exchange(base: str, secret: str) -> httpx.Response:
    """Authorize, then exchange the code with ``secret``; returns the /token response."""
    async with httpx.AsyncClient(follow_redirects=False, timeout=10) as h:
        meta = await h.get(f"{base}/.well-known/oauth-protected-resource")
        assert meta.status_code == 200, meta.text
        resource = meta.json()["resource"]
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        r = await h.get(
            f"{base}/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT,
                "redirect_uri": REDIRECT,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource,
            },
        )
        assert r.status_code == 302, r.text
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        return await h.post(
            f"{base}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT,
                "client_id": CLIENT,
                "client_secret": secret,
                "code_verifier": verifier,
                "resource": resource,
            },
        )


async def test_signed_in_client_reaches_the_tools() -> None:
    with running() as base:
        token = await _sign_in(base)
        assert {t.name for t in await list_tools(base + "/mcp", token)} >= {"begin_change"}
        res = await call_tool(base + "/mcp", token, "begin_change", {})
        assert not res.is_error, res.text


class _BrokenSink:
    """Fails every event, or only those of one phase."""

    def __init__(self, phase: str | None = None) -> None:
        self.phase = phase
        self.attempts = 0
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        self.attempts += 1
        if self.phase is None or event.get("phase") == self.phase:
            raise OSError("disk full")
        self.events.append(event)


async def _authorize(h: httpx.AsyncClient, base: str) -> dict[str, str]:
    """The authorization step; returns the /token form for its code."""
    meta = await h.get(f"{base}/.well-known/oauth-protected-resource")
    resource = meta.json()["resource"]
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    r = await h.get(
        f"{base}/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource,
        },
    )
    assert r.status_code == 302, r.text
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": CLIENT,
        "client_secret": SECRET,
        "code_verifier": verifier,
        "resource": resource,
    }


async def test_sign_in_is_audited_attempt_first_then_outcome() -> None:
    sink = MemoryAuditSink()
    with running(sink) as base:
        token = await _sign_in(base)
        assert await list_tools(base + "/mcp", token)
    attempt, outcome = sink.events
    assert attempt["phase"] == "attempt" and outcome["phase"] == "outcome"
    for event in (attempt, outcome):
        assert event["action"] == "sign_in"
        assert event["grant_type"] == "authorization_code"
        assert event["client_id"] == CLIENT
        assert event["tenant"] == "t"
        assert event["client_ip"] == "127.0.0.1"
        assert event["event_id"] and event["time"]
        # Never the token itself.
        assert token not in repr(event)
    assert "subject" not in attempt
    assert outcome["outcome"] == "ok" and outcome["subject"] == "oauth:" + CLIENT


async def test_a_failed_attempt_write_refuses_before_origo_spends_the_code() -> None:
    sink = _BrokenSink("attempt")
    with running(sink) as base:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10) as h:
            form = await _authorize(h, base)
            tok = await h.post(f"{base}/token", data=form)
            assert tok.status_code == 503, tok.text
            assert "access_token" not in tok.json()
            assert tok.json()["error"] == "temporarily_unavailable"
            # origo never saw it: the same code still works once audit does.
            sink.phase = "never"
            again = await h.post(f"{base}/token", data=form)
    assert again.status_code == 200, again.text
    assert again.json()["access_token"]


async def test_a_failed_sign_in_outcome_withholds_the_token() -> None:
    sink = _BrokenSink("outcome")
    with running(sink) as base:
        tok = await _exchange(base, SECRET)
    assert tok.status_code == 503, tok.text
    assert "access_token" not in tok.json()
    [attempt] = sink.events
    assert attempt["phase"] == "attempt"


async def test_a_failed_refresh_outcome_delivers_and_keeps_the_family() -> None:
    """origo rotates the refresh token before alasin sees the outcome: a
    refresh whose outcome cannot be recorded is delivered (logged), so the
    client keeps a working refresh token instead of a spent one."""
    sink = _BrokenSink("never")
    with running(sink) as base:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10) as h:
            form = await _authorize(h, base)
            first = (await h.post(f"{base}/token", data=form)).json()
            refresh = {
                "grant_type": "refresh_token",
                "refresh_token": first["refresh_token"],
                "client_id": CLIENT,
                "client_secret": SECRET,
                "resource": form["resource"],
            }
            sink.phase = "outcome"
            second = await h.post(f"{base}/token", data=refresh)
            assert second.status_code == 200, second.text
            rotated = second.json()["refresh_token"]
            assert rotated != first["refresh_token"]
            # The family is intact: the delivered refresh token works.
            sink.phase = "never"
            third = await h.post(f"{base}/token", data={**refresh, "refresh_token": rotated})
            assert third.status_code == 200, third.text
            assert await list_tools(base + "/mcp", third.json()["access_token"])
    refreshes = [e for e in sink.events if e["action"] == "token_refresh"]
    assert [e["phase"] for e in refreshes] == ["attempt", "attempt", "outcome"]


async def test_an_unattributable_token_is_never_delivered(monkeypatch: pytest.MonkeyPatch) -> None:
    sink = MemoryAuditSink()

    async def refuse(self: Any, token: str) -> None:
        return None

    monkeypatch.setattr("alasin_mcp.oauth._OrigoVerifier.verify", refuse)
    with running(sink) as base:
        tok = await _exchange(base, SECRET)
    assert tok.status_code == 503, tok.text
    assert "access_token" not in tok.json()
    assert sink.events[-1]["outcome"] == "error"
    assert sink.events[-1]["error"] == "issued token could not be attributed"


async def test_client_secret_basic_names_the_client() -> None:
    sink = MemoryAuditSink()
    with running(sink) as base:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10) as h:
            form = await _authorize(h, base)
            del form["client_id"], form["client_secret"]
            basic = base64.b64encode(f"{CLIENT}:{SECRET}".encode()).decode()
            await h.post(f"{base}/token", data=form, headers={"Authorization": f"Basic {basic}"})
    assert sink.events[0]["phase"] == "attempt"
    assert sink.events[0]["client_id"] == CLIENT


async def test_refused_exchange_is_audited_best_effort() -> None:
    sink = MemoryAuditSink()
    with running(sink) as base:
        tok = await _exchange(base, "wrong")
    assert tok.status_code == 401
    attempt, outcome = sink.events
    assert attempt["phase"] == "attempt"
    assert outcome["outcome"] == "error" and outcome["status"] == 401
    assert "subject" not in outcome
    # Its outcome failing to record does not change the refusal.
    with running(_BrokenSink("outcome")) as base:
        assert (await _exchange(base, "wrong")).status_code == 401


async def test_static_bearer_still_works_beside_oauth() -> None:
    with running() as base:
        assert await list_tools(base + "/mcp", "tok")


async def test_unauthenticated_request_is_pointed_at_discovery() -> None:
    with running() as base:
        async with httpx.AsyncClient(timeout=10) as h:
            r = await h.post(base + "/mcp", json={})
            assert r.status_code == 401
            challenge = r.headers["www-authenticate"]
            assert f'resource_metadata="{base}/.well-known/oauth-protected-resource"' in challenge
            bad = await h.post(base + "/mcp", json={}, headers={"Authorization": "Bearer nope"})
            assert bad.status_code == 401


async def test_wrong_client_secret_gets_no_token() -> None:
    with running() as base:
        r = await _exchange(base, "wrong")
        assert r.status_code in (400, 401), r.text
        assert "access_token" not in r.text


async def test_unregistered_redirect_uri_is_refused() -> None:
    with running() as base:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10) as h:
            r = await h.get(
                f"{base}/authorize",
                params={
                    "response_type": "code",
                    "client_id": CLIENT,
                    "redirect_uri": "https://evil.example.com/cb",
                    "code_challenge": "x" * 43,
                    "code_challenge_method": "S256",
                },
            )
            # Never a redirect to the unregistered URI with a code.
            assert r.status_code == 400, (r.status_code, r.headers.get("location"))
            assert "evil.example.com" not in r.headers.get("location", "")


async def test_registration_is_refused_when_off() -> None:
    with running() as base:
        async with httpx.AsyncClient(timeout=10) as h:
            r = await h.post(
                f"{base}/register",
                json={"redirect_uris": ["https://evil.example.com/cb"], "client_name": "x"},
            )
            assert r.status_code in (400, 401, 403), r.text
            assert "client_id" not in r.text


async def test_rfc9728_resource_metadata_path_is_public() -> None:
    with running() as base:
        async with httpx.AsyncClient(timeout=10) as h:
            r = await h.get(f"{base}/.well-known/oauth-protected-resource/mcp")
            assert r.status_code == 200, r.text
            assert r.json()["resource"] == f"{base}/mcp"


async def test_oauth_subject_is_namespaced_from_static_subjects() -> None:
    door = OrigoFrontDoor(_oauth_cfg(), "http://127.0.0.1:1", "/mcp")
    assert await door.verifier.verify("not-a-token") is None
    provider: Any = door._provider
    provider.verify_token = lambda token, resource=None: {"client_id": "s"}
    principal = await door.verifier.verify("x")
    assert principal is not None
    assert principal.key == ("t", "oauth:s")


# -- config --------------------------------------------------------------------------------

BASE: dict[str, Any] = {
    "server": {
        "public_url": "https://alasin.example.com/",
        "allowed_hosts": ["alasin.example.com"],
    },
    "tenants": [
        {
            "id": "t",
            "forgejo_url": "https://forgejo.example.com",
            "service_token_env": "F",
            "repos": ["acme/*"],
        }
    ],
}
OAUTH = {
    "tenant": "t",
    "clients": [{"id": "c", "secret_env": "S", "redirect_uris": ["https://claude.ai/cb"]}],
}


def test_oauth_alone_is_enough_inbound_auth() -> None:
    cfg = parse({**BASE, "auth": {"oauth": OAUTH}})
    assert cfg.oauth is not None
    assert cfg.oauth.base_url == "https://alasin.example.com"
    assert cfg.oauth.clients[0].redirect_uris == ("https://claude.ai/cb",)
    assert cfg.oauth.provider == "origo"


@pytest.mark.parametrize(
    "bad",
    [
        {**OAUTH, "tenant": "other"},
        {**OAUTH, "clients": []},
        {**OAUTH, "clients": [{"id": "c", "secret": "inline"}]},
    ],
)
def test_bad_oauth_config_refused(bad: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        parse({**BASE, "auth": {"oauth": bad}})


@pytest.mark.parametrize("mode", ["user_delegated", "platform_scoped"])
def test_oauth_tenant_must_be_service_account(mode: str) -> None:
    extra: dict[str, Any] = {"auth_mode": mode}
    if mode == "user_delegated":
        extra["oauth"] = {"client_id": "f", "client_secret_env": "S", "redirect_uri": "https://x"}
    t = {**BASE["tenants"][0], **extra}
    server = {**BASE["server"], "master_key_env": "K"}
    with pytest.raises(ConfigError, match="service_account"):
        parse({**BASE, "server": server, "tenants": [t], "auth": {"oauth": OAUTH}})


def test_public_registration_needs_the_acknowledgement() -> None:
    public = {"tenant": "t", "public_registration": True}
    with pytest.raises(ConfigError, match=PUBLIC_REGISTRATION_ACK):
        parse({**BASE, "auth": {"oauth": public}})
    with pytest.raises(ConfigError, match=PUBLIC_REGISTRATION_ACK):
        parse({**BASE, "auth": {"oauth": {**public, PUBLIC_REGISTRATION_ACK: "yes"}}})
    cfg = parse({**BASE, "auth": {"oauth": {**public, PUBLIC_REGISTRATION_ACK: True}}})
    assert cfg.oauth is not None and cfg.oauth.public_registration


def test_oauth_subject_prefix_is_reserved_for_static_credentials() -> None:
    static = {"token_env": "T", "tenant": "t", "subject": "oauth:connector"}
    with pytest.raises(ConfigError, match="reserved"):
        parse({**BASE, "auth": {"static": [static]}})


@pytest.mark.parametrize("allowed", [[], ["other.example.com"]])
def test_oauth_host_must_be_an_allowed_host(allowed: list[str]) -> None:
    server = {**BASE["server"], "allowed_hosts": allowed}
    with pytest.raises(ConfigError, match="allowed_hosts"):
        parse({**BASE, "server": server, "auth": {"oauth": OAUTH}})


def test_oauth_needs_a_base_url() -> None:
    with pytest.raises(ConfigError, match="base_url"):
        parse({**BASE, "server": {}, "auth": {"oauth": OAUTH}})


def test_unknown_provider_refused() -> None:
    with pytest.raises(ConfigError, match="provider"):
        front_door(_oauth_cfg(provider="keycloak"), "https://x", "/mcp")


def test_missing_origo_extra_is_a_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "origo", None)
    with pytest.raises(ConfigError, match=r"alasin-mcp\[origo\]"):
        OrigoFrontDoor(_oauth_cfg(), "https://x", "/mcp")
