# SPDX-License-Identifier: Apache-2.0
"""claude.ai managed authorization (origo's ManagedSignIn, ID-JAG): the
ALASIN_MANAGED_SIGNIN_* settings, and that origo's /token takes the
jwt-bearer grant only when they are set.

No assertion is ever verified here: origo's own suite pins every check of
the grant. These tests pin that alasin turns it on (and only then), refuses
half-configured settings at start-up, and audits the grant by name."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest

from alasin_mcp.app import build_app
from alasin_mcp.audit import MemoryAuditSink
from alasin_mcp.auth import StaticTokenVerifier
from alasin_mcp.config import AuthMode, ConfigError, ManagedSignInConfig, parse
from alasin_mcp.credentials import ModeRouter, ServiceAccountProvider
from alasin_mcp.oauth import JWT_BEARER, OrigoFrontDoor
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.tenancy import StaticTenantResolver
from alasin_mcp.tools import Services
from tests.harness import free_port, serve, tenant
from tests.test_people import BASE, ENV, _auth, _idp, _oauth_cfg

pytestmark = pytest.mark.anyio

CLAUDE = "https://claude.ai/oauth/mcp-oauth-client-metadata"
MANAGED_ISSUER = "https://identity.anthropic.com/issuers/iss_test"
MANAGED_ENV = {"ALASIN_MANAGED_SIGNIN_ISSUER": MANAGED_ISSUER}


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OAUTH", "connector-secret")
    monkeypatch.setenv("TEST_IDP_SECRET", "idp-secret")


def _managed_auth(**oauth: Any) -> dict[str, Any]:
    return _auth(cimd_allowed_clients=[CLAUDE], **oauth)


# --- configuration -------------------------------------------------------------


def test_unset_leaves_managed_sign_in_off() -> None:
    cfg = parse({**BASE, "auth": _managed_auth()}, env={})
    assert cfg.oauth is not None and cfg.oauth.managed_sign_in is None


def test_issuer_alone_turns_it_on_without_a_tenant() -> None:
    cfg = parse({**BASE, "auth": _managed_auth()}, env=MANAGED_ENV)
    assert cfg.oauth is not None
    assert cfg.oauth.managed_sign_in == ManagedSignInConfig(issuer=MANAGED_ISSUER, tenant=None)


def test_issuer_and_tenant() -> None:
    env = {**MANAGED_ENV, "ALASIN_MANAGED_SIGNIN_TENANT": " tenant-1 "}
    cfg = parse({**BASE, "auth": _managed_auth()}, env=env)
    assert cfg.oauth is not None
    assert cfg.oauth.managed_sign_in == ManagedSignInConfig(MANAGED_ISSUER, "tenant-1")


def test_with_the_identity_provider_from_the_environment() -> None:
    auth = _managed_auth()
    del auth["oauth"]["identity_provider"]
    cfg = parse({**BASE, "auth": auth}, env={**ENV, **MANAGED_ENV})
    assert cfg.oauth is not None and cfg.oauth.identity_provider is not None
    assert cfg.oauth.managed_sign_in is not None


@pytest.mark.parametrize(
    ("auth", "env", "match"),
    [
        pytest.param(
            _managed_auth(),
            {"ALASIN_MANAGED_SIGNIN_TENANT": "tenant-1"},
            "without ALASIN_MANAGED_SIGNIN_ISSUER",
            id="tenant-without-issuer",
        ),
        pytest.param(
            _managed_auth(),
            {"ALASIN_MANAGED_SIGNIN_ISSUER": "http://identity.anthropic.com/issuers/iss_x"},
            "https",
            id="plain-http-issuer",
        ),
        pytest.param(
            _managed_auth(),
            {"ALASIN_MANAGED_SIGNIN_ISSUER": "iss_test"},
            "https",
            id="not-a-url",
        ),
        pytest.param(
            {"static": [{"token_env": "T", "tenant": "t", "subject": "s"}]},
            MANAGED_ENV,
            r"\[auth.oauth\]",
            id="no-oauth",
        ),
        pytest.param(_auth(), MANAGED_ENV, "cimd_allowed_clients", id="no-cimd-clients"),
    ],
)
def test_bad_managed_sign_in_refused(auth: dict[str, Any], env: dict[str, str], match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        parse({**BASE, "auth": auth}, env=env)


def test_managed_sign_in_needs_an_identity_provider() -> None:
    # The shape of a deployment without one: approve-only, CIMD acknowledged.
    oauth = {
        "tenant": "t",
        "cimd_allowed_clients": [CLAUDE],
        "public_registration_i_understand_anyone_can_connect": True,
    }
    shared = {**BASE["tenants"][0], "author_source": "service_account", "branch_owners": False}
    raw = {**BASE, "tenants": [shared], "auth": {"oauth": oauth}}
    assert parse(raw, env={}).oauth is not None
    with pytest.raises(ConfigError, match="identity provider"):
        parse(raw, env=MANAGED_ENV)


def test_managed_sign_in_reaches_origo() -> None:
    cfg = _oauth_cfg(
        identity_provider=_idp(),
        cimd_allowed_clients=(CLAUDE,),
        managed_sign_in=ManagedSignInConfig(MANAGED_ISSUER, "tenant-1"),
    )
    provider: Any = OrigoFrontDoor(cfg, "http://127.0.0.1:1", "/mcp")._provider
    managed = provider.managed_sign_in
    assert (managed.issuer, managed.tenant, managed.group_paths) == (
        MANAGED_ISSUER,
        "tenant-1",
        False,
    )


# --- the server ---------------------------------------------------------------


@contextmanager
def running(managed: bool, sink: Any = None) -> Iterator[str]:
    services = Services(
        resolver=StaticTenantResolver([tenant("t", "https://forgejo.example.com", "UNUSED")]),
        credentials=ModeRouter({AuthMode.SERVICE_ACCOUNT: ServiceAccountProvider()}),
        store=Store(":memory:", LocalKeyWrapper(os.urandom(32))),
        audit_sink=MemoryAuditSink(),
    )
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    cfg = _oauth_cfg(
        identity_provider=_idp(),
        cimd_allowed_clients=(CLAUDE,),
        managed_sign_in=ManagedSignInConfig(MANAGED_ISSUER) if managed else None,
    )
    door = OrigoFrontDoor(cfg, base, "/mcp", sink)
    app = build_app(services, StaticTokenVerifier([("tok", "t", "s")]), oauth=door)
    with serve(app, port):
        yield base


async def _metadata_and_bare_grant(base: str) -> tuple[list[str], httpx.Response]:
    async with httpx.AsyncClient(timeout=10) as h:
        meta = await h.get(f"{base}/.well-known/oauth-authorization-server")
        assert meta.status_code == 200, meta.text
        # The grant with neither client nor assertion: origo answers before
        # any client check, so the error says whether it knows the grant.
        r = await h.post(f"{base}/token", data={"grant_type": JWT_BEARER})
    return meta.json()["grant_types_supported"], r


async def test_set_the_server_advertises_and_takes_the_jwt_bearer_grant() -> None:
    with running(managed=True) as base:
        grants, r = await _metadata_and_bare_grant(base)
    assert JWT_BEARER in grants
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "invalid_request"


async def test_unset_the_server_neither_advertises_nor_takes_it() -> None:
    with running(managed=False) as base:
        grants, r = await _metadata_and_bare_grant(base)
    assert JWT_BEARER not in grants
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "unsupported_grant_type"


async def test_a_managed_sign_in_is_audited_by_name() -> None:
    sink = MemoryAuditSink()
    with running(managed=True, sink=sink) as base:
        async with httpx.AsyncClient(timeout=10) as h:
            r = await h.post(
                f"{base}/token",
                data={"grant_type": JWT_BEARER, "client_id": CLAUDE, "assertion": "x.y.z"},
            )
    assert r.status_code >= 400
    attempt, outcome = sink.events
    for event in (attempt, outcome):
        assert event["action"] == "managed_sign_in"
        assert event["grant_type"] == JWT_BEARER
        # The assertion is never written.
        assert "x.y.z" not in repr(event)
    assert outcome["outcome"] == "error"
