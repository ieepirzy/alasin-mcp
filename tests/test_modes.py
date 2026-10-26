# SPDX-License-Identifier: Apache-2.0
"""Auth modes (b) user-delegated and (c) platform-scoped, and the JWT verifier."""

from __future__ import annotations

import os
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from alasin_mcp.auth import JwtVerifier, Principal
from alasin_mcp.config import (
    AuthMode,
    JwtConfig,
    OAuthAppConfig,
    PlatformConfig,
    SecretRef,
    TenantConfig,
)
from alasin_mcp.credentials import (
    AuthorizationRequired,
    CredentialError,
    Identity,
    MintedToken,
    MinterNotConfigured,
    PlatformScopedProvider,
    UnconfiguredMinter,
    UserDelegatedProvider,
)
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.validation import RepoRef

pytestmark = pytest.mark.anyio

FORGEJO = "https://forgejo.example.com"


def _tenant(**kw: Any) -> TenantConfig:
    return TenantConfig(
        id="t1",
        forgejo_url=FORGEJO,
        auth_mode=AuthMode.USER_DELEGATED,
        oauth=OAuthAppConfig(
            client_id="cid",
            client_secret=SecretRef(env="TEST_OAUTH_SECRET"),
            redirect_uri="https://alasin.example.com/oauth/forgejo/callback",
        ),
        **kw,
    )


class FakeOAuth:
    def __init__(self, email: str = "alice@example.com", expires_in: int = 3600):
        self.email = email
        self.expires_in = expires_in
        self.posts: list[dict[str, list[str]]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            form = parse_qs(request.content.decode())
            self.posts.append(form)
            n = len(self.posts)
            return httpx.Response(
                200,
                json={
                    "access_token": f"access-{n}",
                    "refresh_token": f"refresh-{n}",
                    "expires_in": self.expires_in,
                },
            )
        if request.url.path == "/api/v1/user":
            return httpx.Response(200, json={"login": "alice", "email": self.email})
        return httpx.Response(404)


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OAUTH_SECRET", "s3cret")


def _provider(fake: FakeOAuth) -> tuple[UserDelegatedProvider, Store, TenantConfig]:
    store = Store(":memory:", LocalKeyWrapper(os.urandom(32)))
    tenant = _tenant()
    p = UserDelegatedProvider(store, {"t1": tenant}.__getitem__, httpx.MockTransport(fake.handle))
    return p, store, tenant


ALICE = Principal("t1", "alice-sub", "Alice", "alice@example.com")


async def test_delegated_flow_binds_token_to_tenant_and_subject() -> None:
    fake = FakeOAuth()
    p, store, tenant = _provider(fake)
    with pytest.raises(AuthorizationRequired) as e:
        await p.credential(tenant, ALICE, None)
    q = parse_qs(urlparse(e.value.url).query)
    assert e.value.url.startswith(f"{FORGEJO}/login/oauth/authorize?")
    assert q["code_challenge_method"] == ["S256"] and q["client_id"] == ["cid"]
    await p.complete(q["state"][0], "the-code")
    assert fake.posts[0]["code_verifier"][0]
    assert fake.posts[0]["grant_type"] == ["authorization_code"]
    cred = await p.credential(tenant, ALICE, None)
    assert cred.token == "access-1"
    assert store.get_token("t1", "alice-sub") is not None
    # Another subject, or the same subject in another tenant, has nothing.
    with pytest.raises(AuthorizationRequired):
        await p.credential(tenant, Principal("t1", "bob", None, "bob@example.com"), None)
    assert store.get_token("t2", "alice-sub") is None


async def test_delegated_flow_refuses_someone_elses_forgejo_account() -> None:
    fake = FakeOAuth(email="mallory@example.com")
    p, store, tenant = _provider(fake)
    with pytest.raises(AuthorizationRequired) as e:
        await p.credential(tenant, ALICE, None)
    state = parse_qs(urlparse(e.value.url).query)["state"][0]
    with pytest.raises(CredentialError, match="does not match"):
        await p.complete(state, "code")
    assert store.get_token("t1", "alice-sub") is None


async def test_delegated_state_is_single_use() -> None:
    p, _, tenant = _provider(FakeOAuth())
    with pytest.raises(AuthorizationRequired) as e:
        await p.credential(tenant, ALICE, None)
    state = parse_qs(urlparse(e.value.url).query)["state"][0]
    await p.complete(state, "code")
    with pytest.raises(CredentialError, match="unknown or expired"):
        await p.complete(state, "code")


async def test_delegated_token_refreshes_when_expired() -> None:
    fake = FakeOAuth(expires_in=1)
    p, store, tenant = _provider(fake)
    store.put_token(
        "t1",
        "alice-sub",
        {"access_token": "old", "refresh_token": "r0", "expires_at": time.time() - 5},
    )
    cred = await p.credential(tenant, ALICE, None)
    assert cred.token == "access-1"
    assert fake.posts[0]["grant_type"] == ["refresh_token"]
    assert fake.posts[0]["refresh_token"] == ["r0"]


async def test_delegated_needs_a_claim_to_bind() -> None:
    p, _, tenant = _provider(FakeOAuth())
    with pytest.raises(CredentialError, match="no 'email' claim"):
        await p.credential(tenant, Principal("t1", "anon"), None)


# -- platform-scoped (mode c) ----------------------------------------------------------------

REPO = RepoRef("acme", "site")
PLATFORM_TENANT = TenantConfig(
    id="t1",
    forgejo_url=FORGEJO,
    auth_mode=AuthMode.PLATFORM_SCOPED,
    platform=PlatformConfig(),
)


async def test_platform_mode_without_minter_is_a_clear_error() -> None:
    p = PlatformScopedProvider()
    with pytest.raises(MinterNotConfigured):
        await p.credential(PLATFORM_TENANT, ALICE, REPO)
    with pytest.raises(MinterNotConfigured):
        await UnconfiguredMinter().mint(PLATFORM_TENANT, ALICE, REPO)


class RecordingMinter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    async def mint(self, tenant: TenantConfig, principal: Principal, repo: RepoRef) -> MintedToken:
        self.calls.append((tenant.id, principal.subject, repo.full_name))
        return MintedToken("short-lived", time.time() + 300, Identity("Platform Bot", "bot@x.test"))


async def test_platform_mode_author_is_user_committer_is_bot() -> None:
    minter = RecordingMinter()
    p = PlatformScopedProvider({"t1": minter})
    cred = await p.credential(PLATFORM_TENANT, ALICE, REPO)
    assert cred.token == "short-lived"
    assert cred.author == Identity("Alice", "alice@example.com")
    assert cred.committer == Identity("Platform Bot", "bot@x.test")
    assert minter.calls == [("t1", "alice-sub", "acme/site")]


async def test_platform_mode_is_per_repo_and_needs_an_email() -> None:
    p = PlatformScopedProvider({"t1": RecordingMinter()})
    with pytest.raises(CredentialError, match="per repository"):
        await p.credential(PLATFORM_TENANT, ALICE, None)
    with pytest.raises(CredentialError, match="email"):
        await p.credential(PLATFORM_TENANT, Principal("t1", "x"), REPO)


# -- JWT verifier ----------------------------------------------------------------------------


class StaticJwks:
    def __init__(self, key: Any):
        self._key = key

    def get_signing_key_from_jwt(self, token: str) -> Any:
        return type("K", (), {"key": self._key})()


def _jwt(key: Any, **claims: Any) -> str:
    base = {
        "iss": "https://idp.example.com",
        "aud": "alasin",
        "sub": "alice-sub",
        "exp": int(time.time()) + 60,
        "tenant": "t1",
        "email": "alice@example.com",
        "name": "Alice",
    }
    base.update(claims)
    return jwt.encode({k: v for k, v in base.items() if v is not None}, key, algorithm="RS256")


async def test_jwt_verifier() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cfg = JwtConfig(
        jwks_url="https://idp.example.com/jwks", issuer="https://idp.example.com", audience="alasin"
    )
    v = JwtVerifier(cfg, StaticJwks(key.public_key()))  # type: ignore[arg-type]
    p = await v.verify(_jwt(key))
    assert p == Principal("t1", "alice-sub", "Alice", "alice@example.com", p.claims if p else {})
    assert await v.verify(_jwt(other)) is None
    assert await v.verify(_jwt(key, aud="other")) is None
    assert await v.verify(_jwt(key, iss="https://evil.example.com")) is None
    assert await v.verify(_jwt(key, exp=int(time.time()) - 10)) is None
    assert await v.verify(_jwt(key, tenant=None)) is None
    assert await v.verify(_jwt(key, tenant="../etc")) is None
