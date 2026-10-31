# SPDX-License-Identifier: Apache-2.0
"""Per-person sign-in: people sign in through origo's upstream identity provider
(Keycloak), each commit is authored by the person, the lane group is checked on
every write, and only a branch's creator may write it.

origo's ``verify_token`` is replaced with a table of fake tokens, so nothing here
talks to an IdP; everything after it (the verifier, the gate, the tools, the
branch webhook, Forgejo's commit body) is the real code.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import anyio
import httpx
import pytest

from alasin_mcp.app import build_app, from_config
from alasin_mcp.auth import Principal, StaticTokenVerifier
from alasin_mcp.config import (
    AuthorSource,
    ConfigError,
    IdentityProviderConfig,
    OAuthClientConfig,
    OAuthServerConfig,
    SecretRef,
    parse,
)
from alasin_mcp.oauth import OrigoFrontDoor
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.tools import PolicyError
from tests.harness import call_tool, fake_services, free_port, serve
from tests.test_review_fixes import HOOK_SECRET, HookServer, _fake, _hook_tenant_kw, _tenant

pytestmark = pytest.mark.anyio

ISSUER = "https://auth.example.com/realms/staff"
LANE = "/forgejo-lane"


def _claims(idp_sub: str, groups: list[str], **kw: Any) -> dict[str, Any]:
    return {
        "client_id": "claude-connector",
        "sub": f"{ISSUER}|{idp_sub}",
        "groups": groups,
        **kw,
    }


TOKENS: dict[str, dict[str, Any]] = {
    "alice": _claims("alice-id", [LANE], name="Alice Example", email="alice@example.com"),
    "bob": _claims("bob-id", ["/other", LANE], name="Bob Example", email="bob@example.com"),
    "outsider": _claims("out-id", ["/other"], name="Out Sider", email="out@example.com"),
    "noname": _claims("nn-id", [LANE], email="nn@example.com"),
    "noemail": _claims("ne-id", [LANE], name="No Email"),
}


def _idp() -> IdentityProviderConfig:
    return IdentityProviderConfig(
        issuer=ISSUER,
        client_id="alasin",
        client_secret=SecretRef(env="TEST_IDP_SECRET"),
        allowed_groups=(LANE,),
    )


def _oauth_cfg(**kw: Any) -> OAuthServerConfig:
    return OAuthServerConfig(
        tenant="t",
        clients=(
            OAuthClientConfig(
                "claude-connector", SecretRef(env="TEST_OAUTH"), ("http://localhost/cb",)
            ),
        ),
        storage_path="",
        **kw,
    )


def _door(base: str = "http://127.0.0.1:1") -> OrigoFrontDoor:
    door = OrigoFrontDoor(_oauth_cfg(identity_provider=_idp()), base, "/mcp")
    provider: Any = door._provider
    provider.verify_token = lambda token, resource=None: TOKENS.get(token)
    return door


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OAUTH", "connector-secret")
    monkeypatch.setenv("TEST_IDP_SECRET", "idp-secret")
    monkeypatch.setenv("TEST_FORGEJO", "forgejo-token")
    monkeypatch.setenv("TEST_HOOK", HOOK_SECRET)


class People:
    def __init__(self, url: str, fake: Any, services: Any, hook: HookServer):
        self.url, self.fake, self.services, self.hook = url, fake, services, hook

    async def sid(self, token: str) -> str:
        r = await call_tool(self.url, token, "begin_change", {})
        assert not r.is_error, r.text
        assert r.data is not None
        return r.data["session_id"]

    async def create(self, token: str, branch: str) -> Any:
        args = {"session_id": await self.sid(token), "repo": "acme/site", "branch": branch}
        return await call_tool(self.url, token, "create_branch", args)

    async def commit(self, token: str, branch: str) -> Any:
        args = {
            "session_id": await self.sid(token),
            "repo": "acme/site",
            "branch": branch,
            "message": "Change the copy",
            "files": [{"path": "a.txt", "content": f"by {token}"}],
        }
        return await call_tool(self.url, token, "commit_files", args)

    @property
    def commits(self) -> list[dict[str, Any]]:
        return self.fake.hosts["forgejo.example.com"]["repos"]["acme/site"].commits


@contextmanager
def people(refuse: tuple[int, bytes] | None = None, create: bool = True) -> Iterator[People]:
    """The app as a per-person deployment: IdP front door, token_claims authors,
    branch owners, the lane gate, webhook branch creation."""
    fake = _fake()
    hook = HookServer(fake, create=create, delay=0.05, refuse=refuse)
    t = _tenant(
        author_source=AuthorSource.TOKEN_CLAIMS,
        branch_owners=True,
        **_hook_tenant_kw(hook.url),
    )
    services = fake_services(fake, [t], writer_groups={"t": frozenset({LANE})})
    port = free_port()
    door = _door(f"http://127.0.0.1:{port}")
    app = build_app(services, StaticTokenVerifier([]), oauth=door)
    try:
        with serve(app, port) as url:
            yield People(url, fake, services, hook)
    finally:
        hook.close()


# -- the verifier --------------------------------------------------------------------------


async def test_person_token_becomes_a_person_principal() -> None:
    p = await _door().verifier.verify("alice")
    assert p is not None
    assert p.key == ("t", f"oauth:{ISSUER}|alice-id")
    assert (p.name, p.email, p.email_verified) == ("Alice Example", "alice@example.com", True)
    assert p.idp_subject == "alice-id"
    assert p.claims["groups"] == [LANE]


@pytest.mark.parametrize(
    "claims",
    [
        {"client_id": "claude-connector"},  # names no person
        {"client_id": "claude-connector", "sub": f"{ISSUER}|"},  # empty IdP subject
        {"client_id": "claude-connector", "sub": "https://evil.example.com/realms/staff|x"},
        {"client_id": "claude-connector", "sub": f"{ISSUER}x|alice-id"},  # issuer look-alike
        {"sub": f"{ISSUER}|alice-id"},  # no client
    ],
)
async def test_token_without_a_person_of_this_issuer_is_refused(claims: dict[str, Any]) -> None:
    door = _door()
    provider: Any = door._provider
    provider.verify_token = lambda token, resource=None: claims
    assert await door.verifier.verify("x") is None


async def test_unverified_email_is_never_an_author() -> None:
    # origo drops an unverified email; a token without one can't author.
    p = await _door().verifier.verify("noemail")
    assert p is not None and p.email is None and not p.email_verified


def test_identity_provider_reaches_origo() -> None:
    idp: Any = _door()._provider.identity_provider
    assert idp.issuer == ISSUER and idp.client_id == "alasin"
    assert idp.client_secret == "idp-secret"
    assert idp.allowed_groups == frozenset({LANE}) and idp.groups_claim == "groups"


async def test_idp_callback_is_public_and_mcp_is_not() -> None:
    port = free_port()
    services = fake_services(_fake(), [_tenant()])
    app = build_app(services, StaticTokenVerifier([]), oauth=_door(f"http://127.0.0.1:{port}"))
    with serve(app, port) as url:
        async with httpx.AsyncClient(timeout=10) as h:
            r = await h.get(url.removesuffix("/mcp") + "/authorize/callback")
            assert r.status_code != 401, r.text
            assert (await h.post(url, json={})).status_code == 401


async def test_approve_only_stays_off_whatever_the_env_says(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The config's False is passed to origo, so its env var can't open the
    # consent page behind it.
    monkeypatch.setenv("ORIGO_ALLOW_UNAUTHENTICATED_CONSENT", "true")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    door = OrigoFrontDoor(_oauth_cfg(auto_approve=True), base, "/mcp")
    services = fake_services(_fake(), [_tenant()])
    with serve(build_app(services, StaticTokenVerifier([]), oauth=door), port):
        async with httpx.AsyncClient(follow_redirects=False, timeout=10) as h:
            r = await h.get(
                f"{base}/authorize",
                params={
                    "response_type": "code",
                    "client_id": "claude-connector",
                    "redirect_uri": "http://localhost/cb",
                    "code_challenge": "x" * 43,
                    "code_challenge_method": "S256",
                },
            )
            assert r.status_code == 403, (r.status_code, r.headers.get("location"))


# -- the tools -------------------------------------------------------------------------------


async def test_person_authors_the_commit_and_the_bot_commits_it() -> None:
    with people() as p:
        res = await p.create("alice", "lane/alice")
        assert not res.is_error, res.text
        res = await p.commit("alice", "lane/alice")
        assert not res.is_error, res.text
        body = p.commits[-1]
        assert body["author"] == {"name": "Alice Example", "email": "alice@example.com"}
        assert body["committer"] == {"name": "bot", "email": "bot@example.com"}
        assert res.data is not None
        assert res.data["author"] == "Alice Example <alice@example.com>"


async def test_branch_registration_carries_the_owner_sub() -> None:
    with people() as p:
        res = await p.create("alice", "lane/owned")
        assert not res.is_error, res.text
        (sent,) = p.hook.received
        assert sent["owner_sub"] == "alice-id"
        assert sent["subject"] == f"oauth:{ISSUER}|alice-id"


async def test_only_the_creator_may_write_a_branch() -> None:
    with people() as p:
        assert not (await p.create("alice", "lane/mine")).is_error
        res = await p.commit("bob", "lane/mine")
        assert res.is_error and "not created by you" in res.text
        # The refusal names nobody.
        assert "alice" not in res.text.lower()
        assert not (await p.commit("alice", "lane/mine")).is_error
        assert len(p.commits) == 1


async def test_branch_without_a_recorded_owner_is_refused() -> None:
    # "work" exists in Forgejo but was never created through this server (or
    # its record was lost): nobody may write it here.
    with people() as p:
        res = await p.commit("alice", "work")
        assert res.is_error and "not created by you" in res.text
        assert p.commits == []


async def test_lost_owner_record_is_restored_by_the_webhook() -> None:
    # "work" exists and this server has no record of it (a restart on an
    # emptyDir, say). Re-requesting it asks the receiver, which knows the owner
    # and answers the owner with success.
    with people(create=False) as p:
        res = await p.create("alice", "work")
        assert not res.is_error, res.text
        assert p.hook.received[0]["branch"] == "work"
        assert p.hook.received[0]["owner_sub"] == "alice-id"
        assert p.services.store.branch_owner("t", "acme/site", "work") == (
            f"oauth:{ISSUER}|alice-id"
        )
        assert not (await p.commit("alice", "work")).is_error


async def test_lost_owner_record_is_not_restored_for_someone_else() -> None:
    with people(refuse=(409, b'{"error": "branch belongs to another owner"}')) as p:
        res = await p.create("bob", "work")
        assert res.is_error and "another owner" in res.text
        assert p.services.store.branch_owner("t", "acme/site", "work") is None
        assert (await p.commit("bob", "work")).is_error


async def test_recorded_branch_is_not_re_requested() -> None:
    with people() as p:
        assert not (await p.create("alice", "lane/rec")).is_error
        res = await p.create("bob", "lane/rec")
        assert res.is_error and "already exists" in res.text
        assert len(p.hook.received) == 1


async def test_a_branch_reserved_by_someone_else_cannot_be_created() -> None:
    with people() as p:
        # Bob's creation is in flight: reserved, not yet in Forgejo.
        p.services.store.reserve_branch(
            "t", "acme/site", "lane/race", f"oauth:{ISSUER}|bob-id", 600
        )
        res = await p.create("alice", "lane/race")
        assert res.is_error and "already taken" in res.text
        assert p.hook.received == []


class SlowRefusal:
    """A ``refuse`` value the hook stub unpacks only after a delay: a sync bot
    that takes its lock and fetches before answering 409."""

    def __iter__(self) -> Iterator[Any]:
        time.sleep(1.5)
        yield 409
        yield b'{"error": "registered to another owner"}'


async def test_no_write_while_a_reclaim_is_unanswered() -> None:
    # Review finding (PR #8): reclaim recorded Bob as owner before the bot
    # answered, so a commit in that window landed on Alice's branch as Bob.
    with people(refuse=SlowRefusal()) as p:  # type: ignore[arg-type]
        sid_c, sid_k = await p.sid("bob"), await p.sid("bob")

        async def commit_later() -> Any:
            await anyio.sleep(0.7)
            args = {
                "session_id": sid_k,
                "repo": "acme/site",
                "branch": "work",
                "message": "m",
                "files": [{"path": "a.txt", "content": "by bob"}],
            }
            return await call_tool(p.url, "bob", "commit_files", args)

        results: dict[str, Any] = {}

        async def run(key: str, fn: Any) -> None:
            results[key] = await fn()

        args = {"session_id": sid_c, "repo": "acme/site", "branch": "work"}
        async with anyio.create_task_group() as tg:
            tg.start_soon(run, "create", lambda: call_tool(p.url, "bob", "create_branch", args))
            tg.start_soon(run, "commit", commit_later)
        assert results["create"].is_error and "another owner" in results["create"].text
        assert results["commit"].is_error, results["commit"].text
        assert "not created by you" in results["commit"].text
        assert p.commits == []
        assert p.services.store.branch_owner("t", "acme/site", "work") is None


async def test_an_unanswered_reclaim_does_not_block_the_owner() -> None:
    # A reclaim reserves nothing: Bob's re-request, still unanswered, can't
    # hold the branch against Alice's; the receiver decides both.
    with people(refuse=SlowRefusal()) as p:  # type: ignore[arg-type]
        sid_b, sid_a = await p.sid("bob"), await p.sid("alice")
        results: dict[str, Any] = {}

        async def create(token: str, sid: str, delay: float) -> None:
            await anyio.sleep(delay)
            args = {"session_id": sid, "repo": "acme/site", "branch": "work"}
            results[token] = await call_tool(p.url, token, "create_branch", args)

        async with anyio.create_task_group() as tg:
            tg.start_soon(create, "bob", sid_b, 0)
            tg.start_soon(create, "alice", sid_a, 0.5)
        assert "already taken" not in results["alice"].text
        assert {r["owner_sub"] for r in p.hook.received} == {"bob-id", "alice-id"}


async def test_no_write_while_a_creation_is_pending() -> None:
    # The creator's own reservation is not ownership either.
    with people() as p:
        p.services.store.reserve_branch("t", "acme/site", "work", f"oauth:{ISSUER}|alice-id", 600)
        res = await p.commit("alice", "work")
        assert res.is_error and "not created by you" in res.text


async def test_failed_creation_releases_the_claim() -> None:
    with people(refuse=(409, b'{"error": "busy"}')) as p:
        res = await p.create("alice", "lane/retry")
        assert res.is_error and "busy" in res.text
        assert p.services.store.branch_owner("t", "acme/site", "lane/retry") is None


@pytest.mark.parametrize(
    ("token", "message"),
    [("outsider", "group"), ("noname", "no name"), ("noemail", "verified email")],
)
async def test_lane_gate_on_every_write(token: str, message: str) -> None:
    with people() as p:
        assert not (await p.create("alice", "lane/gate")).is_error
        res = await p.create(token, f"lane/{token}")
        assert res.is_error and message in res.text, res.text
        res = await p.commit(token, "lane/gate")
        assert res.is_error and message in res.text, res.text
        assert p.hook.received == [p.hook.received[0]]
        # Reads stay open to anyone who passed sign-in.
        sid = await p.sid(token)
        args = {"session_id": sid, "repo": "acme/site"}
        assert not (await call_tool(p.url, token, "list_branches", args)).is_error


async def test_gate_reads_this_tokens_groups() -> None:
    # Bob is in the lane group today; removed from it, his next token is refused
    # on writes even though sign-in once let him in.
    with people() as p:
        TOKENS["bob-later"] = {**TOKENS["bob"], "groups": ["/other"]}
        try:
            res = await p.create("bob-later", "lane/later")
            assert res.is_error and "group" in res.text
        finally:
            del TOKENS["bob-later"]


def _store() -> Store:
    return Store(":memory:", LocalKeyWrapper(os.urandom(32)))


def test_reservation_is_first_come_and_never_ownership() -> None:
    store = _store()
    assert store.reserve_branch("t", "Acme/Site", "lane/x", "a", 600) == "a"
    assert store.reserve_branch("t", "acme/site", "lane/x", "a", 600) == "a"
    assert store.reserve_branch("t", "acme/site", "lane/x", "b", 600) == "a"
    assert store.branch_owner("t", "acme/site", "lane/x") is None
    store.release_branch("t", "acme/site", "lane/x", "b")
    assert store.reserve_branch("t", "acme/site", "lane/x", "b", 600) == "a"
    store.release_branch("t", "acme/site", "lane/x", "a")
    assert store.reserve_branch("t", "acme/site", "lane/x", "b", 600) == "b"


def test_confirmed_owner_survives_release_and_holds_reservations() -> None:
    store = _store()
    store.reserve_branch("t", "acme/site", "lane/x", "a", 600)
    store.confirm_branch("t", "acme/site", "lane/x", "a")
    assert store.branch_owner("t", "ACME/site", "lane/x") == "a"
    store.release_branch("t", "acme/site", "lane/x", "a")
    assert store.branch_owner("t", "acme/site", "lane/x") == "a"
    # A confirmed owner is never stale.
    assert store.reserve_branch("t", "acme/site", "lane/x", "b", -1) == "a"


def test_stale_reservation_is_dropped() -> None:
    # A crash between reserving and the creator's answer leaves a pending row;
    # it never counts as ownership and, once stale, holds nothing.
    store = _store()
    store.reserve_branch("t", "acme/site", "lane/x", "a", 600)
    assert store.reserve_branch("t", "acme/site", "lane/x", "b", 600) == "a"
    assert store.reserve_branch("t", "acme/site", "lane/x", "b", -1) == "b"
    assert store.branch_owner("t", "acme/site", "lane/x") is None


# -- config ---------------------------------------------------------------------------------

BASE: dict[str, Any] = {
    "server": {
        "public_url": "https://alasin.example.com",
        "allowed_hosts": ["alasin.example.com"],
    },
    "tenants": [
        {
            "id": "t",
            "forgejo_url": "https://forgejo.example.com",
            "service_token_env": "F",
            "repos": ["acme/*"],
            "author_source": "token_claims",
            "branch_owners": True,
        }
    ],
}
IDP = {
    "issuer": ISSUER,
    "client_id": "alasin",
    "client_secret_env": "TEST_IDP_SECRET",
    "allowed_groups": [LANE],
}


def _auth(idp: dict[str, Any] | None = None, **oauth: Any) -> dict[str, Any]:
    return {
        "oauth": {
            "tenant": "t",
            "clients": [{"id": "c", "secret_env": "TEST_OAUTH", "redirect_uris": ["https://x/cb"]}],
            "identity_provider": IDP if idp is None else idp,
            **oauth,
        }
    }


def test_identity_provider_config() -> None:
    cfg = parse({**BASE, "auth": _auth({**IDP, "groups_claim": "realm_access.roles"})})
    assert cfg.oauth is not None and cfg.oauth.identity_provider is not None
    idp = cfg.oauth.identity_provider
    assert idp.allowed_groups == (LANE,) and idp.groups_claim == "realm_access.roles"
    assert idp.client_secret == SecretRef(env="TEST_IDP_SECRET")
    assert not cfg.oauth.allow_unauthenticated_consent


@pytest.mark.parametrize(
    ("idp", "match"),
    [
        ({**IDP, "allowed_groups": []}, "allowed_groups"),
        ({k: v for k, v in IDP.items() if k != "allowed_groups"}, "allowed_groups"),
        ({**IDP, "issuer": "http://auth.example.com/realms/staff"}, "https issuer"),
        ({**IDP, "client_id": ""}, "client_id"),
        ({k: v for k, v in IDP.items() if k != "client_secret_env"}, "client_secret"),
        ({**IDP, "client_secret": "inline"}, "client_secret"),
    ],
)
def test_bad_identity_provider_refused(idp: dict[str, Any], match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        parse({**BASE, "auth": _auth(idp)})


@pytest.mark.parametrize(
    ("tenant_kw", "match"),
    [
        ({"author_source": "service_account"}, "token_claims"),
        ({"branch_owners": False}, "branch_owners"),
    ],
)
def test_person_tenant_needs_person_authors_and_branch_owners(
    tenant_kw: dict[str, Any], match: str
) -> None:
    t = {**BASE["tenants"][0], **tenant_kw}
    with pytest.raises(ConfigError, match=match):
        parse({**BASE, "tenants": [t], "auth": _auth()})


ENV = {
    "ALASIN_IDP_ISSUER": ISSUER,
    "ALASIN_IDP_CLIENT_ID": "alasin",
    "ALASIN_IDP_CLIENT_SECRET_FILE": "/etc/alasin/keycloak/client-secret",
    "ALASIN_IDP_ALLOWED_GROUPS": "forgejo-lane, other",
}


def test_identity_provider_from_the_environment() -> None:
    auth = _auth()
    del auth["oauth"]["identity_provider"]
    cfg = parse({**BASE, "auth": auth}, env=ENV)
    assert cfg.oauth is not None and cfg.oauth.identity_provider is not None
    idp = cfg.oauth.identity_provider
    assert (idp.issuer, idp.client_id) == (ISSUER, "alasin")
    assert idp.client_secret == SecretRef(file="/etc/alasin/keycloak/client-secret")
    assert idp.allowed_groups == ("forgejo-lane", "other")
    assert idp.groups_claim == "groups"


def test_grant_age_from_the_environment() -> None:
    auth = _auth()
    del auth["oauth"]["identity_provider"]
    cfg = parse({**BASE, "auth": auth}, env={**ENV, "ALASIN_IDP_MAX_GRANT_AGE": "3600"})
    assert cfg.oauth is not None and cfg.oauth.identity_provider is not None
    assert cfg.oauth.identity_provider.max_grant_age_seconds == 3600
    with pytest.raises(ConfigError, match="positive"):
        parse({**BASE, "auth": auth}, env={**ENV, "ALASIN_IDP_MAX_GRANT_AGE": "0"})


def test_grant_age_reaches_origo() -> None:
    cfg = _oauth_cfg(
        identity_provider=IdentityProviderConfig(
            issuer=ISSUER,
            client_id="alasin",
            client_secret=SecretRef(env="TEST_IDP_SECRET"),
            allowed_groups=(LANE,),
            max_grant_age_seconds=3600,
        ),
        token_ttl_seconds=900,
    )
    provider: Any = OrigoFrontDoor(cfg, "http://127.0.0.1:1", "/mcp")._provider
    assert provider.identity_provider.max_grant_age == 3600
    assert provider.storage.token_ttl == 900


def test_person_tenant_has_no_jwt_issuer() -> None:
    jwt = {"jwks_url": "https://x/certs", "issuer": "https://x", "audience": "a"}
    with pytest.raises(ConfigError, match="auth.jwt"):
        parse({**BASE, "auth": {**_auth(), "jwt": jwt}})


async def test_writes_need_an_identity_provider_principal() -> None:
    # A principal that merely asserts the lane group (a JWT, a static
    # credential) can't write in the person tenant.
    with people() as p:
        svc: Any = p.services
        forged = Principal(
            "t",
            "forged",
            "Forged",
            "f@example.com",
            claims={"groups": [LANE]},
            email_verified=True,
        )
        t = p.services.resolver.resolve(forged)
        with pytest.raises(PolicyError, match="identity provider"):
            svc.check_writer(t, forged)
        real = await _door().verifier.verify("alice")
        assert real is not None
        svc.check_writer(t, real)


def test_identity_provider_from_one_source_only() -> None:
    with pytest.raises(ConfigError, match="use one"):
        parse({**BASE, "auth": _auth()}, env=ENV)
    with pytest.raises(ConfigError, match=r"\[auth.oauth\]"):
        parse(
            {**BASE, "auth": {"static": [{"token_env": "T", "tenant": "t", "subject": "s"}]}},
            env=ENV,
        )
    no_groups = {k: v for k, v in ENV.items() if k != "ALASIN_IDP_ALLOWED_GROUPS"}
    auth = _auth()
    del auth["oauth"]["identity_provider"]
    with pytest.raises(ConfigError, match="allowed_groups"):
        parse({**BASE, "auth": auth}, env=no_groups)


def test_person_tenant_has_no_shared_static_credential() -> None:
    auth = {**_auth(), "static": [{"token_env": "T", "tenant": "t", "subject": "lane"}]}
    with pytest.raises(ConfigError, match="shared"):
        parse({**BASE, "auth": auth})


def test_person_tenant_has_no_public_registration() -> None:
    auth = _auth(public_registration=True, public_registration_i_understand_anyone_can_connect=True)
    with pytest.raises(ConfigError, match="public_registration"):
        parse({**BASE, "auth": auth})


def test_from_config_gates_the_person_tenant(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import alasin_mcp.app as app_mod

    built: list[Any] = []
    monkeypatch.setattr(app_mod, "build_app", lambda services, *a, **kw: built.append(services))
    server = {
        **BASE["server"],
        "state_path": str(tmp_path / "state.db"),
        "audit_dir": str(tmp_path / "audit"),
    }
    from_config(parse({**BASE, "server": server, "auth": _auth(storage_path="")}))
    assert built[0].writer_groups == {"t": frozenset({LANE})}
