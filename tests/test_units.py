# SPDX-License-Identifier: Apache-2.0
"""Unit tests: validation, the store's envelope encryption, messages, limits, config."""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag

from alasin_mcp import validation
from alasin_mcp.auth import Principal
from alasin_mcp.config import ConfigError, parse
from alasin_mcp.limits import PrincipalCache, RateLimited, TenantRateLimiter
from alasin_mcp.store import DecryptionFailed, LocalKeyWrapper, Store
from alasin_mcp.tools import build_message, parse_identity
from alasin_mcp.validation import InvalidInput

# -- validation --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "../x",
        "a/../b",
        "a/b/c",
        "https://h/a/b",
        "a",
        "./b",
        ".a/b",
        "a/b.git",
        "a/..",
        "a/b%2F..",
        "a /b",
        "",
    ],
)
def test_bad_repos(value: str) -> None:
    with pytest.raises(InvalidInput):
        validation.repo(value)


def test_good_repo() -> None:
    r = validation.repo("acme-co/site.web_1")
    assert r.api_path == "/repos/acme-co/site.web_1"


@pytest.mark.parametrize(
    "value",
    ["", "-x", "a..b", "a/", "/a", "a//b", "a.lock", "a@{1}", "HEAD", "a b", "a~1", "a/.b"],
)
def test_bad_branches(value: str) -> None:
    with pytest.raises(InvalidInput):
        validation.branch(value)


def test_branch_strips_refs_heads() -> None:
    assert validation.branch("refs/heads/feature/x") == "feature/x"


@pytest.mark.parametrize(
    "value", ["/etc/passwd", "../x", "a/../../b", "a//b", ".git/config", "a\\b", "a\x00", "."]
)
def test_bad_paths(value: str) -> None:
    with pytest.raises(InvalidInput):
        validation.file_path(value)


def test_paths_are_quoted_per_segment() -> None:
    assert validation.quote_path("dir/a b?.md") == "dir/a%20b%3F.md"
    assert validation.file_path(".github/workflows/ci.yml") == ".github/workflows/ci.yml"


# -- store -----------------------------------------------------------------------------------


def _store() -> Store:
    return Store(":memory:", LocalKeyWrapper(os.urandom(32)))


def test_tokens_round_trip_per_tenant_and_subject() -> None:
    s = _store()
    s.put_token("a", "alice", {"access_token": "A"})
    s.put_token("b", "alice", {"access_token": "B"})
    assert s.get_token("a", "alice") == {"access_token": "A"}
    assert s.get_token("b", "alice") == {"access_token": "B"}
    assert s.get_token("a", "bob") is None


def test_tenants_get_distinct_data_keys() -> None:
    s = _store()
    s.put_token("a", "x", {"t": 1})
    s.put_token("b", "x", {"t": 1})
    rows = s._q("SELECT tenant, wrapped FROM tenant_keys ORDER BY tenant")
    assert len(rows) == 2 and rows[0][1] != rows[1][1]
    assert s._tenant_key("a") != s._tenant_key("b")


def test_ciphertext_moved_to_another_tenant_or_subject_fails() -> None:
    s = _store()
    s.put_token("a", "alice", {"access_token": "A"})
    s.put_token("b", "mallory", {"access_token": "M"})
    nonce, ct = s._q("SELECT nonce, ciphertext FROM tokens WHERE tenant='a'")[0]
    s._q("UPDATE tokens SET nonce=?, ciphertext=? WHERE tenant='b'", (nonce, ct))
    with pytest.raises(DecryptionFailed):
        s.get_token("b", "mallory")
    s.put_token("a", "bob", {"access_token": "B"})
    s._q("UPDATE tokens SET nonce=?, ciphertext=? WHERE subject='bob'", (nonce, ct))
    with pytest.raises(DecryptionFailed):
        s.get_token("a", "bob")


def test_tokens_are_not_stored_in_clear() -> None:
    s = _store()
    s.put_token("a", "alice", {"access_token": "very-secret-value"})
    raw = s._q("SELECT ciphertext FROM tokens")[0][0]
    assert b"very-secret-value" not in raw


def test_wrong_master_key_cannot_unwrap(tmp_path) -> None:
    path = str(tmp_path / "s.db")
    s1 = Store(path, LocalKeyWrapper(os.urandom(32)))
    s1.put_token("a", "alice", {"access_token": "A"})
    s1.close()
    s2 = Store(path, LocalKeyWrapper(os.urandom(32)))
    with pytest.raises(InvalidTag):
        s2.get_token("a", "alice")


def test_wrapped_key_bound_to_tenant() -> None:
    w = LocalKeyWrapper(os.urandom(32))
    nonce, wrapped = w.wrap("a", b"k" * 32)
    with pytest.raises(InvalidTag):
        w.unwrap("b", nonce, wrapped)


def test_sessions_expire_and_are_scoped() -> None:
    s = _store()
    live = s.create_session("a", "alice", "1" * 32, "2" * 16, "", ttl=60)
    dead = s.create_session("a", "alice", "1" * 32, "2" * 16, "", ttl=-1)
    assert s.get_session("a", "alice", live.session_id) is not None
    assert s.get_session("a", "alice", dead.session_id) is None
    assert s.get_session("b", "alice", live.session_id) is None


def test_oauth_state_is_single_use() -> None:
    s = _store()
    state = s.put_oauth_state("a", "alice", "verifier", "alice@example.com")
    assert s.take_oauth_state(state) is not None
    assert s.take_oauth_state(state) is None
    expired = s.put_oauth_state("a", "alice", "v", "m", ttl=-1)
    assert s.take_oauth_state(expired) is None


# -- limits ------------------------------------------------------------------------------------


def test_rate_limit_is_per_tenant() -> None:
    lim = TenantRateLimiter()
    for _ in range(3):
        lim.check("a", 3, now=100.0)
    with pytest.raises(RateLimited):
        lim.check("a", 3, now=100.0)
    lim.check("b", 3, now=100.0)
    lim.check("a", 3, now=120.0)  # 20 s refills one call at 3/min


def test_cache_is_principal_scoped() -> None:
    c = PrincipalCache()
    a = Principal("a", "alice")
    c.set(a, "repo", "x", 1)
    assert c.get(a, "repo", "x") == 1
    assert c.get(Principal("b", "alice"), "repo", "x") is None
    assert c.get(Principal("a", "bob"), "repo", "x") is None


# -- commit messages ---------------------------------------------------------------------------


def test_trailers_appended() -> None:
    msg = build_message(
        "Fix typo\n\nOn the front page.", "Claude <c@example.com>", "ab" * 16, "ws_1"
    )
    assert msg.endswith(
        "On the front page.\n\nCo-Authored-By: Claude <c@example.com>\n"
        f"Trace-Id: {'ab' * 16}\nAlasin-Session: ws_1\n"
    )


def test_trailers_join_an_existing_trailer_block() -> None:
    msg = build_message("Fix\n\nSigned-off-by: A <a@example.com>", "", "t", "s")
    assert msg == "Fix\n\nSigned-off-by: A <a@example.com>\nTrace-Id: t\nAlasin-Session: s\n"


def test_coauthor_not_duplicated() -> None:
    msg = build_message(
        "Fix\n\nCo-Authored-By: Claude <c@example.com>", "Claude <c@example.com>", "t", "s"
    )
    assert msg.count("Co-Authored-By") == 1


@pytest.mark.parametrize(
    "bad", ["", "  ", "x\n\nTrace-Id: forged", "x\ntrace-id: f", "x\nAlasin-Session: y"]
)
def test_reserved_trailers_and_empty_refused(bad: str) -> None:
    with pytest.raises(InvalidInput):
        build_message(bad, "", "t", "s")


def test_parse_identity() -> None:
    i = parse_identity("Jane Doe <jane@example.com>")
    assert i is not None and i.name == "Jane Doe" and i.email == "jane@example.com"
    assert parse_identity("jane@example.com") is None
    assert parse_identity("A <b@c>\nX") is None


# -- config ---------------------------------------------------------------------------------------

BASE = {
    "auth": {"static": [{"token_env": "T", "tenant": "default", "subject": "gateway"}]},
    "tenants": [
        {
            "id": "default",
            "forgejo_url": "https://forgejo.example.com",
            "service_token_env": "F",
            "repos": ["acme/*"],
        }
    ],
}


def test_minimal_config() -> None:
    cfg = parse(BASE)
    assert cfg.tenants[0].service_token.env == "F"
    assert cfg.tenants[0].api_base == "https://forgejo.example.com/api/v1"
    assert "main" in cfg.tenants[0].protected_branches


def test_inline_secret_refused() -> None:
    bad = {**BASE, "tenants": [{**BASE["tenants"][0], "service_token": "plain"}]}
    with pytest.raises(ConfigError):
        parse(bad)


def test_static_credential_for_unknown_tenant_refused() -> None:
    bad = {**BASE, "auth": {"static": [{"token_env": "T", "tenant": "other", "subject": "s"}]}}
    with pytest.raises(ConfigError):
        parse(bad)


def test_user_delegated_needs_master_key() -> None:
    t = {
        **BASE["tenants"][0],
        "auth_mode": "user_delegated",
        "oauth": {"client_id": "c", "client_secret_env": "S", "redirect_uri": "https://x/cb"},
    }
    with pytest.raises(ConfigError):
        parse({**BASE, "tenants": [t]})
    ok = parse({**BASE, "tenants": [t], "server": {"master_key_env": "K"}})
    assert ok.tenants[0].oauth is not None


def test_example_config_parses() -> None:
    from alasin_mcp.config import load

    here = os.path.dirname(__file__)
    cfg = load(os.path.join(here, "..", "examples", "config.toml"))
    assert cfg.tenants[0].id == "default"
