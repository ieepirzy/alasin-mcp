# SPDX-License-Identifier: Apache-2.0
"""Audit events carry no personal data (Loimi decision-record 49f5331d,
Ilari 2026-11-01): they ship to an object-locked bucket nobody can edit for a
year, so a person is named only by their Keycloak subject. No name, email or
username, and no free text that could hold one (messages, intents, branch
names, paths, errors). ``client_ip`` stays raw here: the infra audit gateway
replaces it with a keyed hash before the bucket.

Events are driven through the real tools and the real OAuth front door; the
scanner walks every event they wrote."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

import httpx
import pytest

from alasin_mcp.audit import MemoryAuditSink, redact
from alasin_mcp.auth import Principal
from alasin_mcp.oauth import OrigoFrontDoor
from tests import test_oauth
from tests.harness import call_tool
from tests.test_people import ISSUER, people
from tests.test_review_fixes import HOOK_SECRET

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_OAUTH", test_oauth.SECRET)
    monkeypatch.setenv("TEST_IDP_SECRET", "idp-secret")
    monkeypatch.setenv("TEST_FORGEJO", "forgejo-token")
    monkeypatch.setenv("TEST_HOOK", HOOK_SECRET)


FORBIDDEN_KEYS = frozenset(
    {
        "name",
        "email",
        "preferred_username",
        "username",
        "principal_name",
        "principal_email",
        "author",
        "committer",
        "author_name",
        "author_email",
        "full_name",
        "title",
        "message",
        "intent",
        "branch",
        "path",
    }
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Names and free text the tests put in; none may reach an event.
INJECTED = (
    "Alice Example",
    "Ilari Testinen",
    "lane/alice",
    "lane/ilari-fix",
    "Fix Ilari's typo",
    "notes/ilari.txt",
    "for Ilari Testinen",
)


def pii_findings(event: Any, where: str = "") -> list[str]:
    """Every place in ``event`` that holds a forbidden key, an email address
    or an injected name."""
    found: list[str] = []
    if isinstance(event, dict):
        for k, v in event.items():
            if k in FORBIDDEN_KEYS:
                found.append(f"{where}.{k}: forbidden key")
            found += pii_findings(v, f"{where}.{k}")
    elif isinstance(event, list):
        for i, v in enumerate(event):
            found += pii_findings(v, f"{where}[{i}]")
    elif isinstance(event, str):
        if EMAIL.search(event):
            found.append(f"{where}: an email address")
        found += [f"{where}: {n!r}" for n in INJECTED if n.casefold() in event.casefold()]
    return found


def assert_no_pii(events: list[dict[str, Any]]) -> None:
    assert events
    found = [f for e in events for f in pii_findings(e, e.get("action") or e.get("tool") or "?")]
    assert not found, "\n".join(found)


def test_the_scanner_catches_what_it_must() -> None:
    """The scanner itself, against events that do carry personal data."""
    assert pii_findings({"principal_email": "a@b.example"})
    assert pii_findings({"x": {"y": ["contact alice@example.com"]}})
    assert pii_findings({"arguments": {"branch": "lane/x"}})
    assert pii_findings({"result": {"note": "by Ilari Testinen"}})
    assert not pii_findings({"sub": "alice-id", "branch_sha256": "0" * 64})


def test_redact_drops_and_digests() -> None:
    e = redact(
        {
            "principal_name": "Ilari Testinen",
            "principal_email": "ilari@example.com",
            "author": "Ilari Testinen <ilari@example.com>",
            "branch": "lane/ilari-fix",
            "error": "branch 'lane/ilari-fix' already exists",
            "error_kind": "policy",
            "surprise": "for Ilari Testinen",
            "repo": "acme/site",
        }
    )
    assert_no_pii([e])
    assert e["branch_sha256"] == hashlib.sha256(b"lane/ilari-fix").hexdigest()
    assert e["error_kind"] == "policy" and e["error_chars"] > 0
    assert e["surprise_sha256"] == hashlib.sha256(b"for Ilari Testinen").hexdigest()
    assert e["surprise_chars"] == 18 and "surprise" not in e
    assert e["repo"] == "acme/site"


async def test_tool_calls_record_the_sub_and_no_personal_data() -> None:
    with people() as p:
        sink: MemoryAuditSink = p.services.audit_sink
        assert not (await p.create("alice", "lane/alice")).is_error
        sid = await p.sid("alice")
        args = {
            "session_id": sid,
            "repo": "acme/site",
            "branch": "lane/alice",
            "message": "Fix Ilari's typo",
            "files": [{"path": "notes/ilari.txt", "content": "for Ilari Testinen"}],
        }
        ok = await call_tool(p.url, "alice", "commit_files", args)
        assert not ok.is_error, ok.text
        # Author arguments where the tenant takes the author from the token:
        # refused, and the refusal is an event too.
        bad = await call_tool(
            p.url,
            "alice",
            "commit_files",
            {**args, "author_name": "Ilari Testinen", "author_email": "ilari@example.com"},
        )
        assert bad.is_error
        # Someone else's branch, and an unknown session: error events.
        assert (await p.commit("bob", "lane/alice")).is_error
        bad_sid = {**args, "session_id": "nope"}
        assert (await call_tool(p.url, "alice", "commit_files", bad_sid)).is_error
        # Branch creation for a name that exists: error with the name in its text.
        assert (await p.create("bob", "lane/ilari-fix")).is_error is False
        assert (await p.create("alice", "lane/ilari-fix")).is_error
    events = sink.events
    assert_no_pii(events)
    commits = [e for e in events if e.get("tool") == "commit_files"]
    assert {e["phase"] for e in commits} == {"attempt", "outcome"}
    ok_outcome = next(e for e in commits if e["phase"] == "outcome" and e["outcome"] == "ok")
    assert ok_outcome["sub"] == "alice-id" and "subject" not in ok_outcome
    assert ok_outcome["branch_sha256"] == hashlib.sha256(b"lane/alice").hexdigest()
    assert ok_outcome["commit"] and ok_outcome["author_source"]
    recorded = ok_outcome["arguments"]
    assert recorded["message_sha256"] == hashlib.sha256(b"Fix Ilari's typo").hexdigest()
    assert recorded["message_chars"] == len("Fix Ilari's typo")
    assert recorded["files"][0]["path_sha256"] == hashlib.sha256(b"notes/ilari.txt").hexdigest()
    assert ok_outcome["result"]["branch_sha256"] == ok_outcome["branch_sha256"]
    errors = [e for e in events if e.get("outcome") == "error"]
    assert errors and all(e["error_kind"] and e["error_sha256"] for e in errors)
    given = [e for e in commits if e.get("arguments", {}).get("author_given")]
    assert given, "the author arguments are recorded as given, not by value"
    assert {e.get("sub") for e in events} == {"alice-id", "bob-id"}


async def test_sign_in_and_refresh_record_the_sub_and_no_personal_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    person = Principal(
        tenant="t",
        subject=f"oauth:{ISSUER}|ilari-id",
        name="Ilari Testinen",
        email="ilari@example.com",
        email_verified=True,
        idp_subject="ilari-id",
    )

    async def issued(self: Any, response: Any) -> Principal | None:
        return person if response.status_code == 200 else None

    monkeypatch.setattr(OrigoFrontDoor, "_issued_principal", issued)
    sink = MemoryAuditSink()
    with test_oauth.running(sink) as base:
        first = await test_oauth._exchange(base, test_oauth.SECRET)
        assert first.status_code == 200, first.text
        async with httpx.AsyncClient(timeout=10) as h:
            again = await h.post(
                f"{base}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": first.json()["refresh_token"],
                    "client_id": test_oauth.CLIENT,
                    "client_secret": test_oauth.SECRET,
                },
            )
            assert again.status_code == 200, again.text
            refused = await h.post(
                f"{base}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": "spent",
                    "client_id": test_oauth.CLIENT,
                    "client_secret": test_oauth.SECRET,
                },
            )
            assert refused.status_code != 200
    assert_no_pii(sink.events)
    outcomes = [e for e in sink.events if e["phase"] == "outcome" and e["outcome"] == "ok"]
    assert {e["action"] for e in outcomes} == {"sign_in", "token_refresh"}
    assert all(e["sub"] == "ilari-id" and "subject" not in e for e in outcomes)
    assert any(e.get("error_kind") == "token_refused" for e in sink.events)
    # client_ip stays raw here; the infra gateway hashes it before the bucket.
    assert all(e["client_ip"] == "127.0.0.1" for e in sink.events)
    assert "ilari@example.com" not in json.dumps(sink.events)


# -- values a caller chooses ----------------------------------------------------------
# The /token form and Basic header are read before origo authenticates
# anything, and a tool call's session_id and repo before they are checked:
# anyone who can reach the server chooses them. None may carry a person.

HOSTILE = ("Ilari Testinen <ilari.testinen@example.fi>", "ilari.testinen@example.fi")


def test_redact_keeps_caller_values_only_in_their_own_shape() -> None:
    for bad in HOSTILE:
        e = redact(
            {
                "client_id": bad,
                "grant_type": bad,
                "session_id": bad,
                "repo": bad,
                "client_ip": bad,
                "trace_id": bad,
                "arguments": {"repo": bad, "session_id": bad, "nested": {"x": bad}, "l": [bad]},
                "result": {"url": bad, "commit": bad},
            }
        )
        assert pii_findings(e) == [], (bad, pii_findings(e))
        assert "client_id" not in e and "grant_type" not in e and "session_id" not in e
    good = redact(
        {
            "client_id": test_oauth.CLIENT,
            "grant_type": "refresh_token",
            "session_id": "ws_" + "a" * 24,
            "repo": "acme/site",
            "client_ip": "2a01:4f8::7",
            "trace_id": "0" * 32,
            "arguments": {"files": [{"path_sha256": "0" * 64, "encoding": "utf-8"}]},
        }
    )
    assert good["client_id"] == test_oauth.CLIENT and good["grant_type"] == "refresh_token"
    assert good["session_id"] == "ws_" + "a" * 24 and good["repo"] == "acme/site"
    assert good["client_ip"] == "2a01:4f8::7" and good["trace_id"] == "0" * 32
    assert good["arguments"]["files"][0] == {"path_sha256": "0" * 64, "encoding": "utf-8"}


async def test_a_hostile_token_request_leaves_no_personal_data() -> None:
    """client_id and grant_type straight from the internet, form and Basic."""
    sink = MemoryAuditSink()
    with test_oauth.running(sink) as base:
        async with httpx.AsyncClient(timeout=10) as h:
            for bad in HOSTILE:
                r = await h.post(
                    f"{base}/token",
                    data={"grant_type": bad, "client_id": bad, "client_secret": "x", "code": "c"},
                )
                assert r.status_code != 200
                basic = base64.b64encode(f"{bad}:x".encode()).decode()
                r = await h.post(
                    f"{base}/token",
                    data={"grant_type": "authorization_code", "code": "c"},
                    headers={"Authorization": f"Basic {basic}"},
                )
                assert r.status_code != 200
            # The configured client is still named as it is.
            r = await h.post(
                f"{base}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": "spent",
                    "client_id": test_oauth.CLIENT,
                    "client_secret": test_oauth.SECRET,
                },
            )
    assert len(sink.events) >= 8
    assert_no_pii(sink.events)
    assert any(e.get("client_id") == test_oauth.CLIENT for e in sink.events)
    assert any("client_id_sha256" in e for e in sink.events)
    assert any("grant_type_sha256" in e for e in sink.events)


async def test_a_hostile_session_id_and_repo_leave_no_personal_data() -> None:
    with people() as p:
        sink: MemoryAuditSink = p.services.audit_sink
        sid = await p.sid("alice")
        for bad in HOSTILE:
            bad_sid = {"session_id": bad, "repo": "acme/site", "branch": "lane/alice"}
            assert (await call_tool(p.url, "alice", "create_branch", bad_sid)).is_error
            bad_repo = {"session_id": sid, "repo": bad, "branch": "lane/alice"}
            assert (await call_tool(p.url, "alice", "create_branch", bad_repo)).is_error
        # owner/name-shaped but not the tenant's: a login could be the owner.
        other = {"session_id": sid, "repo": "ilari-testinen/notes", "branch": "lane/alice"}
        assert (await call_tool(p.url, "alice", "create_branch", other)).is_error
    events = sink.events
    assert_no_pii(events)
    assert "ilari-testinen" not in json.dumps(events)
    assert all(e.get("repo") in (None, "acme/site") for e in events)
    assert all(e.get("session_id") in (None, sid) for e in events)


# -- last review round: client ids, result URLs, session ids --------------------------

# Exactly the shape of an origo-registered client id (token_urlsafe(16)),
# chosen by a caller to carry a name.
NAMED_CLIENT = "IlariTestinenHelsinki0"


def test_a_client_id_is_kept_only_when_configured_or_trusted() -> None:
    assert len(NAMED_CLIENT) == 22
    e = redact({"client_id": NAMED_CLIENT})
    assert "client_id" not in e and e["client_id_sha256"]
    assert redact({"client_id": NAMED_CLIENT}, trusted=frozenset({"client_id"}))["client_id"] == (
        NAMED_CLIENT
    )
    # trusted applies at the top level only.
    nested = redact({"arguments": {"client_id": NAMED_CLIENT}}, trusted=frozenset({"client_id"}))
    assert "client_id" not in nested["arguments"]


async def test_an_unauthenticated_client_id_of_the_registered_shape_is_a_digest() -> None:
    sink = MemoryAuditSink()
    with test_oauth.running(sink) as base:
        async with httpx.AsyncClient(timeout=10) as h:
            r = await h.post(
                f"{base}/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": NAMED_CLIENT,
                    "client_secret": "x",
                    "code": "c",
                },
            )
            assert r.status_code != 200
    phases = {e["phase"] for e in sink.events}
    assert phases == {"attempt", "outcome"}
    assert NAMED_CLIENT not in json.dumps(sink.events)
    assert all("client_id_sha256" in e and "client_id" not in e for e in sink.events)


async def test_an_issued_token_names_its_client_even_when_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client id origo issued a token for is origo's: kept on that
    outcome. The attempt before it, still unauthenticated, is a digest."""
    import alasin_mcp.audit as audit

    person = Principal(tenant="t", subject=f"oauth:{ISSUER}|ilari-id", idp_subject="ilari-id")

    async def issued(self: Any, response: Any) -> Principal | None:
        return person if response.status_code == 200 else None

    monkeypatch.setattr(OrigoFrontDoor, "_issued_principal", issued)
    sink = MemoryAuditSink()
    with test_oauth.running(sink) as base:
        monkeypatch.setattr(
            audit, "_known_clients", frozenset()
        )  # as if registered, not configured
        first = await test_oauth._exchange(base, test_oauth.SECRET)
        assert first.status_code == 200, first.text
    attempt = next(e for e in sink.events if e["phase"] == "attempt")
    outcome = next(e for e in sink.events if e["phase"] == "outcome")
    assert "client_id" not in attempt and attempt["client_id_sha256"]
    assert outcome["outcome"] == "ok" and outcome["client_id"] == test_oauth.CLIENT


async def test_a_result_url_is_gated_like_the_repo(monkeypatch: pytest.MonkeyPatch) -> None:
    """The commit URL names the repo's owner: where the repo is written only
    as a digest (the owner is not configured), so is the URL."""
    import alasin_mcp.tools as tools

    with people() as p:
        sink: MemoryAuditSink = p.services.audit_sink
        assert not (await p.create("alice", "lane/alice")).is_error
        monkeypatch.setattr(tools, "owner_configured", lambda tenant, name: False)
        ok = await p.commit("alice", "lane/alice")
        assert not ok.is_error, ok.text
    outcome = next(
        e
        for e in sink.events
        if e.get("tool") == "commit_files" and e["phase"] == "outcome" and e["outcome"] == "ok"
    )
    assert "repo" not in outcome and outcome["repo_sha256"]
    assert "url" not in outcome["result"] and outcome["result"]["url_sha256"]
    assert "acme" not in json.dumps(outcome)


def test_a_result_url_is_kept_where_the_owner_is_named() -> None:
    from alasin_mcp.tools import _result_summary

    url = "https://forgejo.example.com/acme/site/commit/abc"
    assert _result_summary({"url": url}, owner_named=True)["url"] == url
    assert "url" not in _result_summary({"url": url}, owner_named=False)


async def test_a_session_id_is_kept_only_when_it_is_a_live_session() -> None:
    with people() as p:
        sink: MemoryAuditSink = p.services.audit_sink
        sid = await p.sid("alice")
        unknown = "ws_" + "A" * 24  # the right shape, no such session
        name_like = "ws_IlariTestinenFromHelsinkiFinland"  # name-like, wrong length
        for bad in (unknown, name_like):
            args = {"session_id": bad, "repo": "acme/site", "branch": "lane/alice"}
            assert (await call_tool(p.url, "alice", "create_branch", args)).is_error
    events = sink.events
    dumped = json.dumps(events)
    assert unknown not in dumped and name_like not in dumped
    assert all(e.get("session_id") in (None, sid) for e in events)
    assert redact({"session_id": name_like}).get("session_id") is None
    assert redact({"session_id": "ws_" + "A" * 25}).get("session_id") is None
