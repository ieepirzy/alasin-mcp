# SPDX-License-Identifier: Apache-2.0
"""change_status and propose_change: following a branch from push to merge,
and proposing it upstream through a signed proposal service."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from alasin_mcp.app import build_app
from alasin_mcp.audit import MemoryAuditSink
from alasin_mcp.auth import Principal
from alasin_mcp.branching import sign
from alasin_mcp.config import PreviewsConfig, ProposalsConfig, SecretRef
from tests.harness import FakeForgejo, FakeRepo, call_tool, fake_services, serve, tenant

pytestmark = pytest.mark.anyio

HOST = "forgejo.example.com"
SECRET = "proposal-test-secret"
SHA = "1" * 40
JANE = Principal("t", "jane", "Jane Doe", "jane@example.com", email_verified=True)
BOB = Principal("t", "bob", "Bob Roe", "bob@example.com", email_verified=True)
UPLOAD = "testing-site-lane / upload (push)"
PR = {
    "proposed": True,
    "pull_request": "https://github.com/acme/site/pull/7",
    "number": 7,
    "state": "open",
    "draft": False,
    "head_sha": SHA,
    "review": "none",
    "checks": "pending",
}


class Principals:
    async def verify(self, token: str) -> Principal | None:
        return {"jane": JANE, "bob": BOB}.get(token)


class FakeProposer:
    """The proposal service: checks the signature like forgejo_lane.py."""

    def __init__(self, status: Any = None, propose: tuple[int, Any] = (201, None), down=False):
        self.status, self.propose, self.down = status, propose, down
        self.received: list[tuple[str, dict[str, Any]]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("refused", request=request)
        ts = request.headers["x-alasin-timestamp"]
        if request.headers["x-alasin-signature"] != sign(SECRET, ts, request.content):
            return httpx.Response(401, json={})
        body = json.loads(request.content)
        self.received.append((request.url.path, body))
        if request.url.path.endswith("/status"):
            return httpx.Response(200, json=self.status or {"proposed": False})
        code, payload = self.propose
        default = {"pull_request": PR["pull_request"], "commit": SHA, "owner_sub": "kc|jane"}
        return httpx.Response(code, json=payload if payload is not None else default)


def _fake(statuses: list[dict[str, Any]] | None = None) -> FakeForgejo:
    fake = FakeForgejo()
    repo = FakeRepo(branches={"main": {"a.txt": b"a\n"}, "lane/hero": {"a.txt": b"b\n"}})
    if statuses is not None:
        repo.statuses[SHA] = statuses
    fake.add_host(HOST, "tok", "bot", {"acme/site": repo})
    return fake


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_FORGEJO", "tok")
    monkeypatch.setenv("TEST_PROPOSALS", SECRET)


def running(
    fake: FakeForgejo, proposer: FakeProposer | None, proposals: bool = True
) -> Iterator[tuple[str, MemoryAuditSink]]:
    t = tenant(
        "t",
        f"https://{HOST}",
        "TEST_FORGEJO",
        repos=("acme/site",),
        branch_prefix="lane/",
        branch_owners=True,
        proposals=ProposalsConfig(
            url="http://proposer.invalid:8081/v1/proposals", secret=SecretRef(env="TEST_PROPOSALS")
        )
        if proposals
        else None,
        previews=PreviewsConfig(base_url="https://testing.example.com/p/", upload_context=UPLOAD),
    )
    sink = MemoryAuditSink()
    services = fake_services(
        fake,
        [t],
        sink,
        proposal_transport=httpx.MockTransport(proposer.handle) if proposer else None,
    )
    with serve(build_app(services, Principals())) as url:
        yield url, sink


async def _sid(url: str, token: str = "jane") -> str:
    r = await call_tool(url, token, "begin_change", {})
    assert not r.is_error, r.text
    assert r.data is not None
    return r.data["session_id"]


async def _status(url: str, branch: str = "lane/hero") -> dict[str, Any]:
    sid = await _sid(url)
    r = await call_tool(
        url, "jane", "change_status", {"session_id": sid, "repo": "acme/site", "branch": branch}
    )
    assert not r.is_error, r.text
    assert r.data is not None
    return r.data


def _st(context: str, status: str) -> dict[str, Any]:
    return {"context": context, "status": status, "description": "d", "target_url": "http://x/1"}


async def test_status_before_any_build_says_so() -> None:
    for url, _ in running(_fake(), FakeProposer()):
        out = await _status(url)
        assert out["commit"] == SHA and out["builds"] == [] and out["build_state"] == "none"
        assert "no build has reported" in out["build_note"]
        assert out["preview"]["url"] == "https://testing.example.com/p/hero/"
        assert out["preview"]["uploaded_for_this_commit"] is False
        assert out["pull_request"] == {"available": True, "proposed": False}


async def test_status_reports_builds_and_the_preview_once_uploaded() -> None:
    builds = [_st("testing-site-lane / build (push)", "success"), _st(UPLOAD, "success")]
    for url, _ in running(_fake(builds), FakeProposer()):
        out = await _status(url)
        assert out["build_state"] == "success"
        assert [b["context"] for b in out["builds"]] == [b["context"] for b in builds]
        assert out["builds"][0] == {
            "context": "testing-site-lane / build (push)",
            "state": "success",
            "description": "d",
            "target_url": "http://x/1",
        }
        assert out["preview"]["uploaded_for_this_commit"] is True


async def test_failed_upload_is_not_a_live_preview() -> None:
    builds = [_st("testing-site-lane / build (push)", "success"), _st(UPLOAD, "failure")]
    for url, _ in running(_fake(builds), FakeProposer()):
        out = await _status(url)
        assert out["build_state"] == "failure"
        assert out["preview"]["uploaded_for_this_commit"] is False


async def test_status_follows_the_pull_request() -> None:
    merged = {**PR, "state": "merged", "review": "approved", "checks": "success"}
    proposer = FakeProposer(status=merged)
    for url, _ in running(_fake(), proposer):
        out = await _status(url)
        assert out["pull_request"] == {"available": True, **merged}
        # Signed, naming the tenant, the repo as Forgejo spells it and the branch.
        assert proposer.received == [
            (
                "/v1/proposals/status",
                {"tenant": "t", "repo": "acme/site", "branch": "lane/hero"},
            )
        ]


async def test_status_without_the_proposer_still_reports_the_build() -> None:
    for url, _ in running(_fake([_st(UPLOAD, "success")]), FakeProposer(down=True)):
        out = await _status(url)
        assert out["build_state"] == "success" and out["preview"]["uploaded_for_this_commit"]
        assert out["pull_request"]["available"] is False
        assert "unavailable" in out["pull_request"]["note"]
    for url, _ in running(_fake(), None, proposals=False):
        out = await _status(url)
        assert out["pull_request"] == {"available": False, "note": "proposals are not enabled"}


async def test_only_lane_branches_get_a_preview_link() -> None:
    for url, _ in running(_fake(), FakeProposer()):
        assert "preview" not in await _status(url, "main")


async def test_status_of_a_missing_branch_is_an_error() -> None:
    for url, _ in running(_fake(), FakeProposer()):
        sid = await _sid(url)
        r = await call_tool(
            url, "jane", "change_status", {"session_id": sid, "repo": "acme/site", "branch": "x"}
        )
        assert r.is_error and "does not exist" in r.text


async def _own_branch(url: str, sid: str, token: str = "jane") -> str:
    r = await call_tool(
        url, token, "create_branch", {"session_id": sid, "repo": "acme/site", "branch": "lane/new"}
    )
    assert not r.is_error, r.text
    return "lane/new"


def _propose_args(sid: str, branch: str, **kw: Any) -> dict[str, Any]:
    return {
        "session_id": sid,
        "repo": "acme/site",
        "branch": branch,
        "title": "Hero copy",
        "body": "Checked on the preview.",
        **kw,
    }


async def test_owner_proposes_their_branch() -> None:
    proposer = FakeProposer()
    for url, sink in running(_fake(), proposer):
        sid = await _sid(url)
        branch = await _own_branch(url, sid)
        r = await call_tool(url, "jane", "propose_change", _propose_args(sid, branch))
        assert not r.is_error, r.text
        assert r.data == {
            "proposed": True,
            "pull_request": PR["pull_request"],
            "commit": SHA,
            "owner_sub": "kc|jane",
        }
        assert proposer.received == [
            (
                "/v1/proposals",
                {
                    "tenant": "t",
                    "repo": "acme/site",
                    "branch": "lane/new",
                    "title": "Hero copy",
                    "body": "Checked on the preview.",
                },
            )
        ]
        # An attempt record first; the person's subject never in the result summary.
        events = [e for e in sink.events if e.get("tool") == "propose_change"]
        assert any(e.get("phase") == "attempt" for e in events)
        assert all("owner_sub" not in e.get("result", {}) for e in events)


async def test_someone_elses_branch_is_refused() -> None:
    proposer = FakeProposer()
    for url, _ in running(_fake(), proposer):
        sid = await _sid(url)
        branch = await _own_branch(url, sid)
        bob = await _sid(url, "bob")
        r = await call_tool(url, "bob", "propose_change", _propose_args(bob, branch))
        assert r.is_error and "not created by you" in r.text
        assert proposer.received == []


async def test_refusals_and_a_down_proposer_reach_the_model() -> None:
    refused = FakeProposer(propose=(422, {"refused": ["structural path: .forgejo/x.yml"]}))
    for url, _ in running(_fake(), refused):
        sid = await _sid(url)
        branch = await _own_branch(url, sid)
        r = await call_tool(url, "jane", "propose_change", _propose_args(sid, branch))
        assert not r.is_error, r.text
        assert r.data == {"proposed": False, "refused": ["structural path: .forgejo/x.yml"]}
    for url, _ in running(_fake(), FakeProposer(down=True)):
        sid = await _sid(url)
        branch = await _own_branch(url, sid)
        r = await call_tool(url, "jane", "propose_change", _propose_args(sid, branch))
        assert r.is_error and "not running" in r.text
    disabled = FakeProposer(
        propose=(503, {"error": "proposals are disabled: no proposer credential"})
    )
    for url, _ in running(_fake(), disabled):
        sid = await _sid(url)
        branch = await _own_branch(url, sid)
        r = await call_tool(url, "jane", "propose_change", _propose_args(sid, branch))
        assert r.is_error and "no proposer credential" in r.text


async def test_title_and_body_are_bounded() -> None:
    proposer = FakeProposer()
    for url, _ in running(_fake(), proposer):
        sid = await _sid(url)
        branch = await _own_branch(url, sid)
        for bad in ({"title": "  "}, {"title": "x" * 201}, {"body": "y" * 4001}):
            r = await call_tool(url, "jane", "propose_change", _propose_args(sid, branch, **bad))
            assert r.is_error, bad
        assert proposer.received == []


async def test_proposals_off_is_refused() -> None:
    for url, _ in running(_fake(), None, proposals=False):
        sid = await _sid(url)
        branch = await _own_branch(url, sid)
        r = await call_tool(url, "jane", "propose_change", _propose_args(sid, branch))
        assert r.is_error and "not enabled" in r.text
