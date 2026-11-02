# SPDX-License-Identifier: Apache-2.0
"""git_access end to end: MCP tool → real ``git`` through the /git/ proxy →
a real Forgejo (tests/forgejo.py)."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from alasin_mcp.app import build_app
from alasin_mcp.audit import MemoryAuditSink
from alasin_mcp.auth import Principal
from alasin_mcp.config import AuthMode, GitAccessConfig
from alasin_mcp.credentials import ModeRouter, ServiceAccountProvider
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.tenancy import StaticTenantResolver
from alasin_mcp.tools import Services
from tests import forgejo as fj
from tests.harness import call_tool, free_port, serve, tenant

pytestmark = [pytest.mark.anyio, pytest.mark.forgejo, pytest.mark.timeout(300)]

GIT_TIMEOUT = 60


@pytest.fixture(scope="module")
def forgejo() -> Iterator[fj.Forgejo]:
    name, instance = fj.start()
    try:
        yield instance
    finally:
        fj.stop(name)


class Verifier:
    def __init__(self, table: dict[str, Principal]):
        self.table = table

    async def verify(self, token: str) -> Principal | None:
        return self.table.get(token)


JANE = Principal("a", "jane", "Jane Doe", "jane@example.com", email_verified=True)
BOB = Principal("a", "bob", "Bob Roe", "bob@example.com", email_verified=True)


@contextmanager
def server(
    forgejo: fj.Forgejo, monkeypatch: pytest.MonkeyPatch, ttl: int = 900
) -> Iterator[tuple[str, MemoryAuditSink, Store]]:
    monkeypatch.setenv("IT_BOT_TOKEN", forgejo.bot_token)
    port = free_port()
    t = tenant(
        "a",
        forgejo.url,
        "IT_BOT_TOKEN",
        repos=("acme/site",),
        branch_prefix="lane/",
        branch_owners=True,
        git_access=GitAccessConfig(public_url=f"http://127.0.0.1:{port}", ttl_seconds=ttl),
    )
    audit = MemoryAuditSink()
    store = Store(":memory:", LocalKeyWrapper(os.urandom(32)))
    services = Services(
        resolver=StaticTenantResolver([t]),
        credentials=ModeRouter({AuthMode.SERVICE_ACCOUNT: ServiceAccountProvider()}),
        store=store,
        audit_sink=audit,
    )
    app = build_app(services, Verifier({"tok-jane": JANE, "tok-bob": BOB}))
    with serve(app, port) as url:
        yield url, audit, store


async def ok(url: str, tool: str, args: dict[str, Any], token: str = "tok-jane") -> dict[str, Any]:
    r = await call_tool(url, token, tool, args)
    assert not r.is_error, r.text
    assert r.data is not None
    return r.data


def git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(cwd.parent),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C",
    }
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
        check=check,
    )


def clone(tmp: Path, access: dict[str, Any], name: str = "work") -> Path:
    git(tmp, "clone", "--branch", access["branch"], access["clone_url"], name)
    work = tmp / name
    for key, value in access["git_config"].items():
        git(work, "config", key, value)
    return work


def branch_head(forgejo: fj.Forgejo, branch: str) -> str | None:
    r = httpx.get(
        f"{forgejo.url}/api/v1/repos/acme/site/branches/{branch}",
        headers={"Authorization": f"token {forgejo.admin_token}"},
        timeout=10,
    )
    return r.json()["commit"]["id"] if r.status_code == 200 else None


async def test_clone_commit_push_through_the_proxy(
    forgejo: fj.Forgejo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: Any
) -> None:
    caplog.set_level(logging.DEBUG)
    with server(forgejo, monkeypatch) as (url, audit, _):
        sid = (await ok(url, "begin_change", {"intent": "copy edit"}))["session_id"]
        access = await ok(url, "git_access", {"session_id": sid, "repo": "acme/site"})
        branch = access["branch"]
        assert branch.startswith("lane/change-")
        token = access["clone_url"].split("x-token:", 1)[1].split("@", 1)[0]
        assert len(token) >= 40
        work = clone(tmp_path, access)
        assert (work / "index.html").read_text() == "<h1>Hi</h1>\n"
        (work / "index.html").write_text("<h1>Hello from git</h1>\n")
        git(work, "commit", "-am", "Update the headline")
        local = git(work, "rev-parse", "HEAD").stdout.strip()
        push = git(work, "push", "origin", branch, check=False)
        assert push.returncode == 0, push.stderr
        assert branch_head(forgejo, branch) == local
        commit = httpx.get(
            f"{forgejo.url}/api/v1/repos/acme/site/git/commits/{local}",
            headers={"Authorization": f"token {forgejo.admin_token}"},
            timeout=10,
        ).json()
        assert commit["commit"]["author"]["email"] == "jane@example.com"

        # A second push, after fetching: ordinary git keeps working.
        git(work, "fetch", "origin")
        (work / "index.html").write_text("<h1>Hello again</h1>\n")
        git(work, "commit", "-am", "Again")
        assert git(work, "push", "origin", branch, check=False).returncode == 0

    events = audit.events
    pushes = [e for e in events if e.get("action") == "git_push"]
    assert [e["phase"] for e in pushes] == ["attempt", "outcome", "attempt", "outcome"]
    assert all(e["outcome"] == "ok" for e in pushes if e["phase"] == "outcome")
    assert pushes[0]["refs"][0]["new_sha"] == local
    assert any(e.get("action") == "git_fetch" for e in events)
    # The credential is never written: not in the audit, not in the logs.
    assert token not in json.dumps(events)
    assert token not in caplog.text
    tool_events = [e for e in events if e.get("tool") == "git_access"]
    assert tool_events and "clone_url" not in json.dumps(tool_events)


async def test_pushes_outside_the_grant_are_refused(
    forgejo: fj.Forgejo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with server(forgejo, monkeypatch) as (url, audit, _):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        access = await ok(url, "git_access", {"session_id": sid, "repo": "acme/site"})
        branch = access["branch"]
        work = clone(tmp_path, access)
        (work / "index.html").write_text("<h1>sneaky</h1>\n")
        git(work, "commit", "-am", "x")
        main_before = branch_head(forgejo, "main")

        to_main = git(work, "push", "origin", "HEAD:main", check=False)
        assert to_main.returncode != 0
        assert "only refs/heads/" + branch in to_main.stderr
        new_branch = git(work, "push", "origin", "HEAD:refs/heads/lane/other", check=False)
        assert new_branch.returncode != 0 and branch_head(forgejo, "lane/other") is None
        git(work, "tag", "v1")
        assert git(work, "push", "origin", "v1", check=False).returncode != 0
        delete = git(work, "push", "origin", f":{branch}", check=False)
        assert delete.returncode != 0 and branch_head(forgejo, branch) is not None
        assert branch_head(forgejo, "main") == main_before

        # Forgejo's own protection still applies to the granted branch: the
        # lane/* rule protects schema/**.
        (work / "schema").mkdir()
        (work / "schema" / "x.sql").write_text("drop table users;\n")
        git(work, "add", "schema/x.sql")
        git(work, "commit", "-m", "schema")
        protected = git(work, "push", "origin", branch, check=False)
        assert protected.returncode != 0, protected.stderr

    refused = [e for e in audit.events if e.get("action") == "git_push" and e.get("error_kind")]
    assert len(refused) >= 4


async def test_expired_unknown_or_foreign_credentials_are_refused(
    forgejo: fj.Forgejo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with server(forgejo, monkeypatch, ttl=900) as (url, _, store):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        access = await ok(url, "git_access", {"session_id": sid, "repo": "acme/site"})
        base = access["clone_url"]
        # Another repository with this credential: refused.
        other = base.replace("/acme/site.git", "/acme/other.git")
        assert git(tmp_path, "clone", other, "o", check=False).returncode != 0
        # A made-up credential: 401 with git's Basic challenge.
        bogus = base.split("x-token:", 1)[0] + "x-token:nope@" + base.split("@", 1)[1]
        assert git(tmp_path, "clone", bogus, "b", check=False).returncode != 0
        r = httpx.get(base.split("@", 1)[0].split("//")[0] + "//" + base.split("@", 1)[1]
                      + "/info/refs?service=git-upload-pack", timeout=10)  # fmt: skip
        assert r.status_code == 401
        assert r.headers["www-authenticate"].startswith("Basic")
        # Expiry: move the credential's clock past its end.
        store._q("UPDATE git_tokens SET expires_at = ?", (time.time() - 1,))
        expired = git(tmp_path, "clone", base, "e", check=False)
        assert expired.returncode != 0
        assert "401" in expired.stderr or "Authentication failed" in expired.stderr


async def test_someone_elses_branch_is_refused(
    forgejo: fj.Forgejo, monkeypatch: pytest.MonkeyPatch
) -> None:
    with server(forgejo, monkeypatch) as (url, _, _):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        access = await ok(url, "git_access", {"session_id": sid, "repo": "acme/site"})
        bob_sid = (await ok(url, "begin_change", {}, token="tok-bob"))["session_id"]
        r = await call_tool(
            url,
            "tok-bob",
            "git_access",
            {"session_id": bob_sid, "repo": "acme/site", "branch": access["branch"]},
        )
        assert r.is_error and "not created by you" in r.text


async def test_force_push_is_left_to_forgejo(
    forgejo: fj.Forgejo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The proxy doesn't decide force pushes: Forgejo's branch protection does.
    The lane/* rule here doesn't allow them, so a rewrite of the branch fails."""
    with server(forgejo, monkeypatch) as (url, _, _):
        sid = (await ok(url, "begin_change", {}))["session_id"]
        access = await ok(url, "git_access", {"session_id": sid, "repo": "acme/site"})
        branch = access["branch"]
        work = clone(tmp_path, access)
        (work / "index.html").write_text("<h1>one</h1>\n")
        git(work, "commit", "-am", "one")
        assert git(work, "push", "origin", branch, check=False).returncode == 0
        pushed = branch_head(forgejo, branch)
        git(work, "commit", "--amend", "-m", "rewritten")
        forced = git(work, "push", "--force", "origin", branch, check=False)
        assert forced.returncode != 0, forced.stderr
        assert branch_head(forgejo, branch) == pushed
