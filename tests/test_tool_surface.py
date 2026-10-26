# SPDX-License-Identifier: Apache-2.0
"""The tool surface is fixed. Adding a merge, delete or admin tool fails here."""

from __future__ import annotations

import os

import pytest

from alasin_mcp.app import build_app
from alasin_mcp.audit import MemoryAuditSink
from alasin_mcp.auth import StaticTokenVerifier
from alasin_mcp.config import AuthMode
from alasin_mcp.credentials import ModeRouter, ServiceAccountProvider
from alasin_mcp.store import LocalKeyWrapper, Store
from alasin_mcp.tenancy import StaticTenantResolver
from alasin_mcp.tools import TOOL_NAMES, Services
from tests.harness import list_tools, serve, tenant

pytestmark = pytest.mark.anyio

EXPECTED = {
    "begin_change",
    "list_repos",
    "list_branches",
    "list_folder",
    "read_file",
    "diff_branch",
    "create_branch",
    "commit_files",
}
FORBIDDEN_WORDS = ("merge", "delete", "remove", "admin", "secret", "setting", "sudo", "webhook")
FORBIDDEN_ARGS = {"tenant", "tenant_id", "base_url", "forgejo_url", "url", "host", "token"}


async def _tools() -> list:
    services = Services(
        resolver=StaticTenantResolver([tenant("t", "https://forgejo.example.com", "UNUSED")]),
        credentials=ModeRouter({AuthMode.SERVICE_ACCOUNT: ServiceAccountProvider()}),
        store=Store(":memory:", LocalKeyWrapper(os.urandom(32))),
        audit_sink=MemoryAuditSink(),
    )
    with serve(build_app(services, StaticTokenVerifier([("tok", "t", "s")]))) as url:
        return await list_tools(url, "tok")


async def test_exact_tool_set() -> None:
    names = {t.name for t in await _tools()}
    assert names == EXPECTED == set(TOOL_NAMES)
    for name in names:
        assert not any(w in name for w in FORBIDDEN_WORDS)


async def test_no_tool_takes_a_tenant_or_host_argument() -> None:
    for tool in await _tools():
        props = set((tool.input_schema or {}).get("properties", {}))
        assert not props & FORBIDDEN_ARGS, (tool.name, props)


async def test_every_tool_but_begin_change_requires_a_session() -> None:
    for tool in await _tools():
        required = set((tool.input_schema or {}).get("required", []))
        if tool.name == "begin_change":
            assert "session_id" not in required
        else:
            assert "session_id" in required, tool.name


async def test_commit_file_entries_offer_no_delete_or_rename() -> None:
    commit = next(t for t in await _tools() if t.name == "commit_files")
    text = str(commit.input_schema)
    assert "operation" not in text
    assert "from_path" not in text
