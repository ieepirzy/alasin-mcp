# SPDX-License-Identifier: Apache-2.0
"""Every tool result stays under a client's limit, measured as it goes on the
wire (JSON, sent twice: as text and as structuredContent), and anything cut
can be read on until the file is whole."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from alasin_mcp.app import build_app
from alasin_mcp.audit import MemoryAuditSink
from alasin_mcp.auth import Principal
from alasin_mcp.tools import (
    MAX_DIFF_COMMITS,
    MAX_FOLDER_ENTRIES,
    RESULT_BUDGET,
    _decode_text,
    _line_window,
)
from tests.harness import FakeForgejo, FakeRepo, ToolResult, call_tool, fake_services, serve, tenant

pytestmark = pytest.mark.anyio

HOST, TOKEN = "forgejo.example.com", "forgejo-token"
WIRE_LIMIT = 60_000  # both copies together
# Every character JSON escapes, a control character at six bytes each.
ESCAPES = '"\\\t\x01\x1f'


class Principals:
    def __init__(self, table: dict[str, Principal]):
        self.table = table

    async def verify(self, token: str) -> Principal | None:
        return self.table.get(token)


PERSON = Principal("t", "person", "Jane Person", "jane@example.com", email_verified=True)


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_FORGEJO", TOKEN)


@contextmanager
def world(repo: FakeRepo) -> Iterator[tuple[str, MemoryAuditSink]]:
    fake = FakeForgejo()
    fake.add_host(HOST, TOKEN, "bot", {"acme/site": repo})
    sink = MemoryAuditSink()
    services = fake_services(fake, [tenant("t", f"https://{HOST}", "TEST_FORGEJO")], sink)
    with serve(build_app(services, Principals({"p": PERSON}))) as url:
        yield url, sink


async def ok(url: str, tool: str, args: dict[str, Any]) -> ToolResult:
    r = await call_tool(url, "p", tool, args)
    assert not r.is_error, r.text
    assert r.data is not None
    return r


def wire(r: ToolResult) -> int:
    """Bytes of both copies: the text block and structuredContent."""
    return len(r.text.encode()) + len(json.dumps(r.data, ensure_ascii=False).encode())


async def sid(url: str) -> str:
    r = await ok(url, "begin_change", {})
    assert r.data is not None
    return r.data["session_id"]


async def read_all(url: str, s: str, path: str) -> tuple[bytes, int]:
    """Follow next_start_line / next_offset to the end; the file and the call count."""
    args: dict[str, Any] = {"session_id": s, "repo": "acme/site", "path": path}
    got, calls = b"", 0
    while True:
        r = await ok(url, "read_file", args)
        assert r.data is not None
        calls += 1
        assert wire(r) <= WIRE_LIMIT, wire(r)
        d = r.data
        if d["encoding"] == "base64":
            got += base64.b64decode(d["content"])
            if d["next_offset"] is None:
                return got, calls
            args["offset"] = d["next_offset"]
        else:
            got += d["content"].encode()
            assert d["truncated"] is (d["next_start_line"] is not None)
            if d["next_start_line"] is None:
                return got, calls
            args["start_line"], args["offset"] = d["next_start_line"], d["next_offset"] or 0


@pytest.mark.parametrize(
    "content",
    [
        (ESCAPES * 4 + "\n") * 3000,  # escape-heavy lines
        ("x" * 99 + "\n") * 2000,  # plain lines
        "ä" * 100_000,  # one 200 KB line of two-byte characters
        "a" + ESCAPES * 40_000,  # one line, escape-heavy
        "a\r\nb\fc d\n" * 5000,  # CRLF and characters splitlines would split on
    ],
)
async def test_any_text_file_reads_back_exactly_within_the_wire_limit(content: str) -> None:
    data = content.encode()
    with world(FakeRepo(branches={"main": {"f.txt": data}})) as (url, _):
        got, calls = await read_all(url, await sid(url), "f.txt")
    assert got == data and calls >= 2


async def test_a_binary_file_reads_back_exactly_in_parts() -> None:
    data = bytes(range(256)) * 400  # ~100 KB, NUL bytes: binary
    with world(FakeRepo(branches={"main": {"b.bin": data}})) as (url, _):
        got, calls = await read_all(url, await sid(url), "b.bin")
    assert got == data and calls >= 3


async def test_lines_are_counted_on_newlines_only() -> None:
    with world(FakeRepo(branches={"main": {"f.txt": b"a\fb\nc d\n", "e.txt": b""}})) as (url, _):
        s = await sid(url)
        base = {"session_id": s, "repo": "acme/site"}
        r = await ok(url, "read_file", {**base, "path": "f.txt", "start_line": 2})
        assert r.data is not None
        assert r.data["total_lines"] == 2 and r.data["content"] == "c d\n"
        # An empty file has no line 2, like any other file has no line past its end.
        empty = await ok(url, "read_file", {**base, "path": "e.txt"})
        assert empty.data is not None and empty.data["total_lines"] == 0
        for bad in ({"start_line": 2}, {"offset": 1}):
            r = await call_tool(url, "p", "read_file", {**base, "path": "e.txt", **bad})
            assert r.is_error
        r = await call_tool(url, "p", "read_file", {**base, "path": "f.txt", "start_line": 3})
        assert r.is_error


async def test_list_folder_caps_entries_and_says_so() -> None:
    files = {f"many/{'n' * 40}{i:04d}.js": b"x" for i in range(MAX_FOLDER_ENTRIES + 100)}
    with world(FakeRepo(branches={"main": files})) as (url, _):
        s = await sid(url)
        r = await ok(url, "list_folder", {"session_id": s, "repo": "acme/site", "path": "many"})
    assert r.data is not None
    assert r.data["total_entries"] == MAX_FOLDER_ENTRIES + 100 and r.data["truncated"] is True
    assert 0 < len(r.data["entries"]) <= MAX_FOLDER_ENTRIES
    assert wire(r) <= WIRE_LIMIT


async def test_diff_branch_caps_commits_messages_and_diffs() -> None:
    commits = [
        {
            "sha": f"{i:040d}",
            "commit": {"message": ESCAPES * 500},
            "parents": [{"sha": f"{i - 1:040d}" if i else "b" * 40}],
        }
        for i in range(MAX_DIFF_COMMITS + 20)
    ]
    repo = FakeRepo(
        branches={"main": {}, "work": {"a.txt": ((ESCAPES * 30 + "\n") * 2000).encode()}},
        compare={"commits": commits, "files": [{"filename": "a.txt", "status": "added"}]},
    )
    with world(repo) as (url, _):
        s = await sid(url)
        r = await ok(url, "diff_branch", {"session_id": s, "repo": "acme/site", "branch": "work"})
    assert r.data is not None
    assert r.data["truncated"] is True and r.data["commit_count"] == MAX_DIFF_COMMITS + 20
    assert len(r.data["commits"]) <= MAX_DIFF_COMMITS
    assert wire(r) <= WIRE_LIMIT


async def test_a_small_diff_is_whole() -> None:
    repo = FakeRepo(
        branches={"main": {}, "work": {"a.txt": b"hi\n"}},
        compare={
            "commits": [{"sha": "1" * 40, "commit": {"message": "m"}, "parents": [{"sha": "b"}]}],
            "files": [{"filename": "a.txt", "status": "added"}],
        },
    )
    with world(repo) as (url, _):
        s = await sid(url)
        r = await ok(url, "diff_branch", {"session_id": s, "repo": "acme/site", "branch": "work"})
    assert r.data is not None and r.data["truncated"] is False
    assert "+hi" in r.data["files"][0]["diff"]


async def test_whoami_leaves_no_trace_of_the_person_in_the_audit() -> None:
    with world(FakeRepo(branches={"main": {}})) as (url, sink):
        r = await ok(url, "whoami", {})
        assert r.data is not None and r.data["email"] == "jane@example.com"
    logged = json.dumps(sink.events)
    for value in ("jane@example.com", "Jane Person"):
        assert value not in logged
        assert hashlib.sha256(value.encode()).hexdigest() not in logged
    assert "email_sha256" not in logged and "name_sha256" not in logged


# -- the window helper, without a server ---------------------------------------------------


def test_window_never_splits_a_character() -> None:
    w = _line_window("ä" * RESULT_BUDGET, 1, 0, 0, False)
    assert set(w["content"]) == {"ä"} and w["next_offset"] == len(w["content"])


def test_a_character_split_by_the_read_limit_is_still_text() -> None:
    data = "aä".encode()[:-1]  # the read stopped inside "ä"
    assert _decode_text(data, cut=True) == "a"
    assert _decode_text(data, cut=False) is None
    assert _decode_text(b"a\x00b", cut=False) is None


def test_a_file_cut_by_the_read_limit_says_so() -> None:
    w = _line_window("a\nb\n", 1, 0, 0, True)
    assert w["truncated"] is True and w["next_start_line"] is None and "longer" in w["note"]
