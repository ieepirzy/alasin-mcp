# SPDX-License-Identifier: Apache-2.0
"""The push checks in gitproxy.py, without a network: the pkt-line parser,
the refusal rules and the report-status answer."""

from __future__ import annotations

import base64

import pytest
from starlette.requests import ClientDisconnect, Request

from alasin_mcp.gitproxy import (
    MAX_COMMAND_BYTES,
    ProtocolError,
    credential,
    parse_push_head,
    pkt,
    refusal,
    report_refused,
)

A = "a" * 40
B = "b" * 40
Z = "0" * 40
CAPS = b"report-status side-band-64k agent=git/2.56.0"


def cmd(old: str, new: str, ref: str, caps: bytes | None = None) -> bytes:
    line = f"{old} {new} {ref}".encode()
    if caps is not None:
        line += b"\0" + caps
    return pkt(line + b"\n")


def test_parses_one_command_with_capabilities() -> None:
    body = cmd(A, B, "refs/heads/lane/x", CAPS) + b"0000" + b"PACK...."
    head = parse_push_head(body)
    assert head is not None
    assert [(c.old, c.new, c.ref) for c in head.commands] == [(A, B, "refs/heads/lane/x")]
    assert "report-status" in head.capabilities and "side-band-64k" in head.capabilities
    assert body[head.length :] == b"PACK...."


def test_partial_input_asks_for_more() -> None:
    body = cmd(A, B, "refs/heads/lane/x", CAPS) + b"0000"
    for cut in (0, 3, 10, len(body) - 4, len(body) - 1):
        assert parse_push_head(body[:cut]) is None, cut
    assert parse_push_head(body) is not None


@pytest.mark.parametrize(
    "body",
    [
        b"zzzz",  # not hex
        b"0003",  # shorter than its own length field
        b"0001",  # delimiter packet: protocol v2, not a push
        b"+00a",  # sign in the length
        b"0000",  # flush with no commands
        pkt(b"shallow " + A.encode() + b"\n") + b"0000",
        pkt(b"push-cert\0" + CAPS + b"\n") + b"0000",
        pkt(f"{A} {B}".encode() + b"\n") + b"0000",  # two fields
        pkt(f"{A} nothex refs/heads/x".encode() + b"\n") + b"0000",
        cmd(A, B, "refs/heads/x", CAPS) + pkt(f"{A} {B} refs/heads/y\0junk".encode()) + b"0000",
    ],
)
def test_malformed_input_is_refused(body: bytes) -> None:
    with pytest.raises(ProtocolError):
        parse_push_head(body)


def test_command_list_is_bounded() -> None:
    line = cmd(A, B, "refs/heads/lane/x", CAPS)
    many = line * (MAX_COMMAND_BYTES // len(line) + 2)
    with pytest.raises(ProtocolError):
        parse_push_head(many)
    # And a length field claiming more than a pkt-line may hold.
    with pytest.raises(ProtocolError):
        parse_push_head(b"fff1" + b"x" * 10)


def test_only_the_granted_branch_may_be_updated() -> None:
    def head(*cmds: bytes, caps: bytes = CAPS):  # noqa: ANN202
        body = cmds[0][:4] and b"".join(cmds) + b"0000"
        h = parse_push_head(body)
        assert h is not None
        return h

    ok = head(cmd(A, B, "refs/heads/lane/x", CAPS))
    assert refusal(ok, "lane/x") is None
    assert refusal(head(cmd(A, B, "refs/heads/main", CAPS)), "lane/x")
    assert refusal(head(cmd(A, B, "refs/heads/lane/xy", CAPS)), "lane/x")
    assert refusal(head(cmd(A, B, "refs/tags/v1", CAPS)), "lane/x")
    assert refusal(head(cmd(A, Z, "refs/heads/lane/x", CAPS)), "lane/x")  # delete
    assert refusal(head(cmd(Z, B, "refs/heads/lane/x", CAPS)), "lane/x")  # create
    two = head(cmd(A, B, "refs/heads/lane/x", CAPS), cmd(A, B, "refs/heads/other"))
    assert refusal(two, "lane/x")  # every command must qualify
    opts = head(cmd(A, B, "refs/heads/lane/x", CAPS + b" push-options"))
    assert refusal(opts, "lane/x")


def _pkts(data: bytes) -> list[bytes]:
    out, pos = [], 0
    while pos < len(data):
        size = int(data[pos : pos + 4], 16)
        if size == 0:
            out.append(b"")
            pos += 4
            continue
        out.append(data[pos + 4 : pos + size])
        pos += size
    return out


def test_refusal_is_a_report_status_the_client_prints() -> None:
    plain = parse_push_head(cmd(A, B, "refs/heads/main", b"report-status") + b"0000")
    assert plain is not None
    assert _pkts(report_refused(plain, "no")) == [
        b"unpack ok\n",
        b"ng refs/heads/main no\n",
        b"",
    ]
    banded = parse_push_head(cmd(A, B, "refs/heads/main", CAPS) + b"0000")
    assert banded is not None
    frames = _pkts(report_refused(banded, "no"))
    assert frames[0].startswith(b"\x02alasin: push refused")
    inner = b"".join(f[1:] for f in frames if f[:1] == b"\x01")
    assert _pkts(inner) == [b"unpack ok\n", b"ng refs/heads/main no\n", b""]
    assert frames[-1] == b""


def _request(auth: str | None) -> Request:
    headers = [] if auth is None else [(b"authorization", auth.encode())]
    return Request({"type": "http", "headers": headers, "method": "GET", "path": "/"})


def test_credential_is_the_basic_password() -> None:
    enc = base64.b64encode(b"x-token:secret-value").decode()
    assert credential(_request(f"Basic {enc}")) == "secret-value"
    assert credential(_request(None)) is None
    assert credential(_request("Bearer secret-value")) is None
    assert credential(_request("Basic !!!")) is None
    assert credential(_request("Basic " + base64.b64encode(b"nopassword").decode())) is None
    assert credential(_request("Basic " + base64.b64encode(b"user:").decode())) is None


def test_capabilities_are_an_allowlist() -> None:
    def caps(c: bytes):  # noqa: ANN202
        h = parse_push_head(cmd(A, B, "refs/heads/lane/x", c) + b"0000")
        assert h is not None
        return h

    real = b"report-status-v2 side-band-64k quiet object-format=sha1 agent=git/2.56.0"
    assert refusal(caps(real), "lane/x") is None
    assert refusal(caps(b"report-status atomic ofs-delta session-id=abc"), "lane/x") is None
    # git enables a feature for "name=value" too: push-options=1 must not slip by.
    assert refusal(caps(b"report-status push-options"), "lane/x")
    assert refusal(caps(b"report-status push-options=1"), "lane/x")
    assert refusal(caps(b"report-status some-future-thing"), "lane/x")


@pytest.mark.anyio
async def test_finishing_response_finishes_when_never_iterated() -> None:
    from alasin_mcp.gitproxy import _Finishing

    finished: list[bool] = []

    async def body():  # noqa: ANN202
        yield b"never"

    async def finish() -> None:
        finished.append(True)

    async def send(_message: object) -> None:
        raise OSError("client went away")

    async def receive() -> dict[str, str]:
        return {"type": "http.disconnect"}

    r = _Finishing(body(), finish, status_code=200)
    with pytest.raises((OSError, ClientDisconnect)):
        await r({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)
    assert finished == [True]
    await r.finish()  # idempotent
    assert finished == [True]
