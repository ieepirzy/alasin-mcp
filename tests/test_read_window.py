# SPDX-License-Identifier: Apache-2.0
"""read_file's windowing, without a server: caps, cut lines, split characters."""

from __future__ import annotations

from alasin_mcp.tools import MAX_READ_BYTES, _decode_text, _line_window


def test_one_line_longer_than_the_cap_returns_its_start() -> None:
    w = _line_window("x" * (MAX_READ_BYTES * 2) + "\nnext\n", 1, 0, False)
    assert len(w["content"]) == MAX_READ_BYTES
    assert w["truncated"] is True and w["next_start_line"] == 2 and "longer" in w["note"]


def test_window_never_splits_a_character() -> None:
    w = _line_window("ä" * MAX_READ_BYTES, 1, 0, False)
    assert len(w["content"].encode()) <= MAX_READ_BYTES and set(w["content"]) == {"ä"}


def test_a_character_split_by_the_read_limit_is_still_text() -> None:
    data = "aä".encode()[:-1]  # the read stopped inside "ä"
    assert _decode_text(data, cut=True) == "a"
    assert _decode_text(data, cut=False) is None
    assert _decode_text(b"a\x00b", cut=False) is None


def test_a_file_cut_by_the_read_limit_says_so() -> None:
    w = _line_window("a\nb\n", 1, 0, True)
    assert w["truncated"] is True and w["next_start_line"] is None and "longer" in w["note"]
