# SPDX-License-Identifier: Apache-2.0
"""Append-only audit events, one per tool call, separated per tenant.

File contents are not copied into the audit trail: each committed file is
recorded by path, size and SHA-256. The commit itself holds the content.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from . import validation

log = logging.getLogger("alasin_mcp")


class AuditSink(Protocol):
    def emit(self, event: dict[str, Any]) -> None: ...


def new_event(**fields: Any) -> dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "time": datetime.now(UTC).isoformat(timespec="milliseconds"),
        **fields,
    }


class JsonlAuditSink:
    """One JSON line per event in ``<dir>/<tenant>/audit-<date>.jsonl``.

    Files are opened in append mode and each line is written with a single
    write and fsync. When the write creates the day's file (or the tenant's
    folder), the folder that gained the entry is fsynced too, so a crash right
    after cannot leave a written, fsynced line in a file no directory names.
    ``emit`` returns only once all of that is on disk, and raises otherwise.
    Ship the directory to write-once storage for retention.
    """

    def __init__(self, directory: str):
        self._dir = directory
        self._lock = threading.Lock()

    def ensure_dir(self) -> None:
        """Create the audit directory and make its entry durable (fsync the
        parent). Raises if it cannot."""
        with self._lock:
            path = os.path.abspath(self._dir)
            if not os.path.isdir(path):
                os.makedirs(path, mode=0o750, exist_ok=True)
                _fsync_dir(os.path.dirname(path))

    def emit(self, event: dict[str, Any]) -> None:
        tenant = validation.tenant_id(str(event["tenant"]))
        day = time.strftime("%Y-%m-%d", time.gmtime())
        folder = os.path.join(self._dir, tenant)
        path = os.path.join(folder, f"audit-{day}.jsonl")
        line = (json.dumps(event, separators=(",", ":"), default=str) + "\n").encode()
        with self._lock:
            new_folder = not os.path.isdir(folder)
            if new_folder:
                os.makedirs(folder, mode=0o750, exist_ok=True)
            new_file = not os.path.exists(path)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                _write_all(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            if new_file:
                _fsync_dir(folder)
            if new_folder:
                _fsync_dir(self._dir)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class StreamAuditSink:
    """Events as JSON lines on stderr (for log collectors)."""

    def emit(self, event: dict[str, Any]) -> None:
        sys.stderr.write(json.dumps({"audit": event}, default=str) + "\n")


class MemoryAuditSink:
    """Keeps events in a list (tests)."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class AuditUnavailable(Exception):
    """An audit event could not be recorded."""


class FanoutAuditSink:
    """Emit to every sink; raise if a required sink failed.

    ``sinks`` are required: if any of them failed, ``emit`` raises
    ``AuditUnavailable`` after all sinks have been tried, and the caller
    refuses the write it was about to make. ``best_effort`` sinks (stderr, a
    log collector) are tried too, but their failure is logged and never
    refuses anything: the durable record is the required sink's.
    """

    def __init__(self, sinks: list[AuditSink], best_effort: list[AuditSink] | None = None):
        self._sinks = sinks
        self._best_effort = best_effort or []

    def emit(self, event: dict[str, Any]) -> None:
        errors: list[BaseException] = []
        for s in self._sinks:
            try:
                s.emit(event)
            except Exception as e:  # noqa: BLE001 - every sink gets its turn
                errors.append(e)
        for s in self._best_effort:
            try:
                s.emit(event)
            except Exception as e:  # noqa: BLE001 - best effort by definition
                log.warning(
                    "best-effort audit sink %s failed: %s", type(s).__name__, type(e).__name__
                )
        if errors:
            raise AuditUnavailable(
                f"{len(errors)} of {len(self._sinks)} audit sinks failed: "
                + "; ".join(type(e).__name__ for e in errors)
            ) from errors[0]
