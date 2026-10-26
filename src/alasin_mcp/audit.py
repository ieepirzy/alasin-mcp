# SPDX-License-Identifier: Apache-2.0
"""Append-only audit events, one per tool call, separated per tenant.

File contents are not copied into the audit trail: each committed file is
recorded by path, size and SHA-256. The commit itself holds the content.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from . import validation


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
    write and fsync. Ship the directory to write-once storage for retention.
    """

    def __init__(self, directory: str):
        self._dir = directory
        self._lock = threading.Lock()

    def emit(self, event: dict[str, Any]) -> None:
        tenant = validation.tenant_id(str(event["tenant"]))
        day = time.strftime("%Y-%m-%d", time.gmtime())
        folder = os.path.join(self._dir, tenant)
        line = (json.dumps(event, separators=(",", ":"), default=str) + "\n").encode()
        with self._lock:
            os.makedirs(folder, mode=0o750, exist_ok=True)
            fd = os.open(
                os.path.join(folder, f"audit-{day}.jsonl"),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                0o640,
            )
            try:
                os.write(fd, line)
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
    """Emit to every sink; if any failed, raise after all have been tried."""

    def __init__(self, sinks: list[AuditSink]):
        self._sinks = sinks

    def emit(self, event: dict[str, Any]) -> None:
        errors: list[BaseException] = []
        for s in self._sinks:
            try:
                s.emit(event)
            except Exception as e:  # noqa: BLE001 - every sink gets its turn
                errors.append(e)
        if errors:
            raise AuditUnavailable(
                f"{len(errors)} of {len(self._sinks)} audit sinks failed: "
                + "; ".join(type(e).__name__ for e in errors)
            ) from errors[0]
