# SPDX-License-Identifier: Apache-2.0
"""Append-only audit events, one per tool call, separated per tenant.

File contents are not copied into the audit trail: each committed file is
recorded by size and SHA-256. The commit itself holds the content.

No personal data (Loimi decision-record 49f5331d, 2026-11-01): the events
ship to an object-locked bucket that nobody can edit for a year, so a
person is named only by their Keycloak subject (``sub``), never by name,
email or username, and free text that could contain one (commit messages,
intents, branch names, paths, refs, error messages) is recorded as a
SHA-256 and a length. ``redact`` is applied to every event before any sink
sees it. ``client_ip`` stays the raw address here: the audit-log gateway
(ieepirzy/infra, flux/audit-log/gateway.yaml) replaces every IP address
with a keyed hash before the record reaches the bucket, the same hash it
applies to the API server's sourceIPs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from . import validation

if TYPE_CHECKING:
    from .auth import Principal

log = logging.getLogger("alasin_mcp")

# Set by the code itself, never by a caller: kept as they are.
_KEEP = frozenset(
    {
        "event_id",
        "time",
        "tenant",
        "sub",
        "subject",
        "phase",
        "action",
        "tool",
        "outcome",
        "status",
        "commit",
        "auth_mode",
        "author_source",
        "method",
        "error_kind",
    }
)
# Never recorded: they name a person.
_DROP = frozenset({"principal_name", "principal_email", "author", "committer"})
# Free text naming a ref or a path: recorded as <key>_sha256.
_HASHED = frozenset({"branch", "from_ref", "ref", "base", "path"})

# Values a caller can choose (a /token form, a Basic header, a tool argument,
# a forwarded address) are written only in their own narrow shape; anything
# else becomes a digest, so nobody can lock a name or an email into the
# bucket by sending it as a client id, a grant type or a session id.
_GRANT_TYPES = frozenset({"authorization_code", "refresh_token", "client_credentials"})
# origo's registered clients: secrets.token_urlsafe(16).
_DCR_CLIENT = re.compile(r"[A-Za-z0-9_-]{22}")
# alasin's own session ids (store.py): "ws_" + secrets.token_urlsafe(18).
_SESSION = re.compile(r"ws_[A-Za-z0-9_-]{24}")
_HEX_SHA = re.compile(r"[0-9a-f]{64}")
_SHAPES: dict[str, re.Pattern[str]] = {
    "session_id": _SESSION,
    "trace_id": re.compile(r"[0-9a-f]{32}"),
    "span_id": re.compile(r"[0-9a-f]{16}"),
    "commit": re.compile(r"[0-9a-f]{7,64}"),
    "sha": re.compile(r"[0-9a-f]{7,64}"),
    "merge_base": re.compile(r"[0-9a-f]{7,64}"),
    "encoding": re.compile(r"utf-8|base64"),
}
# Pre-registered OAuth client ids (configuration, not callers): set by the
# OAuth front door at start (known_client_ids).
_known_clients: frozenset[str] = frozenset()


def known_client_ids(ids: Iterable[str]) -> None:
    """The configured OAuth client ids, written as they are; any other
    client_id that is not origo-registered-shaped becomes a digest."""
    global _known_clients
    _known_clients = frozenset(ids)


def _repo_shaped(value: str) -> bool:
    try:
        validation.repo(value)
    except validation.InvalidInput:
        return False
    return "@" not in value


def _ip_shaped(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _shaped(key: str, value: str) -> bool:
    """Whether a caller-reachable string value may be written as it is."""
    if key == "grant_type":
        return value in _GRANT_TYPES
    if key == "client_id":
        return value in _known_clients or bool(_DCR_CLIENT.fullmatch(value))
    if key == "client_ip":
        return _ip_shaped(value)
    if key == "repo":
        return _repo_shaped(value)
    if key.endswith("_sha256"):
        return bool(_HEX_SHA.fullmatch(value))
    if key == "url":
        return len(value) <= 300 and not EMAIL.search(value) and " " not in value
    shape = _SHAPES.get(key)
    return bool(shape and shape.fullmatch(value))


EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def digest(key: str, text: str) -> dict[str, Any]:
    """Free text as recorded: ``<key>_sha256`` and ``<key>_chars``, never the
    text (and never under its own key, so a reader never mistakes it)."""
    return {f"{key}_sha256": sha256_hex(text), f"{key}_chars": len(text)}


def who(principal: Principal) -> dict[str, str]:
    """The caller as an audit event names them: a person by their Keycloak
    subject alone; a principal with no person behind it (a static credential,
    an OAuth client) by its configured subject."""
    if principal.idp_subject:
        return {"sub": principal.idp_subject}
    return {"subject": principal.subject}


def redact(event: dict[str, Any], *, top: bool = True) -> dict[str, Any]:
    """The event as it is written: no names, emails or free text. Known
    identifying fields are dropped, refs and paths become ``<key>_sha256``,
    an error message becomes its digest, a caller-chosen value is kept only in
    its own narrow shape, and any other text becomes a digest too (fail safe,
    not open). Nested objects (``arguments``, ``result``, files) get the same
    treatment, except that only the top level keeps the code-set fields."""
    out: dict[str, Any] = {}
    for key, value in event.items():
        if key in _DROP or value is None and key in _HASHED:
            continue
        if key in _HASHED:
            out[f"{key}_sha256"] = sha256_hex(str(value))
        elif key == "error":
            out.update(digest("error", str(value)))
            out.setdefault("error_kind", event.get("error_kind") or "error")
        elif value is None or isinstance(value, bool | int | float):
            out[key] = value
        elif isinstance(value, dict):
            out[key] = redact(value, top=False)
        elif isinstance(value, list | tuple):
            out[key] = [
                redact(v, top=False) if isinstance(v, dict) else _item(key, v) for v in value
            ]
        elif isinstance(value, str) and (top and key in _KEEP or _shaped(key, value)):
            out[key] = value
        elif isinstance(value, str):
            out.update(digest(key, value))
        else:
            out.update(digest(key, json.dumps(value, sort_keys=True, default=str)))
    return out


def _item(key: str, value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    return sha256_hex(value if isinstance(value, str) else json.dumps(value, default=str))


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
