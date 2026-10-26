# SPDX-License-Identifier: Apache-2.0
"""Durable state: work sessions, delegated tokens and OAuth flow state (SQLite).

Isolation rules this module enforces:

- Every row is keyed by ``(tenant, subject)``. Lookups take both and match
  both, so a session ID or token row of one principal is invisible to another.
- Stored tokens are encrypted with a per-tenant data key (AES-256-GCM). Each
  data key is itself encrypted ("wrapped") by the master key: envelope
  encryption. The associated data binds each ciphertext to its tenant and
  subject, so a ciphertext copied to another row fails to decrypt.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenant_keys (
    tenant TEXT PRIMARY KEY,
    nonce BLOB NOT NULL,
    wrapped BLOB NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    tenant TEXT NOT NULL,
    subject TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (tenant, subject)
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    subject TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    subject TEXT NOT NULL,
    verifier TEXT NOT NULL,
    match_value TEXT NOT NULL,
    expires_at REAL NOT NULL
);
"""


class KeyWrapper(Protocol):
    """Wraps and unwraps per-tenant data keys. Swap in a KMS client here."""

    def wrap(self, tenant: str, dek: bytes) -> tuple[bytes, bytes]: ...

    def unwrap(self, tenant: str, nonce: bytes, wrapped: bytes) -> bytes: ...


class LocalKeyWrapper:
    """Wrap data keys with a 32-byte master key held by the process."""

    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._aead = AESGCM(master_key)

    @classmethod
    def from_secret(cls, secret: str) -> LocalKeyWrapper:
        """The secret is the master key, base64 encoded (``openssl rand -base64 32``)."""
        return cls(base64.b64decode(secret, validate=True))

    def wrap(self, tenant: str, dek: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        return nonce, self._aead.encrypt(nonce, dek, b"alasin-dek\x00" + tenant.encode())

    def unwrap(self, tenant: str, nonce: bytes, wrapped: bytes) -> bytes:
        return self._aead.decrypt(nonce, wrapped, b"alasin-dek\x00" + tenant.encode())


class DecryptionFailed(Exception):
    pass


@dataclass(frozen=True)
class WorkSession:
    session_id: str
    tenant: str
    subject: str
    trace_id: str
    span_id: str
    intent: str
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class OAuthState:
    tenant: str
    subject: str
    verifier: str
    match_value: str


class Store:
    def __init__(self, path: str, key_wrapper: KeyWrapper | None = None):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()
        self._keys = key_wrapper
        self._dek_cache: dict[str, bytes] = {}

    def close(self) -> None:
        self._db.close()

    def _q(self, sql: str, args: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # -- envelope encryption -------------------------------------------------

    def _tenant_key(self, tenant: str) -> bytes:
        if self._keys is None:
            raise RuntimeError("no master key configured; token storage is unavailable")
        if tenant in self._dek_cache:
            return self._dek_cache[tenant]
        rows = self._q("SELECT nonce, wrapped FROM tenant_keys WHERE tenant = ?", (tenant,))
        if rows:
            dek = self._keys.unwrap(tenant, rows[0][0], rows[0][1])
        else:
            dek = AESGCM.generate_key(bit_length=256)
            nonce, wrapped = self._keys.wrap(tenant, dek)
            self._q(
                "INSERT OR IGNORE INTO tenant_keys VALUES (?, ?, ?, ?)",
                (tenant, nonce, wrapped, time.time()),
            )
            # Another writer may have won the insert; always use the stored key.
            rows = self._q("SELECT nonce, wrapped FROM tenant_keys WHERE tenant = ?", (tenant,))
            dek = self._keys.unwrap(tenant, rows[0][0], rows[0][1])
        self._dek_cache[tenant] = dek
        return dek

    @staticmethod
    def _aad(tenant: str, subject: str) -> bytes:
        return b"alasin-token\x00" + tenant.encode() + b"\x00" + subject.encode()

    def put_token(self, tenant: str, subject: str, record: dict[str, Any]) -> None:
        aead = AESGCM(self._tenant_key(tenant))
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, json.dumps(record).encode(), self._aad(tenant, subject))
        self._q(
            "INSERT OR REPLACE INTO tokens VALUES (?, ?, ?, ?, ?)",
            (tenant, subject, nonce, ct, time.time()),
        )

    def get_token(self, tenant: str, subject: str) -> dict[str, Any] | None:
        rows = self._q(
            "SELECT nonce, ciphertext FROM tokens WHERE tenant = ? AND subject = ?",
            (tenant, subject),
        )
        if not rows:
            return None
        aead = AESGCM(self._tenant_key(tenant))
        try:
            plain = aead.decrypt(rows[0][0], rows[0][1], self._aad(tenant, subject))
        except InvalidTag:
            raise DecryptionFailed(f"token row for {tenant}/{subject} failed to decrypt") from None
        return json.loads(plain)

    def delete_token(self, tenant: str, subject: str) -> None:
        self._q("DELETE FROM tokens WHERE tenant = ? AND subject = ?", (tenant, subject))

    # -- work sessions ---------------------------------------------------------

    def create_session(
        self, tenant: str, subject: str, trace_id: str, span_id: str, intent: str, ttl: float
    ) -> WorkSession:
        now = time.time()
        s = WorkSession(
            session_id="ws_" + secrets.token_urlsafe(18),
            tenant=tenant,
            subject=subject,
            trace_id=trace_id,
            span_id=span_id,
            intent=intent,
            created_at=now,
            expires_at=now + ttl,
        )
        self._q(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (s.session_id, tenant, subject, trace_id, span_id, intent, now, s.expires_at),
        )
        self._q("DELETE FROM sessions WHERE expires_at < ?", (now,))
        return s

    def get_session(self, tenant: str, subject: str, session_id: str) -> WorkSession | None:
        """A session is visible only to the (tenant, subject) that began it."""
        rows = self._q(
            "SELECT session_id, tenant, subject, trace_id, span_id, intent, created_at, expires_at"
            " FROM sessions WHERE session_id = ? AND tenant = ? AND subject = ? AND expires_at > ?",
            (session_id, tenant, subject, time.time()),
        )
        return WorkSession(*rows[0]) if rows else None

    # -- OAuth flow state (user-delegated mode) ----------------------------------

    def put_oauth_state(
        self, tenant: str, subject: str, verifier: str, match_value: str, ttl: float = 600
    ) -> str:
        state = secrets.token_urlsafe(32)
        now = time.time()
        self._q("DELETE FROM oauth_states WHERE expires_at < ?", (now,))
        self._q(
            "INSERT INTO oauth_states VALUES (?, ?, ?, ?, ?, ?)",
            (state, tenant, subject, verifier, match_value, now + ttl),
        )
        return state

    def take_oauth_state(self, state: str) -> OAuthState | None:
        """Single use: the row is deleted whether or not it has expired."""
        with self._lock:
            rows = self._db.execute(
                "SELECT tenant, subject, verifier, match_value, expires_at"
                " FROM oauth_states WHERE state = ?",
                (state,),
            ).fetchall()
            self._db.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
        if not rows or rows[0][4] < time.time():
            return None
        return OAuthState(*rows[0][:4])
