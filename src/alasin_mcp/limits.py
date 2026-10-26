# SPDX-License-Identifier: Apache-2.0
"""Per-tenant rate limits and a per-principal cache (both in process memory)."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any

from .auth import Principal


class RateLimited(Exception):
    pass


class TenantRateLimiter:
    """A token bucket per tenant: ``per_minute`` calls, refilled continuously."""

    def __init__(self) -> None:
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, tenant: str, per_minute: int, now: float | None = None) -> None:
        if per_minute <= 0:
            return
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last = self._buckets.get(tenant, (float(per_minute), now))
            tokens = min(float(per_minute), tokens + (now - last) * per_minute / 60.0)
            if tokens < 1.0:
                self._buckets[tenant] = (tokens, now)
                raise RateLimited(f"rate limit of {per_minute} calls per minute reached")
            self._buckets[tenant] = (tokens - 1.0, now)


class PrincipalCache:
    """A small TTL cache whose keys always start with the caller's (tenant, subject).

    There is no way to read or write an entry without naming a principal, so
    one principal's entries can never answer another's lookup.
    """

    def __init__(self, ttl: float = 60.0, max_entries: int = 4096):
        self._ttl = ttl
        self._max = max_entries
        self._data: OrderedDict[tuple[Any, ...], tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, principal: Principal, *key: Any) -> Any | None:
        full = (*principal.key, *key)
        with self._lock:
            hit = self._data.get(full)
            if hit is None:
                return None
            if hit[0] < time.monotonic():
                del self._data[full]
                return None
            return hit[1]

    def set(self, principal: Principal, *key_and_value: Any) -> None:
        *key, value = key_and_value
        full = (*principal.key, *key)
        with self._lock:
            self._data[full] = (time.monotonic() + self._ttl, value)
            self._data.move_to_end(full)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def keys(self) -> list[tuple[Any, ...]]:
        with self._lock:
            return list(self._data)
