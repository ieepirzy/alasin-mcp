# SPDX-License-Identifier: Apache-2.0
"""The caller's address for audit events.

Behind a tunnel connector (cloudflared) every request comes from the
connector's pod, so the peer address says nothing about who called. The
connector passes the caller's address in a header (``CF-Connecting-IP``).
That header is believed only when the peer itself is a trusted proxy;
from anyone else it is ignored, so a caller cannot choose the address
recorded for it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from starlette.requests import Request

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class ClientIpPolicy:
    header: str = ""
    trusted: tuple[_Net, ...] = ()

    @classmethod
    def from_config(cls, header: str, trusted: Iterable[str]) -> ClientIpPolicy:
        return cls(header.strip(), tuple(ipaddress.ip_network(t, strict=False) for t in trusted))

    def client_ip(self, request: Request | None) -> str | None:
        if request is None or request.client is None:
            return None
        peer = request.client.host
        if not self.header or not self.trusted:
            return peer
        try:
            peer_ip = ipaddress.ip_address(peer)
        except ValueError:
            return peer
        if not any(peer_ip in net for net in self.trusted):
            return peer
        raw = request.headers.get(self.header, "").strip()
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            # A trusted proxy without the header (or with garbage): the peer,
            # never the raw header value.
            return peer
