# SPDX-License-Identifier: Apache-2.0
"""Inbound authentication: who is calling, and for which tenant.

The tenant is taken from the verified credential and nowhere else. No tool
has a tenant argument, and nothing a client sends besides the bearer token
can change the principal.

Two verifiers ship:

- ``StaticTokenVerifier``: fixed bearer credentials, each bound to one
  tenant and subject. This is the service-account deployment: an OAuth
  gateway in front authenticates the user and forwards with this credential.
- ``JwtVerifier``: JWTs signed by an identity provider, checked against its
  JWKS. The tenant comes from a configured claim.

Anything else implements ``TokenVerifier``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import anyio
import jwt
from starlette.types import ASGIApp, Receive, Scope, Send

from . import validation
from .config import JwtConfig, StaticCredential

PRINCIPAL_SCOPE_KEY = "alasin.principal"


@dataclass(frozen=True)
class Principal:
    """A verified caller. ``(tenant, subject)`` keys everything stored for them."""

    tenant: str
    subject: str
    name: str | None = None
    email: str | None = None
    claims: Mapping[str, Any] = field(default_factory=dict)
    # Verified through a static credential marked gateway = true: the only
    # callers whose trusted author header is honoured.
    via_gateway: bool = False
    # The identity provider asserted the email is verified (email_verified).
    email_verified: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return (self.tenant, self.subject)


class TokenVerifier(Protocol):
    async def verify(self, token: str) -> Principal | None:
        """Return the principal for a valid token, or None."""
        ...


class StaticTokenVerifier:
    """Accept a fixed set of bearer credentials, compared in constant time.

    Credentials given as secret references (``from_config``) are re-read every
    ``reload_seconds``, so rotating the file or variable needs no restart. List
    two ``[[auth.static]]`` entries for the same tenant and subject to keep the
    old and new credential valid while the gateway switches over.
    """

    def __init__(
        self,
        credentials: list[tuple[str, str, str]] | None = None,
        refs: tuple[StaticCredential, ...] = (),
        reload_seconds: float = 30.0,
    ):
        self._fixed = [
            (hashlib.sha256(tok.encode()).digest(), validation.tenant_id(tenant), subject, False)
            for tok, tenant, subject in credentials or []
        ]
        self._refs = refs
        self._reload = reload_seconds
        self._loaded: list[tuple[bytes, str, str, bool]] = []
        self._loaded_at = float("-inf")
        if refs:
            self._load()

    @classmethod
    def from_config(cls, creds: tuple[StaticCredential, ...]) -> StaticTokenVerifier:
        return cls(refs=creds)

    def _load(self) -> None:
        loaded = []
        for c in self._refs:
            try:
                token = c.token.resolve()
            except (OSError, ValueError):
                # A credential mid-rotation (file briefly missing) is skipped,
                # not fatal; the others keep working.
                continue
            digest = hashlib.sha256(token.encode()).digest()
            loaded.append((digest, c.tenant, c.subject, c.gateway))
        self._loaded = loaded
        self._loaded_at = time.monotonic()

    async def verify(self, token: str) -> Principal | None:
        if self._refs and time.monotonic() - self._loaded_at > self._reload:
            self._load()
        digest = hashlib.sha256(token.encode()).digest()
        found: Principal | None = None
        for expected, tenant, subject, gateway in self._fixed + self._loaded:
            # No early exit, so timing does not reveal which entry matched.
            if hmac.compare_digest(digest, expected):
                found = Principal(tenant=tenant, subject=subject, via_gateway=gateway)
        return found


class JwtVerifier:
    """Verify JWTs against an issuer's JWKS; the tenant comes from a claim."""

    def __init__(self, cfg: JwtConfig, jwks_client: jwt.PyJWKClient | None = None):
        self._cfg = cfg
        self._jwks = jwks_client or jwt.PyJWKClient(cfg.jwks_url, cache_keys=True, timeout=10)

    async def verify(self, token: str) -> Principal | None:
        cfg = self._cfg
        try:
            # PyJWKClient fetches over the network synchronously.
            key = await anyio.to_thread.run_sync(self._jwks.get_signing_key_from_jwt, token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=list(cfg.algorithms),
                audience=cfg.audience,
                issuer=cfg.issuer,
                options={"require": ["exp", "iss", "aud", cfg.subject_claim]},
            )
        except (jwt.PyJWTError, OSError):
            return None
        tenant = claims.get(cfg.tenant_claim) or cfg.default_tenant
        subject = claims.get(cfg.subject_claim)
        if not isinstance(tenant, str) or not isinstance(subject, str) or not subject:
            return None
        try:
            validation.tenant_id(tenant)
        except validation.InvalidInput:
            return None
        name = claims.get(cfg.name_claim)
        email = claims.get(cfg.email_claim)
        return Principal(
            tenant=tenant,
            subject=subject,
            name=name if isinstance(name, str) else None,
            email=email if isinstance(email, str) else None,
            claims=claims,
            email_verified=claims.get("email_verified") is True,
        )


class ChainVerifier:
    """Try each verifier in order; the first principal wins."""

    def __init__(self, verifiers: list[TokenVerifier]):
        self._verifiers = verifiers

    async def verify(self, token: str) -> Principal | None:
        for v in self._verifiers:
            p = await v.verify(token)
            if p is not None:
                return p
        return None


class BearerAuthMiddleware:
    """Require a valid bearer token on every path except the public ones.

    The verified principal is put in the ASGI scope; tools read it from the
    request that carried their message, so it can't leak between requests.
    """

    def __init__(
        self,
        app: ASGIApp,
        verifier: TokenVerifier,
        public_paths: tuple[str, ...] = ("/healthz",),
        public_prefixes: tuple[str, ...] = (),
        max_body_bytes: int = 8 * 1024 * 1024,
        challenge: bytes = b'Bearer error="invalid_token"',
    ):
        self.app = app
        self.verifier = verifier
        self.public_paths = public_paths
        self.public_prefixes = public_prefixes
        self.max_body_bytes = max_body_bytes
        self.challenge = challenge

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            # WebSockets and anything else: this server speaks plain HTTP only.
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        length = _content_length(scope)
        if length is not None and length > self.max_body_bytes:
            await _error(send, 413, "request_too_large")
            return
        # Never trust a principal that something upstream put in the scope.
        scope.pop(PRINCIPAL_SCOPE_KEY, None)
        path: str = scope.get("path", "")
        if path in self.public_paths or path.startswith(self.public_prefixes):
            await self.app(scope, receive, send)
            return
        token = _bearer(scope)
        principal = await self.verifier.verify(token) if token else None
        if principal is None:
            await _error(send, 401, "invalid_token", [(b"www-authenticate", self.challenge)])
            return
        scope[PRINCIPAL_SCOPE_KEY] = principal
        await self.app(scope, receive, send)


def _bearer(scope: Scope) -> str | None:
    for name, value in scope.get("headers", ()):
        if name == b"authorization":
            raw = value.decode("latin-1")
            scheme, _, token = raw.partition(" ")
            if scheme.lower() == "bearer" and token.strip():
                return token.strip()
            return None
    return None


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", ()):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _error(
    send: Send, status: int, error: str, extra: list[tuple[bytes, bytes]] | None = None
) -> None:
    body = json.dumps({"error": error}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                *(extra or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
