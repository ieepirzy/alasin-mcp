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

    @property
    def key(self) -> tuple[str, str]:
        return (self.tenant, self.subject)


class TokenVerifier(Protocol):
    async def verify(self, token: str) -> Principal | None:
        """Return the principal for a valid token, or None."""
        ...


class StaticTokenVerifier:
    """Accept a fixed set of bearer credentials, compared in constant time."""

    def __init__(self, credentials: list[tuple[str, str, str]]):
        # (token, tenant, subject); only the SHA-256 of each token is kept.
        self._entries = [
            (hashlib.sha256(tok.encode()).digest(), validation.tenant_id(tenant), subject)
            for tok, tenant, subject in credentials
        ]

    @classmethod
    def from_config(cls, creds: tuple[StaticCredential, ...]) -> StaticTokenVerifier:
        return cls([(c.token.resolve(), c.tenant, c.subject) for c in creds])

    async def verify(self, token: str) -> Principal | None:
        digest = hashlib.sha256(token.encode()).digest()
        found: Principal | None = None
        for expected, tenant, subject in self._entries:
            # No early exit, so timing does not reveal which entry matched.
            if hmac.compare_digest(digest, expected):
                found = Principal(tenant=tenant, subject=subject)
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
    ):
        self.app = app
        self.verifier = verifier
        self.public_paths = public_paths
        self.public_prefixes = public_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
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
            await _unauthorized(send)
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


async def _unauthorized(send: Send) -> None:
    body = json.dumps({"error": "invalid_token"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b'Bearer error="invalid_token"'),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
