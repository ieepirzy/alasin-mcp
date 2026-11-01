# SPDX-License-Identifier: Apache-2.0
"""OAuth front door: an MCP client such as claude.ai signs in to this server.

An ``OAuthFrontDoor`` adds three things to the app: the routes a client
discovers and signs in through, a ``TokenVerifier`` for the access tokens it
then sends, and the ``WWW-Authenticate`` challenge that points a client
without a token at the discovery document. It sits beside the static
credentials, never in place of them: a machine caller with an
``[[auth.static]]`` bearer keeps working on the same ``/mcp``.

One front door ships:

- ``OrigoFrontDoor`` (``provider = "origo"``): origo, an OAuth 2.1 + PKCE
  authorization server that runs in this process. Needs the ``origo`` extra
  (``pip install 'alasin-mcp[origo]'``).

An external OAuth/OIDC issuer would be another implementation: its verifier
is a ``JwtVerifier`` against the issuer's JWKS, and its routes serve only the
protected-resource metadata naming that issuer.

Every token from a front door maps to one configured tenant. Who the subject
is depends on how people sign in:

- With ``[auth.oauth.identity_provider]``, origo sends each person to the
  upstream OIDC provider (Keycloak) and its tokens carry that person's claims.
  The subject is ``oauth:<origo sub>``, where origo's sub is
  ``<issuer>|<IdP sub>``; the name, the verified email and the groups come
  with it. A token that names no person, or names one from another issuer, is
  refused.
- Without one, origo's approve-only consent page authenticates nobody, so the
  subject is the OAuth client, ``oauth:<client id>``, shared by everyone who
  signs in through it. origo refuses that unless
  ``allow_unauthenticated_consent`` is set.

Sign-ins are audited at origo's ``/token`` (it has no issuance hook), in the
same two phases as the write tools:

1. an *attempt* event (grant type, client, address) is written BEFORE origo
   sees the request. If it cannot be written the client gets 503 and origo
   is never called, so no code or refresh token is spent (fail closed);
2. an *outcome* event naming the person the issued token speaks for. A token
   that cannot be attributed (an unparsable response, or a token our own
   verifier refuses) is never delivered: 503. If only the outcome write
   fails: a sign-in (authorization code) gets 503, which costs a fresh
   authorization; a refresh gets its token, logged, because origo has
   already rotated the refresh token and withholding it would end the
   session.
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol
from urllib.parse import unquote

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .audit import AuditSink, new_event
from .auth import Principal, TokenVerifier
from .clientip import ClientIpPolicy
from .config import (
    OAUTH_SUBJECT_PREFIX,
    ConfigError,
    IdentityProviderConfig,
    OAuthServerConfig,
)

log = logging.getLogger("alasin_mcp")

# origo's token endpoint: where a sign-in (authorization_code) or a refresh
# turns into an access token.
TOKEN_PATH = "/token"  # noqa: S105 - a URL path, not a credential
_GRANT_ACTIONS = {"authorization_code": "sign_in", "refresh_token": "token_refresh"}
# origo's own limit on a /token form (endpoints._read_body_limited).
_MAX_TOKEN_BODY = 1024 * 1024
_UNAVAILABLE = {
    "error": "temporarily_unavailable",
    "error_description": "the audit trail is unavailable; try again",
}


class OAuthFrontDoor(Protocol):
    verifier: TokenVerifier

    def install(self, app: Starlette) -> tuple[str, ...]:
        """Add the sign-in routes to ``app``; return the paths that need no token."""
        ...

    def challenge(self) -> bytes:
        """The ``WWW-Authenticate`` value sent with a 401."""
        ...


class _OrigoVerifier:
    def __init__(self, provider: Any, tenant: str, issuer: str | None = None):
        self._provider = provider
        self._tenant = tenant
        # Set when people sign in through an IdP: every token must then name a
        # person from exactly this issuer.
        self._issuer = issuer

    async def verify(self, token: str) -> Principal | None:
        # Bound to this server's resource, so a token origo minted for another
        # resource is refused.
        meta = self._provider.verify_token(token, resource=self._provider.resource_identifier)
        if meta is None:
            return None
        client = meta.get("client_id")
        if not isinstance(client, str) or not client:
            return None
        if self._issuer is None:
            return Principal(tenant=self._tenant, subject=OAUTH_SUBJECT_PREFIX + client)
        sub = meta.get("sub")
        prefix = self._issuer + "|"
        if not isinstance(sub, str) or not sub.startswith(prefix) or len(sub) == len(prefix):
            return None
        name, email, groups = meta.get("name"), meta.get("email"), meta.get("groups")
        return Principal(
            tenant=self._tenant,
            subject=OAUTH_SUBJECT_PREFIX + sub,
            name=name if isinstance(name, str) and name.strip() else None,
            email=email if isinstance(email, str) and email else None,
            claims={
                **meta,
                "groups": [g for g in groups if isinstance(g, str)]
                if isinstance(groups, list)
                else [],
            },
            # origo includes email only when the IdP asserted email_verified.
            email_verified=isinstance(email, str) and bool(email),
            # The issuer is dropped: with one configured issuer the IdP's own
            # sub is unambiguous, and it is what the sync bot records (owner_sub).
            # The full origo sub stays in the subject.
            idp_subject=sub[len(prefix) :],
        )


async def _read_token_form(request: Request) -> tuple[str, str] | None:
    """grant_type and client_id of a /token request, read before origo sees
    it. The body is read once, with origo's own size limit, into the cache
    origo then uses (request._body); Starlette parses the form once for
    both. None: a body origo would refuse anyway (too large, unparsable)."""
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_TOKEN_BODY:
            return None
    request._body = bytes(body)  # pyright: ignore[reportAttributeAccessIssue]
    try:
        form = await request.form()
    except Exception:  # noqa: BLE001 - a malformed form; origo answers 400
        return None
    grant_type, client_id = form.get("grant_type"), form.get("client_id")
    client = client_id if isinstance(client_id, str) else ""
    if not client:
        client = _basic_client_id(request.headers.get("authorization", ""))
    return (grant_type if isinstance(grant_type, str) else "", client)


def _basic_client_id(header: str) -> str:
    """The client id of client_secret_basic (RFC 6749 2.3.1), or ''."""
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic" or not value:
        return ""
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode()
    except (ValueError, UnicodeDecodeError):
        return ""
    user, sep, _ = decoded.partition(":")
    return unquote(user) if sep else ""


def _identity_provider(cfg: IdentityProviderConfig) -> Any:
    from origo import IdentityProvider

    return IdentityProvider(
        issuer=cfg.issuer,
        client_id=cfg.client_id,
        client_secret=cfg.client_secret.resolve(),
        allowed_groups=list(cfg.allowed_groups),
        groups_claim=cfg.groups_claim,
        allowed_email_domains=list(cfg.allowed_email_domains) or None,
        max_grant_age=cfg.max_grant_age_seconds,
    )


class OrigoFrontDoor:
    def __init__(
        self,
        cfg: OAuthServerConfig,
        base_url: str,
        mcp_path: str,
        audit_sink: AuditSink | None = None,
        client_ip: ClientIpPolicy | None = None,
    ):
        self._tenant = cfg.tenant
        self._audit_sink = audit_sink
        self._client_ip = client_ip or ClientIpPolicy()
        try:
            from origo import OAuthProvider
        except ImportError as e:
            raise ConfigError(
                'auth.oauth provider = "origo" needs the origo extra: '
                "pip install 'alasin-mcp[origo]'"
            ) from e
        idp = cfg.identity_provider
        self._provider = OAuthProvider(
            base_url=base_url,
            clients={c.id: c.secret.resolve() for c in cfg.clients},
            client_redirect_uris={c.id: list(c.redirect_uris) for c in cfg.clients},
            public_registration=cfg.public_registration,
            auto_approve=cfg.auto_approve,
            token_ttl=cfg.token_ttl_seconds,
            refresh_token_ttl=cfg.refresh_token_ttl_seconds,
            client_ttl=cfg.client_ttl_seconds,
            mcp_path=mcp_path,
            storage_path=cfg.storage_path or None,
            identity_provider=_identity_provider(idp) if idp is not None else None,
            allow_unauthenticated_consent=cfg.allow_unauthenticated_consent,
        )
        self.verifier: TokenVerifier = _OrigoVerifier(
            self._provider, cfg.tenant, idp.issuer if idp is not None else None
        )

    def install(self, app: Starlette) -> tuple[str, ...]:
        # Routes and state are both taken from origo's own app: its handlers
        # read request.app.state, and that set grows between origo releases.
        oauth_app = self._provider.asgi_app()
        for route in reversed(oauth_app.routes):
            if (
                self._audit_sink is not None
                and isinstance(route, Route)
                and route.path == TOKEN_PATH
            ):
                route = Route(
                    route.path,
                    self._audited_token(route.endpoint),
                    methods=list(route.methods or ()),
                    name=route.name,
                )
            app.router.routes.insert(0, route)
        for key, value in vars(oauth_app.state)["_state"].items():
            setattr(app.state, key, value)
        # origo's handlers check their own credentials (client secret, code,
        # PKCE verifier, the IdP's answer on /authorize/callback, the bearer on
        # /userinfo); none takes an /mcp token.
        return tuple(getattr(r, "path", "") for r in oauth_app.routes)

    def _audited_token(
        self, endpoint: Callable[[Request], Awaitable[Response]]
    ) -> Callable[[Request], Awaitable[Response]]:
        sink = self._audit_sink
        assert sink is not None

        async def emit(event: dict[str, Any]) -> None:
            await anyio.to_thread.run_sync(sink.emit, event)

        async def token(request: Request) -> Response:
            form = await _read_token_form(request)
            if form is None:
                # origo refuses it too (it sees the same cached body); no
                # token can come of it, so no attempt to record.
                return await endpoint(request)
            grant_type, client_id = form
            base = new_event(
                tenant=self._tenant,
                action=_GRANT_ACTIONS.get(grant_type, "token"),
                grant_type=grant_type or None,
                client_id=client_id or None,
                client_ip=self._client_ip.client_ip(request),
            )
            try:
                await emit({**base, "phase": "attempt"})
            except Exception:
                log.error("token attempt event could not be recorded; refusing before origo")
                return JSONResponse(
                    _UNAVAILABLE, status_code=503, headers={"Cache-Control": "no-store"}
                )
            response = await endpoint(request)
            outcome = {**base, **new_event(), "phase": "outcome", "status": response.status_code}
            if response.status_code != 200:
                outcome["outcome"] = "error"
                try:
                    await emit(outcome)
                except Exception:
                    log.exception(
                        "audit outcome for a refused token exchange could not be recorded"
                    )
                return response
            principal = await self._issued_principal(response)
            if principal is None:
                # A 200 whose token we cannot attribute: never delivered.
                outcome.update(outcome="error", error="issued token could not be attributed")
                try:
                    await emit(outcome)
                except Exception:
                    log.exception("audit outcome for an unattributed token could not be recorded")
                log.error("token issued that no verifier attributes; withholding it")
                return JSONResponse(
                    _UNAVAILABLE, status_code=503, headers={"Cache-Control": "no-store"}
                )
            outcome.update(
                outcome="ok",
                subject=principal.subject,
                principal_name=principal.name,
                principal_email=principal.email,
            )
            try:
                await emit(outcome)
            except Exception:
                if grant_type == "refresh_token":
                    # origo already rotated the refresh token: withholding the
                    # new pair would end the session. The attempt is recorded.
                    # Who it was goes to stderr at least: the attempt event
                    # names no person.
                    log.error(
                        "token refresh outcome could not be recorded; delivering "
                        "(attempt %s, subject %s, client %s)",
                        base["event_id"],
                        principal.subject,
                        client_id or "-",
                    )
                    return response
                log.error("sign-in outcome could not be recorded; withholding the token")
                return JSONResponse(
                    _UNAVAILABLE, status_code=503, headers={"Cache-Control": "no-store"}
                )
            return response

        return token

    async def _issued_principal(self, response: Response) -> Principal | None:
        """The person a successful /token response's access token names, if any."""
        if response.status_code != 200:
            return None
        try:
            payload = json.loads(bytes(response.body))
        except (ValueError, TypeError, AttributeError):
            return None
        access = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(access, str) or not access:
            return None
        return await self.verifier.verify(access)

    def challenge(self) -> bytes:
        url = self._provider.protected_resource_metadata_url
        return f'Bearer error="invalid_token", resource_metadata="{url}"'.encode()


def front_door(
    cfg: OAuthServerConfig,
    base_url: str,
    mcp_path: str,
    audit_sink: AuditSink | None = None,
    client_ip: ClientIpPolicy | None = None,
) -> OAuthFrontDoor:
    if cfg.provider == "origo":
        return OrigoFrontDoor(cfg, base_url, mcp_path, audit_sink, client_ip)
    raise ConfigError(f"unknown auth.oauth provider {cfg.provider!r}")
