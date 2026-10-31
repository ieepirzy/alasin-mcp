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
"""

from __future__ import annotations

from typing import Any, Protocol

from starlette.applications import Starlette

from .auth import Principal, TokenVerifier
from .config import (
    OAUTH_SUBJECT_PREFIX,
    ConfigError,
    IdentityProviderConfig,
    OAuthServerConfig,
)


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
            idp_subject=sub[len(prefix) :],
        )


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
    def __init__(self, cfg: OAuthServerConfig, base_url: str, mcp_path: str):
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
            app.router.routes.insert(0, route)
        for key, value in vars(oauth_app.state)["_state"].items():
            setattr(app.state, key, value)
        # origo's handlers check their own credentials (client secret, code,
        # PKCE verifier, the IdP's answer on /authorize/callback, the bearer on
        # /userinfo); none takes an /mcp token.
        return tuple(getattr(r, "path", "") for r in oauth_app.routes)

    def challenge(self) -> bytes:
        url = self._provider.protected_resource_metadata_url
        return f'Bearer error="invalid_token", resource_metadata="{url}"'.encode()


def front_door(cfg: OAuthServerConfig, base_url: str, mcp_path: str) -> OAuthFrontDoor:
    if cfg.provider == "origo":
        return OrigoFrontDoor(cfg, base_url, mcp_path)
    raise ConfigError(f"unknown auth.oauth provider {cfg.provider!r}")
