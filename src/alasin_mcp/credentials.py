# SPDX-License-Identifier: Apache-2.0
"""Outbound Forgejo credentials, one provider per auth mode.

- ``ServiceAccountProvider`` (service_account): one Forgejo token per tenant.
  Commits come from the service account unless the tenant configures a
  trusted author source (see ``tools.resolve_author``).
- ``UserDelegatedProvider`` (user_delegated): Forgejo OAuth per person. Tokens
  are stored encrypted per ``(tenant, subject)`` and refreshed when expired.
- ``PlatformScopedProvider`` (platform_scoped): short-lived per-repository
  tokens minted by a platform service through a ``TokenMinter``. The author
  is the verified end user and the committer is the platform bot.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx

from .auth import Principal
from .config import AuthMode, TenantConfig
from .store import DecryptionFailed, Store
from .validation import RepoRef


@dataclass(frozen=True)
class Identity:
    name: str
    email: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "email": self.email}

    def __str__(self) -> str:
        return f"{self.name} <{self.email}>"


@dataclass(frozen=True)
class ForgejoCredential:
    token: str
    mode: AuthMode
    # The author the mode itself dictates (platform mode: the end user).
    author: Identity | None = None
    # The committer to set when the author is not the token's own user.
    committer: Identity | None = None


class CredentialError(Exception):
    """The caller can't get a Forgejo credential right now. Safe to show the model."""


class AuthorizationRequired(CredentialError):
    def __init__(self, url: str):
        super().__init__(
            f"Forgejo authorization is needed. Ask the user to open this link once: {url}"
        )
        self.url = url


class CredentialProvider(Protocol):
    async def credential(
        self, tenant: TenantConfig, principal: Principal, repo: RepoRef | None
    ) -> ForgejoCredential: ...


class ServiceAccountProvider:
    async def credential(
        self, tenant: TenantConfig, principal: Principal, repo: RepoRef | None
    ) -> ForgejoCredential:
        return ForgejoCredential(token=tenant.service_token.resolve(), mode=tenant.auth_mode)


# -- user-delegated ------------------------------------------------------------------


class UserDelegatedProvider:
    """Per-person Forgejo OAuth2 tokens (authorization code + PKCE)."""

    REFRESH_MARGIN = 60.0

    def __init__(
        self,
        store: Store,
        tenant_by_id: Callable[[str], TenantConfig],
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._store = store
        self._tenant_by_id = tenant_by_id
        self._transport = transport

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=5.0),
            follow_redirects=False,
            transport=self._transport,
        )

    def authorization_url(self, tenant: TenantConfig, principal: Principal) -> str:
        oauth = tenant.oauth
        assert oauth is not None
        match_value = principal.claims.get(oauth.match_claim) if principal.claims else None
        if oauth.match_claim == "email" and match_value is None:
            match_value = principal.email
        if not isinstance(match_value, str) or not match_value:
            raise CredentialError(
                f"the verified token has no '{oauth.match_claim}' claim to bind a Forgejo account"
            )
        verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        state = self._store.put_oauth_state(tenant.id, principal.subject, verifier, match_value)
        query = urlencode(
            {
                "client_id": oauth.client_id,
                "redirect_uri": oauth.redirect_uri,
                "response_type": "code",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{tenant.forgejo_url}/login/oauth/authorize?{query}"

    async def complete(self, state: str, code: str) -> str:
        """Handle the OAuth callback. Returns the tenant id on success."""
        pending = self._store.take_oauth_state(state)
        if pending is None:
            raise CredentialError("unknown or expired authorization state")
        tenant = self._tenant_by_id(pending.tenant)
        oauth = tenant.oauth
        if oauth is None:
            raise CredentialError("tenant has no OAuth application")
        token = await self._token_request(
            tenant,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": oauth.redirect_uri,
                "code_verifier": pending.verifier,
            },
        )
        # Bind only if the Forgejo account is the caller's own: a link opened
        # by someone else must not attach their account to this subject.
        async with self._http() as http:
            resp = await http.get(
                f"{tenant.api_base}/user",
                headers={"Authorization": f"token {token['access_token']}"},
            )
        if resp.status_code != 200:
            raise CredentialError("could not read the Forgejo account for the new token")
        actual = resp.json().get(oauth.match_field)
        if not isinstance(actual, str) or actual.casefold() != pending.match_value.casefold():
            raise CredentialError("the Forgejo account does not match the verified caller")
        self._store.put_token(tenant.id, pending.subject, token)
        return tenant.id

    async def _token_request(self, tenant: TenantConfig, form: dict[str, str]) -> dict[str, Any]:
        oauth = tenant.oauth
        assert oauth is not None
        payload = {
            **form,
            "client_id": oauth.client_id,
            "client_secret": oauth.client_secret.resolve(),
        }
        async with self._http() as http:
            resp = await http.post(f"{tenant.forgejo_url}/login/oauth/access_token", data=payload)
        if resp.status_code != 200:
            raise CredentialError(f"Forgejo token endpoint returned {resp.status_code}")
        body = resp.json()
        access = body.get("access_token")
        if not isinstance(access, str) or not access:
            raise CredentialError("Forgejo token endpoint returned no access token")
        expires_in = body.get("expires_in")
        return {
            "access_token": access,
            "refresh_token": body.get("refresh_token") or "",
            "expires_at": time.time() + float(expires_in) if expires_in else 0.0,
        }

    async def credential(
        self, tenant: TenantConfig, principal: Principal, repo: RepoRef | None
    ) -> ForgejoCredential:
        try:
            record = self._store.get_token(tenant.id, principal.subject)
        except DecryptionFailed:
            self._store.delete_token(tenant.id, principal.subject)
            record = None
        if record is None:
            raise AuthorizationRequired(self.authorization_url(tenant, principal))
        expires_at = float(record.get("expires_at") or 0)
        if expires_at and expires_at - self.REFRESH_MARGIN < time.time():
            refresh = record.get("refresh_token")
            try:
                if not refresh:
                    raise CredentialError("no refresh token")
                record = await self._token_request(
                    tenant, {"grant_type": "refresh_token", "refresh_token": refresh}
                )
            except CredentialError:
                self._store.delete_token(tenant.id, principal.subject)
                raise AuthorizationRequired(self.authorization_url(tenant, principal)) from None
            self._store.put_token(tenant.id, principal.subject, record)
        return ForgejoCredential(token=record["access_token"], mode=AuthMode.USER_DELEGATED)


# -- platform-scoped -------------------------------------------------------------------


@dataclass(frozen=True)
class MintedToken:
    token: str
    expires_at: float
    bot: Identity


class TokenMinter(Protocol):
    """Mints a short-lived Forgejo token scoped to one repository.

    Implement this against your platform's token service and name the factory
    in the tenant's ``platform.minter`` setting (``"package.module:factory"``).
    The factory is called with the tenant config and returns the minter.
    """

    async def mint(
        self, tenant: TenantConfig, principal: Principal, repo: RepoRef
    ) -> MintedToken: ...


class MinterNotConfigured(CredentialError):
    pass


class UnconfiguredMinter:
    """The default: platform-scoped mode has no built-in token service.

    TODO: ship a reference minter once a platform token-exchange protocol is
    settled (for example RFC 8693 token exchange against the platform's STS).
    """

    async def mint(self, tenant: TenantConfig, principal: Principal, repo: RepoRef) -> MintedToken:
        raise MinterNotConfigured(
            f"tenant {tenant.id} uses platform_scoped mode but no token minter is configured"
        )


def load_minter(tenant: TenantConfig) -> TokenMinter:
    spec = tenant.platform.minter if tenant.platform else ""
    if not spec:
        return UnconfiguredMinter()
    module, _, attr = spec.partition(":")
    factory = getattr(importlib.import_module(module), attr)
    return factory(tenant)


class PlatformScopedProvider:
    def __init__(self, minters: dict[str, TokenMinter] | None = None):
        self._minters = minters or {}

    def _minter(self, tenant: TenantConfig) -> TokenMinter:
        if tenant.id not in self._minters:
            self._minters[tenant.id] = load_minter(tenant)
        return self._minters[tenant.id]

    async def credential(
        self, tenant: TenantConfig, principal: Principal, repo: RepoRef | None
    ) -> ForgejoCredential:
        if repo is None:
            raise CredentialError(
                "platform-scoped tokens are per repository; this tool needs a repo argument"
            )
        if not principal.email:
            raise CredentialError("platform-scoped commits need an email claim on the caller")
        minted = await self._minter(tenant).mint(tenant, principal, repo)
        if minted.expires_at <= time.time():
            raise CredentialError("the platform minted an already expired token")
        author = Identity(principal.name or principal.subject, principal.email)
        return ForgejoCredential(
            token=minted.token, mode=AuthMode.PLATFORM_SCOPED, author=author, committer=minted.bot
        )


class ModeRouter:
    """Picks the provider for the tenant's configured auth mode."""

    def __init__(self, providers: dict[AuthMode, CredentialProvider]):
        self._providers = providers

    async def credential(
        self, tenant: TenantConfig, principal: Principal, repo: RepoRef | None
    ) -> ForgejoCredential:
        provider = self._providers.get(tenant.auth_mode)
        if provider is None:
            raise CredentialError(f"auth mode {tenant.auth_mode} is not enabled on this server")
        return await provider.credential(tenant, principal, repo)
