# SPDX-License-Identifier: Apache-2.0
"""The ASGI application and the ``alasin-mcp`` entry point.

Routes:

- ``/mcp``: the MCP endpoint (Streamable HTTP, stateless), bearer token required.
- ``/healthz``: liveness, public.
- ``/oauth/forgejo/callback``: the Forgejo OAuth redirect target for
  user-delegated tenants, public (it is protected by the single-use state).
- With ``[auth.oauth]``: the front door's discovery and sign-in routes
  (``/.well-known/...``, ``/authorize``, ``/authorize/callback``, ``/token``,
  ...), public.

Configuration: ``ALASIN_CONFIG`` names the TOML file (see README.md).
"""

from __future__ import annotations

import logging
import os

import httpx
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from . import config as config_mod
from . import telemetry
from .audit import AuditSink, FanoutAuditSink, JsonlAuditSink, StreamAuditSink
from .auth import (
    BearerAuthMiddleware,
    ChainVerifier,
    JwtVerifier,
    StaticTokenVerifier,
    TokenVerifier,
)
from .config import AuthMode, Config
from .credentials import (
    CredentialError,
    CredentialProvider,
    ModeRouter,
    PlatformScopedProvider,
    ServiceAccountProvider,
    UserDelegatedProvider,
)
from .oauth import OAuthFrontDoor, front_door
from .store import LocalKeyWrapper, Store
from .tenancy import StaticTenantResolver, TenantResolver
from .tools import Services, build_server

MCP_PATH = "/mcp"
CALLBACK_PATH = "/oauth/forgejo/callback"
log = logging.getLogger("alasin_mcp")


async def _health(_: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


def build_app(
    services: Services,
    verifier: TokenVerifier,
    allowed_hosts: tuple[str, ...] = (),
    delegated: UserDelegatedProvider | None = None,
    max_request_bytes: int = 8 * 1024 * 1024,
    oauth: OAuthFrontDoor | None = None,
) -> Starlette:
    server = build_server(services)
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=bool(allowed_hosts),
        allowed_hosts=list(allowed_hosts),
        allowed_origins=[f"https://{h}" for h in allowed_hosts],
    )
    app = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=True,
        transport_security=security,
        max_request_body_size=max_request_bytes,
        host="0.0.0.0",  # noqa: S104 - binding is decided by uvicorn, not here
    )
    app.router.routes.append(Route("/healthz", _health))

    async def oauth_callback(request: Request) -> HTMLResponse:
        if delegated is None:
            return HTMLResponse("Not found", status_code=404)
        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        if not state or not code:
            return HTMLResponse("Missing state or code.", status_code=400)
        try:
            await delegated.complete(state, code)
        except CredentialError as e:
            return HTMLResponse(f"Authorization failed: {_escape(str(e))}", status_code=400)
        except httpx.HTTPError:
            return HTMLResponse("Authorization failed: Forgejo unreachable.", status_code=502)
        return HTMLResponse("Forgejo access is connected. You can close this tab.")

    app.router.routes.append(Route(CALLBACK_PATH, oauth_callback))
    public_paths: tuple[str, ...] = ("/healthz", CALLBACK_PATH)
    challenge = b'Bearer error="invalid_token"'
    if oauth is not None:
        public_paths += oauth.install(app)
        verifier = ChainVerifier([verifier, oauth.verifier])
        challenge = oauth.challenge()
    app.add_middleware(
        BearerAuthMiddleware,
        verifier=verifier,
        public_paths=public_paths,
        max_body_bytes=max_request_bytes,
        challenge=challenge,
    )
    return app


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def from_config(
    cfg: Config,
    resolver: TenantResolver | None = None,
    audit_sink: AuditSink | None = None,
) -> Starlette:
    """Build the app from config. Pass ``resolver`` to plug in your own tenant resolver."""
    telemetry.configure(cfg.telemetry.service_name, cfg.telemetry.otlp_endpoint)
    key_wrapper = (
        LocalKeyWrapper.from_secret(cfg.server.master_key.resolve())
        if cfg.server.master_key.configured
        else None
    )
    store = Store(cfg.server.state_path, key_wrapper)
    tenants = {t.id: t for t in cfg.tenants}
    resolver = resolver or StaticTenantResolver(cfg.tenants)
    providers: dict[AuthMode, CredentialProvider] = {
        AuthMode.SERVICE_ACCOUNT: ServiceAccountProvider(),
        AuthMode.PLATFORM_SCOPED: PlatformScopedProvider(),
    }
    delegated = None
    if any(t.auth_mode is AuthMode.USER_DELEGATED for t in cfg.tenants):
        delegated = UserDelegatedProvider(store, tenants.__getitem__)
        providers[AuthMode.USER_DELEGATED] = delegated
    verifiers: list[TokenVerifier] = []
    if cfg.static_credentials:
        verifiers.append(StaticTokenVerifier.from_config(cfg.static_credentials))
    if cfg.jwt is not None:
        verifiers.append(JwtVerifier(cfg.jwt))
    # The JSONL file is the durable record: a write is refused when it fails
    # (fail closed). stderr is a convenience copy and never refuses anything.
    sink = audit_sink or FanoutAuditSink(
        [JsonlAuditSink(cfg.server.audit_dir)], best_effort=[StreamAuditSink()]
    )
    writer_groups: dict[str, frozenset[str]] = {}
    if cfg.oauth is not None and cfg.oauth.identity_provider is not None:
        writer_groups[cfg.oauth.tenant] = frozenset(cfg.oauth.identity_provider.allowed_groups)
    services = Services(
        resolver=resolver,
        credentials=ModeRouter(providers),
        store=store,
        audit_sink=sink,
        session_ttl=cfg.server.session_ttl_seconds,
        writer_groups=writer_groups,
    )
    oauth = front_door(cfg.oauth, cfg.oauth.base_url, MCP_PATH, sink) if cfg.oauth else None
    return build_app(
        services,
        ChainVerifier(verifiers),
        cfg.server.allowed_hosts,
        delegated,
        cfg.server.max_request_bytes,
        oauth,
    )


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    cfg = config_mod.load(os.environ.get("ALASIN_CONFIG", "/etc/alasin/config.toml"))
    uvicorn.run(
        from_config(cfg),
        host=cfg.server.host,
        port=cfg.server.port,
        proxy_headers=True,
        forwarded_allow_ips=cfg.server.forwarded_allow_ips,
    )


if __name__ == "__main__":
    main()
