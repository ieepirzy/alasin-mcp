# SPDX-License-Identifier: Apache-2.0
"""Configuration: one TOML file, secrets referenced by file path or env name.

Secrets never appear in the file itself. Every secret field ``x`` is given as
``x_file = "/run/secrets/..."`` or ``x_env = "NAME"``; see README.md.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from . import validation

DEFAULT_PROTECTED_BRANCHES = ("main", "master", "release/*", "releases/*")
DEFAULT_COAUTHOR = "Claude <noreply@anthropic.com>"


class ConfigError(ValueError):
    pass


class AuthMode(StrEnum):
    SERVICE_ACCOUNT = "service_account"
    USER_DELEGATED = "user_delegated"
    PLATFORM_SCOPED = "platform_scoped"


class AuthorSource(StrEnum):
    """Where a commit's author comes from in service-account mode."""

    SERVICE_ACCOUNT = "service_account"  # the default: the service account authors
    TOKEN_CLAIMS = "token_claims"  # noqa: S105 - claims of the verified inbound token
    TRUSTED_HEADER = "trusted_header"  # a header your gateway sets and strips from clients
    TOOL_ARGUMENT = "tool_argument"  # the model supplies it; explicit opt-in only


@dataclass(frozen=True)
class SecretRef:
    """A secret given by file path or environment variable name."""

    file: str | None = None
    env: str | None = None

    def resolve(self) -> str:
        if self.file:
            value = Path(self.file).read_text().strip()
        elif self.env:
            value = os.environ.get(self.env, "").strip()
        else:
            raise ConfigError("secret has neither a file nor an env reference")
        if not value:
            raise ConfigError(f"secret {self.file or self.env} is empty")
        return value

    @property
    def configured(self) -> bool:
        return bool(self.file or self.env)


@dataclass(frozen=True)
class OAuthAppConfig:
    """A Forgejo OAuth2 application, for user-delegated mode."""

    client_id: str
    client_secret: SecretRef
    redirect_uri: str
    # Which claim of the inbound token must equal which Forgejo user field
    # before a delegated token is stored. Prevents a user from binding someone
    # else's Forgejo account to their own subject.
    match_claim: str = "email"
    match_field: str = "email"


@dataclass(frozen=True)
class PlatformConfig:
    """Platform-scoped mode: tokens minted per repository by a platform service."""

    minter: str = ""  # "module:attribute" of a TokenMinter factory
    bot_name: str = ""
    bot_email: str = ""


@dataclass(frozen=True)
class TenantConfig:
    id: str
    forgejo_url: str
    auth_mode: AuthMode = AuthMode.SERVICE_ACCOUNT
    service_token: SecretRef = field(default_factory=SecretRef)
    # owner/name glob patterns the tenant may reach. Empty means none.
    repos: tuple[str, ...] = ()
    protected_branches: tuple[str, ...] = DEFAULT_PROTECTED_BRANCHES
    branch_prefix: str = ""
    author_source: AuthorSource = AuthorSource.SERVICE_ACCOUNT
    author_header: str = ""
    agent_coauthor: str = DEFAULT_COAUTHOR
    rate_limit_per_minute: int = 120
    max_file_bytes: int = 1_000_000
    max_commit_files: int = 50
    max_commit_bytes: int = 5_000_000
    oauth: OAuthAppConfig | None = None
    platform: PlatformConfig | None = None

    @property
    def api_base(self) -> str:
        return self.forgejo_url.rstrip("/") + "/api/v1"


@dataclass(frozen=True)
class StaticCredential:
    """An inbound bearer credential accepted as-is (service-account deployments)."""

    token: SecretRef
    tenant: str
    subject: str


@dataclass(frozen=True)
class JwtConfig:
    jwks_url: str
    issuer: str
    audience: str
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    tenant_claim: str = "tenant"
    subject_claim: str = "sub"
    name_claim: str = "name"
    email_claim: str = "email"
    # When set, tokens without a tenant claim belong to this tenant.
    default_tenant: str = ""


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"  # noqa: S104 - a container binds all interfaces
    port: int = 8000
    # Host header values accepted on /mcp (DNS-rebinding protection). Set it to
    # the name your gateway uses to reach this server. Empty disables the check.
    allowed_hosts: tuple[str, ...] = ()
    forwarded_allow_ips: str = "127.0.0.1"
    state_path: str = "/var/lib/alasin/state.db"
    audit_dir: str = "/var/lib/alasin/audit"
    master_key: SecretRef = field(default_factory=SecretRef)
    session_ttl_seconds: int = 12 * 3600
    public_url: str = ""


@dataclass(frozen=True)
class TelemetryConfig:
    otlp_endpoint: str = ""  # off by default
    service_name: str = "alasin-mcp"


@dataclass(frozen=True)
class Config:
    server: ServerConfig
    telemetry: TelemetryConfig
    tenants: tuple[TenantConfig, ...]
    static_credentials: tuple[StaticCredential, ...] = ()
    jwt: JwtConfig | None = None


def _secret(raw: dict[str, Any], name: str) -> SecretRef:
    ref = SecretRef(file=raw.get(f"{name}_file"), env=raw.get(f"{name}_env"))
    if name in raw:
        raise ConfigError(
            f"'{name}' must not be written in the config file; use {name}_file or {name}_env"
        )
    return ref


def _tenant(raw: dict[str, Any]) -> TenantConfig:
    tid = validation.tenant_id(str(raw["id"]))
    url = str(raw["forgejo_url"]).rstrip("/")
    if not url.startswith(("https://", "http://")):
        raise ConfigError(f"tenant {tid}: forgejo_url must be an http(s) URL")
    mode = AuthMode(raw.get("auth_mode", AuthMode.SERVICE_ACCOUNT))
    source = AuthorSource(raw.get("author_source", AuthorSource.SERVICE_ACCOUNT))
    if source is AuthorSource.TRUSTED_HEADER and not raw.get("author_header"):
        raise ConfigError(f"tenant {tid}: author_source=trusted_header needs author_header")
    oauth = None
    if "oauth" in raw:
        o = raw["oauth"]
        oauth = OAuthAppConfig(
            client_id=str(o["client_id"]),
            client_secret=_secret(o, "client_secret"),
            redirect_uri=str(o["redirect_uri"]),
            match_claim=str(o.get("match_claim", "email")),
            match_field=str(o.get("match_field", "email")),
        )
    platform = None
    if "platform" in raw:
        p = raw["platform"]
        platform = PlatformConfig(
            minter=str(p.get("minter", "")),
            bot_name=str(p.get("bot_name", "")),
            bot_email=str(p.get("bot_email", "")),
        )
    tenant = TenantConfig(
        id=tid,
        forgejo_url=url,
        auth_mode=mode,
        service_token=_secret(raw, "service_token"),
        repos=tuple(raw.get("repos", ())),
        protected_branches=tuple(raw.get("protected_branches", DEFAULT_PROTECTED_BRANCHES)),
        branch_prefix=str(raw.get("branch_prefix", "")),
        author_source=source,
        author_header=str(raw.get("author_header", "")).lower(),
        agent_coauthor=str(raw.get("agent_coauthor", DEFAULT_COAUTHOR)),
        rate_limit_per_minute=int(raw.get("rate_limit_per_minute", 120)),
        max_file_bytes=int(raw.get("max_file_bytes", 1_000_000)),
        max_commit_files=int(raw.get("max_commit_files", 50)),
        max_commit_bytes=int(raw.get("max_commit_bytes", 5_000_000)),
        oauth=oauth,
        platform=platform,
    )
    if mode is AuthMode.SERVICE_ACCOUNT and not tenant.service_token.configured:
        raise ConfigError(f"tenant {tid}: service_account mode needs service_token_file/_env")
    if mode is AuthMode.USER_DELEGATED and oauth is None:
        raise ConfigError(f"tenant {tid}: user_delegated mode needs an [tenants.oauth] table")
    return tenant


def parse(raw: dict[str, Any]) -> Config:
    s = raw.get("server", {})
    server = ServerConfig(
        host=str(s.get("host", ServerConfig.host)),
        port=int(s.get("port", ServerConfig.port)),
        allowed_hosts=tuple(s.get("allowed_hosts", ())),
        forwarded_allow_ips=str(s.get("forwarded_allow_ips", ServerConfig.forwarded_allow_ips)),
        state_path=str(s.get("state_path", ServerConfig.state_path)),
        audit_dir=str(s.get("audit_dir", ServerConfig.audit_dir)),
        master_key=_secret(s, "master_key"),
        session_ttl_seconds=int(s.get("session_ttl_seconds", ServerConfig.session_ttl_seconds)),
        public_url=str(s.get("public_url", "")).rstrip("/"),
    )
    t = raw.get("telemetry", {})
    telemetry = TelemetryConfig(
        otlp_endpoint=str(t.get("otlp_endpoint", "")),
        service_name=str(t.get("service_name", "alasin-mcp")),
    )
    tenants = tuple(_tenant(x) for x in raw.get("tenants", ()))
    if not tenants:
        raise ConfigError("no [[tenants]] configured")
    ids = [x.id for x in tenants]
    if len(set(ids)) != len(ids):
        raise ConfigError("duplicate tenant ids")
    auth = raw.get("auth", {})
    statics = tuple(
        StaticCredential(
            token=_secret(c, "token"),
            tenant=validation.tenant_id(str(c["tenant"])),
            subject=str(c["subject"]),
        )
        for c in auth.get("static", ())
    )
    jwt = None
    if "jwt" in auth:
        j = auth["jwt"]
        jwt = JwtConfig(
            jwks_url=str(j["jwks_url"]),
            issuer=str(j["issuer"]),
            audience=str(j["audience"]),
            algorithms=tuple(j.get("algorithms", ("RS256", "ES256"))),
            tenant_claim=str(j.get("tenant_claim", "tenant")),
            subject_claim=str(j.get("subject_claim", "sub")),
            name_claim=str(j.get("name_claim", "name")),
            email_claim=str(j.get("email_claim", "email")),
            default_tenant=str(j.get("default_tenant", "")),
        )
    if not statics and jwt is None:
        raise ConfigError("no inbound auth configured: add [[auth.static]] or [auth.jwt]")
    for c in statics:
        if c.tenant not in ids:
            raise ConfigError(f"static credential for unknown tenant {c.tenant!r}")
    needs_key = any(x.auth_mode is AuthMode.USER_DELEGATED for x in tenants)
    if needs_key and not server.master_key.configured:
        raise ConfigError("user_delegated mode stores tokens: set server.master_key_file/_env")
    return Config(server, telemetry, tenants, statics, jwt)


def load(path: str | os.PathLike[str]) -> Config:
    with open(path, "rb") as f:
        return parse(tomllib.load(f))
