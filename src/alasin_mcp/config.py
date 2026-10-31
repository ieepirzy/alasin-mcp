# SPDX-License-Identifier: Apache-2.0
"""Configuration: one TOML file, secrets referenced by file path or env name.

Secrets never appear in the file itself. Every secret field ``x`` is given as
``x_file = "/run/secrets/..."`` or ``x_env = "NAME"``; see README.md.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import validation

DEFAULT_PROTECTED_BRANCHES = ("main", "master", "release/*", "releases/*")
DEFAULT_COAUTHOR = "Claude <noreply@anthropic.com>"
# Folders whose files a forge runs as CI. Writing them can run code with the
# repository's secrets, so they are refused unless a tenant opts in.
DEFAULT_CI_PATHS = (".forgejo/", ".gitea/", ".github/")


class ConfigError(ValueError):
    pass


# Subjects of OAuth front-door principals (a person or a client, oauth.py)
# start with this. No other credential may claim it, so a front-door principal
# never shares sessions or branches with one.
OAUTH_SUBJECT_PREFIX = "oauth:"
# public_registration lets anyone who can reach the server register a client
# and get a token for the tenant: origo has no user accounts. Opting in takes
# this key as well, so it can't be switched on by accident.
PUBLIC_REGISTRATION_ACK = "public_registration_i_understand_anyone_can_connect"


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
class BranchWebhookConfig:
    """Where branch-creation requests go when branch_creation = "webhook"."""

    url: str
    secret: SecretRef
    timeout_seconds: float = 60.0
    poll_interval_seconds: float = 2.0


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
    allow_ci_paths: bool = False
    ci_paths: tuple[str, ...] = DEFAULT_CI_PATHS
    oauth: OAuthAppConfig | None = None
    platform: PlatformConfig | None = None
    # How branches are created: "api" (default), "webhook", or a name you
    # registered in Services.branch_creators.
    branch_creation: str = "api"
    branch_webhook: BranchWebhookConfig | None = None
    # Only the subject that created a branch through this server may commit to
    # it. The owner is recorded in server.state_path at create_branch; a
    # branch with no record (made elsewhere, or before the state was lost) is
    # refused. Required for a tenant whose people sign in through an IdP.
    branch_owners: bool = False

    @property
    def api_base(self) -> str:
        return self.forgejo_url.rstrip("/") + "/api/v1"


@dataclass(frozen=True)
class StaticCredential:
    """An inbound bearer credential accepted as-is (service-account deployments)."""

    token: SecretRef
    tenant: str
    subject: str
    # The holder is a gateway that sets (and strips from clients) the trusted
    # author header. Only principals from such entries may supply it.
    gateway: bool = False


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
class OAuthClientConfig:
    """A client pre-registered with the OAuth front door (e.g. a claude.ai connector)."""

    id: str
    secret: SecretRef
    # Exact-match allowlist; a client with none can't complete /authorize.
    redirect_uris: tuple[str, ...] = ()


@dataclass(frozen=True)
class IdentityProviderConfig:
    """An upstream OIDC provider people sign in with (origo's IdentityProvider)."""

    issuer: str
    client_id: str
    client_secret: SecretRef
    # The lane gate: at least one must appear in the person's groups, checked
    # at sign-in (origo) and again on every write tool.
    allowed_groups: tuple[str, ...]
    groups_claim: str = "groups"
    allowed_email_domains: tuple[str, ...] = ()
    max_grant_age_seconds: int = 12 * 3600


@dataclass(frozen=True)
class OAuthServerConfig:
    """The OAuth front door MCP clients sign in through (see oauth.py)."""

    tenant: str
    provider: str = "origo"
    # Externally visible base URL; defaults to server.public_url.
    base_url: str = ""
    clients: tuple[OAuthClientConfig, ...] = ()
    public_registration: bool = False
    auto_approve: bool = False
    token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 30 * 24 * 3600
    client_ttl_seconds: int | None = None
    # People sign in at this IdP; each token then names a person, not a client.
    identity_provider: IdentityProviderConfig | None = None
    # Without an IdP, origo refuses every authorization unless this is on (it
    # serves an approve-only consent page that authenticates nobody). Passed to
    # origo explicitly, so its ORIGO_ALLOW_UNAUTHENTICATED_CONSENT env var
    # can't switch it on behind the config's back.
    allow_unauthenticated_consent: bool = False
    # SQLite file for tokens and registered clients; empty keeps them in
    # memory, so every client signs in again after a restart.
    storage_path: str = "/var/lib/alasin/oauth.db"


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
    # Largest request body accepted, checked before authentication. Leave room
    # for base64: a commit of max_commit_bytes is about 4/3 of that on the wire.
    max_request_bytes: int = 8 * 1024 * 1024


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
    oauth: OAuthServerConfig | None = None


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
    webhook = None
    if "branch_webhook" in raw:
        w = raw["branch_webhook"]
        hook_url = str(w["url"])
        if not hook_url.startswith(("https://", "http://")):
            raise ConfigError(f"tenant {tid}: branch_webhook.url must be an http(s) URL")
        webhook = BranchWebhookConfig(
            url=hook_url,
            secret=_secret(w, "secret"),
            timeout_seconds=float(w.get("timeout_seconds", 60)),
            poll_interval_seconds=float(w.get("poll_interval_seconds", 2)),
        )
        if not webhook.secret.configured:
            raise ConfigError(f"tenant {tid}: branch_webhook needs secret_file or secret_env")
        if not 0 < webhook.timeout_seconds <= 600 or webhook.poll_interval_seconds <= 0:
            raise ConfigError(f"tenant {tid}: branch_webhook timing out of range")
    creation = str(raw.get("branch_creation", "api"))
    if creation == "webhook" and webhook is None:
        raise ConfigError(f"tenant {tid}: branch_creation=webhook needs [tenants.branch_webhook]")
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
        allow_ci_paths=bool(raw.get("allow_ci_paths", False)),
        ci_paths=tuple(raw.get("ci_paths", DEFAULT_CI_PATHS)),
        oauth=oauth,
        platform=platform,
        branch_creation=creation,
        branch_webhook=webhook,
        branch_owners=bool(raw.get("branch_owners", False)),
    )
    if mode is AuthMode.SERVICE_ACCOUNT and not tenant.service_token.configured:
        raise ConfigError(f"tenant {tid}: service_account mode needs service_token_file/_env")
    if mode is AuthMode.USER_DELEGATED and oauth is None:
        raise ConfigError(f"tenant {tid}: user_delegated mode needs an [tenants.oauth] table")
    return tenant


# The identity provider may come from the environment instead of the file, so
# a deployment sets it beside the secret mount it names. Either source, never
# both. ALASIN_IDP_ALLOWED_GROUPS is comma-separated.
IDP_ENV = {
    "ALASIN_IDP_ISSUER": "issuer",
    "ALASIN_IDP_CLIENT_ID": "client_id",
    "ALASIN_IDP_CLIENT_SECRET_FILE": "client_secret_file",
    "ALASIN_IDP_ALLOWED_GROUPS": "allowed_groups",
    "ALASIN_IDP_GROUPS_CLAIM": "groups_claim",
}


def _idp_from_env(env: Mapping[str, str]) -> dict[str, Any] | None:
    raw: dict[str, Any] = {}
    for name, key in IDP_ENV.items():
        value = env.get(name, "").strip()
        if not value:
            continue
        if key == "allowed_groups":
            raw[key] = [g.strip() for g in value.split(",") if g.strip()]
        else:
            raw[key] = value
    return raw or None


def parse(raw: dict[str, Any], env: Mapping[str, str] | None = None) -> Config:
    """``env`` (default ``os.environ``) supplies the ``ALASIN_IDP_*`` settings."""
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
        max_request_bytes=int(s.get("max_request_bytes", ServerConfig.max_request_bytes)),
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
            gateway=bool(c.get("gateway", False)),
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
    idp_env = _idp_from_env(os.environ if env is None else env)
    if idp_env is not None:
        if "oauth" not in auth:
            raise ConfigError("ALASIN_IDP_* is set but there is no [auth.oauth] to sign in through")
        if "identity_provider" in auth["oauth"]:
            raise ConfigError(
                "the identity provider is set both in [auth.oauth.identity_provider] and in "
                "ALASIN_IDP_*; use one"
            )
        auth = {**auth, "oauth": {**auth["oauth"], "identity_provider": idp_env}}
    oauth = _oauth_server(auth["oauth"], server) if "oauth" in auth else None
    if not statics and jwt is None and oauth is None:
        raise ConfigError(
            "no inbound auth configured: add [[auth.static]], [auth.jwt] or [auth.oauth]"
        )
    if oauth is not None:
        _check_oauth(oauth, tenants, server, statics)
    for c in statics:
        if c.subject.startswith(OAUTH_SUBJECT_PREFIX):
            raise ConfigError(
                f"static credential subject {c.subject!r}: the prefix "
                f"{OAUTH_SUBJECT_PREFIX!r} is reserved for OAuth clients"
            )
    for c in statics:
        if c.tenant not in ids:
            raise ConfigError(f"static credential for unknown tenant {c.tenant!r}")
    for t in tenants:
        if t.author_source is AuthorSource.TRUSTED_HEADER and not any(
            c.gateway and c.tenant == t.id for c in statics
        ):
            raise ConfigError(
                f"tenant {t.id}: author_source=trusted_header needs an [[auth.static]] entry "
                "with gateway = true for this tenant"
            )
    needs_key = any(x.auth_mode is AuthMode.USER_DELEGATED for x in tenants)
    if needs_key and not server.master_key.configured:
        raise ConfigError("user_delegated mode stores tokens: set server.master_key_file/_env")
    return Config(server, telemetry, tenants, statics, jwt, oauth)


def _oauth_server(raw: dict[str, Any], server: ServerConfig) -> OAuthServerConfig:
    base_url = str(raw.get("base_url", server.public_url)).rstrip("/")
    if not base_url.startswith(("https://", "http://")):
        raise ConfigError("auth.oauth needs base_url (or server.public_url): clients sign in there")
    clients = tuple(
        OAuthClientConfig(
            id=str(c["id"]),
            secret=_secret(c, "secret"),
            redirect_uris=tuple(str(u) for u in c.get("redirect_uris", ())),
        )
        for c in raw.get("clients", ())
    )
    public = bool(raw.get("public_registration", False))
    if public and raw.get(PUBLIC_REGISTRATION_ACK) is not True:
        raise ConfigError(
            "auth.oauth public_registration lets anyone who can reach this server get a "
            f"token for the tenant; to accept that, also set {PUBLIC_REGISTRATION_ACK} = true"
        )
    if not clients and not public:
        raise ConfigError("auth.oauth: add [[auth.oauth.clients]] or set public_registration")
    client_ttl = raw.get("client_ttl_seconds")
    idp = _identity_provider(raw["identity_provider"]) if "identity_provider" in raw else None
    if idp is not None and public:
        raise ConfigError(
            "auth.oauth: public_registration can't be combined with identity_provider; "
            "list the clients under [[auth.oauth.clients]]"
        )
    return OAuthServerConfig(
        tenant=validation.tenant_id(str(raw["tenant"])),
        provider=str(raw.get("provider", "origo")),
        base_url=base_url,
        clients=clients,
        public_registration=public,
        auto_approve=bool(raw.get("auto_approve", False)),
        token_ttl_seconds=int(raw.get("token_ttl_seconds", 3600)),
        refresh_token_ttl_seconds=int(raw.get("refresh_token_ttl_seconds", 30 * 24 * 3600)),
        client_ttl_seconds=int(client_ttl) if client_ttl is not None else None,
        identity_provider=idp,
        allow_unauthenticated_consent=raw.get("allow_unauthenticated_consent") is True,
        storage_path=str(raw.get("storage_path", OAuthServerConfig.storage_path)),
    )


def _identity_provider(raw: dict[str, Any]) -> IdentityProviderConfig:
    issuer = str(raw.get("issuer", ""))
    if not issuer.startswith("https://"):
        raise ConfigError("auth.oauth.identity_provider needs an https issuer")
    groups = raw.get("allowed_groups")
    # Written out, never defaulted: Keycloak emits "/name" or "name" depending
    # on its mapper's "Full group path" setting, and a mismatch locks out all.
    if (
        not isinstance(groups, list)
        or not groups
        or not all(isinstance(g, str) and g for g in groups)
    ):
        raise ConfigError(
            "auth.oauth.identity_provider needs allowed_groups, a non-empty list of the "
            "group names exactly as the IdP emits them"
        )
    idp = IdentityProviderConfig(
        issuer=issuer,
        client_id=str(raw.get("client_id", "")),
        client_secret=_secret(raw, "client_secret"),
        allowed_groups=tuple(groups),
        groups_claim=str(raw.get("groups_claim", "groups")),
        allowed_email_domains=tuple(str(d) for d in raw.get("allowed_email_domains", ())),
        max_grant_age_seconds=int(raw.get("max_grant_age_seconds", 12 * 3600)),
    )
    if not idp.client_id:
        raise ConfigError("auth.oauth.identity_provider needs client_id")
    if not idp.client_secret.configured:
        raise ConfigError(
            "auth.oauth.identity_provider needs client_secret_file or client_secret_env"
        )
    return idp


def _check_oauth(
    oauth: OAuthServerConfig,
    tenants: tuple[TenantConfig, ...],
    server: ServerConfig,
    statics: tuple[StaticCredential, ...] = (),
) -> None:
    tenant = next((t for t in tenants if t.id == oauth.tenant), None)
    if tenant is None:
        raise ConfigError(f"auth.oauth for unknown tenant {oauth.tenant!r}")
    # Without an IdP the subject is the OAuth client, shared by every person
    # who signs in through it; and with one, the Forgejo credential is still
    # the service account's (the person is the commit author, not the token).
    if tenant.auth_mode is not AuthMode.SERVICE_ACCOUNT:
        raise ConfigError(f"auth.oauth tenant {tenant.id!r} must use auth_mode = service_account")
    # Clients sign in through a browser at base_url, so its host must also be
    # covered by the DNS-rebinding check.
    host = urlsplit(oauth.base_url).netloc
    if host not in server.allowed_hosts:
        raise ConfigError(f"auth.oauth: add the base_url host {host!r} to server.allowed_hosts")
    if oauth.identity_provider is None:
        return
    # Each person signs in as themselves: no shared account in this tenant,
    # each commit authored by the person, each branch writable by its creator.
    if tenant.author_source is not AuthorSource.TOKEN_CLAIMS:
        raise ConfigError(
            f"tenant {tenant.id}: with auth.oauth.identity_provider, set "
            'author_source = "token_claims" so each commit is authored by the person'
        )
    if not tenant.branch_owners:
        raise ConfigError(
            f"tenant {tenant.id}: with auth.oauth.identity_provider, set branch_owners = true "
            "so only a branch's creator may write it"
        )
    if any(c.tenant == tenant.id for c in statics):
        raise ConfigError(
            f"tenant {tenant.id}: [[auth.static]] credentials are shared accounts; remove them "
            "from a tenant whose people sign in through auth.oauth.identity_provider"
        )


def load(path: str | os.PathLike[str]) -> Config:
    with open(path, "rb") as f:
        return parse(tomllib.load(f))
