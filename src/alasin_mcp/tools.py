# SPDX-License-Identifier: Apache-2.0
"""The MCP tools.

Every tool call goes through ``Services.call``, which:

1. takes the principal from the request that carried the call (never from an
   argument) and resolves the tenant from it;
2. applies the tenant's rate limit;
3. checks the work session belongs to this ``(tenant, subject)``;
4. for the write tools, applies the tenant's writer gate, if it has one: the
   caller's verified groups must include an allowed group, and the token must
   carry a name and a verified email to author commits with;
5. runs the tool inside a span in the work session's trace;
6. appends one audit event, whether the call succeeded or failed.

In a tenant with ``branch_owners``, ``create_branch`` records the caller as
the branch's owner and ``commit_files`` refuses a branch it has no owner for,
or whose owner is someone else.

The tool set is fixed: reads, ``create_branch`` and ``commit_files``. There
is no tool to merge, delete, change settings, administer or read secrets.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import difflib
import fnmatch
import hashlib
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

import anyio
import httpx
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from opentelemetry.trace import StatusCode
from pydantic import BaseModel, Field
from starlette.requests import Request

from . import telemetry, validation
from .audit import AuditSink, AuditUnavailable, digest, new_event, redact, sha256_hex, who
from .auth import PRINCIPAL_SCOPE_KEY, Principal
from .branching import (
    ApiBranchCreator,
    BranchCreationError,
    BranchCreator,
    BranchRequest,
    WebhookBranchCreator,
)
from .clientip import ClientIpPolicy
from .config import AuthMode, AuthorSource, TenantConfig
from .credentials import (
    AuthorizationRequired,
    CredentialError,
    CredentialProvider,
    ForgejoCredential,
    Identity,
)
from .forgejo import ForgejoClient, ForgejoError
from .limits import PrincipalCache, RateLimited, TenantRateLimiter
from .store import Store, WorkSession
from .tenancy import TenantResolver, UnknownTenant
from .validation import InvalidInput, RepoRef

INSTRUCTIONS = """\
Branch-and-commit access to a Forgejo instance.

Start every piece of work with begin_change; pass the session_id it returns to
every other tool. Read with list_repos, list_branches, list_folder, read_file
and diff_branch. To change files: create_branch from the default branch, then
commit_files to that branch (several files in one commit). You can't write to
the default branch or to protected branches, and you can't merge, delete or
change settings: a person reviews and merges your branch.
"""

log = logging.getLogger("alasin_mcp.tools")

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)

# The exact tool set. tests/test_tool_surface.py fails if this changes.
TOOL_NAMES = (
    "begin_change",
    "list_repos",
    "list_branches",
    "list_folder",
    "read_file",
    "diff_branch",
    "create_branch",
    "commit_files",
)
WRITE_TOOLS = frozenset({"create_branch", "commit_files"})

RESERVED_TRAILERS = ("trace-id", "alasin-session")
# Trailers that attribute a commit to someone. The author is the verified
# caller; the message can't name anyone else. The configured agent co-author
# alone may be written out (the server adds it anyway).
ATTRIBUTION_TRAILERS = ("co-authored-by", "signed-off-by")
MAX_DIFF_FILES = 50
MAX_DIFF_CHARS = 200_000
_TRAILER_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*: .+$")
_IDENTITY = re.compile(r"^\s*([^<>\r\n]+?)\s*<([^<>\s@]+@[^<>\s@]+)>\s*$")

SessionId = Annotated[str, Field(description="The session_id returned by begin_change.")]
RepoArg = Annotated[str, Field(description="Repository as 'owner/name'.")]


class PolicyError(Exception):
    """A request the server refuses by policy. Safe to show the model."""


class FileChange(BaseModel):
    path: str = Field(description="Repository-relative file path.")
    content: str = Field(description="The complete new file content.")
    encoding: Literal["utf-8", "base64"] = Field(
        default="utf-8", description="How content is encoded: plain utf-8 text or base64."
    )


@dataclass
class Call:
    """What a tool body gets: the verified caller and the helpers bound to them."""

    services: Services
    principal: Principal
    tenant: TenantConfig
    session: WorkSession | None
    request: Request | None
    audit: dict[str, Any] = field(default_factory=dict)

    async def credential(self, repo: RepoRef | None) -> ForgejoCredential:
        cred = await self.services.credentials.credential(self.tenant, self.principal, repo)
        self.audit["auth_mode"] = str(cred.mode)
        return cred

    def client(self, cred: ForgejoCredential) -> ForgejoClient:
        return ForgejoClient(self.tenant.api_base, cred.token, transport=self.services.transport)

    async def record_attempt(self, action: str, **details: Any) -> None:
        """Write an attempt event before a mutating call; refuse the write if it fails.
        The fsyncing write runs in a worker thread, off the event loop."""
        event = {
            **self.audit,
            **new_event(),
            "phase": "attempt",
            "action": action,
            **details,
        }
        try:
            await anyio.to_thread.run_sync(self.services.audit_sink.emit, redact(event))
        except Exception as e:
            log.error("audit attempt event could not be recorded; refusing %s", action)
            raise AuditUnavailable("the audit trail is unavailable; the write was not made") from e

    def check_repo(self, raw: str) -> RepoRef:
        repo = validation.repo(raw)
        allowed = repo_allowed(self.tenant, repo.full_name)
        # Written by name only when the configuration names its owner (an
        # org): otherwise the caller chose the owner, which can be a person's
        # login, so only its digest is written.
        if allowed and owner_configured(self.tenant, repo.full_name):
            self.audit["repo"] = repo.full_name
        else:
            self.audit["repo_sha256"] = sha256_hex(repo.full_name)
        if not allowed:
            raise PolicyError(f"repository {repo.full_name} is not available to this tenant")
        return repo

    async def repo_info(self, client: ForgejoClient, repo: RepoRef) -> dict[str, Any]:
        cache = self.services.cache
        hit = cache.get(self.principal, "repo", repo.full_name.casefold())
        if hit is not None:
            return hit
        info = await client.repo(repo)
        cache.set(self.principal, "repo", repo.full_name.casefold(), info)
        return info

    async def account_identity(self, client: ForgejoClient) -> Identity:
        cache = self.services.cache
        hit = cache.get(self.principal, "identity", self.tenant.auth_mode)
        if hit is not None:
            return hit
        user = await client.current_user()
        ident = Identity(str(user.get("full_name") or user["login"]), str(user["email"]))
        cache.set(self.principal, "identity", self.tenant.auth_mode, ident)
        return ident


def is_ci_path(tenant: TenantConfig, path: str) -> bool:
    folded = path.casefold()
    return any(folded.startswith(prefix.casefold()) for prefix in tenant.ci_paths)


def repo_allowed(tenant: TenantConfig, full_name: str) -> bool:
    name = full_name.casefold()
    return any(fnmatch.fnmatchcase(name, pat.casefold()) for pat in tenant.repos)


def owner_configured(tenant: TenantConfig, full_name: str) -> bool:
    """Whether a pattern that admits ``full_name`` names its owner literally."""
    name = full_name.casefold()
    return any(
        fnmatch.fnmatchcase(name, pat.casefold()) and not set(pat.partition("/")[0]) & set("*?[")
        for pat in tenant.repos
    )


def canonical_repo(repo: RepoRef, info: dict[str, Any]) -> RepoRef:
    """The repo as Forgejo spells it. Lookups ignore case; other services may not."""
    owner, _, name = str(info.get("full_name") or "").partition("/")
    if name and f"{owner}/{name}".casefold() == repo.full_name.casefold():
        return RepoRef(owner, name)
    return repo


@dataclass
class Services:
    resolver: TenantResolver
    credentials: CredentialProvider
    store: Store
    audit_sink: AuditSink
    limiter: TenantRateLimiter = field(default_factory=TenantRateLimiter)
    cache: PrincipalCache = field(default_factory=PrincipalCache)
    session_ttl: float = 12 * 3600
    # Tests inject a transport; production uses the default network transport.
    transport: httpx.AsyncBaseTransport | None = None
    branch_creators: dict[str, BranchCreator] = field(
        default_factory=lambda: {"api": ApiBranchCreator(), "webhook": WebhookBranchCreator()}
    )
    # Tenant id -> the groups whose members may use the write tools (the
    # identity provider's allowed_groups). Tenants not listed have no gate.
    writer_groups: dict[str, frozenset[str]] = field(default_factory=dict)
    # Which address an audit event records for the caller (clientip.py).
    client_ip: ClientIpPolicy = field(default_factory=ClientIpPolicy)

    def check_writer(self, tenant: TenantConfig, principal: Principal) -> None:
        """The per-write lane gate. Sign-in checked the groups once; this
        re-checks them on every write, against the claims of this token."""
        allowed = self.writer_groups.get(tenant.id)
        if allowed is None:
            return
        # Only the identity provider's people: their groups, name and email
        # come from the IdP, never from a credential that asserts its own.
        if principal.idp_subject is None:
            raise PolicyError("changes here need a sign-in through the identity provider")
        groups = principal.claims.get("groups")
        if not isinstance(groups, list) or not allowed.intersection(
            g for g in groups if isinstance(g, str)
        ):
            raise PolicyError("your account is not in a group that may make changes here")
        if not principal.name or not principal.email or not principal.email_verified:
            raise PolicyError(
                "your sign-in carries no name or no verified email to author commits with; "
                "ask an administrator to set them on your account, then sign in again"
            )

    def branch_creator(self, tenant: TenantConfig) -> BranchCreator:
        creator = self.branch_creators.get(tenant.branch_creation)
        if creator is None:
            raise PolicyError(f"branch creation '{tenant.branch_creation}' is not available")
        return creator

    async def call(
        self,
        ctx: Context,
        tool: str,
        arguments: dict[str, Any],
        session_id: str | None,
        body: Callable[[Call], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        request = ctx.request_context.request
        principal = request.scope.get(PRINCIPAL_SCOPE_KEY) if isinstance(request, Request) else None
        if not isinstance(principal, Principal):
            raise ToolError("unauthenticated")
        try:
            tenant = self.resolver.resolve(principal)
        except UnknownTenant:
            raise ToolError("the caller's tenant is not configured on this server") from None
        event = new_event(
            tenant=principal.tenant,
            **who(principal),
            client_ip=self.client_ip.client_ip(request if isinstance(request, Request) else None),
            tool=tool,
            session_id=session_id,
            arguments=_audit_arguments(arguments),
        )
        try:
            self.limiter.check(tenant.id, tenant.rate_limit_per_minute)
        except RateLimited as e:
            await self._finish(event, None, error=str(e), error_kind="rate_limited")
            raise ToolError(str(e)) from None
        session = None
        if session_id is not None:
            session = self.store.get_session(tenant.id, principal.subject, session_id)
            if session is None:
                msg = "unknown or expired session_id; call begin_change first"
                await self._finish(event, None, error=msg, error_kind="unknown_session")
                raise ToolError(msg)
        if tool in WRITE_TOOLS:
            try:
                self.check_writer(tenant, principal)
            except PolicyError as e:
                await self._finish(event, None, error=str(e), error_kind="writer_gate")
                raise ToolError(str(e)) from None
        session_trace = (session.trace_id, session.span_id) if session else None
        attrs = {
            "alasin.tenant": tenant.id,
            "alasin.subject": principal.subject,
            "alasin.tool": tool,
            "alasin.session_id": session_id or "",
        }
        meta = ctx.request_context.meta
        new_root = tool == "begin_change"
        with telemetry.tool_span(tool, session_trace, attrs, meta, new_root=new_root) as span:
            trace_id, span_id = telemetry.ids(span)
            event["trace_id"] = session.trace_id if session else trace_id
            event["span_id"] = span_id
            call = Call(self, principal, tenant, session, request, audit=event)
            result: dict[str, Any] | None = None
            error: str | None = "internal error: incomplete"
            error_kind: str | None = "internal"
            try:
                result = await body(call)
                error = error_kind = None
            except (
                InvalidInput,
                PolicyError,
                CredentialError,
                AuditUnavailable,
                BranchCreationError,
            ) as e:
                error, error_kind = _loggable(e), _error_kind(e)
                raise ToolError(str(e)) from None
            except ForgejoError as e:
                error, error_kind = str(e), "forgejo"
                raise ToolError(str(e)) from None
            except httpx.HTTPError as e:
                error = f"could not reach an upstream service: {type(e).__name__}"
                error_kind = "upstream_unreachable"
                raise ToolError(error) from None
            except BaseException as e:
                # Including cancellation: the outcome is recorded either way.
                cancelled = isinstance(e, asyncio.CancelledError)
                error = "cancelled" if cancelled else f"internal error: {type(e).__name__}"
                error_kind = "cancelled" if cancelled else "internal"
                raise
            finally:
                for key in ("repo", "branch", "commit", "author", "committer"):
                    if event.get(key) is not None:
                        span.set_attribute(f"alasin.{key}", str(event[key]))
                summary = _result_summary(result) if result is not None else None
                await self._finish(event, span, result=summary, error=error, error_kind=error_kind)
            assert result is not None
            return result

    async def _finish(
        self,
        event: dict[str, Any],
        span: Any,
        *,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        error_kind: str | None = None,
    ) -> None:
        """Record the outcome. Never raises: a write may already have landed, and
        failing the call now would invite a retry that duplicates it. The attempt
        event written before the write is the fail-closed record."""
        event = {**event, "phase": "outcome"}
        event["outcome"] = "error" if error else "ok"
        if error:
            event["error"] = error
            event["error_kind"] = error_kind or "error"
            if span is not None:
                span.set_status(StatusCode.ERROR, error)
        if result is not None:
            event["result"] = result
        try:
            # Shielded: a cancelled call still records its outcome.
            with anyio.CancelScope(shield=True):
                await anyio.to_thread.run_sync(self.audit_sink.emit, redact(event))
        except Exception:
            log.exception("audit outcome event could not be recorded: %s", event["event_id"])


def _loggable(e: BaseException) -> str:
    """An error message safe for audit and spans: no authorization links or state."""
    if isinstance(e, AuthorizationRequired):
        return "Forgejo authorization required (link issued to the caller)"
    return str(e)


def _error_kind(e: BaseException) -> str:
    """A fixed category for an error: the audit records this, and the
    message only as a digest (a message can quote input)."""
    return {
        InvalidInput: "invalid_input",
        PolicyError: "policy",
        CredentialError: "credential",
        AuditUnavailable: "audit_unavailable",
        BranchCreationError: "branch_creation",
    }.get(type(e), "error")


def _audit_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Arguments as recorded, with no personal data or free text: the repo as
    its SHA-256; intents and messages as ``<key>_sha256`` and ``<key>_chars``; branches, refs and
    paths as ``<key>_sha256``; author arguments only as whether they were
    given; file contents as size and SHA-256, file paths as their SHA-256."""
    out: dict[str, Any] = {}
    for key, value in arguments.items():
        if key in ("author_name", "author_email"):
            out["author_given"] = bool(
                arguments.get("author_name") or arguments.get("author_email")
            )
        elif key == "files":
            out["files"] = [_audit_file(f) for f in value] if isinstance(value, list) else None
        elif value is None or isinstance(value, bool | int | float):
            out[key] = value
        elif key == "repo":
            # As typed, before it is checked: only its digest. The event's
            # own `repo` is the checked one, and only for the tenant's repos.
            out["repo_sha256"] = sha256_hex(str(value))
        elif key in ("branch", "ref", "base", "from_ref", "path"):
            if value:
                out[f"{key}_sha256"] = sha256_hex(str(value))
        else:
            out.update(digest(key, str(value)))
    return out


def _audit_file(f: Any) -> dict[str, Any]:
    if not isinstance(f, FileChange):
        return {}
    data = f.content.encode()
    return {
        "path_sha256": sha256_hex(f.path),
        "encoding": f.encoding,
        "content_bytes": len(data),
        "content_sha256": hashlib.sha256(data).hexdigest(),
    }


# Result values recorded as they are: ids, shas, counts, flags, the commit URL.
_RESULT_KEEP = frozenset(
    {
        "session_id",
        "trace_id",
        "expires_at",
        "commit",
        "sha",
        "merge_base",
        "url",
        "size",
        "encoding",
        "truncated",
        "files_changed",
    }
)


def _result_summary(result: dict[str, Any]) -> dict[str, Any]:
    """The result as recorded: ids, shas, counts and flags kept; lists as
    their length; author and committer left out; any other text (paths,
    branches, messages, file contents) as ``<key>_sha256`` and ``<key>_chars``."""
    out: dict[str, Any] = {}
    for k, v in result.items():
        if k in ("author", "committer"):
            continue  # people; the commit records them
        if isinstance(v, list):
            out[k] = {"count": len(v)}
        elif v is None or isinstance(v, bool | int | float):
            out[k] = v
        elif k in _RESULT_KEEP and isinstance(v, str) and len(v) <= 300:
            out[k] = v
        elif isinstance(v, str):
            out.update(digest(k, v))
        else:
            out[k] = {"keys": len(v) if isinstance(v, dict) else 0}
    return out


# -- policy ---------------------------------------------------------------------------


async def check_writable(
    call: Call, client: ForgejoClient, repo: RepoRef, branch: str, info: dict[str, Any]
) -> None:
    """Refuse writes to the default branch and to protected branches.

    Defence in depth: Forgejo's branch protection and protected file patterns
    are the real gate. This check keeps the server from even trying.
    """
    tenant = call.tenant
    default = str(info.get("default_branch") or "main")
    if branch == default:
        raise PolicyError(f"'{branch}' is the default branch; write to a new branch instead")
    for pattern in tenant.protected_branches:
        if fnmatch.fnmatchcase(branch, pattern):
            raise PolicyError(f"branch '{branch}' is protected by server policy ({pattern})")
    if tenant.branch_prefix and not branch.startswith(tenant.branch_prefix):
        raise PolicyError(f"branch names must start with '{tenant.branch_prefix}'")
    # Forgejo marks every branch a protection rule matches as "protected",
    # including work branches where pushing is allowed and only some file
    # patterns are locked. What matters is whether this account may push.
    existing = await client.branch(repo, branch)
    if existing is not None and existing.get("user_can_push") is False:
        raise PolicyError(f"branch '{branch}' is protected in Forgejo (no push allowed)")


# How long a pending reservation holds beyond the creator's own time limit
# (the webhook's request timeout plus its polling). Older, it is dropped.
RESERVATION_MARGIN = 60.0


def reservation_ttl(tenant: TenantConfig) -> float:
    hook = tenant.branch_webhook
    return (hook.timeout_seconds + 15.0 if hook is not None else 30.0) + RESERVATION_MARGIN


def reserve_branch(call: Call, repo: RepoRef, branch: str) -> None:
    """Reserve a new branch for the caller before it is created.

    Pending only: it keeps a second person from starting the same creation but
    is never ownership. confirm_owner makes it so once the creator succeeds.
    """
    if not call.tenant.branch_owners:
        return
    holder = call.services.store.reserve_branch(
        call.tenant.id,
        repo.full_name,
        branch,
        call.principal.subject,
        reservation_ttl(call.tenant),
    )
    if holder != call.principal.subject:
        # Never say who: an echo would tell anyone which branches whose are.
        raise PolicyError(f"branch '{branch}' is already taken; choose another name")


def confirm_owner(call: Call, repo: RepoRef, branch: str) -> None:
    if call.tenant.branch_owners:
        call.services.store.confirm_branch(
            call.tenant.id, repo.full_name, branch, call.principal.subject
        )


def may_reclaim(call: Call, repo: RepoRef, branch: str) -> bool:
    """Whether create_branch may re-request a branch that already exists.

    Only where the branch webhook is the owner's authority and this server has
    no confirmed owner (its state was lost, say). The receiver answers a
    re-request by the branch's owner with success and anyone else with a
    refusal. Nothing is recorded before that answer, so the branch has no
    owner here, and takes no writes, until the receiver has named the caller.
    """
    return (
        call.tenant.branch_owners
        and call.tenant.branch_creation == "webhook"
        and call.services.store.branch_owner(call.tenant.id, repo.full_name, branch) is None
    )


def check_owner(call: Call, repo: RepoRef, branch: str) -> None:
    """In a branch_owners tenant, only the branch's recorded creator may write it."""
    if not call.tenant.branch_owners:
        return
    owner = call.services.store.branch_owner(call.tenant.id, repo.full_name, branch)
    if owner != call.principal.subject:
        raise PolicyError(
            f"branch '{branch}' was not created by you through this server; "
            "create your own branch with create_branch and commit there (if you did create "
            "it, call create_branch for it again to confirm)"
        )


def parse_identity(value: str) -> Identity | None:
    m = _IDENTITY.match(value)
    return Identity(m.group(1), m.group(2)) if m else None


async def resolve_author(
    call: Call,
    client: ForgejoClient,
    cred: ForgejoCredential,
    author_name: str | None,
    author_email: str | None,
) -> tuple[Identity | None, Identity | None, str]:
    """(author, committer, source) for a commit. None means the token's own user.

    The author is only ever taken from somewhere the deployer chose: the
    platform's verified end user, the inbound token's claims, a header the
    gateway sets, or (explicit opt-in only) the tool arguments.
    """
    tenant = call.tenant
    argument_given = bool(author_name or author_email)
    if cred.author is not None:
        if argument_given:
            raise PolicyError("the commit author is fixed by the platform; omit author_*")
        return cred.author, cred.committer, "platform"
    source = tenant.author_source
    if cred.mode is not AuthMode.SERVICE_ACCOUNT:
        source = AuthorSource.SERVICE_ACCOUNT
    if argument_given and source is not AuthorSource.TOOL_ARGUMENT:
        raise PolicyError("this server does not accept the commit author as an argument")
    author: Identity | None = None
    if source is AuthorSource.TOKEN_CLAIMS:
        p = call.principal
        if not p.email:
            raise PolicyError("author_source=token_claims but the token carries no email claim")
        if not p.email_verified:
            raise PolicyError("author_source=token_claims needs email_verified=true on the token")
        author = Identity(p.name or p.subject, p.email)
    elif source is AuthorSource.TRUSTED_HEADER and call.request is not None:
        raw = call.request.headers.get(tenant.author_header)
        if raw and not call.principal.via_gateway:
            raise PolicyError("the author header is accepted only from the configured gateway")
        if raw:
            author = parse_identity(raw)
            if author is None:
                raise PolicyError("the upstream author header is malformed")
    elif source is AuthorSource.TOOL_ARGUMENT and argument_given:
        if not (author_name and author_email):
            raise PolicyError("give both author_name and author_email")
        author = parse_identity(f"{author_name} <{author_email}>")
        if author is None:
            raise InvalidInput("invalid author identity")
    if author is None:
        return None, None, "service_account"
    # Forgejo copies the author into the committer unless told otherwise; the
    # committer stays the account that actually made the change.
    return author, await call.account_identity(client), str(source)


def build_message(message: str, coauthor: str, trace_id: str, session_id: str) -> str:
    text = message.strip()
    if not text:
        raise InvalidInput("commit message must not be empty")
    if len(text) > 10_000:
        raise InvalidInput("commit message is too long")
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().casefold()
        if key in RESERVED_TRAILERS:
            raise InvalidInput(f"the server adds the '{name.strip()}' trailer itself")
        if key in ATTRIBUTION_TRAILERS and not (
            key == "co-authored-by" and value.strip().casefold() == coauthor.casefold()
        ):
            raise InvalidInput(
                f"the '{name.strip()}' trailer can't be set: the commit is attributed to the "
                "signed-in person by the server"
            )
    trailers = []
    if coauthor and f"co-authored-by: {coauthor}".casefold() not in text.casefold():
        trailers.append(f"Co-Authored-By: {coauthor}")
    trailers.append(f"Trace-Id: {trace_id}")
    trailers.append(f"Alasin-Session: {session_id}")
    paragraphs = text.split("\n\n")
    last = paragraphs[-1].splitlines()
    if len(paragraphs) > 1 and all(_TRAILER_LINE.match(x) for x in last):
        return text + "\n" + "\n".join(trailers) + "\n"
    return text + "\n\n" + "\n".join(trailers) + "\n"


def _decode(f: FileChange) -> bytes:
    if f.encoding == "base64":
        try:
            return base64.b64decode(f.content, validate=True)
        except (binascii.Error, ValueError):
            raise InvalidInput(f"{f.path}: content is not valid base64") from None
    return f.content.encode("utf-8")


def _text_or_none(data: bytes | None) -> list[str] | None:
    if data is None:
        return []
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return None


# -- the server ---------------------------------------------------------------------------


def build_server(services: Services) -> MCPServer:
    server = MCPServer(name="alasin-mcp", instructions=INSTRUCTIONS)

    @server.tool(
        description=(
            "Start a piece of work. Returns a session_id that every other tool requires, "
            "and the trace ID stamped into your commits. Describe the intent in a sentence."
        ),
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def begin_change(ctx: Context, intent: str = "") -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            trace_id, span_id = call.audit["trace_id"], call.audit["span_id"]
            session = call.services.store.create_session(
                call.tenant.id,
                call.principal.subject,
                trace_id,
                span_id,
                intent[:500],
                call.services.session_ttl,
            )
            call.audit["session_id"] = session.session_id
            return {
                "session_id": session.session_id,
                "trace_id": session.trace_id,
                "expires_at": int(session.expires_at),
            }

        return await services.call(ctx, "begin_change", {"intent": intent}, None, body)

    @server.tool(
        description="List the repositories you can work in.",
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def list_repos(ctx: Context, session_id: SessionId) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            cred = await call.credential(None)
            async with call.client(cred) as client:
                repos = await client.user_repos()
            out = [
                {
                    "repo": r["full_name"],
                    "default_branch": r.get("default_branch"),
                    "description": r.get("description") or "",
                    "archived": bool(r.get("archived")),
                }
                for r in repos
                if isinstance(r.get("full_name"), str) and repo_allowed(call.tenant, r["full_name"])
            ]
            return {"repos": out}

        return await services.call(ctx, "list_repos", {}, session_id, body)

    @server.tool(
        description="List a repository's branches, with whether each is protected.",
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def list_branches(ctx: Context, session_id: SessionId, repo: RepoArg) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            r = call.check_repo(repo)
            cred = await call.credential(r)
            async with call.client(cred) as client:
                info = await call.repo_info(client, r)
                branches = await client.branches(r)
            return {
                "default_branch": info.get("default_branch"),
                "branches": [
                    {
                        "name": b["name"],
                        "protected": bool(b.get("protected")),
                        "commit": (b.get("commit") or {}).get("id"),
                    }
                    for b in branches
                ],
            }

        return await services.call(ctx, "list_branches", {"repo": repo}, session_id, body)

    @server.tool(
        description="List a folder. path '' is the repository root; ref defaults to the "
        "default branch.",
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def list_folder(
        ctx: Context, session_id: SessionId, repo: RepoArg, path: str = "", ref: str = ""
    ) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            r = call.check_repo(repo)
            p = validation.file_path(path, allow_root=True)
            rf = validation.ref(ref) if ref else None
            cred = await call.credential(r)
            async with call.client(cred) as client:
                listing = await client.contents(r, p, rf)
            if not isinstance(listing, list):
                raise InvalidInput(f"'{p}' is a file; use read_file")
            return {
                "path": p,
                "entries": [
                    {
                        "name": e.get("name"),
                        "path": e.get("path"),
                        "type": e.get("type"),
                        "size": e.get("size"),
                    }
                    for e in listing
                ],
            }

        args = {"repo": repo, "path": path, "ref": ref}
        return await services.call(ctx, "list_folder", args, session_id, body)

    @server.tool(
        description="Read a file. ref defaults to the default branch. Text comes back as "
        "utf-8, anything else as base64.",
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def read_file(
        ctx: Context, session_id: SessionId, repo: RepoArg, path: str, ref: str = ""
    ) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            r = call.check_repo(repo)
            p = validation.file_path(path)
            rf = validation.ref(ref) if ref else None
            cred = await call.credential(r)
            async with call.client(cred) as client:
                meta = await client.contents(r, p, rf)
            if isinstance(meta, list):
                raise InvalidInput(f"'{p}' is a folder; use list_folder")
            if meta.get("type") != "file":
                raise InvalidInput(f"'{p}' is a {meta.get('type')}, not a file")
            size = int(meta.get("size") or 0)
            if meta.get("content") is None and size > 0:
                # Forgejo leaves content out for blobs above its API limit.
                return {
                    "path": p,
                    "sha": meta.get("sha"),
                    "size": size,
                    "encoding": None,
                    "truncated": True,
                    "content": "",
                    "note": "Forgejo did not return this file's content (too large for its API)",
                }
            data = base64.b64decode(meta.get("content") or "")
            limit = call.tenant.max_file_bytes
            truncated = len(data) > limit
            data = data[:limit]
            lines = _text_or_none(data)
            if lines is not None:
                content, encoding = data.decode("utf-8", errors="ignore"), "utf-8"
            else:
                content, encoding = base64.b64encode(data).decode(), "base64"
            return {
                "path": p,
                "sha": meta.get("sha"),
                "size": meta.get("size"),
                "encoding": encoding,
                "truncated": truncated,
                "content": content,
            }

        args = {"repo": repo, "path": path, "ref": ref}
        return await services.call(ctx, "read_file", args, session_id, body)

    @server.tool(
        description="Show what a branch changes compared with the default branch (or base): "
        "the commits and a unified diff per file.",
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def diff_branch(
        ctx: Context, session_id: SessionId, repo: RepoArg, branch: str, base: str = ""
    ) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            r = call.check_repo(repo)
            head = validation.branch(branch)
            call.audit["branch"] = head
            cred = await call.credential(r)
            async with call.client(cred) as client:
                info = await call.repo_info(client, r)
                base_ref = validation.ref(base) if base else str(info["default_branch"])
                cmp = await client.compare(r, base_ref, head)
                commits = cmp.get("commits") or []
                shas = {c["sha"] for c in commits}
                merge_base = base_ref
                for c in commits:
                    for parent in c.get("parents") or []:
                        if parent.get("sha") not in shas:
                            merge_base = parent["sha"]
                diffs: list[dict[str, Any]] = []
                budget = MAX_DIFF_CHARS
                files = cmp.get("files") or []
                for f in files[:MAX_DIFF_FILES]:
                    raw_name = f.get("filename")
                    try:
                        # Names come from Forgejo, but they still go into URLs
                        # made with this tenant's token: validate like any input.
                        name = validation.file_path(str(raw_name))
                    except InvalidInput:
                        diffs.append(
                            {
                                "path": str(raw_name)[:200],
                                "status": f.get("status"),
                                "diff": None,
                                "note": "skipped: path not accepted by the server",
                            }
                        )
                        continue
                    entry: dict[str, Any] = {"path": name, "status": f.get("status")}
                    if budget <= 0:
                        entry["diff"] = None
                        entry["note"] = "diff omitted: output limit reached"
                        diffs.append(entry)
                        continue
                    old = _text_or_none(await client.raw(r, name, merge_base))
                    new = _text_or_none(await client.raw(r, name, head))
                    if old is None or new is None:
                        entry["diff"] = None
                        entry["note"] = "binary file"
                    else:
                        text = "".join(difflib.unified_diff(old, new, f"a/{name}", f"b/{name}"))
                        entry["diff"] = text[:budget]
                        if len(text) > budget:
                            entry["note"] = "diff truncated"
                        budget -= len(text)
                    diffs.append(entry)
            return {
                "base": base_ref,
                "merge_base": merge_base,
                "branch": head,
                "commits": [
                    {
                        "sha": c["sha"],
                        "message": ((c.get("commit") or {}).get("message") or "")[:2000],
                    }
                    for c in commits
                ],
                "files_changed": len(files),
                "files": diffs,
            }

        args = {"repo": repo, "branch": branch, "base": base}
        return await services.call(ctx, "diff_branch", args, session_id, body)

    @server.tool(
        description="Create a new branch, from the default branch unless from_ref is given. "
        "Protected and default branches can't be created or written.",
        annotations=WRITE,
        structured_output=True,
    )
    async def create_branch(
        ctx: Context, session_id: SessionId, repo: RepoArg, branch: str, from_ref: str = ""
    ) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            r = call.check_repo(repo)
            name = validation.branch(branch)
            call.audit["branch"] = name
            cred = await call.credential(r)
            async with call.client(cred) as client:
                info = await call.repo_info(client, r)
                await check_writable(call, client, r, name, info)
                exists = await client.branch(r, name) is not None
                if exists and not may_reclaim(call, r, name):
                    raise PolicyError(f"branch '{name}' already exists")
                source = validation.ref(from_ref) if from_ref else str(info["default_branch"])
                creator = call.services.branch_creator(call.tenant)
                await call.record_attempt(
                    "create_branch",
                    branch=name,
                    from_ref=source,
                    method=call.tenant.branch_creation,
                )
                assert call.session is not None
                if not exists:
                    reserve_branch(call, r, name)
                try:
                    sha = await creator.create(
                        BranchRequest(
                            call.tenant,
                            call.principal,
                            call.session.session_id,
                            canonical_repo(r, info),
                            name,
                            source,
                        ),
                        client,
                    )
                except BaseException:
                    if call.tenant.branch_owners:
                        call.services.store.release_branch(
                            call.tenant.id, r.full_name, name, call.principal.subject
                        )
                    raise
                confirm_owner(call, r, name)
            call.audit["commit"] = sha
            return {"branch": name, "from": source, "commit": sha}

        args = {"repo": repo, "branch": branch, "from_ref": from_ref}
        return await services.call(ctx, "create_branch", args, session_id, body)

    @server.tool(
        description="Commit several files to an existing work branch in one commit. Each file "
        "is created or replaced with the full content given. The server adds Co-Authored-By, "
        "Trace-Id and Alasin-Session trailers.",
        annotations=WRITE,
        structured_output=True,
    )
    async def commit_files(
        ctx: Context,
        session_id: SessionId,
        repo: RepoArg,
        branch: str,
        message: str,
        files: list[FileChange],
        author_name: str = "",
        author_email: str = "",
    ) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            assert call.session is not None
            tenant = call.tenant
            r = call.check_repo(repo)
            name = validation.branch(branch)
            call.audit["branch"] = name
            if not files:
                raise InvalidInput("files must not be empty")
            if len(files) > tenant.max_commit_files:
                raise InvalidInput(f"at most {tenant.max_commit_files} files per commit")
            decoded: list[tuple[str, bytes]] = []
            seen: set[str] = set()
            total = 0
            for f in files:
                p = validation.file_path(f.path)
                if not tenant.allow_ci_paths and is_ci_path(tenant, p):
                    raise PolicyError(
                        f"{p}: CI workflow folders ({', '.join(tenant.ci_paths)}) can't be "
                        "written through this server"
                    )
                if p in seen:
                    raise InvalidInput(f"{p} appears twice")
                seen.add(p)
                data = _decode(f)
                if len(data) > tenant.max_file_bytes:
                    raise InvalidInput(f"{p} is larger than {tenant.max_file_bytes} bytes")
                total += len(data)
                decoded.append((p, data))
            if total > tenant.max_commit_bytes:
                raise InvalidInput(f"the commit is larger than {tenant.max_commit_bytes} bytes")
            full_message = build_message(
                message, tenant.agent_coauthor, call.session.trace_id, call.session.session_id
            )
            cred = await call.credential(r)
            async with call.client(cred) as client:
                info = await call.repo_info(client, r)
                await check_writable(call, client, r, name, info)
                if await client.branch(r, name) is None:
                    raise PolicyError(f"branch '{name}' does not exist; create_branch first")
                check_owner(call, r, name)
                ops: list[dict[str, Any]] = []
                for p, data in decoded:
                    try:
                        current = await client.contents(r, p, name)
                    except ForgejoError as e:
                        if e.status != 404:
                            raise
                        current = None
                    if current is None:
                        ops.append({"operation": "create", "path": p, "content": data})
                        continue
                    if isinstance(current, list) or current.get("type") != "file":
                        raise PolicyError(f"{p} exists and is not a regular file")
                    if base64.b64decode(current.get("content") or "") == data:
                        continue
                    ops.append(
                        {"operation": "update", "path": p, "content": data, "sha": current["sha"]}
                    )
                if not ops:
                    raise InvalidInput("no changes: every file already has this content")
                author, committer, source = await resolve_author(
                    call, client, cred, author_name or None, author_email or None
                )
                # The attempt names no author or committer: they are people
                # (the commit itself records them).
                await call.record_attempt("commit_files", branch=name, author_source=source)
                result = await client.change_files(
                    r,
                    name,
                    full_message,
                    ops,
                    author.as_dict() if author else None,
                    committer.as_dict() if committer else None,
                )
            commit = result.get("commit") or {}
            sha = commit.get("sha")
            c_author = commit.get("author") or {}
            c_committer = commit.get("committer") or {}
            call.audit.update(
                commit=sha,
                author=f"{c_author.get('name')} <{c_author.get('email')}>",
                committer=f"{c_committer.get('name')} <{c_committer.get('email')}>",
                author_source=source,
            )
            return {
                "commit": sha,
                "branch": name,
                "url": commit.get("html_url"),
                "files": [{"path": o["path"], "operation": o["operation"]} for o in ops],
                "unchanged": [p for p, _ in decoded if p not in {o["path"] for o in ops}],
                "trace_id": call.session.trace_id,
                "author": call.audit["author"],
                "committer": call.audit["committer"],
            }

        args = {
            "repo": repo,
            "branch": branch,
            "message": message,
            "files": files,
            "author_name": author_name,
            "author_email": author_email,
        }
        return await services.call(ctx, "commit_files", args, session_id, body)

    return server
