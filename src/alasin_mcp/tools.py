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

The tool set is fixed: reads (``change_status`` among them: a branch's
builds, preview and upstream pull request), ``create_branch``,
``commit_files``, ``git_access`` (a short-lived git URL for one of the
caller's branches, served by gitproxy.py) and ``propose_change`` (the
caller's own branch to an upstream pull request, through proposals.py).
There is no tool to merge, delete, change settings, administer or read
secrets.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import difflib
import fnmatch
import hashlib
import json
import logging
import re
import secrets
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

from . import proposals, telemetry, validation
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
from .config import AuthMode, AuthorSource, ConfigError, TenantConfig
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
A change lane into a Forgejo mirror of GitHub repositories, for people who
can't push to the GitHub repository themselves. A person reviews every change
and merges it upstream.

Who should change code through it: only someone without write access to the
GitHub repository. If you, or the person you're working for, can push to the
GitHub repository directly (a GitHub integration, the gh CLI or git with write
access), make the change on GitHub and don't use this server's write tools
(git_access with access="write", create_branch, commit_files,
propose_change): a lane change has to come back to GitHub through a pull
request anyway. Reading through this server is fine either way.

Start with begin_change and pass its session_id to every other tool. Read with
list_repos, list_branches, list_folder, read_file and diff_branch, or clone
with git_access(access="read").

To change code, use plain git: git_access gives a work branch and a
short-lived clone URL, and its result says exactly how to clone, commit and
push. create_branch and commit_files do the same without git, for when no
sandbox with git is available. You can't write to the default branch or to
protected branches, and you can't merge, delete or change settings.

After a push, change_status shows the branch's builds, its preview link and,
once proposed, its upstream pull request. When the work is done and checked,
propose_change opens that pull request; keep checking change_status to follow
the build, the review and the merge.
"""

log = logging.getLogger("alasin_mcp.tools")

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)

# The exact tool set. tests/test_tool_surface.py fails if this changes.
TOOL_NAMES = (
    "whoami",
    "begin_change",
    "list_repos",
    "list_branches",
    "list_folder",
    "read_file",
    "diff_branch",
    "create_branch",
    "commit_files",
    "git_access",
    "change_status",
    "propose_change",
)
WRITE_TOOLS = frozenset({"create_branch", "commit_files", "git_access", "propose_change"})

RESERVED_TRAILERS = ("trace-id", "alasin-session")
# Trailers that attribute a commit to someone. The author is the verified
# caller; the message can't name anyone else. The configured agent co-author
# alone may be written out (the server adds it anyway).
ATTRIBUTION_TRAILERS = ("co-authored-by", "signed-off-by")
# Output caps, so that one tool result stays well under a client's limit
# (claude.ai cuts a tool result at about 25k tokens). Measured as JSON: what
# goes on the wire, where a quote, a backslash or a tab takes two bytes and
# another control character six. The SDK sends a structured result twice
# (as text and as structuredContent), so each copy gets under half of ~60 KB.
# A result that is cut says truncated: true and how to continue.
RESULT_BUDGET = 28_000
MAX_DIFF_FILES = 50
MAX_DIFF_COMMITS = 100
MAX_FOLDER_ENTRIES = 500
MAX_STATUSES = 30
_PREVIEW_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
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
    # The proposal service's transport, apart from Forgejo's (tests inject it).
    proposal_transport: httpx.AsyncBaseTransport | None = None
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
                # Not a session of this caller's: their own text, not an id.
                event.pop("session_id", None)
                event.update(digest("session_id", session_id))
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
                proposals.ProposalError,
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
                summary = (
                    _result_summary(result, owner_named="repo" in event)
                    if result is not None
                    else None
                )
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
        proposals.ProposalError: "proposal",
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
        "tenant",
        "auth_mode",
    }
)


# Results that name a person (whoami, commit_files) leave these out entirely:
# a digest of an email or a name is guessable, so not even that is written.
_RESULT_PEOPLE = frozenset(
    {
        "author",
        "committer",
        "name",
        "email",
        "subject",
        "idp_subject",
        "owner_sub",
        "groups",
        "git_config",
    }
)
# Results carrying a credential (git_access's URL) leave it out entirely.
_RESULT_SECRET = frozenset({"clone_url"})


def _result_summary(result: dict[str, Any], *, owner_named: bool = False) -> dict[str, Any]:
    """The result as recorded: ids, shas, counts and flags kept; lists as
    their length; author and committer left out; any other text (paths,
    branches, messages, file contents) as ``<key>_sha256`` and ``<key>_chars``.
    A URL names the repo's owner, so it is kept only when the event names the
    repo itself (``owner_named``: the configuration names that owner)."""
    out: dict[str, Any] = {}
    for k, v in result.items():
        if k in _RESULT_PEOPLE or k in _RESULT_SECRET:
            continue  # people: the commit records authors, the event the sub
        if k == "url" and not owner_named and isinstance(v, str):
            out.update(digest(k, v))
            continue
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


def new_branch_name(tenant: TenantConfig) -> str:
    """A fresh work-branch name under the tenant's prefix."""
    return f"{tenant.branch_prefix}change-{secrets.token_hex(4)}"


async def create_owned_branch(
    call: Call,
    client: ForgejoClient,
    repo: RepoRef,
    canonical: RepoRef,
    name: str,
    info: dict[str, Any],
) -> str | None:
    """Create a branch from the default branch for the caller, recording them
    as its owner, the way create_branch does."""
    assert call.session is not None
    source = str(info["default_branch"])
    creator = call.services.branch_creator(call.tenant)
    await call.record_attempt(
        "create_branch", branch=name, from_ref=source, method=call.tenant.branch_creation
    )
    reserve_branch(call, repo, name)
    try:
        sha = await creator.create(
            BranchRequest(
                call.tenant, call.principal, call.session.session_id, canonical, name, source
            ),
            client,
        )
    except BaseException:
        if call.tenant.branch_owners:
            call.services.store.release_branch(
                call.tenant.id, repo.full_name, name, call.principal.subject
            )
        raise
    confirm_owner(call, repo, name)
    return sha


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
        return _split_lines(data.decode("utf-8"))
    except UnicodeDecodeError:
        return None


def _split_lines(text: str) -> list[str]:
    """Lines as git, grep and editors count them: split on \n only, ends kept
    (a CRLF line keeps its \r; str.splitlines would also split on \f, \v,
    \x85, U+2028 and a lone \r)."""
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def _json_size(text: str) -> int:
    """Bytes ``text`` takes inside a JSON string."""
    return len(json.dumps(text, ensure_ascii=False).encode("utf-8")) - 2


def _char_json_size(ch: str) -> int:
    if ch in '"\\\n\r\t\b\f':
        return 2
    if ord(ch) < 0x20:
        return 6
    return len(ch.encode("utf-8"))


def _fit(text: str, budget: int) -> int:
    """How many characters of ``text`` fit in ``budget`` JSON bytes."""
    if _json_size(text) <= budget:
        return len(text)
    used = 0
    for i, ch in enumerate(text):
        used += _char_json_size(ch)
        if used > budget:
            return i
    return len(text)


def _decode_text(data: bytes, cut: bool) -> str | None:
    """The bytes as text, or None for binary. When ``cut`` (the read stopped at
    a byte limit) a character split at the very end is dropped, not taken
    as a sign of binary content."""
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        if cut and e.start >= len(data) - 3:
            try:
                return data[: e.start].decode("utf-8")
            except UnicodeDecodeError:
                return None
        return None


def _line_window(
    text: str, start_line: int, offset: int, max_lines: int, cut: bool
) -> dict[str, Any]:
    """Lines from ``start_line`` (from character ``offset`` in it), as many as
    fit in RESULT_BUDGET (and at most ``max_lines`` when set). A line too long
    for one result comes back in pieces: ``next_offset`` says where it goes on,
    so every file the server reads can be put back together exactly."""
    lines = _split_lines(text)
    total = len(lines)
    if start_line > max(total, 1):
        raise InvalidInput(f"start_line {start_line} is past the end ({total} lines)")
    if offset and (not total or offset >= len(lines[start_line - 1])):
        raise InvalidInput(f"offset {offset} is past the end of line {start_line}")
    budget = RESULT_BUDGET
    taken: list[str] = []
    i, pos = start_line - 1, offset
    next_line = next_offset = None
    while i < total and not (max_lines and len(taken) >= max_lines):
        rest = lines[i][pos:]
        size = _json_size(rest)
        if size <= budget:
            taken.append(rest)
            budget -= size
            i, pos = i + 1, 0
            continue
        if not taken:
            # Longer than one result (minified code): this piece, then more.
            n = max(_fit(rest, budget), 1)
            taken.append(rest[:n])
            next_line, next_offset = i + 1, pos + n
        break
    if next_line is None and i < total:
        next_line = i + 1
    end_line = next_line if next_offset is not None else i
    window: dict[str, Any] = {
        "content": "".join(taken),
        "start_line": start_line,
        "offset": offset,
        "end_line": end_line,
        "total_lines": total,
        # More to read, or a file longer than the tenant's read limit.
        "truncated": next_line is not None or cut,
        "next_start_line": next_line,
        "next_offset": next_offset,
    }
    if cut and next_line is None:
        window["note"] = "the file is longer than this server reads; the rest is not available"
    return window


# -- the server ---------------------------------------------------------------------------


# What git_access hands back besides the URL: the commands, in order, and
# what this server's git answers mean, so a model in a sandbox can work the
# repository the way a person with a checkout would.
GIT_ERRORS: dict[str, dict[str, str]] = {
    "write": {
        "401": "The URL has expired (it lasts minutes). Call git_access again with the same "
        "branch, then git remote set-url origin <new clone_url>, and repeat the command.",
        "403": "Refused: the branch isn't yours, the push touches another ref (main, a tag, a "
        "new or deleted branch), or Forgejo's rules refuse a file. The message says which; "
        "don't retry the same push.",
        "429": "A push to this branch is already running, or too many requests: wait about "
        "ten seconds and retry once.",
        "rejected (non-fast-forward)": "The branch moved: git fetch origin <branch>, git "
        "rebase origin/<branch>, then push again. Never force-push.",
    },
    "read": {
        "401": "The URL has expired: call git_access again, then git remote set-url origin "
        "<new clone_url>.",
        "403": "Read-only: this URL can't push. For a change, call git_access with access='write'.",
        "429": "Too many requests: wait about ten seconds and retry once.",
    },
}


def git_steps(access: str, branch: str, name: str) -> list[str]:
    clone = (
        f"git clone --depth 1 --branch {branch} <clone_url> {name}: give it a generous "
        "timeout (several minutes) and don't interrupt it while it unpacks, even if it looks "
        "stalled"
    )
    rules = (
        f"Before changing anything, read CLAUDE.md, AGENTS.md and README.md at the root of "
        f"{name} (whichever exist) and follow them."
    )
    if access == "read":
        return [
            clone,
            rules,
            f"Other branches: git -C {name} fetch --depth 1 origin <branch>.",
            "This URL never pushes: call git_access with access='write' to change code.",
        ]
    return [
        clone,
        f"git -C {name} config user.name and user.email from git_config.",
        rules,
        "Edit, then commit with a message saying what changed and why.",
        f"Before pushing: git -C {name} fetch origin {branch} and rebase onto "
        f"origin/{branch} if it moved.",
        f"git -C {name} push origin {branch}. Only this branch can be pushed.",
        "After each push: change_status shows the build and, once it has uploaded, the "
        "preview link. When the change is done and checked: propose_change.",
    ]


def build_server(services: Services) -> MCPServer:
    server = MCPServer(name="alasin-mcp", instructions=INSTRUCTIONS)

    @server.tool(
        description=(
            "Show who the server thinks you are: your identity, tenant, sign-in "
            "groups and the repositories you may work in. Needs no session."
        ),
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def whoami(ctx: Context) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            principal, tenant = call.principal, call.tenant
            groups = principal.claims.get("groups")
            return {
                "tenant": tenant.id,
                "auth_mode": tenant.auth_mode.value,
                "subject": principal.subject,
                "idp_subject": principal.idp_subject,
                "name": principal.name,
                "email": principal.email,
                "email_verified": principal.email_verified,
                # None when the credential carries no groups claim at all.
                "groups": [g for g in groups if isinstance(g, str)]
                if isinstance(groups, list)
                else None,
                "repos": list(tenant.repos),
                "protected_branches": list(tenant.protected_branches),
            }

        return await services.call(ctx, "whoami", {}, None, body)

    @server.tool(
        description=(
            "Start a piece of work in the Forgejo change lane (for people without write "
            "access to the GitHub repository; with it, change GitHub directly). Returns a "
            "session_id that every other tool requires, and the trace ID stamped into your "
            "commits. Describe the intent in a sentence."
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
                "tenant": call.tenant.id,
                "repos": list(call.tenant.repos),
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
            # Repos the configuration names outright are looked up one by one,
            # which needs only the repository scope: a repo-scoped token gets
            # 403 (no read:user) from /user/repos. Only patterns need the listing.
            literal = [p for p in call.tenant.repos if not set(p) & set("*?[")]
            repos: list[dict[str, Any]] = []
            async with call.client(cred) as client:
                for name in literal:
                    # A bad entry, or a repo gone, hidden or renamed (Forgejo
                    # answers a rename with a redirect, not followed here),
                    # lists nothing instead of failing the whole listing.
                    try:
                        repos.append(await client.repo(validation.repo(name)))
                    except InvalidInput:
                        log.warning(
                            "tenant %s: repos entry is not owner/name; skipped", call.tenant.id
                        )
                    except ForgejoError as e:
                        if not (300 <= e.status < 400 or e.status in (403, 404)):
                            raise
                if len(literal) < len(call.tenant.repos):
                    repos.extend(await client.user_repos())
            out: dict[str, dict[str, Any]] = {}
            for r in repos:
                if isinstance(r.get("full_name"), str) and repo_allowed(
                    call.tenant, r["full_name"]
                ):
                    out.setdefault(
                        r["full_name"].casefold(),
                        {
                            "repo": r["full_name"],
                            "default_branch": r.get("default_branch"),
                            "description": r.get("description") or "",
                            "archived": bool(r.get("archived")),
                        },
                    )
            return {"repos": list(out.values())}

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
            entries: list[dict[str, Any]] = []
            budget = RESULT_BUDGET
            for e in listing[:MAX_FOLDER_ENTRIES]:
                entry = {
                    "name": e.get("name"),
                    "path": e.get("path"),
                    "type": e.get("type"),
                    "size": e.get("size"),
                }
                budget -= _json_size(json.dumps(entry, ensure_ascii=False))
                if budget < 0:
                    break
                entries.append(entry)
            return {
                "path": p,
                "entries": entries,
                "total_entries": len(listing),
                "truncated": len(entries) < len(listing),
            }

        args = {"repo": repo, "path": path, "ref": ref}
        return await services.call(ctx, "list_folder", args, session_id, body)

    @server.tool(
        description="Read a file. ref defaults to the default branch. Text comes back as "
        f"utf-8, anything else as base64. About {RESULT_BUDGET // 1000} KB per call: a longer "
        "file comes back in parts with truncated: true; pass next_start_line and "
        "next_offset back as start_line and offset for the next part.",
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def read_file(
        ctx: Context,
        session_id: SessionId,
        repo: RepoArg,
        path: str,
        ref: str = "",
        start_line: Annotated[int, Field(ge=1, description="First line to return (1-based).")] = 1,
        offset: Annotated[
            int,
            Field(
                ge=0,
                description="Where to start in start_line, in characters (for base64 "
                "content: in bytes of the file). Use next_offset from the last part.",
            ),
        ] = 0,
        max_lines: Annotated[
            int, Field(ge=0, description="Most lines to return; 0 means as many as fit.")
        ] = 0,
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
            cut = len(data) > limit
            data = data[:limit]
            text = _decode_text(data, cut)
            out: dict[str, Any] = {"path": p, "sha": meta.get("sha"), "size": meta.get("size")}
            if text is None:
                # base64 grows 4/3; a multiple of 3 bytes per part keeps each
                # part's base64 whole, so the parts decode one by one.
                if offset and offset >= len(data):
                    raise InvalidInput(f"offset {offset} is past the end ({len(data)} bytes)")
                part = data[offset : offset + RESULT_BUDGET * 3 // 4 // 3 * 3]
                more = offset + len(part) < len(data)
                return {
                    **out,
                    "encoding": "base64",
                    "offset": offset,
                    "truncated": more or cut,
                    "next_offset": offset + len(part) if more else None,
                    "content": base64.b64encode(part).decode(),
                }
            window = _line_window(text, start_line, offset, max_lines, cut)
            return {**out, "encoding": "utf-8", **window}

        args = {
            "repo": repo,
            "path": path,
            "ref": ref,
            "start_line": start_line,
            "offset": offset,
            "max_lines": max_lines,
        }
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
                # Commit messages may take a quarter of the budget, diffs the rest.
                budget = RESULT_BUDGET // 4
                truncated = len(commits) > MAX_DIFF_COMMITS
                listed: list[dict[str, Any]] = []
                for c in commits[:MAX_DIFF_COMMITS]:
                    message = ((c.get("commit") or {}).get("message") or "")[:2000]
                    budget -= 60  # the sha and the keys
                    n = _fit(message, max(budget, 0))
                    if budget <= 0 or (n < len(message) and n == 0):
                        truncated = True
                        break
                    truncated = truncated or n < len(message)
                    listed.append({"sha": c["sha"], "message": message[:n]})
                    budget -= _json_size(message[:n])
                budget += RESULT_BUDGET - RESULT_BUDGET // 4
                diffs: list[dict[str, Any]] = []
                files = cmp.get("files") or []
                truncated = truncated or len(files) > MAX_DIFF_FILES
                for f in files[:MAX_DIFF_FILES]:
                    raw_name = f.get("filename")
                    try:
                        # Names come from Forgejo, but they still go into URLs
                        # made with this tenant's token: validate like any input.
                        name = validation.file_path(str(raw_name))
                    except InvalidInput:
                        name = None
                    shown = name or str(raw_name)[:200]
                    # The entry's keys, path, status and a note.
                    budget -= 120 + _json_size(shown)
                    if budget <= 0:
                        # Out of room: the rest of the files are left out.
                        truncated = True
                        break
                    entry: dict[str, Any] = {"path": shown, "status": f.get("status")}
                    if name is None:
                        entry["diff"] = None
                        entry["note"] = "skipped: path not accepted by the server"
                        diffs.append(entry)
                        continue
                    old = _text_or_none(await client.raw(r, name, merge_base))
                    new = _text_or_none(await client.raw(r, name, head))
                    if old is None or new is None:
                        entry["diff"] = None
                        entry["note"] = "binary file"
                    else:
                        text = "".join(difflib.unified_diff(old, new, f"a/{name}", f"b/{name}"))
                        n = _fit(text, budget)
                        entry["diff"] = text[:n]
                        if n < len(text):
                            entry["note"] = "diff truncated"
                            truncated = True
                        budget -= _json_size(text[:n])
                    diffs.append(entry)
            return {
                "base": base_ref,
                "merge_base": merge_base,
                "branch": head,
                "commits": listed,
                "commit_count": len(commits),
                "files_changed": len(files),
                "files": diffs,
                "truncated": truncated,
            }

        args = {"repo": repo, "branch": branch, "base": base}
        return await services.call(ctx, "diff_branch", args, session_id, body)

    @server.tool(
        description="Create a new branch, from the default branch unless from_ref is given. "
        "Protected and default branches can't be created or written. Prefer git_access when "
        "you have git; with write access to the GitHub repository, change GitHub instead.",
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
        description="Commit several files to an existing work branch in one commit, for when "
        "no sandbox with git is available (otherwise use git_access). Each file is created or "
        "replaced with the full content given. The server adds Co-Authored-By, Trace-Id and "
        "Alasin-Session trailers.",
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

    @server.tool(
        description="Plain git to a repository: a clone URL with a short-lived credential in "
        "it, for ordinary git in your sandbox. access='write' (the default) gives one of your "
        "work branches, made for you when branch is empty, and only that branch can be "
        "pushed; use it only without write access to the GitHub repository (with it, change "
        "GitHub instead). access='read' reserves nothing and can clone or fetch any branch but "
        "never push. The result lists the exact commands and what each git error means.",
        annotations=WRITE,
        structured_output=True,
    )
    async def git_access(
        ctx: Context,
        session_id: SessionId,
        repo: RepoArg,
        branch: str = "",
        access: Literal["read", "write"] = "write",
    ) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            assert call.session is not None
            cfg = call.tenant.git_access
            r = call.check_repo(repo)
            if cfg is None:
                raise PolicyError("git access is not enabled on this server")
            call.audit["access"] = access
            cred = await call.credential(r)
            if access == "read":
                # Reserves and creates nothing: the credential is the repo's.
                name = validation.branch(branch) if branch else ""
                async with call.client(cred) as client:
                    info = await call.repo_info(client, r)
                canonical = canonical_repo(r, info)
                token_branch = ""
            else:
                name = validation.branch(branch) if branch else new_branch_name(call.tenant)
                call.audit["branch"] = name
                async with call.client(cred) as client:
                    info = await call.repo_info(client, r)
                    await check_writable(call, client, r, name, info)
                    canonical = canonical_repo(r, info)
                    if await client.branch(r, name) is None:
                        await create_owned_branch(call, client, r, canonical, name, info)
                    else:
                        check_owner(call, r, name)
                token_branch = name
            await call.record_attempt("git_access", branch=token_branch, access=access)
            token, expires = call.services.store.put_git_token(
                call.tenant.id,
                call.principal.subject,
                call.principal.idp_subject,
                canonical.full_name,
                token_branch,
                call.session.session_id,
                cfg.ttl_seconds,
            )
            scheme, _, host = cfg.public_url.partition("://")
            url = f"{scheme}://x-token:{token}@{host}/git/{canonical.full_name}.git"
            p = call.principal
            checkout = name or str(info["default_branch"])
            result: dict[str, Any] = {
                "access": access,
                "clone_url": url,
                "branch": checkout,
                "expires_at": int(expires),
                "steps": git_steps(access, checkout, canonical.name),
                "errors": GIT_ERRORS[access],
            }
            if access == "write":
                result["git_config"] = {
                    "user.name": p.name or p.subject,
                    "user.email": p.email or "",
                }
            return result

        args = {"repo": repo, "branch": branch, "access": access}
        return await services.call(ctx, "git_access", args, session_id, body)

    @server.tool(
        description=(
            "Follow a branch's change from push to merge: its head commit, the builds "
            "reported on it (each job's state and a link to its log), its preview link "
            "when the deployment serves branch previews, and its upstream pull request "
            "once proposed (open, closed or merged; review; checks). Call it after a push "
            "and again until the build has finished."
        ),
        annotations=READ_ONLY,
        structured_output=True,
    )
    async def change_status(
        ctx: Context, session_id: SessionId, repo: RepoArg, branch: str
    ) -> dict[str, Any]:
        async def body(call: Call) -> dict[str, Any]:
            r = call.check_repo(repo)
            name = validation.branch(branch)
            call.audit["branch"] = name
            cred = await call.credential(r)
            async with call.client(cred) as client:
                info = await call.repo_info(client, r)
                canonical = canonical_repo(r, info)
                found = await client.branch(r, name)
                if found is None:
                    raise PolicyError(f"branch '{name}' does not exist")
                sha = str((found.get("commit") or {}).get("id") or "")
                combined = await client.combined_status(r, sha) if sha else {}
            out: dict[str, Any] = {"branch": name, "commit": sha}
            statuses = [s for s in combined.get("statuses") or [] if isinstance(s, dict)]
            out["builds"] = [
                {
                    "context": str(s.get("context") or "")[:200],
                    "state": str(s.get("status") or s.get("state") or "")[:20],
                    "description": str(s.get("description") or "")[:300],
                    "target_url": str(s.get("target_url") or "")[:500],
                }
                for s in statuses[:MAX_STATUSES]
            ]
            if out["builds"]:
                out["build_state"] = str(combined.get("state") or "")[:20]
            else:
                out["build_state"] = "none"
                out["build_note"] = (
                    "no build has reported on this commit yet; a build usually starts within "
                    "a minute or two of a push, so check again shortly"
                )
            pv = call.tenant.previews
            slug = None
            if pv is not None and name.startswith(pv.branch_prefix):
                slug = name[len(pv.branch_prefix) :]
            if pv is not None and slug is not None and _PREVIEW_SLUG.fullmatch(slug):
                uploaded = any(
                    b["context"] == pv.upload_context and b["state"] == "success"
                    for b in out["builds"]
                )
                out["preview"] = {
                    "url": f"{pv.base_url}{slug}/",
                    "uploaded_for_this_commit": uploaded,
                    "note": (
                        "the preview shows this commit"
                        if uploaded
                        else "the preview shows this commit once its upload job succeeds; "
                        "until then the link shows an older upload of the branch or none. "
                        "The person opens it in their own browser and signs in"
                    ),
                }
            cfg = call.tenant.proposals
            if cfg is None:
                out["pull_request"] = {"available": False, "note": "proposals are not enabled"}
            else:
                try:
                    pr = await proposals.status(
                        cfg,
                        call.tenant.id,
                        canonical.full_name,
                        name,
                        transport=call.services.proposal_transport,
                    )
                    out["pull_request"] = {"available": True, **pr}
                except (proposals.ProposalError, ConfigError) as e:
                    out["pull_request"] = {
                        "available": False,
                        "note": f"the pull request state is unavailable: {e}",
                    }
            return out

        args = {"repo": repo, "branch": branch}
        return await services.call(ctx, "change_status", args, session_id, body)

    @server.tool(
        description=(
            "Propose your branch upstream: opens a pull request from it for a person to "
            "review and merge. Only the branch's creator may propose it. Give a short "
            "title and a body saying what changed and how it was checked. The service may "
            "refuse a branch (for example a change to CI files) and say why."
        ),
        annotations=WRITE,
        structured_output=True,
    )
    async def propose_change(
        ctx: Context, session_id: SessionId, repo: RepoArg, branch: str, title: str, body: str = ""
    ) -> dict[str, Any]:
        async def run(call: Call) -> dict[str, Any]:
            cfg = call.tenant.proposals
            r = call.check_repo(repo)
            if cfg is None:
                raise PolicyError("proposing upstream is not enabled on this server")
            name = validation.branch(branch)
            call.audit["branch"] = name
            clean_title = " ".join(title.split())
            if not clean_title or len(clean_title) > 200:
                raise PolicyError("title must be 1-200 characters")
            if len(body) > 4000:
                raise PolicyError("body must be at most 4000 characters")
            check_owner(call, r, name)
            cred = await call.credential(r)
            async with call.client(cred) as client:
                info = await call.repo_info(client, r)
                if await client.branch(r, name) is None:
                    raise PolicyError(f"branch '{name}' does not exist")
            canonical = canonical_repo(r, info)
            await call.record_attempt("propose_change", branch=name)
            return await proposals.propose(
                cfg,
                call.tenant.id,
                canonical.full_name,
                name,
                clean_title,
                body,
                transport=call.services.proposal_transport,
            )

        args = {"repo": repo, "branch": branch, "title": title, "body": body}
        return await services.call(ctx, "propose_change", args, session_id, run)

    return server
