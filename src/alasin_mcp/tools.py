# SPDX-License-Identifier: Apache-2.0
"""The MCP tools.

Every tool call goes through ``Services.call``, which:

1. takes the principal from the request that carried the call (never from an
   argument) and resolves the tenant from it;
2. applies the tenant's rate limit;
3. checks the work session belongs to this ``(tenant, subject)``;
4. runs the tool inside a span in the work session's trace;
5. appends one audit event, whether the call succeeded or failed.

The tool set is fixed: reads, ``create_branch`` and ``commit_files``. There
is no tool to merge, delete, change settings, administer or read secrets.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import fnmatch
import hashlib
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

import httpx
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field
from starlette.requests import Request

from . import telemetry, validation
from .audit import AuditSink, new_event
from .auth import PRINCIPAL_SCOPE_KEY, Principal
from .config import AuthMode, AuthorSource, TenantConfig
from .credentials import CredentialError, CredentialProvider, ForgejoCredential, Identity
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

RESERVED_TRAILERS = ("trace-id", "alasin-session")
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

    def check_repo(self, raw: str) -> RepoRef:
        repo = validation.repo(raw)
        self.audit["repo"] = repo.full_name
        if not repo_allowed(self.tenant, repo.full_name):
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


def repo_allowed(tenant: TenantConfig, full_name: str) -> bool:
    name = full_name.casefold()
    return any(fnmatch.fnmatchcase(name, pat.casefold()) for pat in tenant.repos)


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
            subject=principal.subject,
            principal_name=principal.name,
            principal_email=principal.email,
            tool=tool,
            session_id=session_id,
            arguments=_audit_arguments(arguments),
        )
        try:
            self.limiter.check(tenant.id, tenant.rate_limit_per_minute)
        except RateLimited as e:
            self._finish(event, None, error=str(e))
            raise ToolError(str(e)) from None
        session = None
        if session_id is not None:
            session = self.store.get_session(tenant.id, principal.subject, session_id)
            if session is None:
                msg = "unknown or expired session_id; call begin_change first"
                self._finish(event, None, error=msg)
                raise ToolError(msg)
        session_trace = (session.trace_id, session.span_id) if session else None
        attrs = {
            "alasin.tenant": tenant.id,
            "alasin.subject": principal.subject,
            "alasin.tool": tool,
            "alasin.session_id": session_id or "",
        }
        meta = ctx.request_context.meta
        with telemetry.tool_span(tool, session_trace, attrs, meta) as span:
            trace_id, span_id = telemetry.ids(span)
            event["trace_id"] = session.trace_id if session else trace_id
            event["span_id"] = span_id
            call = Call(self, principal, tenant, session, request, audit=event)
            try:
                result = await body(call)
            except (InvalidInput, PolicyError, CredentialError) as e:
                self._finish(event, span, error=str(e))
                raise ToolError(str(e)) from None
            except ForgejoError as e:
                self._finish(event, span, error=str(e))
                raise ToolError(str(e)) from None
            except httpx.HTTPError as e:
                msg = f"could not reach Forgejo: {type(e).__name__}"
                self._finish(event, span, error=msg)
                raise ToolError(msg) from None
            except Exception as e:
                self._finish(event, span, error=f"internal error: {type(e).__name__}")
                raise
            for key in ("repo", "branch", "commit", "author", "committer"):
                if key in event and event[key] is not None:
                    span.set_attribute(f"alasin.{key}", str(event[key]))
            self._finish(event, span, result=_result_summary(result))
            return result

    def _finish(
        self,
        event: dict[str, Any],
        span: Any,
        *,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        event["outcome"] = "error" if error else "ok"
        if error:
            event["error"] = error
            if span is not None:
                from opentelemetry.trace import StatusCode

                span.set_status(StatusCode.ERROR, error)
        if result is not None:
            event["result"] = result
        self.audit_sink.emit(event)


def _audit_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Arguments as recorded: file contents replaced by size and SHA-256."""
    out = dict(arguments)
    files = out.get("files")
    if isinstance(files, list):
        recorded = []
        for f in files:
            if isinstance(f, FileChange):
                data = f.content.encode()
                recorded.append(
                    {
                        "path": f.path,
                        "encoding": f.encoding,
                        "content_bytes": len(data),
                        "content_sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
        out["files"] = recorded
    return out


def _result_summary(result: dict[str, Any]) -> dict[str, Any]:
    """The result as recorded: scalars kept, large values summarised."""
    out: dict[str, Any] = {}
    for k, v in result.items():
        if isinstance(v, list):
            out[k] = {"count": len(v)}
        elif isinstance(v, str) and len(v) > 300:
            out[k] = {"chars": len(v)}
        else:
            out[k] = v
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
        author = Identity(p.name or p.subject, p.email)
    elif source is AuthorSource.TRUSTED_HEADER and call.request is not None:
        raw = call.request.headers.get(tenant.author_header)
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
        key = line.split(":", 1)[0].strip().casefold()
        if ":" in line and key in RESERVED_TRAILERS:
            raise InvalidInput(f"the server adds the '{line.split(':', 1)[0]}' trailer itself")
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
                    name = f.get("filename")
                    if not isinstance(name, str):
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
                if await client.branch(r, name) is not None:
                    raise PolicyError(f"branch '{name}' already exists")
                source = validation.ref(from_ref) if from_ref else str(info["default_branch"])
                created = await client.create_branch(r, name, source)
            sha = (created.get("commit") or {}).get("id")
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
