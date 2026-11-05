# alasin-mcp

A remote, multi-tenant [MCP](https://modelcontextprotocol.io) server that gives AI agents
**branch-and-commit** access to a [Forgejo](https://forgejo.org) or Gitea instance.

An agent can read repositories, create a work branch and commit several files to it in
one commit. It can't merge, delete, change settings or touch secrets: a person reviews
and merges the branch. *Alasin* is Finnish for "anvil".

It's a change lane for people who can't push to the upstream (GitHub) repository
themselves. The server's instructions and tool descriptions tell a model that can push
upstream to change it there instead, and to use alasin only for reading.

- **Transport:** Streamable HTTP (stateless) at `/mcp`. People sign in through its OAuth
  front door (origo, with your OIDC provider upstream); it can also sit behind an OAuth
  gateway that forwards a bearer token, or verify JWTs from your identity provider.
- **Multi-tenant:** one deployment serves many tenants, each with its own Forgejo. The
  tenant comes only from the verified token.
- **Audited and traced:** every tool call is an OpenTelemetry span and an append-only
  audit event; commits carry a `Trace-Id` trailer.

Licence: [Apache-2.0](LICENSE).

## Tools

Every result stays well under a client's tool-result limit (claude.ai cuts at about
25k tokens). The caps are server-side and measured as JSON on the wire, where a quote,
backslash or tab takes two bytes and other control characters six. The SDK sends a
structured result twice (text and `structuredContent`), so each copy stays under about
28 KB of content and both together under 60 KB. A result that was cut says
`truncated: true`.

| Tool | Kind | What it does |
|---|---|---|
| `whoami` | read | Who the server thinks you are: subject, IdP subject, name and email, tenant, auth mode, the groups in your sign-in token (`null` if it carries none), and the tenant's repo patterns and protected branches. Needs no session. |
| `begin_change` | start | Opens a work session. Returns `session_id` (required by every other tool), the `trace_id` stamped into commits, the tenant and its repo patterns. |
| `list_repos` | read | Repositories the tenant may reach (the tenant's allowlist ∩ what the Forgejo account can see). |
| `list_branches` | read | Branches, with whether each is protected. |
| `list_folder` | read | A folder's entries at a ref (default branch by default), at most 500 and within the budget (`total_entries`, `truncated`). |
| `read_file` | read | A file at a ref; text as UTF-8, anything else as base64, in parts that fit the budget. Text: `start_line` (lines counted on `\n` only, like git and grep), `offset` (a character offset within that line, for a line longer than one part), optional `max_lines`. Binary: `offset` in bytes. The result gives `end_line`, `total_lines`, `truncated`, `next_start_line` and `next_offset`; passing those back reads on, so every file up to `max_file_bytes` reassembles exactly. |
| `diff_branch` | read | A branch's commits and a unified diff per file against the default branch (or `base`), from the merge base. At most 100 commits (their messages within a quarter of the budget), 50 files, and diffs within the rest; `commit_count`, `files_changed` and `truncated` say what was left out. |
| `create_branch` | write | A new branch from the default branch (or `from_ref`). |
| `commit_files` | write | One commit with several files (`POST /repos/{owner}/{repo}/contents`), each created or replaced in full. |
| `git_access` | write | Plain git (tenants with `[tenants.git_access]`). `access="write"` (default): one of your work branches, made for you when none is given (or checked to be yours), with a `clone_url` holding a short-lived credential, `expires_at`, the `git_config` to commit with, the `steps` to run and what each git `errors` answer means. `access="read"`: reserves and creates nothing; the URL clones and fetches any branch and never pushes. See *Plain git*. |
| `change_status` | read | Follow a branch from push to merge: its head `commit`, the `builds` reported on it (each job's `context`, `state`, `description` and log `target_url`) with an overall `build_state` (`none` and a note before any build reports), its `preview` link (tenants with `[tenants.previews]`, for branches under its prefix) and whether this commit's upload has succeeded, and its upstream `pull_request` (tenants with `[tenants.proposals]`: `state` open, closed or merged, `review`, `checks`; `available: false` with a note when the proposal service can't say). |
| `propose_change` | write | Open an upstream pull request from your own branch (tenants with `[tenants.proposals]`): a `title` (1-200 characters) and a `body` (up to 4000). Returns the `pull_request` URL, or `proposed: false` with the service's `refused` reasons. See *Proposals*. |

Not provided, by design: merging, deleting branches, files or repositories, repository
settings, administration, webhooks and Actions secrets. File deletion and renames are
not exposed either (the contents API's `delete` operation and `from_path` are never sent).

Commit messages get trailers added by the server:

```
Update the headline

Co-Authored-By: Claude <noreply@anthropic.com>
Trace-Id: 0af7651916cd43dd8448eb211c80319c
Alasin-Session: ws_7ZBUuDKkAf-wwjrEiPQ15Uz5
```

The model can't set `Trace-Id` or `Alasin-Session` itself; a message containing them is
refused.

## Plain git

For a client with a real shell and git (claude.ai's code sandbox, for one),
`git_access` turns a work branch into an ordinary git remote:

```
git clone --branch lane/change-1a2b3c4d https://x-token:<credential>@alasin.example.com/git/acme/site.git
git config user.name "Jane Doe"; git config user.email jane@example.com   # from git_config
# edit, git commit ...
git push origin lane/change-1a2b3c4d
```

- **The credential** is random (32 bytes), stored only as its SHA-256, and valid for
  `ttl_seconds` (15 minutes by default) for one person, one repository and one branch.
  It **reads the whole repository** (every branch, as clone and fetch do) by design, and
  **pushes only that branch**.
  It sits in the URL's user part, so git sends it as HTTP Basic auth and it never appears
  in a request path or an access log. When it expires, call `git_access` again and
  `git remote set-url origin <new clone_url>`.
- **Read-only access** (`access="read"`) mints a credential bound to no branch. Every
  `git-receive-pack` route answers it 403 ("read-only access: call git_access with
  access='write' to push") before anything reaches Forgejo.
- **The result is a playbook.** `steps` lists the commands in order: a shallow clone with
  a generous timeout, reading the repository's own `CLAUDE.md` / `AGENTS.md` / `README.md`
  first, committing, fetching before a push, and then `change_status` and
  `propose_change`. `errors` maps this server's 401, 403 and 429 answers and a rejected
  non-fast-forward to what to do.
- **Routes:** only git's smart HTTP under `/git/<owner>/<repo>.git/`: `info/refs`
  (exactly one `service`, `git-upload-pack` or `git-receive-pack`), `git-upload-pack`
  and `git-receive-pack`. No dumb HTTP, no LFS. The client's query string is never
  forwarded; the server builds `?service=` itself. A missing or expired credential gets
  `401` with a Basic challenge; one client address may fail 30 times a minute before it
  gets `429` (successes don't count: sandboxes share addresses).
- **Forwarding:** to the tenant's Forgejo with the tenant's service token (re-read on
  every request); the caller's credential never leaves the server. Request and response
  bodies are streamed; a push is capped at `max_push_bytes`.
- **Pushes are checked before anything reaches Forgejo.** Every ref command must update
  exactly `refs/heads/<the credential's branch>`: no other branch, no tag, no new
  branch, no deletion, no shallow or signed pushes. Capabilities are an allowlist
  (`report-status`, `report-status-v2`, `side-band-64k`, `side-band`, `quiet`, `atomic`,
  `ofs-delta`, `agent`, `object-format`, `session-id`, by name before any `=`): push
  options in particular are refused, because Forgejo applies options such as
  `repo.private` as the pusher, the service account. The branch's owner is checked again
  at every push. A refused push is
  answered in git's report-status format, so git prints
  `! [remote rejected] ... (<reason>)`. Forgejo's branch protection still decides what
  the push may change (protected file patterns, force pushes).
- **Audit:** each push writes an attempt event before it is forwarded (no audit, no
  push) and an outcome event after, also when the client disconnects early. A clone or
  fetch is recorded at its `info/refs` request, and the first `git-upload-pack` POST per
  credential each minute is recorded too, since a protocol v2 client can fetch without
  `info/refs` (one event per window, not one per negotiation round). Events carry the person's subject, the repo, the branch's
  digest and the old and new commit ids; never the credential.
- **Limits:** `requests_per_minute` per person on the proxy, and one push at a time per
  person and branch, however many credentials they hold.
- **Commit authorship inside a push is whatever the client sets.** `git_access` returns
  the signed-in person's name and email as `git_config`, the audit records who really
  pushed, and the lane's proposer re-checks a branch before anything reaches GitHub; the
  server does not rewrite or verify the author fields of pushed commits.
- **The credential passes through the model's context** (the sandbox has nowhere else to
  keep it). Its short life and narrow grant are the mitigation: it can only update that
  person's own work branch, which Forgejo's protection limits further.

Requires `auth_mode = "service_account"` and `branch_owners = true`.

## Security model

**Identity.** Every request to `/mcp` needs `Authorization: Bearer <token>`. A
`TokenVerifier` turns the token into a `Principal(tenant, subject, name, email)`. The
principal is attached to that HTTP request only; tools read it from the request that
carried their call, so concurrent requests can't see each other's identity. No tool has
a tenant, host or URL argument, and headers can't change the principal.

**Tenancy.** A `TenantResolver` maps the principal to the tenant's settings: Forgejo
base URL, auth mode, credentials and policy. The Forgejo URL comes only from there. A
repository argument is validated as `owner/name` (no URLs, no `..`) and checked against
the tenant's allowlist, so naming another tenant's repository or host reaches nothing
outside the caller's own Forgejo.

**Isolation.**

- Work sessions, stored tokens and cache entries are keyed by `(tenant, subject)`. A
  session ID presented by any other principal is "unknown".
- Stored tokens (user-delegated mode) are encrypted with AES-256-GCM under a per-tenant
  data key. Each data key is wrapped by a master key (envelope encryption). The
  associated data binds every ciphertext to its tenant and subject, so a row copied to
  another tenant or subject fails to decrypt. Swap `LocalKeyWrapper` for a KMS client by
  implementing `KeyWrapper`.
- Rate limits are per tenant. Audit files are written per tenant.
- `tests/test_cross_tenant.py` fails if a valid token for tenant A can reach tenant B's
  Forgejo, cache, session or stored token, including through B's repository or host
  named in an argument, and under concurrent interleaved calls.

**Writes.** The server refuses writes to the default branch, to branches matching
`protected_branches`, to branches outside `branch_prefix` (when set), and to existing
branches the account can't push to. This is defence in depth: Forgejo's branch
protection and **protected file patterns** are the real gate, and they apply to the
contents API too (a commit touching a protected path is rejected with 403).

**CI workflow folders.** Files under `.forgejo/`, `.gitea/` and `.github/` (any case)
are refused by default, because a forge with Actions enabled runs them, with the
repository's secrets. A tenant can opt in with `allow_ci_paths = true`, or change the
list with `ci_paths`. Protect these paths in Forgejo as well.

**Request size.** Bodies over `server.max_request_bytes` (default 8 MiB) are refused with
413 before authentication. Only HTTP is served; WebSocket connections are closed.

**Outbound requests.** Every value placed in a Forgejo URL is validated and
percent-encoded per segment. The HTTP client never follows redirects, so a token can't
be carried to another host.

**Audit.** One outcome event per tool call, success, failure or cancellation: time,
tenant, who called (`sub`, the person's Keycloak subject, for a person signed in through
the identity provider; otherwise `subject`, the static credential's or OAuth client's
configured subject), client address, tool, session ID, trace and span IDs, arguments,
outcome, result summary, repository, commit, author source and auth mode.

Audit events carry no personal data: no name, email or username, and no free text that
could hold one. Commit messages, intents, branch names, refs, file paths, error messages
and any other text are recorded as `<key>_sha256` and `<key>_chars` (an error also has a
fixed `error_kind`); author arguments only as `author_given`; author and committer not
at all (the commit records them; `commit` locates it). File contents are recorded as size
and SHA-256, not copied. A short branch name's SHA-256 can be guessed from a list of
likely names: the commit SHA, not the branch, is what locates a change.
Values a caller chooses are written only in their own narrow shape, otherwise as a digest:
`grant_type` only as one of `authorization_code`, `refresh_token`, `client_credentials`;
`client_id` only as a configured client, or on the outcome of a token origo issued for it
(an attempt or a refusal names it only as a digest: anyone can send any id); `session_id`
only as a live session of the caller's (alasin's exact `ws_` + 24-character id); `repo`, and
a result's `url`, only when the tenant's configuration names the owner (an argument's repo
always as its SHA-256); `client_ip` only as an IP address. Nested arguments and results get
the same rules.
`client_ip` is the raw address in the local file; the Muutto365 audit-log gateway replaces
every IP address with a keyed hash before the record reaches the object-locked bucket.
Authorization links and OAuth `state` never reach audit events or span status. Spans
(telemetry, not the audit trail) still carry branch, author and committer.

Sign-ins through the OAuth front door are audited too, in the same two phases. Before
origo sees a `/token` request, an *attempt* event (grant type, client ID, client address)
is written; if it can't be, the client gets 503 and no code or refresh token is spent.
After origo answers, an *outcome* event names the person the token speaks for by their
`sub` alone (`sign_in` or `token_refresh`). A token that can't be attributed is never delivered (503). If only
the outcome can't be recorded, a sign-in gets 503 (a fresh authorization fixes it) and a
refresh gets its token, logged: origo has already rotated the refresh token, so
withholding it would end the session.

Writes fail closed. Before any mutating Forgejo call (creating a branch, committing) an
*attempt* event is written; if it can't be recorded, the write isn't made. The outcome
event is written afterwards whatever happens. If only the outcome can't be recorded, the
call still returns its result, because the write has landed and an error would invite a
retry that duplicates it; the attempt event is the record. Every sink is tried; only a
failure of a required sink (the JSONL file) counts as a failure. stderr is best effort.

## Auth modes

Chosen per tenant with `auth_mode`.

| Mode | Forgejo credential | Commit author | Committer | Status |
|---|---|---|---|---|
| `service_account` | one token per tenant | the service account, or a trusted override (below) | the service account | implemented |
| `user_delegated` | Forgejo OAuth2 per person (authorization code + PKCE), stored encrypted, refreshed | the person | the person | implemented, unit-tested; not yet run against a live Forgejo OAuth app |
| `platform_scoped` | short-lived per-repository token from a `TokenMinter` you provide | the end user from the verified token | the platform bot | interface only; no minter ships |

**Service-account author override.** By default the service account authors commits.
`author_source` lets the deployer choose a trusted source for the author; the committer
stays the service account and the audit records both:

- `token_claims`: `name` and `email` from the verified inbound token (JWT verifier, or
  the OAuth front door's identity provider). The token must carry `email_verified: true`
  (origo includes the email only when the IdP verified it).
- `trusted_header`: a `Name <email>` header named by `author_header`. It is honoured only
  from callers that authenticated with an `[[auth.static]]` credential marked
  `gateway = true`; any other caller sending it is refused, and the config won't load
  without such a credential. Your gateway must set this header itself and strip any copy
  sent by clients.
- `tool_argument`: `author_name` and `author_email` tool arguments. The model controls
  these; use only when that is acceptable. Without this opt-in the arguments are refused.

**User-delegated mode.** When a person has no token yet, tools return a Forgejo
authorization link. Forgejo redirects to `/oauth/forgejo/callback`; the server exchanges
the code, then checks that the Forgejo account's `match_field` (default `email`) equals
the caller's `match_claim`. When matching on email, the caller's token must carry
`email_verified: true` and the address must be a *verified* address of the Forgejo account
(`GET /user/emails`). That check stops a link opened by someone else from binding their
Forgejo account to your subject. Refreshes are serialised per person; a refresh that
Forgejo rejects with `invalid_grant` drops the stored token, while any other failure
(an outage, for example) keeps it. Register an OAuth2 application in Forgejo with
the callback URL as its redirect URI. Requires `server.master_key_*`.

**Platform-scoped mode.** Implement `alasin_mcp.credentials.TokenMinter`:

```python
class TokenMinter(Protocol):
    async def mint(
        self, tenant: TenantConfig, principal: Principal, repo: RepoRef
    ) -> MintedToken: ...
```

and name a factory `package.module:factory` (called with the `TenantConfig`) in the
tenant's `platform.minter`. Without one, calls fail with a clear "no token minter is
configured" error. Tokens are per repository, so `list_repos` isn't available in this
mode. The author's email must be verified (`email_verified: true`).

## Branch creation

Chosen per tenant with `branch_creation`:

- `api` (default): the server's Forgejo account creates the branch.
- `webhook`: for setups where another service must create branches. The server sends
  `POST <branch_webhook.url>` with the JSON body
  `{"tenant", "repo", "branch", "from_ref", "session_id", "subject"}`, plus `owner_sub`
  when the caller signed in through the identity provider (see *OAuth sign-in*): the
  person's own subject at the IdP, for Keycloak the user ID, without origo's
  `<issuer>|` prefix. The headers:
  - `X-Alasin-Timestamp`: Unix seconds.
  - `X-Alasin-Signature`: `sha256=` followed by the hex HMAC-SHA256 of
    `"<timestamp>." + body`, keyed with the tenant's webhook secret.

  The secret is re-read on every call. After a 2xx reply the server polls Forgejo until
  the branch exists, up to `timeout_seconds`. The receiver should verify the signature
  and reject stale timestamps.

To add another strategy, implement `alasin_mcp.branching.BranchCreator` and register it
in `Services.branch_creators` under a name tenants can select.

**Branch owners.** With `branch_owners = true`, only the subject that created a branch
through this server may commit to it. Owners are kept in `server.state_path`.

- Before creating a new branch, `create_branch` *reserves* it for the caller, so a
  second person can't start the same creation. A reservation is never ownership:
  nobody, the reserver included, may commit to a branch that is only reserved. Once
  the creator answers with success, the caller is *confirmed* as the owner. If creation
  fails, the reservation is dropped. A reservation left behind by a crash expires after
  the creator's time limit plus a minute, and never counts in the meantime.
- `commit_files` refuses a branch whose confirmed owner is someone else, and a branch
  with no confirmed owner: one that is still being created, one created outside this
  server or before the setting was on, or one whose record was lost. Refusals never say
  whose a branch is.
- With `branch_creation = "webhook"`, a lost record can be restored. `create_branch` on
  an existing branch with no confirmed owner re-requests it from the receiver and
  records nothing until it answers. The receiver must answer 2xx only when `owner_sub`
  is the branch's registered owner, and refuse (409) anyone else. With `api`, keep
  `state_path` on a persistent volume, or a restart leaves every open branch unwritable
  here.

## Proposals

Where the tenant's Forgejo is a staging copy of another forge, a separate
service turns a work branch into a pull request there; this server only asks
it, signed like the branch webhook (`X-Alasin-Timestamp`,
`X-Alasin-Signature`):

- `POST <proposals.url>` with `{"tenant", "repo", "branch", "title", "body"}`,
  sent by `propose_change` for the branch's owner only. It answers **201**
  `{"pull_request", "commit", "owner_sub"}`, **422** `{"refused": [...]}`, or
  another status with `{"error"}`.
- `POST <proposals.url>/status` with `{"tenant", "repo", "branch"}`, read only,
  sent by `change_status`. It answers **200** `{"proposed": false}` or
  `{"proposed": true, "pull_request", "number", "state", "draft", "head_sha",
  "review", "checks"}`.

Every request carries a random `nonce`, so two identical requests in the
same second are still distinct for the receiver's replay check. A branch
that already has an open pull request gets **200** with that pull request
and `created: false`, because the push has already updated it. If the
answer is lost after sending, `propose_change` says to check
`change_status` before retrying. The secret must be at least 32 bytes, and
a shorter one is refused at load.

The service names the branch's owner from its own records, never from the
request. When it is down, `propose_change` fails with a message saying so,
and `change_status` still reports the build and the preview.

## Tenant resolver

```python
class TenantResolver(Protocol):
    def resolve(self, principal: Principal) -> TenantConfig:
        """Return the tenant's settings, or raise UnknownTenant."""
```

The default, `StaticTenantResolver`, serves the `[[tenants]]` from the config file. To
look tenants up elsewhere (a database, a control plane), implement the protocol and
pass it to `alasin_mcp.app.from_config(cfg, resolver=...)`. The principal's tenant comes
from the verifier; the resolver decides what that tenant may reach.

Inbound verifiers implement:

```python
class TokenVerifier(Protocol):
    async def verify(self, token: str) -> Principal | None: ...
```

Two ship: `StaticTokenVerifier` (fixed credentials, each bound to a tenant and subject,
compared by SHA-256 in constant time) and `JwtVerifier` (JWKS, issuer, audience, expiry;
the tenant from a configured claim).

## Sessions and tracing

`begin_change` mints a work-session ID; every other tool requires it. Sessions expire
after `server.session_ttl_seconds` (default 12 h).

`begin_change` always starts a new trace, which becomes the work session's trace. If the
client sent `_meta.traceparent` (MCP SEP-414), its trace is recorded as a span link, not
adopted, so a client can't choose the `Trace-Id` stamped into commits. Later tool spans
are parented into the session's trace, so one work session is one trace. Incoming traces
on later calls are linked too. The session's trace ID goes into the `Trace-Id` trailer and
every audit event.

Spans are exported over OTLP/HTTP when `telemetry.otlp_endpoint` is set; export is off
by default. Trace IDs are generated either way.

## Configuration

`ALASIN_CONFIG` names a TOML file (default `/etc/alasin/config.toml`). Secrets are never
written in it: every secret is referenced as `<name>_file` (a path) or `<name>_env` (an
environment variable name). See [`examples/config.toml`](examples/config.toml).

| Key | Default | Meaning |
|---|---|---|
| `server.host`, `server.port` | `0.0.0.0`, `8000` | Bind address. |
| `server.allowed_hosts` | `[]` | `Host` values accepted on `/mcp` (DNS-rebinding protection). Use the name your gateway uses to reach this server. Empty disables the check. |
| `server.forwarded_allow_ips` | `127.0.0.1` | Proxies whose `X-Forwarded-*` headers are trusted. |
| `server.client_ip_header` | (unset) | Header carrying the caller's address for audit events, e.g. `CF-Connecting-IP` behind cloudflared. |
| `server.client_ip_trusted_proxies` | `[]` | CIDRs of the peers whose `client_ip_header` is believed (the tunnel connector). From any other peer the header is ignored and the peer address is recorded. |
| `server.state_path` | `/var/lib/alasin/state.db` | SQLite: sessions, encrypted tokens, OAuth state. |
| `server.audit_dir` | `/var/lib/alasin/audit` | `<tenant>/audit-<date>.jsonl`, each line fsynced (and the folder, when the line creates a file) before the call goes on. This file is the record that fails closed; the copy on stderr is best effort. |
| `server.master_key_file` / `_env` | none | Base64 of 32 random bytes (`openssl rand -base64 32`). Required for `user_delegated`. |
| `server.session_ttl_seconds` | `43200` | Work-session lifetime. |
| `telemetry.otlp_endpoint` | `""` (off) | OTLP/HTTP traces endpoint. |
| `server.max_request_bytes` | 8 MiB | Largest request body, checked before authentication. |
| `[[auth.static]]` | | `token_file`/`token_env`, `tenant`, `subject`, `gateway` (may send the trusted author header). Re-read every 30 s, so rotation needs no restart; list two entries to overlap old and new. The Forgejo service token is re-read on every call. |
| `[auth.jwt]` | | `jwks_url`, `issuer`, `audience`, `algorithms`, `tenant_claim`, `subject_claim`, `name_claim`, `email_claim`, `default_tenant`. |
| `[auth.oauth]` | | The OAuth front door; see *OAuth sign-in*. `provider` (`origo`), `tenant` (a `service_account` tenant), `base_url` (default `server.public_url`; its host must be in `server.allowed_hosts`), `public_registration` (`false`; see the warning under *OAuth sign-in*), `cimd_allowed_clients` (exact https client_id URLs, e.g. claude.ai's `https://claude.ai/oauth/mcp-oauth-client-metadata`, that sign in without a pre-registered client; `/register` stays off, works with `identity_provider`), `allow_unauthenticated_consent` (`false`; the approve-only page, without an IdP), `auto_approve` (`false`; only with the previous), `token_ttl_seconds` (3600), `refresh_token_ttl_seconds` (30 days), `client_ttl_seconds`, `storage_path` (`/var/lib/alasin/oauth.db`; `""` = memory). |
| `[[auth.oauth.clients]]` | | `id`, `secret_file`/`secret_env`, `redirect_uris` (exact match). Read at start-up: a new secret needs a restart. |
| `[auth.oauth.identity_provider]` | | Per-person sign-in; see *OAuth sign-in*. `issuer` (https, exactly as in the IdP's tokens), `client_id`, `client_secret_file`/`_env` (read at start-up), `allowed_groups` (required, non-empty, exactly as emitted), `groups_claim` (`groups`; a dotted path reaches nested claims), `allowed_email_domains` (`[]`), `max_grant_age_seconds` (43200), `recheck_on_refresh` (`false`), `token_key_files` (`[]`; required with `recheck_on_refresh`: files holding 32-byte AES-256 keys, raw/hex/base64; the first seals, all open, so a key rotates by adding the new one first). |
| `ALASIN_IDP_ISSUER`, `ALASIN_IDP_CLIENT_ID`, `ALASIN_IDP_CLIENT_SECRET_FILE`, `ALASIN_IDP_ALLOWED_GROUPS`, `ALASIN_IDP_GROUPS_CLAIM`, `ALASIN_IDP_MAX_GRANT_AGE` (seconds), `ALASIN_IDP_RECHECK_ON_REFRESH` (`true`/`false`), `ALASIN_IDP_TOKEN_KEY_FILES` | | Environment variables that set the identity provider instead of the table above (never both; `[auth.oauth]` must still be in the file). `ALASIN_IDP_ALLOWED_GROUPS` and `ALASIN_IDP_TOKEN_KEY_FILES` are comma-separated. |
| `ALASIN_MANAGED_SIGNIN_ISSUER`, `ALASIN_MANAGED_SIGNIN_TENANT` | (unset) | claude.ai managed authorization; see *Managed sign-in* under *OAuth sign-in*. The issuer (https) turns it on; the tenant is optional and needs the issuer. Environment only. |
| `[[tenants]] id` | | Lowercase tenant ID. |
| `forgejo_url` | | Base URL of the tenant's Forgejo. |
| `auth_mode` | `service_account` | `service_account`, `user_delegated` or `platform_scoped`. |
| `service_token_file` / `_env` | | The service account's Forgejo token (scopes `write:repository`, `read:user`). |
| `repos` | `[]` | `owner/name` glob allowlist. Empty means none. |
| `protected_branches` | `main`, `master`, `release/*`, `releases/*` | Never written by the server. |
| `branch_prefix` | `""` | If set, work branches must start with it. |
| `author_source`, `author_header` | `service_account` | See *Auth modes*. |
| `agent_coauthor` | `Claude <noreply@anthropic.com>` | The `Co-Authored-By` trailer; empty to omit. |
| `rate_limit_per_minute` | `120` | Per tenant. |
| `max_file_bytes`, `max_commit_files`, `max_commit_bytes` | 1 MB, 50, 5 MB | Read and commit caps. |
| `[tenants.oauth]` | | `client_id`, `client_secret_file`/`_env`, `redirect_uri`, `match_claim`, `match_field`. |
| `[tenants.platform]` | | `minter`, `bot_name`, `bot_email`. |
| `allow_ci_paths`, `ci_paths` | `false`, `.forgejo/`, `.gitea/`, `.github/` | CI workflow folders; see *Security model*. |
| `branch_creation` | `api` | `api`, `webhook`, or a registered name; see *Branch creation*. |
| `[tenants.branch_webhook]` | | `url`, `secret_file`/`secret_env`, `timeout_seconds` (60), `poll_interval_seconds` (2). |
| `branch_owners` | `false` | Only a branch's creator may commit to it; see *Branch creation*. |
| `[tenants.git_access]` | off | `enabled` (`false`), `public_url` (the server's own `https://host`, as git clients reach it), `ttl_seconds` (900; 60–3600), `max_push_bytes` (100 MiB), `requests_per_minute` (60, per person). See *Plain git*. |
| `[tenants.proposals]` | off | `url` (the proposal service's endpoint), `secret_file`/`secret_env` (signs requests like the branch webhook), `timeout_seconds` (60). Needs `branch_owners`. See *Proposals*. |
| `[tenants.previews]` | off | `base_url` (`https://host/path/`; a branch `<branch_prefix><slug>` is served at `<base_url><slug>/`), `branch_prefix` (`lane/`), `upload_context` (the commit status whose success means this commit is the live preview), `repos` (owner/name patterns of the repositories that build previews; default every repository of the tenant: other repositories get no `preview` link, since a slug would point at another repository's preview). |

## OAuth sign-in

With `[auth.oauth]`, MCP clients that speak OAuth, such as claude.ai connectors, sign in
to this server directly; no gateway is needed. `provider = "origo"` runs
[origo](https://github.com/ieepirzy/origo), an OAuth 2.1 + PKCE authorization server, in
this process. Install it with the extra: `pip install 'alasin-mcp[origo]'` (the image
includes it).

- A request to `/mcp` without a valid token gets a 401 whose `WWW-Authenticate` names the
  protected-resource metadata, so the client can discover where to sign in.
- The discovery and sign-in routes (`/.well-known/...`, `/authorize`,
  `/authorize/callback`, `/token`, `/register`, `/userinfo`) are public; each checks its
  own credentials.
- Every token from the front door belongs to the one `tenant` configured, which must use
  `auth_mode = "service_account"`.
- The `oauth:` subject prefix is reserved: an `[[auth.static]]` subject using it is
  refused, and a JWT whose subject starts with it is rejected.
- The `base_url` host must be listed in `server.allowed_hosts`, so the DNS-rebinding
  check covers the host clients sign in at.

**Per-person sign-in (`[auth.oauth.identity_provider]`).** origo sends each person to
the upstream OpenID Connect provider (Keycloak, say) to sign in, and its tokens then
carry that person: origo's `sub` (`<issuer>|<IdP sub>`), the email only if the IdP
verified it, the name and the groups. The MCP client is still one pre-registered
`[[auth.oauth.clients]]` entry, such as a claude.ai connector.

- The principal's subject is `oauth:<issuer>|<IdP sub>`. Work sessions and branches
  belong to the person, not to the client. A token that names no person, or a person of
  another issuer, is refused.
- The lane gate: origo checks `allowed_groups` at sign-in, and this server checks it
  again on every write tool (`create_branch`, `commit_files`) against the groups in the
  token used. Reads stay open to anyone who signed in. A write also needs a name and a
  verified email on the token, and a principal from the identity provider: a credential
  that asserts its own groups can't write.
- With `recheck_on_refresh = true` (recommended), every refresh first refreshes at
  the IdP and re-applies `allowed_groups` to the fresh groups. A disabled account, an
  ended or revoked IdP session (Keycloak: SSO Session Idle/Max, Client Session
  Idle/Max) or a removed group ends the grant within one access-token lifetime
  (`token_ttl_seconds`), whatever the client holds; `max_grant_age_seconds` stays an
  outer cap. Grants from before it was turned on need one new sign-in.
- Without it, groups are those of the sign-in: a refresh doesn't ask the IdP, so a
  person removed at the IdP keeps access until the grant reaches
  `max_grant_age_seconds`, plus at most one access-token lifetime. MCP clients such
  as claude.ai don't re-sign-in silently once refresh is refused, so a short
  `max_grant_age_seconds` means a manual reconnect that often.
- Commits are authored by the person (their verified name and email) and committed by
  the Forgejo service account.
- The config refuses an inconsistent tenant: it needs `author_source = "token_claims"`
  and `branch_owners = true`, may have no `[[auth.static]]` credentials (they are
  shared accounts), `public_registration` can't be on (list connector platforms in
  `cimd_allowed_clients` instead), and `[auth.jwt]` can't be
  configured at all (a JWT's tenant comes from a claim, so it could reach this tenant).
- Commit messages can't carry `Co-authored-by` or `Signed-off-by` trailers (except the
  configured `agent_coauthor`, which the server adds anyway): the commit is attributed to
  the signed-in person and nobody else. This applies to every tenant.
- Register the callback `<base_url>/authorize/callback` at the IdP as the client's
  only redirect URI. For Keycloak, add a *Group Membership* mapper with *Add to ID
  token* on, and write `allowed_groups` exactly as it emits them: `/name` with *Full
  group path* on, `name` with it off.

**Managed sign-in (claude.ai managed authorization).** With
`ALASIN_MANAGED_SIGNIN_ISSUER` set, origo also accepts the RFC 7523 jwt-bearer grant
(`urn:ietf:params:oauth:grant-type:jwt-bearer`) at `/token` with an Identity Assertion
JWT Authorization Grant (ID-JAG): claude.ai connects every member of the organization
without a browser sign-in. Unset, `/token` refuses the grant (`unsupported_grant_type`)
and the metadata doesn't advertise it.

- `ALASIN_MANAGED_SIGNIN_ISSUER`: the *Issuer URL* claude.ai's managed-authorization
  page shows for "Claude-issued" (`https://identity.anthropic.com/issuers/iss_...`), one
  per organization. `ALASIN_MANAGED_SIGNIN_TENANT` (optional): the *Tenant ID* entered
  there; the assertion's `aud_tenant` must then equal it.
- It needs the identity provider and `cimd_allowed_clients` (only those clients may
  present an assertion); start-up refuses it without either, a tenant without an issuer,
  or a non-https issuer.
- The assertion only names an email. The token is for the one enabled IdP user with that
  verified email, with the same subject, groups and `allowed_groups` gate as an
  interactive sign-in; no such user means `invalid_grant`. origo looks the person up with
  the identity provider's own client (client credentials), so for Keycloak that client
  needs **Service accounts** enabled and the realm-management role **view-users**.
- Groups are emitted as names (origo's `group_paths=False`): the Keycloak group mapper's
  *Full group path* must be off, as `allowed_groups` assumes.
- No refresh token: claude.ai fetches a fresh assertion, so someone removed from the
  organization or disabled in the IdP stops within one access-token lifetime.
- Each exchange is audited as `action = "managed_sign_in"`, attempt then outcome, like a
  sign-in.

**Approve-only (no identity provider).** origo then signs in nobody: whoever opens the
authorize URL can approve, and the subject is the OAuth client, `oauth:<client id>`,
shared by everyone who signs in through it. origo refuses every authorization in this
mode unless `allow_unauthenticated_consent = true`. The setting is passed to origo
explicitly, so its `ORIGO_ALLOW_UNAUTHENTICATED_CONSENT` environment variable has no
effect here. `[[auth.static]]` and `[auth.jwt]` work beside it on the same `/mcp`.

> **Warning: `public_registration` lets anyone on the internet connect.** With it on, any
> client that can reach this server registers itself at `/register` and gets a token for
> the tenant: origo checks no user. It is refused unless the config also sets
> `public_registration_i_understand_anyone_can_connect = true`. Leave it off and list
> each client under `[[auth.oauth.clients]]`, unless something in front of this server
> (a network policy, an access proxy) already limits who can reach it.

Another OAuth or OIDC issuer can be added as a further front door (`oauth.py`): its
verifier is a `JwtVerifier` against the issuer's JWKS.

## Running

```sh
docker build -t alasin-mcp .
docker run -p 8000:8000 \
  -v ./config.toml:/etc/alasin/config.toml:ro \
  -v ./secrets:/run/secrets:ro \
  -v alasin-state:/var/lib/alasin \
  alasin-mcp
```

Behind an OAuth gateway: the gateway authenticates the user, then forwards `/mcp` to this
server with `Authorization: Bearer <the static credential>`. `/healthz` is public, as is
`/oauth/forgejo/callback` (used only by user-delegated tenants). Point `allowed_hosts` at
the host name the gateway uses for this upstream.

The Forgejo service account needs write access to the lane repositories and nothing
more: not an admin, not an organisation owner. Put branch protection on the default
branch, and protected file patterns on work branches for anything the agent must not
change.

## Development

```sh
uv sync
uv run ruff check . && uv run ruff format --check . && uv run pyright
uv run pytest tests/test_units.py tests/test_cross_tenant.py   # no Docker needed
uv run pytest tests/test_integration.py                          # starts Forgejo in Docker
```

The integration tests start a pinned Forgejo image (`tests/forgejo.py`) with a 512 MB
memory cap and tear it down afterwards. Every test has a timeout. CI sets
`ALASIN_REQUIRE_FORGEJO=1`, which turns a missing Docker into a failure instead of a skip.

Source files carry an `SPDX-License-Identifier: Apache-2.0` header
(`scripts/check_spdx.py` checks it).
