# SPDX-License-Identifier: Apache-2.0
"""A narrow Forgejo/Gitea API client: only the calls the tools need.

The base URL comes from the resolved tenant, never from a tool argument.
Redirects are not followed, so a token can't be carried to another host.
There are no methods for merging, deleting, settings, admin or secrets.
"""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

import httpx

from .validation import RepoRef, quote_path

DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
MAX_PAGES = 20


class ForgejoError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"Forgejo returned {status}: {message}")
        self.status = status
        self.message = message


class ForgejoClient:
    def __init__(
        self,
        api_base: str,
        token: str,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ):
        self._http = httpx.AsyncClient(
            base_url=api_base,
            headers={"Authorization": f"token {token}", "Accept": "application/json"},
            follow_redirects=False,
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> ForgejoClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        resp = await self._http.request(method, path, **kw)
        if resp.status_code >= 300:
            try:
                message = str(resp.json().get("message", ""))[:500]
            except ValueError:
                message = resp.text[:200]
            raise ForgejoError(resp.status_code, message or resp.reason_phrase)
        return resp

    async def _json(self, method: str, path: str, **kw: Any) -> Any:
        return (await self._request(method, path, **kw)).json()

    async def _paged(self, path: str, limit: int = 50) -> list[Any]:
        out: list[Any] = []
        for page in range(1, MAX_PAGES + 1):
            items = await self._json("GET", path, params={"page": page, "limit": limit})
            if not isinstance(items, list):
                break
            out.extend(items)
            if len(items) < limit:
                break
        return out

    # -- reads ---------------------------------------------------------------------

    async def current_user(self) -> dict[str, Any]:
        return await self._json("GET", "/user")

    async def user_repos(self) -> list[dict[str, Any]]:
        return await self._paged("/user/repos")

    async def repo(self, r: RepoRef) -> dict[str, Any]:
        return await self._json("GET", r.api_path)

    async def branches(self, r: RepoRef) -> list[dict[str, Any]]:
        return await self._paged(f"{r.api_path}/branches")

    async def branch(self, r: RepoRef, name: str) -> dict[str, Any] | None:
        try:
            return await self._json("GET", f"{r.api_path}/branches/{quote(name, safe='')}")
        except ForgejoError as e:
            if e.status == 404:
                return None
            raise

    async def contents(self, r: RepoRef, path: str, ref: str | None) -> Any:
        """A file's metadata and base64 content, or a folder listing."""
        url = f"{r.api_path}/contents/{quote_path(path)}" if path else f"{r.api_path}/contents"
        params = {"ref": ref} if ref else None
        return await self._json("GET", url, params=params)

    async def raw(self, r: RepoRef, path: str, ref: str) -> bytes | None:
        try:
            resp = await self._request(
                "GET", f"{r.api_path}/raw/{quote_path(path)}", params={"ref": ref}
            )
        except ForgejoError as e:
            if e.status == 404:
                return None
            raise
        return resp.content

    async def compare(self, r: RepoRef, base: str, head: str) -> dict[str, Any]:
        basehead = quote(f"{base}...{head}", safe=".")
        return await self._json("GET", f"{r.api_path}/compare/{basehead}")

    # -- writes (branch creation and commits only) -----------------------------------

    async def create_branch(self, r: RepoRef, name: str, from_ref: str) -> dict[str, Any]:
        return await self._json(
            "POST",
            f"{r.api_path}/branches",
            json={"new_branch_name": name, "old_ref_name": from_ref},
        )

    async def change_files(
        self,
        r: RepoRef,
        branch: str,
        message: str,
        files: list[dict[str, Any]],
        author: dict[str, str] | None,
        committer: dict[str, str] | None,
    ) -> dict[str, Any]:
        """One commit with several files (POST /repos/{o}/{r}/contents).

        Only ``create`` and ``update`` operations are ever sent; callers can't
        pass ``delete`` or ``from_path`` (a rename) through this method.
        """
        ops = []
        for f in files:
            if f["operation"] not in ("create", "update"):
                raise ValueError("only create and update operations are allowed")
            op = {
                "operation": f["operation"],
                "path": f["path"],
                "content": base64.b64encode(f["content"]).decode(),
            }
            if f["operation"] == "update":
                op["sha"] = f["sha"]
            ops.append(op)
        body: dict[str, Any] = {"branch": branch, "message": message, "files": ops}
        if author:
            body["author"] = author
        if committer:
            body["committer"] = committer
        return await self._json("POST", f"{r.api_path}/contents", json=body)
