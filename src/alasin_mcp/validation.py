# SPDX-License-Identifier: Apache-2.0
"""Strict validation of every value that ends up in a Forgejo URL.

The server holds a privileged Forgejo credential. A repository name such as
``../../admin`` or a file path with ``..`` in it must never turn a read tool
into a call on some other API route, so every segment is validated against a
narrow pattern first and percent-encoded second.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

# Forgejo user, organisation and repository names: alphanumerics, '-', '_' and
# '.', not starting with '.' or '-'.
_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
_FULL_REF = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
_SHA = re.compile(r"^[0-9a-f]{7,64}$")
_TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

MAX_PATH_LENGTH = 1024


class InvalidInput(ValueError):
    """A tool argument failed validation. The message is safe to show the model."""


@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def api_path(self) -> str:
        return f"/repos/{quote(self.owner, safe='')}/{quote(self.name, safe='')}"


def tenant_id(value: str) -> str:
    """A tenant id is also a path segment (audit files), so it is kept narrow."""
    if not _TENANT.fullmatch(value):
        raise InvalidInput(f"invalid tenant id {value!r}")
    return value


def repo(value: str) -> RepoRef:
    """Parse ``owner/name``. URLs, extra segments and dot-names are refused."""
    if not isinstance(value, str):
        raise InvalidInput("repo must be a string 'owner/name'")
    parts = value.split("/")
    if len(parts) != 2:
        raise InvalidInput(f"repo must be 'owner/name', got {value!r}")
    owner, name = parts
    for part in (owner, name):
        if not _NAME.fullmatch(part) or ".." in part or part.endswith(".git"):
            raise InvalidInput(f"invalid repository name {value!r}")
    return RepoRef(owner, name)


def branch(value: str) -> str:
    """A branch name, following git's ref-format rules (refs/heads/ is stripped)."""
    if not isinstance(value, str) or not value:
        raise InvalidInput("branch must be a non-empty string")
    if value.startswith("refs/heads/"):
        value = value[len("refs/heads/") :]
    bad = (
        not _FULL_REF.fullmatch(value)
        or value.startswith(("/", "-", "."))
        or value.endswith(("/", ".", ".lock"))
        or ".." in value
        or "//" in value
        or "/." in value
        or "@{" in value
        or value == "HEAD"
    )
    if bad:
        raise InvalidInput(f"invalid branch name {value!r}")
    return value


def ref(value: str) -> str:
    """A branch name or a commit SHA, as accepted for reads."""
    if isinstance(value, str) and _SHA.fullmatch(value):
        return value
    return branch(value)


def file_path(value: str, *, allow_root: bool = False) -> str:
    """A repository-relative path. Returns it normalised (no leading or trailing slash)."""
    if not isinstance(value, str):
        raise InvalidInput("path must be a string")
    stripped = value.strip("/")
    if not stripped:
        if allow_root:
            return ""
        raise InvalidInput("path must not be empty")
    if len(stripped) > MAX_PATH_LENGTH:
        raise InvalidInput("path is too long")
    if value.startswith("/"):
        raise InvalidInput(f"path must be relative to the repository root, got {value!r}")
    if any(c in stripped for c in ("\\", "\x00")) or any(ord(c) < 0x20 for c in stripped):
        raise InvalidInput(f"invalid path {value!r}")
    segments = stripped.split("/")
    for seg in segments:
        if seg in ("", ".", "..") or seg == ".git":
            raise InvalidInput(f"invalid path {value!r}")
    return stripped


def quote_path(path: str) -> str:
    """Percent-encode each segment of a validated path."""
    return "/".join(quote(seg, safe="") for seg in path.split("/"))
