# SPDX-License-Identifier: Apache-2.0
"""A real Forgejo in Docker for the integration tests.

The image is pinned by digest. Every step is bounded: the container has a
memory cap, every docker and HTTP call has a timeout, and start-up gives up
after ``STARTUP_TIMEOUT`` seconds.

Set ``ALASIN_REQUIRE_FORGEJO=1`` (CI does) to make a missing Docker fail the
run instead of skipping the integration tests.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass

import httpx
import pytest

IMAGE = (
    "codeberg.org/forgejo/forgejo:16.0.6-rootless"
    "@sha256:51b47921660e1ec7127f094208fe06901ba57df4fe6d59fcccc3a2419514a77f"
)
STARTUP_TIMEOUT = 120
DOCKER_TIMEOUT = 180


@dataclass
class Forgejo:
    port: int
    admin_token: str
    bot_token: str
    bot_login: str
    bot_email: str

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def alt_url(self) -> str:
        """The same instance under another host name, for a second tenant."""
        return f"http://localhost:{self.port}"


def _docker(*args: str, timeout: float = DOCKER_TIMEOUT) -> str:
    out = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=True
    )
    return out.stdout.strip()


def _unavailable(reason: str) -> None:
    if os.environ.get("ALASIN_REQUIRE_FORGEJO") == "1":
        pytest.fail(f"Forgejo integration tests are required but can't run: {reason}")
    pytest.skip(reason)


def start() -> tuple[str, Forgejo]:
    if shutil.which("docker") is None:
        _unavailable("docker is not installed")
    try:
        _docker("info", timeout=20)
    except (subprocess.SubprocessError, OSError) as e:
        _unavailable(f"docker is not usable: {e}")
    name = f"alasin-test-{secrets.token_hex(4)}"
    _docker(
        "run", "-d", "--rm", "--name", name, "--memory", "512m",
        "-p", "127.0.0.1::3000",
        "-e", "FORGEJO__security__INSTALL_LOCK=true",
        "-e", "FORGEJO__database__DB_TYPE=sqlite3",
        "-e", "FORGEJO__service__DISABLE_REGISTRATION=true",
        IMAGE,
    )  # fmt: skip
    try:
        port = int(_docker("port", name, "3000/tcp").splitlines()[0].rsplit(":", 1)[1])
        base = f"http://127.0.0.1:{port}/api/v1"
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while True:
            try:
                if httpx.get(f"{base}/version", timeout=3).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("Forgejo did not start in time")
            time.sleep(1)
        return name, _bootstrap(name, base, port)
    except BaseException:
        stop(name)
        raise


def stop(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60, check=False)


def _bootstrap(name: str, base: str, port: int) -> Forgejo:
    admin_pw = "Adm1n-" + secrets.token_hex(8)
    _docker(
        "exec", name, "forgejo", "admin", "user", "create", "--admin",
        "--username", "root", "--password", admin_pw, "--email", "root@example.com",
        "--must-change-password=false",
    )  # fmt: skip
    with httpx.Client(base_url=base, timeout=20) as http:

        def ok(resp: httpx.Response) -> httpx.Response:
            if resp.status_code >= 300:
                raise RuntimeError(f"{resp.request.method} {resp.request.url}: {resp.text}")
            return resp

        admin_token = ok(
            http.post(
                "/users/root/tokens",
                auth=("root", admin_pw),
                json={"name": "admin", "scopes": ["all"]},
            )
        ).json()["sha1"]
        h = {"Authorization": f"token {admin_token}"}
        bot_pw = "B0t-" + secrets.token_hex(8)
        ok(
            http.post(
                "/admin/users",
                headers=h,
                json={
                    "username": "alasin-bot",
                    "email": "alasin-bot@example.com",
                    "full_name": "Alasin Bot",
                    "password": bot_pw,
                    "must_change_password": False,
                },
            )
        )
        bot_token = ok(
            http.post(
                "/users/alasin-bot/tokens",
                auth=("alasin-bot", bot_pw),
                json={"name": "alasin", "scopes": ["write:repository", "read:user"]},
            )
        ).json()["sha1"]
        ok(http.post("/orgs", headers=h, json={"username": "acme"}))
        for repo in ("site", "other"):
            ok(
                http.post(
                    "/orgs/acme/repos",
                    headers=h,
                    json={"name": repo, "auto_init": True, "default_branch": "main"},
                )
            )
            ok(
                http.put(
                    f"/repos/acme/{repo}/collaborators/alasin-bot",
                    headers=h,
                    json={"permission": "write"},
                )
            )
        # A repository the bot can't see at all (tenant B's, in the isolation test).
        ok(
            http.post(
                "/user/repos",
                headers=h,
                json={
                    "name": "private",
                    "auto_init": True,
                    "default_branch": "main",
                    "private": True,
                },
            )
        )
        ok(
            http.post(
                "/repos/acme/site/contents",
                headers=h,
                json={
                    "branch": "main",
                    "message": "seed",
                    "files": [
                        {
                            "operation": "create",
                            "path": "index.html",
                            "content": _b64("<h1>Hi</h1>\n"),
                        },
                        {"operation": "create", "path": "css/site.css", "content": _b64("a{}\n")},
                    ],
                },
            )
        )
        ok(
            http.post(
                "/repos/acme/site/branch_protections",
                headers=h,
                json={"rule_name": "main", "enable_push": False},
            )
        )
        ok(
            http.post(
                "/repos/acme/site/branch_protections",
                headers=h,
                json={
                    "rule_name": "lane/*",
                    "enable_push": True,
                    "protected_file_patterns": "schema/**;*.sql",
                },
            )
        )
        # An existing protected work branch the server must refuse to write.
        ok(
            http.post(
                "/repos/acme/site/branches",
                headers=h,
                json={"new_branch_name": "frozen", "old_ref_name": "main"},
            )
        )
        ok(
            http.post(
                "/repos/acme/site/branch_protections",
                headers=h,
                json={"rule_name": "frozen", "enable_push": False},
            )
        )
    return Forgejo(port, admin_token, bot_token, "alasin-bot", "alasin-bot@example.com")


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode()).decode()
