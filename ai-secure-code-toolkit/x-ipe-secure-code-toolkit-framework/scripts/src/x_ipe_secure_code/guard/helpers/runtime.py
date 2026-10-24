"""Docker/Podman-compatible CLI adapter (FEATURE-002-F design §8.1).

The toolkit never installs, configures, pulls or builds: only the subcommands in `ALLOWED` are ever
issued, every call runs without a shell under a deadline with capped output, the environment is
sanitized (no DOCKER_HOST/CONTEXT, no host variables) and Docker calls are pinned to a local unix-socket
endpoint read from the active context.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ...adapters import process
from ..mask import mask_text

ALLOWED = {
    ("context", "inspect"),
    ("version",),
    ("info",),
    ("image", "inspect"),
    ("volume", "create"),
    ("volume", "inspect"),
    ("volume", "ls"),
    ("volume", "rm"),
    ("ps",),
    ("create",),
    ("inspect",),
    ("start",),
    ("kill",),
    ("rm",),
    ("cp",),
}
NEVER = {"pull", "build", "load", "import", "login", "push", "run", "system", "machine", "network", "plugin"}
CALL_TIMEOUT = 30.0
CALL_CAP = 4 * 1024 * 1024
STOP_POLL = 10.0


class RuntimeGap(Exception):
    """The runtime cannot be used; `code` is the refusal/reason code, `reason` the masked explanation."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code, self.reason = code, reason


def _tail(text: str) -> str:
    return mask_text(text.strip()[-300:])[0]


class CliRuntime:
    """One discovered runtime CLI bound to its local endpoint."""

    def __init__(self, cli: str, kind: str) -> None:
        self.cli, self.kind = cli, kind
        self.endpoint: str | None = None
        self.calls: list[list[str]] = []

    # ----------------------------------------------------------------- discovery
    @classmethod
    def discover(cls) -> CliRuntime:
        if os.name != "posix":
            raise RuntimeGap(
                "HELPER_PLATFORM_UNSUPPORTED", "helper execution needs a POSIX host in this version"
            )
        for kind in ("docker", "podman"):
            path = shutil.which(kind)
            if path:
                found = cls(os.path.realpath(path), kind)
                found.resolve_endpoint()
                return found
        raise RuntimeGap("HELPER_RUNTIME_UNAVAILABLE", "no container runtime CLI")

    def env(self) -> dict[str, str]:
        env = {"PATH": f"{os.defpath}:{os.path.dirname(self.cli)}", "LANG": "C"}
        if os.environ.get("HOME"):
            env["HOME"] = os.environ["HOME"]
        if os.environ.get("XDG_RUNTIME_DIR"):
            env["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
        return env

    def resolve_endpoint(self) -> None:
        if self.kind == "docker":
            doc = self.json(["context", "inspect"])
            try:
                host = doc[0]["Endpoints"]["docker"]["Host"]
            except (TypeError, KeyError, IndexError):
                raise RuntimeGap("HELPER_RUNTIME_UNAVAILABLE", "runtime context has no endpoint") from None
            path = host[len("unix://") :] if isinstance(host, str) and host.startswith("unix://") else None
            try:
                local = path is not None and stat.S_ISSOCK(os.stat(path).st_mode)
            except OSError:
                local = False
            if not local:
                raise RuntimeGap("HELPER_RUNTIME_UNAVAILABLE", "runtime endpoint is not a local socket")
            self.endpoint = host
            return
        info = self.json(["info", "--format", "json"])
        if (info.get("host") or {}).get("serviceIsRemote") not in (False, None):
            raise RuntimeGap("HELPER_RUNTIME_UNAVAILABLE", "runtime endpoint is not a local socket")

    # ----------------------------------------------------------------- calls
    def argv(self, args: list[str]) -> list[str]:
        key = tuple(args[:2]) if args[0] in ("context", "image", "volume") else (args[0],)
        if key not in ALLOWED or args[0] in NEVER:
            raise ValueError(f"runtime subcommand not allowed: {args[:2]}")
        if args[0] == "create" and "--pull=never" not in args:
            raise ValueError("create without --pull=never")
        if args[0] == "cp" and any(a in ("-L", "--follow-link") for a in args):
            raise ValueError("cp may never follow links")
        prefix = ["-H", self.endpoint] if self.kind == "docker" and self.endpoint else []
        return [self.cli, *prefix, *args]

    def call(
        self,
        args: list[str],
        *,
        timeout: float = CALL_TIMEOUT,
        cap: int = CALL_CAP,
        should_stop: Callable[[], bool] | None = None,
        stderr_sink: Callable[[bytes], None] | None = None,
    ) -> process.ProcessOutcome:
        argv = self.argv(args)
        self.calls.append(argv)
        return process.run(
            argv, Path("/"), self.env(), time.monotonic() + timeout, None, cap, should_stop, stderr_sink
        )

    def ok(self, args: list[str], **kw: Any) -> process.ProcessOutcome:
        out = self.call(args, **kw)
        if out.exit != 0:
            raise RuntimeGap(
                "HELPER_RUNTIME_UNAVAILABLE",
                f"runtime command {' '.join(args[:2])} failed (exit {out.exit}): {_tail(out.stderr_tail)}",
            )
        return out

    def json(self, args: list[str], **kw: Any) -> Any:
        out = self.ok(args, **kw)
        try:
            return json.loads((out.stdout or b"").decode("utf-8"))
        except (UnicodeError, ValueError):
            raise RuntimeGap(
                "HELPER_RUNTIME_UNAVAILABLE", f"unreadable runtime answer to {args[0]}"
            ) from None

    def lines(self, args: list[str]) -> list[dict[str, Any]]:
        out = self.ok(args)
        rows = []
        for line in (out.stdout or b"").decode("utf-8", "replace").splitlines():
            if line.strip():
                try:
                    row = json.loads(line)
                except ValueError:
                    raise RuntimeGap("HELPER_RUNTIME_UNAVAILABLE", "unreadable runtime listing") from None
                if isinstance(row, dict):
                    rows.append(row)
        return rows

    # ----------------------------------------------------------------- identity and objects
    def identity(self) -> dict[str, Any]:
        fmt = ["--format", "{{json .}}"] if self.kind == "docker" else ["--format", "json"]
        version = self.json(["version", *fmt])
        info = self.json(["info", *fmt])
        if not isinstance(version, dict) or not isinstance(info, dict):
            raise RuntimeGap("HELPER_RUNTIME_UNAVAILABLE", "unreadable runtime identity")
        client, server = version.get("Client") or {}, version.get("Server") or {}
        options = [str(o) for o in info.get("SecurityOptions") or []]
        with open(self.cli, "rb") as handle:
            cli_sha = "sha256:" + hashlib.file_digest(handle, "sha256").hexdigest()
        return {
            "kind": self.kind,
            "cli_path": self.cli,
            "cli_sha256": cli_sha,
            "client_version": client.get("Version"),
            "endpoint": self.endpoint,
            "server_version": server.get("Version"),
            "api_version": server.get("ApiVersion"),
            "server_id": info.get("ID"),
            "os": info.get("OSType") or info.get("OperatingSystem"),
            "arch": info.get("Architecture"),
            "rootless": any("rootless" in o for o in options),
            "userns": next((o for o in options if "userns" in o), ""),
            "cgroup_version": str(info.get("CgroupVersion") or ""),
            "security_options": sorted(options),
        }

    def image(self, ref: str) -> dict[str, Any] | None:
        out = self.call(["image", "inspect", ref])
        if out.exit != 0:
            return None
        try:
            doc = json.loads((out.stdout or b"").decode("utf-8"))
        except (UnicodeError, ValueError):
            raise RuntimeGap("HELPER_RUNTIME_UNAVAILABLE", "unreadable image inspect answer") from None
        return doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else None

    def inspect(self, name: str) -> dict[str, Any] | None:
        out = self.call(["inspect", "--type", "container", name])
        if out.exit != 0:
            return None
        try:
            doc = json.loads((out.stdout or b"").decode("utf-8"))
        except (UnicodeError, ValueError):
            return None
        return doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else None

    def volume(self, name: str) -> dict[str, Any] | None:
        out = self.call(["volume", "inspect", name])
        if out.exit != 0:
            return None
        try:
            doc = json.loads((out.stdout or b"").decode("utf-8"))
        except (UnicodeError, ValueError):
            return None
        return doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else None

    def remove(self, containers: list[str], volume: str | None) -> bool:
        """Kill/remove owned objects and verify they are gone (True = runtime reports every object gone)."""
        for name in containers:
            self.call(["kill", name])
            self.call(["rm", "-f", name])
        if volume:
            self.call(["volume", "rm", "-f", volume])
        end = time.monotonic() + STOP_POLL
        while True:
            left = [n for n in containers if self.inspect(n) is not None]
            vol_left = bool(volume) and self.volume(volume) is not None
            if not left and not vol_left:
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(0.2)

    def wait_stopped(self, name: str, wait: float = STOP_POLL) -> bool:
        end = time.monotonic() + wait
        while True:
            doc = self.inspect(name)
            if doc is None or not (doc.get("State") or {}).get("Running"):
                return doc is not None
            if time.monotonic() >= end:
                return False
            time.sleep(0.2)

    def labelled(self, label: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        """Containers and volumes carrying `label` (each with its parsed labels)."""
        fmt = ["--format", "{{json .}}"] if self.kind == "docker" else ["--format", "json"]
        containers = self.lines(["ps", "-a", "--filter", f"label={label}", *fmt])
        volumes = self.lines(["volume", "ls", "--filter", f"label={label}", *fmt])

        def parsed(row: dict[str, Any], key: str) -> dict[str, str]:
            raw = row.get("Labels") or ""
            labels = (
                raw
                if isinstance(raw, dict)
                else dict(p.split("=", 1) for p in str(raw).split(",") if "=" in p)
            )
            name = row.get(key) or ""
            return {
                "name": name[0] if isinstance(name, list) else str(name),
                **{f"label:{k}": v for k, v in labels.items()},
            }

        return [parsed(r, "Names") for r in containers], [parsed(r, "Name") for r in volumes]
