"""Machine-local tool registration records and the pre-execution checks against the digest table."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..atomic import atomic_write_bytes, dumps_json
from ..knowledge import store
from . import ADAPTERS, digests, safe_io

TOOLS_REL = f"{store.PRIVATE_REL}/tools"
MAX_BINARY = 512 * 1024 * 1024
REGISTER_STEP = (
    "A Maintainer registers the official binary: secure-code tools register --tool opengrep --path PATH"
)
PLATFORM_STEP = "Run on a Linux x86-64 or arm64 host, or use another method for these checks"


@dataclass(frozen=True)
class Gap:
    code: str
    reason: str
    next_step: str


def register_step(tool: str) -> str:
    return f"A Maintainer registers the official binary: secure-code tools register --tool {tool} --path PATH"


def platform_gap(tool: str, host: dict[str, str | None]) -> Gap | None:
    """Execution-platform gate of an Adapter (FEATURE-002-D); Adapters without a list refuse only Windows."""
    spec = ADAPTERS.get(tool)
    if spec is not None and spec.platforms is not None:
        if (host["os"], host["arch"]) in spec.platforms:
            return None
        reason = spec.platform_gap or "platform not supported"
        return Gap("ADAPTER_PLATFORM_UNSUPPORTED", reason, PLATFORM_STEP)
    if host["os"] == "windows":
        return Gap(
            "ADAPTER_PLATFORM_UNSUPPORTED",
            "Adapter execution is not supported on Windows in this version",
            "Run the verification on macOS or Linux, or use another method for these checks",
        )
    return None


def record_path(root: Path, tool: str) -> Path:
    rel = f"{TOOLS_REL}/{tool}.json"
    store.ensure_safe(root, rel, expect_dir=False)
    return root / rel


def inspect_binary(path: str) -> tuple[str, digests.ToolBuild | None] | Gap:
    """Digest of a binary (never executed) and its table entry."""
    p = Path(path).expanduser()
    if not p.is_absolute():
        return Gap(
            "TOOL_PATH_INVALID", f"{path} is not an absolute path", "Pass the absolute path of the binary"
        )
    try:
        digest = safe_io.hash_fd(safe_io.open_absolute_nofollow(p))
    except (OSError, safe_io.UnsafePath) as exc:
        return Gap(
            "TOOL_PATH_INVALID",
            f"{path} is not a readable regular file (no symbolic links): {exc}",
            "Pass the real binary file, not a link",
        )
    return digest, digests.lookup(digest)


def register(root: Path, tool: str, path: str, now: str) -> dict[str, Any] | Gap:
    spec = ADAPTERS.get(tool)
    if spec is not None and spec.platforms is not None:
        gap = platform_gap(tool, digests.host_platform())
        if gap is not None:
            return gap
    inspected = inspect_binary(path)
    if isinstance(inspected, Gap):
        return inspected
    digest, build = inspected
    if build is None or build.tool != tool:
        return Gap(
            "TOOL_DIGEST_UNKNOWN",
            f"{path} ({digest}) is not an official release of a verified {tool} version; "
            "nothing was executed",
            "Install an official release listed in the toolkit's verified versions, then register it",
        )
    host = digests.host_platform()
    if not digests.matches(build, host):
        return Gap(
            "TOOL_PLATFORM_MISMATCH",
            f"{build.asset} is built for another platform than this machine ({host})",
            "Install the official build for this platform",
        )
    record = {
        "tool": tool,
        "path": str(Path(path).expanduser()),
        "digest": digest,
        "version": build.version,
        "asset": build.asset,
        "platform": {"os": build.os, "arch": build.arch, "libc": build.libc},
        "host": host,
        "platform_validated": build.validated,
        "registered_at": now,
    }
    atomic_write_bytes(record_path(root, tool), dumps_json(record), private=True)
    return record


def load_record(root: Path, tool: str) -> dict[str, Any] | Gap:
    path = record_path(root, tool)
    if not path.is_file():
        reason = f"No {tool} binary is registered for this project"
        return Gap("TOOL_NOT_REGISTERED", reason, register_step(tool))
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        record = None
    if (
        not isinstance(record, dict)
        or not isinstance(record.get("path"), str)
        or not isinstance(record.get("digest"), str)
    ):
        reason = f"The {tool} registration record is not readable"
        return Gap("TOOL_RECORD_INVALID", reason, register_step(tool))
    return record


def check(
    root: Path, tool: str, stage_bin: Path | None = None
) -> tuple[dict[str, Any], digests.ToolBuild] | Gap:
    """Pre-check without executing; with `stage_bin` the binary is snapshotted there and checked."""
    host = digests.host_platform()
    gap = platform_gap(tool, host)
    if gap is not None:
        return gap
    record = load_record(root, tool)
    if isinstance(record, Gap):
        return record
    build = digests.lookup(record["digest"])
    if build is None or build.tool != tool or not digests.matches(build, host):
        return Gap(
            "TOOL_PLATFORM_MISMATCH",
            "The registered binary is not an official build for this machine",
            register_step(tool),
        )
    try:
        fd = safe_io.open_absolute_nofollow(Path(record["path"]))
        if stage_bin is None:
            digest = safe_io.hash_fd(fd)
        else:
            digest, _ = safe_io.copy_hash(fd, stage_bin, MAX_BINARY, mode=0o700)
    except (OSError, safe_io.UnsafePath, safe_io.TooLarge) as exc:
        return Gap(
            "TOOL_NOT_REGISTERED",
            f"The registered binary is missing or unreadable: {exc}",
            register_step(tool),
        )
    if digest != record["digest"]:
        return Gap(
            "TOOL_DIGEST_MISMATCH",
            "The registered binary's digest changed since registration; nothing was executed",
            register_step(tool),
        )
    return record, build
