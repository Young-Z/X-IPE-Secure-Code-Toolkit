"""Official release digests of verified tool versions: the trust root for executing a tool.

Source: Opengrep v1.31.0 GitHub release metadata (asset `digest`), checked 10-19-2026; only the
manylinux aarch64 build was executed in the tool-level validation (FEATURE-002-B).
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolBuild:
    tool: str
    version: str
    os: str
    arch: str
    libc: str | None
    asset: str
    validated: bool


def _b(os_: str, arch: str, libc: str | None, asset: str, validated: bool = False) -> ToolBuild:
    return ToolBuild("opengrep", "1.31.0", os_, arch, libc, asset, validated)


TABLE: dict[str, ToolBuild] = {
    "sha256:2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d": _b(
        "linux", "aarch64", "glibc", "opengrep_manylinux_aarch64", validated=True
    ),
    "sha256:dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147": _b(
        "linux", "x86", "glibc", "opengrep_manylinux_x86"
    ),
    "sha256:b7cbedab0b6c9953ea27ce3baa006ad8b6fa1c50ee7433638b63f7fc731519d9": _b(
        "linux", "aarch64", "musl", "opengrep_musllinux_aarch64"
    ),
    "sha256:02c9fba481611aa0664bc79ccf7ce59e9e334b76af8921c80b2f738d17fabf9b": _b(
        "linux", "x86", "musl", "opengrep_musllinux_x86"
    ),
    "sha256:035dd8fd2410fe68513916df0c2895257fffafcd5314b4a118484ce8db62bedb": _b(
        "macos", "aarch64", None, "opengrep_osx_arm64"
    ),
    "sha256:2f0d0c7a41a3e48dc02c30dabc4851bc37c18f021b46c9ae54b15177ece088ee": _b(
        "macos", "x86", None, "opengrep_osx_x86"
    ),
    "sha256:fdd2e22549e7000ceb66976a01366db6910760b2aa4e457b6bda62545070d26a": _b(
        "windows", "x86", None, "opengrep_windows_x86.exe"
    ),
}


# FEATURE-002-D: Trivy v0.76.1 official Linux binaries (statically linked: no C-library value), kept apart
# from the Opengrep table. Source: GitHub release metadata and trivy_0.76.1_checksums.txt (10-22-2026);
# binary digests from the tool-level validation (TASK-055). Only Linux arm64 was executed there. The formal
# evaluation (AC-28) is pending in FEATURE-003-C.
TRIVY: dict[str, ToolBuild] = {
    "sha256:b422130ea54e53e142e65c838662e48919ce9c3f23f17d80066b43e70550cb85": ToolBuild(
        "trivy", "0.76.1", "linux", "aarch64", None, "trivy_0.76.1_Linux-ARM64.tar.gz", True
    ),
    "sha256:d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83": ToolBuild(
        "trivy", "0.76.1", "linux", "x86", None, "trivy_0.76.1_Linux-64bit.tar.gz", False
    ),
}
TRIVY_ARCHIVES: dict[str, str] = {
    "trivy_0.76.1_Linux-ARM64.tar.gz": (
        "sha256:e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"
    ),
    "trivy_0.76.1_Linux-64bit.tar.gz": (
        "sha256:c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
    ),
}


def lookup(digest: str) -> ToolBuild | None:
    return TABLE.get(digest) or TRIVY.get(digest)


def host_platform() -> dict[str, str | None]:
    os_ = {"darwin": "macos", "win32": "windows"}.get(
        sys.platform, "linux" if sys.platform.startswith("linux") else sys.platform
    )
    machine = platform.machine().lower()
    arch = (
        "aarch64" if machine in ("aarch64", "arm64") else "x86" if machine in ("x86_64", "amd64") else machine
    )
    libc = None
    if os_ == "linux":
        libc = "glibc" if platform.libc_ver()[0] == "glibc" else "musl"
    return {"os": os_, "arch": arch, "libc": libc}


def matches(build: ToolBuild, host: dict[str, str | None]) -> bool:
    return (
        build.os == host["os"]
        and build.arch == host["arch"]
        and (build.os != "linux" or build.libc is None or build.libc == host["libc"])
    )
