"""Adapter contract and registry (FEATURE-002-B).

Framework scripts hold Adapters; Guard decides how to call them.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    max_time_limit: int = 1800
    # FEATURE-002-C: {"purpose", "recipient", "data", "offline_argv"} when the configured tool needs network
    network: dict | None = None
    # FEATURE-002-D: supported execution platforms as (os, arch); None = every POSIX host (Opengrep)
    platforms: tuple[tuple[str, str], ...] | None = None
    platform_gap: str | None = None


TRIVY_PLATFORM_GAP = "Trivy execution is supported only on Linux x86-64 and Linux arm64 in this version"
ADAPTERS: dict[str, AdapterSpec | None] = {
    "opengrep": AdapterSpec("opengrep"),
    "trivy": AdapterSpec("trivy", 1800, None, (("linux", "x86"), ("linux", "aarch64")), TRIVY_PLATFORM_GAP),
    "strix": None,
}


def provided() -> list[str]:
    return [name for name, spec in ADAPTERS.items() if spec is not None]


def reserved_name(value: str) -> bool:
    """Method names and finding sources that only the Adapter may record."""
    return isinstance(value, str) and value.casefold() in provided()


def reserved_id(value: str) -> bool:
    """Evidence and finding ids in the Adapter namespace (`<adapter>-…`)."""
    return isinstance(value, str) and any(value.casefold().startswith(f"{name}-") for name in provided())
