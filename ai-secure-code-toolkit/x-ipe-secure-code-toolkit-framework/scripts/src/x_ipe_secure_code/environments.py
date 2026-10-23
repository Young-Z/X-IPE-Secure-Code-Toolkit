"""Agent environment profiles. The calling agent passes its environment explicitly."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    skills_dir: str
    host_entry: str
    verified_host: bool


PROFILES: dict[str, Profile] = {
    "github-copilot": Profile("github-copilot", ".github/skills", "AGENTS.md", True),
    "claude-code": Profile("claude-code", ".claude/skills", "CLAUDE.md", False),
}


class EnvError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def lookup(name: str | None) -> Profile:
    supported = ", ".join(PROFILES)
    if not name:
        raise EnvError("ENV_REQUIRED", f"No environment given; supported: {supported}")
    if name not in PROFILES:
        raise EnvError("ENV_UNSUPPORTED", f"Unsupported environment '{name}'; supported: {supported}")
    return PROFILES[name]
