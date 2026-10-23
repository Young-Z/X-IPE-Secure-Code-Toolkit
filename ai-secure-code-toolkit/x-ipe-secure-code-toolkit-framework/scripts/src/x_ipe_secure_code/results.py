"""Result envelope shared by every command (text and JSON carry the same content)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "ai-secure-code-toolkit/result/v1"


@dataclass(frozen=True)
class Problem:
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass
class Result:
    command: str
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    problems: list[Problem] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)

    @classmethod
    def refused(cls, command: str, code: str, message: str, next_step: str | None = None,
                data: dict[str, Any] | None = None) -> Result:
        return cls(command=command, ok=False, data=data or {},
                   problems=[Problem(code, message)],
                   next_steps=[next_step] if next_step else [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "command": self.command,
            "ok": self.ok,
            "data": self.data,
            "problems": [p.to_dict() for p in self.problems],
            "next_steps": list(self.next_steps),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False, sort_keys=False)

    def to_text(self) -> str:
        lines = [f"{self.command}: {'OK' if self.ok else 'REFUSED'}"]
        lines += _render(self.data, indent=0)
        if self.problems:
            lines.append("Problems:")
            lines += [f"  - [{p.code}] {p.message}" for p in self.problems]
        if self.next_steps:
            lines.append("Next steps:")
            lines += [f"  - {step}" for step in self.next_steps]
        return "\n".join(lines)


SECTION_TITLES = {
    "notices": "!! Notices",
    "install": "Install",
    "authorization": "Authorization",
    "policies": "Policies",
    "default_preset": "Default Preset",
    "tools": "Tools",
    "host_integration": "Host integration",
    "problems": "Problems found",
}


def _render(value: Any, indent: int) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            title = SECTION_TITLES.get(key, key) if indent == 0 else key
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{title}:")
                lines += _render(item, indent + 1)
            else:
                lines.append(f"{pad}{title}: {item}")
    elif isinstance(value, list):
        if not value:
            lines.append(f"{pad}(none)")
        for item in value:
            if isinstance(item, dict):
                lines.append(f"{pad}- " + ", ".join(f"{k}: {v}" for k, v in item.items()))
            else:
                lines.append(f"{pad}- {item}")
    return lines
