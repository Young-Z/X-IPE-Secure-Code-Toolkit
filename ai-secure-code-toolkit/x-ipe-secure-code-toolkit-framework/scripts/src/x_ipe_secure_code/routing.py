"""The single routing definition of the toolkit's host integration (FEATURE-003-B).

One toolkit-owned data file inside the installed Framework skill holds the routing statements; every
carrier (host entry fragment, GitHub instructions, system-prompt fragment) is rendered from it.
Rendering is deterministic and holds only routing statements, skill pointers and the status command.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .environments import Profile
from .guard.mask import mask_text
from .payload import SKILL_NAMES

DEFINITION_REL = "x-ipe-secure-code-toolkit-framework/references/routing-definition.json"
SCHEMA = "ai-secure-code-toolkit/routing-definition/v1"
MAX_BYTES = 65536
KEYS = {"schema", "title", "declaration", "skills", "sections", "status_command"}
SECTION_IDS = ("copilot", "guard", "deduplication", "results", "roles", "handoff")
KINDS = ("host-entry", "github-instructions", "system-prompt")
PLACEHOLDER = "{skills_dir}"
ABS_PATH = re.compile(r"(^|[\s`(])(/[^\s/]|~/|[A-Za-z]:\\)")


class RoutingError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _invalid(reason: str) -> RoutingError:
    return RoutingError("ROUTING_DEFINITION_INVALID", f"routing definition invalid: {reason}")


@dataclass(frozen=True)
class RoutingDefinition:
    obj: dict[str, Any]
    digest: str


@dataclass(frozen=True)
class RoutingIdentity:
    toolkit_version: str
    definition_sha256: str

    def display(self) -> str:
        return f"ai-secure-code-toolkit {self.toolkit_version}, definition sha256:{self.definition_sha256}"

    def to_dict(self) -> dict[str, str]:
        return {"toolkit_version": self.toolkit_version, "definition_sha256": self.definition_sha256}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> RoutingIdentity:
        return cls(data["toolkit_version"], data["definition_sha256"])


def digest(obj: dict[str, Any]) -> str:
    canonical = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_string(value: Any, where: str, *, placeholder: bool = False) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 500:
        raise _invalid(f"{where} must be a string of 1 to 500 characters")
    if "\n" in value or "\r" in value:
        raise _invalid(f"{where} contains a line break")
    if "<!--" in value or "-->" in value or value.strip() == "---":
        raise _invalid(f"{where} contains a marker or front-matter token")
    bare = value.replace(PLACEHOLDER, "") if placeholder else value
    if "{" in bare or "}" in bare:
        raise _invalid(f"{where} contains a template brace")
    if ABS_PATH.search(value.replace(PLACEHOLDER, "skills") if placeholder else value):
        raise _invalid(f"{where} contains an absolute path")
    if mask_text(value)[0] != value:
        raise _invalid(f"{where} contains credential-like text")


def validate(obj: Any) -> None:
    """Raise RoutingError unless `obj` is a valid v1 routing definition."""
    if not isinstance(obj, dict):
        raise _invalid("not a JSON object")
    if set(obj) != KEYS:
        raise _invalid(f"keys must be exactly {sorted(KEYS)}")
    if obj["schema"] != SCHEMA:
        raise _invalid(f"schema must be {SCHEMA}")
    _check_string(obj["title"], "title")
    _check_string(obj["declaration"], "declaration")
    skills = obj["skills"]
    if not isinstance(skills, list) or sorted(_name(s) for s in skills) != sorted(SKILL_NAMES):
        raise _invalid(f"skills must list each of {', '.join(SKILL_NAMES)} exactly once")
    for skill in skills:
        if set(skill) != {"name", "pointer"}:
            raise _invalid("each skill has exactly 'name' and 'pointer'")
        _check_string(skill["pointer"], f"pointer of {skill['name']}")
    sections = obj["sections"]
    if not isinstance(sections, list) or sorted(_id(s) for s in sections) != sorted(SECTION_IDS):
        raise _invalid(f"sections must hold {', '.join(SECTION_IDS)} exactly once each")
    for section in sections:
        if set(section) != {"id", "heading", "statements"}:
            raise _invalid("each section has exactly 'id', 'heading' and 'statements'")
        _check_string(section["heading"], f"heading of {section['id']}")
        statements = section["statements"]
        if not isinstance(statements, list) or not 1 <= len(statements) <= 20:
            raise _invalid(f"section {section['id']} needs 1 to 20 statements")
        for index, statement in enumerate(statements):
            _check_string(statement, f"statement {index + 1} of {section['id']}")
    _check_string(obj["status_command"], "status_command", placeholder=True)
    if "secure-code status" not in obj["status_command"]:
        raise _invalid("status_command must run 'secure-code status'")


def _name(skill: Any) -> str:
    return skill.get("name", "") if isinstance(skill, dict) and isinstance(skill.get("name"), str) else ""


def _id(section: Any) -> str:
    return section.get("id", "") if isinstance(section, dict) and isinstance(section.get("id"), str) else ""


def parse(data: bytes) -> RoutingDefinition:
    if len(data) > MAX_BYTES:
        raise _invalid(f"larger than {MAX_BYTES} bytes")
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _invalid(f"not UTF-8 JSON ({exc.__class__.__name__})") from None
    validate(obj)
    return RoutingDefinition(obj, digest(obj))


def load_file(path: Path) -> RoutingDefinition:
    """Read a definition file without following a symbolic link (bounded read)."""
    if path.is_symlink() or not path.is_file():
        raise _invalid(f"{path.name} is missing or not a regular file")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        raise _invalid(f"{path.name} unreadable: {exc.strerror or exc}") from None
    return parse(data)


def carrier_line(profile: Profile, kind: str, host: str | None) -> str:
    if kind == "host-entry":
        return f"Integration carrier: host entry (`{profile.host_entry}`)."
    if kind == "github-instructions":
        return "Integration carrier: GitHub instructions."
    return f'Integration carrier: system-prompt fragment for host "{host}".'


def render(
    defn: RoutingDefinition, identity: RoutingIdentity, profile: Profile, kind: str, host: str | None = None
) -> str:
    """The carrier body (LF newlines) for one carrier kind; no time or machine-specific text."""
    obj = defn.obj
    skills_dir = profile.skills_dir
    lines = [
        f"## {obj['title']}",
        "",
        f"{carrier_line(profile, kind, host)} Routing identity: {identity.display()}.",
        obj["declaration"],
        "",
        f"This project uses the AI secure-code toolkit skills in `{skills_dir}/`:",
        "",
    ]
    lines += [f"- `{skill['name']}`: {skill['pointer']}" for skill in obj["skills"]]
    by_id = {section["id"]: section for section in obj["sections"]}
    for section_id in SECTION_IDS:
        section = by_id[section_id]
        lines += ["", f"### {section['heading']}", ""]
        lines += [f"- {statement}" for statement in section["statements"]]
    lines += ["", "Check status: `" + obj["status_command"].replace(PLACEHOLDER, skills_dir) + "`"]
    return "\n".join(lines) + "\n"
