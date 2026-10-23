"""Install record: what project initialization placed, with per-file SHA-256.

FEATURE-003-B adds one optional, defaulted `carriers` member under the same v1 schema. It is omitted
while no optional carrier was selected and no customization accepted, so such records are byte-equal
to what FEATURE-001-A writes. Toolkit versions without the member refuse an extended record.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .atomic import atomic_write_bytes, dumps_json
from .paths import unsafe_component

RECORD_REL = ".x-ipe/private/secure-code/install-record.json"
SCHEMA = "ai-secure-code-toolkit/install-record/v1"
CARRIER_KINDS = ("host-entry", "github-instructions", "system-prompt")
CARRIER_PATHS = {"github-instructions": ".github/instructions/x-ipe-secure-code-toolkit.instructions.md",
                 "system-prompt": ".x-ipe/private/secure-code/carriers/system-prompt.md"}
HOST_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
DIGEST = re.compile(r"[0-9a-f]{64}")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class RecordError(Exception):
    def __init__(self, message: str, code: str = "RECORD_INVALID") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class InstallRecord:
    toolkit_version: str
    environment: str
    skills_dir: str
    host_entry: str
    fragment_sha256: str | None
    initialized_at: str
    updated_at: str
    files: dict[str, str] = field(default_factory=dict)
    carriers: dict[str, Any] | None = None  # FEATURE-003-B: optional, defaulted

    def to_dict(self) -> dict[str, Any]:
        data = {"schema": SCHEMA, **asdict(self)}
        if not self.carriers:
            data.pop("carriers")  # omitted when unused: FEATURE-001-A bytes
        return data

    def comparable(self) -> dict[str, Any]:
        """init's rewrite decision (the carriers member excluded: plain init stays a no-op)."""
        data = self.to_dict()
        data.pop("updated_at")
        data.pop("carriers", None)
        return data

    def full_comparable(self) -> dict[str, Any]:
        """The carriers operation's rewrite decision."""
        data = self.to_dict()
        data.pop("updated_at")
        return data


def _digest_or_none(value: Any, where: str) -> None:
    if value is not None and not (isinstance(value, str) and DIGEST.fullmatch(value)):
        raise RecordError(f"install record carriers member invalid: {where} is not a SHA-256 digest")


def _routing(value: Any, where: str) -> None:
    if (not isinstance(value, dict) or set(value) != {"toolkit_version", "definition_sha256"}
            or not isinstance(value["toolkit_version"], str) or not value["toolkit_version"]):
        raise RecordError(f"install record carriers member invalid: {where} routing identity")
    _digest_or_none(value["definition_sha256"], f"{where} definition digest")
    if value["definition_sha256"] is None:
        raise RecordError(f"install record carriers member invalid: {where} definition digest missing")


def _accepted(value: Any, kind: str) -> None:
    allowed = {"fragment_sha256", "routing", "accepted_at"}
    if kind == "github-instructions":
        allowed.add("front_matter_sha256")
    required = {"fragment_sha256", "routing", "accepted_at"}
    if not isinstance(value, dict) or not required <= set(value) <= allowed:
        raise RecordError(f"install record carriers member invalid: {kind} acceptance keys")
    _digest_or_none(value["fragment_sha256"], f"{kind} accepted digest")
    if value["fragment_sha256"] is None:
        raise RecordError(f"install record carriers member invalid: {kind} accepted digest missing")
    _routing(value["routing"], f"{kind} accepted")
    if not isinstance(value["accepted_at"], str) or not TIMESTAMP.fullmatch(value["accepted_at"]):
        raise RecordError(f"install record carriers member invalid: {kind} accepted_at")
    if "front_matter_sha256" in value:
        _digest_or_none(value["front_matter_sha256"], f"{kind} accepted front matter digest")


def validate_carriers(member: Any) -> None:
    """Strict validation of the optional member; any defect makes the whole record invalid."""
    if member is None:
        return
    if not isinstance(member, dict) or set(member) != {"selected", "entries"}:
        raise RecordError("install record carriers member invalid: keys must be 'selected' and 'entries'")
    selected, entries = member["selected"], member["entries"]
    if (not isinstance(selected, list) or len(set(map(str, selected))) != len(selected)
            or not all(kind in CARRIER_KINDS for kind in selected) or "host-entry" not in selected):
        raise RecordError("install record carriers member invalid: selection")
    if not isinstance(entries, dict) or not all(kind in CARRIER_KINDS for kind in entries):
        raise RecordError("install record carriers member invalid: entries")
    for kind, entry in entries.items():
        if not isinstance(entry, dict):
            raise RecordError(f"install record carriers member invalid: {kind} entry")
        if kind == "host-entry":
            if set(entry) != {"accepted"}:
                raise RecordError("install record carriers member invalid: host-entry holds only 'accepted'")
            _accepted(entry["accepted"], kind)
            continue
        keys = {"path", "fragment_sha256", "routing"} | ({"host"} if kind == "system-prompt" else set())
        if not keys <= set(entry) <= keys | {"accepted"}:
            raise RecordError(f"install record carriers member invalid: {kind} entry keys")
        if entry["path"] != CARRIER_PATHS[kind]:
            raise RecordError(f"install record carriers member invalid: {kind} path")
        _digest_or_none(entry["fragment_sha256"], f"{kind} digest")
        _routing(entry["routing"], kind)
        host = entry.get("host")
        if kind == "system-prompt" and not (isinstance(host, str) and HOST_NAME.fullmatch(host)):
            raise RecordError("install record carriers member invalid: system-prompt host")
        if "accepted" in entry:
            _accepted(entry["accepted"], kind)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(root: Path) -> InstallRecord | None:
    path = root / RECORD_REL
    unsafe = unsafe_component(root, RECORD_REL, expect_dir=False)
    if unsafe:
        raise RecordError(f"install record path is unsafe: {unsafe}", "PATH_UNSAFE")
    if not path.exists():
        return None
    if not path.is_file():  # e.g. a FIFO: reading it would block (in init/carriers under the project lock)
        raise RecordError("install record unreadable: not a regular file")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.pop("schema") != SCHEMA:
            raise RecordError("unexpected install record schema")
        record = InstallRecord(**data)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise RecordError(f"install record unreadable: {exc}") from exc
    if not isinstance(record.files, dict):
        raise RecordError("install record files must be a mapping")
    validate_carriers(record.carriers)
    return record


def save(root: Path, record: InstallRecord) -> None:
    atomic_write_bytes(root / RECORD_REL, dumps_json(record.to_dict()))
