"""Guard constants, identifiers, bounds and request validation helpers (FEATURE-002-A)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..knowledge import store
from .mask import mask_text

SCHEMA_OPEN = "ai-secure-code-toolkit/guard-open/v1"
SCHEMA_PLAN = "ai-secure-code-toolkit/guard-plan/v1"
SCHEMA_RECORD = "ai-secure-code-toolkit/guard-record/v1"
SCHEMA_REVIEW = "ai-secure-code-toolkit/reviewer-record/v1"
SCHEMA_RUN = "ai-secure-code-toolkit/guard-run/v1"
SCHEMA_RESULT = "ai-secure-code-toolkit/guard-result/v1"

KINDS = ("document", "reading", "runtime", "reviewer")
STATES = ("met", "not_met", "unconfirmed", "n/a")
NA_REASON_TYPES = ("objective", "method_unavailable", "not_executed", "evidence_missing")
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_VALUES = (*SEVERITIES, "unknown")
SEVERE = frozenset({"medium", "high", "critical"})
CHANGES = ("added", "modified", "deleted", "renamed", "unspecified")
CONFLICT_KINDS = ("requirement", "severity", "evidence")
FINDING_RESULTS = ("confirmed", "false_positive", "unconfirmed")
NA_RESULTS = ("confirmed", "rejected")

RUN_ID = re.compile(r"gv-\d{8}T\d{6}Z-[0-9a-f]{8}")
ITEM_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,59}")
LINES = re.compile(r"\d{1,9}(?:-\d{1,9})?")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_ITEMS = 1000
MAX_TEXT = 8 * 1024
MAX_CONTENT = 1024 * 1024
MAX_CONTENT_FILE = 16 * 1024 * 1024
MAX_EVIDENCE_TOTAL = 256 * 1024 * 1024
RETENTION_DAYS = 30

GUARD_REL = f"{store.PRIVATE_REL}/guard"
LOCK_REL = f"{store.PRIVATE_REL}/locks/guard.lock"
REPORTS_REL = "x-ipe-docs/secure-code/reports/guard"


class GuardError(Exception):
    def __init__(
        self, code: str, message: str, next_step: str | None = None, data: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.next_step = next_step
        self.data = data or {}


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def severity_rank(value: str) -> int:
    return SEVERITIES.index(value)


def load_request(path: str, schema: str, code: str, next_step: str) -> dict[str, Any]:
    """Read one bounded UTF-8 JSON request object with the exact schema."""
    file = Path(path)
    try:
        if file.is_symlink() or not file.is_file():
            raise GuardError(code, f"Request file not found or not a regular file: {path}", next_step)
        if file.stat().st_size > MAX_REQUEST_BYTES:
            raise GuardError(code, f"Request file larger than {MAX_REQUEST_BYTES} bytes: {path}", next_step)
        doc = json.loads(file.read_bytes().decode("utf-8"))
    except GuardError:
        raise
    except RecursionError:
        raise GuardError(code, "Request file is nested too deeply", next_step) from None
    except (OSError, UnicodeError, ValueError) as exc:
        raise GuardError(code, f"Request file is not readable UTF-8 JSON: {exc}", next_step) from None
    if not isinstance(doc, dict):
        raise GuardError(code, "Request file must contain a JSON object", next_step)
    if doc.get("schema") != schema:
        raise GuardError(code, f"Request schema must be {schema}", next_step)
    return doc


class Checker:
    """Field validation bound to one refusal code; free text is always masked."""

    def __init__(self, code: str, next_step: str) -> None:
        self.code = code
        self.next_step = next_step

    def fail(self, message: str, code: str | None = None) -> GuardError:
        return GuardError(code or self.code, message, self.next_step)

    def obj(self, value: Any, where: str, allowed: set[str], required: frozenset[str] = frozenset()) -> dict:
        if not isinstance(value, dict):
            raise self.fail(f"{where} must be an object")
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise self.fail(f"{where} has unknown fields: {', '.join(unknown)}")
        missing = sorted(k for k in required if value.get(k) in (None, "", []))
        if missing:
            raise self.fail(f"{where} is missing: {', '.join(missing)}")
        return value

    def items(self, value: Any, where: str, *, required: bool = False) -> list:
        if value is None:
            value = []
        if not isinstance(value, list):
            raise self.fail(f"{where} must be a list")
        if len(value) > MAX_ITEMS:
            raise self.fail(f"{where} has more than {MAX_ITEMS} items")
        if required and not value:
            raise self.fail(f"{where} must not be empty")
        return value

    def text(self, value: Any, where: str, *, required: bool = True, limit: int = MAX_TEXT) -> str | None:
        if value is None or value == "":
            if required:
                raise self.fail(f"{where} is required")
            return None
        if not isinstance(value, str):
            raise self.fail(f"{where} must be text")
        if len(value) > limit:
            raise self.fail(f"{where} is longer than {limit} characters")
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise self.fail(f"{where} must be valid UTF-8 text") from None
        return mask_text(value)[0]

    def pattern(self, value: Any, where: str, regex: re.Pattern, *, required: bool = True) -> str | None:
        if value is None and not required:
            return None
        if not isinstance(value, str) or not regex.fullmatch(value):
            raise self.fail(f"{where} id or name is not valid: {value!r}")
        if mask_text(value)[1]:
            raise self.fail(f"{where} looks like a credential; ids and names are stored unmasked")
        return value

    def key(self, value: Any, where: str) -> str:
        """A string identifier that may be looked up (never an unhashable value)."""
        if not isinstance(value, str) or not value:
            raise self.fail(f"{where} must be a non-empty identifier text")
        return value

    def choice(self, value: Any, where: str, options: tuple[str, ...]) -> str:
        if value not in options:
            raise self.fail(f"{where} must be one of {', '.join(options)} (got {value!r})")
        return value

    def flag(self, value: Any, where: str, default: bool = False) -> bool:
        if value is None:
            return default
        if not isinstance(value, bool):
            raise self.fail(f"{where} must be true or false")
        return value

    def refs(self, value: Any, where: str, known: Any, *, required: bool = False) -> list[str]:
        """List of existing ids (order kept, duplicates removed)."""
        result: list[str] = []
        for item in self.items(value, where, required=required):
            ref = self.pattern(item, where, ITEM_ID)
            if ref not in known:
                raise self.fail(f"{where} refers to unknown id {ref}")
            if ref not in result:
                result.append(ref)
        if required and not result:
            raise self.fail(f"{where} needs at least one evidence id")
        return result
