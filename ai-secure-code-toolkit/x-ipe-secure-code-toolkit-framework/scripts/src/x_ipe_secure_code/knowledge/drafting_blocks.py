"""Labelled AI example blocks inside `example-<lang>.md` (FEATURE-001-G, FR-001G-5, V4).

A block is plain line-comment text appended to the language's example file. Its begin marker
binds the draft digest and the digest of the body lines; the notice carries only check-time
values (no approval time). Markers are tamper-evident for accidental edits only.
"""

from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass
from typing import Any

from .drafting_model import ATTESTATIONS, MARKER_WORD

COMMENT = {
    "python": "#",
    "java": "//",
    "javascript": "//",
    "typescript": "//",
    "c": "//",
    "cpp": "//",
    "csharp": "//",
    "go": "//",
}
SUPPORTED = tuple(sorted(COMMENT))
NOTICE = (
    "AI-generated example — not source text, non-normative; does not add or change requirements of the source"
)
DECISION_ORDER = (
    "unsafe_violates_rule",
    "safe_addresses_rule",
    "language_correct",
    "unchecked_syntax_understood",
)
UNSAFE_LABEL = "--- unsafe example (violates the rule) ---"
SAFE_LABEL = "--- safe example (addresses the rule) ---"
_LANG = r"[a-z0-9+#-]{1,20}"
_DIGEST = r"sha256:[0-9a-f]{64}"
BEGIN = re.compile(
    rf"(#|//) >>> {MARKER_WORD} v1 kind=example lang=({_LANG}) draft=({_DIGEST}) "
    rf"body=({_DIGEST})"
)
END = re.compile(rf"(#|//) <<< {MARKER_WORD} v1 end draft=({_DIGEST})")
NOT_RETRIEVED = "source page not retrieved; drafted from the stored rule"


class MarkerError(Exception):
    """A marker grammar violation (`file` and 1-based `line`)."""

    def __init__(self, file: str, line: int, reason: str) -> None:
        super().__init__(f"{file}:{line}: {reason}")
        self.file = file
        self.line = line
        self.reason = reason


@dataclass(frozen=True)
class Block:
    lang: str
    draft_digest: str
    body_digest: str
    begin: int  # 0-based index of the begin line
    end: int  # 0-based index of the end line
    body: tuple[str, ...]
    token: str

    @property
    def state(self) -> str:
        return "intact" if sha256_text(_joined(self.body)) == self.body_digest else "modified"

    @property
    def begin_line(self) -> str:
        return (
            f"{self.token} >>> {MARKER_WORD} v1 kind=example lang={self.lang} draft={self.draft_digest} "
            f"body={self.body_digest}"
        )


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _joined(lines: tuple[str, ...] | list[str]) -> str:
    return "".join(line + "\n" for line in lines)


def file_language(name: str) -> str | None:
    """Language of a supported `example-<lang>.md`; None for every other rule file."""
    if name.startswith("example-") and name.endswith(".md"):
        lang = name[len("example-") : -3]
        return lang if lang in COMMENT else None
    return None


def _markerish(line: str) -> bool:
    return MARKER_WORD in line.lower()


def check_part(lang: str, part: str, text: str) -> None:
    """Draft text must not contain marker-like lines (they would forge or break a block)."""
    for index, line in enumerate(text.split("\n")):
        if _markerish(line):
            raise MarkerError(f"examples.{lang}.{part}", index + 1, f"contains '{MARKER_WORD}'")


def scan_markers(name: str, text: str) -> list[Block]:
    """Well-formed blocks of one rule file, or MarkerError naming file and line."""
    lang = file_language(name)
    lines = text.split("\n")
    blocks: list[Block] = []
    opened: tuple[int, re.Match[str]] | None = None
    for index, line in enumerate(lines):
        if not _markerish(line):
            continue
        if lang is None:
            raise MarkerError(
                name,
                index + 1,
                "AI marker inside non-AI text (only example-<lang>.md of a "
                f"supported language may hold AI blocks: {', '.join(SUPPORTED)})",
            )
        begin, end = BEGIN.fullmatch(line), END.fullmatch(line)
        if begin:
            if opened is not None:
                raise MarkerError(name, index + 1, "nested begin marker inside an open AI block")
            if begin.group(1) != COMMENT[lang] or begin.group(2) != lang:
                raise MarkerError(name, index + 1, f"marker comment or language does not match {name}")
            if blocks:
                raise MarkerError(name, index + 1, f"more than one AI block for language {lang}")
            opened = (index, begin)
        elif end:
            if opened is None:
                raise MarkerError(name, index + 1, "end marker without a begin marker")
            start, match = opened
            if end.group(1) != COMMENT[lang]:
                raise MarkerError(name, index + 1, f"marker comment does not match {name}")
            if end.group(2) != match.group(3):
                raise MarkerError(name, index + 1, "end marker names another draft than its begin marker")
            blocks.append(
                Block(
                    lang,
                    match.group(3),
                    match.group(4),
                    start,
                    index,
                    tuple(lines[start + 1 : index]),
                    COMMENT[lang],
                )
            )
            opened = None
        else:
            raise MarkerError(name, index + 1, "line is not a valid AI begin or end marker")
    if opened is not None:
        raise MarkerError(name, opened[0] + 1, "AI block is not terminated by an end marker")
    return blocks


def strip(text: str | None) -> str:
    """Text without its (well-formed) AI blocks and their separator lines; '' means file absent."""
    if not text:
        return ""
    lines = text.split("\n")
    drop: set[int] = set()
    for found in scan_markers_any(text):
        drop.update(range(found.begin, found.end + 1))
        if found.begin > 0 and lines[found.begin - 1] == "":
            drop.add(found.begin - 1)
    kept = [line for index, line in enumerate(lines) if index not in drop]
    result = "\n".join(kept)
    return "" if result in ("", "\n") else result


def scan_markers_any(text: str) -> list[Block]:
    """Blocks of a text whose grammar was already checked for its file (language from the marker)."""
    found = []
    lines = text.split("\n")
    start: tuple[int, re.Match[str]] | None = None
    for index, line in enumerate(lines):
        begin, end = BEGIN.fullmatch(line), END.fullmatch(line)
        if begin and start is None:
            start = (index, begin)
        elif end and start is not None:
            first, match = start
            found.append(
                Block(
                    match.group(2),
                    match.group(3),
                    match.group(4),
                    first,
                    index,
                    tuple(lines[first + 1 : index]),
                    match.group(1),
                )
            )
            start = None
    return found


def render_file(current: str | None, block: str) -> str:
    """New file text: the current non-AI text, one empty separator line, then the new block."""
    base = strip(current)
    return base + "\n" + block if base else block


def notice_lines(
    *,
    draft_digest: str,
    sources: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    level: str,
    decisions: set[str],
    attestations: set[str],
    acknowledgements: set[str],
    confidentiality: str | None,
    python_version: str | None = None,
) -> list[str]:
    lines = [NOTICE, f"draft: {draft_digest}"]
    for source in sources:
        kind = source.get("kind")
        if kind == "stored_rule_content":
            lines.append("source: stored rule content (drafted from the stored rule)")
        elif kind == "not_retrieved":
            lines.append(f"source: {NOT_RETRIEVED} ({source.get('url')}; reason: {source.get('reason')})")
        else:
            att = source.get("attribution") or {}
            lines.append(
                f"source: fetched {source.get('url')} at {source.get('fetched_at')} (HTTP "
                f"{source.get('http_status')}, body {source.get('body_sha256')}); attribution: "
                f'"{att.get("title")}", {att.get("url")}, licence: {att.get("licence")}'
            )
    if level == "syntax_checked":
        version = python_version or f"{sys.version_info.major}.{sys.version_info.minor}"
        lines.append(f"validation: syntax_checked (Python {version} grammar, AST only; not executed)")
    else:
        lines.append(f"validation: {level} (not executed)")
    recorded = [d for d in DECISION_ORDER if d in decisions]
    lines.append("maintainer decisions: " + (", ".join(recorded) or "none recorded"))
    attested = [a for a in ATTESTATIONS if a in attestations]
    lines.append("maintainer attestations: " + (", ".join(attested) or "none recorded"))
    if "example_commands_acknowledged" in acknowledgements:
        lines.append("maintainer acknowledgements: example_commands_acknowledged")
    if confidentiality:
        lines.append(f"confidentiality: {confidentiality}")
    return lines


def render_block(lang: str, draft_digest: str, notice: list[str], unsafe: str, safe: str) -> str:
    c = COMMENT[lang]
    body = [f"{c} {line}" for line in notice]
    body += [f"{c} {UNSAFE_LABEL}", *unsafe.split("\n"), f"{c} {SAFE_LABEL}", *safe.split("\n")]
    begin = (
        f"{c} >>> {MARKER_WORD} v1 kind=example lang={lang} draft={draft_digest} "
        f"body={sha256_text(_joined(body))}"
    )
    end = f"{c} <<< {MARKER_WORD} v1 end draft={draft_digest}"
    return _joined([begin, *body, end])


def parse_notice(found: Block) -> dict[str, Any]:
    """Notice fields read back from the fixed line prefixes (nothing is repaired)."""
    prefix = found.token + " "
    fields: dict[str, Any] = {
        "sources": [],
        "validation_level": None,
        "decisions": [],
        "attestations": [],
        "acknowledgements": [],
        "confidentiality": None,
    }
    for line in found.body:
        if line.startswith(f"{prefix}{UNSAFE_LABEL}"):
            break
        text = line[len(prefix) :] if line.startswith(prefix) else ""
        key, _, value = text.partition(": ")
        if key == "source":
            fields["sources"].append(value)
        elif key == "validation":
            fields["validation_level"] = value.split(" ", 1)[0]
        elif key in ("maintainer decisions", "maintainer attestations", "maintainer acknowledgements"):
            name = key.split(" ", 1)[1]
            fields[name] = [] if value == "none recorded" else value.split(", ")
        elif key == "confidentiality":
            fields["confidentiality"] = value
    return fields
