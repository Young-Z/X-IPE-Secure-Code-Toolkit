"""Masked display of drafting output (FEATURE-001-G, FR-001G-10, BR-14, DEC-5).

Spans are re-located with the delivered pre-check pattern constants, iterating exactly like
`precheck.scan`, and must reproduce its findings (parity guard). Masking is a display
transformation only: diff hunks are computed from the unmasked texts, and only the emitted line
contents are redacted (`[REDACTED:<fingerprint>]`), so no unmasked diff text is ever built.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any

from . import precheck
from .precheck import ASSIGNMENT, AWS_DOC_EXAMPLES, CREDENTIALS, INSTRUCTIONS, Finding, is_placeholder

KEY_END = re.compile(r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
KEY_ID_LABEL = b"x-ipe-secure-code/001g/key-id"


class MaskingParity(Exception):
    """Span location diverged from the delivered pre-check (defensive invariant)."""


@dataclass(frozen=True)
class Span:
    finding: Finding
    start: int
    end: int

    @property
    def token(self) -> str:
        return f"[REDACTED:{self.finding.fingerprint}]"


def key_id(key: bytes) -> str:
    return hmac.new(key, KEY_ID_LABEL, hashlib.sha256).hexdigest()[:16]


def _file_spans(name: str, text: str, key: bytes) -> list[Span]:
    spans: list[Span] = []
    seen: dict[tuple[str, str], int] = {}
    in_example = name != "content.md"

    def add(kind: str, value: str, offset: int, blocking: bool, start: int, end: int) -> None:
        seen[(kind, value)] = seen.get((kind, value), 0) + 1
        mac = hmac.new(key, f"{kind}\0{name}\0{value}\0{seen[(kind, value)]}".encode(), hashlib.sha256)
        line = text.count("\n", 0, offset) + 1
        spans.append(Span(Finding(kind, name, line, mac.hexdigest()[:16], blocking), start, end))

    for kind, pattern in CREDENTIALS:
        for match in pattern.finditer(text):
            value = match.group(0)
            documented = kind == "credential.cloud_key" and value in AWS_DOC_EXAMPLES
            end = match.end()
            if kind == "credential.private_key":
                tail = KEY_END.search(text, match.end())
                end = tail.end() if tail else len(text)
            add(
                "note.placeholder" if documented else kind,
                value,
                match.start(),
                not documented,
                match.start(),
                end,
            )
    for match in ASSIGNMENT.finditer(text):
        value = match.group(1)
        if value in AWS_DOC_EXAMPLES or is_placeholder(value):
            add("note.placeholder", value, match.start(), False, match.start(1), match.end(1))
        else:
            add("credential.assignment", value, match.start(), True, match.start(1), match.end(1))
    for kind, pattern in INSTRUCTIONS:
        for match in pattern.finditer(text):
            shown = "note.example_command" if kind == "instruction.shell" and in_example else kind
            add(shown, match.group(0), match.start(), shown == kind, match.start(), match.end())
    return spans


def locate(files: dict[str, str], key: bytes) -> dict[str, list[Span]]:
    """Spans per file in `precheck.scan` order; MaskingParity if the findings differ."""
    spans = {name: _file_spans(name, text, key) for name, text in sorted(files.items())}
    located = [s.finding for name in sorted(spans) for s in spans[name]]
    if located != precheck.scan(files, key):
        raise MaskingParity("pre-check span location diverged from the delivered pre-check")
    return spans


def redact_lines(text: str, spans: list[Span]) -> list[str]:
    """`text.splitlines(True)` with every span's part of each line content replaced by its token."""
    result: list[str] = []
    offset = 0
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    for line in text.splitlines(True):
        content = line.splitlines()[0] if line.splitlines() else ""
        start, end = offset, offset + len(content)
        pieces, cursor = [], start
        hits = [s for s in ordered if s.start < end and s.end > start]
        index = 0
        while index < len(hits):
            first = hits[index]
            region_start, region_end = max(first.start, start), min(first.end, end)
            tokens = [first.token]
            index += 1
            while index < len(hits) and hits[index].start < region_end:
                region_end = max(region_end, min(hits[index].end, end))
                if hits[index].token not in tokens:
                    tokens.append(hits[index].token)
                index += 1
            if region_start < cursor:
                region_start = cursor
            pieces.append(text[cursor:region_start])
            pieces.append("".join(tokens))
            cursor = max(cursor, region_end)
        pieces.append(text[cursor:end])
        result.append("".join(pieces) + line[len(content) :])
        offset += len(line)
    return result


def _range(start: int, stop: int) -> str:
    beginning, length = start + 1, stop - start
    if length == 1:
        return f"{beginning}"
    if not length:
        beginning -= 1
    return f"{beginning},{length}"


def masked_diff(
    old: dict[str, str | None],
    new: dict[str, str],
    old_spans: dict[str, list[Span]],
    new_spans: dict[str, list[Span]],
) -> str:
    """Unified diff (stdlib format, as in the delivered changelog) of each new file; hunks come from
    the unmasked lines, emitted lines from their redacted forms."""
    out: list[str] = []
    for name in sorted(new):
        before, after = old.get(name), new[name]
        a, b = (before or "").splitlines(True), after.splitlines(True)
        ra = redact_lines(before or "", old_spans.get(name, []))
        rb = redact_lines(after, new_spans.get(name, []))
        groups = list(difflib.SequenceMatcher(None, a, b).get_grouped_opcodes(3))
        if not groups:
            continue
        out += ["--- /dev/null" if before is None else f"--- a/{name}", f"+++ b/{name}"]
        for group in groups:
            first, last = group[0], group[-1]
            out.append(f"@@ -{_range(first[1], last[2])} +{_range(first[3], last[4])} @@")
            for tag, i1, i2, j1, j2 in group:
                if tag == "equal":
                    out += [" " + line for line in ra[i1:i2]]
                    continue
                if tag in ("replace", "delete"):
                    out += ["-" + line for line in ra[i1:i2]]
                if tag in ("replace", "insert"):
                    out += ["+" + line for line in rb[j1:j2]]
    return "".join(line if line.endswith("\n") else line + "\n" for line in out)


def values(spans: dict[str, list[Span]], files: dict[str, str]) -> list[tuple[str, str]]:
    """(value, token) pairs for the output sweep, longest value first; multi-line spans also
    contribute each of their non-trivial lines."""
    pairs: dict[str, str] = {}
    for name, found in spans.items():
        text = files.get(name) or ""
        for span in found:
            value = text[span.start : span.end]
            if value:
                pairs.setdefault(value, span.token)
            if "\n" in value:
                for part in value.split("\n"):
                    if len(part.strip()) >= 8:
                        pairs.setdefault(part.strip(), span.token)
    return sorted(pairs.items(), key=lambda kv: (-len(kv[0]), kv[0]))


def sweep(obj: Any, pairs: list[tuple[str, str]]) -> Any:
    """Replace every matched value anywhere in a result structure by its redaction token."""
    if not pairs:
        return obj
    if isinstance(obj, str):
        for value, token in pairs:
            if value in obj:
                obj = obj.replace(value, token)
        return obj
    if isinstance(obj, dict):
        return {key: sweep(item, pairs) for key, item in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sweep(item, pairs) for item in obj]
    return obj
