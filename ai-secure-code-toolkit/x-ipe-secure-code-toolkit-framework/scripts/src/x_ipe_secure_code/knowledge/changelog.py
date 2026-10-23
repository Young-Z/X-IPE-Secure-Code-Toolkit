"""Append-only per-rule changelog with full unified diffs."""

from __future__ import annotations

import difflib
import re

from .precheck import Finding


def _fence(text: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(4, longest + 1)


def _diff(name: str, old: str | None, new: str | None) -> str:
    lines = difflib.unified_diff(
        (old or "").splitlines(keepends=True),
        (new or "").splitlines(keepends=True),
        fromfile="/dev/null" if old is None else f"a/{name}",
        tofile="/dev/null" if new is None else f"b/{name}",
    )
    body = "".join(line if line.endswith("\n") else line + "\n" for line in lines)
    fence = _fence(body)
    return f"### {name}\n{fence}diff\n{body}{fence}\n"


def header(rule: str) -> str:
    return f"# Changelog — {rule}\n\n"


def entry(
    *,
    time: str,
    operation: str,
    item_digest: str,
    base_digest: str | None,
    source_document: str | None,
    declared: list[Finding],
    changes: list[tuple[str, str | None, str | None]],
) -> str:
    lines = [
        f"## {time} — {operation} (role: maintainer)",
        "",
        f"- item digest: {item_digest}" + (f" (base {base_digest})" if base_digest else ""),
        f"- source document digest: {source_document or 'none'}",
    ]
    if declared:
        lines.append(
            "- declared false positives: "
            + "; ".join(f"{f.type} @ {f.file}:{f.line} ({f.fingerprint})" for f in declared)
        )
    text = "\n".join(lines) + "\n\n"
    for name, old, new in changes:
        if old != new:
            text += _diff(name, old, new) + "\n"
    return text


LIFECYCLE_OPERATIONS = {"deactivate": "deactivated", "reactivate": "reactivated", "rename": "renamed"}


def lifecycle_entry(
    *,
    time: str,
    action: str,
    exit_id: str,
    reason: str,
    rule: str,
    target: str | None,
    revision_from: int,
    revision_to: int,
    state_before: str | None,
    state_after: str | None,
    impact_digest: str,
    transition: str,
    old_record: str,
    new_record: str,
) -> str:
    """Changelog entry of a deactivation, reactivation or rename (binds the exit transition)."""
    rule_line = f"{rule} → {target}" if target else rule
    return (
        f"## {time} — {LIFECYCLE_OPERATIONS[action]} (role: maintainer)\n\n"
        f"- exit id: {exit_id}\n- reason: {reason}\n- rule id: {rule_line}\n"
        f"- lifecycle revision: {revision_from} → {revision_to}; "
        f"state digest: {state_before} → {state_after}\n"
        f"- impact digest: {impact_digest}\n- transition: {transition}\n\n"
        + _diff("record.json", old_record, new_record)
        + "\n"
    )
