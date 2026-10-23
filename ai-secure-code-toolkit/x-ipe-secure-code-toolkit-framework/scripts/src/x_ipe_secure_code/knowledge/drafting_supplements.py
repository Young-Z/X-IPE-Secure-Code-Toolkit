"""`knowledge supplements`: read-only listing of AI example blocks (FEATURE-001-G, FR-001G-4).

Each block reports its state (`intact` when the recorded body digest matches, `modified` otherwise;
grammar failures are `malformed`) and the approval time read from the delivered changelog entry that
added it (`not_found` otherwise). Nothing is repaired, removed or relabelled; no authorization needed.
Values matched by the pre-check anywhere in a rule's files are masked in the listing (FR-001G-10,
DEC-I15): with the existing pre-check key as `[REDACTED:<fingerprint>]`, without a usable key as
`[REDACTED]` (the key is never created).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..paths import unsafe_component
from ..projects import knowledge_root
from ..results import Result
from . import drafting_blocks as blocks
from . import drafting_mask, durable, exit_journal, precheck, store
from .identity import IdentityError, RuleRef

COMMAND = "knowledge supplements"
ENTRY = re.compile(r"^## (\S+) — updated \(role: maintainer\)$", re.M)
RECOVERY_STEP = (
    "Run `secure-code knowledge list --project <path>`, which completes the interrupted "
    "operation, then repeat the command"
)


def approved_at(changelog: str, file_name: str, begin_line: str) -> str:
    """Time of the latest `updated` entry whose diff of `file_name` adds the block's begin marker."""
    found = "not_found"
    heads = list(ENTRY.finditer(changelog))
    starts = [m.start() for m in re.finditer(r"^## ", changelog, re.M)] + [len(changelog)]
    for head in heads:
        end = next(s for s in starts if s > head.start())
        entry = changelog[head.start() : end]
        for section in entry.split("\n### ")[1:]:
            if section.startswith(file_name + "\n") and f"\n+{begin_line}\n" in section:
                found = head.group(1)
    return found


def _blocks(ref: RuleRef, stored: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    log = stored.files.get("changelog.md", "")
    for name, text in sorted(stored.files.items()):
        if name == "changelog.md":
            continue
        try:
            found = blocks.scan_markers(name, text)
        except blocks.MarkerError as exc:
            rows.append(
                {"rule": ref.rel, "file": name, "line": exc.line, "state": "malformed", "reason": exc.reason}
            )
            continue
        for block in found:
            notice = blocks.parse_notice(block)
            rows.append(
                {
                    "rule": ref.rel,
                    "file": name,
                    "kind": "example",
                    "language": block.lang,
                    "draft_digest": block.draft_digest,
                    "body_digest_recorded": block.body_digest,
                    "state": block.state,
                    "sources": notice["sources"],
                    "confidentiality": notice["confidentiality"],
                    "validation_level": notice["validation_level"],
                    "decisions": notice["decisions"],
                    "attestations": notice["attestations"],
                    "acknowledgements": notice["acknowledgements"],
                    "approved_at": approved_at(log, name, block.begin_line),
                }
            )
    return rows


def list_supplements(project: str | None, rule: str | None) -> Result:
    root = knowledge_root(project, COMMAND)
    if isinstance(root, Result):
        return root
    try:
        refs = [RuleRef.parse(rule)] if rule else None
    except IdentityError as exc:
        return Result.refused(COMMAND, exc.code, exc.message)
    try:
        with durable.Tree(root) as tree:
            if exit_journal.has_pending(tree):
                return Result.refused(
                    COMMAND,
                    "RECOVERY_PENDING",
                    "An interrupted knowledge exit is pending; "
                    "read-only drafting commands do not complete it",
                    RECOVERY_STEP,
                )
        rows = _collect(root, refs, _key(root))
    except drafting_mask.MaskingParity as exc:
        return Result.refused(COMMAND, "MASKING_PARITY", str(exc), "Report this to the Maintainer")
    except _NotFound as exc:
        return Result.refused(COMMAND, "RULE_NOT_FOUND", f"{exc} is not stored")
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.refusal(COMMAND, exc)
    return Result(COMMAND, True, {"supplements": rows, "count": len(rows)})


class _NotFound(Exception):
    pass


def _key(root: Path) -> bytes | None:
    """The existing pre-check key (read-only, never created); None when absent, unsafe or invalid."""
    if unsafe_component(root, precheck.KEY_REL, expect_dir=False):
        return None
    try:
        key = precheck.read_key(root)
    except OSError:
        return None
    return key if key is not None and len(key) == 32 else None


def _masked(stored: Any, rows: list[dict[str, Any]], key: bytes | None) -> list[dict[str, Any]]:
    """Mask every pre-check-matched value of the rule's files in its rows (DEC-I15)."""
    files = {n: t for n, t in stored.files.items() if n != "changelog.md"}
    spans = drafting_mask.locate(files, key if key is not None else bytes(32))
    pairs = drafting_mask.values(spans, files)
    if key is None:
        pairs = [(value, "[REDACTED]") for value, _ in pairs]
    return drafting_mask.sweep(rows, pairs)


def _collect(root: Path, refs: list[RuleRef] | None, key: bytes | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ref in refs if refs is not None else store.iter_refs(root):
        stored = store.read_rule(root, ref)
        if stored is None:
            if refs is not None:
                raise _NotFound(ref.rel)
            continue
        found = _blocks(ref, stored)
        rows += _masked(stored, found, key) if found else found
    return rows
