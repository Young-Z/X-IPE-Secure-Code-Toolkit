"""Validate Copilot open requests, suggestion batches and Reviewer records (AC-003A-03*, 04a…04d, 04f, 04h).

Validation never decides adoption; it refuses malformed or out-of-scope input and masks free text
(with labels, so reports can say which fields were masked).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..guard.model import ITEM_ID, MAX_ITEMS, MAX_TEXT, SEVERITY_VALUES, Checker, GuardError
from ..guard.targets import kind_of, normalize
from ..reviewer import envelope
from . import manifest
from .model import ADOPTION_RESULTS, AUTHORITY_KEYS, STAGES

OPEN_STEP = "Fix the open request (see the Copilot skill references/copilot-records.md)"
SUGGEST_STEP = "Fix the suggestion batch and record it again; nothing from it was stored"
REVIEW_STEP = "Fix the Reviewer record file and record it again; nothing from it was stored"
SELECT_STEP = (
    "Resolve, select and confirm Policies with the Framework skill (secure-code policy resolve, "
    "then secure-code scope save), then pass its scope_id"
)


MASK_MARKER = re.compile(r"\[masked:[a-z_.]+\]")


class LabellingChecker(Checker):
    """Checker that remembers which free-text fields were masked (`self.masked`, field paths)."""

    def __init__(self, code: str, next_step: str) -> None:
        super().__init__(code, next_step)
        self.masked: list[str] = []

    def text(self, value: Any, where: str, *, required: bool = True, limit: int = MAX_TEXT) -> str | None:
        if isinstance(value, str) and MASK_MARKER.search(value):
            raise self.fail(f"{where} contains a toolkit mask marker ([masked:...]); remove it")
        result = super().text(value, where, required=required, limit=limit)
        if result is not None and result != value and where not in self.masked:
            self.masked.append(where)
        return result

    def required(self, value: Any, where: str) -> str:
        """Required text that is not blank."""
        if isinstance(value, str) and not value.strip():
            raise self.fail(f"{where} is required")
        return self.text(value, where)  # type: ignore[return-value]


def validate_open(root: Path, doc: dict[str, Any]) -> dict[str, Any]:
    """Validate a `copilot-open/v1` request (no scope loading, nothing written)."""
    ck = LabellingChecker("REQUEST_INVALID", OPEN_STEP)
    ck.obj(doc, "request", {"schema", "scope_id", "stage", "task", "artifacts", "context", "whole_project"})
    if doc.get("whole_project") not in (None, False):
        raise GuardError(
            "WHOLE_PROJECT_REFUSED", "Copilot never reviews the whole project", manifest.NAME_STEP
        )
    scope_id = doc.get("scope_id")
    if scope_id in (None, ""):
        raise GuardError(
            "SCOPE_REQUIRED",
            "No adopted scope was given; Copilot suggests only from adopted Policies",
            SELECT_STEP,
        )
    if not isinstance(scope_id, str):
        raise ck.fail("scope_id must be text")
    stage = ck.choice(doc.get("stage"), "stage", STAGES)
    task = ck.required(doc.get("task"), "task")
    entries = manifest.parse_entries(root, doc.get("artifacts"), "artifacts")
    taken = {e["path"] for e in entries} | {e["old_path"] for e in entries if e["old_path"]}
    context: list[dict[str, Any]] = []
    for index, raw in enumerate(ck.items(doc.get("context"), "context")):
        where = f"context[{index}]"
        ck.obj(raw, where, {"path"}, frozenset({"path"}))
        rel = normalize(raw["path"], where)
        if rel in taken:
            raise GuardError(
                "ROLE_CONFLICT",
                f"{rel} is given as artifact and as context",
                "Give each path one role: artifact or read-only context",
            )
        kind = kind_of(root, rel, where)
        if kind is None or rel == ".":
            raise GuardError("TARGET_INVALID", f"{where}: {rel} is not an existing file or folder", OPEN_STEP)
        digest = manifest.current(root, [rel])[rel] if kind == "file" else None
        context.append({"path": rel, "kind": kind, "digest": digest})
        taken.add(rel)
    return {
        "scope_id": scope_id,
        "stage": stage,
        "task": task,
        "masked": list(ck.masked),
        "entries": entries,
        "context": context,
    }


def validate_suggest(state: dict[str, Any], doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate one whole suggestion batch (atomic); returns the suggestions to append."""
    ck = LabellingChecker("SUGGESTION_INVALID", SUGGEST_STEP)
    ck.obj(doc, "request", {"schema", "suggestions"})
    raw_list = ck.items(doc.get("suggestions"), "suggestions", required=True)
    adopted = {a["rule"] for a in state["scope"]["adopted"]}
    used = {s["id"] for s in state["suggestions"]}
    batch = 1 + max((s["batch"] for s in state["suggestions"]), default=0)
    out: list[dict[str, Any]] = []
    for i, raw in enumerate(raw_list):
        where = f"suggestions[{i}]"
        ck.obj(
            raw,
            where,
            {"id", "rule", "files", "location", "action", "reason", "severity", "stage"},
            frozenset({"id"}),
        )
        sid = ck.pattern(raw["id"], f"{where}.id", ITEM_ID)
        if sid in used:
            raise ck.fail(f"{where}.id {sid} is already used in this collaboration")
        used.add(sid)
        rule = raw.get("rule")
        if not isinstance(rule, str) or rule not in adopted:
            raise ck.fail(f"{where}.rule {rule!r} is not in the adopted scope")
        files: list[str] = []
        for j, p in enumerate(ck.items(raw.get("files"), f"{where}.files", required=True)):
            try:
                rel = normalize(p, f"{where}.files[{j}]")
            except GuardError as exc:
                raise ck.fail(exc.message) from None
            if rel not in state["manifest"]:
                raise ck.fail(f"{where}.files[{j}] {rel} is not a manifest member of this collaboration")
            if rel not in files:
                files.append(rel)
        before = len(ck.masked)
        texts = {k: ck.required(raw.get(k), f"{where}.{k}") for k in ("location", "action", "reason")}
        severity = raw.get("severity")
        out.append(
            {
                "id": sid,
                "rule": rule,
                "files": files,
                **texts,
                "severity": "unknown"
                if severity is None
                else ck.choice(severity, f"{where}.severity", SEVERITY_VALUES),
                "stage": state["stage"]
                if raw.get("stage") is None
                else ck.choice(raw["stage"], f"{where}.stage", STAGES),
                "masked": [m.removeprefix(f"{where}.") for m in ck.masked[before:]],
                "batch": batch,
            }
        )
    if len(state["suggestions"]) + len(out) > MAX_ITEMS * 10:
        raise ck.fail(f"A collaboration holds at most {MAX_ITEMS * 10} suggestions")
    return out


def validate_review(root: Path, state: dict[str, Any], doc: Any) -> dict[str, Any]:
    """Validate one Reviewer record with `adoption` subjects; returns the record to store.

    Reviewed digests that already differ from the files now are listed in `wrong_version`.
    """
    ck = LabellingChecker("REVIEW_INVALID", REVIEW_STEP)
    known = {s["id"]: s for s in state["suggestions"]}

    def path(raw: Any, where: str) -> str:
        try:
            rel = normalize(raw, where)
        except GuardError as exc:
            raise ck.fail(exc.message) from None
        if rel not in state["manifest"]:
            raise ck.fail(f"{where}: {rel} is not a manifest member of this collaboration")
        return rel

    def subjects(raw_subjects: list, warnings: list[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for i, raw in enumerate(raw_subjects):
            where = f"subjects[{i}]"
            ck.obj(raw, where, {"type", "id", "result", "basis"}, frozenset({"type", "id"}))
            ck.choice(raw["type"], f"{where}.type", ("adoption",))
            sid = ck.key(raw["id"], f"{where}.id")
            if sid not in known:
                raise ck.fail(f"{where}.id: unknown suggestion {sid!r}")
            if any(s["id"] == sid for s in out):
                raise ck.fail(f"{where} is a duplicate subject")
            result = raw.get("result")
            if result is not None:
                ck.choice(result, f"{where}.result", ADOPTION_RESULTS)
            else:
                warnings.append(f"{where}.result is missing")
            out.append(
                {
                    "type": "adoption",
                    "id": sid,
                    "result": result,
                    "basis": ck.required(raw.get("basis"), f"{where}.basis"),
                }
            )
        return out

    record, _ = envelope(
        ck,
        doc,
        authority_keys=AUTHORITY_KEYS,
        allowed_extra=set(),
        allow_absent=True,
        require_invoked_at=True,
        normalize_path=path,
        subjects=subjects,
    )
    reviewed = {}
    for item in record["reviewed_targets"]:
        if item["path"] in reviewed:
            raise ck.fail(f"reviewed_targets names {item['path']} twice")
        reviewed[item["path"]] = item["digest"]
    if reviewed:
        for s in record["subjects"]:
            missing = [f for f in known[s["id"]]["files"] if f not in reviewed]
            if missing:
                raise ck.fail(
                    f"reviewed_targets lacks {', '.join(missing)}, bound to suggestion {s['id']}; give its "
                    "digest as seen by the Reviewer, or absent when the file no longer exists"
                )
    current = manifest.current(root, reviewed)
    record["wrong_version"] = [
        p
        for p, d in reviewed.items()
        if (current.get(p) is None and d != "absent") or (current.get(p) is not None and d != current.get(p))
    ]
    record["masked"] = list(ck.masked)
    return record
