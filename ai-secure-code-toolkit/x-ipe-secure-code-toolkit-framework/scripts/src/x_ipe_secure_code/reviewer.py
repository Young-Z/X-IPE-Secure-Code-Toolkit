"""Shared Reviewer-record envelope (`reviewer-record/v1`, FEATURE-002-A FR-002A-4; reused by Copilot).

The envelope covers invocation, review requirement, reviewed file digests, the review time and the
refusal of authority-changing parts. Each caller validates its own typed subjects through a callback,
so the validation order (and every message) stays exactly as Guard produced it before extraction.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .guard.model import DIGEST, Checker, GuardError

ABSENT = "absent"
BASE_KEYS = frozenset({"schema", "invocation", "requirement", "reviewed_targets", "subjects", "reviewed_at"})


def envelope(
    ck: Checker,
    doc: Any,
    *,
    authority_keys: tuple[str, ...],
    allowed_extra: set[str],
    allow_absent: bool,
    require_invoked_at: bool,
    normalize_path: Callable[[Any, str], str],
    subjects: Callable[[list, list[str]], list[dict[str, Any]]],
) -> tuple[dict[str, Any], list[str]]:
    """Validate one Reviewer record; return (record, completeness warnings).

    Args:
        ck: Checker of the caller (its `text` masks free text; a labelling checker records where).
        doc: The parsed request object.
        authority_keys: Top-level keys refused with `REVIEW_AUTHORITY`, reported in this order.
        allowed_extra: Further top-level keys the caller accepts (Guard: attempt, usage).
        allow_absent: Accept the digest marker `absent` for a reviewed file that no longer exists.
        require_invoked_at: A missing invocation time makes the record incomplete.
        normalize_path: `(raw, where) -> project-relative path`, raising the caller's refusal.
        subjects: `(raw_subjects, warnings) -> subjects`; validates typed subjects, may add warnings.

    Raises:
        GuardError: `REVIEW_AUTHORITY` for authority keys; the checker's code for malformed input.
    """
    if not isinstance(doc, dict):
        raise ck.fail("Reviewer record must be a JSON object")
    extra = [k for k in authority_keys if k in doc]
    if extra:
        raise GuardError(
            "REVIEW_AUTHORITY",
            f"A Reviewer record cannot set {', '.join(extra)}: Reviewers have no extra authority",
            "Remove those parts and record only the review result",
        )
    ck.obj(doc, "review", set(BASE_KEYS) | set(allowed_extra))
    warnings: list[str] = []
    inv = ck.obj(doc.get("invocation") or {}, "invocation", {"host", "agent", "read_only", "invoked_at"})
    invocation = {
        "host": ck.text(inv.get("host"), "invocation.host", required=False, limit=200),
        "agent": ck.text(inv.get("agent"), "invocation.agent", required=False, limit=200),
        "read_only": inv.get("read_only") is True,
        "invoked_at": ck.text(inv.get("invoked_at"), "invocation.invoked_at", required=False, limit=64),
        "declared": True,
    }
    for key in ("host", "agent"):
        if not invocation[key]:
            warnings.append(f"invocation.{key} is missing")
    if not invocation["read_only"]:
        warnings.append("invocation.read_only is not true")
    if require_invoked_at and not invocation["invoked_at"]:
        warnings.append("invocation.invoked_at is missing")
    requirement = ck.text(doc.get("requirement"), "requirement", required=False)
    if not requirement:
        warnings.append("requirement is missing")
    reviewed: list[dict[str, str]] = []
    for i, raw in enumerate(ck.items(doc.get("reviewed_targets"), "reviewed_targets")):
        where = f"reviewed_targets[{i}]"
        ck.obj(raw, where, {"path", "digest"}, frozenset({"path", "digest"}))
        path = normalize_path(raw["path"], where)
        if allow_absent and raw["digest"] == ABSENT:
            digest = ABSENT
        else:
            digest = ck.pattern(raw["digest"], f"{where}.digest", DIGEST)
        reviewed.append({"path": path, "digest": digest})
    if not reviewed:
        warnings.append("reviewed_targets is missing")
    raw_subjects = ck.items(doc.get("subjects"), "subjects")
    if not raw_subjects:
        warnings.append("subjects is missing")
    checked = subjects(raw_subjects, warnings)
    record = {
        "invocation": invocation,
        "requirement": requirement,
        "reviewed_targets": reviewed,
        "subjects": checked,
        "reviewed_at": ck.text(doc.get("reviewed_at"), "reviewed_at", required=False, limit=64),
        "completeness": warnings,
    }
    return record, warnings
