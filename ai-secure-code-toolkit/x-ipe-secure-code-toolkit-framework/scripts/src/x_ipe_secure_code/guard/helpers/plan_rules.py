"""Helper-method plan rules (AC-002F-01b, design §2.1): `helper.<slug>` methods are auxiliary runtime
methods with a recorded gap reason; the additive `gap` key is accepted only for them.

Called by the delivered `records.validate_plan` / `_method_changes` hooks; a plan or method change without
`helper.` names and without `gap` passes through unchanged (byte-identical validation).
"""

from __future__ import annotations

import copy
from typing import Any

from ..model import NAME, Checker
from .model import HELPER_METHOD, RESERVED, is_helper_method  # noqa: F401 - RESERVED re-exported

GAP_KEYS = {"considered", "why_insufficient", "gap"}


def split_plan(doc: dict[str, Any]) -> tuple[dict[str, Any], dict[int, Any]]:
    """Remove `method_choice.gap` from a copy of the plan request; return the copy and the gaps by check."""
    checks = doc.get("checks")
    if not isinstance(checks, list) or not any(
        isinstance(c, dict) and isinstance(c.get("method_choice"), dict) and "gap" in c["method_choice"]
        for c in checks
    ):
        return doc, {}
    doc = copy.deepcopy(doc)
    gaps = {
        i: c["method_choice"].pop("gap")
        for i, c in enumerate(doc["checks"])
        if isinstance(c, dict) and isinstance(c.get("method_choice"), dict) and "gap" in c["method_choice"]
    }
    return doc, gaps


def _gap(ck: Checker, raw: Any, where: str) -> dict[str, Any]:
    ck.obj(raw, where, GAP_KEYS, frozenset(GAP_KEYS))
    considered = [
        ck.pattern(x, f"{where}.considered", NAME)
        for x in ck.items(raw["considered"], f"{where}.considered", required=True)
    ]
    return {
        "considered": considered,
        "why_insufficient": ck.text(raw["why_insufficient"], f"{where}.why_insufficient"),
        "gap": ck.text(raw["gap"], f"{where}.gap"),
    }


def _helper_method(ck: Checker, name: str, kind: str, required: bool, where: str) -> None:
    if not HELPER_METHOD.fullmatch(name):
        raise ck.fail(f"{where}: helper method name {name!r} must match helper.<lowercase-slug>")
    if kind != "runtime":
        raise ck.fail(f"{where}: helper method {name} must have kind runtime")
    if required:
        raise ck.fail(f"{where}: helper method {name} is an auxiliary method and must be required: false")


def check_plan(ck: Checker, checks: list[dict[str, Any]], gaps: dict[int, Any]) -> None:
    """Helper methods are auxiliary runtime methods with a gap reason; `gap` only for such checks."""
    for i, check in enumerate(checks):
        where = f"checks[{i}]"
        names = [m for m in check["methods"] if is_helper_method(m["name"])]
        for j, m in enumerate(check["methods"]):
            if is_helper_method(m["name"]):
                _helper_method(ck, m["name"], m["kind"], m["required"], f"{where}.methods[{j}]")
        if i in gaps and not names:
            raise ck.fail(f"{where}.method_choice.gap is accepted only for a check with a helper method")
        if names and i not in gaps:
            raise ck.fail(
                f"{where}.method_choice.gap is required for helper methods (methods considered, why they "
                "cannot provide the minimum evidence, and the gap the helper covers)"
            )
        if names:
            check["method_choice"]["gap"] = _gap(ck, gaps[i], f"{where}.method_choice.gap")


def split_changes(raw_list: Any) -> tuple[Any, dict[int, Any]]:
    """Remove `gap` from a copy of the method-change requests; return the copy and the gaps by index."""
    if not isinstance(raw_list, list) or not any(isinstance(r, dict) and "gap" in r for r in raw_list):
        return raw_list, {}
    raw_list = copy.deepcopy(raw_list)
    gaps = {i: r.pop("gap") for i, r in enumerate(raw_list) if isinstance(r, dict) and "gap" in r}
    return raw_list, gaps


def check_changes(ck: Checker, entries: list[dict[str, Any]], gaps: dict[int, Any]) -> None:
    """`entries` are the method-change log entries of this record, in request order."""
    for i, entry in enumerate(entries):
        where = f"method_changes[{i}]"
        name, kind = entry["method"]["name"], entry["method"]["kind"]
        helper = is_helper_method(name)
        if helper:
            _helper_method(ck, name, kind, False, where)
        if i in gaps and not helper:
            raise ck.fail(f"{where}.gap is accepted only for a helper method")
        if helper and i not in gaps:
            raise ck.fail(
                f"{where}.gap is required for helper methods (methods considered, why they cannot provide "
                "the minimum evidence, and the gap the helper covers)"
            )
        if helper:
            entry["gap"] = _gap(ck, gaps[i], f"{where}.gap")
