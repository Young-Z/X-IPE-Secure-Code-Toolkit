"""Tool request validation for `secure-code guard tool` (FEATURE-002-B; moved from toolrun.py)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..adapters import ADAPTERS, provided, rules, safe_io
from . import targets
from .model import Checker, GuardError

SCHEMA_TOOL = "ai-secure-code-toolkit/guard-tool/v1"
STEP = "Fix the tool request (see the Guard skill references/guard-records.md); nothing was run"
MAX_CHECKS, MAX_RULE_FILES, MAX_TARGETS = 50, 20, 1000
MAX_RULE_BYTES = 1024 * 1024


# --------------------------------------------------------------------------- validation
def _rule_file(root: Path, ck: Checker, raw: Any, where: str) -> tuple[str, bytes]:
    if isinstance(raw, str) and "://" in raw:
        raise ck.fail(f"{where}: rule sources must be local rule files, not URLs")
    try:
        rel = targets.normalize(raw, where)
    except GuardError as exc:
        raise ck.fail(exc.message) from None
    if not rel.endswith((".yaml", ".yml", ".json")):
        raise ck.fail(f"{where}: {rel} is not a rule file (.yaml, .yml or .json)")
    try:
        fd = safe_io.open_nofollow(root, rel)
    except (OSError, safe_io.UnsafePath) as exc:
        raise ck.fail(
            f"{where}: {rel} is not an existing regular local rule file without links ({exc})"
        ) from None
    try:
        data = b""
        while chunk := os.read(fd, 65536):
            data += chunk
            if len(data) > MAX_RULE_BYTES:
                raise ck.fail(f"{where}: {rel} is larger than {MAX_RULE_BYTES} bytes")
    finally:
        os.close(fd)
    return rel, data


def planned_method(state: dict[str, Any], cid: str, adapter: str, where: str) -> dict[str, Any]:
    """The planned check whose selected (or activated) runtime method is the Adapter, else a refusal."""
    plan = state["plan"]
    check = {c["id"]: c for c in plan["checks"]}.get(cid)
    activated = {(e["check"], e["method"]["name"]) for e in plan.get("method_changes", [])}
    method = next(
        (
            m
            for m in (check or {}).get("methods", [])
            if m["name"].casefold() == adapter and m["kind"] == "runtime"
        ),
        None,
    )
    if method is None:
        raise GuardError(
            "METHOD_NOT_PLANNED",
            f"{where}: check {cid} has no planned {adapter} runtime method",
            "Plan the method (or record a method change) before running the tool",
        )
    selected = (check.get("method_choice") or {}).get("selected", [])
    if method["name"] not in selected and (cid, method["name"]) not in activated:
        raise GuardError(
            "METHOD_NOT_SELECTED",
            f"{where}: {adapter} is not a selected method of {cid}",
            "Select it in the plan's method_choice or record a method_changes entry with a reason",
        )
    return check


def bind_targets(
    state: dict[str, Any], check: dict[str, Any], raw: Any, ck: Checker, where: str
) -> list[str]:
    """Normalized scan targets: verification targets (or inside one) that together equal the check object."""
    scan = []
    for j, t in enumerate(ck.items(raw, f"{where}.targets", required=True)):
        try:
            rel = targets.normalize(t, f"{where}.targets[{j}]")
        except GuardError as exc:
            raise ck.fail(exc.message) from None
        if targets.path_role(state["artifact"], rel) != "target":
            raise GuardError("TARGETS_MISMATCH", f"{where}: {rel} is not a verification target", STEP)
        scan.append(rel)
    if len(scan) > MAX_TARGETS:
        raise ck.fail(f"{where}: at most {MAX_TARGETS} targets")
    objects = check["object"]
    inside = [t for t in scan if not any(t == o or o == "." or t.startswith(o + "/") for o in objects)]
    uncovered = [o for o in objects if not any(o == t or t == "." or o.startswith(t + "/") for t in scan)]
    if inside or uncovered:
        raise GuardError(
            "TARGETS_MISMATCH",
            f"{where}: targets must equal the check object (outside: {inside or 'none'}; "
            f"not covered: {uncovered or 'none'})",
            STEP,
        )
    return sorted(set(scan))


def validate(root: Path, state: dict[str, Any], doc: dict[str, Any]) -> dict[str, Any]:
    ck = Checker("TOOL_REQUEST_INVALID", STEP)
    if isinstance(doc, dict) and doc.get("adapter") == "trivy":
        from ..adapters import trivy_request

        return trivy_request.validate(root, state, doc, ck)
    ck.obj(
        doc,
        "request",
        {"schema", "adapter", "include_ignored", "time_limit_seconds", "checks"},
        frozenset({"adapter", "time_limit_seconds", "checks"}),
    )
    adapter = doc["adapter"]
    if adapter not in provided():
        raise ck.fail(f"adapter must be one of {', '.join(provided())}")
    spec = ADAPTERS[adapter]
    limit = doc["time_limit_seconds"]
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= spec.max_time_limit:
        raise ck.fail(f"time_limit_seconds must be a whole number from 1 to {spec.max_time_limit}")
    raw_checks = ck.items(doc["checks"], "checks", required=True)
    if len(raw_checks) > MAX_CHECKS:
        raise ck.fail(f"at most {MAX_CHECKS} checks per run")
    seen_rules: dict[str, str] = {}
    out = []
    for i, raw in enumerate(raw_checks):
        where = f"checks[{i}]"
        ck.obj(raw, where, {"check", "rules", "targets"}, frozenset({"check", "rules", "targets"}))
        cid = ck.key(raw["check"], f"{where}.check")
        if any(c["check"] == cid for c in out):
            raise ck.fail(f"{where}: check {cid} appears twice")
        check = planned_method(state, cid, adapter, where)
        rule_files = []
        for j, r in enumerate(ck.items(raw["rules"], f"{where}.rules", required=True)):
            rel, data = _rule_file(root, ck, r, f"{where}.rules[{j}]")
            if rel in seen_rules:
                raise GuardError(
                    "RULE_FILE_SHARED",
                    f"{rel} is used by {seen_rules[rel]} and {cid}",
                    "Give each check its own rule files",
                )
            seen_rules[rel] = cid
            try:
                loaded = rules.load_rules(data)
            except rules.RuleError as exc:
                raise GuardError("RULE_FILE_INVALID", f"{rel}: {exc}", STEP) from None
            rule_files.append({"path": rel, "data": data, "rules": loaded})
        if len(rule_files) > MAX_RULE_FILES:
            raise ck.fail(f"{where}: at most {MAX_RULE_FILES} rule files per check")
        try:
            rules.check_set([r for f in rule_files for r in f["rules"]])
        except rules.RuleError as exc:
            code = "RULE_ID_DUPLICATE" if "duplicate" in str(exc) else "RULE_ID_AMBIGUOUS"
            raise GuardError(code, f"{where}: {exc}", STEP) from None
        scan = bind_targets(state, check, raw["targets"], ck, where)
        out.append({"check": cid, "check_def": check, "rule_files": rule_files, "targets": scan})
    return {
        "adapter": adapter,
        "include_ignored": ck.flag(doc.get("include_ignored"), "include_ignored"),
        "time_limit": limit,
        "checks": out,
    }
