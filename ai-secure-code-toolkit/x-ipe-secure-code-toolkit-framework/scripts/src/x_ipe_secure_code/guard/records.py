"""Validate the agent-recorded plan, evidence/findings/ledger/conflicts and Reviewer records.

Nothing here decides a verdict; validation only refuses malformed or out-of-scope input.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from ..adapters import provided, reserved_helper_id, reserved_helper_name, reserved_id, reserved_name
from ..reviewer import envelope
from .helpers import plan_rules
from .helpers import review as helper_review
from .mask import mask_text
from .model import (
    CONFLICT_KINDS,
    FINDING_RESULTS,
    GUARD_REL,
    ITEM_ID,
    KINDS,
    LINES,
    MAX_CONTENT,
    MAX_CONTENT_FILE,
    MAX_EVIDENCE_TOTAL,
    NA_REASON_TYPES,
    NA_RESULTS,
    NAME,
    SEVERITIES,
    SEVERITY_VALUES,
    STATES,
    Checker,
    GuardError,
)
from .targets import normalize, owning_target, path_role

PLAN_STEP = "Fix the plan file (see the Guard skill references/guard-records.md) and record it again"
RECORD_STEP = "Fix the record file and record it again; nothing from it was stored"
REVIEW_STEP = "Fix the Reviewer record file and record it again"
AUTHORITY_KEYS = (
    "targets",
    "scope",
    "scope_id",
    "plan",
    "ledger",
    "findings",
    "evidence",
    "conflicts",
    "risk_acceptances",
    "exclusions",
)


def _path(ck: Checker, raw: Any, where: str) -> str:
    try:
        return normalize(raw, where)
    except GuardError as exc:
        raise ck.fail(exc.message) from None


def _adopted(state: dict[str, Any]) -> set[str]:
    return {a["rule"] for a in state["scope"]["adopted"]}


def validate_plan(state: dict[str, Any], doc: dict[str, Any]) -> dict[str, Any]:
    """Necessary checks over adopted rules only; every adopted rule is planned, N/A or excluded."""
    ck = Checker("PLAN_INVALID", PLAN_STEP)
    ck.obj(doc, "plan", {"schema", "checks", "not_applicable", "exclusions"})
    doc, gaps = plan_rules.split_plan(doc)  # FEATURE-002-F: additive `gap` for helper methods only
    adopted = _adopted(state)

    def rule(value: Any, where: str) -> str:
        if not isinstance(value, str) or value not in adopted:
            raise ck.fail(f"{where}.rule {value!r} is not in the adopted scope")
        return value

    checks: list[dict[str, Any]] = []
    for i, raw in enumerate(ck.items(doc.get("checks"), "checks")):
        where = f"checks[{i}]"
        ck.obj(
            raw,
            where,
            {
                "id",
                "rule",
                "object",
                "object_part",
                "methods",
                "minimum_evidence",
                "description",
                "method_choice",
            },
            frozenset({"id", "rule"}),
        )
        cid = ck.pattern(raw["id"], f"{where}.id", ITEM_ID)
        if any(c["id"] == cid for c in checks):
            raise ck.fail(f"{where}.id {cid} is a duplicate")
        objects: list[str] = []
        for j, p in enumerate(ck.items(raw.get("object"), f"{where}.object", required=True)):
            rel = _path(ck, p, f"{where}.object[{j}]")
            if owning_target(state["artifact"], rel) is None:
                raise ck.fail(f"{where}.object[{j}] {rel} is not a target or inside a target folder")
            if rel not in objects:
                objects.append(rel)
        methods: list[dict[str, Any]] = []
        for j, m in enumerate(ck.items(raw.get("methods"), f"{where}.methods", required=True)):
            mw = f"{where}.methods[{j}]"
            ck.obj(m, mw, {"name", "kind", "required"}, frozenset({"name", "kind"}))
            name = ck.pattern(m["name"], f"{mw}.name", NAME)
            if any(x["name"] == name for x in methods):
                raise ck.fail(f"{mw}.name {name} is a duplicate")
            kind = ck.choice(m["kind"], f"{mw}.kind", KINDS)
            if reserved_name(name) and (kind != "runtime" or name not in provided()):
                raise ck.fail(
                    f"{mw}: Adapter method must be named exactly {name.casefold()!r} with kind runtime"
                )
            methods.append(
                {
                    "name": name,
                    "kind": kind,
                    "required": ck.flag(m.get("required"), f"{mw}.required", default=True),
                }
            )
        minimum: list[str] = []
        for j, k in enumerate(
            ck.items(raw.get("minimum_evidence"), f"{where}.minimum_evidence", required=True)
        ):
            kind = ck.choice(k, f"{where}.minimum_evidence[{j}]", KINDS)
            if kind not in minimum:
                minimum.append(kind)
        checks.append(
            {
                "id": cid,
                "rule": rule(raw["rule"], where),
                "object": objects,
                "object_part": ck.text(raw.get("object_part"), f"{where}.object_part", required=False),
                "methods": methods,
                "minimum_evidence": minimum,
                "description": ck.text(raw.get("description"), f"{where}.description", required=False),
                "method_choice": _method_choice(ck, raw.get("method_choice"), methods, where),
            }
        )
    planned = {c["rule"] for c in checks}
    not_applicable: list[dict[str, Any]] = []
    for i, raw in enumerate(ck.items(doc.get("not_applicable"), "not_applicable")):
        where = f"not_applicable[{i}]"
        ck.obj(raw, where, {"rule", "reason"}, frozenset({"rule"}))
        r = rule(raw["rule"], where)
        if r in planned or any(n["rule"] == r for n in not_applicable):
            raise ck.fail(f"{where}.rule {r} is already planned or declared not applicable")
        not_applicable.append({"rule": r, "reason": ck.text(raw.get("reason"), f"{where}.reason")})
    exclusions: list[dict[str, Any]] = []
    check_ids = {c["id"] for c in checks}
    for i, raw in enumerate(ck.items(doc.get("exclusions"), "exclusions")):
        where = f"exclusions[{i}]"
        ck.obj(raw, where, {"rule", "check", "reason"})
        if (raw.get("rule") is None) == (raw.get("check") is None):
            raise ck.fail(f"{where} must name exactly one of rule or check")
        r = rule(raw["rule"], where) if raw.get("rule") is not None else None
        c = raw.get("check")
        if c is not None:
            c = ck.key(c, f"{where}.check")
        if c is not None and c not in check_ids:
            raise ck.fail(f"{where}.check {c!r} is not a planned check")
        if r is not None and (r in planned or any(n["rule"] == r for n in not_applicable)):
            raise ck.fail(f"{where}.rule {r} is also planned or declared not applicable")
        exclusions.append({"rule": r, "check": c, "reason": ck.text(raw.get("reason"), f"{where}.reason")})
    covered = planned | {n["rule"] for n in not_applicable} | {e["rule"] for e in exclusions if e["rule"]}
    missing = sorted(adopted - covered)
    if missing:
        raise GuardError(
            "PLAN_INCOMPLETE",
            f"Adopted Policies without a check, N/A reason or user exclusion: {', '.join(missing)}",
            "Plan a check for each, give a factual N/A reason, or record the user's exclusion",
        )
    plan_rules.check_plan(ck, checks, gaps)
    return {
        "checks": checks,
        "not_applicable": not_applicable,
        "exclusions": exclusions,
        "method_changes": [],
    }


def _method_choice(ck: Checker, raw: Any, methods: list[dict[str, Any]], where: str) -> dict[str, Any] | None:
    """Required when a check has several methods or a tool (Adapter) method (FEATURE-002-B)."""
    needed = len(methods) > 1 or any(reserved_name(m["name"]) for m in methods)
    if raw is None:
        if needed:
            raise ck.fail(
                f"{where}.method_choice is required for checks with several methods or a tool method"
            )
        return None
    ck.obj(
        raw,
        f"{where}.method_choice",
        {"considered", "cost", "selected", "reason"},
        frozenset({"considered", "selected", "reason"}),
    )
    names = {m["name"] for m in methods}
    considered = [
        ck.pattern(x, f"{where}.method_choice.considered", NAME)
        for x in ck.items(raw.get("considered"), f"{where}.method_choice.considered", required=True)
    ]
    selected = []
    for x in ck.items(raw.get("selected"), f"{where}.method_choice.selected", required=True):
        if x not in names:
            raise ck.fail(f"{where}.method_choice.selected names {x!r}, which is not a method of the check")
        selected.append(x)
    return {
        "considered": considered,
        "cost": ck.text(raw.get("cost"), f"{where}.method_choice.cost", required=False),
        "selected": selected,
        "reason": ck.text(raw.get("reason"), f"{where}.method_choice.reason"),
    }


def _method_changes(ck: Checker, state: dict[str, Any], new: dict[str, Any], raw_list: Any) -> None:
    """Switches/supplements add a method as auxiliary and are logged with the results present at that time."""
    checks = {c["id"]: c for c in new["plan"]["checks"]}
    log = new["plan"].setdefault("method_changes", [])
    raw_list, gaps = plan_rules.split_changes(raw_list)  # FEATURE-002-F
    start = len(log)
    for i, raw in enumerate(ck.items(raw_list, "method_changes")):
        where = f"method_changes[{i}]"
        ck.obj(
            raw,
            where,
            {"check", "change", "method", "from", "reason"},
            frozenset({"check", "change", "method", "reason"}),
        )
        cid = ck.key(raw["check"], f"{where}.check")
        if cid not in checks:
            raise ck.fail(f"{where}.check: unknown check {cid!r}")
        change = ck.choice(raw["change"], f"{where}.change", ("switch", "supplement"))
        m = ck.obj(raw["method"], f"{where}.method", {"name", "kind"}, frozenset({"name", "kind"}))
        name = ck.pattern(m["name"], f"{where}.method.name", NAME)
        kind = ck.choice(m["kind"], f"{where}.method.kind", KINDS)
        if reserved_name(name) and (kind != "runtime" or name not in provided()):
            raise ck.fail(
                f"{where}: Adapter method must be named exactly {name.casefold()!r} with kind runtime"
            )
        target = checks[cid]
        existing = next((x for x in target["methods"] if x["name"] == name), None)
        if existing is not None and existing["kind"] != kind:
            raise ck.fail(f"{where}: method {name} already exists with kind {existing['kind']}")
        if existing is None:
            target["methods"].append({"name": name, "kind": kind, "required": False})
        choice = target.get("method_choice") or {}
        log.append(
            {
                "check": cid,
                "change": change,
                "method": {"name": name, "kind": kind},
                "from": ck.pattern(raw.get("from"), f"{where}.from", NAME, required=False),
                "reason": ck.text(raw.get("reason"), f"{where}.reason"),
                "selected_before": list(choice.get("selected", [])),
                "evidence_ids": [e["id"] for e in state["evidence"]],
                "finding_ids": [f["id"] for f in state["findings"]],
                "adapter_runs": len(state.get("adapter_runs", [])),
            }
        )
    plan_rules.check_changes(ck, log[start:], gaps)


def _content_file(root: Path, ck: Checker, raw: Any, where: str) -> str:
    rel = _path(ck, raw, where)
    if rel == "." or f"{rel}/".startswith(f"{GUARD_REL}/"):
        raise ck.fail(f"{where} {rel} cannot be used as evidence input")
    current = root
    for part in rel.split("/"):
        current = current / part
        if current.is_symlink():
            raise ck.fail(f"{where} {rel} contains a symbolic link")
    try:
        if not current.is_file():
            raise ck.fail(f"{where} {rel} is not an existing regular file")
        if current.stat().st_size > MAX_CONTENT_FILE:
            raise ck.fail(f"{where} {rel} is larger than {MAX_CONTENT_FILE} bytes")
        return current.read_bytes().decode("utf-8", errors="replace")
    except OSError as exc:
        raise ck.fail(f"{where} {rel} could not be read: {exc}") from None


def _bound(state: dict[str, Any], evidence_ids: list[str], location: str) -> bool:
    """True if one successful evidence item names the location or its owning target."""
    owner = owning_target(state["artifact"], location)
    by_id = {e["id"]: e for e in state["evidence"]}
    return any(
        by_id[e]["method_status"] == "ok" and (location in by_id[e]["paths"] or owner in by_id[e]["paths"])
        for e in evidence_ids
    )


def apply_record(
    root: Path, state: dict[str, Any], doc: dict[str, Any]
) -> tuple[dict, list[tuple[str, str]]]:
    """Validate one record file completely; return the new state and evidence texts to store."""
    ck = Checker("RECORD_INVALID", RECORD_STEP)
    ck.obj(
        doc,
        "record",
        {"schema", "evidence", "findings", "ledger", "conflicts", "method_changes", "attempt", "usage"},
    )
    new = copy.deepcopy(state)
    _method_changes(ck, state, new, doc.get("method_changes"))
    checks = {c["id"]: c for c in new["plan"]["checks"]}
    writes: list[tuple[str, str]] = []
    total = sum(e.get("stored_bytes", 0) for e in new["evidence"])
    for i, raw in enumerate(ck.items(doc.get("evidence"), "evidence")):
        where = f"evidence[{i}]"
        ck.obj(
            raw,
            where,
            {
                "id",
                "kind",
                "method",
                "method_status",
                "checks",
                "paths",
                "lines",
                "summary",
                "content",
                "content_file",
            },
            frozenset({"id", "kind", "method", "method_status", "paths", "summary"}),
        )
        eid = ck.pattern(raw["id"], f"{where}.id", ITEM_ID)
        if reserved_id(eid) or reserved_name(raw.get("method")):
            raise ck.fail(f"{where}: tool evidence is recorded only by secure-code guard tool")
        if reserved_helper_id(eid) or reserved_helper_name(raw.get("method")):
            raise ck.fail(f"{where}: {plan_rules.RESERVED}")
        if any(e["id"].casefold() == eid.casefold() for e in new["evidence"]):
            raise ck.fail(f"{where}.id {eid} is a duplicate")
        kind = ck.choice(raw["kind"], f"{where}.kind", KINDS)
        method = ck.pattern(raw["method"], f"{where}.method", NAME)
        status = ck.choice(raw["method_status"], f"{where}.method_status", ("ok", "failed"))
        check_ids: list[str] = []
        for c in ck.items(raw.get("checks"), f"{where}.checks"):
            c = ck.key(c, f"{where}.checks")
            if c not in checks:
                raise ck.fail(f"{where}.checks refers to unknown check {c!r}")
            declared = next((m for m in checks[c]["methods"] if m["name"] == method), None)
            if declared is None:
                raise ck.fail(f"{where}.method {method} is not a method of check {c}")
            if declared["kind"] != kind:
                raise ck.fail(
                    f"{where}.kind {kind} differs from the kind {declared['kind']} of method {method}"
                )
            if c not in check_ids:
                check_ids.append(c)
        paths: list[str] = []
        for j, p in enumerate(ck.items(raw.get("paths"), f"{where}.paths", required=True)):
            rel = _path(ck, p, f"{where}.paths[{j}]")
            if path_role(new["artifact"], rel) is None:
                raise ck.fail(f"{where}.paths[{j}] {rel} is not a recorded path")
            if rel not in paths:
                paths.append(rel)
        if raw.get("content") is not None and raw.get("content_file") is not None:
            raise ck.fail(f"{where} has both content and content_file")
        body: str | None = None
        if raw.get("content") is not None:
            if not isinstance(raw["content"], str):
                raise ck.fail(f"{where}.content must be text")
            if len(raw["content"]) > MAX_CONTENT:
                raise ck.fail(f"{where}.content is longer than {MAX_CONTENT} characters")
            body = raw["content"]
        elif raw.get("content_file") is not None:
            body = _content_file(root, ck, raw["content_file"], f"{where}.content_file")
        kinds = set(mask_text(raw["summary"])[1]) if isinstance(raw["summary"], str) else set()
        item = {
            "id": eid,
            "kind": kind,
            "method": method,
            "method_status": status,
            "checks": check_ids,
            "paths": paths,
            "lines": ck.pattern(raw.get("lines"), f"{where}.lines", LINES, required=False),
            "summary": ck.text(raw["summary"], f"{where}.summary"),
            "stored": None,
            "stored_bytes": 0,
        }
        if body is not None:
            masked, found = mask_text(body)
            kinds |= set(found)
            data = masked.encode("utf-8", errors="replace")
            total += len(data)
            if total > MAX_EVIDENCE_TOTAL:
                raise GuardError(
                    "EVIDENCE_QUOTA",
                    f"Stored evidence would exceed {MAX_EVIDENCE_TOTAL} bytes",
                    "Store a smaller excerpt or summary of the evidence",
                )
            writes.append((eid, masked))
            item["stored"], item["stored_bytes"] = f"evidence/{eid}.txt", len(data)
        item["masked"], item["masked_types"] = bool(kinds), sorted(kinds)
        new["evidence"].append(item)
    evidence_ids = {e["id"] for e in new["evidence"]}
    adopted = _adopted(new)
    for i, raw in enumerate(ck.items(doc.get("findings"), "findings")):
        where = f"findings[{i}]"
        ck.obj(
            raw,
            where,
            {
                "id",
                "rule",
                "check",
                "location",
                "cwe",
                "title",
                "description",
                "source",
                "severity",
                "evidence",
                "disputed",
                "related",
                "merged_from",
                "merge_evidence",
            },
            frozenset({"id", "rule", "location", "title", "source", "severity"}),
        )
        fid = ck.pattern(raw["id"], f"{where}.id", ITEM_ID)
        if reserved_id(fid) or reserved_name(raw.get("source")):
            raise ck.fail(f"{where}: tool findings are recorded only by secure-code guard tool")
        if reserved_helper_id(fid) or reserved_helper_name(raw.get("source")):
            raise ck.fail(f"{where}: {plan_rules.RESERVED}")
        known = {f["id"]: f for f in new["findings"]}
        if fid in known:
            raise ck.fail(f"{where}.id {fid} is a duplicate")
        ck.key(raw["rule"], f"{where}.rule")
        if raw.get("check") is not None:
            ck.key(raw["check"], f"{where}.check")
        if raw["rule"] not in adopted:
            raise ck.fail(f"{where}.rule {raw['rule']!r} is not in the adopted scope")
        if raw.get("check") is not None and raw["check"] not in checks:
            raise ck.fail(f"{where}.check {raw['check']!r} is not a planned check")
        loc = ck.obj(raw["location"], f"{where}.location", {"path", "line"}, frozenset({"path"}))
        rel = _path(ck, loc["path"], f"{where}.location")
        if owning_target(new["artifact"], rel) is None:
            raise ck.fail(f"{where}.location.path {rel} is not a target or inside a target folder")
        line = loc.get("line")
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            raise ck.fail(f"{where}.location.line must be a positive number")
        merged_from = ck.refs(raw.get("merged_from"), f"{where}.merged_from", known)
        merge_evidence = ck.refs(raw.get("merge_evidence"), f"{where}.merge_evidence", evidence_ids)
        if merged_from and not merge_evidence:
            raise ck.fail(f"{where}.merged_from needs merge_evidence showing the same root cause")
        for source in merged_from:
            if not _bound(new, merge_evidence, known[source]["location"]["path"]):
                raise ck.fail(f"{where}.merge_evidence is not bound to the location of {source}")
        new["findings"].append(
            {
                "id": fid,
                "rule": raw["rule"],
                "check": raw.get("check"),
                "location": {"path": rel, "line": line},
                "cwe": ck.pattern(raw.get("cwe"), f"{where}.cwe", NAME, required=False),
                "title": ck.text(raw["title"], f"{where}.title"),
                "description": ck.text(raw.get("description"), f"{where}.description", required=False),
                "source": ck.pattern(raw["source"], f"{where}.source", NAME),
                "severity": ck.choice(raw["severity"], f"{where}.severity", SEVERITY_VALUES),
                "evidence": ck.refs(raw.get("evidence"), f"{where}.evidence", evidence_ids),
                "disputed": ck.flag(raw.get("disputed"), f"{where}.disputed"),
                "related": ck.refs(raw.get("related"), f"{where}.related", known),
                "merged_from": merged_from,
                "merge_evidence": merge_evidence,
                "merged_into": None,
            }
        )
        for source in merged_from:
            known[source]["merged_into"] = fid
    finding_ids = {f["id"] for f in new["findings"]}
    for i, raw in enumerate(ck.items(doc.get("ledger"), "ledger")):
        where = f"ledger[{i}]"
        ck.obj(
            raw,
            where,
            {"check", "state", "evidence", "findings", "reason", "reason_type"},
            frozenset({"check", "state"}),
        )
        cid = ck.key(raw["check"], f"{where}.check")
        if cid not in checks:
            raise ck.fail(f"{where}.check: unknown check {cid!r}")
        state_value = ck.choice(raw["state"], f"{where}.state", STATES)
        evidence = ck.refs(raw.get("evidence"), f"{where}.evidence", evidence_ids)
        findings = ck.refs(raw.get("findings"), f"{where}.findings", finding_ids)
        reason = ck.text(raw.get("reason"), f"{where}.reason", required=False)
        reason_type = None
        if state_value == "met" and not evidence:
            raise ck.fail(f"{where}: met needs at least one evidence id")
        if state_value == "not_met" and not (evidence or findings):
            raise ck.fail(f"{where}: not_met needs evidence or findings")
        if state_value == "unconfirmed" and not reason:
            raise ck.fail(f"{where}: unconfirmed needs a reason naming what is missing")
        if state_value == "n/a":
            reason_type = ck.choice(raw.get("reason_type"), f"{where}.reason_type", NA_REASON_TYPES)
            if reason_type != "objective":
                raise GuardError(
                    "NA_NOT_OBJECTIVE",
                    f"{where}: {reason_type} is not an objective N/A; "
                    "the check must be recorded as unconfirmed",
                    "Record the check as unconfirmed and name the missing method or evidence",
                )
            if not reason:
                raise ck.fail(f"{where}: n/a needs a factual reason")
        previous = new["ledger"].get(cid)
        new["ledger"][cid] = {
            "state": state_value,
            "evidence": evidence,
            "findings": findings,
            "reason": reason,
            "reason_type": reason_type,
            "superseded": previous["superseded"] + 1 if previous else 0,
        }
    for i, raw in enumerate(ck.items(doc.get("conflicts"), "conflicts")):
        where = f"conflicts[{i}]"
        ck.obj(
            raw,
            where,
            {"id", "kind", "description", "verdict_affecting", "resolved", "resolution", "evidence"},
            frozenset({"id", "kind", "description"}),
        )
        kid = ck.pattern(raw["id"], f"{where}.id", ITEM_ID)
        resolved = ck.flag(raw.get("resolved"), f"{where}.resolved")
        resolution = ck.text(raw.get("resolution"), f"{where}.resolution", required=resolved)
        evidence = ck.refs(raw.get("evidence"), f"{where}.evidence", evidence_ids, required=resolved)
        entry = {
            "id": kid,
            "kind": ck.choice(raw["kind"], f"{where}.kind", CONFLICT_KINDS),
            "description": ck.text(raw["description"], f"{where}.description"),
            "verdict_affecting": ck.flag(raw.get("verdict_affecting"), f"{where}.verdict_affecting", True),
            "resolved": resolved,
            "resolution": resolution,
            "evidence": evidence,
        }
        new["conflicts"] = [c for c in new["conflicts"] if c["id"] != kid] + [entry]
    return new, writes


def _na_ids(state: dict[str, Any]) -> set[str]:
    plan = state["plan"]
    return {c["id"] for c in plan["checks"]} | {f"policy:{n['rule']}" for n in plan["not_applicable"]}


def validate_review(state: dict[str, Any], doc: Any) -> tuple[dict[str, Any], list[str]]:
    """Shared Reviewer envelope; incomplete records are kept (judged invalid at conclusion)."""
    ck = Checker("REVIEW_INVALID", REVIEW_STEP)
    def check_subjects(raw_subjects: list, warnings: list[str]) -> list[dict[str, Any]]:
        findings = {f["id"]: f for f in state["findings"]}
        evidence_ids = {e["id"] for e in state["evidence"]}
        na_ids = _na_ids(state)
        subjects: list[dict[str, Any]] = []
        for i, raw in enumerate(raw_subjects):
            subjects.append(_subject(ck, state, findings, evidence_ids, na_ids, subjects, raw, i, warnings))
        return subjects

    return envelope(
        ck,
        doc,
        authority_keys=AUTHORITY_KEYS,
        allowed_extra={"attempt", "usage"},
        allow_absent=False,
        require_invoked_at=False,
        normalize_path=lambda raw, where: _path(ck, raw, where),
        subjects=check_subjects,
    )


def _subject(
    ck: Checker,
    state: dict[str, Any],
    findings: dict[str, Any],
    evidence_ids: set[str],
    na_ids: set[str],
    subjects: list[dict[str, Any]],
    raw: Any,
    i: int,
    warnings: list[str],
) -> dict[str, Any]:
    if isinstance(raw, dict) and raw.get("type") == "helper":  # FEATURE-002-F (FR-002A-4 extension)
        return helper_review.subject(ck, state, subjects, raw, i, warnings)
    where = f"subjects[{i}]"
    ck.obj(
        raw,
        where,
        {"type", "id", "result", "basis", "evidence", "severity_opinion"},
        frozenset({"type", "id"}),
    )
    kind = ck.choice(raw["type"], f"{where}.type", ("finding", "na_decision"))
    sid = ck.key(raw["id"], f"{where}.id")
    if any(s["type"] == kind and s["id"] == sid for s in subjects):
        raise ck.fail(f"{where} is a duplicate subject")
    evidence = ck.refs(raw.get("evidence"), f"{where}.evidence", evidence_ids)
    result = raw.get("result")
    opinion = None
    if kind == "finding":
        if sid not in findings:
            raise ck.fail(f"{where}.id: unknown finding {sid!r}")
        location = findings[sid]["location"]["path"]
        if result is not None:
            ck.choice(result, f"{where}.result", FINDING_RESULTS)
        if result == "false_positive":
            if not evidence:
                raise ck.fail(f"{where}: false_positive needs evidence")
            if not _bound(state, evidence, location):
                raise ck.fail(f"{where}: false_positive evidence is not bound to the finding location")
        if raw.get("severity_opinion") is not None:
            op = ck.obj(
                raw["severity_opinion"],
                f"{where}.severity_opinion",
                {"severity", "evidence"},
                frozenset({"severity"}),
            )
            op_evidence = ck.refs(op.get("evidence"), f"{where}.severity_opinion.evidence", evidence_ids)
            if op_evidence and not _bound(state, op_evidence, location):
                raise ck.fail(f"{where}.severity_opinion evidence is not bound to the finding location")
            opinion = {
                "severity": ck.choice(op["severity"], f"{where}.severity_opinion.severity", SEVERITIES),
                "evidence": op_evidence,
            }
    else:
        if sid not in na_ids:
            raise ck.fail(f"{where}.id: unknown N/A decision {sid!r}")
        if result is not None:
            ck.choice(result, f"{where}.result", NA_RESULTS)
    if result is None:
        warnings.append(f"{where}.result is missing")
    return {
        "type": kind,
        "id": sid,
        "result": result,
        "basis": ck.text(raw.get("basis"), f"{where}.basis", required=False),
        "evidence": evidence,
        "severity_opinion": opinion,
    }
