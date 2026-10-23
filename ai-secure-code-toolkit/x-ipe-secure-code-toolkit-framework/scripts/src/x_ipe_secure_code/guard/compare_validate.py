"""Strict validation of every consumed `guard-result/v1` field (FEATURE-002-G, FR-002G-2a).

`validate(doc, file_id)` raises `Invalid(rule, path)` for the first violation and never names a value.
Phase 1 checks every leaf of the consumed-leaf contract `CONTRACT` (presence, JSON type, enum and
format), in contract order; phase 2 checks uniqueness, referential integrity, target changes and
merges. Unconsumed keys are ignored (they still take part in the integrity checks).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from ..adapters import provided, reserved_name
from . import model
from .compare_bounds import Invalid, key_part
from .targets import owning_target

__all__ = ["CONTRACT", "VALIDATION_ONLY", "Invalid", "Leaf", "validate"]

# Value-set extensions the delivered writers emit beyond the model constants (DEC-06 A).
LEDGER_STATES = (*model.STATES, "excluded")  # engine._ledger writes "excluded" for user exclusions
REVIEW_RESULTS = (*model.FINDING_RESULTS, "not_required")  # engine._findings: no review needed
VERDICTS = ("pass", "fail", "cannot_confirm_pass")
AT_CONCLUSION = ("unchanged", "changed", "missing")
STATUS = ("ok", "failed")
ENTRY_KINDS = ("file", "dir")
SCANNERS = ("vuln", "misconfig", "secret")
MODES = ("filesystem", "image_archive")
DIGEST_AT_OPEN = ("unreadable",)  # targets.snapshot sentinel
DIGEST_AT_CONCLUSION = ("missing", "unreadable", "unsafe")  # engine.conclude / targets.observe sentinels

TIMESTAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
REASON_CODE = re.compile(r"[A-Z_]{1,40}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MASK_MARKER = re.compile(r"\[masked:[a-z_.]+\]")

STR, INT, BOOL, NUL, OBJ, LST = "str", "int", "bool", "null", "object", "list"


@dataclass(frozen=True)
class Leaf:
    """One consumed field: pattern (`[*]` list items, `{*}` data-keyed map), JSON kinds, value rule."""

    pattern: str
    kinds: tuple[str, ...]
    rule: str | None = None
    values: tuple[Any, ...] | None = None
    optional: bool = False


def _leaf(pattern: str, kinds: str, rule: str | None = None, values: Any = None, optional: bool = False):
    return Leaf(
        pattern, tuple(kinds.split("|")), rule, tuple(values) if values is not None else None, optional
    )


F = "$.findings[*]"
T = "$.artifact.targets[*]"
AR = "$.adapter_runs[*]"
CONTRACT: tuple[Leaf, ...] = (
    _leaf("$.schema", STR),
    _leaf("$.verification_id", STR, "format.run_id"),
    _leaf("$.opened_at", STR, "format.timestamp"),
    _leaf("$.ended_at", STR, "format.timestamp"),
    _leaf("$.verdict", STR, "enum", VERDICTS),
    _leaf("$.reasons", LST),
    _leaf("$.reasons[*]", OBJ),
    _leaf("$.reasons[*].code", STR, "format.code"),
    _leaf("$.reasons[*].subject", STR, "format.text"),
    _leaf("$.reasons[*].detail", STR, "format.text"),
    _leaf("$.scope", OBJ),
    _leaf("$.scope.adopted", LST),
    _leaf("$.scope.adopted[*]", OBJ),
    _leaf("$.scope.adopted[*].rule", STR, "format.rule"),
    _leaf("$.scope.adopted[*].state_digest", STR, "format.digest"),
    _leaf("$.scope.adopted[*].at_conclusion", STR, "enum", AT_CONCLUSION),
    _leaf("$.artifact", OBJ),
    _leaf("$.artifact.whole_project", BOOL),
    _leaf("$.artifact.targets", LST),
    _leaf(T, OBJ),
    _leaf(f"{T}.path", STR, "format.path"),
    _leaf(f"{T}.kind", f"{STR}|{NUL}", "enum", ENTRY_KINDS),
    _leaf(f"{T}.change", STR, "enum", model.CHANGES),
    _leaf(f"{T}.old_path", f"{STR}|{NUL}", "format.path"),
    _leaf(f"{T}.digest_at_open", f"{STR}|{NUL}", "format.digest", DIGEST_AT_OPEN),
    _leaf(f"{T}.digest_at_conclusion", f"{STR}|{NUL}", "format.digest", DIGEST_AT_CONCLUSION),
    _leaf(f"{T}.changed", BOOL),
    _leaf(f"{T}.incomplete", BOOL),
    _leaf("$.artifact.context", LST),
    _leaf("$.artifact.context[*]", OBJ),
    _leaf("$.artifact.context[*].path", STR, "format.path"),
    _leaf("$.artifact.context[*].kind", STR, "enum", ENTRY_KINDS),
    _leaf("$.artifact.copilot_reports", LST),
    _leaf("$.artifact.copilot_reports[*]", OBJ),
    _leaf("$.artifact.copilot_reports[*].path", STR, "format.path"),
    _leaf("$.artifact.copilot_reports[*].kind", STR, "enum", ENTRY_KINDS),
    _leaf("$.artifact.suggested", LST),
    _leaf("$.artifact.suggested[*]", OBJ),
    _leaf("$.artifact.suggested[*].path", STR, "format.path"),
    _leaf("$.plan", f"{OBJ}|{NUL}"),
    _leaf("$.plan.checks", LST),
    _leaf("$.plan.checks[*]", OBJ),
    _leaf("$.plan.checks[*].id", STR, "format.id"),
    _leaf("$.plan.checks[*].rule", STR, "format.rule"),
    _leaf("$.plan.checks[*].object", LST),
    _leaf("$.plan.checks[*].object[*]", STR, "format.path"),
    _leaf("$.plan.checks[*].methods", LST),
    _leaf("$.plan.checks[*].methods[*]", OBJ),
    _leaf("$.plan.checks[*].methods[*].name", STR, "format.name"),
    _leaf("$.plan.checks[*].methods[*].kind", STR, "enum", model.KINDS),
    _leaf("$.plan.checks[*].methods[*].required", BOOL),
    _leaf("$.plan.not_applicable", LST),
    _leaf("$.plan.not_applicable[*]", OBJ),
    _leaf("$.plan.not_applicable[*].rule", STR, "format.rule"),
    _leaf("$.plan.not_applicable[*].reason", STR, "format.text"),
    _leaf("$.plan.exclusions", LST),
    _leaf("$.plan.exclusions[*]", OBJ),
    _leaf("$.plan.exclusions[*].rule", f"{STR}|{NUL}", "format.rule"),
    _leaf("$.plan.exclusions[*].check", f"{STR}|{NUL}", "format.id"),
    _leaf("$.plan.exclusions[*].reason", STR, "format.text"),
    _leaf("$.ledger", LST),
    _leaf("$.ledger[*]", OBJ),
    _leaf("$.ledger[*].check", STR, "format.ledger_check"),
    _leaf("$.ledger[*].rule", STR, "format.rule"),
    _leaf("$.ledger[*].state", STR, "enum", LEDGER_STATES),
    _leaf("$.ledger[*].reason", f"{STR}|{NUL}", "format.text"),
    _leaf("$.ledger[*].findings", LST),
    _leaf("$.ledger[*].findings[*]", STR, "format.id"),
    _leaf("$.evidence", LST),
    _leaf("$.evidence[*]", OBJ),
    _leaf("$.evidence[*].id", STR, "format.id"),
    _leaf("$.evidence[*].kind", STR, "enum", model.KINDS),
    _leaf("$.evidence[*].method", STR, "format.name"),
    _leaf("$.evidence[*].method_status", STR, "enum", STATUS),
    _leaf("$.evidence[*].checks", LST),
    _leaf("$.evidence[*].checks[*]", STR, "format.id"),
    _leaf("$.evidence[*].paths", LST),
    _leaf("$.evidence[*].paths[*]", STR, "format.path"),
    _leaf("$.findings", LST),
    _leaf(F, OBJ),
    _leaf(f"{F}.id", STR, "format.id"),
    _leaf(f"{F}.rule", STR, "format.rule"),
    _leaf(f"{F}.check", f"{STR}|{NUL}", "format.id"),
    _leaf(f"{F}.location", OBJ),
    _leaf(f"{F}.location.path", STR, "format.location"),
    _leaf(f"{F}.location.line", f"{INT}|{NUL}", "range.positive"),
    _leaf(f"{F}.cwe", f"{STR}|{NUL}", "format.name"),
    _leaf(f"{F}.title", STR, "format.bounded_text"),
    _leaf(f"{F}.description", f"{STR}|{NUL}", "format.bounded_text"),
    _leaf(f"{F}.source", STR, "format.name"),
    _leaf(f"{F}.original_severity", STR, "enum", model.SEVERITY_VALUES),
    _leaf(f"{F}.final_severity", STR, "enum", model.SEVERITY_VALUES),
    _leaf(f"{F}.review", STR, "enum", REVIEW_RESULTS),
    _leaf(f"{F}.merged_into", f"{STR}|{NUL}", "format.id"),
    _leaf(f"{F}.merged_from", LST),
    _leaf(f"{F}.merged_from[*]", STR, "format.id"),
    _leaf(f"{F}.tool", OBJ, optional=True),
    _leaf(f"{F}.tool.adapter", STR, "enum", provided()),
    _leaf(f"{F}.tool.run", INT, "range.positive"),
    _leaf(f"{F}.tool.rule_id", STR, "format.rule"),
    _leaf(f"{F}.tool.fingerprint", f"{STR}|{NUL}", optional=True),
    _leaf(f"{F}.tool.tool_severity", f"{STR}|{NUL}", "format.text"),
    _leaf(f"{F}.tool.scanner", STR, "enum", SCANNERS, optional=True),
    _leaf(f"{F}.tool.pkg_path", f"{STR}|{NUL}", "format.text", optional=True),
    _leaf(f"{F}.tool.package", OBJ, optional=True),
    _leaf(f"{F}.tool.package.name", f"{STR}|{NUL}", "format.text", optional=True),
    _leaf(f"{F}.tool.package.installed", f"{STR}|{NUL}", "format.text", optional=True),
    _leaf("$.risk_acceptances", LST),
    _leaf("$.risk_acceptances[*]", OBJ),
    _leaf("$.risk_acceptances[*].finding", STR, "format.id"),
    _leaf("$.risk_acceptances[*].reason", STR, "format.text"),
    _leaf("$.risk_acceptances[*].role", STR, "format.text"),
    _leaf("$.risk_acceptances[*].recorded_at", STR, "format.timestamp"),
    _leaf("$.adapter_runs", LST, optional=True),
    _leaf(AR, OBJ),
    _leaf(f"{AR}.n", INT, "range.positive"),
    _leaf(f"{AR}.adapter", STR, "enum", provided()),
    _leaf(f"{AR}.version", STR, "format.short", optional=True),
    _leaf(f"{AR}.binary_digest", STR, "format.short", optional=True),
    _leaf(f"{AR}.include_ignored", BOOL, optional=True),
    _leaf(f"{AR}.gap", f"{OBJ}|{NUL}"),
    _leaf(f"{AR}.gap.code", STR, "format.text"),
    _leaf(f"{AR}.gap.reason", STR, "format.text"),
    _leaf(f"{AR}.checks", OBJ),
    _leaf(f"{AR}.checks{{*}}", OBJ),
    _leaf(f"{AR}.checks{{*}}.method_status", STR, "enum", STATUS),
    _leaf(f"{AR}.checks{{*}}.counts", OBJ),
    _leaf(f"{AR}.checks{{*}}.counts.scanned", INT, "range.count"),
    _leaf(f"{AR}.checks{{*}}.counts.skipped", INT, "range.count"),
    _leaf(f"{AR}.checks{{*}}.counts.unaccounted", INT, "range.count"),
    _leaf(f"{AR}.checks{{*}}.gaps", LST),
    _leaf(f"{AR}.checks{{*}}.gaps[*]", STR, "format.text"),
    _leaf(f"{AR}.checks{{*}}.scanners", LST, optional=True),
    _leaf(f"{AR}.checks{{*}}.scanners[*]", STR, "enum", SCANNERS),
    _leaf(f"{AR}.checks{{*}}.mode", STR, "enum", MODES, optional=True),
    _leaf(f"{AR}.checks{{*}}.components_used", LST, optional=True),
    _leaf(f"{AR}.checks{{*}}.components_used[*]", STR, "format.text"),
    _leaf(f"{AR}.rules", LST, optional=True),
    _leaf(f"{AR}.rules[*]", OBJ),
    _leaf(f"{AR}.rules[*].check", STR, "format.id"),
    _leaf(f"{AR}.rules[*].config_digests", OBJ),
    _leaf(f"{AR}.rules[*].config_digests{{*}}", STR, "format.digest"),
    _leaf(f"{AR}.components", OBJ, optional=True),
    _leaf(f"{AR}.components{{*}}", OBJ),
    _leaf(f"{AR}.components{{*}}.state", STR, "format.text"),
    _leaf(f"{AR}.components{{*}}.content_digest", f"{STR}|{NUL}", "format.text", optional=True),
    _leaf(f"{AR}.components{{*}}.metadata", f"{OBJ}|{NUL}", optional=True),
    _leaf(f"{AR}.components{{*}}.metadata.Version", f"{STR}|{INT}|{NUL}", "format.short", optional=True),
    _leaf(f"{AR}.components{{*}}.metadata.UpdatedAt", f"{STR}|{INT}|{NUL}", "format.short", optional=True),
    _leaf(f"{AR}.components{{*}}.metadata.Digest", f"{STR}|{INT}|{NUL}", "format.short", optional=True),
    _leaf(f"{AR}.components{{*}}.metadata.MajorVersion", f"{STR}|{INT}|{NUL}", "format.short", optional=True),
    _leaf("$.cancellation", f"{OBJ}|{NUL}", optional=True),
    _leaf("$.cancellation.requested_at", STR, "format.timestamp"),
    _leaf("$.cancellation.reason", f"{STR}|{NUL}", "format.text"),
)

# Leaves read only by the validator's referential rules, never by the comparison or its Markdown.
VALIDATION_ONLY = frozenset(
    {
        "$.schema",
        "$.artifact.targets[*].digest_at_open",
        "$.ledger[*].rule",
        "$.ledger[*].findings",
        "$.ledger[*].findings[*]",
        "$.evidence[*].id",
        "$.risk_acceptances[*].role",
    }
)


# ------------------------------------------------------------------------------------------ phase 1
def _kind(value: Any) -> str:
    if value is None:
        return NUL
    if isinstance(value, bool):
        return BOOL
    if isinstance(value, int):
        return INT
    if isinstance(value, str):
        return STR
    if isinstance(value, dict):
        return OBJ
    if isinstance(value, list):
        return LST
    return "other"


def _valid_time(text: str) -> bool:
    if not TIMESTAMP.fullmatch(text):
        return False
    try:
        model.parse_time(text)
    except ValueError:
        return False
    return True


def valid_path(text: str, *, dot: bool = True) -> bool:
    """Project-relative POSIX path (`.` alone is the whole project)."""
    if not text or text.startswith("/") or "\\" in text or _CONTROL.search(text):
        return False
    if text == ".":
        return dot
    return all(part not in ("", ".", "..") for part in text.split("/"))


def _text(text: str) -> bool:
    return "\x00" not in text


FORMATS: dict[str, Callable[[str], bool]] = {
    "format.run_id": lambda v: bool(model.RUN_ID.fullmatch(v)),
    "format.timestamp": _valid_time,
    "format.digest": lambda v: bool(model.DIGEST.fullmatch(v)),
    "format.path": valid_path,
    "format.location": lambda v: valid_path(v, dot=False),
    "format.id": lambda v: bool(model.ITEM_ID.fullmatch(v)),
    "format.name": lambda v: bool(model.NAME.fullmatch(v)),
    "format.code": lambda v: bool(REASON_CODE.fullmatch(v)),
    "format.rule": lambda v: 0 < len(v) <= 200 and not _CONTROL.search(v),
    "format.ledger_check": lambda v: (
        bool(model.ITEM_ID.fullmatch(v))
        or any(v.startswith(p) and FORMATS["format.rule"](v[len(p) :]) for p in ("policy:", "rule:"))
    ),
    "format.text": _text,
    # The writer bounds titles/descriptions to MAX_TEXT characters before masking; markers may add length.
    "format.bounded_text": lambda v: _text(v) and len(_MASK_MARKER.sub("", v)) <= model.MAX_TEXT,
    "format.short": lambda v: not isinstance(v, str) or (len(v) <= 200 and _text(v)),
}


def _value_ok(leaf: Leaf, value: Any) -> bool:
    if leaf.rule is None or value is None:
        return True
    if leaf.rule == "enum":
        return value in leaf.values
    if leaf.rule in ("range.positive", "range.count"):
        return value >= (1 if leaf.rule == "range.positive" else 0)
    if leaf.values is not None and value in leaf.values:  # writer sentinels (target digests)
        return True
    if not isinstance(value, str) and leaf.rule != "format.short":
        return True
    return FORMATS[leaf.rule](value)


def _segments(pattern: str) -> list[str]:
    return re.findall(r"\[\*\]|\{\*\}|\.[^.\[{]+", pattern[1:])


def instances(doc: Any, pattern: str) -> Iterator[tuple[Any, str, bool]]:
    """(value, JSON path, present) of every instance of a pattern; absent last keys are yielded once."""
    segments = _segments(pattern)
    current: list[tuple[Any, str]] = [(doc, "$")]
    for depth, seg in enumerate(segments):
        last = depth == len(segments) - 1
        nxt: list[tuple[Any, str]] = []
        for value, path in current:
            if seg == "[*]":
                if isinstance(value, list):
                    nxt += [(item, f"{path}[{i}]") for i, item in enumerate(value)]
            elif seg == "{*}":
                if isinstance(value, dict):
                    nxt += [(value[k], path + key_part(k, i)) for i, k in enumerate(sorted(value))]
            elif isinstance(value, dict):
                key = seg[1:]
                if key in value:
                    nxt.append((value[key], f"{path}.{key}"))
                elif last:
                    yield None, f"{path}.{key}", False
        current = nxt
    for value, path in current:
        yield value, path, True


def _phase1(doc: dict[str, Any]) -> None:
    for leaf in CONTRACT:
        for value, path, present in instances(doc, leaf.pattern):
            if not present:
                if not leaf.optional:
                    raise Invalid("required", path)
                continue
            if _kind(value) not in leaf.kinds:
                raise Invalid("type", path)
            if not _value_ok(leaf, value):
                raise Invalid(leaf.rule, path)


# ------------------------------------------------------------------------------------------ phase 2
def _unique(items: list[Any], rule: str, path: str, field: str | None = None) -> None:
    seen: set[Any] = set()
    for i, item in enumerate(items):
        value = item[field] if field else item
        if value in seen:
            raise Invalid(rule, f"{path}[{i}]" + (f".{field}" if field else ""))
        seen.add(value)


def _targets(doc: dict[str, Any]) -> None:
    art = doc["artifact"]
    targets = art["targets"]
    _unique(targets, "unique.target_path", "$.artifact.targets", "path")
    olds: set[str] = set()
    for i, t in enumerate(targets):
        where = f"$.artifact.targets[{i}]"
        if t["path"] == "." and not (art["whole_project"] and t["kind"] == "dir"):
            raise Invalid("format.path", f"{where}.path")
        if (t["change"] == "renamed") != (t["old_path"] is not None):
            raise Invalid("target.renamed_old_path", f"{where}.old_path")
        if t["old_path"] is not None:
            if t["old_path"] in olds:
                raise Invalid("target.old_path_unique", f"{where}.old_path")
            olds.add(t["old_path"])
        deleted = t["change"] == "deleted"
        if deleted and (t["digest_at_open"] is not None or t["kind"] is not None):
            raise Invalid("target.deleted_digest", f"{where}.digest_at_open")
        if not deleted and (t["digest_at_open"] is None or t["kind"] is None):
            raise Invalid("target.deleted_digest", f"{where}.digest_at_open")
        if t["changed"] != (t["digest_at_open"] != t["digest_at_conclusion"]):
            raise Invalid("target.changed_flag", f"{where}.changed")


def _plan(doc: dict[str, Any], adopted: set[str]) -> dict[str, str]:
    plan = doc["plan"]
    if plan is None:
        if doc["ledger"]:
            raise Invalid("ref.plan_missing", "$.ledger")
        if doc["findings"]:
            raise Invalid("ref.plan_missing", "$.findings")
        return {}
    checks = plan["checks"]
    _unique(checks, "unique.check_id", "$.plan.checks", "id")
    for i, c in enumerate(checks):
        if c["rule"] not in adopted:
            raise Invalid("ref.check_rule", f"$.plan.checks[{i}].rule")
        for j, obj in enumerate(c["object"]):
            if owning_target(doc["artifact"], obj) is None:
                raise Invalid("ref.object_target", f"$.plan.checks[{i}].object[{j}]")
    rules = {c["id"]: c["rule"] for c in checks}
    planned_rules = set(rules.values())
    na_rules: set[str] = set()
    for i, na in enumerate(plan["not_applicable"]):
        if na["rule"] not in adopted or na["rule"] in planned_rules or na["rule"] in na_rules:
            raise Invalid("ref.na_rule", f"$.plan.not_applicable[{i}].rule")
        na_rules.add(na["rule"])
    for i, ex in enumerate(plan["exclusions"]):
        where = f"$.plan.exclusions[{i}]"
        if (ex["rule"] is None) == (ex["check"] is None):
            raise Invalid("ref.exclusion_rule", f"{where}.rule")
        if ex["rule"] is not None and (
            ex["rule"] not in adopted or ex["rule"] in planned_rules or ex["rule"] in na_rules
        ):
            raise Invalid("ref.exclusion_rule", f"{where}.rule")
        if ex["check"] is not None and ex["check"] not in rules:
            raise Invalid("ref.exclusion_check", f"{where}.check")
    return rules


def _ledger(doc: dict[str, Any], rules: dict[str, str], finding_ids: set[str]) -> None:
    plan = doc["plan"] or {"not_applicable": [], "exclusions": []}
    na_rules = {n["rule"] for n in plan["not_applicable"]}
    rule_excl = {e["rule"] for e in plan["exclusions"] if e["rule"] is not None}
    check_excl = {e["check"] for e in plan["exclusions"] if e["check"] is not None}
    rows = doc["ledger"]
    _unique(rows, "unique.ledger_check", "$.ledger", "check")
    for i, row in enumerate(rows):
        where = f"$.ledger[{i}]"
        check, state = row["check"], row["state"]
        if check in rules:
            expected, shape = rules[check], (state == "excluded") == (check in check_excl)
        elif check.startswith("policy:") and check[7:] in na_rules:
            expected, shape = check[7:], state in ("n/a", "unconfirmed")
        elif check.startswith("rule:") and check[5:] in rule_excl:
            expected, shape = check[5:], state == "excluded"
        else:
            raise Invalid("ref.ledger_check", f"{where}.check")
        if row["rule"] != expected:
            raise Invalid("ref.ledger_rule", f"{where}.rule")
        if not shape:
            raise Invalid("ledger.state_shape", f"{where}.state")
        for j, fid in enumerate(row["findings"]):
            if fid not in finding_ids:
                raise Invalid("ref.ledger_finding", f"{where}.findings[{j}]")
    present = {row["check"] for row in rows}
    if any(cid not in present for cid in rules):
        raise Invalid("ref.ledger_missing", "$.ledger")


def _evidence(doc: dict[str, Any], rules: dict[str, str]) -> None:
    _unique(doc["evidence"], "unique.evidence_id", "$.evidence", "id")
    for i, e in enumerate(doc["evidence"]):
        for j, cid in enumerate(e["checks"]):
            if cid not in rules:
                raise Invalid("ref.evidence_check", f"$.evidence[{i}].checks[{j}]")


def _findings(doc: dict[str, Any], adopted: set[str], rules: dict[str, str]) -> None:
    findings = doc["findings"]
    _unique(findings, "unique.finding_id", "$.findings", "id")
    runs = {r["n"]: r for r in doc.get("adapter_runs") or []}
    for i, f in enumerate(findings):
        where = f"$.findings[{i}]"
        if f["rule"] not in adopted:
            raise Invalid("ref.finding_rule", f"{where}.rule")
        tool = f.get("tool")
        if (f["check"] is not None or tool is not None) and rules.get(f["check"]) != f["rule"]:
            raise Invalid("ref.finding_check", f"{where}.check")
        if owning_target(doc["artifact"], f["location"]["path"]) is None:
            raise Invalid("ref.finding_target", f"{where}.location.path")
        if tool is None:
            if reserved_name(f["source"]):
                raise Invalid("ref.tool_source", f"{where}.source")
            continue
        run = runs.get(tool["run"])
        if run is None:
            raise Invalid("ref.tool_run", f"{where}.tool.run")
        if run["adapter"] != tool["adapter"]:
            raise Invalid("ref.tool_adapter", f"{where}.tool.adapter")
        if f["source"] != tool["adapter"]:
            raise Invalid("ref.tool_source", f"{where}.source")
        if f["check"] not in run["checks"]:
            raise Invalid("ref.tool_check", f"{where}.check")
        if tool["adapter"] == "trivy":
            if "scanner" not in tool:
                raise Invalid("required", f"{where}.tool.scanner")
            if tool["scanner"] == "vuln":
                for key in ("package", "pkg_path"):
                    if key not in tool:
                        raise Invalid("required", f"{where}.tool.{key}")
                for key in ("name", "installed"):
                    if key not in tool["package"]:
                        raise Invalid("required", f"{where}.tool.package.{key}")


def _merges(doc: dict[str, Any]) -> None:
    by_id = {f["id"]: f for f in doc["findings"]}
    for i, f in enumerate(doc["findings"]):
        where = f"$.findings[{i}]"
        target = f["merged_into"]
        if target is not None:
            if target not in by_id:
                raise Invalid("merge.unknown", f"{where}.merged_into")
            if target == f["id"]:
                raise Invalid("merge.self", f"{where}.merged_into")
        for j, source in enumerate(f["merged_from"]):
            if source not in by_id:
                raise Invalid("merge.unknown", f"{where}.merged_from[{j}]")
            if source == f["id"]:
                raise Invalid("merge.self", f"{where}.merged_from[{j}]")
    for i, f in enumerate(doc["findings"]):
        where = f"$.findings[{i}]"
        seen, current = {f["id"]}, f["merged_into"]
        while current is not None:
            if current in seen:
                raise Invalid("merge.cycle", f"{where}.merged_into")
            seen.add(current)
            current = by_id[current]["merged_into"]
        if f["merged_into"] is not None and f["id"] not in by_id[f["merged_into"]]["merged_from"]:
            raise Invalid("merge.backref", f"{where}.merged_into")


def _adapter_runs(doc: dict[str, Any], rules: dict[str, str]) -> None:
    runs = doc.get("adapter_runs") or []
    _unique(runs, "unique.adapter_run", "$.adapter_runs", "n")
    for i, run in enumerate(runs):
        where = f"$.adapter_runs[{i}]"
        for k, cid in enumerate(sorted(run["checks"])):
            if cid not in rules:
                raise Invalid("ref.adapter_run_check", f"{where}.checks" + key_part(cid, k))
        for j, rule in enumerate(run.get("rules") or []):
            if rule["check"] not in rules:
                raise Invalid("ref.adapter_run_check", f"{where}.rules[{j}].check")


def validate(doc: dict[str, Any], file_id: str) -> None:
    """Refuse (raise `Invalid`) unless every consumed field of the result satisfies the contract."""
    _phase1(doc)
    if doc["verification_id"] != file_id:
        raise Invalid("id.file_name", "$.verification_id")
    if model.parse_time(doc["ended_at"]) < model.parse_time(doc["opened_at"]):
        raise Invalid("order.timestamps", "$.ended_at")
    adopted_list = doc["scope"]["adopted"]
    _unique(adopted_list, "unique.adopted_rule", "$.scope.adopted", "rule")
    adopted = {a["rule"] for a in adopted_list}
    _targets(doc)
    rules = _plan(doc, adopted)
    _adapter_runs(doc, rules)
    finding_ids = {f["id"] for f in doc["findings"]}
    _ledger(doc, rules, finding_ids)
    _evidence(doc, rules)
    _findings(doc, adopted, rules)
    _merges(doc)
    for i, acc in enumerate(doc["risk_acceptances"]):
        if acc["finding"] not in finding_ids:
            raise Invalid("ref.risk_acceptance_finding", f"$.risk_acceptances[{i}].finding")
