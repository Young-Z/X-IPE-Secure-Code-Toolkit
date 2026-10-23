"""Comparability of unpaired findings and difference notes of pairs (FEATURE-002-G, FR-002G-5, BR-09).

Pure functions over validated results. An unpaired finding is comparable against the other run only
when every global condition holds (scope, stability, deletion, Policy, N/A and exclusions) and at least
one covering-check candidate succeeds completely (ledger state, method parity, tool build, rule
configuration, tool data and coverage). A succeeding candidate suppresses the failures of the other
candidates; global failures are always reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..adapters import reserved_name
from .mask import mask_text
from .targets import owning_target, path_role

TEXT = {
    "scope_differs": "artifact scope differs",
    "target_unstable": "target unstable or incomplete in run {role}",
    "location_deleted": "location deleted in the {role} run",
    "policy_differs": "Policy differs",
    "na_other_run": "N/A in the other run",
    "excluded_by_user": "excluded by the user",
    "not_covered": "not covered",
    "check_unconfirmed": "check unconfirmed",
    "run_cancelled": "{role} run cancelled",
    "method_differs": "tool or method differs",
    "tool_data_differs": "tool data differs",
    "tool_coverage_incomplete": "tool coverage incomplete",
}
DIFFERENCE_KINDS = (
    "policy",
    "adapter_build",
    "rule_configuration",
    "include_ignored",
    "tool_data",
    "scanners_mode",
)
COMPONENT_FIELDS = ("state", "content_digest")
METADATA_FIELDS = ("Version", "UpdatedAt", "Digest", "MajorVersion")


def show(value: Any) -> str | None:
    """A value written into a reason or note: text masked, absent shown as None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, tuple):
        value = ", ".join(str(v) for v in value)
    return mask_text(str(value))[0]


def plain(value: Any) -> Any:
    """A recorded list as a tuple of its items (compared by value), other values unchanged."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return tuple(value)


def on_object(path: str, objects: Any) -> bool:
    """Same coverage rule as the engine: equal, the whole project, or inside a folder object."""
    return any(path == o or o == "." or path.startswith(o + "/") for o in objects)


class Run:
    """Pre-indexed read-only view of one validated result."""

    def __init__(self, doc: Any, role: str) -> None:
        self.doc, self.role = doc, role
        self.artifact = doc["artifact"]
        self.targets = {t["path"]: t for t in self.artifact["targets"]}
        self.adopted = {a["rule"]: a for a in doc["scope"]["adopted"]}
        plan = doc["plan"]
        self.checks = sorted(plan["checks"], key=lambda c: c["id"]) if plan is not None else []
        self.check_by_id = {c["id"]: c for c in self.checks}
        self.na = {n["rule"]: n for n in plan["not_applicable"]} if plan is not None else {}
        exclusions = list(plan["exclusions"]) if plan is not None else []
        self.rule_excl = {e["rule"]: e for e in exclusions if e["rule"] is not None}
        self.check_excl = {e["check"] for e in exclusions if e["check"] is not None}
        self.ledger = {row["check"]: row for row in doc["ledger"]}
        self.runs_recorded = "adapter_runs" in doc
        self.runs = {r["n"]: r for r in doc["adapter_runs"]} if self.runs_recorded else {}
        self.evidence = doc["evidence"]
        cancellation = doc["cancellation"] if "cancellation" in doc else None
        self.cancelled = cancellation is not None
        self.suggested = {s["path"] for s in self.artifact["suggested"]}

    def owner(self, path: str) -> Any:
        rel = owning_target(self.artifact, path)
        return self.targets[rel] if rel is not None else None

    def role_of(self, path: str) -> str:
        if path in self.suggested:
            return "suggested"
        return path_role(self.artifact, path) or "not in scope"


@dataclass
class Assessment:
    comparable: bool
    reasons: list[dict[str, Any]] = field(default_factory=list)


def _reason(
    code: str, role: str | None = None, detail: str | None = None, earlier: Any = None, later: Any = None
) -> dict[str, Any]:
    return {
        "code": code,
        "text": TEXT[code].format(role=role or ""),
        "detail": detail,
        "earlier": show(earlier),
        "later": show(later),
    }


def _by_role(own: Run, a: Any, b: Any) -> tuple[Any, Any]:
    """(earlier value, later value) from (own-run value, other-run value)."""
    return (a, b) if own.role == "earlier" else (b, a)


def _global(f: Any, own: Run, other: Run, p_own: str, p_other: str) -> list[dict[str, Any]]:
    reasons = []
    other_target = other.owner(p_other)
    if other_target is None or other.role_of(p_other) != "target":
        e, lt = _by_role(own, own.role_of(p_own), other.role_of(p_other))
        reasons.append(_reason("scope_differs", detail=f"path {show(p_own)}", earlier=e, later=lt))
    own_target = own.owner(p_own)
    for run, target in ((own, own_target), (other, other_target)):
        if target is not None and (target["changed"] or target["incomplete"]):
            flags = f"changed {show(target['changed'])}, incomplete {show(target['incomplete'])}"
            reasons.append(_reason("target_unstable", run.role, f"target {show(target['path'])}: {flags}"))
    for run, target in ((own, own_target), (other, other_target)):
        if target is not None and target["change"] == "deleted":
            reasons.append(_reason("location_deleted", run.role, f"target {show(target['path'])}"))
    rule = f["rule"]
    mine, theirs = own.adopted.get(rule), other.adopted.get(rule)
    if (
        theirs is None
        or theirs["state_digest"] != mine["state_digest"]
        or mine["at_conclusion"] != "unchanged"
        or theirs["at_conclusion"] != "unchanged"
    ):
        e, lt = _by_role(own, _policy_value(mine), _policy_value(theirs))
        reasons.append(_reason("policy_differs", detail=f"rule {show(rule)}", earlier=e, later=lt))
    if rule in other.na:
        reasons.append(_reason("na_other_run", detail=f"rule {show(rule)}: {show(other.na[rule]['reason'])}"))
    if rule in other.rule_excl:
        reasons.append(
            _reason("excluded_by_user", detail=f"rule {show(rule)}: {show(other.rule_excl[rule]['reason'])}")
        )
    return reasons


def _policy_value(adopted: Any) -> str:
    if adopted is None:
        return "not adopted"
    return f"{adopted['state_digest']} ({adopted['at_conclusion']})"


def _state(check: Any, other: Run) -> list[dict[str, Any]]:
    row = other.ledger.get(check["id"])
    state = row["state"] if row is not None else "unconfirmed"
    detail = f"check {check['id']}: {state}" + (f" ({show(row['reason'])})" if row and row["reason"] else "")
    if state in ("met", "not_met"):
        return []
    if state == "unconfirmed":
        reasons = [_reason("check_unconfirmed", detail=detail)]
        if other.cancelled:
            reasons.append(_reason("run_cancelled", other.role, detail=f"check {check['id']}"))
        return reasons
    if state == "n/a":
        return [_reason("na_other_run", detail=detail)]
    return [_reason("excluded_by_user", detail=detail)]


def _rule_config(run: Any, check_id: str, rule_id: str) -> str | None:
    for rule in run.get("rules") or []:
        if rule["check"] == check_id and rule_id in rule["config_digests"]:
            return rule["config_digests"][rule_id]
    return None


def component_view(run: Any, check_id: str) -> dict[str, tuple]:
    """Trivy components used by one check of a run, with their recorded fields."""
    used = run["checks"][check_id].get("components_used") or []
    components = run.get("components") or {}
    view = {}
    for name in used:
        comp = components.get(name)
        if comp is None:
            view[name] = ("not recorded",)
            continue
        meta = comp.get("metadata") or {}
        view[name] = (comp["state"], comp.get("content_digest"), *(meta.get(k) for k in METADATA_FIELDS))
    return view


def _component_text(view: dict[str, tuple]) -> str:
    return "; ".join(f"{name} {', '.join(str(v) for v in values)}" for name, values in sorted(view.items()))


def _tool_candidate(f: Any, own: Run, mine: Any, theirs: Any, check: Any, other: Run) -> list[dict[str, Any]]:
    tool, cid = f["tool"], check["id"]
    where = f"check {cid}, run {theirs['n']}"
    reasons = []
    entry = theirs["checks"][cid]
    if entry["method_status"] != "ok":
        reasons.append(_reason("method_differs", detail=f"{where}: Adapter run did not succeed"))
    for key in ("version", "binary_digest"):
        if mine.get(key) != theirs.get(key):
            e, lt = _by_role(own, mine.get(key), theirs.get(key))
            reasons.append(
                _reason("method_differs", detail=f"{where}: Adapter build {key} differs", earlier=e, later=lt)
            )
    if tool["adapter"] == "opengrep":
        a, b = _rule_config(mine, f["check"], tool["rule_id"]), _rule_config(theirs, cid, tool["rule_id"])
        if a is None or a != b:
            e, lt = _by_role(own, a, b)
            reasons.append(
                _reason("method_differs", detail=f"{where}: rule configuration differs", earlier=e, later=lt)
            )
        if mine.get("include_ignored") != theirs.get("include_ignored"):
            e, lt = _by_role(own, mine.get("include_ignored"), theirs.get("include_ignored"))
            reasons.append(
                _reason(
                    "method_differs", detail=f"{where}: include-ignored setting differs", earlier=e, later=lt
                )
            )
    if tool["adapter"] == "trivy":
        a, b = component_view(mine, f["check"]), component_view(theirs, cid)
        if a != b:
            names = ", ".join(sorted(set(a) | set(b)))
            e, lt = _by_role(own, _component_text(a), _component_text(b))
            reasons.append(
                _reason("tool_data_differs", detail=f"{where}: components {names}", earlier=e, later=lt)
            )
        mine_entry = mine["checks"][f["check"]]
        for key in ("scanners", "mode"):
            a, b = plain(mine_entry.get(key)), plain(entry.get(key))
            if a != b:
                e, lt = _by_role(own, a, b)
                reasons.append(
                    _reason("tool_data_differs", detail=f"{where}: {key} differ", earlier=e, later=lt)
                )
    counts, gaps, gap = entry["counts"], list(entry["gaps"]), theirs["gap"]
    if counts["skipped"] or counts["unaccounted"] or gaps or gap is not None:
        text = (
            f"{where}: scanned {counts['scanned']}, skipped {counts['skipped']}, unaccounted "
            f"{counts['unaccounted']}; gaps: {'; '.join(gaps[:5]) or 'none'}; run gap: "
            + (f"{gap['code']} ({gap['reason']})" if gap is not None else "none")
        )
        reasons.append(_reason("tool_coverage_incomplete", detail=show(text)))
    return reasons


def _semantic_candidate(check: Any, other: Run, p_other: str) -> list[dict[str, Any]]:
    for e in other.evidence:
        if (
            e["method_status"] == "ok"
            and e["kind"] in ("reading", "document")
            and not reserved_name(e["method"])
            and check["id"] in e["checks"]
            and on_object(p_other, e["paths"])
        ):
            return []
    return [
        _reason(
            "method_differs",
            detail=f"check {check['id']}: no successful reading or document evidence on this path",
        )
    ]


def _candidates(f: Any, own: Run, other: Run, p_other: str) -> tuple[bool, list[dict[str, Any]]]:
    checks = [c for c in other.checks if c["rule"] == f["rule"] and on_object(p_other, c["object"])]
    if not checks:
        return False, [_reason("not_covered", detail=f"rule {show(f['rule'])}")]
    results: list[list[dict[str, Any]]] = []
    tool = f.get("tool")
    for check in checks:
        state = _state(check, other)
        if state:
            results.append(state)
            continue
        if tool is None:
            results.append(_semantic_candidate(check, other, p_other))
            continue
        runs = sorted(
            (
                r
                for r in other.runs.values()
                if r["adapter"] == tool["adapter"] and check["id"] in r["checks"]
            ),
            key=lambda r: r["n"],
        )
        if not runs:
            why = (
                f"no {tool['adapter']} run for the covering check {check['id']}"
                if other.runs_recorded
                else f"Adapter runs not recorded in run {other.role}"
            )
            results.append([_reason("method_differs", detail=why)])
        mine = own.runs[tool["run"]]
        results += [_tool_candidate(f, own, mine, theirs, check, other) for theirs in runs]
    if any(not r for r in results):
        return True, []
    return False, [reason for r in results for reason in r]


def assess(f: Any, own: Run, other: Run, p_own: str, p_other: str) -> Assessment:
    """Comparability of one unpaired finding of `own` against `other` (all failing reasons listed)."""
    global_reasons = _global(f, own, other, p_own, p_other)
    succeeded, candidate_reasons = _candidates(f, own, other, p_other)
    return Assessment(not global_reasons and succeeded, dedupe(global_reasons + candidate_reasons))


def dedupe(reasons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {
        (r["code"], r["text"], r["detail"] or "", r["earlier"] or "", r["later"] or ""): r for r in reasons
    }
    return [unique[k] for k in sorted(unique)]


def pair_notes(e: Any, lt: Any, earlier: Run, later: Run) -> list[dict[str, Any]]:
    """Every Policy, tool and tool-data difference of a pair observed in both runs."""
    notes = []

    def note(kind: str, subject: str, a: Any, b: Any) -> None:
        notes.append({"kind": kind, "subject": show(subject), "earlier": show(a), "later": show(b)})

    rule = e["rule"]
    pe, pl = earlier.adopted[rule], later.adopted[rule]
    if (pe["state_digest"], pe["at_conclusion"]) != (pl["state_digest"], pl["at_conclusion"]):
        note("policy", rule, _policy_value(pe), _policy_value(pl))
    te, tl = e.get("tool"), lt.get("tool")
    if te is None or tl is None:
        return notes
    re_, rl = earlier.runs[te["run"]], later.runs[tl["run"]]
    for key in ("version", "binary_digest"):
        if re_.get(key) != rl.get(key):
            note("adapter_build", f"{te['adapter']} {key}", re_.get(key), rl.get(key))
    if te["adapter"] == "opengrep":
        a, b = _rule_config(re_, e["check"], te["rule_id"]), _rule_config(rl, lt["check"], tl["rule_id"])
        if a != b:
            note("rule_configuration", te["rule_id"], a, b)
        if re_.get("include_ignored") != rl.get("include_ignored"):
            note(
                "include_ignored",
                "opengrep include-ignored",
                re_.get("include_ignored"),
                rl.get("include_ignored"),
            )
    if te["adapter"] == "trivy":
        a, b = component_view(re_, e["check"]), component_view(rl, lt["check"])
        for name in sorted(set(a) | set(b)):
            if a.get(name) != b.get(name):
                note(
                    "tool_data",
                    f"trivy component {name}",
                    _component_text({name: a[name]}) if name in a else "not used",
                    _component_text({name: b[name]}) if name in b else "not used",
                )
        ce, cl = re_["checks"][e["check"]], rl["checks"][lt["check"]]
        for key in ("scanners", "mode"):
            a, b = plain(ce.get(key)), plain(cl.get(key))
            if a != b:
                note("scanners_mode", f"trivy {key}", a, b)
    return notes


def _rename_overlap(path_e: str, l_paths: list[str]) -> bool:
    return any(
        p == path_e or p == "." or path_e == "." or path_e.startswith(p + "/") or p.startswith(path_e + "/")
        for p in l_paths
    )


def summary(earlier: Run, later: Run, forward: Any) -> dict[str, Any]:
    """Run-level comparability summary: scope, Policy, coverage, methods, tools and tool data."""
    e_paths = sorted(earlier.targets)
    l_paths = sorted(later.targets)
    mapped = {p: forward(p) for p in e_paths}
    shared = sorted(p for p in e_paths if mapped[p] in later.targets)
    scope = {
        "only_earlier": [show(p) for p in e_paths if mapped[p] not in later.targets],
        "only_later": [show(p) for p in l_paths if p not in set(mapped.values())],
        "shared": [show(p) for p in shared],
        "earlier": _target_flags(earlier),
        "later": _target_flags(later),
        "whole_project": {run.role: run.artifact["whole_project"] for run in (earlier, later)},
    }
    rules = sorted(set(earlier.adopted) | set(later.adopted))
    policy = {
        "only_earlier": [show(r) for r in rules if r not in later.adopted],
        "only_later": [show(r) for r in rules if r not in earlier.adopted],
        "differing": [
            {
                "rule": show(r),
                "earlier": show(_policy_value(earlier.adopted[r])),
                "later": show(_policy_value(later.adopted[r])),
            }
            for r in rules
            if r in earlier.adopted
            and r in later.adopted
            and _policy_value(earlier.adopted[r]) != _policy_value(later.adopted[r])
        ],
    }
    coverage = [
        {"rule": show(r), "earlier": _coverage(earlier, r), "later": _coverage(later, r)} for r in rules
    ]
    methods = {
        run.role: {
            "kinds": sorted({m["kind"] for c in run.checks for m in c["methods"]}),
            "planned": sorted(
                {
                    f"{show(m['name'])} ({m['kind']}, {'required' if m['required'] else 'auxiliary'})"
                    for c in run.checks
                    for m in c["methods"]
                }
            ),
            "adapters": sorted({r["adapter"] for r in run.runs.values()}),
            "adapter_runs": "recorded" if run.runs_recorded else "not recorded in this result",
        }
        for run in (earlier, later)
    }
    tools = {
        run.role: [
            {
                "n": r["n"],
                "adapter": r["adapter"],
                "version": show(r.get("version")),
                "include_ignored": r.get("include_ignored"),
            }
            for r in sorted(run.runs.values(), key=lambda r: r["n"])
        ]
        for run in (earlier, later)
    }
    tool_data = {
        run.role: [
            {"n": r["n"], "check": cid, "components": show(_component_text(component_view(r, cid)))}
            for r in sorted(run.runs.values(), key=lambda r: r["n"])
            if r["adapter"] == "trivy"
            for cid in sorted(r["checks"])
        ]
        for run in (earlier, later)
    }
    return {
        "shared_targets": any(_rename_overlap(mapped[p], l_paths) for p in e_paths),
        "scope": scope,
        "policy": policy,
        "coverage": coverage,
        "methods": methods,
        "tools": tools,
        "tool_data": tool_data,
    }


def _target_flags(run: Run) -> list[dict[str, Any]]:
    return [
        {"path": show(p), "change": t["change"], "changed": t["changed"], "incomplete": t["incomplete"]}
        for p, t in sorted(run.targets.items())
    ]


def _coverage(run: Run, rule: str) -> dict[str, Any]:
    states: dict[str, int] = {}
    planned = [c for c in run.checks if c["rule"] == rule]
    for c in planned:
        row = run.ledger.get(c["id"])
        if row is not None:
            states[row["state"]] = states.get(row["state"], 0) + 1
    na = run.na.get(rule)
    excl = run.rule_excl.get(rule)
    return {
        "adopted": rule in run.adopted,
        "planned_checks": len(planned),
        "not_applicable": show(na["reason"]) if na is not None else None,
        "excluded": show(excl["reason"]) if excl is not None else None,
        "excluded_checks": sorted(c["id"] for c in planned if c["id"] in run.check_excl),
        "states": dict(sorted(states.items())),
    }
