"""Identity, pairing and classification of two validated Guard results (FEATURE-002-G, FR-002G-3…6).

`build(earlier, later, facts)` is a pure function: it returns the comparison document without its
comparison id and creation time. Identity uses recorded facts only (never run-local ids, titles or
`tool.secret`); every non-exact pairing is labelled; comparability gates only unpaired findings.
"""

from __future__ import annotations

import json
import re
from typing import Any

from . import compare_cover as cover
from .compare_cover import Run, show
from .compare_render import IDENTITY_RULES, LIMITS, SCHEMA, STATEMENTS, masked

VALID_FP = re.compile(r"[0-9a-f]{16,128}")
CLASSES = ("new", "still_present", "not_observed_this_time", "not_comparable")
WEAK = "semantic identity (weak)"


class Item:
    """One non-merged finding of one run with its identity key in the later run's namespace."""

    def __init__(self, role: str, finding: Any, index: int, path_star: str) -> None:
        self.role, self.f, self.index = role, finding, index
        self.path = finding["location"]["path"]
        self.path_star = path_star
        self.line = finding["location"]["line"]
        tool = finding.get("tool")
        fp = tool.get("fingerprint") if tool is not None else None
        self.fp = fp if isinstance(fp, str) and VALID_FP.fullmatch(fp) else None
        self.key = identity(finding, path_star)
        self.merged: list[str] = []


def identity(f: Any, path: str | None) -> tuple:
    """Identity key (BR-06, BR-07); `path` is the path after declared-rename mapping."""
    tool = f.get("tool")
    if tool is None:
        return ("semantic", f["rule"], f["source"], path, f["cwe"])
    if tool["adapter"] == "trivy":
        scanner = tool["scanner"]
        if scanner == "vuln":
            return (
                "tool",
                f["rule"],
                "trivy",
                "vuln",
                tool["rule_id"],
                path,
                tool["package"]["name"],
                tool["pkg_path"],
            )
        return ("tool", f["rule"], "trivy", scanner, tool["rule_id"], path)
    return ("tool", f["rule"], tool["adapter"], tool["rule_id"], path)


def identity_object(key: tuple) -> dict[str, Any]:
    if key[0] == "semantic":
        _, rule, source, path, cwe = key
        return {
            "kind": "semantic",
            "rule": show(rule),
            "source": show(source),
            "path": show(path),
            "cwe": show(cwe),
        }
    obj = {"kind": "tool", "rule": show(key[1]), "adapter": key[2]}
    if key[2] == "trivy":
        obj.update(scanner=key[3], rule_id=show(key[4]), path=show(key[5]))
        if key[3] == "vuln":
            obj.update(package=show(key[6]), pkg_path=show(key[7]))
    else:
        obj.update(rule_id=show(key[3]), path=show(key[4]))
    return obj


def _without_path(key: tuple) -> tuple:
    index = 3 if key[0] == "semantic" else 5 if key[2] == "trivy" else 4
    return key[:index] + (None,) + key[index + 1 :]


def _serial(key: tuple) -> str:
    return json.dumps(list(key), ensure_ascii=False)


class Renames:
    """Declared renames of the later run (BR-08): old path -> new path, folders by longest prefix."""

    def __init__(self, later: Run) -> None:
        self.fwd = {t["old_path"]: p for p, t in later.targets.items() if t["change"] == "renamed"}
        self.rev = {new: old for old, new in self.fwd.items()}

    @staticmethod
    def _map(path: str, table: dict[str, str]) -> str:
        if path in table:
            return table[path]
        best = max((old for old in table if path.startswith(old + "/")), key=len, default=None)
        return table[best] + path[len(best) :] if best is not None else path

    def forward(self, path: str) -> str:
        return self._map(path, self.fwd)

    def reverse(self, path: str) -> str:
        return self._map(path, self.rev)


def final_survivor(fid: str, by_id: dict[str, Any]) -> str:
    """Follow `merged_into` (the writer's last write, authoritative) to the finding not merged away."""
    while by_id[fid]["merged_into"] is not None:
        fid = by_id[fid]["merged_into"]
    return fid


def _normalize(run: Run, path_map: Any) -> tuple[list[Item], dict[str, Item], list[dict[str, Any]]]:
    findings = run.doc["findings"]
    by_id = {f["id"]: f for f in findings}
    items, by_survivor = [], {}
    for index, f in enumerate(findings):
        if f["merged_into"] is None:
            item = Item(run.role, f, index, path_map(f["location"]["path"]))
            items.append(item)
            by_survivor[f["id"]] = item
    for f in findings:
        if f["merged_into"] is not None:
            by_survivor[final_survivor(f["id"], by_id)].merged.append(f["id"])
    notes: list[dict[str, Any]] = []
    for s in findings:
        for source in s["merged_from"]:
            target = by_id[source]["merged_into"]
            if target is not None and target != s["id"]:
                detail = (
                    f"{source} is also listed in merged_from of {s['id']}; merged_into names {target} "
                    "(last write wins)"
                )
                for survivor in sorted({final_survivor(s["id"], by_id), final_survivor(target, by_id)}):
                    notes.append(
                        {
                            "survivor": survivor,
                            "kind": "merge",
                            "subject": show(source),
                            "earlier": show(detail) if run.role == "earlier" else None,
                            "later": show(detail) if run.role == "later" else None,
                        }
                    )
    return items, by_survivor, notes


def _pos(item: Item) -> tuple:
    return (item.line is None, item.line or 0, item.index)


def _unique_by(items: list[Item], attr: str) -> dict[Any, Item]:
    seen: dict[Any, list[Item]] = {}
    for item in items:
        value = getattr(item, attr)
        if value is not None:
            seen.setdefault(value, []).append(item)
    return {v: group[0] for v, group in seen.items() if len(group) == 1}


def pair_group(e_items: list[Item], l_items: list[Item]) -> tuple[list[tuple[Item, Item, str]], list, list]:
    """Pair one identity group: unique valid fingerprint, then unique equal line, then position order."""
    pairs, e_rest, l_rest = [], list(e_items), list(l_items)
    for attr, label in (("fp", "fingerprint"), ("line", "exact")):
        fe, fl = _unique_by(e_rest, attr), _unique_by(l_rest, attr)
        for value in sorted(fe.keys() & fl.keys()):
            pairs.append((fe[value], fl[value], label))
            e_rest.remove(fe[value])
            l_rest.remove(fl[value])
    e_rest.sort(key=_pos)
    l_rest.sort(key=_pos)
    for e, lt in zip(e_rest, l_rest, strict=False):
        moved = e.line is not None and lt.line is not None and e.line != lt.line
        pairs.append((e, lt, f"position (line moved {e.line}→{lt.line})" if moved else "position"))
    n = min(len(e_rest), len(l_rest))
    return pairs, e_rest[n:], l_rest[n:]


def _side(item: Item, run: Run) -> dict[str, Any]:
    f = item.f
    title, title_kinds = masked(f["title"])
    description, desc_kinds = masked(f["description"]) if f["description"] is not None else (None, [])
    kinds = sorted(set(title_kinds) | set(desc_kinds))
    return {
        "finding": f["id"],
        "check": f["check"],
        "path": show(item.path),
        "line": item.line,
        "original_severity": f["original_severity"],
        "final_severity": f["final_severity"],
        "review": f["review"],
        "title": title,
        "description": description,
        "masked": bool(kinds),
        "masked_types": kinds,
        "merged": sorted(item.merged),
    }


def _attribute_changes(e: Item, lt: Item) -> list[dict[str, Any]]:
    changes = []
    for name, a, b in (
        ("final_severity", e.f["final_severity"], lt.f["final_severity"]),
        ("original_severity", e.f["original_severity"], lt.f["original_severity"]),
        ("review", e.f["review"], lt.f["review"]),
        ("line", e.line, lt.line),
        ("title", e.f["title"], lt.f["title"]),
        ("cwe", e.f["cwe"], lt.f["cwe"]),
    ):
        if a != b:
            changes.append({"attribute": name, "earlier": _plain(a), "later": _plain(b)})
    te, tl = e.f.get("tool"), lt.f.get("tool")
    if te is not None and tl is not None:
        if te["tool_severity"] != tl["tool_severity"]:
            changes.append(
                {
                    "attribute": "tool_severity",
                    "earlier": show(te["tool_severity"]),
                    "later": show(tl["tool_severity"]),
                }
            )
        if "package" in te and "package" in tl and te["package"]["installed"] != tl["package"]["installed"]:
            changes.append(
                {
                    "attribute": "installed_version",
                    "earlier": show(te["package"]["installed"]),
                    "later": show(tl["package"]["installed"]),
                }
            )
        if te.get("fingerprint") != tl.get("fingerprint"):
            changes.append(
                {"attribute": "fingerprint", "earlier": "differs (not shown)", "later": "differs (not shown)"}
            )
    return changes


def _plain(value: Any) -> Any:
    return masked(value)[0] if isinstance(value, str) else value


def _entry(cls: str, e: Item | None, lt: Item | None, runs: dict[str, Run]) -> dict[str, Any]:
    item = lt if lt is not None else e
    return {
        "class": cls,
        "identity": identity_object(item.key),
        "earlier": _side(e, runs["earlier"]) if e is not None else None,
        "later": _side(lt, runs["later"]) if lt is not None else None,
        "basis": [],
        "attribute_changes": [],
        "notes": [],
        "reasons": [],
        "annotations": [],
        "risk_acceptance": None,
        "input_integrity": [],
        "_e": e,
        "_l": lt,
    }


def _sort_key(entry: dict[str, Any]) -> tuple:
    e, lt = entry["_e"], entry["_l"]
    item = lt if lt is not None else e
    return (
        item.path_star,
        _serial(item.key),
        (e is None or e.line is None, e.line or 0 if e else 0),
        (lt is None or lt.line is None, lt.line or 0 if lt else 0),
        e.index if e else -1,
        lt.index if lt else -1,
    )


def _classify(runs: dict[str, Run], renames: Renames) -> tuple[list[dict[str, Any]], dict, dict]:
    earlier, later = runs["earlier"], runs["later"]
    e_items, e_by, e_notes = _normalize(earlier, renames.forward)
    l_items, l_by, l_notes = _normalize(later, lambda p: p)
    groups: dict[tuple, tuple[list[Item], list[Item]]] = {}
    for item in e_items:
        groups.setdefault(item.key, ([], []))[0].append(item)
    for item in l_items:
        groups.setdefault(item.key, ([], []))[1].append(item)
    entries = []
    for key in sorted(groups, key=_serial):
        pairs, e_left, l_left = pair_group(*groups[key])
        for e, lt, label in pairs:
            entry = _entry("still_present", e, lt, runs)
            entry["basis"] = [label]
            if e.path != e.path_star:
                entry["basis"].append(f"declared rename {show(e.path)}→{show(e.path_star)}")
            if key[0] == "semantic":
                entry["basis"].append(WEAK)
            entry["attribute_changes"] = _attribute_changes(e, lt)
            entry["notes"] = cover.pair_notes(e.f, lt.f, earlier, later)
            entries.append(entry)
        for e in e_left:
            result = cover.assess(e.f, earlier, later, e.path, e.path_star)
            entry = _entry("not_observed_this_time" if result.comparable else "not_comparable", e, None, runs)
            entry["reasons"] = result.reasons
            entries.append(entry)
        for lt in l_left:
            result = cover.assess(lt.f, later, earlier, lt.path, renames.reverse(lt.path))
            entry = _entry("new" if result.comparable else "not_comparable", None, lt, runs)
            entry["reasons"] = result.reasons
            entries.append(entry)
    entries.sort(key=_sort_key)
    for n, entry in enumerate(entries, 1):
        entry["entry"] = f"c-{n}"
    _check_coverage(entries, e_items, l_items, e_by, l_by)
    return entries, {"earlier": e_notes, "later": l_notes}, {"earlier": e_by, "later": l_by}


def _check_coverage(entries: list, e_items: list, l_items: list, e_by: dict, l_by: dict) -> None:
    """Internal invariant (AC-002G-03g): every non-merged finding in exactly one entry."""
    for role, items in (("_e", e_items), ("_l", l_items)):
        used = [id(entry[role]) for entry in entries if entry[role] is not None]
        assert sorted(used) == sorted(id(i) for i in items), "comparison entries do not cover the findings"
    for by in (e_by, l_by):
        merged = [m for item in by.values() for m in item.merged]
        assert len(merged) == len(set(merged)), "a merged-away finding is listed twice"


def _annotate(
    entries: list[dict[str, Any]],
    runs: dict[str, Run],
    renames: Renames,
    merge_notes: dict[str, list],
    facts: dict[str, Any],
) -> None:
    earlier, later = runs["earlier"], runs["later"]
    gone = [x for x in entries if x["class"] == "not_observed_this_time"]
    new = [x for x in entries if x["class"] == "new"]
    for entry in gone:
        e = entry["_e"]
        te, tl = earlier.owner(e.path), later.owner(e.path_star)
        if (
            te is not None
            and tl is not None
            and isinstance(te["digest_at_conclusion"], str)
            and te["digest_at_conclusion"].startswith("sha256:")
            and te["digest_at_conclusion"] == tl["digest_at_conclusion"]
        ):
            entry["annotations"].append(
                {"code": "target_unchanged", "text": "target content unchanged between runs", "refers_to": []}
            )
    for entry in gone:
        mates = [x for x in new if _without_path(x["_l"].key) == _without_path(entry["_e"].key)]
        if mates:
            entry["annotations"].append(_move([x["entry"] for x in mates]))
            for mate in mates:
                mate["annotations"].append(_move([entry["entry"]]))
    accepted = {role: {a["finding"] for a in runs[role].doc["risk_acceptances"]} for role in runs}
    for entry in entries:
        for role in ("earlier", "later"):
            item = entry["_e" if role == "earlier" else "_l"]
            if item is None:
                continue
            if item.merged:
                entry["annotations"].append(
                    {
                        "code": "merge",
                        "text": f"merged from {', '.join(sorted(item.merged))} in run {role}",
                        "refers_to": [],
                    }
                )
            entry["notes"] += [
                {k: v for k, v in n.items() if k != "survivor"}
                for n in merge_notes[role]
                if n["survivor"] == item.f["id"]
            ]
            if facts[role]["state"] == "unresolved":
                entry["input_integrity"].append(role)
        e = entry["_e"]
        if e is not None and e.f["id"] in accepted["earlier"]:
            entry["risk_acceptance"] = {"run": "earlier", "applies_to_later": False}
        elif entry["_l"] is not None and entry["_l"].f["id"] in accepted["later"]:
            entry["risk_acceptance"] = {"run": "later", "applies_to_later": True}
        for collection in ("annotations",):
            entry[collection].sort(key=lambda a: (a["code"], a["refers_to"]))


def _move(refers_to: list[str]) -> dict[str, Any]:
    return {
        "code": "possible_move",
        "text": "possibly the same finding moved (unverified)",
        "refers_to": sorted(refers_to, key=lambda x: int(x[2:])),
    }


def _run_block(run: Run, fact: dict[str, Any]) -> dict[str, Any]:
    doc = run.doc
    cancellation = doc["cancellation"] if "cancellation" in doc else "not recorded"
    if cancellation == "not recorded":
        cancel = {"state": "not recorded in this result", "requested_at": None, "reason": None}
    elif cancellation is None:
        cancel = {"state": "not cancelled", "requested_at": None, "reason": None}
    else:
        reason = cancellation["reason"]
        cancel = {
            "state": "cancelled",
            "requested_at": cancellation["requested_at"],
            "reason": masked(reason)[0] if reason is not None else None,
        }
    return {
        "verification_id": doc["verification_id"],
        "opened_at": doc["opened_at"],
        "ended_at": doc["ended_at"],
        "result_sha256": fact["result_sha256"],
        "verdict": doc["verdict"],
        "reasons": [
            _text_obj(
                {"code": r["code"], "subject": r["subject"], "detail": r["detail"]}, ("subject", "detail")
            )
            for r in doc["reasons"]
        ],
        "raw_evidence": fact["raw_evidence"],
        "cancellation": cancel,
        "adapter_runs": "recorded" if run.runs_recorded else "not recorded in this result",
        "risk_acceptances": [
            _text_obj(
                {"finding": a["finding"], "recorded_at": a["recorded_at"], "reason": a["reason"]}, ("reason",)
            )
            for a in doc["risk_acceptances"]
        ],
    }


def _text_obj(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    kinds: set[str] = set()
    for name in fields:
        obj[name], found = masked(obj[name])
        kinds.update(found)
    obj["masked"] = bool(kinds)
    return obj


def build(earlier_doc: Any, later_doc: Any, facts: dict[str, Any]) -> dict[str, Any]:
    """Comparison document (without `comparison_id` and `created_at`) of two validated results.

    `facts[role]` holds `state`, `failed_checks`, `markdown_present`, `statement`, `result_sha256` and
    `raw_evidence` of that run.
    """
    runs = {"earlier": Run(earlier_doc, "earlier"), "later": Run(later_doc, "later")}
    renames = Renames(runs["later"])
    entries, merge_notes, _ = _classify(runs, renames)
    _annotate(entries, runs, renames, merge_notes, facts)
    counts = {c: sum(1 for x in entries if x["class"] == c) for c in CLASSES}
    counts["total"] = len(entries)
    counts["still_present_with_differences"] = sum(
        1
        for x in entries
        if x["class"] == "still_present" and any(n["kind"] in cover.DIFFERENCE_KINDS for n in x["notes"])
    )
    for entry in entries:
        del entry["_e"], entry["_l"]
    return {
        "schema": SCHEMA,
        "statements": dict(STATEMENTS),
        "input_integrity": {
            role: {
                "verification_id": runs[role].doc["verification_id"],
                "state": facts[role]["state"],
                "failed_checks": list(facts[role]["failed_checks"]),
                "markdown_present": facts[role]["markdown_present"],
                "statement": facts[role]["statement"],
            }
            for role in ("earlier", "later")
        },
        "runs": {role: _run_block(runs[role], facts[role]) for role in ("earlier", "later")},
        "comparability": cover.summary(runs["earlier"], runs["later"], renames.forward),
        "counts": counts,
        "entries": entries,
        "identity_rules": list(IDENTITY_RULES),
        "limits": list(LIMITS),
    }
