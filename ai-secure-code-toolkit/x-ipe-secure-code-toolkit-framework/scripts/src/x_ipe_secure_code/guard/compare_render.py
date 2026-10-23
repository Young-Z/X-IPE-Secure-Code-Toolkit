"""Fixed texts, masking and the Markdown of a Guard report comparison (FEATURE-002-G, FR-002G-7).

The Markdown is rendered only from the structured comparison: every cell passes through the delivered
`report.md_text` neutralisation, and the footer binds it to the SHA-256 of the structured comparison.
"""

from __future__ import annotations

import re
from typing import Any

from .mask import mask_text
from .report import md_text

SCHEMA = "ai-secure-code-toolkit/guard-comparison/v1"
FOOTER = re.compile(r"<!-- guard-comparison-sha256: ([0-9a-f]{64}) -->\n\Z")
_MARKER = "[masked:"

STATEMENTS = {
    "not_observed_meaning": '"Not observed this time" does not mean fixed. It only means that the later run '
    "did not report the finding although it looked at the same place under comparable conditions.",
    "still_present_meaning": '"Still present" means observed in both runs under the stated identity rule; it '
    "never means the same issue confirmed.",
    "not_evidence": "This comparison is a reading aid, not verification evidence; it does not change either "
    "verdict.",
    "evidence_basis": "The comparison is based only on recorded findings, never on raw evidence.",
    "provenance": "Both reports were resolved from the supplied project's report store "
    "(x-ipe-docs/secure-code/reports/guard/). Their project provenance cannot be proven: a report copied in "
    "from another project is not detected. A structured result and Markdown report edited consistently "
    "cannot be detected.",
    "no_trend": "No trend, score, percentage or derived verdict is produced.",
}

IDENTITY_RULES = (
    "Run-local finding ids, check ids and titles are never identity.",
    "Opengrep finding: adopted Policy rule, Adapter, tool rule id and path.",
    "Trivy vulnerability: adopted Policy rule, scanner, vulnerability id, path, package name and package "
    "path; the installed version is an attribute.",
    "Trivy misconfiguration or secret: adopted Policy rule, scanner, tool rule id and path; secret values "
    "are never read or shown.",
    "Semantic finding: adopted Policy rule, source, path and CWE; always labelled semantic identity (weak).",
    "Paths follow only renames declared in the later run; no content similarity is used.",
    "Within one identity, pairs are formed by a unique valid fingerprint, then a unique equal line, then "
    "by position order (lines ascending, findings without a line last, then recorded order); "
    "position pairs are labelled.",
)

LIMITS = (
    "Identity is computed from recorded facts, not proven sameness: code moved to another file without a "
    "declared rename, renamed tool rules, changed CWE or source names and same-key collisions can split or "
    "mispair findings; labels show where.",
    "Project provenance of the two reports cannot be proven; a consistently edited result and Markdown pair "
    "cannot be detected; a report rendered by another toolkit version is indistinguishable from an edited "
    "one.",
    "Trivy per-path accounting is not read; any skipped or unaccounted count makes absences of that check "
    "not comparable.",
    "Semantic review is not deterministic; a semantic finding not observed this time may only mean that it "
    "was not reported again.",
    "Masking is pattern-based, not a data-loss-prevention guarantee.",
    "A comparison is valid only as a pair whose Markdown footer equals the SHA-256 of the structured "
    "comparison; a lone or mismatched file is not a comparison.",
)

CLASS_TITLES = (
    ("new", "New"),
    ("still_present", "Still present (observed in both runs under the stated identity rule)"),
    ("not_observed_this_time", "Not observed this time"),
    ("not_comparable", "Not comparable"),
)


def masked(text: str | None) -> tuple[str | None, list[str]]:
    """Mask free text again; values masked by the Guard writer stay labelled as masked."""
    if text is None:
        return None, []
    out, kinds = mask_text(text)
    if not kinds and _MARKER in out:
        kinds = ["masked earlier"]
    return out, sorted(kinds)


def footer_digest(text: str) -> str | None:
    match = FOOTER.search(text)
    return match.group(1) if match else None


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    if not rows:
        return ["(none)", ""]
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(md_text(cell) for cell in row) + " |" for row in rows]
    return [*lines, ""]


def _bullets(items: list[str]) -> list[str]:
    return [*(f"- {item}" for item in items), ""] if items else ["(none)", ""]


def _side_cells(side: dict[str, Any] | None) -> tuple[str, str]:
    if side is None:
        return "—", "—"
    where = side["path"] + (f":{side['line']}" if side["line"] is not None else "")
    label = f"{side['final_severity']} / {side['review']}" + (" (masked)" if side["masked"] else "")
    return where, label


def _identity_text(identity: dict[str, Any]) -> str:
    return ", ".join(f"{k} {v}" for k, v in identity.items() if k != "path" and v is not None)


def _reason_text(reason: dict[str, Any]) -> str:
    text = reason["text"] + (f" ({reason['detail']})" if reason["detail"] else "")
    if reason["earlier"] is not None or reason["later"] is not None:
        text += f" [earlier: {reason['earlier'] or '—'}; later: {reason['later'] or '—'}]"
    return text


def _class_rows(entries: list[dict[str, Any]], cls: str) -> list[list[Any]]:
    rows = []
    for x in entries:
        if x["class"] != cls:
            continue
        e_where, e_label = _side_cells(x["earlier"])
        l_where, l_label = _side_cells(x["later"])
        basis = x["basis"] if cls == "still_present" else [_reason_text(r) for r in x["reasons"]]
        notes = [
            a["text"] + (f" ({', '.join(a['refers_to'])})" if a["refers_to"] else "")
            for a in x["annotations"]
        ]
        if x["risk_acceptance"] is not None and x["risk_acceptance"]["run"] == "earlier":
            notes.append("risk accepted in the earlier run only; it does not apply to the later run")
        if x["input_integrity"]:
            notes.append(f"input integrity unresolved for run {', '.join(x['input_integrity'])}")
        rows.append(
            [x["entry"], _identity_text(x["identity"]), e_where, l_where, e_label, l_label, basis, notes]
        )
    return rows


def _run_lines(doc: dict[str, Any]) -> list[str]:
    out = []
    rows = []
    for role in ("earlier", "later"):
        run = doc["runs"][role]
        cancel = run["cancellation"]
        rows.append(
            [
                role,
                run["verification_id"],
                run["opened_at"],
                run["ended_at"],
                run["verdict"],
                run["result_sha256"],
                doc["input_integrity"][role]["state"],
                run["raw_evidence"],
                cancel["state"] + (f" at {cancel['requested_at']}" if cancel["requested_at"] else ""),
            ]
        )
    out += _table(
        [
            "Role",
            "Verification",
            "Opened",
            "Ended",
            "Verdict",
            "Result SHA-256",
            "Input integrity",
            "Raw evidence",
            "Cancellation",
        ],
        rows,
    )
    for role in ("earlier", "later"):
        out += [f"Recorded verdict reasons ({role}):", ""]
        out += _bullets(
            [
                f"`{r['code']}` {md_text(r['subject'])}: {md_text(r['detail'])}"
                for r in doc["runs"][role]["reasons"]
            ]
        )
    return out


def _comparability_lines(comp: dict[str, Any]) -> list[str]:
    scope, policy = comp["scope"], comp["policy"]
    whole = scope["whole_project"]
    items = [
        "Shared targets: yes" if comp["shared_targets"] else "The runs share no targets",
        f"Whole project: earlier {_yes(whole['earlier'])}, later {_yes(whole['later'])}",
        f"Targets only in the earlier run: {md_text(scope['only_earlier'])}",
        f"Targets only in the later run: {md_text(scope['only_later'])}",
        f"Shared targets: {md_text(scope['shared'])}",
    ]
    for role in ("earlier", "later"):
        flagged = [
            f"{t['path']} ({t['change']}, changed {t['changed']}, incomplete {t['incomplete']})"
            for t in scope[role]
            if t["changed"] or t["incomplete"] or t["change"] == "deleted"
        ]
        items.append(f"Changed, incomplete or deleted targets ({role}): {md_text(flagged)}")
    items += [
        f"Policies only in the earlier run: {md_text(policy['only_earlier'])}",
        f"Policies only in the later run: {md_text(policy['only_later'])}",
        "Policy differences: "
        + md_text([f"{d['rule']} {d['earlier']} → {d['later']}" for d in policy["differing"]]),
    ]
    for c in comp["coverage"]:
        items.append(
            f"Coverage of {md_text(c['rule'])}: earlier {md_text(_cov(c['earlier']))}; "
            f"later {md_text(_cov(c['later']))}"
        )
    for role in ("earlier", "later"):
        m = comp["methods"][role]
        items.append(
            f"Methods ({role}): {md_text(m['planned'])}; adapters {md_text(m['adapters'])}; "
            f"Adapter runs {md_text(m['adapter_runs'])}"
        )
        items.append(
            f"Tools ({role}): "
            + md_text(
                [
                    f"run {t['n']} {t['adapter']} {t['version']}"
                    + (
                        f", include-ignored {t['include_ignored']}"
                        if t["include_ignored"] is not None
                        else ""
                    )
                    for t in comp["tools"][role]
                ]
            )
        )
        items.append(
            f"Tool data ({role}): "
            + md_text(
                [f"run {t['n']} check {t['check']}: {t['components']}" for t in comp["tool_data"][role]]
            )
        )
    return _bullets(items)


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def _cov(c: dict[str, Any]) -> str:
    if not c["adopted"]:
        return "not adopted"
    parts = [f"{c['planned_checks']} planned check(s)"]
    if c["not_applicable"] is not None:
        parts.append(f"Policy-level N/A ({c['not_applicable']})")
    if c["excluded"] is not None:
        parts.append(f"excluded by the user ({c['excluded']})")
    if c["excluded_checks"]:
        parts.append(f"checks excluded by the user: {', '.join(c['excluded_checks'])}")
    parts += [f"{k} {v}" for k, v in c["states"].items()]
    return ", ".join(parts)


def markdown(doc: dict[str, Any], json_sha256: str) -> str:
    """Markdown twin of a structured comparison; ends with the comparison footer."""
    st = doc["statements"]
    out = [f"# Guard Report Comparison {md_text(doc['comparison_id'])}", ""]
    for role in ("earlier", "later"):
        integrity = doc["input_integrity"][role]
        if integrity["state"] == "unresolved":
            out += [f"> **{md_text(integrity['statement'])}**", ""]
    out += [
        f"**{md_text(st['not_observed_meaning'])}**",
        "",
        md_text(st["not_evidence"]),
        "",
        md_text(st["no_trend"]),
        "",
        md_text(st["still_present_meaning"]),
        "",
        "## Runs",
        "",
    ]
    out += _run_lines(doc)
    out += ["## Comparability", ""]
    out += _comparability_lines(doc["comparability"])
    counts = doc["counts"]
    out += ["## Counts", ""]
    out += _table(
        ["Class", "Entries"],
        [[title.split(" (")[0], counts[cls]] for cls, title in CLASS_TITLES] + [["Total", counts["total"]]],
    )
    out += [
        f"Still-present pairs with Policy, tool or tool-data differences: "
        f"{counts['still_present_with_differences']}",
        "",
    ]
    headers = [
        "Entry",
        "Identity",
        "Earlier path:line",
        "Later path:line",
        "Severity / review (earlier)",
        "Severity / review (later)",
        "Basis or reasons",
        "Annotations",
    ]
    for cls, title in CLASS_TITLES:
        out += [f"## {title}", ""]
        out += _table(headers, _class_rows(doc["entries"], cls))
    rows = []
    for x in doc["entries"]:
        rows += [[x["entry"], c["attribute"], c["earlier"], c["later"]] for c in x["attribute_changes"]]
        rows += [[x["entry"], f"{n['kind']}: {n['subject']}", n["earlier"], n["later"]] for n in x["notes"]]
    out += ["## Attribute Changes and Difference Notes", ""]
    out += _table(["Entry", "Attribute or note", "Earlier", "Later"], rows)
    out += [
        "## Risk Acceptances",
        "",
        "Shown per run; an acceptance never carries over to the other run.",
        "",
    ]
    acc_rows = [
        [role, a["finding"], a["recorded_at"], a["reason"] + (" (masked)" if a["masked"] else "")]
        for role in ("earlier", "later")
        for a in doc["runs"][role]["risk_acceptances"]
    ]
    out += _table(["Run", "Finding", "Recorded at", "Reason"], acc_rows)
    carried = [
        x["entry"]
        for x in doc["entries"]
        if x["risk_acceptance"] is not None and x["risk_acceptance"]["run"] == "earlier"
    ]
    if carried:
        out += _bullets(
            [
                f"{md_text(e)}: accepted in the earlier run only; it does not apply to the later run"
                for e in carried
            ]
        )
    out += ["## Identity Rules and Limits", ""]
    out += _bullets([md_text(x) for x in [*doc["identity_rules"], *doc["limits"]]])
    out += ["## Provenance and Evidence", ""]
    availability = [
        f"Raw evidence of the {role} run: {md_text(doc['runs'][role]['raw_evidence'])}"
        for role in ("earlier", "later")
    ]
    out += _bullets(
        [md_text(st["provenance"]), md_text(st["evidence_basis"]), *availability, md_text(st["not_evidence"])]
    )
    return "\n".join(out) + f"\n<!-- guard-comparison-sha256: {json_sha256} -->\n"
