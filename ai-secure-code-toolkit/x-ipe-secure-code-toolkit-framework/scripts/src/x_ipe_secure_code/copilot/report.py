"""Copilot Markdown report, rendered only from the structured result (AC-003A-05a…05d, 05g).

Agent-supplied text passes through `md_text` (no headings, HTML, links or images); identifiers,
states, paths, digests and generated reasons are shown as code spans. The footer binds the
Markdown to the exact bytes of the structured result.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ..atomic import dumps_json
from ..guard.report import md_text

FOOTER = re.compile(r"<!-- copilot-result-sha256: ([0-9a-f]{64}) -->\s*\Z")
_MASK_MARKER = re.compile(r"\\\[masked:([a-z_.]+)\\\]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
__all__ = ["md_text", "render", "footer_digest", "sha256_hex", "cell", "code"]


def cell(value: Any) -> str:
    """Neutralized free text; mask markers are shown as code spans, so no link can form after them."""
    return _MASK_MARKER.sub(r"`[masked:\1]`", md_text(value))


def code(value: Any) -> str:
    """An identifier, state, path, digest or generated reason as an inline code span."""
    if value is None or value == "" or value == []:
        return "—"
    if isinstance(value, list):
        return ", ".join(code(v) for v in value)
    text = _CONTROL.sub("", str(value))
    if "`" in text:
        return md_text(text)
    return "`" + text.replace("|", "\\|") + "`"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["(none)", ""]
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return [*lines, ""]


def _bullets(items: list[str]) -> list[str]:
    return [*(f"- {item}" for item in items), ""] if items else ["(none)", ""]


def _risk_rows(rows: list[dict[str, Any]]) -> list[list[str]]:
    return [
        [
            code(r["id"]),
            code(r["severity"]),
            code(r["state"]),
            code(r["rule"]),
            code(r["files"]),
            cell(r["reason"]),
        ]
        for r in rows
    ]


def _masked(labels: list[str]) -> str:
    return code([f"masked: {label}" for label in labels])


def _review_detail(r: dict[str, Any]) -> list[str]:
    """Reviewed targets and subjects of one Reviewer record (AC-003A-05a: same record as the JSON)."""
    declared = "declared by the agent, not proven" if r["invocation"]["declared"] else "not declared"
    out = [f"### Reviewer record {r['seq']}", "", f"Invocation {declared}.", ""]
    out += ["Reviewed targets (digest the Reviewer saw; `absent` = the file no longer existed):", ""]
    out += _table(["File", "Digest"], [[code(t["path"]), code(t["digest"])] for t in r["reviewed_targets"]])
    out += ["Subjects:", ""]
    rows = []
    for i, s in enumerate(r["subjects"]):
        prefix = f"subjects[{i}]."
        labels = [m.removeprefix(prefix) for m in r["masked"] if m.startswith(prefix)]
        rows.append([code(s["id"]), code(s["type"]), code(s["result"]), cell(s["basis"]), _masked(labels)])
    return out + _table(["Suggestion", "Type", "Result", "Basis", "Masked"], rows)


def render(result: dict[str, Any]) -> str:
    """Markdown report of one round (deterministic: same result, same text)."""
    cid = md_text(result["collaboration_id"])
    risk_headers = ["ID", "Severity", "State", "Policy", "Files", "Reason"]
    out = [
        f"# Copilot Adoption Report {cid} — round {result['round']}",
        "",
        "## Attention",
        "",
        "Suggestions of severity High, Critical or unknown that are not adopted, partly adopted, cannot be "
        "verified, not reviewed, stale or Policy-changed. Copilot does not pause the work; the upstream "
        "caller decides.",
        "",
    ]
    out += _table(risk_headers, _risk_rows(result["attention"]))
    if result["policy_next_step"]:
        out += [f"Next step for Policy-changed suggestions: {md_text(result['policy_next_step'])}.", ""]
    out += ["## Gaps", "", "Other suggestions in one of those states.", ""]
    out += _table(risk_headers, _risk_rows(result["gaps"]))
    task = ("Task (masked): " if "task" in result["masked"] else "Task: ") + cell(result["task"])
    collab = [
        f"Collaboration: {code(result['collaboration_id'])}, round {result['round']}",
        f"Stage: {code(result['stage'])}",
        task,
        f"Opened: {md_text(result['opened_at'])}",
        f"Adopted scope: {code(result['scope']['scope_id'])}",
    ]
    if result["snapshot_before_review"]:
        collab.append("This round is a snapshot before review: no valid Reviewer record exists yet.")
    out += ["## Collaboration", "", *_bullets(collab)]
    out += ["## Suggestions", ""]
    out += _table(
        [
            "ID",
            "State",
            "Severity",
            "Policy",
            "Files",
            "Location",
            "Action",
            "Reason",
            "Reviewer basis",
            "Review",
            "Changed files",
            "Masked",
        ],
        [
            [
                code(s["id"]),
                code(s["state"]),
                code(s["severity"]),
                code(s["rule"]),
                code(s["files"]),
                cell(s["location"]),
                cell(s["action"]),
                cell(s["reason"]),
                cell(s["basis"]),
                md_text(s["review_seq"]),
                code([f"{c['path']} ({c['change']})" for c in s["changed"]]),
                _masked(s["masked"]),
            ]
            for s in result["suggestions"]
        ],
    )
    history = [
        f"History of {code(s['id'])}: review {h['seq']} {code(h['result'])} — {cell(h['basis'])}"
        for s in result["suggestions"]
        for h in s["history"]
    ]
    if history:
        out += ["Earlier results (history, not current adoption):", "", *_bullets(history)]
    out += ["## Re-review Needed", "", *_bullets([code(x) for x in result["re_review"]])]
    out += ["## Artifacts", ""]
    out += _table(
        ["Path", "Kind", "Change", "Old path"],
        [
            [code(a["path"]), code(a["kind"]), code(a["change"]), code(a["old_path"])]
            for a in result["artifacts"]
        ],
    )
    out += _table(
        ["File", "Change", "Recorded digest", "Current digest", "Recorded"],
        [
            [
                code(m["path"]),
                code(m["change"]),
                code(m["recorded_digest"]),
                code(m["current_digest"]),
                md_text(m["recorded_at"]),
            ]
            for m in result["manifest"]
        ],
    )
    if result["context"]:
        out += ["Read-only context (not reviewed): " + code([c["path"] for c in result["context"]]), ""]
    scope = result["scope"]
    out += ["## Adopted Policies", ""]
    out += _table(
        ["Policy", "Confirmed state digest", "Now"],
        [[code(a["rule"]), code(a["state_digest"]), code(a["now"])] for a in scope["adopted"]],
    )
    out += [
        "Invalidated for the rest of this collaboration: "
        + (code(sorted(scope["invalidated"])) if scope["invalidated"] else "none"),
        "",
    ]
    out += ["## Reviewer Records", ""]
    out += _table(
        [
            "Seq",
            "Valid",
            "Host",
            "Agent",
            "Read-only",
            "Invoked",
            "Reviewed",
            "Recorded",
            "Requirement",
            "Reasons",
            "Counts for",
            "Not counted",
            "Masked",
        ],
        [
            [
                str(r["seq"]),
                "yes" if r["valid"] else "no",
                cell(r["invocation"]["host"]),
                cell(r["invocation"]["agent"]),
                "yes" if r["invocation"]["read_only"] else "no",
                cell(r["invocation"]["invoked_at"]),
                cell(r["reviewed_at"]),
                code(r["recorded_at"]),
                cell(r["requirement"]),
                code(r["reasons"]),
                code(r["counted"]),
                code([f"{x['id']}: {x['reason']}" for x in r["not_counted"]]),
                _masked(r["masked"]),
            ]
            for r in result["reviews"]
        ],
    )
    for r in result["reviews"]:
        out += _review_detail(r)
    out += ["## Boundaries", "", *_bullets([md_text(b) for b in result["boundaries"]])]
    retention = result["retention"]
    published = md_text(result["published_at"])
    out += [
        "## Retention",
        "",
        *_bullets(
            [
                f"Reports: {md_text(retention['reports'])}",
                f"Private collaboration data: {md_text(retention['private_data'])}",
                "Private collaboration data present as of publication "
                f"{published}: {'yes' if result['private_data_present_as_of_publication'] else 'no'}",
            ]
        ),
    ]
    supersedes = result["supersedes"]
    out += [
        "## Supersedes",
        "",
        f"This round supersedes {md_text(supersedes)}; older rounds are history and never prove the "
        "current version."
        if supersedes
        else "This is the first round of this collaboration.",
        "",
    ]
    return "\n".join(out) + f"\n<!-- copilot-result-sha256: {sha256_hex(dumps_json(result))} -->\n"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def footer_digest(text: str) -> str | None:
    """The structured-result digest named by the report footer, or None."""
    match = FOOTER.search(text)
    return match.group(1) if match else None
