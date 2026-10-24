"""Markdown report rendered only from the structured result (same data, same conclusion).

Every agent-supplied string passes through `md_text`, so it can never add headings, HTML, links,
images or a second verdict line.
"""

from __future__ import annotations

import functools
import hashlib
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .. import __version__
from ..atomic import dumps_json

VERDICT_TEXT = {"pass": "Pass", "fail": "Fail", "cannot_confirm_pass": "Cannot confirm pass"}
FOOTER = re.compile(r"<!-- guard-result-sha256: ([0-9a-f]{64}) -->\s*\Z")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SPECIAL = re.compile(r"([\\`*_\[\]<>#|!~])")

# CR-TASK-086 (FR-002A-10): every package module that affects the report output, package-relative and
# sorted. A toolkit-internal module imported by any of them must be listed too (closure test), so the
# package `__init__.py` (imported for `__version__`) is listed as well; over-inclusion is harmless.
RENDERER_MANIFEST: tuple[str, ...] = ("__init__.py", "atomic.py", "guard/report.py")
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent


def manifest_digest(root: Path, manifest: Iterable[str] = RENDERER_MANIFEST) -> str | None:
    """SHA-256 over `path NUL length NUL bytes` of each sorted component; None when one is unreadable."""
    digest = hashlib.sha256()
    for rel in sorted(manifest):
        try:
            data = (root / rel).read_bytes()
        except OSError:
            return None
        digest.update(rel.encode("utf-8") + b"\0" + str(len(data)).encode("ascii") + b"\0" + data)
    return digest.hexdigest()


@functools.cache
def _package_digest() -> str | None:
    return manifest_digest(_PACKAGE_ROOT)


def renderer_identity() -> dict[str, Any]:
    """The build writing a structured result: toolkit version and renderer digest (None = unknown)."""
    return {"toolkit_version": __version__, "renderer_digest": _package_digest()}


def stamp(result: dict[str, Any]) -> dict[str, Any]:
    """Record the current build in a structured result about to be written (and rendered)."""
    result["renderer"] = renderer_identity()
    return result


def same_renderer(a: Any, b: Any) -> bool:
    """Equal recorded identities; an unknown or missing identity never matches any identity."""
    if not (isinstance(a, dict) and isinstance(b, dict)):
        return False
    if not (isinstance(a.get("renderer_digest"), str) and isinstance(b.get("renderer_digest"), str)):
        return False
    keys = ("toolkit_version", "renderer_digest")
    return all(a.get(k) == b.get(k) for k in keys)


def md_text(value: Any) -> str:
    """Neutralize any value for inline Markdown (also inside table cells)."""
    if value is None or value == "" or value == []:
        return "—"
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    text = _CONTROL.sub("", str(value)).replace("\r", " ").replace("\n", " ")
    return _SPECIAL.sub(r"\\\1", text)


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    if not rows:
        return ["(none)", ""]
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(md_text(cell) for cell in row) + " |" for row in rows]
    return [*lines, ""]


def _bullets(items: list[str]) -> list[str]:
    return [*(f"- {item}" for item in items), ""] if items else ["(none)", ""]


def _reasons(reasons: list[dict[str, str]]) -> list[str]:
    return _bullets([f"`{r['code']}` {md_text(r['subject'])}: {md_text(r['detail'])}" for r in reasons])


def render(result: dict[str, Any]) -> str:
    vid = md_text(result["verification_id"])
    art, plan = result["artifact"], result["plan"]
    out = [
        f"# Guard Verification Report {vid}",
        "",
        "## Verdict",
        "",
        f"**Verdict: {VERDICT_TEXT[result['verdict']]}**",
        "",
        "Reasons that determined the verdict:",
        "",
    ]
    out += _reasons(result["reasons"])
    if result["other_blockers"]:
        out += ["Other blockers (also reported; Fail takes precedence):", ""] + _reasons(
            result["other_blockers"]
        )
    out += [
        "## Scope",
        "",
        *_bullets(
            [
                f"Verification: {vid}",
                f"Opened: {md_text(result['opened_at'])}",
                f"Ended: {md_text(result['ended_at'])}",
                f"Request: {md_text(result['request'])}",
                f"Baseline: {md_text(result['baseline'])}",
                f"Whole project: {'yes (explicit choice)' if art['whole_project'] else 'no'}",
            ]
        ),
        "### Targets (verified)",
        "",
    ]
    out += _table(
        [
            "Path",
            "Change",
            "Old path",
            "Digest at open",
            "Digest at conclusion",
            "Changed",
            "Incomplete",
            "Not followed / unreadable",
        ],
        [
            [
                t["path"],
                t["change"],
                t["old_path"],
                t["digest_at_open"],
                t["digest_at_conclusion"],
                "yes" if t["changed"] else "no",
                "yes" if t["incomplete"] else "no",
                t["not_followed"] + t["unreadable"],
            ]
            for t in art["targets"]
        ],
    )
    out += ["### Read-only context (not verified)", ""]
    out += _table(["Path", "Digest"], [[c["path"], c["digest"]] for c in art["context"]])
    out += ["### Suggested files (not verified)", ""]
    out += _table(["Path", "Reason"], [[s["path"], s["reason"]] for s in art["suggested"]])
    out += ["### Copilot reports (context only, never evidence of a pass)", ""]
    out += _table(["Path", "Digest"], [[c["path"], c["digest"]] for c in art["copilot_reports"]])
    out += [
        "### Adopted Policies",
        "",
        f"Adopted scope: {md_text(result['scope']['scope_id'])} (mode {md_text(result['scope']['mode'])})",
        "",
    ]
    out += _table(
        ["Rule", "Confirmed state digest", "At conclusion"],
        [[a["rule"], a["state_digest"], a["at_conclusion"]] for a in result["scope"]["adopted"]],
    )
    out += ["## Check Plan", ""]
    if plan is None:
        out += ["No check plan was recorded.", ""]
    else:
        out += _table(
            ["Check", "Policy", "Object", "Part", "Methods", "Minimum evidence"],
            [
                [
                    c["id"],
                    c["rule"],
                    c["object"],
                    c["object_part"],
                    [
                        f"{m['name']} ({m['kind']}, {'required' if m['required'] else 'auxiliary'})"
                        for m in c["methods"]
                    ],
                    c["minimum_evidence"],
                ]
                for c in plan["checks"]
            ],
        )
        out += ["Policies judged not applicable:", ""]
        out += _table(
            ["Policy", "Factual reason"], [[n["rule"], n["reason"]] for n in plan["not_applicable"]]
        )
        out += ["User scope exclusions (not N/A, not met):", ""]
        out += _table(
            ["Policy or check", "User's reason"],
            [[e["rule"] or e["check"], e["reason"]] for e in plan["exclusions"]],
        )
    out += _method_section(plan)
    out += [
        "## Ledger",
        "",
        "States: met, not_met, unconfirmed, n/a, excluded. No percentage is computed.",
        "",
    ]
    out += _table(
        [
            "Check",
            "Policy",
            "State",
            "Recorded state",
            "Evidence by kind",
            "Findings",
            "Reason",
            "Substitution",
        ],
        [
            [
                r["check"],
                r["rule"],
                r["state"],
                r["recorded_state"],
                [f"{k}: {', '.join(v)}" for k, v in r["evidence_by_kind"].items()],
                r["findings"],
                r["reason"],
                [f"{s['method']} {s['status']}" for s in r["substitution"]],
            ]
            for r in result["ledger"]
        ],
    )
    out += ["## Findings", ""]
    out += _table(
        [
            "Finding",
            "Policy",
            "Location",
            "Title",
            "Source",
            "Original severity",
            "Reviewer opinion",
            "Final severity",
            "Severity conflict",
            "Review",
            "Review basis",
            "Evidence",
            "Merged into",
        ],
        [
            [
                f["id"],
                f["rule"],
                f"{f['location']['path']}" + (f":{f['location']['line']}" if f["location"]["line"] else ""),
                f["title"],
                f["source"]
                + (f" ({f['tool']['tool_severity']}, rule {f['tool']['rule_id']})" if f.get("tool") else ""),
                f["original_severity"],
                (f["severity_opinion"] or {}).get("severity"),
                f["final_severity"],
                "yes" if f["severity_conflict"] else "no",
                f["review"] + (" (reviews disagree)" if f["review_disagreement"] else ""),
                f["review_basis"],
                f["evidence"],
                f["merged_into"],
            ]
            for f in result["findings"]
        ],
    )
    out += ["## Reviewer Records", "", "Invocation is declared by the agent, not proven by the script.", ""]
    out += _table(
        ["Record", "Valid", "Why not valid", "Host / agent", "Requirement", "Reviewed targets", "Subjects"],
        [
            [
                r["index"],
                "yes" if r["valid"] else "no",
                r["invalid_reasons"],
                f"{r['invocation']['host']} / {r['invocation']['agent']}",
                r["requirement"],
                [f"{t['path']}@{t['digest']}" for t in r["reviewed_targets"]],
                [f"{s['type']} {s['id']}: {s['result']}" for s in r["subjects"]],
            ]
            for r in result["reviews"]
        ],
    )
    out += ["## Conflicts", ""]
    out += _table(
        ["Conflict", "Kind", "Description", "Verdict-affecting", "Resolved", "Resolution"],
        [
            [
                c["id"],
                c["kind"],
                c["description"],
                "yes" if c["verdict_affecting"] else "no",
                "yes" if c["resolved"] else "no",
                c["resolution"],
            ]
            for c in result["conflicts"]
        ],
    )
    out += [
        "## Risk Acceptances",
        "",
        "Recorded separately; findings, severities and the verdict are unchanged.",
        "",
    ]
    out += _table(
        ["Finding", "Role", "Recorded at", "Reason"],
        [[a["finding"], a["role"], a["recorded_at"], a["reason"]] for a in result["risk_acceptances"]],
    )
    out += ["## Evidence", ""]
    out += _table(
        ["Evidence", "Kind", "Method", "Status", "Paths", "Lines", "Summary", "Stored", "Masking"],
        [
            [
                e["id"],
                e["kind"],
                e["method"],
                e["method_status"],
                e["paths"],
                e["lines"],
                e["summary"],
                e["stored"],
                f"masked ({', '.join(e['masked_types'])})" if e["masked"] else "not masked",
            ]
            for e in result["evidence"]
        ],
    )
    out += _adapter_section(result.get("adapter_runs") or [])
    out += _trivy_component_section(result.get("adapter_runs") or [])
    out += _provisioning_section(result.get("tool_provisioning"))
    out += _budget_section(result)
    out += _cancel_section(result.get("cancellation"))
    out += _egress_section(result.get("egress"))
    out += _helper_section(result.get("helpers"))
    ret = result["evidence_retention"]
    out += [
        "## Evidence Retention",
        "",
        *_bullets(
            [
                f"Raw evidence location: {md_text(ret['location'])}",
                f"Kept {ret['days_after_end']} days after the verification ended, then removable",
                f"Removal: {md_text(ret['removal'])}; this report stays until the user removes it",
            ]
        ),
        "## Limits",
        "",
        *_bullets([md_text(x) for x in result["limits"]]),
    ]
    out += _origin_section(result.get("renderer"))
    digest = hashlib.sha256(dumps_json(result)).hexdigest()
    return "\n".join(out) + f"\n<!-- guard-result-sha256: {digest} -->\n"


def _method_section(plan: dict[str, Any] | None) -> list[str]:
    """Method choices and switches/supplements (FEATURE-002-B); omitted when the plan has none."""
    if not plan:
        return []
    choices = [c for c in plan["checks"] if c.get("method_choice")]
    changes = plan.get("method_changes") or []
    if not choices and not changes:
        return []
    out = ["## Method Choices and Changes", ""]
    out += _table(
        ["Check", "Considered", "Cost factors", "Selected", "Reason"],
        [
            [
                c["id"],
                c["method_choice"]["considered"],
                c["method_choice"]["cost"],
                c["method_choice"]["selected"],
                c["method_choice"]["reason"],
            ]
            for c in choices
        ],
    )
    out += ["Changes during the run:", ""]
    out += _table(
        [
            "Check",
            "Change",
            "Method",
            "From",
            "Reason",
            "Selected before",
            "Evidence so far",
            "Findings so far",
        ],
        [
            [
                e["check"],
                e["change"],
                f"{e['method']['name']} ({e['method']['kind']})",
                e["from"],
                e["reason"],
                e["selected_before"],
                e["evidence_ids"],
                e["finding_ids"],
            ]
            for e in changes
        ],
    )
    return out


def _adapter_section(adapter_runs: list[dict[str, Any]]) -> list[str]:
    if not adapter_runs:
        return []
    out = ["## Adapter Runs", ""]
    rows = []
    # FEATURE-002-D: the Scanners/Mode columns appear only when a Trivy run is present
    trivy_cols = any(r.get("adapter") == "trivy" for r in adapter_runs)
    for r in adapter_runs:
        for check, c in sorted((r.get("checks") or {}).items()):
            counts = c.get("counts", {})
            extra = [c.get("scanners") or "—", c.get("mode") or "—"] if trivy_cols else []
            rows.append(
                [
                    r["n"],
                    r["adapter"],
                    r.get("version"),
                    r.get("asset"),
                    "yes" if r.get("platform_validated") else "no",
                    check,
                    *extra,
                    c["status"],
                    c["method_status"],
                    f"{counts.get('scanned', 0)}/{counts.get('skipped', 0)}/{counts.get('unaccounted', 0)}",
                    c.get("gaps"),
                ]
            )
        if not r.get("checks") and r.get("gap"):
            rows.append(
                [
                    r["n"],
                    r["adapter"],
                    r.get("version"),
                    r.get("asset"),
                    "—",
                    "—",
                    *(["—", "—"] if trivy_cols else []),
                    "precheck_failed",
                    "failed",
                    "—",
                    r["gap"]["reason"],
                ]
            )
    out += _table(
        [
            "Run",
            "Adapter",
            "Version",
            "Asset",
            "Platform validated",
            "Check",
            *(["Scanners", "Mode"] if trivy_cols else []),
            "Status",
            "Method status",
            "Scanned/skipped/unaccounted",
            "Gaps",
        ],
        rows,
    )
    return out


def _trivy_component_section(adapter_runs: list[dict[str, Any]]) -> list[str]:
    """Trivy component state per run (FEATURE-002-D); omitted unless a Trivy run is present."""
    runs = [r for r in adapter_runs if r.get("adapter") == "trivy"]
    if not runs:
        return []
    rows = []
    for r in runs:
        for name, c in sorted((r.get("components") or {}).items()):
            meta = c.get("metadata") or {}
            repo = f"{c['repository']}:{c['tag']}" if c.get("repository") else "—"
            rows.append(
                [
                    r["n"],
                    name,
                    c.get("state"),
                    c.get("registry") or "—",
                    repo,
                    c.get("content_digest") or "—",
                    ", ".join(f"{k}: {v}" for k, v in meta.items()) or "—",
                    c.get("age") or "—",
                    (r.get("rehash") or {}).get(name, "not used"),
                    c.get("reason") or "—",
                ]
            )
    out = ["## Trivy Component State", ""]
    out += _table(
        ["Run", "Component", "State", "Registry", "Repository:tag", "Content digest", "Metadata",
         "Age at scan", "Re-hash after scan", "Reason"],
        rows,
    )
    out += _bullets(
        [
            "No staleness threshold is applied; Guard judged sufficiency in the ledger",
            "Components are read in place; changes are detected by re-hashing after each scan, "
            "not prevented; "
            "the digest-verified binary is trusted not to write to them",
        ]
    )
    return out


def _provisioning_section(provisioning: list[dict[str, Any]] | None) -> list[str]:
    """Trivy component provisioning (FEATURE-002-D); omitted unless the verification provisioned."""
    if not provisioning:
        return []
    rows, limits = [], []
    for p in provisioning:
        if not p.get("operations"):
            rows.append([p["n"], "—", p.get("registry"), "—", "—", "—", p.get("outcome"), p.get("previous"),
                         "—", "—", "—", "—"])
        for op in p.get("operations") or []:
            rows.append(
                [
                    p["n"],
                    op["component"],
                    p.get("registry"),
                    f"{op['repository']}:{op['tag']}",
                    [h["host"] for h in op.get("known_hosts") or []],
                    op.get("grants") or [],
                    op["outcome"] + (f" ({op['reason']})" if op.get("reason") else ""),
                    op.get("previous"),
                    op.get("size_bytes"),
                    op.get("seconds"),
                    ", ".join(f"{k}: {v}" for k, v in (op.get("metadata") or {}).items()) or "—",
                    op.get("content_digest") or "—",
                ]
            )
        if p.get("limit") and md_text(p["limit"]) not in limits:
            limits.append(md_text(p["limit"]))
    out = ["## Tool Provisioning", ""]
    out += _table(
        ["Run", "Component", "Registry", "Repository:tag", "Known hosts", "Grants", "Outcome", "Previous",
         "Size (bytes)", "Seconds", "Metadata", "Content digest"],
        rows,
    )
    out += _bullets(
        [
            "Each provisioning run is a budgeted `tool_update` attempt under the verification's time limit",
            *limits,
            "Registries are not interchangeable: a component is provisioned only from the granted registry",
            "Masking covers recorded text only; it cannot prove that no secret was ever present",
        ]
    )
    return out


def _helper_section(part: dict[str, Any] | None) -> list[str]:
    """FEATURE-002-F "Temporary helper checks": rendered from the structured part only (no import, so the
    renderer manifest of CR-TASK-086 is unchanged); absent part → nothing."""
    if not part:
        return []
    out = ["## Temporary helper checks", "", md_text(part["statement"]), ""]
    out += _table(part["columns"], part["rows"])
    out += _bullets([md_text(g) for g in part["gaps"]])
    return out + _bullets([md_text(n) for n in part["notes"]])


def footer_digest(text: str) -> str | None:
    match = FOOTER.search(text)
    return match.group(1) if match else None


# --------------------------------------------------------------------------- FEATURE-002-C sections
def _minutes(seconds: Any) -> str:
    return f"{round((seconds or 0) / 60, 1)} min"


def _budget_section(result: dict[str, Any]) -> list[str]:
    b = result.get("budget")
    if not b:
        return []
    usage = b["model_usage"]
    out = ["## Budget", ""]
    out += _table(
        ["Limit", "Value"],
        [
            ["Total time", _minutes(b["total_seconds"]) + (" (toolkit default)" if b["defaulted"] else "")],
            ["Extra attempts", b["extra_attempts"]],
            ["Consumed time", _minutes(b["consumed_seconds"])],
            ["Extra attempts used", b["extra_used"]],
            ["Budget of a verification opened before budgets existed", "yes" if b["legacy"] else "no"],
        ],
    )
    if b["exhausted"] or b["attempts_exhausted"]:
        which = "time" if b["exhausted"] else "extra attempts"
        unverified = [r["check"] for r in result["ledger"] if r["state"] == "unconfirmed"]
        out += [
            f"**Budget exhausted ({which})** — unverified checks: {md_text(unverified)}",
            "",
        ]
    out += ["Extensions (by the user):", ""]
    out += _table(
        ["At", "Added time", "Added attempts", "Reason"],
        [[e["at"], _minutes(e["seconds"]), e["attempts"], e["reason"]] for e in b["extensions"]],
    )
    out += ["Pauses (excluded from the consumed time):", ""]
    out += _table(["Start", "End", "Reason"], [[p["start"], p["end"], p["reason"]] for p in b["pauses"]])
    out += ["Attempts:", ""]
    out += _table(
        ["Id", "Kind", "Covers", "Extra", "Status", "Overrun"],
        [
            [
                a["id"],
                a["kind"],
                [f"{c}/{m}" for c, m in a["covers"]["pairs"]]
                + a["covers"]["findings"]
                + a["covers"]["na"]
                + a["covers"].get("helpers", []),
                a["extra"],
                a["status"],
                _minutes(a["overrun_seconds"]) if a["overrun_seconds"] else "—",
            ]
            for a in result.get("attempts", [])
        ],
    )
    out += _bullets(
        [
            f"Model usage reported by the host: {usage['requests']} requests, {usage['input_tokens']} input "
            f"and {usage['output_tokens']} output tokens; "
            f"unknown for {usage['unknown_attempts']} attempt(s); "
            f"not applicable for {usage['not_applicable_attempts']} attempt(s) without a model"
        ]
    )
    return out


def _cancel_section(c: dict[str, Any] | None) -> list[str]:
    if not c:
        return []
    term = c["tool_termination"]
    tool = {
        "none": "no tool was running",
        "confirmed": "running tool stopped; its process group was seen exiting "
        "(processes that left the group are not tracked)",
        "finished": "the tool run ended before it could be stopped",
        "not_confirmed": f"termination NOT confirmed (process {term.get('pid')})",
    }.get(term.get("tool"), md_text(term))
    items = [
        f"Cancelled at {md_text(c['requested_at'])}"
        + (f" — reason: {md_text(c['reason'])}" if c.get("reason") else ""),
        f"Tool: {tool}" + (f" ({md_text(term.get('detail'))})" if term.get("detail") else ""),
        f"Agent work in progress {md_text(c['agent_attempts'])}: {md_text(c['agent_note'])}",
        md_text(c["remote_note"]),
        "Results recorded before the cancellation are kept; a cancelled verification is never a pass",
    ]
    if c.get("policy_note"):
        items.append(md_text(c["policy_note"]))
    return ["## Cancellation", "", *_bullets(items)]


def _egress_section(e: dict[str, Any] | None) -> list[str]:
    if e is None:
        return []
    out = ["## Outbound Calls (Egress)", "", "Grants (by the user, this verification only):", ""]
    out += _table(
        ["Id", "Purpose", "Recipient", "Data", "Scope", "Reason"],
        [[g["id"], g["purpose"], g["recipient"], g["data"], g["scope"], g["reason"]] for g in e["grants"]],
    )
    out += ["Declared or gated calls:", ""]
    # FEATURE-002-D: known hosts and use are shown only when a declaration carries known hosts
    hosts = any("known_hosts" in d for d in e["declarations"])
    out += _table(
        ["Id", "By", "Purpose", "Recipient", "Data", "Scope", "Decision"]
        + (["Known hosts", "Used"] if hosts else []),
        [
            [
                d["id"],
                d["by"],
                d["purpose"],
                d["recipient"],
                d["data"],
                d["scope"],
                d["decision"] + (f" (missing {d['missing']})" if d.get("missing") else ""),
                *(
                    [[h["host"] for h in d.get("known_hosts") or []], "yes" if d.get("used") else "no"]
                    if hosts
                    else []
                ),
            ]
            for d in e["declarations"]
        ],
    )
    out += _bullets(
        [
            "Agent declarations are an audit record, not enforced blocking",
            "Network access is not OS-enforced (including by tools the Adapters launch); calls that were "
            "not declared cannot be observed by the toolkit",
        ]
    )
    return out


def _origin_section(renderer: Any) -> list[str]:
    """Structured Result Origin (CR-TASK-086); omitted for results written before it."""
    if not renderer or not isinstance(renderer, dict):
        return []
    digest = renderer.get("renderer_digest")
    shown = md_text(digest) if isinstance(digest, str) else "renderer unknown"
    version = md_text(renderer.get("toolkit_version"))
    return [
        "## Structured Result Origin",
        "",
        *_bullets(
            [
                f"Structured result written by secure-code toolkit {version}; "
                f"renderer sha256 {shown}",
                "This identifies the build that wrote the structured result; a report re-created later by "
                "repair may come from a different build",
            ]
        ),
    ]
