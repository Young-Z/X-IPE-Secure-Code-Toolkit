"""The structured "Temporary helper checks" result part (AC-002F-07e, 05c, 09c; design §13 item 4).

`attach` runs right after the unchanged `engine.conclude` and adds `result["helpers"]` only when the
verification has helpers or helper methods (otherwise the result stays byte-identical). The part is a pure
function of the stored state and of the engine's review validity; the Markdown renderer prints its
`statement`, `rows`, `gaps` and `notes` (so both outputs come from the same recorded data).
"""

from __future__ import annotations

from typing import Any

from .model import (
    CONSENT,
    L01_HELPERS,
    TEMPORARY,
    UNCOVERED_IN_REPORT,
    granted,
    has_helper_methods,
    helpers,
)

COLUMNS = [
    "Helper",
    "Check",
    "Goal",
    "Read scope",
    "Judgement basis",
    "Script SHA-256",
    "Samples",
    "Reviewer",
    "Grant",
    "Conformance",
    "Manifest",
    "Execution",
    "Limits",
    "Time",
    "Findings",
    "Marking",
]
STATEMENT = (
    f"Temporary helper checks ({TEMPORARY}). The enforced container limits are the security boundary; the "
    "user grant is recorded cooperative consent that the toolkit cannot prove a person gave, never a "
    "security boundary. A clean helper result counts only with Reviewer acceptance and whole-object coverage."
)
NOTES = [
    "Static rules are defence in depth only; samples prove only that the script separates those samples",
    "Reviewer acceptance is a model judgement, not proof of completeness",
    "Guard does not enforce per-file coverage of the check object for any method; uncovered files are listed",
    "Runtime or kernel escapes are outside the toolkit's protection; a forged runtime CLI could lie to "
    "probes",
    "Record integrity (HMAC) resists accidental edits, not a local actor who can read the key file",
    f"Limits: at most {L01_HELPERS} helpers per verification; no network; read-only link-free input copy; "
    "512 MiB memory, 1 CPU, 64 processes, 256 open files, 16 MiB /tmp, 2 MiB results, 64 KiB output, "
    "120 s per run",
]


def _decisions(result: dict[str, Any], digests: dict[str, str]) -> dict[tuple, list[tuple[int, dict]]]:
    grouped: dict[tuple, list[tuple[int, dict]]] = {}
    for review in result.get("reviews") or []:
        if not review.get("valid"):
            continue
        for s in review["subjects"]:
            if s["type"] == "helper" and "phase" in s and digests.get(s["id"]) == s.get("helper_digest"):
                grouped.setdefault((s["id"], s["phase"], s.get("run")), []).append((review["index"], s))
    return grouped


def _pre(grouped: dict, hid: str) -> str:
    entries = grouped.get((hid, "pre_execution", None))
    if not entries:
        return "not_reviewed"
    votes = {s["result"] for _, s in entries}
    return entries[0][1]["result"] if len(votes) == 1 and entries[0][1]["result"] else "disagreement"


def display(helper: dict[str, Any], pre: str, grant: dict | None) -> tuple[str, str]:
    """(displayed state, gap reason) — design §4; "reviewed" is never followed by "executable"."""
    finished = [r for r in helper["runs"] if r["outcome"] in ("failed", "findings", "clean")]
    not_executed = [e for e in helper["events"] if e["step"] == "not_executed"]
    if helper["status"] == "check_failed":
        return "check_failed", f"checks failed: {helper['reason']}"
    if helper.get("blocked"):
        return "blocked: samples failed", "samples failed: the helper was not run on targets"
    if finished:
        run = finished[-1]
        if run["outcome"] == "failed":
            return "executed: failed", f"helper run failed: {run['reason']}"
        if run["outcome"] == "findings":
            return "executed: findings", None
        state = run["acceptance"]["state"]
        label = {
            "pending": "acceptance pending",
            "accepted_full": "accepted, whole object",
            "accepted_partial": "accepted, partial coverage",
            "rejected": "rejected",
            "stale": "rejected",
        }[state]
        gap = {
            "pending": "clean result not accepted",
            "accepted_full": None,
            "accepted_partial": "clean result accepted with partial coverage",
            "rejected": "clean result rejected by the Reviewer",
            "stale": "post-run acceptance not valid when recorded",
        }[state]
        return f"executed: clean ({label})", gap
    if pre == "rejected":
        return "reviewed (rejected)", "rejected by the Reviewer"
    if pre != "accepted":
        return "checked", "not reviewed" if pre == "not_reviewed" else "Reviewer decisions disagree"
    if grant is None:
        return "reviewed (accepted, not granted)", "not granted"
    if not_executed:
        reason = not_executed[-1]["detail"]
        return f"not executed: {reason}", f"not executed: {reason}"
    return "granted (not executed)", "not executed"


def _entry(state: dict[str, Any], helper: dict[str, Any], grouped: dict) -> dict[str, Any]:
    pre = _pre(grouped, helper["id"])
    grant = granted(state, helper)
    shown, gap = display(helper, pre, grant)
    runs = helper["runs"]
    last = next((r for r in reversed(runs) if r["outcome"] in ("failed", "findings", "clean")), None)
    uncovered = last["uncovered"] if last and last["outcome"] == "clean" else []
    findings = [f["id"] for f in state["findings"] if (f.get("helper") or {}).get("id") == helper["id"]]
    decisions = [
        {
            "phase": key[1],
            "run": key[2],
            "result": entries[0][1]["result"]
            if len({s["result"] for _, s in entries}) == 1
            else "disagreement",
            "records": [i for i, _ in entries],
        }
        for key, entries in sorted(grouped.items(), key=lambda kv: (kv[0][1], kv[0][2] or 0))
        if key[0] == helper["id"]
    ]
    return {
        "id": helper["id"],
        "check": helper["check"],
        "method": helper["method"],
        "goal": helper["goal"],
        "read_scope": helper["read_scope"],
        "judgement_basis": helper["judgement_basis"],
        "script_sha256": helper["script"]["sha256"],
        "helper_digest": helper["helper_digest"],
        "samples": [
            {
                "id": s["id"],
                "kind": s["kind"],
                "origin": s["origin"]["type"],
                "path": s["path"],
                "sha256": s["sha256"],
            }
            for s in helper["samples"]
        ],
        "sample_outcomes": [o for r in runs for o in r.get("samples", [])],
        "state": shown,
        "review": {
            "not_reviewed": "not reviewed",
            "accepted": "accepted (not permission to execute)",
            "rejected": "rejected",
            "disagreement": "reviews disagree",
        }[pre],
        "reviewer_decisions": decisions,
        "grant": f"granted {grant['id']} (recorded cooperative consent)" if grant else "not granted",
        "grant_wording": CONSENT if grant else None,
        "conformance": last["conformance"] if last else None,
        "manifest": last["manifest"]["digest"] if last and last.get("manifest") else None,
        "execution": shown if shown.startswith(("executed", "not executed", "blocked")) else "not executed",
        "runs": [
            {
                k: r.get(k)
                for k in (
                    "n",
                    "attempt",
                    "outcome",
                    "reason",
                    "seconds",
                    "time_limit",
                    "time_limit_capped",
                    "cleanup",
                )
            }
            | {
                "limit": (r.get("target") or {}).get("limit"),
                "acceptance": r["acceptance"]["state"] if r.get("acceptance") else None,
            }
            for r in runs
        ],
        "time_seconds": round(sum(r.get("seconds") or 0 for r in runs), 2),
        "limits": "L-01…L-12 enforced and proven by conformance",
        "findings": findings,
        "gap": gap,
        "uncovered": uncovered,
        "uncovered_count": len(uncovered) if last else 0,
        "object_too_large": bool(last and last["outcome"] == "clean" and last["object_files"]["too_large"]),
        "events": len(helper["events"]),
        "marking": TEMPORARY,
    }


def part(state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    digests = {h["id"]: h["helper_digest"] for h in helpers(state)}
    grouped = _decisions(result, digests)
    entries = [_entry(state, h, grouped) for h in helpers(state)]
    submitted = {(h["check"], h["method"]) for h in helpers(state)}
    unsubmitted = [
        {"check": c["id"], "method": m["name"]}
        for c in (state.get("plan") or {}).get("checks", [])
        for m in c["methods"]
        if m["name"].casefold().startswith("helper.") and (c["id"], m["name"]) not in submitted
    ]
    gaps = []
    for e in entries:
        if e["gap"]:
            gaps.append(f"Gap: helper {e['id']} (check {e['check']}, goal: {e['goal']}): {e['gap']}")
        if e["uncovered_count"] or e["object_too_large"]:
            shown = e["uncovered"][:UNCOVERED_IN_REPORT]
            more = (
                "" if e["uncovered_count"] <= len(shown) else f" and {e['uncovered_count'] - len(shown)} more"
            )
            gaps.append(
                f"Gap: helper {e['id']} did not cover {e['uncovered_count']} file(s) of check {e['check']}: "
                f"{', '.join(shown)}{more} — not covered by this helper; Guard does not check per-file "
                "coverage, "
                "other evidence may still make the check met"
            )
    for h in helpers(state):
        if any(r.get("cleanup") == "not confirmed" for r in h["runs"]):
            gaps.append(
                f"Gap: helper {h['id']}: removal of its runtime objects or staging was not confirmed; "
                "the next helper command's sweep retries"
            )
    for u in unsubmitted:
        gaps.append(f"Gap: helper method {u['method']} of check {u['check']}: no helper was submitted")
    rows = [
        [
            e["id"],
            e["check"],
            e["goal"],
            e["read_scope"],
            f"finding: {e['judgement_basis']['finding']}; no finding: {e['judgement_basis']['no_finding']}",
            e["script_sha256"],
            [f"{s['id']} {s['kind']} ({s['origin']})" for s in e["samples"]],
            f"{e['review']}; " + ", ".join(f"{d['phase']}: {d['result']}" for d in e["reviewer_decisions"]),
            e["grant"],
            e["conformance"],
            e["manifest"],
            e["execution"],
            e["limits"],
            f"{e['time_seconds']} s",
            e["findings"],
            e["marking"],
        ]
        for e in entries
    ]
    return {
        "statement": STATEMENT,
        "columns": COLUMNS,
        "rows": rows,
        "gaps": gaps,
        "notes": NOTES,
        "helpers": entries,
        "unsubmitted_methods": unsubmitted,
    }


def attach(state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Add the helper part after `engine.conclude` when the run has helpers or helper methods."""
    if helpers(state) or has_helper_methods(state):
        result["helpers"] = part(state, result)
    return result
