"""Deterministic adoption states, attention list and gaps (AC-003A-01a…01d, 02d, 04e…04i, 05a…05g).

No AI and no randomness: the same state, current digests and Policy states give the same content.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..atomic import dumps_json
from .model import HIGH_RISK, NEEDS_ATTENTION, SCHEMA_RESULT, SEVERITY_ORDER, STATES

POLICY_STEP = (
    "Re-confirm the scope with the Framework skill (secure-code policy resolve, scope save) "
    "and open a new collaboration"
)
BOUNDARIES = (
    "This report is not a pass, approval or security verification; Copilot gives no verdict.",
    "The independent review reduces self-confirmation bias but is not a correctness guarantee.",
    "This report does not replace Guard verification; Guard takes it as context only, never as evidence "
    "of a pass.",
    "An upstream decision to continue is not adoption.",
)
DESIGN_BOUNDARY = "For the design stage, adoption in the design does not show the measure is implemented."
RETENTION = {
    "reports": "kept until the user removes them",
    "private_data": "kept until the user removes it; no automatic expiry",
}


def invalidated(state: dict[str, Any], policy_now: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Persisted invalidated rules plus adopted rules that are now changed or missing (never shrinks)."""
    out = {rule: dict(info) for rule, info in state.get("invalidated_rules", {}).items()}
    for a in state["scope"]["adopted"]:
        now = policy_now.get(a["rule"], "missing")
        if now != "unchanged" and a["rule"] not in out:
            out[a["rule"]] = {"detected_at": None, "now": now}
    return out


def _change(state: dict[str, Any], path: str, now: str | None) -> str:
    if now is None:
        entry = state["manifest"].get(path, {})
        return "renamed_away" if entry.get("change") == "renamed_away" else "deleted"
    return now if now in ("unreadable", "unsafe", "not_a_file") else "modified"


def _matches(reviewed: str, now: str | None) -> bool:
    return now is None if reviewed == "absent" else reviewed == now


def evaluate(
    state: dict[str, Any], current: dict[str, str | None], policy_now: dict[str, str]
) -> dict[str, Any]:
    """Round-independent structured content of one collaboration (the state signature covers it)."""
    bad_rules = invalidated(state, policy_now)
    reviews = sorted(state["reviews"], key=lambda r: r["seq"])
    counted: dict[int, list[str]] = {r["seq"]: [] for r in reviews}
    not_counted: dict[int, list[dict[str, str]]] = {r["seq"]: [] for r in reviews}
    suggestions: list[dict[str, Any]] = []
    any_valid = False
    for s in state["suggestions"]:
        valid: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for r in reviews:
            subject = next((x for x in r["subjects"] if x["id"] == s["id"]), None)
            if subject is None:
                continue
            wrong = [f for f in s["files"] if f in r["wrong_version"]]
            if r["completeness"]:
                not_counted[r["seq"]].append({"id": s["id"], "reason": "record incomplete"})
            elif subject["result"] is None:
                not_counted[r["seq"]].append({"id": s["id"], "reason": "no result"})
            elif wrong:
                not_counted[r["seq"]].append(
                    {"id": s["id"], "reason": f"wrong version of {', '.join(wrong)}"}
                )
            else:
                valid.append((r, subject))
        item = {
            k: s[k]
            for k in (
                "id",
                "rule",
                "files",
                "location",
                "action",
                "reason",
                "severity",
                "stage",
                "masked",
                "batch",
                "recorded_at",
            )
        }
        item.update(state=None, basis=None, review_seq=None, changed=[], history=[])
        latest = valid[-1] if valid else None
        any_valid = any_valid or bool(valid)
        for r, _ in valid[:-1]:
            not_counted[r["seq"]].append(
                {"id": s["id"], "reason": f"superseded by review {latest[0]['seq']}"}
            )
        if s["rule"] in bad_rules:
            item["state"] = "policy_changed"
            if latest:
                not_counted[latest[0]["seq"]].append({"id": s["id"], "reason": "policy changed"})
        elif latest is None:
            item["state"] = "not_reviewed"
        else:
            r, subject = latest
            reviewed = {t["path"]: t["digest"] for t in r["reviewed_targets"]}
            changed = [
                {"path": f, "change": _change(state, f, current.get(f))}
                for f in s["files"]
                if not _matches(reviewed.get(f, "absent"), current.get(f))
            ]
            if changed:
                item["state"], item["changed"] = "stale", changed
                text = ", ".join(f"{c['path']} {c['change']}" for c in changed)
                not_counted[r["seq"]].append({"id": s["id"], "reason": f"stale: {text} since the review"})
            else:
                item.update(state=subject["result"], basis=subject["basis"], review_seq=r["seq"])
                counted[r["seq"]].append(s["id"])
        item["history"] = [
            {"seq": r["seq"], "result": x["result"], "basis": x["basis"]}
            for r, x in valid
            if r["seq"] != item["review_seq"]
        ]
        suggestions.append(item)
    attention, gaps = _attention(suggestions)
    review_rows = [
        {
            "seq": r["seq"],
            "valid": not r["completeness"] and not r["wrong_version"],
            "reasons": [*r["completeness"], *(f"wrong version: {p}" for p in r["wrong_version"])],
            "invocation": r["invocation"],
            "requirement": r["requirement"],
            "reviewed_targets": r["reviewed_targets"],
            "reviewed_at": r["reviewed_at"],
            "subjects": r["subjects"],
            "masked": r["masked"],
            "recorded_at": r["recorded_at"],
            "counted": counted[r["seq"]],
            "not_counted": not_counted[r["seq"]],
        }
        for r in reviews
    ]
    policy = {a["rule"]: policy_now.get(a["rule"], "missing") for a in state["scope"]["adopted"]}
    boundaries = [*BOUNDARIES, *([DESIGN_BOUNDARY] if state["stage"] == "design" else [])]
    return {
        "schema": SCHEMA_RESULT,
        "collaboration_id": state["collaboration_id"],
        "stage": state["stage"],
        "task": state["task"],
        "masked": state["masked"],
        "opened_at": state["opened_at"],
        "scope": {
            "scope_id": state["scope"]["scope_id"],
            "mode": state["scope"]["mode"],
            "adopted": [{**a, "now": policy[a["rule"]]} for a in state["scope"]["adopted"]],
            "invalidated": bad_rules,
        },
        "artifacts": state["artifacts"],
        "manifest": [
            {
                "path": p,
                "change": m["change"],
                "old_path": m["old_path"],
                "source": m["source"],
                "recorded_digest": m["digest"],
                "current_digest": current.get(p),
                "recorded_at": m["recorded_at"],
            }
            for p, m in sorted(state["manifest"].items())
        ],
        "context": state["context"],
        "suggestions": suggestions,
        "counts": {k: sum(1 for s in suggestions if s["state"] == k) for k in STATES},
        "attention": attention,
        "gaps": gaps,
        "re_review": sorted(s["id"] for s in suggestions if s["state"] in ("stale", "not_reviewed")),
        "reviews": review_rows,
        "snapshot_before_review": not any_valid,
        "policy_next_step": POLICY_STEP if any(s["state"] == "policy_changed" for s in suggestions) else None,
        "boundaries": boundaries,
        "retention": dict(RETENTION),
    }


def _reason(s: dict[str, Any]) -> str:
    state = s["state"]
    if state == "not_reviewed":
        return "no valid review covers it"
    if state == "stale":
        return "bound file changed since the review: " + ", ".join(
            f"{c['path']} ({c['change']})" for c in s["changed"]
        )
    if state == "policy_changed":
        return f"Policy {s['rule']} changed or was removed since the collaboration was opened"
    return f"Reviewer: {s['basis']}"


def _attention(suggestions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = [
        {
            "id": s["id"],
            "severity": s["severity"],
            "state": s["state"],
            "rule": s["rule"],
            "files": s["files"],
            "reason": _reason(s),
        }
        for s in suggestions
        if s["state"] in NEEDS_ATTENTION
    ]
    rows.sort(key=lambda r: (SEVERITY_ORDER.index(r["severity"]), r["id"]))
    return [r for r in rows if r["severity"] in HIGH_RISK], [
        r for r in rows if r["severity"] not in HIGH_RISK
    ]


def signature(content: dict[str, Any]) -> str:
    """`sha256:` of the canonical JSON of the round-independent content."""
    return "sha256:" + hashlib.sha256(dumps_json(content)).hexdigest()


ROUND_FIELDS = (
    "round",
    "supersedes",
    "published_at",
    "private_data_present_as_of_publication",
    "state_signature",
)


def content_of(result: dict[str, Any]) -> dict[str, Any]:
    """The round-independent content of a published result (its round fields removed)."""
    return {k: v for k, v in result.items() if k not in ROUND_FIELDS}
