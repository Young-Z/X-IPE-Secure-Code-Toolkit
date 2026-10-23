"""Deterministic conclusion: ledger finalization, review validity, severity and verdict (no AI, no I/O).

`conclude` is a pure function of the recorded run state, the current target observations and the
current state of each adopted Policy. The same inputs always give the same result.
"""

from __future__ import annotations

from typing import Any

from .model import GUARD_REL, RETENTION_DAYS, SCHEMA_RESULT, SEVERE, severity_rank
from .targets import owning_target, path_role

LIMITS = [
    "Reviewer invocation is declared by the agent and bound to target digests; "
    "the script cannot prove it ran",
    "Adapters: Opengrep and Trivy run only as the registered official binaries on staged copies; their "
    "file-system and network access are not OS-enforced; Trivy runs on Linux x86-64/arm64 only, scans "
    "offline, reads the provisioned components in place (changes are detected by re-hashing after each "
    "scan, not prevented) and its provisioning hosts are a configuration-level expectation; Strix is not "
    "available yet",
    "Masking uses pattern-based credential detection, not a complete data-loss-prevention guarantee",
    "Budget: only work registered as attempts and tool runs is counted; work done without an attempt or "
    "while paused cannot be observed; time is wall-clock minus pauses, not a money cap",
    "Egress: agent declarations are an audit record; network access (including by tools the Adapters "
    "launch) is not OS-enforced and undeclared calls cannot be observed",
    "Budget extensions, egress grants and risk acceptance need an interactive confirmation; this is a "
    "cooperative control (a program driving a pseudo-terminal could pass it), not an authorization boundary",
    "Termination is confirmed when the tool's process group was seen exiting; processes that left the "
    "group are not tracked",
]


def _reason(code: str, subject: str, detail: str) -> dict[str, str]:
    return {"code": code, "subject": subject, "detail": detail}


def _relevant_paths(state: dict[str, Any], subject: dict[str, Any]) -> list[str]:
    artifact = state["artifact"]
    if subject["type"] == "finding":
        found = next(f for f in state["findings"] if f["id"] == subject["id"])
        paths = [owning_target(artifact, found["location"]["path"])]
    elif subject["id"].startswith("policy:"):
        paths = [t["path"] for t in artifact["targets"]]
    else:
        check = next(c for c in state["plan"]["checks"] if c["id"] == subject["id"])
        paths = [owning_target(artifact, o) for o in check["object"]]
    digests = {t["path"]: t["digest"] for t in artifact["targets"]}
    return sorted({p for p in paths if p is not None and digests.get(p) is not None})


def _judge_review(state: dict[str, Any], review: dict[str, Any], current: dict[str, Any]) -> list[str]:
    reasons = list(review.get("completeness") or [])
    reviewed = {r["path"]: r["digest"] for r in review["reviewed_targets"]}
    for path, digest in sorted(reviewed.items()):
        if path not in current:
            reasons.append(f"reviewed path {path} is not a target")
        elif (current[path] or {}).get("digest") != digest:
            reasons.append(f"stale: {path} changed since it was reviewed")
    for subject in review["subjects"]:
        for path in _relevant_paths(state, subject):
            if path not in reviewed:
                reasons.append(f"not bound: {subject['id']} needs reviewed digest of {path}")
    return reasons


def _decisions(state: dict[str, Any], reviews: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """Agreement of all valid reviews per subject; disagreement never resolves by order."""
    grouped: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
    for review in reviews:
        if not review["valid"]:
            continue
        for subject in review["subjects"]:
            grouped.setdefault((subject["type"], subject["id"]), []).append((review["index"], subject))
    decided: dict[tuple[str, str], dict[str, Any]] = {}
    for key, entries in grouped.items():
        votes = {(s["result"], (s["severity_opinion"] or {}).get("severity")) for _, s in entries}
        evidence = sorted({e for _, s in entries for e in (s["severity_opinion"] or {}).get("evidence", [])})
        opinion = entries[0][1]["severity_opinion"]
        decided[key] = {
            "agreed": len(votes) == 1,
            "result": entries[0][1]["result"] if len(votes) == 1 else None,
            "opinion": {"severity": opinion["severity"], "evidence": evidence} if opinion else None,
            "basis": [s["basis"] for _, s in entries if s["basis"]],
            "records": [i for i, _ in entries],
        }
    return decided


def _severity(original: str, opinion: dict[str, Any] | None) -> tuple[str, bool]:
    """Higher severity stands unless the Reviewer gave bound evidence; unknown never becomes Low."""
    if opinion is None:
        return original, False
    proposed = opinion["severity"]
    conflict = proposed != original
    if opinion["evidence"]:
        return proposed, conflict
    if original == "unknown":
        return (proposed if proposed in SEVERE else "unknown"), conflict
    return (proposed if severity_rank(proposed) > severity_rank(original) else original), conflict


def _on_object(path: str, objects: list[str]) -> bool:
    return any(path == o or o == "." or path.startswith(o + "/") for o in objects)


def _met(check: dict[str, Any], entry: dict[str, Any], state: dict[str, Any]) -> tuple[list[str], list[dict]]:
    """Missing evidence that prevents `met`, and failed auxiliary methods replaced by other evidence."""
    by_id = {e["id"]: e for e in state["evidence"]}
    referenced = [by_id[e] for e in entry["evidence"] if e in by_id]
    usable = [
        e
        for e in referenced
        if e["method_status"] == "ok"
        and check["id"] in e["checks"]
        and any(
            _on_object(p, check["object"]) and path_role(state["artifact"], p) == "target" for p in e["paths"]
        )
    ]
    missing: list[str] = []
    if not any(e["kind"] in check["minimum_evidence"] for e in usable):
        missing.append(f"no successful {' or '.join(check['minimum_evidence'])} evidence on the check object")
    substitution: list[dict[str, str]] = []
    for method in check["methods"]:
        done = [e for e in usable if e["method"] == method["name"] and e["kind"] == method["kind"]]
        if done:
            continue
        if method["required"]:
            missing.append(f"required method {method['name']} ({method['kind']}) has no successful evidence")
        elif any(
            e["method"] == method["name"] and e["method_status"] == "failed" and check["id"] in e["checks"]
            for e in state["evidence"]
        ):
            substitution.append({"method": method["name"], "status": "failed"})
    return missing, substitution


def _na_state(decision: dict[str, Any] | None) -> tuple[str, str | None]:
    if decision is None:
        return "unconfirmed", "N/A not confirmed by a valid review"
    if not decision["agreed"]:
        return "unconfirmed", "N/A reviews disagree"
    if decision["result"] == "confirmed":
        return "n/a", None
    return "unconfirmed", "N/A rejected by review"


def _ledger(state: dict[str, Any], decided: dict) -> list[dict[str, Any]]:
    plan = state["plan"]
    if plan is None:
        return []
    by_id = {e["id"]: e for e in state["evidence"]}
    excluded = {e["check"]: e["reason"] for e in plan["exclusions"] if e["check"]}
    rows: list[dict[str, Any]] = []
    for check in plan["checks"]:
        entry = state["ledger"].get(check["id"])
        row = {
            "check": check["id"],
            "rule": check["rule"],
            "object": check["object"],
            "object_part": check["object_part"],
            "minimum_evidence": check["minimum_evidence"],
            "recorded_state": entry["state"] if entry else None,
            "state": None,
            "reason": None,
            "evidence_by_kind": {},
            "findings": entry["findings"] if entry else [],
            "substitution": [],
            "superseded": entry["superseded"] if entry else 0,
        }
        for eid in (entry or {}).get("evidence", []):
            row["evidence_by_kind"].setdefault(by_id[eid]["kind"], []).append(eid)
        row["evidence_by_kind"] = dict(sorted(row["evidence_by_kind"].items()))
        if check["id"] in excluded:
            row["state"], row["reason"] = "excluded", f"user scope exclusion: {excluded[check['id']]}"
        elif entry is None:
            row["state"], row["reason"] = "unconfirmed", "not executed: no ledger state was recorded"
        elif entry["state"] == "n/a":
            row["state"], why = _na_state(decided.get(("na_decision", check["id"])))
            row["reason"] = entry["reason"] if why is None else f"{why} (recorded reason: {entry['reason']})"
        elif entry["state"] == "met":
            missing, row["substitution"] = _met(check, entry, state)
            row["state"], row["reason"] = (
                ("unconfirmed", "; ".join(missing)) if missing else ("met", entry["reason"])
            )
        else:
            row["state"], row["reason"] = entry["state"], entry["reason"]
        rows.append(row)
    for na in plan["not_applicable"]:
        sid = f"policy:{na['rule']}"
        state_value, why = _na_state(decided.get(("na_decision", sid)))
        rows.append(
            {
                "check": sid,
                "rule": na["rule"],
                "object": [],
                "object_part": None,
                "minimum_evidence": [],
                "recorded_state": "n/a",
                "state": state_value,
                "reason": na["reason"] if why is None else f"{why} (recorded reason: {na['reason']})",
                "evidence_by_kind": {},
                "findings": [],
                "substitution": [],
                "superseded": 0,
            }
        )
    for ex in plan["exclusions"]:
        if ex["rule"]:
            rows.append(
                {
                    "check": f"rule:{ex['rule']}",
                    "rule": ex["rule"],
                    "object": [],
                    "object_part": None,
                    "minimum_evidence": [],
                    "recorded_state": None,
                    "state": "excluded",
                    "reason": f"user scope exclusion: {ex['reason']}",
                    "evidence_by_kind": {},
                    "findings": [],
                    "substitution": [],
                    "superseded": 0,
                }
            )
    return rows


def _findings(state: dict[str, Any], decided: dict) -> list[dict[str, Any]]:
    result = []
    for found in state["findings"]:
        decision = decided.get(("finding", found["id"]))
        opinion = decision["opinion"] if decision and decision["agreed"] else None
        final, conflict = _severity(found["severity"], opinion)
        requires = (
            found["severity"] == "unknown"
            or final == "unknown"
            or found["severity"] in SEVERE
            or final in SEVERE
            or found["disputed"]
        )
        if decision and decision["agreed"]:
            review = decision["result"]
        elif decision or requires:
            review = "unconfirmed"
        else:
            review = "not_required"
        out = {k: v for k, v in found.items() if k != "severity"}
        out.update(
            {
                "original_severity": found["severity"],
                "severity_opinion": decision["opinion"] if decision else None,
                "final_severity": final,
                "severity_conflict": conflict,
                "requires_review": requires,
                "review": review,
                "review_disagreement": bool(decision and not decision["agreed"]),
                "review_basis": decision["basis"] if decision else [],
                "review_records": decision["records"] if decision else [],
            }
        )
        result.append(out)
    return result


def conclude(
    state: dict[str, Any],
    observed: dict[str, Any],
    policy_now: dict[str, str],
    ended_at: str,
    control: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute the structured result of one verification."""
    artifact = state["artifact"]
    current = {t["path"]: observed.get(t["path"]) for t in artifact["targets"]}
    reviews = []
    for index, review in enumerate(state["reviews"]):
        reasons = _judge_review(state, review, current)
        reviews.append(
            {
                "index": index,
                "valid": not reasons,
                "invalid_reasons": reasons,
                **{k: v for k, v in review.items() if k != "completeness"},
            }
        )
    decided = _decisions(state, reviews)
    ledger = _ledger(state, decided)
    findings = _findings(state, decided)

    fail = [
        _reason("CONFIRMED_FINDING", f["id"], f"{f['final_severity']}, confirmed by a valid review")
        for f in findings
        if f["review"] == "confirmed" and f["final_severity"] in SEVERE
    ]
    blockers: list[dict[str, str]] = []
    if state["plan"] is None:
        blockers.append(_reason("NO_PLAN", "plan", "no check plan was recorded"))
    for row in ledger:
        if row["state"] == "unconfirmed":
            blockers.append(_reason("CHECK_UNCONFIRMED", row["check"], row["reason"]))
        elif row["state"] == "excluded":
            blockers.append(_reason("SCOPE_EXCLUSION", row["check"], row["reason"]))
        elif row["state"] == "not_met":
            blockers.append(_reason("CHECK_NOT_MET", row["check"], row["reason"] or "check not met"))
    for f in findings:
        if f["review_disagreement"]:
            blockers.append(_reason("REVIEW_DISAGREEMENT", f["id"], "valid reviews disagree"))
        if f["requires_review"] and f["review"] not in ("confirmed", "false_positive"):
            blockers.append(
                _reason(
                    "FINDING_UNCONFIRMED",
                    f["id"],
                    f"{f['final_severity']} finding without a confirming valid review",
                )
            )
        if f["review"] == "confirmed" and f["final_severity"] == "unknown":
            blockers.append(_reason("SEVERITY_UNKNOWN", f["id"], "confirmed finding with unknown severity"))
    for key, decision in sorted(decided.items()):
        if key[0] == "na_decision" and not decision["agreed"]:
            blockers.append(_reason("REVIEW_DISAGREEMENT", key[1], "valid reviews disagree"))
    for conflict in state["conflicts"]:
        if conflict["verdict_affecting"] and not conflict["resolved"]:
            blockers.append(_reason("CONFLICT_UNRESOLVED", conflict["id"], conflict["description"]))
    targets_out = []
    for t in artifact["targets"]:
        now = current[t["path"]] or {
            "digest": "missing",
            "incomplete": True,
            "not_followed": [],
            "unreadable": [],
        }
        changed = now["digest"] != t["digest"]
        incomplete = bool(t["incomplete"] or now["incomplete"])
        if changed:
            blockers.append(
                _reason("TARGET_CHANGED", t["path"], "target changed since the verification opened")
            )
        if incomplete:
            blockers.append(
                _reason(
                    "TARGET_INCOMPLETE",
                    t["path"],
                    "content outside the folder, dangling links or unreadable entries",
                )
            )
        targets_out.append(
            {
                "path": t["path"],
                "kind": t["kind"],
                "change": t["change"],
                "old_path": t["old_path"],
                "digest_at_open": t["digest"],
                "digest_at_conclusion": now["digest"],
                "changed": changed,
                "incomplete": incomplete,
                "not_followed": sorted({json_key(n) for n in t["not_followed"] + now["not_followed"]}),
                "unreadable": sorted(set(t["unreadable"]) | set(now["unreadable"])),
            }
        )
    adopted = []
    for a in state["scope"]["adopted"]:
        status = policy_now.get(a["rule"], "missing")
        if status != "unchanged":
            blockers.append(
                _reason("POLICY_CHANGED", a["rule"], f"adopted Policy is {status} since adoption")
            )
        adopted.append({**a, "at_conclusion": status})

    control = control or {}
    if control.get("cancellation"):
        blockers.append(
            _reason("CANCELLED", "verification", "cancelled by the user; unfinished work was not verified")
        )

    if fail:
        verdict, reasons, other = "fail", fail, blockers
    elif blockers:
        verdict, reasons, other = "cannot_confirm_pass", blockers, []
    else:
        verdict, other = "pass", []
        reasons = [
            _reason(
                "ALL_CHECKS_SATISFIED",
                "ledger",
                "every necessary check met or reviewed N/A; no verdict-affecting finding",
            )
        ]
    vid = state["verification_id"]
    return {
        "schema": SCHEMA_RESULT,
        "verification_id": vid,
        "opened_at": state["opened_at"],
        "ended_at": ended_at,
        "request": state["request"],
        "baseline": state["baseline"],
        "verdict": verdict,
        "reasons": reasons,
        "other_blockers": other,
        "scope": {"scope_id": state["scope"]["scope_id"], "mode": state["scope"]["mode"], "adopted": adopted},
        "artifact": {
            "whole_project": artifact["whole_project"],
            "targets": targets_out,
            "context": artifact["context"],
            "suggested": artifact["suggested"],
            "copilot_reports": artifact["copilot_reports"],
            "not_verified": "read-only context, suggested files and Copilot reports are not verified",
        },
        "plan": state["plan"],
        "ledger": ledger,
        "evidence": [{k: v for k, v in e.items() if k != "stored_bytes"} for e in state["evidence"]],
        "findings": findings,
        "reviews": reviews,
        "conflicts": state["conflicts"],
        "risk_acceptances": [],
        "adapter_runs": state.get("adapter_runs", []),
        "evidence_retention": {
            "location": f"{GUARD_REL}/{vid}/",
            "days_after_end": RETENTION_DAYS,
            "removal": "only by the explicit command secure-code guard cleanup",
        },
        "limits": LIMITS,
        "budget": control.get("budget"),
        "attempts": control.get("attempts", []),
        "egress": control.get("egress", {"grants": [], "declarations": []}),
        "cancellation": control.get("cancellation"),
        # FEATURE-002-D: only verifications that provisioned Trivy components carry this key
        **({"tool_provisioning": state["tool_provisioning"]} if state.get("tool_provisioning") else {}),
    }


def json_key(item: dict[str, Any]) -> str:
    return f"{item['path']}{'' if item['inside_tree'] else ' (outside the target)'}"
