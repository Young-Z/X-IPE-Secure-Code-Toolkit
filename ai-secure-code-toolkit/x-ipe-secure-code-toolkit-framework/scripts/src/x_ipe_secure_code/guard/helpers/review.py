"""The `helper` Reviewer subject (FR-002A-4 extension, design §6): validation, current decisions and the
post-run acceptance hook (DEC-3 variant B: engine `_met`/`conclude` unchanged).

A review is bound to the helper digest (script, declaration, samples) and, through the delivered
`engine._judge_review` (called read-only), to the owning targets of the helper's read scope.
"""

from __future__ import annotations

from typing import Any

from .. import engine
from ..model import ITEM_ID, Checker, GuardError
from . import evidence
from .model import DIGEST, UNCOVERED_IN_EVIDENCE, event, find, helpers

KEYS = {"type", "id", "phase", "result", "helper_digest", "run", "result_sha256", "basis", "evidence"}
PHASES = ("pre_execution", "post_run")
RESULTS = ("accepted", "rejected")


def subject(
    ck: Checker,
    state: dict[str, Any],
    subjects: list[dict[str, Any]],
    raw: dict[str, Any],
    i: int,
    warnings: list[str],
) -> dict[str, Any]:
    """Validate one `helper` subject of a Reviewer record (REVIEW_INVALID on any problem)."""
    where = f"subjects[{i}]"
    ck.obj(raw, where, KEYS, frozenset({"type", "id", "phase", "helper_digest"}))
    hid = ck.key(raw["id"], f"{where}.id")
    try:
        helper = find(state, hid)
    except GuardError as exc:
        raise ck.fail(f"{where}.id: {exc.message}") from None
    phase = ck.choice(raw["phase"], f"{where}.phase", PHASES)
    result = raw.get("result")
    if result is not None:
        ck.choice(result, f"{where}.result", RESULTS)
    else:
        warnings.append(f"{where}.result is missing")
    digest = ck.pattern(raw["helper_digest"], f"{where}.helper_digest", DIGEST)
    if digest != helper["helper_digest"]:
        raise ck.fail(f"{where}: review is not bound to the current helper (changed after review)")
    run_n = raw.get("run")
    result_sha = None
    if phase == "pre_execution":
        if run_n is not None or raw.get("result_sha256") is not None:
            raise ck.fail(f"{where}: a pre_execution subject has no run or result_sha256")
        if helper["status"] != "checked":
            raise ck.fail(f"{where}: helper {hid} is {helper['status']}, not checked")
    else:
        if not isinstance(run_n, int) or isinstance(run_n, bool):
            raise ck.fail(f"{where}.run must name the helper run")
        run = next((r for r in helper["runs"] if r["n"] == run_n), None)
        if run is None or run["outcome"] != "clean":
            raise ck.fail(f"{where}.run {run_n} is not a clean run of helper {hid}")
        result_sha = ck.pattern(raw.get("result_sha256"), f"{where}.result_sha256", DIGEST)
        if result_sha != run["target"]["result_sha256"]:
            raise ck.fail(f"{where}.result_sha256 does not match run {run_n}")
        if run["acceptance"]["state"] != "pending":
            raise ck.fail(
                f"{where}: post-run decision already recorded for run {run_n}; re-execute for a new decision"
            )
    key = (hid, phase, run_n)
    if any(s["type"] == "helper" and (s["id"], s["phase"], s.get("run")) == key for s in subjects):
        raise ck.fail(f"{where} is a duplicate subject")
    known = {e["id"] for e in state["evidence"]}
    refs = []
    for ref in ck.items(raw.get("evidence"), f"{where}.evidence"):
        ref = ck.pattern(ref, f"{where}.evidence", ITEM_ID)
        if ref not in known:
            raise ck.fail(f"{where}.evidence refers to unknown id {ref}")
        refs.append(ref)
    return {
        "type": "helper",
        "id": hid,
        "phase": phase,
        "run": run_n,
        "result": result,
        "helper_digest": digest,
        "result_sha256": result_sha,
        "basis": ck.text(raw.get("basis"), f"{where}.basis", required=False),
        "evidence": refs,
        "severity_opinion": None,
    }


def _current(state: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    return {t["path"]: observed.get(t["path"]) for t in state["artifact"]["targets"]}


def decisions(state: dict[str, Any], observed: dict[str, Any]) -> dict[tuple, dict[str, Any]]:
    """Helper decisions of the reviews valid now, grouped by (id, phase, run); disagreement never resolves."""
    current = _current(state, observed)
    digests = {h["id"]: h["helper_digest"] for h in helpers(state)}
    grouped: dict[tuple, list[tuple[int, dict[str, Any]]]] = {}
    for index, review in enumerate(state["reviews"]):
        subjects = [s for s in review["subjects"] if s["type"] == "helper"]
        if not subjects or engine._judge_review(state, review, current):
            continue
        for s in subjects:
            if "phase" in s and digests.get(s["id"]) == s["helper_digest"]:
                grouped.setdefault((s["id"], s["phase"], s.get("run")), []).append((index, s))
    out = {}
    for key, entries in grouped.items():
        votes = {s["result"] for _, s in entries}
        out[key] = {
            "agreed": len(votes) == 1,
            "result": entries[0][1]["result"] if len(votes) == 1 else None,
            "records": [i for i, _ in entries],
            "basis": [s["basis"] for _, s in entries if s["basis"]],
        }
    return out


def pre_execution(state: dict[str, Any], helper: dict[str, Any], observed: dict[str, Any]) -> str:
    """`accepted`, `rejected`, `disagreement` or `not_reviewed` — evaluated now."""
    decision = decisions(state, observed).get((helper["id"], "pre_execution", None))
    if decision is None:
        return "not_reviewed"
    if not decision["agreed"]:
        return "disagreement"
    return decision["result"] or "not_reviewed"


def on_recorded(state: dict[str, Any], entry: dict[str, Any], observed: dict[str, Any], at: str) -> None:
    """Events and acceptance → evidence for the helper subjects of the record just stored (same commit)."""
    index = len(state["reviews"]) - 1
    reasons = engine._judge_review(state, entry, _current(state, observed))
    known = {h["id"]: h for h in helpers(state)}
    for s in entry["subjects"]:
        if s["type"] != "helper" or "phase" not in s or s["id"] not in known:
            continue  # only subjects validated by `subject` (002-F records) carry a phase
        helper = known[s["id"]]
        basis = s["basis"] or "no basis given"
        if s["phase"] == "pre_execution":
            event(helper, "reviewed", s["result"] or "incomplete", at, detail=f"review record {index}")
            if s["result"] == "rejected":
                evidence.failed(
                    state,
                    helper,
                    f"rejected by the Reviewer before execution: {basis}",
                    outcome="not_executed",
                    review=index,
                )
            continue
        run = next(r for r in helper["runs"] if r["n"] == s["run"])
        manifest = run["manifest"]["digest"]
        accept = run["acceptance"]
        accept["review"] = index
        if reasons or s["result"] is None:
            accept["state"] = "stale"
            why = "; ".join(reasons) or "the record is incomplete"
            item = evidence.failed(
                state,
                helper,
                f"post-run acceptance not valid when recorded: {why}",
                run=run["n"],
                outcome="clean",
                acceptance="stale",
                review=index,
                manifest=manifest,
            )
        elif s["result"] == "rejected":
            accept["state"] = "rejected"
            item = evidence.failed(
                state,
                helper,
                f"clean result rejected by the Reviewer: {basis}",
                run=run["n"],
                outcome="clean",
                acceptance="rejected",
                review=index,
                manifest=manifest,
            )
        elif run["uncovered"] or run["object_files"]["too_large"]:
            accept["state"] = "accepted_partial"
            shown = run["uncovered"][:UNCOVERED_IN_EVIDENCE]
            more = (
                ""
                if len(run["uncovered"]) <= len(shown)
                else f" and {len(run['uncovered']) - len(shown)} more"
            )
            too_large = "; the check object is too large to cover" if run["object_files"]["too_large"] else ""
            item = evidence.failed(
                state,
                helper,
                f"clean result accepted but did not cover {run['uncovered_count']} file(s) of check "
                f"{helper['check']}: {', '.join(shown)}{more}{too_large}; the helper never counts for them",
                run=run["n"],
                outcome="clean",
                acceptance="accepted_partial",
                review=index,
                manifest=manifest,
            )
        else:
            accept["state"] = "accepted_full"
            item = evidence.append(
                state,
                helper,
                "ok",
                f"clean result accepted by the Reviewer; {len(run['target']['scanned_paths'])} of "
                f"{run['object_files']['count']} check-object files scanned; manifest {manifest}",
                run["target"]["scanned_paths"],
                run=run["n"],
                outcome="clean",
                acceptance="accepted_full",
                review=index,
                manifest=manifest,
            )
        accept["evidence"] = item["id"]
        event(
            helper, "post_run_review", accept["state"], at, manifest=manifest, detail=f"review record {index}"
        )
