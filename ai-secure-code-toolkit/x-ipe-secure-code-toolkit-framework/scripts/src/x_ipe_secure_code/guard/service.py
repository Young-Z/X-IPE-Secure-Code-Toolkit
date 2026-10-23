"""`secure-code guard` commands (FEATURE-002-A): open, plan, record, review, conclude, show,
accept-risk, keep, release and cleanup.

The agent judges; these commands record, validate and compute the verdict deterministically.
Guard writes only its private run folder, its lock file and its reports.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from ..atomic import LockHeld, ProcessLock, dumps_json
from ..knowledge import store
from ..policy import resolve
from ..policy.service import adoption_now, load_adopted
from ..projects import knowledge_root
from ..results import Result
from . import budget, engine, records, report, runs, targets
from . import model as guard_model
from .model import (
    LOCK_REL,
    SCHEMA_OPEN,
    SCHEMA_PLAN,
    SCHEMA_RECORD,
    SCHEMA_REVIEW,
    SCHEMA_RUN,
    GuardError,
    load_request,
    parse_time,
    utc_now,
)

LOCK_TIMEOUT = 10.0
RETRY = "Retry when the other Guard operation finished"
FRAMEWORK_STEP = (
    "Select and confirm Policies with the Framework skill (secure-code scope save), then pass its scope_id"
)
VERDICT_STEPS = {
    "fail": "Guard does not fix: hand the findings to the current task executor, then run a new verification",
    "cannot_confirm_pass": "Resolve the listed reasons (evidence, review, scope) and run a new verification",
    "pass": "Share the report; a later change to the targets needs a new verification",
}


@contextmanager
def _locked(root: Path):
    store.ensure_safe(root, LOCK_REL, expect_dir=False)
    with ProcessLock(root / LOCK_REL, timeout=LOCK_TIMEOUT, create=True):
        yield


def _call(command: str, project: str | None, body: Callable[[Path], Result]) -> Result:
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    try:
        return body(root)
    except GuardError as exc:
        return Result.refused(command, exc.code, exc.message, exc.next_step, exc.data)
    except LockHeld as exc:
        return Result.refused(command, "LOCKED", str(exc), RETRY)
    except store.StoreError as exc:
        return Result.refused(
            command, exc.code, exc.message, "Replace the symbolic link with a real folder or file"
        )
    except (TypeError, ValueError, KeyError) as exc:
        return Result.refused(
            command,
            "REQUEST_INVALID",
            f"Request content has an unexpected shape: {exc}",
            "Fix the request file (see the Guard skill references/guard-records.md)",
        )
    except OSError as exc:
        return Result.refused(
            command,
            "IO_ERROR",
            f"Guard files could not be read or written: {exc}",
            "Check the permissions of the project's .x-ipe/private and x-ipe-docs folders",
        )


def _refusal(loaded: Result) -> GuardError:
    problem = loaded.problems[0]
    return GuardError(
        problem.code, problem.message, loaded.next_steps[0] if loaded.next_steps else None, loaded.data
    )


def now() -> tuple[str, datetime]:
    """Current UTC time (patchable through model.utc_now)."""
    text = guard_model.utc_now()
    return text, parse_time(text)


def consumed(root: Path, state: dict[str, Any]) -> float:
    """Never-decreasing consumed time of an open verification (persisted high-water mark)."""
    budget.ensure(state)
    return runs.bump_clock(root, state["verification_id"], budget.raw_consumed(state, now()[1]))


def control_of(state: dict[str, Any], used: float, cancellation: dict[str, Any] | None = None) -> dict:
    return {
        "budget": budget.summary(state, used),
        "attempts": state["attempts"],
        "egress": state["egress"],
        "cancellation": cancellation,
    }


# --------------------------------------------------------------------------- open
def open_verification(project: str | None, request: str) -> Result:
    """Open a verification of explicit targets against a complete adopted scope.

    Args:
        project: Explicit project root.
        request: Open request file (`guard-open/v1`).

    Returns:
        Result with the verification_id, targets and adopted rules; refusals write nothing.
    """
    command = "guard open"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_OPEN, "REQUEST_INVALID", targets.REQUEST_STEP)
        parsed = targets.parse_open(root, doc)
        initial_budget = budget.initial(doc.get("budget"))
        with _locked(root):
            loaded = load_adopted(root, parsed["scope_id"], command)
            if isinstance(loaded, Result):
                raise _refusal(loaded)
            groups = {
                s: [e["rule"] for e in loaded["entries"] if e["adoption"] == s]
                for s in ("adopted", "needs_reconfirmation", "missing")
            }
            if loaded["status"] == resolve.MAINTENANCE_NEEDED:
                raise GuardError(
                    "MAINTENANCE_NEEDED",
                    "No Policy of this adopted scope is usable any more",
                    FRAMEWORK_STEP,
                    groups,
                )
            if loaded["status"] != resolve.COMPLETE:
                raise GuardError(
                    "SCOPE_PARTIAL",
                    "Some adopted Policies changed or are missing; "
                    "Guard verifies only a complete adopted scope",
                    "Confirm a new scope with the Framework skill (secure-code scope save), then open again",
                    groups,
                )
            adopted = [
                {"rule": e["rule"], "state_digest": e["confirmed_state_digest"]}
                for e in loaded["entries"]
                if e["adoption"] == "adopted"
            ]
            opened_at = utc_now()
            state = {
                "schema": SCHEMA_RUN,
                "verification_id": None,
                "status": "open",
                "opened_at": opened_at,
                "ended_at": None,
                "request": parsed["request"],
                "baseline": parsed["baseline"],
                "scope": {"scope_id": loaded["scope_id"], "mode": loaded["mode"], "adopted": adopted},
                "artifact": parsed["artifact"],
                "plan": None,
                "evidence": [],
                "findings": [],
                "ledger": {},
                "conflicts": [],
                "reviews": [],
                "budget": initial_budget,
                "attempts": [],
                "egress": {"grants": [], "declarations": []},
                "revision": 0,
            }
            dumps_json(state)  # refuse unserializable input before anything is written
            vid = runs.allocate(root, opened_at)
            state["verification_id"] = vid
            try:
                runs.write_state(root, state)
            except BaseException:
                shutil.rmtree(runs.run_dir(root, vid), ignore_errors=True)
                raise
        art = parsed["artifact"]
        data = {
            "verification_id": vid,
            "opened_at": opened_at,
            "scope_id": loaded["scope_id"],
            "adopted_rules": [a["rule"] for a in adopted],
            "whole_project": art["whole_project"],
            "targets": [
                {
                    "path": t["path"],
                    "change": t["change"],
                    "old_path": t["old_path"],
                    "digest": t["digest"],
                    "incomplete": t["incomplete"],
                }
                for t in art["targets"]
            ],
            "context": [c["path"] for c in art["context"]],
            "suggested": [s["path"] for s in art["suggested"]],
            "copilot_reports": [c["path"] for c in art["copilot_reports"]],
            "budget": budget.status(state, 0.0),
        }
        return Result(
            command,
            True,
            data,
            [],
            [
                f"Record the check plan: secure-code guard plan --run {vid} "
                "--request .x-ipe/private/secure-code/tmp/plan.json"
            ],
        )

    return _call(command, project, body)


# --------------------------------------------------------------------------- plan / record / review
def _mutate(
    root: Path, run_id: str, change: Callable[[dict[str, Any], float], dict[str, Any]], gate: str = "work"
) -> dict[str, Any]:
    """Run `change(state, consumed)` under the Guard lock after the cancel/finish/pause/budget gates.

    gate "work": new work (unpaused, time left); "cited"/"ledger": unpaused only; "none": no budget gate.
    """
    vid = runs.check_id(run_id)
    with _locked(root):
        state = runs.read_state(root, vid)
        runs.refuse_closed(root, vid)
        if state["status"] != "open":
            raise GuardError(
                "RUN_FINISHED",
                f"Verification {vid} is already concluded",
                "Start a new verification with secure-code guard open",
            )
        used = consumed(root, state)
        try:
            if gate == "work":
                budget.require_running(state, used)
            elif gate in ("cited", "ledger"):
                budget.require_not_paused(state)
            return change(state, used)
        except GuardError as exc:
            exc.data.setdefault("budget", budget.status(state, used))
            raise


def _needs_plan(state: dict[str, Any]) -> None:
    if state["plan"] is None:
        raise GuardError(
            "PLAN_REQUIRED",
            "No check plan was recorded yet",
            f"Record the plan first: secure-code guard plan --run {state['verification_id']}",
        )


def record_plan(project: str | None, run_id: str, request: str) -> Result:
    """Record the check plan once (adopted rules only; every adopted rule covered)."""
    command = "guard plan"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_PLAN, "PLAN_INVALID", records.PLAN_STEP)
        info: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            rev = state["revision"]
            if state["plan"] is not None:
                raise GuardError(
                    "PLAN_EXISTS",
                    "A check plan is already recorded for this verification",
                    "Record evidence and ledger states, or open a new verification",
                )
            state["plan"] = records.validate_plan(state, doc)
            budget.set_planned(state)
            runs.commit_state(root, state, expected_revision=rev)
            info["budget"] = budget.status(state, used)
            return state

        state = _mutate(root, run_id, change)
        plan = state["plan"]
        return Result(
            command,
            True,
            {
                "verification_id": state["verification_id"],
                "checks": [c["id"] for c in plan["checks"]],
                "not_applicable": [n["rule"] for n in plan["not_applicable"]],
                "exclusions": [e["rule"] or e["check"] for e in plan["exclusions"]],
                "budget": info["budget"],
            },
            [],
            [
                "Review the targets, then record evidence, findings and ledger states "
                "with secure-code guard record"
            ],
        )

    return _call(command, project, body)


def _record_gate(doc: dict[str, Any]) -> str:
    """Classify a record request by its non-empty operations (FEATURE-002-C AC-002C-01c, 03a)."""
    ops = {k for k in ("evidence", "findings", "ledger", "conflicts", "method_changes") if doc.get(k)}
    if doc.get("attempt") is not None:
        if ops & {"conflicts", "method_changes"}:
            raise GuardError(
                "ATTEMPT_INVALID",
                "A record that cites an attempt may only carry evidence, findings and ledger states",
                "Record conflicts and method changes in a separate record without an attempt",
            )
        return "cited"
    if doc.get("usage") is not None:
        raise GuardError("ATTEMPT_INVALID", "usage belongs to a cited attempt", budget.ATTEMPT_STEP)
    if ops & {"evidence", "findings"}:
        return "attempt_required"
    return "ledger" if ops <= {"ledger"} else "work"


def record(project: str | None, run_id: str, request: str) -> Result:
    """Record evidence (masked), findings, ledger states and conflicts; all or nothing."""
    command = "guard record"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_RECORD, "RECORD_INVALID", records.RECORD_STEP)
        added: dict[str, Any] = {}
        gate = _record_gate(doc)

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            _needs_plan(state)
            rev = state["revision"]
            new, writes = records.apply_record(root, state, doc)
            if gate == "attempt_required":
                raise GuardError(
                    "ATTEMPT_REQUIRED",
                    "Evidence and findings must cite the attempt registered before the work started",
                    budget.ATTEMPT_STEP,
                )
            old_e, old_f = {e["id"] for e in state["evidence"]}, {f["id"] for f in state["findings"]}
            if gate == "cited":
                new_e = [e for e in new["evidence"] if e["id"] not in old_e]
                new_f = [f for f in new["findings"] if f["id"] not in old_f]
                used_items = {
                    "pairs": {(c, e["method"]) for e in new_e for c in e.get("checks") or []},
                    "checks": {f["check"] for f in new_f if f.get("check")},
                }
                budget.cite(
                    new, doc["attempt"], budget.AGENT_KINDS - {"reviewer"}, used_items, used, now()[0],
                    doc.get("usage"),
                )
            for eid, text in writes:
                runs.write_evidence(root, state["verification_id"], eid, text)
            try:
                runs.commit_state(root, new, expected_revision=rev)
            except GuardError:
                # never keep evidence of a commit that lost (e.g. to a cancellation)
                runs.remove_evidence_files(
                    root, state["verification_id"], [f"{eid}.txt" for eid, _ in writes]
                )
                raise
            added["budget"] = budget.status(new, used)
            added["evidence"] = [e["id"] for e in new["evidence"] if e["id"] not in old_e]
            added["masked"] = [e["id"] for e in new["evidence"] if e["id"] not in old_e and e["masked"]]
            added["findings"] = [f["id"] for f in new["findings"] if f["id"] not in old_f]
            added["ledger"] = sorted(new["ledger"])
            added["conflicts"] = [c["id"] for c in new["conflicts"]]
            return new

        state = _mutate(root, run_id, change, "work" if gate == "attempt_required" else gate)
        return Result(
            command,
            True,
            {"verification_id": state["verification_id"], **added},
            [],
            [
                "Ask one independent read-only Reviewer to re-check verdict-affecting findings and N/A "
                "decisions, then record its result with secure-code guard review"
            ],
        )

    return _call(command, project, body)


def record_review(project: str | None, run_id: str, request: str) -> Result:
    """Record one Reviewer record (shared envelope); validity is decided at conclusion."""
    command = "guard review"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_REVIEW, "REVIEW_INVALID", records.REVIEW_STEP)
        found: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            _needs_plan(state)
            rev = state["revision"]
            entry, warnings = records.validate_review(state, doc)
            if doc.get("attempt") is None:
                raise GuardError(
                    "ATTEMPT_REQUIRED",
                    "A Reviewer record must cite the reviewer attempt registered before calling the Reviewer",
                    budget.ATTEMPT_STEP,
                )
            subjects = entry["subjects"]
            used_items = {
                "findings": {s["id"] for s in subjects if s["type"] == "finding"},
                "na": {s["id"] for s in subjects if s["type"] == "na_decision"},
                "helpers": {s["id"] for s in subjects if s["type"] == "helper"},
            }
            budget.cite(state, doc["attempt"], {"reviewer"}, used_items, used, now()[0], doc.get("usage"))
            entry["attempt"] = doc["attempt"]
            state["reviews"].append(entry)
            runs.commit_state(root, state, expected_revision=rev)
            found.update(
                index=len(state["reviews"]) - 1, completeness=warnings, budget=budget.status(state, used)
            )
            return state

        state = _mutate(root, run_id, change, "cited")
        steps = ["Conclude when the review is complete: secure-code guard conclude"]
        if found["completeness"]:
            steps.insert(0, "This record is incomplete and will not count as a valid review")
        return Result(
            command,
            True,
            {
                "verification_id": state["verification_id"],
                **found,
                "validity": "decided at conclusion: complete and bound to current digests",
            },
            [],
            steps,
        )

    return _call(command, project, body)


# --------------------------------------------------------------------------- conclude / show
def _policy_now(root: Path, state: dict[str, Any], command: str) -> dict[str, str]:
    now = adoption_now(root, state["scope"]["scope_id"], state["scope"]["adopted"], command)
    if isinstance(now, Result):
        raise _refusal(now)
    return now


def _repair_report(root: Path, vid: str, result: dict[str, Any]) -> None:
    raw = runs.result_bytes(root, vid) or b""
    text = runs.report_text(root, vid)
    if text is None or report.footer_digest(text) != runs.sha256_hex(raw):
        runs.write_report(root, vid, report.render(result))


def _summary(command: str, result: dict[str, Any]) -> Result:
    vid = result["verification_id"]
    data = {
        "verification_id": vid,
        "verdict": result["verdict"],
        "verdict_text": report.VERDICT_TEXT[result["verdict"]],
        "reasons": result["reasons"],
        "other_blockers": result["other_blockers"],
        "ended_at": result["ended_at"],
        "report": runs.result_rel(vid, "md"),
        "result": runs.result_rel(vid, "json"),
        "ledger": [{"check": r["check"], "state": r["state"]} for r in result["ledger"]],
        "findings": [
            {"id": f["id"], "final_severity": f["final_severity"], "review": f["review"]}
            for f in result["findings"]
        ],
        "risk_acceptances": result["risk_acceptances"],
        "budget": result.get("budget"),
        "cancellation": result.get("cancellation"),
    }
    return Result(command, True, data, [], [VERDICT_STEPS[result["verdict"]]])


def conclude(project: str | None, run_id: str) -> Result:
    """Compute the verdict and write the structured result (commit point) and the Markdown report.

    Concluding again returns the stored result and repairs a missing or mismatched report.
    """
    command = "guard conclude"

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        with _locked(root):
            from ..adapters import trivy_journal  # FEATURE-002-D: interrupted provisioning resolved first

            trivy_journal.recover(root)
            result = runs.read_result(root, vid)
            if result is None and runs.cancel_marker(root, vid) is None:
                result = _conclude_open(root, vid, command)
            if result is None:
                from . import cancel  # cancel imports service

                result = cancel.finalize_locked(root, vid, command)
            _repair_report(root, vid, result)
            reconcile_status(root, vid, result)
        return _summary(command, result)

    return _call(command, project, body)


def _conclude_open(root: Path, vid: str, command: str) -> dict[str, Any] | None:
    """Compute outside the barrier, publish inside it; None when a cancellation arrived meanwhile."""
    state = runs.read_state(root, vid)
    used = consumed(root, state)
    ended_at = now()[0]
    budget.close_pause(state, ended_at)
    observed = {t["path"]: targets.observe(root, t["path"]) for t in state["artifact"]["targets"]}
    result = engine.conclude(
        state, observed, _policy_now(root, state, command), ended_at, control_of(state, used)
    )
    report.stamp(result)  # CR-TASK-086: the build writing this result (engine output stays pure)
    with ProcessLock(runs.commit_lock(root, vid), timeout=runs.BARRIER_TIMEOUT):
        if runs.cancel_marker(root, vid) is not None:
            return None
        if runs.read_state(root, vid).get("revision", 0) != state["revision"]:
            raise GuardError("STATE_CHANGED", f"Verification {vid} changed meanwhile", runs.RETRY_STEP)
        try:
            runs.create_result_exclusive(root, result)
        except FileExistsError:
            pass
    return runs.read_result(root, vid)


def reconcile_status(root: Path, vid: str, result: dict[str, Any]) -> None:
    """After the final result exists, the run state says finished or cancelled (post-result write)."""
    if runs.has_state(root, vid):
        state = runs.read_state(root, vid)
        target = "cancelled" if result.get("cancellation") else "finished"
        if state["status"] != target:
            state["status"], state["ended_at"] = target, result["ended_at"]
            runs.write_state(root, state)


def show(project: str | None, run_id: str) -> Result:
    """Read a concluded result: evidence availability, report consistency, current targets (read-only)."""
    command = "guard show"

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        result = runs.read_result(root, vid)
        if result is None:
            if runs.has_state(root, vid):
                state = runs.read_state(root, vid)
                raise GuardError(
                    "NOT_CONCLUDED",
                    f"Verification {vid} is still open",
                    f"Conclude it first: secure-code guard conclude --run {vid}",
                    {
                        "verification_id": vid,
                        "budget": budget.status(state, consumed(root, state)),
                        "cancel_requested": runs.cancel_marker(root, vid) is not None,
                    },
                )
            raise GuardError("RUN_NOT_FOUND", f"No verification {vid}", runs.NEW_RUN)
        out = _summary(command, result)
        available = runs.run_dir(root, vid).is_dir()
        text = runs.report_text(root, vid)
        consistent = text is not None and report.footer_digest(text) == runs.sha256_hex(
            runs.result_bytes(root, vid) or b""
        )
        changed = [
            t["path"]
            for t in result["artifact"]["targets"]
            if targets.observe(root, t["path"])["digest"] != t["digest_at_conclusion"]
        ]
        out.data.update(
            {
                "evidence_available": available,
                "evidence": (
                    f"raw evidence in {result['evidence_retention']['location']}"
                    if available
                    else "raw evidence is no longer available (removed by cleanup); findings and verdict "
                    "remain in this report"
                ),
                "report_consistent": consistent,
                "targets_now": "changed" if changed else "unchanged",
                "changed_targets": changed,
            }
        )
        out.next_steps = []
        if changed:
            out.next_steps.append(
                f"This report does not describe the current version of {', '.join(changed)}; "
                "run a new verification"
            )
        if not consistent:
            out.next_steps.append(f"Repair the Markdown report: secure-code guard conclude --run {vid}")
        return out

    return _call(command, project, body)


# --------------------------------------------------------------------------- moved commands (re-exported)
from .retention import accept_risk, cleanup, keep, release  # noqa: E402,F401
