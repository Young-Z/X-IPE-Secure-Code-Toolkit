"""`secure-code guard cancel` (FEATURE-002-C): durable cancellation with one final, never-Pass result.

The marker is created at once without any lock (cancellation is durable); every later state commit is
refused by the commit barrier, so after the barrier is passed once the run state is frozen. A running
tool is stopped by the toolkit process that owns it, which acknowledges whether it saw the tool's
processes exit. The final result is built from the frozen state and published exclusively.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..atomic import LockHeld, ProcessLock
from ..results import Result
from . import budget, engine, report, runs, targets
from .helpers import report as helper_report
from .model import MAX_TEXT, Checker, GuardError
from .service import _call, _policy_now, _repair_report, _summary, consumed, control_of, now, reconcile_status

CANCEL_WAIT = 3600.0
POLL = 0.2
AGENT_NOTE = "stop requested, not confirmed by the toolkit"
REMOTE_NOTE = "remote requests already sent may continue or be billed; the toolkit cannot stop them"


def _barrier_free(root: Path, vid: str) -> bool:
    """Wait for a commit already in progress (linearization point); False while it is still held."""
    try:
        with ProcessLock(runs.commit_lock(root, vid), timeout=runs.BARRIER_TIMEOUT):
            return True
    except LockHeld:
        return False


def _alive(pid: object) -> bool:
    """Whether the recorded tool owner still exists (unknown pids count as alive: no false claim)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or os.name != "posix":
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _termination(root: Path, vid: str, wait: float) -> dict[str, Any]:
    """Outcome reported by the toolkit process that owns a running tool (no claim without its ack)."""
    active = runs.read_run_json(root, vid, "tool-active.json")
    end = time.monotonic() + wait
    while True:
        ack = runs.read_run_json(root, vid, "cancel-ack.json")
        if ack is not None:
            return {
                "tool": "confirmed" if ack.get("confirmed") is True else "not_confirmed",
                "pid": ack.get("pid"),
                "detail": ack.get("detail"),
            }
        current = runs.read_run_json(root, vid, "tool-active.json")
        if current is None:
            if active is None:
                return {"tool": "none"}
            return {"tool": "finished", "pid": active.get("pid"), "detail": "tool run ended before stopping"}
        active = current
        if not _alive(current.get("pid")):
            return {
                "tool": "not_confirmed",
                "pid": current.get("pid"),
                "detail": "the owning toolkit process exited without acknowledging the cancellation",
            }
        if time.monotonic() >= end:
            return {
                "tool": "not_confirmed",
                "pid": current.get("pid"),
                "detail": "the owning toolkit process did not acknowledge the cancellation",
            }
        time.sleep(POLL)


def finalize_frozen(root: Path, vid: str, command: str, termination: dict[str, Any]) -> dict[str, Any]:
    """Build and publish the cancelled result from the frozen state (exactly one final result)."""
    existing = runs.read_result(root, vid)
    if existing is not None:
        if existing.get("cancellation"):
            return existing
        raise GuardError("RUN_FINISHED", f"Verification {vid} was concluded before the cancellation")
    marker = runs.cancel_marker(root, vid) or {}
    state = runs.read_state(root, vid)
    budget.ensure(state)
    requested_at = marker.get("requested_at") or now()[0]
    used = marker.get("consumed_at_request")
    used = float(used) if isinstance(used, (int, float)) else consumed(root, state)
    budget.close_pause(state, requested_at)
    unfinished = budget.cancel_unfinished(state)
    cancellation = {
        "requested_at": requested_at,
        "reason": marker.get("reason"),
        "consumed_at_request": round(used, 1),
        "tool_termination": termination,
        "agent_attempts": [a["id"] for a in unfinished if a["kind"] not in ("tool", "tool_update")],
        "agent_note": AGENT_NOTE,
        "remote_note": REMOTE_NOTE,
    }
    try:
        policy_now = _policy_now(root, state, command)
    except GuardError:
        policy_now = {}
        cancellation["policy_note"] = "Policy state could not be read (store busy); treated as not checked"
    observed = {t["path"]: targets.observe(root, t["path"]) for t in state["artifact"]["targets"]}
    result = engine.conclude(state, observed, policy_now, requested_at, control_of(state, used, cancellation))
    helper_report.attach(state, result)  # FEATURE-002-F: key `helpers` only for runs with helpers
    report.stamp(result)  # CR-TASK-086: direct cancel and a pending cancellation finalized by conclude
    try:
        runs.create_result_exclusive(root, result)
    except FileExistsError:
        winner = runs.read_result(root, vid)
        if not (winner or {}).get("cancellation"):
            raise GuardError(
                "RUN_FINISHED", f"Verification {vid} was concluded before the cancellation"
            ) from None
        result = winner
    _repair_report(root, vid, result)
    reconcile_status(root, vid, result)
    return result


def finalize_locked(root: Path, vid: str, command: str) -> dict[str, Any]:
    """Complete an interrupted or pending cancellation (called by conclude under the Guard lock)."""
    if not _barrier_free(root, vid):
        raise GuardError(
            "FINALIZATION_PENDING",
            f"Verification {vid} is cancelled; a commit in progress has not finished yet",
            "Retry later; the cancellation itself is already recorded",
        )
    return finalize_frozen(root, vid, command, _termination(root, vid, 0.0))


def cancel(project: str | None, run_id: str, reason: str | None = None) -> Result:
    """Cancel one verification: durable at once, owned tool stopped, final partial result (never Pass)."""
    command = "guard cancel"

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        text = Checker("REQUEST_INVALID", "Give a reason (at most 8 KiB)").text(
            reason, "--reason", required=False, limit=MAX_TEXT
        )
        result = runs.read_result(root, vid)
        if result is None:
            state = runs.read_state(root, vid)
            if state["status"] != "open" and runs.cancel_marker(root, vid) is None:
                raise GuardError("RUN_FINISHED", f"Verification {vid} is already concluded", runs.NEW_RUN)
            budget.ensure(state)
            requested_at, at = now()
            used = max(runs.stored_clock(root, vid), budget.raw_consumed(state, at))
            runs.create_marker(
                root,
                vid,
                {"requested_at": requested_at, "reason": text, "consumed_at_request": round(used, 1)},
            )
            if not _barrier_free(root, vid):
                return Result(
                    command,
                    True,
                    {"verification_id": vid, "finalization": "pending"},
                    [],
                    [
                        "The cancellation is recorded; a commit in progress has not finished. "
                        f"Run secure-code guard cancel --run {vid} again later to finalize"
                    ],
                )
            result = finalize_frozen(root, vid, command, _termination(root, vid, CANCEL_WAIT))
        elif not result.get("cancellation"):
            won = runs.cancel_marker(root, vid) is not None
            raise GuardError(
                "RUN_FINISHED",
                f"Verification {vid} was concluded before the cancellation took effect"
                if won
                else f"Verification {vid} is already concluded and cannot be cancelled",
                "Start a new verification with secure-code guard open",
            )
        out = _summary(command, result)
        out.data["finalization"] = "done"
        out.next_steps = ["The cancelled report lists what was verified and what was not; rerun when ready"]
        return out

    return _call(command, project, body)
