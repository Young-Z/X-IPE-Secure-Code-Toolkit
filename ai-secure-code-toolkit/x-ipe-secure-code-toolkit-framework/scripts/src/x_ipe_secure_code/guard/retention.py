"""`secure-code guard accept-risk | keep | release | cleanup` (FEATURE-002-A; moved from service.py).

Risk acceptance by a User at an interactive terminal and evidence retention of finished verifications.
"""

from __future__ import annotations

import copy
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..atomic import atomic_write_bytes, dumps_json
from ..auth.interaction import Interaction, TerminalInteraction
from ..knowledge import store
from ..results import Result
from . import report, runs
from .model import (
    GUARD_REL,
    MAX_TEXT,
    RETENTION_DAYS,
    RUN_ID,
    Checker,
    GuardError,
    parse_time,
    utc_now,
)
from .service import _call, _locked


# --------------------------------------------------------------------------- risk acceptance
def _acceptable(result: dict[str, Any] | None, vid: str, finding: str) -> dict[str, Any]:
    if result is None:
        raise GuardError(
            "NOT_CONCLUDED",
            f"Verification {vid} is not concluded",
            f"Conclude it first: secure-code guard conclude --run {vid}",
        )
    if result.get("cancellation"):
        raise GuardError(
            "NOT_ACCEPTABLE",
            f"Verification {vid} was cancelled; its result is final",
            "Run a new verification and accept the risk there if it still fails",
        )
    if result["verdict"] != "fail":
        raise GuardError(
            "NOT_ACCEPTABLE",
            f"Verification {vid} did not fail; there is no failing risk to accept",
            "Risk acceptance applies to a concluded Fail verification only",
        )
    if not any(f["id"] == finding for f in result["findings"]):
        raise GuardError(
            "FINDING_NOT_FOUND", f"No finding {finding!r} in {vid}", "Pass a finding id from the report"
        )
    return result


def accept_risk(
    project: str | None, run_id: str, finding: str, reason: str, interaction: Interaction | None = None
) -> Result:
    """Record a User's risk acceptance for one finding; findings, severities and verdict stay unchanged.

    Only a person at an interactive terminal can record it, typing the finding id to confirm.
    """
    command = "guard accept-risk"
    interaction = interaction or TerminalInteraction()
    if not interaction.is_interactive():
        return Result.refused(
            command,
            "INTERACTIVE_REQUIRED",
            "Risk acceptance needs a person at an interactive terminal; agents, Reviewers and Maintainer "
            "authorization cannot record it",
            "Ask the user to run this command in their own terminal",
        )

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        text = Checker("REQUEST_INVALID", "Give a reason (at most 8 KiB)").text(
            reason, "--reason", limit=MAX_TEXT
        )
        _acceptable(runs.read_result(root, vid), vid, finding)
        typed = interaction.prompt_text(
            f"Accept the risk of finding {finding} in {vid}? Type the finding id to confirm: "
        )
        if typed is None or typed.strip() != finding:
            raise GuardError(
                "CONFIRMATION_MISMATCH",
                "The typed confirmation does not match the finding id",
                "Run the command again and type the exact finding id",
            )
        with _locked(root):
            result = copy.deepcopy(_acceptable(runs.read_result(root, vid), vid, finding))
            entry = {"finding": finding, "reason": text, "role": "user", "recorded_at": utc_now()}
            result["risk_acceptances"] = [*result["risk_acceptances"], entry]
            runs.remove_report(root, vid)
            runs.write_result(root, result)
            runs.write_report(root, vid, report.render(result))
        return Result(
            command,
            True,
            {
                "verification_id": vid,
                "risk_acceptance": entry,
                "verdict": result["verdict"],
                "verdict_unchanged": True,
            },
            [],
            ["The acceptance applies to this verification only; findings and the verdict are unchanged"],
        )

    return _call(command, project, body)


# --------------------------------------------------------------------------- evidence retention
def keep(project: str | None, run_id: str, reason: str) -> Result:
    """Set a keep marker so cleanup does not remove this verification's evidence."""
    command = "guard keep"

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        text = Checker("REQUEST_INVALID", "Give a reason (at most 8 KiB)").text(reason, "--reason")
        with _locked(root):
            if not runs.run_dir(root, vid).is_dir():
                raise GuardError(
                    "RUN_NOT_FOUND",
                    f"No evidence folder for {vid} (unknown or already removed)",
                    runs.NEW_RUN,
                )
            marker = {"reason": text, "set_at": utc_now()}
            atomic_write_bytes(runs.keep_path(root, vid), dumps_json(marker), private=True)
        return Result(
            command,
            True,
            {"verification_id": vid, "keep": marker},
            [],
            [f"Release it when the pending process ends: secure-code guard release --run {vid}"],
        )

    return _call(command, project, body)


def release(project: str | None, run_id: str) -> Result:
    """Remove the keep marker; the evidence becomes removable by cleanup once expired."""
    command = "guard release"

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        with _locked(root):
            if not runs.run_dir(root, vid).is_dir():
                raise GuardError("RUN_NOT_FOUND", f"No evidence folder for {vid}", runs.NEW_RUN)
            path = runs.keep_path(root, vid)
            released = path.is_file()
            path.unlink(missing_ok=True)
        return Result(command, True, {"verification_id": vid, "released": released})

    return _call(command, project, body)


def _ended_at(root: Path, vid: str) -> str | None:
    result = runs.read_result(root, vid)
    if result is not None:
        return result["ended_at"]
    state = runs.read_state(root, vid)
    return state["ended_at"] if state["status"] == "finished" else None


def _keep_reason(root: Path, vid: str) -> str | None:
    path = runs.keep_path(root, vid)
    if not path.exists():
        return None
    try:
        return str(json.loads(path.read_text(encoding="utf-8"))["reason"])
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return "unreadable keep marker"


def cleanup(project: str | None, now: datetime | None = None) -> Result:
    """Remove evidence of finished verifications ended more than 30 days ago without a keep marker.

    Never touches running verifications or reports.
    """
    command = "guard cleanup"

    def body(root: Path) -> Result:
        moment = now or datetime.now(UTC)
        removed: list[dict[str, str]] = []
        kept: list[dict[str, str]] = []
        skipped: list[dict[str, str]] = []
        with _locked(root):
            store.ensure_safe(root, GUARD_REL, expect_dir=True)
            base = root / GUARD_REL
            for entry in sorted(base.iterdir(), key=lambda p: p.name) if base.is_dir() else []:
                name = entry.name
                if entry.is_symlink() or not entry.is_dir() or not RUN_ID.fullmatch(name):
                    skipped.append({"entry": name, "reason": "not a verification folder"})
                    continue
                try:
                    ended = _ended_at(root, name)
                except GuardError:
                    kept.append({"verification_id": name, "reason": "run state unreadable; not removed"})
                    continue
                if ended is None:
                    kept.append({"verification_id": name, "reason": "running (not concluded)"})
                    continue
                marker = _keep_reason(root, name)
                if marker is not None:
                    kept.append({"verification_id": name, "reason": f"keep marker: {marker}"})
                    continue
                expires = parse_time(ended) + timedelta(days=RETENTION_DAYS)
                if moment > expires:
                    shutil.rmtree(entry)
                    removed.append({"verification_id": name, "ended_at": ended})
                else:
                    kept.append(
                        {
                            "verification_id": name,
                            "reason": f"retained until {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                        }
                    )
        return Result(
            command,
            True,
            {
                "removed": removed,
                "kept": kept,
                "skipped": skipped,
                "reports": "reports are never removed by cleanup",
            },
        )

    return _call(command, project, body)
