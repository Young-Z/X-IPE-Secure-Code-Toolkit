"""`secure-code guard attempt | pause | resume | extend` (FEATURE-002-C budget control).

Agents register attempts and pause while waiting for the user; only the user at an interactive
terminal extends the budget (same gate as risk acceptance).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..auth.interaction import Interaction, TerminalInteraction
from ..results import Result
from . import budget, runs
from .model import MAX_TEXT, Checker, GuardError, load_request
from .service import _call, _mutate, _needs_plan, now

SCHEMA_ATTEMPT = "ai-secure-code-toolkit/guard-attempt/v1"


def _reason(value: str | None, where: str) -> str:
    return Checker("REQUEST_INVALID", "Give a reason (at most 8 KiB)").text(value, where, limit=MAX_TEXT)


def attempt(project: str | None, run_id: str, request: str) -> Result:
    """Register one unit of agent work before it starts; returns its id and deadline."""
    command = "guard attempt"

    def body(root: Path) -> Result:
        doc = load_request(request, SCHEMA_ATTEMPT, "ATTEMPT_INVALID", budget.ATTEMPT_STEP)
        Checker("ATTEMPT_INVALID", budget.ATTEMPT_STEP).obj(
            doc, "attempt", {"schema", "kind", "covers"}, frozenset({"kind", "covers"})
        )
        out: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            _needs_plan(state)
            rev = state["revision"]
            a = budget.register(state, doc["kind"], doc["covers"], used, now()[0])
            runs.commit_state(root, state, expected_revision=rev)
            out.update(
                attempt=a["id"],
                kind=a["kind"],
                extra=a["extra"],
                deadline_consumed=a["deadline_consumed"],
                remaining_seconds=budget.status(state, used)["remaining_seconds"],
                budget=budget.status(state, used),
            )
            return state

        state = _mutate(root, run_id, change)
        return Result(
            command,
            True,
            {"verification_id": state["verification_id"], **out},
            [],
            [f'Do the work, then cite it: "attempt": "{out["attempt"]}" in the record or Reviewer record'],
        )

    return _call(command, project, body)


def pause(project: str | None, run_id: str, reason: str) -> Result:
    """Pause while waiting for the user: the clock stops and nothing can start or be recorded."""
    command = "guard pause"

    def body(root: Path) -> Result:
        text = _reason(reason, "--reason")
        out: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            rev = state["revision"]
            budget.pause(state, text, now()[0])
            runs.commit_state(root, state, expected_revision=rev)
            out["budget"] = budget.status(state, used)
            return state

        state = _mutate(root, run_id, change, "none")
        return Result(
            command,
            True,
            {"verification_id": state["verification_id"], **out},
            [],
            [f"Resume when the user answered: secure-code guard resume --run {state['verification_id']}"],
        )

    return _call(command, project, body)


def resume(project: str | None, run_id: str) -> Result:
    """End the current pause; its duration is excluded from the consumed time."""
    command = "guard resume"

    def body(root: Path) -> Result:
        out: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            rev = state["revision"]
            budget.resume(state, now()[0])
            runs.commit_state(root, state, expected_revision=rev)
            out["budget"] = budget.status(state, used)
            return state

        state = _mutate(root, run_id, change, "none")
        return Result(command, True, {"verification_id": state["verification_id"], **out}, [], [])

    return _call(command, project, body)


def extend(
    project: str | None,
    run_id: str,
    minutes: int,
    attempts: int,
    reason: str,
    interaction: Interaction | None = None,
) -> Result:
    """The user adds time and/or extra attempts at an interactive terminal, typing the verification id."""
    command = "guard extend"
    interaction = interaction or TerminalInteraction()
    if not interaction.is_interactive():
        return Result.refused(
            command,
            "INTERACTIVE_REQUIRED",
            "Only the user at an interactive terminal can extend a verification budget; agents cannot",
            "Ask the user to run this command in their own terminal",
        )

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        text = _reason(reason, "--reason")
        typed = interaction.prompt_text(
            f"Add {minutes} minutes and {attempts} extra attempts to {vid}? "
            "Type the verification id to confirm: "
        )
        if typed is None or typed.strip() != vid:
            raise GuardError(
                "CONFIRMATION_MISMATCH",
                "The typed confirmation does not match the verification id",
                "Run the command again and type the exact verification id",
            )
        out: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            rev = state["revision"]
            seconds = minutes * 60 if isinstance(minutes, int) and not isinstance(minutes, bool) else minutes
            out["extension"] = budget.extend(state, seconds, attempts, text, now()[0])
            runs.commit_state(root, state, expected_revision=rev)
            out["budget"] = budget.status(state, used)
            return state

        state = _mutate(root, run_id, change, "none")
        return Result(command, True, {"verification_id": state["verification_id"], **out}, [], [])

    return _call(command, project, body)
