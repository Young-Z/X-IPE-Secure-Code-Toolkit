"""`guard helper grant` (FR-002F-7, AC-002F-04o/04p/05g; design §7) and `guard helper show` (03f).

The grant is typed by the user at an interactive terminal, names the verification and is bound to the
reviewed helpers' current script, declaration and sample digests. It is recorded cooperative consent that
the toolkit cannot prove a person gave — never a security boundary — and creates no egress purpose.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from ...auth.interaction import Interaction, TerminalInteraction
from ...results import Result
from .. import budget, runs, service, targets
from ..model import GuardError
from . import review
from .model import CONSENT, digests, event, find, granted, helpers
from .report import display

NOT_REVIEWED_STEP = "Register a reviewer attempt covering the helper and record the Reviewer's result"


def _observed(root: Path, state: dict[str, Any]) -> dict[str, Any]:
    return {t["path"]: targets.observe(root, t["path"]) for t in state["artifact"]["targets"]}


def _selectable(root: Path, state: dict[str, Any], wanted: list[str] | None) -> list[dict[str, Any]]:
    observed = _observed(root, state)
    chosen = [find(state, h) for h in wanted] if wanted else helpers(state)
    return [
        h
        for h in chosen
        if review.pre_execution(state, h, observed) == "accepted" and granted(state, h) is None
    ]


def _listing(vid: str, chosen: list[dict[str, Any]]) -> str:
    lines = [f"Grant execution of temporary helper scripts in verification {vid}:"]
    for h in chosen:
        d = digests(h)
        lines += [
            f"- {h['id']} for check {h['check']}: {h['goal']}",
            f"  read scope: {', '.join(h['read_scope'])}",
            f"  script {d['script_sha256']}; declaration {d['declaration_sha256']};"
            f" samples {d['samples_sha256']}",
        ]
    lines += [CONSENT, "Type the verification id to confirm: "]
    return "\n".join(lines)


def grant(
    project: str | None, run_id: str, wanted: list[str] | None, interaction: Interaction | None = None
) -> Result:
    """The user grants execution of reviewed, accepted helpers at an interactive terminal."""
    command = "guard helper grant"
    interaction = interaction or TerminalInteraction()
    if not interaction.is_interactive():
        return Result.refused(
            command,
            "INTERACTIVE_REQUIRED",
            "Only the user at an interactive terminal can grant helper execution; agents cannot",
            "Ask the user to run this command in their own terminal",
        )

    def body(root: Path) -> Result:
        vid = runs.check_id(run_id)
        state = runs.read_state(root, vid)
        chosen = _selectable(root, state, wanted)
        if not chosen:
            raise GuardError(
                "HELPER_NOT_REVIEWED",
                "no reviewed, accepted and not yet granted helper to grant",
                NOT_REVIEWED_STEP,
            )
        expected = {h["id"]: h["helper_digest"] for h in chosen}
        typed = interaction.prompt_text(_listing(vid, chosen))
        if typed is None or typed.strip() != vid:
            raise GuardError(
                "CONFIRMATION_MISMATCH",
                "The typed confirmation does not match the verification id",
                "Run the command again and type the exact verification id",
            )
        out: dict[str, Any] = {}

        def change(state: dict[str, Any], used: float) -> dict[str, Any]:
            rev = state["revision"]
            now = _selectable(root, state, wanted)
            if {h["id"]: h["helper_digest"] for h in now} != expected:
                raise GuardError(
                    "STATE_CHANGED", "The helpers changed while confirming", "Run the grant again"
                )
            new = copy.deepcopy(state)
            record = {
                "id": f"hg-{len(new.get('helper_grants') or []) + 1}",
                "at": service.now()[0],
                "verification": vid,
                "interactive": True,
                "typed": vid,
                "helpers": [{"id": h["id"], "check": h["check"], **digests(h)} for h in now],
                "wording": CONSENT,
            }
            new.setdefault("helper_grants", []).append(record)
            for h in now:
                event(find(new, h["id"]), "granted", "granted", record["at"], grant=record["id"])
            runs.commit_state(root, new, expected_revision=rev)
            out.update(
                grant=record["id"],
                helpers=[h["id"] for h in now],
                digests=record["helpers"],
                wording=CONSENT,
                budget=budget.status(new, used),
            )
            return new

        service._mutate(root, run_id, change, "none")
        return Result(
            command,
            True,
            {"verification_id": vid, **out},
            [],
            ["The agent may now run the helper: secure-code guard helper run"],
        )

    return service._call(command, project, body)


def show(project: str | None, run_id: str, wanted: str | None = None) -> Result:
    """Read-only helper state: review, grant and execution shown as three separate fields (03f)."""
    command = "guard helper show"

    def body(root: Path) -> Result:
        from .execute import NotReady, ready
        from .submit import expected_extra

        vid = runs.check_id(run_id)
        state = runs.read_state(root, vid)
        observed = _observed(root, state)
        chosen = [find(state, wanted)] if wanted else helpers(state)
        try:
            ready(root)
            readiness = "ready: runtime, registered image and conformance record match"
        except NotReady as exc:
            readiness = f"not ready ({exc.code}): {exc.reason}"
        entries = []
        for h in chosen:
            pre = review.pre_execution(state, h, observed)
            grant_record = granted(state, h)
            shown, gap = display(h, pre, grant_record)
            entries.append(
                {
                    "id": h["id"],
                    "check": h["check"],
                    "method": h["method"],
                    "state": shown,
                    "review": {
                        "not_reviewed": "not reviewed",
                        "accepted": "accepted (not permission to execute)",
                        "rejected": "rejected",
                        "disagreement": "reviews disagree",
                    }[pre],
                    "grant": f"granted {grant_record['id']} (recorded cooperative consent)"
                    if grant_record
                    else "not granted",
                    "execution": shown
                    if shown.startswith(("executed", "not executed", "blocked"))
                    else "not executed",
                    "gap": gap,
                    "digests": digests(h),
                    "events": h["events"],
                    "runs": h["runs"],
                    "expected_extra_attempts": expected_extra(state, h),
                }
            )
        used = service.consumed(root, state) if state["status"] == "open" else None
        data = {
            "verification_id": vid,
            "helpers": entries,
            "runtime": readiness,
            "budget": budget.status(state, used) if used is not None else None,
        }
        return Result(command, True, data, [], [])

    return service._call(command, project, body)
