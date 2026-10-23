"""Shared tool-attempt control for `guard tool` and Trivy provisioning (extracted from toolrun.py).

Budget gates and time-limit cap, the durable unfinished attempt committed before anything is spawned,
cancellation acknowledgement and the cancelled refusal (FEATURE-002-B/002-C behaviour, unchanged).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..adapters import ADAPTERS
from . import budget, egress, runs, service
from .model import GuardError


class ToolCancelled(Exception):
    """The verification was cancelled while its tool ran; `confirmed` = the owned group was seen exiting."""

    def __init__(self, confirmed: bool) -> None:
        super().__init__("cancelled")
        self.confirmed = confirmed


def ack(root: Path, vid: str, confirmed: bool, detail: str) -> None:
    runs.write_run_json(
        root,
        vid,
        "cancel-ack.json",
        {"pid": os.getpid(), "confirmed": confirmed, "detail": detail, "at": service.now()[0]},
    )


def cancelled_error(vid: str, confirmed: bool, detail: str) -> GuardError:
    return GuardError(
        "RUN_CANCELLED",
        f"Verification {vid} was cancelled; the tool run was stopped and nothing was recorded",
        f"Read its result: secure-code guard show --run {vid}",
        {"termination": "confirmed" if confirmed else "not_confirmed", "detail": detail},
    )


def cap_time_limit(root: Path, state: dict[str, Any], req: dict[str, Any]) -> float:
    """Budget gates and the effective time limit (capped by the remaining budget); returns consumed time."""
    used = service.consumed(root, state)
    budget.require_running(state, used)
    remaining = int(state["budget"]["total_seconds"] - used)
    req["requested_time_limit"] = req["time_limit"]
    req["time_limit"] = min(req["time_limit"], remaining)
    if req["time_limit"] < 1:
        budget.require_running(state, state["budget"]["total_seconds"])
    return used


def start_attempt(root: Path, vid: str, state: dict[str, Any], req: dict[str, Any]) -> dict[str, Any]:
    """Budget gates, time-limit cap and the durable unfinished tool attempt (committed before spawning)."""
    used = cap_time_limit(root, state, req)
    mode = egress.adapter_network_check(state, req["adapter"], [])
    req["argv_extra"] = mode.argv_extra
    req["network_mode"] = mode.mode
    if mode.mode == "networked":
        need = ADAPTERS[req["adapter"]].network
        decl = state["egress"]["declarations"]
        decl.append(
            {
                "id": f"eg-{len(decl) + 1}",
                "by": "toolkit",
                "purpose": need["purpose"],
                "recipient": egress.canonical_url(need["recipient"])[0],
                "data": list(need["data"]),
                "items": [f"{req['adapter']} tool run"],
                "scope": [egress.canonical_url(need["recipient"])[0] + "/"],
                "decision": "allowed",
                "missing": None,
                "at": service.now()[0],
                "used": True,
            }
        )
    pairs = [{"check": c["check"], "method": req["adapter"]} for c in req["checks"]]
    rev = state["revision"]
    attempt = budget.register(state, "tool", {"pairs": pairs}, used, service.now()[0], internal=True)
    runs.commit_state(root, state, expected_revision=rev)
    return attempt
