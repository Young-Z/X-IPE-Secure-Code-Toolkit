"""Shared verification budget (FEATURE-002-C): total time, extra attempts, pauses and registered attempts.

Pure functions on the run state. Consumed time is wall-clock since opening minus pause time; the caller
persists its high-water mark (`runs.bump_clock`). An attempt is a single-use lease registered before
work starts; the first time a check-and-method pair (or a Reviewer item) is covered is planned work,
every further coverage and every method added later is one extra attempt.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .model import Checker, GuardError, parse_time

DEFAULT_SECONDS = 3600
DEFAULT_ATTEMPTS = 3
MAX_SECONDS = 8 * 3600
MAX_ATTEMPTS = 20
MODEL_KINDS = frozenset({"semantic_review", "reviewer", "generation"})
AGENT_KINDS = MODEL_KINDS | {"helper"}
PAIR_KINDS = frozenset({"semantic_review", "helper", "generation", "tool"})
USAGE_KEYS = ("requests", "input_tokens", "output_tokens")
ATTEMPT_STEP = "Register the work first: secure-code guard attempt (see the Guard skill references)"
EXTEND_STEP = "Ask the user to run secure-code guard extend in their own terminal, or conclude now"


def _ck(code: str = "ATTEMPT_INVALID", step: str = ATTEMPT_STEP) -> Checker:
    return Checker(code, step)


def _count(value: Any, ck: Checker, where: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ck.fail(f"{where} must be a whole number from {low} to {high}")
    return value


# --------------------------------------------------------------------------- creation / legacy
def initial(raw: Any) -> dict[str, Any]:
    """Budget of a new verification: the defaults, or a smaller budget from the open request."""
    ck = _ck("BUDGET_INVALID", "Open with the defaults (omit budget) or less; the user can extend later")
    seconds, attempts, defaulted = DEFAULT_SECONDS, DEFAULT_ATTEMPTS, True
    if raw is not None:
        ck.obj(raw, "budget", {"minutes", "extra_attempts"})
        if "minutes" in raw:
            seconds = 60 * _count(raw["minutes"], ck, "budget.minutes", 1, DEFAULT_SECONDS // 60)
        if "extra_attempts" in raw:
            attempts = _count(raw["extra_attempts"], ck, "budget.extra_attempts", 0, DEFAULT_ATTEMPTS)
        defaulted = False
    return {
        "total_seconds": seconds,
        "extra_attempts": attempts,
        "defaulted": defaulted,
        "legacy": False,
        "extensions": [],
        "pauses": [],
        "extra_used": 0,
        "planned": None,
        "seen_before": {"pairs": [], "findings": [], "na": []},
    }


def _planned_pairs(plan: dict[str, Any]) -> list[list[str]]:
    added = {(c["check"], c["method"]["name"]) for c in plan.get("method_changes", [])}
    return sorted(
        [c["id"], m["name"]]
        for c in plan["checks"]
        for m in c["methods"]
        if not ((c["id"], m["name"]) in added and not m.get("required", True))
    )


def set_planned(state: dict[str, Any]) -> None:
    """Record the plan's own check-and-method pairs (called when the plan is recorded)."""
    if state.get("plan") is not None and state["budget"]["planned"] is None:
        state["budget"]["planned"] = _planned_pairs(state["plan"])


def ensure(state: dict[str, Any]) -> dict[str, Any]:
    """Give a verification opened before FEATURE-002-C the defaults and a baseline of its earlier work."""
    state.setdefault("attempts", [])
    state.setdefault("egress", {"grants": [], "declarations": []})
    state.setdefault("revision", 0)
    if "budget" not in state:
        b = initial(None)
        b["legacy"] = True
        seen = b["seen_before"]
        seen["pairs"] = sorted(
            {(c, e["method"]) for e in state.get("evidence", []) for c in e.get("checks", [])}
            | {(c, r["adapter"]) for r in state.get("adapter_runs", []) for c in (r.get("checks") or {})}
        )
        seen["pairs"] = [list(p) for p in seen["pairs"]]
        subjects = [s for r in state.get("reviews", []) for s in r.get("subjects", [])]
        seen["findings"] = sorted({s["id"] for s in subjects if s["type"] == "finding"})
        seen["na"] = sorted({s["id"] for s in subjects if s["type"] == "na_decision"})
        state["budget"] = b
    set_planned(state)
    return state


# --------------------------------------------------------------------------- clock and pauses
def pause_seconds(b: dict[str, Any], now: datetime) -> float:
    total = 0.0
    for p in b["pauses"]:
        end = parse_time(p["end"]) if p["end"] else now
        total += max(0.0, (end - parse_time(p["start"])).total_seconds())
    return total


def raw_consumed(state: dict[str, Any], now: datetime) -> float:
    """Wall-clock since opening minus all pause time (the current pause freezes the clock)."""
    elapsed = (now - parse_time(state["opened_at"])).total_seconds()
    return max(0.0, elapsed - pause_seconds(state["budget"], now))


def paused(state: dict[str, Any]) -> bool:
    pauses = state["budget"]["pauses"]
    return bool(pauses) and pauses[-1]["end"] is None


def pause(state: dict[str, Any], reason: str, at: str) -> None:
    if paused(state):
        raise GuardError("ALREADY_PAUSED", "The verification is already paused", "Resume it first")
    state["budget"]["pauses"].append({"start": at, "end": None, "reason": reason})


def resume(state: dict[str, Any], at: str) -> None:
    if not paused(state):
        raise GuardError("NOT_PAUSED", "The verification is not paused", "Continue with the next step")
    close_pause(state, at)


def close_pause(state: dict[str, Any], at: str) -> None:
    if paused(state):
        last = state["budget"]["pauses"][-1]
        last["end"] = max(at, last["start"])


def require_not_paused(state: dict[str, Any]) -> None:
    if paused(state):
        raise GuardError(
            "RUN_PAUSED",
            "The verification is paused; nothing can start or be recorded",
            f"Resume it first: secure-code guard resume --run {state.get('verification_id')}",
        )


def require_running(state: dict[str, Any], consumed: float) -> None:
    """New work needs an unpaused verification with remaining time."""
    require_not_paused(state)
    b = state["budget"]
    if consumed >= b["total_seconds"]:
        raise GuardError(
            "BUDGET_TIME_EXHAUSTED",
            f"The time limit of {b['total_seconds'] // 60} minutes is used up; no new attempt can start",
            EXTEND_STEP,
        )


def status(state: dict[str, Any], consumed: float) -> dict[str, Any]:
    b = state["budget"]
    return {
        "total_seconds": b["total_seconds"],
        "extra_attempts": b["extra_attempts"],
        "defaulted": b["defaulted"],
        "consumed_seconds": round(consumed, 1),
        "remaining_seconds": round(max(0.0, b["total_seconds"] - consumed), 1),
        "extra_used": b["extra_used"],
        "extra_left": max(0, b["extra_attempts"] - b["extra_used"]),
        "paused": paused(state),
        "exhausted": "time" if consumed >= b["total_seconds"] else None,
    }


# --------------------------------------------------------------------------- attempts
def _covers(state: dict[str, Any], kind: str, raw: Any) -> dict[str, list]:
    ck = _ck()
    if kind == "reviewer":
        ck.obj(raw, "covers", {"findings", "na"})
        findings = {f["id"] for f in state["findings"]}
        plan = state["plan"]
        na_ids = {c["id"] for c in plan["checks"]} | {f"policy:{n['rule']}" for n in plan["not_applicable"]}
        out = {"pairs": [], "findings": [], "na": []}
        for key, known in (("findings", findings), ("na", na_ids)):
            for i, item in enumerate(ck.items(raw.get(key), f"covers.{key}")):
                item = ck.key(item, f"covers.{key}[{i}]")
                if item not in known:
                    raise ck.fail(
                        f"covers.{key}[{i}]: unknown {key[:-1] if key == 'findings' else 'N/A'} {item!r}"
                    )
                if item not in out[key]:
                    out[key].append(item)
        if not out["findings"] and not out["na"]:
            raise ck.fail("a reviewer attempt must cover at least one finding or N/A decision")
        return out
    ck.obj(raw, "covers", {"pairs"}, frozenset({"pairs"}))
    methods = {c["id"]: {m["name"] for m in c["methods"]} for c in state["plan"]["checks"]}
    out = {"pairs": [], "findings": [], "na": []}
    for i, p in enumerate(ck.items(raw["pairs"], "covers.pairs", required=True)):
        ck.obj(p, f"covers.pairs[{i}]", {"check", "method"}, frozenset({"check", "method"}))
        cid = ck.key(p["check"], f"covers.pairs[{i}].check")
        name = ck.key(p["method"], f"covers.pairs[{i}].method")
        if name not in methods.get(cid, set()):
            raise ck.fail(f"covers.pairs[{i}]: {cid}/{name} is not a planned check and method")
        if [cid, name] not in out["pairs"]:
            out["pairs"].append([cid, name])
    return out


def _update_covers(raw: Any) -> dict[str, list]:
    """Toolkit-internal provisioning attempt (FEATURE-002-D): no check pairs, the components instead."""
    ck = _ck()
    ck.obj(raw, "covers", {"components"}, frozenset({"components"}))
    items = ck.items(raw["components"], "covers.components", required=True)
    names = [ck.key(c, "covers.components[]") for c in items]
    return {"pairs": [], "findings": [], "na": [], "components": names}


def _seen(state: dict[str, Any]) -> dict[str, set]:
    base = state["budget"]["seen_before"]
    seen = {
        "pairs": {tuple(p) for p in base["pairs"]},
        "findings": set(base["findings"]),
        "na": set(base["na"]),
    }
    for a in state["attempts"]:
        seen["pairs"] |= {tuple(p) for p in a["covers"]["pairs"]}
        seen["findings"] |= set(a["covers"]["findings"])
        seen["na"] |= set(a["covers"]["na"])
    return seen


def register(
    state: dict[str, Any], kind: str, covers: Any, consumed: float, at: str, *, internal: bool = False
) -> dict[str, Any]:
    """Register one unit of work before it starts; returns the recorded attempt."""
    ck = _ck()
    allowed = AGENT_KINDS | {"tool", "tool_update"} if internal else AGENT_KINDS
    if kind not in allowed:
        raise ck.fail(f"kind must be one of {', '.join(sorted(AGENT_KINDS))}")
    require_running(state, consumed)
    cov = _update_covers(covers) if kind == "tool_update" else _covers(state, kind, covers)
    seen = _seen(state)
    planned = {tuple(p) for p in state["budget"]["planned"] or []}
    extra_pairs = [p for p in cov["pairs"] if tuple(p) in seen["pairs"] or tuple(p) not in planned]
    extra_items = [i for i in cov["findings"] if i in seen["findings"]] + [
        i for i in cov["na"] if i in seen["na"]
    ]
    extra = len(extra_pairs) + len(extra_items)
    b = state["budget"]
    if b["extra_used"] + extra > b["extra_attempts"]:
        names = [f"{c}/{m}" for c, m in extra_pairs] + extra_items
        raise GuardError(
            "ATTEMPTS_EXHAUSTED",
            f"Not enough extra attempts left ({b['extra_attempts'] - b['extra_used']}) for the retries or "
            f"added methods {', '.join(names)}",
            EXTEND_STEP,
            {"extra_needed": extra},
        )
    b["extra_used"] += extra
    suffix = str(state.get("verification_id") or "")[-8:]
    attempt = {
        "id": f"a-{len(state['attempts']) + 1}" + (f"-{suffix}" if suffix else ""),
        "kind": kind,
        "covers": cov,
        "extra": extra,
        "started_at": at,
        "deadline_consumed": b["total_seconds"],
        "deadline_adjustments": [],
        "status": "unfinished",
        "finished_at": None,
        "overrun_seconds": 0,
        "usage": None,
        "tool_run": None,
    }
    state["attempts"].append(attempt)
    return attempt


def _usage(raw: Any) -> dict[str, int] | None:
    if raw is None:
        return None
    ck = _ck()
    ck.obj(raw, "usage", set(USAGE_KEYS))
    return {k: _count(raw.get(k, 0), ck, f"usage.{k}", 0, 10**12) for k in USAGE_KEYS}


def cite(
    state: dict[str, Any],
    attempt_id: Any,
    kinds: set[str] | frozenset[str],
    used: dict[str, set],
    consumed: float,
    at: str,
    usage: Any,
) -> dict[str, Any]:
    """Finish the cited attempt with this record; refuse anything outside its kind or coverage."""
    ck = _ck()
    attempt = next((a for a in state["attempts"] if a["id"] == attempt_id), None)
    if attempt is None:
        own = str(state.get("verification_id") or "")[-8:]
        if (
            isinstance(attempt_id, str)
            and re.fullmatch(r"a-\d+-[0-9a-f]{8}", attempt_id)
            and not attempt_id.endswith(f"-{own}")
        ):
            raise ck.fail(f"attempt {attempt_id} belongs to another verification")
        raise ck.fail(f"attempt {attempt_id!r} is not registered in this verification")
    if attempt["kind"] not in kinds:
        raise ck.fail(f"attempt {attempt_id} is a {attempt['kind']} attempt and cannot be cited here")
    if attempt["status"] != "unfinished":
        raise ck.fail(f"attempt {attempt_id} is already {attempt['status']}; register a new attempt")
    cov = attempt["covers"]
    outside = sorted(
        [f"{c}/{m}" for c, m in used.get("pairs", set()) if [c, m] not in cov["pairs"]]
        + [i for i in used.get("findings", set()) if i not in cov["findings"]]
        + [i for i in used.get("na", set()) if i not in cov["na"]]
        + [c for c in used.get("checks", set()) if c not in {p[0] for p in cov["pairs"]}]
    )
    if outside:
        raise ck.fail(f"attempt {attempt_id} does not cover {', '.join(outside)}")
    attempt["usage"] = _usage(usage)
    attempt["status"] = "finished"
    attempt["finished_at"] = at
    attempt["overrun_seconds"] = round(max(0.0, consumed - attempt["deadline_consumed"]), 1)
    return attempt


def cancel_unfinished(state: dict[str, Any]) -> list[dict[str, Any]]:
    out = [a for a in state["attempts"] if a["status"] == "unfinished"]
    for a in out:
        a["status"] = "cancelled"
    return out


# --------------------------------------------------------------------------- extension / summary
def extend(state: dict[str, Any], seconds: int, attempts: int, reason: str, at: str) -> dict[str, Any]:
    ck = _ck(
        "EXTENSION_INVALID", "Give minutes and/or attempts within the maximum (480 minutes, 20 attempts)"
    )
    b = state["budget"]
    _count(seconds, ck, "seconds", 0, MAX_SECONDS)
    _count(attempts, ck, "attempts", 0, MAX_ATTEMPTS)
    if seconds == 0 and attempts == 0:
        raise ck.fail("add some time or attempts")
    if b["total_seconds"] + seconds > MAX_SECONDS or b["extra_attempts"] + attempts > MAX_ATTEMPTS:
        raise ck.fail(
            f"the budget may not exceed {MAX_SECONDS // 60} minutes and {MAX_ATTEMPTS} extra attempts"
        )
    b["total_seconds"] += seconds
    b["extra_attempts"] += attempts
    entry = {"at": at, "seconds": seconds, "attempts": attempts, "reason": reason, "role": "user"}
    b["extensions"].append(entry)
    for a in state["attempts"]:
        if a["status"] == "unfinished":
            a["deadline_consumed"] = b["total_seconds"]
            a["deadline_adjustments"].append(
                {"at": at, "to": b["total_seconds"], "extension": len(b["extensions"])}
            )
    return entry


def summary(state: dict[str, Any], consumed: float) -> dict[str, Any]:
    """Budget section of the structured result."""
    b = state["budget"]
    usage = {k: 0 for k in USAGE_KEYS}
    unknown = not_applicable = 0
    for a in state["attempts"]:
        if a["kind"] not in MODEL_KINDS:
            not_applicable += 1
        elif a["usage"] is None:
            unknown += 1
        else:
            for k in USAGE_KEYS:
                usage[k] += a["usage"][k]
    return {
        **{
            k: b[k]
            for k in ("total_seconds", "extra_attempts", "defaulted", "legacy", "extensions", "pauses")
        },
        "consumed_seconds": round(consumed, 1),
        "extra_used": b["extra_used"],
        "exhausted": "time" if consumed >= b["total_seconds"] else None,
        "attempts_exhausted": b["extra_used"] >= b["extra_attempts"],
        "model_usage": {**usage, "unknown_attempts": unknown, "not_applicable_attempts": not_applicable},
    }
