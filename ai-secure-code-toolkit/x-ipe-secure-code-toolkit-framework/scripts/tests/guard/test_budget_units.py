"""Unit tests for guard/budget.py (FEATURE-002-C AC-002C-01*, 02*, 03*, 06c)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from x_ipe_secure_code.guard import budget
from x_ipe_secure_code.guard.model import GuardError

T0 = datetime(2026, 10, 20, 10, 0, 0, tzinfo=UTC)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def plan(*checks: tuple[str, tuple[str, ...]], changes=()) -> dict:
    return {
        "checks": [
            {"id": cid, "methods": [{"name": m, "kind": "reading", "required": True} for m in methods]}
            for cid, methods in checks
        ],
        "not_applicable": [{"rule": "R9"}],
        "method_changes": list(changes),
    }


def state(**over) -> dict:
    s = {
        "opened_at": iso(T0),
        "plan": plan(("C1", ("semantic-review", "opengrep")), ("C2", ("semantic-review",))),
        "evidence": [],
        "findings": [{"id": "F1"}, {"id": "F2"}],
        "reviews": [],
        "budget": budget.initial(None),
        "attempts": [],
    }
    s.update(over)
    budget.set_planned(s)
    return s


def pairs(*items: tuple[str, str]) -> dict:
    return {"pairs": [{"check": c, "method": m} for c, m in items]}


# --------------------------------------------------------------------------- AC-002C-01a
def test_initial_defaults_and_caps():
    b = budget.initial(None)
    assert (b["total_seconds"], b["extra_attempts"], b["defaulted"]) == (3600, 3, True)
    b = budget.initial({"minutes": 30, "extra_attempts": 1})
    assert (b["total_seconds"], b["extra_attempts"], b["defaulted"]) == (1800, 1, False)
    for bad in (
        {"minutes": 61},
        {"extra_attempts": 4},
        {"minutes": 0},
        {"minutes": -1},
        {"minutes": "5"},
        {"minutes": True},
        {"other": 1},
        "x",
    ):
        with pytest.raises(GuardError) as exc:
            budget.initial(bad)
        assert exc.value.code == "BUDGET_INVALID"


# --------------------------------------------------------------------------- AC-002C-01b / 02
def test_consumed_time_frozen_while_paused():
    s = state()
    assert budget.raw_consumed(s, T0 + timedelta(seconds=100)) == 100
    budget.pause(s, "asking", iso(T0 + timedelta(seconds=100)))
    assert budget.paused(s)
    assert budget.raw_consumed(s, T0 + timedelta(seconds=500)) == 100
    budget.resume(s, iso(T0 + timedelta(seconds=600)))
    assert not budget.paused(s)
    assert budget.raw_consumed(s, T0 + timedelta(seconds=650)) == 150
    assert s["budget"]["pauses"] == [
        {
            "start": iso(T0 + timedelta(seconds=100)),
            "end": iso(T0 + timedelta(seconds=600)),
            "reason": "asking",
        }
    ]


def test_pause_and_resume_errors():
    s = state()
    with pytest.raises(GuardError) as exc:
        budget.resume(s, iso(T0))
    assert exc.value.code == "NOT_PAUSED"
    budget.pause(s, "x", iso(T0))
    with pytest.raises(GuardError) as exc:
        budget.pause(s, "y", iso(T0))
    assert exc.value.code == "ALREADY_PAUSED"


def test_require_running_paused_and_exhausted():
    s = state()
    budget.require_running(s, 10)
    with pytest.raises(GuardError) as exc:
        budget.require_running(s, 3600)
    assert exc.value.code == "BUDGET_TIME_EXHAUSTED" and "time" in exc.value.message
    budget.pause(s, "x", iso(T0))
    with pytest.raises(GuardError) as exc:
        budget.require_running(s, 10)
    assert exc.value.code == "RUN_PAUSED"


def test_status_reports_limits_and_remaining():
    s = state()
    st = budget.status(s, 600.4)
    assert st["total_seconds"] == 3600 and st["remaining_seconds"] == pytest.approx(2999.6)
    assert st["extra_attempts"] == 3 and st["extra_left"] == 3 and st["paused"] is False
    assert st["exhausted"] is None and st["defaulted"] is True
    assert budget.status(s, 4000)["exhausted"] == "time" and budget.status(s, 4000)["remaining_seconds"] == 0


# --------------------------------------------------------------------------- AC-002C-01c / 01d
def test_register_planned_pairs_are_free_and_grouping_costs_nothing():
    s = state()
    a = budget.register(
        s, "semantic_review", pairs(("C1", "semantic-review"), ("C2", "semantic-review")), 0, iso(T0)
    )
    assert a["id"] == "a-1" and a["extra"] == 0 and a["status"] == "unfinished"
    assert a["deadline_consumed"] == 3600 and a["started_at"] == iso(T0)


def test_retry_counts_per_pair_whatever_the_result():
    s = state()
    budget.register(
        s, "semantic_review", pairs(("C1", "semantic-review"), ("C2", "semantic-review")), 0, iso(T0)
    )
    again = budget.register(
        s, "semantic_review", pairs(("C1", "semantic-review"), ("C2", "semantic-review")), 0, iso(T0)
    )
    assert again["extra"] == 2 and s["budget"]["extra_used"] == 2


def test_method_added_later_is_extra():
    s = state()
    s["plan"]["checks"][1]["methods"].append({"name": "manual", "kind": "reading", "required": False})
    s["plan"]["method_changes"].append({"check": "C2", "method": {"name": "manual", "kind": "reading"}})
    a = budget.register(s, "helper", pairs(("C2", "manual")), 0, iso(T0))
    assert a["extra"] == 1


def test_attempts_exhausted_refuses_extra_but_not_planned():
    s = state()
    s["budget"]["extra_attempts"] = 1
    budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    with pytest.raises(GuardError) as exc:
        budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    assert exc.value.code == "ATTEMPTS_EXHAUSTED" and "C1/semantic-review" in exc.value.message
    assert budget.register(s, "semantic_review", pairs(("C2", "semantic-review")), 0, iso(T0))["extra"] == 0


def test_register_refused_when_time_exhausted_or_paused():
    s = state()
    with pytest.raises(GuardError) as exc:
        budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 3600, iso(T0))
    assert exc.value.code == "BUDGET_TIME_EXHAUSTED"
    budget.pause(s, "x", iso(T0))
    with pytest.raises(GuardError) as exc:
        budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    assert exc.value.code == "RUN_PAUSED"


@pytest.mark.parametrize(
    "kind, covers",
    [
        ("semantic_review", pairs(("C9", "semantic-review"))),
        ("semantic_review", pairs(("C1", "nope"))),
        ("semantic_review", {"pairs": []}),
        ("semantic_review", {"findings": ["F1"]}),
        ("reviewer", {"findings": ["F9"]}),
        ("reviewer", {"na": ["policy:R1"]}),
        ("reviewer", {"findings": [], "na": []}),
        ("reviewer", pairs(("C1", "semantic-review"))),
        ("tool", pairs(("C1", "opengrep"))),
        ("magic", pairs(("C1", "semantic-review"))),
    ],
)
def test_register_invalid_coverage(kind, covers):
    with pytest.raises(GuardError) as exc:
        budget.register(state(), kind, covers, 0, iso(T0))
    assert exc.value.code == "ATTEMPT_INVALID"


def test_reviewer_items_retry_counts():
    s = state()
    a = budget.register(s, "reviewer", {"findings": ["F1", "F2"], "na": ["policy:R9"]}, 0, iso(T0))
    assert a["extra"] == 0
    b = budget.register(s, "reviewer", {"findings": ["F1"], "na": ["C1"]}, 0, iso(T0))
    assert b["extra"] == 1


def test_tool_attempt_internal():
    s = state()
    a = budget.register(s, "tool", pairs(("C1", "opengrep")), 0, iso(T0), internal=True)
    assert a["kind"] == "tool" and a["extra"] == 0


# --------------------------------------------------------------------------- AC-002C-01e / 01f
def test_cite_finishes_once_and_checks_coverage():
    s = state()
    a = budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    with pytest.raises(GuardError) as exc:
        budget.cite(s, "a-1", {"semantic_review"}, {"pairs": {("C2", "semantic-review")}}, 10, iso(T0), None)
    assert exc.value.code == "ATTEMPT_INVALID"
    with pytest.raises(GuardError) as exc:
        budget.cite(s, "a-1", {"reviewer"}, {"pairs": set()}, 10, iso(T0), None)
    assert exc.value.code == "ATTEMPT_INVALID"
    with pytest.raises(GuardError) as exc:
        budget.cite(s, "a-7", {"semantic_review"}, {"pairs": set()}, 10, iso(T0), None)
    assert exc.value.code == "ATTEMPT_INVALID"
    done = budget.cite(
        s,
        "a-1",
        {"semantic_review"},
        {"pairs": {("C1", "semantic-review")}},
        10,
        iso(T0),
        {"requests": 2, "input_tokens": 100, "output_tokens": 7},
    )
    assert done is a and a["status"] == "finished" and a["usage"]["input_tokens"] == 100
    with pytest.raises(GuardError) as exc:
        budget.cite(s, "a-1", {"semantic_review"}, {"pairs": {("C1", "semantic-review")}}, 10, iso(T0), None)
    assert exc.value.code == "ATTEMPT_INVALID" and "finished" in exc.value.message


def test_overrun_measured_in_consumed_time():
    s = state()
    budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 3500, iso(T0))
    a = budget.cite(
        s, "a-1", {"semantic_review"}, {"pairs": {("C1", "semantic-review")}}, 3700, iso(T0), None
    )
    assert a["overrun_seconds"] == 100


@pytest.mark.parametrize(
    "usage", [{"requests": -1}, {"tokens": 1}, {"requests": 1.5}, {"requests": True}, "x"]
)
def test_usage_validated(usage):
    s = state()
    budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    with pytest.raises(GuardError) as exc:
        budget.cite(s, "a-1", {"semantic_review"}, {"pairs": set()}, 1, iso(T0), usage)
    assert exc.value.code == "ATTEMPT_INVALID"


def test_summary_usage_unknown_and_not_applicable():
    s = state()
    budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    budget.cite(
        s, "a-1", {"semantic_review"}, {"pairs": set()}, 1, iso(T0), {"requests": 1, "input_tokens": 5}
    )
    budget.register(s, "semantic_review", pairs(("C2", "semantic-review")), 0, iso(T0))
    budget.register(s, "tool", pairs(("C1", "opengrep")), 0, iso(T0), internal=True)
    u = budget.summary(s, 30)["model_usage"]
    assert u == {
        "requests": 1,
        "input_tokens": 5,
        "output_tokens": 0,
        "unknown_attempts": 1,
        "not_applicable_attempts": 1,
    }


# --------------------------------------------------------------------------- AC-002C-03d
def test_extend_moves_unfinished_deadlines_and_caps():
    s = state()
    budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    budget.extend(s, 1800, 2, "needs more", iso(T0))
    assert s["budget"]["total_seconds"] == 5400 and s["budget"]["extra_attempts"] == 5
    assert s["attempts"][0]["deadline_consumed"] == 5400
    assert s["attempts"][0]["deadline_adjustments"][0]["to"] == 5400
    assert s["budget"]["extensions"][0]["reason"] == "needs more"
    for seconds, attempts in ((0, 0), (-60, 0), (28800, 0), (0, 16)):
        with pytest.raises(GuardError) as exc:
            budget.extend(s, seconds, attempts, "x", iso(T0))
        assert exc.value.code == "EXTENSION_INVALID"


# --------------------------------------------------------------------------- AC-002C-06c legacy
def test_ensure_legacy_defaults_and_seen_baseline():
    s = {
        "opened_at": iso(T0),
        "plan": plan(
            ("C1", ("semantic-review", "opengrep")),
            ("C2", ("semantic-review", "manual")),
            changes=[{"check": "C2", "method": {"name": "manual", "kind": "reading"}}],
        ),
        "evidence": [{"id": "E1", "method": "semantic-review", "checks": ["C1"]}],
        "adapter_runs": [{"checks": {"C1": {}}, "adapter": "opengrep"}],
        "findings": [{"id": "F1"}],
        "reviews": [
            {"subjects": [{"type": "finding", "id": "F1"}, {"type": "na_decision", "id": "policy:R9"}]}
        ],
    }
    s["plan"]["checks"][1]["methods"][1]["required"] = False
    budget.ensure(s)
    b = s["budget"]
    assert b["legacy"] is True and b["defaulted"] is True and s["attempts"] == [] and s["revision"] == 0
    assert ["C2", "manual"] not in b["planned"] and ["C1", "opengrep"] in b["planned"]
    assert ["C1", "semantic-review"] in b["seen_before"]["pairs"] and ["C1", "opengrep"] in b["seen_before"][
        "pairs"
    ]
    assert b["seen_before"]["findings"] == ["F1"] and b["seen_before"]["na"] == ["policy:R9"]
    assert budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))["extra"] == 1
    assert budget.register(s, "semantic_review", pairs(("C2", "semantic-review")), 0, iso(T0))["extra"] == 0
    assert budget.register(s, "reviewer", {"findings": ["F1"]}, 0, iso(T0))["extra"] == 1


def test_ensure_is_idempotent_for_new_states():
    s = state()
    before = dict(s["budget"])
    budget.ensure(s)
    assert s["budget"] == before


def test_cite_checks_finding_checks_against_covered_checks():
    s = state()
    budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 0, iso(T0))
    with pytest.raises(GuardError) as exc:
        budget.cite(s, "a-1", {"semantic_review"}, {"checks": {"C2"}}, 1, iso(T0), None)
    assert exc.value.code == "ATTEMPT_INVALID" and "C2" in exc.value.message
    done = budget.cite(s, "a-1", {"semantic_review"}, {"checks": {"C1"}}, 1, iso(T0), None)
    assert done["status"] == "finished"
