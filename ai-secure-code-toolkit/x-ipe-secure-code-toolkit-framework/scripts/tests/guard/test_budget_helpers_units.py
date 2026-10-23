"""Unit tests for the Reviewer coverage item `helpers` (CR-TASK-077: AC-002C-01h, AC-002C-01i, FR-002C-2a).

The `helpers` run-state key belongs to FEATURE-002-F; these tests seed it directly (DEC-2).
"""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest
from test_budget_units import T0, iso, pairs, state

from x_ipe_secure_code.guard import budget
from x_ipe_secure_code.guard.model import GuardError


def with_helpers(*ids: str, **over) -> dict:
    return state(helpers=[{"id": h} for h in ids], **over)


def reviewer(s: dict, consumed: float = 10, **covers) -> dict:
    return budget.register(s, "reviewer", covers, consumed, iso(T0))


def refused(s: dict, kind: str, covers, code: str = "ATTEMPT_INVALID", consumed: float = 10) -> GuardError:
    before = copy.deepcopy(s)
    with pytest.raises(GuardError) as exc:
        budget.register(s, kind, covers, consumed, iso(T0))
    assert exc.value.code == code
    assert s == before
    return exc.value


# --------------------------------------------------------------------------- AC-002C-01h
def test_01h_reviewer_attempt_records_helpers_alone_or_mixed():
    s = with_helpers("h-1", "h-2")
    a = reviewer(s, helpers=["h-1"])
    assert a["kind"] == "reviewer" and a["extra"] == 0
    assert a["covers"] == {"pairs": [], "findings": [], "na": [], "helpers": ["h-1"]}
    b = reviewer(s, findings=["F1"], na=["C2"], helpers=["h-2"])
    assert b["covers"] == {"pairs": [], "findings": ["F1"], "na": ["C2"], "helpers": ["h-2"]}
    assert b["extra"] == 0 and s["budget"]["extra_used"] == 0
    assert [x["id"] for x in s["attempts"]] == [a["id"], b["id"]]


def test_01h_helpers_deduplicated_in_request_order():
    s = with_helpers("h-1", "h-2")
    a = reviewer(s, helpers=["h-2", "h-1", "h-2"])
    assert a["covers"]["helpers"] == ["h-2", "h-1"] and a["extra"] == 0


def test_01h_unknown_helper_refused_and_nothing_recorded():
    s = with_helpers("h-1")
    err = refused(s, "reviewer", {"helpers": ["h-1", "h-9"]})
    assert "covers.helpers[1]" in err.message and "unknown helper 'h-9'" in err.message
    assert s["attempts"] == []


@pytest.mark.parametrize(
    "helpers",
    [None, [], "h-1", [{"name": "h-1"}], [{"id": 7}], [{"id": None}], ["h-1"], {"h-1": {}}],
)
def test_01h_no_known_helpers_fails_closed(helpers):
    s = state() if helpers is None else state(helpers=helpers)
    if helpers is None:
        assert "helpers" not in s
    err = refused(s, "reviewer", {"helpers": ["h-1"]})
    assert "unknown helper 'h-1'" in err.message


@pytest.mark.parametrize("bad", ["h-1", [1], [""], [None], [{"id": "h-1"}]])
def test_01h_malformed_helper_ids_refused(bad):
    s = with_helpers("h-1")
    refused(s, "reviewer", {"helpers": bad})


@pytest.mark.parametrize("kind", ["semantic_review", "helper", "generation"])
def test_01h_helpers_on_other_kinds_refused(kind):
    s = with_helpers("h-1")
    err = refused(s, kind, {**pairs(("C1", "semantic-review")), "helpers": ["h-1"]})
    assert "unknown fields" in err.message


def test_01h_helpers_on_internal_kinds_refused():
    s = with_helpers("h-1")
    for kind, covers in (
        ("tool", {**pairs(("C1", "opengrep")), "helpers": ["h-1"]}),
        ("tool_update", {"components": ["trivy"], "helpers": ["h-1"]}),
    ):
        with pytest.raises(GuardError) as exc:
            budget.register(s, kind, covers, 10, iso(T0), internal=True)
        assert exc.value.code == "ATTEMPT_INVALID"
    assert s["attempts"] == []


@pytest.mark.parametrize(
    "covers", [{}, {"helpers": []}, {"findings": [], "na": [], "helpers": []}, {"helpers": None}]
)
def test_01h_reviewer_covering_nothing_refused(covers):
    s = with_helpers("h-1")
    err = refused(s, "reviewer", covers)
    assert err.message.endswith("a reviewer attempt must cover at least one finding, N/A decision or helper")


def test_01h_record_shape_unchanged_when_no_helper_named():
    s = with_helpers("h-1")
    a = reviewer(s, findings=["F1"], na=["policy:R9"])
    assert a["covers"] == {"pairs": [], "findings": ["F1"], "na": ["policy:R9"]}
    b = budget.register(s, "semantic_review", pairs(("C1", "semantic-review")), 10, iso(T0))
    assert b["covers"] == {"pairs": [["C1", "semantic-review"]], "findings": [], "na": []}
    c = budget.register(s, "tool_update", {"components": ["trivy"]}, 10, iso(T0), internal=True)
    assert c["covers"] == {"pairs": [], "findings": [], "na": [], "components": ["trivy"]}
    assert "helpers" not in s["budget"]["seen_before"]


def test_01h_cite_refuses_helper_outside_coverage_and_accepts_inside():
    s = with_helpers("h-1", "h-2")
    a = reviewer(s, na=["C2"], helpers=["h-1"])
    for used in ({"helpers": {"h-2"}}, {"na": {"C2"}, "helpers": {"h-1", "h-2"}}):
        with pytest.raises(GuardError) as exc:
            budget.cite(s, a["id"], {"reviewer"}, used, 20, iso(T0), None)
        assert exc.value.code == "ATTEMPT_INVALID" and "does not cover h-2" in exc.value.message
        assert a["status"] == "unfinished"
    done = budget.cite(s, a["id"], {"reviewer"}, {"na": {"C2"}, "helpers": {"h-1"}}, 20, iso(T0), None)
    assert done["status"] == "finished"


def test_01h_cite_refuses_any_helper_for_attempt_without_helpers():
    s = with_helpers("h-1")
    a = reviewer(s, findings=["F1"])
    with pytest.raises(GuardError) as exc:
        budget.cite(s, a["id"], {"reviewer"}, {"findings": {"F1"}, "helpers": {"h-1"}}, 20, iso(T0), None)
    assert exc.value.code == "ATTEMPT_INVALID" and "does not cover h-1" in exc.value.message
    assert budget.cite(s, a["id"], {"reviewer"}, {"findings": {"F1"}}, 20, iso(T0), None)["status"] == (
        "finished"
    )


# --------------------------------------------------------------------------- AC-002C-01i
def test_01i_first_coverage_planned_recoverage_extra():
    s = with_helpers("h-1", "h-2")
    assert reviewer(s, helpers=["h-1"])["extra"] == 0
    again = reviewer(s, helpers=["h-1", "h-2"])
    assert again["extra"] == 1 and s["budget"]["extra_used"] == 1
    third = reviewer(s, helpers=["h-1", "h-2"])
    assert third["extra"] == 2 and s["budget"]["extra_used"] == 3


def test_01i_mixed_coverage_counts_each_reviewer_item():
    s = with_helpers("h-1")
    s["budget"]["extra_attempts"] = 10
    assert reviewer(s, findings=["F1"], na=["C1"], helpers=["h-1"])["extra"] == 0
    assert reviewer(s, findings=["F1", "F2"], na=["C1", "C2"], helpers=["h-1"])["extra"] == 3
    assert s["budget"]["extra_used"] == 3


@pytest.mark.parametrize("ending", ["finished", "cancelled", "unfinished"])
def test_01i_recoverage_extra_whatever_earlier_status(ending):
    s = with_helpers("h-1")
    first = reviewer(s, helpers=["h-1"])
    if ending == "finished":
        budget.cite(s, first["id"], {"reviewer"}, {"helpers": {"h-1"}}, 20, iso(T0), None)
    elif ending == "cancelled":
        assert budget.cancel_unfinished(s) == [first]
    assert first["status"] == ending
    assert reviewer(s, helpers=["h-1"])["extra"] == 1


def test_01i_exhausted_names_helper_while_first_coverage_accepted():
    s = with_helpers("h-1", "h-2")
    s["budget"]["extra_attempts"] = 1
    reviewer(s, findings=["F1"], helpers=["h-1"])
    assert reviewer(s, helpers=["h-1"])["extra"] == 1
    err = refused(s, "reviewer", {"findings": ["F1"], "na": ["C1"], "helpers": ["h-1"]}, "ATTEMPTS_EXHAUSTED")
    assert "F1, h-1" in err.message and err.data == {"extra_needed": 2}
    assert reviewer(s, na=["C1"], helpers=["h-2"])["extra"] == 0
    assert s["budget"]["extra_used"] == 1


def test_01i_exhausted_message_orders_pairs_findings_na_helpers():
    s = with_helpers("h-1")
    reviewer(s, findings=["F1"], na=["C1"], helpers=["h-1"])
    s["budget"]["extra_attempts"] = 0
    err = refused(s, "reviewer", {"helpers": ["h-1"], "na": ["C1"], "findings": ["F1"]}, "ATTEMPTS_EXHAUSTED")
    assert err.message.endswith("added methods F1, C1, h-1")


def test_01i_pause_and_time_exhaustion_unchanged():
    s = with_helpers("h-1")
    refused(s, "reviewer", {"helpers": ["h-1"]}, "BUDGET_TIME_EXHAUSTED", consumed=3600)
    budget.pause(s, "asking", iso(T0))
    refused(s, "reviewer", {"helpers": ["h-1"]}, "RUN_PAUSED")


def test_01i_overrun_and_model_usage_unchanged():
    s = with_helpers("h-1", "h-2")
    a = reviewer(s, helpers=["h-1"])
    b = reviewer(s, helpers=["h-2"])
    late = iso(T0 + timedelta(seconds=3700))
    budget.cite(s, a["id"], {"reviewer"}, {"helpers": {"h-1"}}, 3700, late, {"requests": 2})
    assert a["overrun_seconds"] == 100
    assert a["usage"] == {"requests": 2, "input_tokens": 0, "output_tokens": 0}
    budget.cite(s, b["id"], {"reviewer"}, {"helpers": {"h-2"}}, 50, iso(T0), None)
    usage = budget.summary(s, 3700)["model_usage"]
    assert usage["requests"] == 2 and usage["unknown_attempts"] == 1 and usage["not_applicable_attempts"] == 0


def test_01i_legacy_state_without_helpers_loads_and_counts_as_before():
    delivered = state()
    old = {
        "id": "a-1",
        "kind": "reviewer",
        "covers": {"pairs": [], "findings": ["F1"], "na": []},
        "extra": 0,
        "status": "finished",
    }
    delivered["attempts"].append(old)
    assert "helpers" not in delivered and "helpers" not in delivered["budget"]["seen_before"]
    seen = budget._seen(delivered)
    assert seen["findings"] == {"F1"} and seen["helpers"] == set()
    assert reviewer(delivered, findings=["F1"])["extra"] == 1
    assert reviewer(delivered, na=["C1"])["covers"] == {"pairs": [], "findings": [], "na": ["C1"]}


def test_01i_pre_budget_state_ensured_then_helper_first_coverage_planned():
    s = {
        "opened_at": iso(T0),
        "verification_id": "gv-legacy",
        "plan": with_helpers()["plan"],
        "evidence": [],
        "findings": [{"id": "F1"}],
        "reviews": [{"subjects": [{"type": "finding", "id": "F1"}]}],
        "helpers": [{"id": "h-1"}],
    }
    budget.ensure(s)
    assert s["budget"]["legacy"] is True and set(s["budget"]["seen_before"]) == {"pairs", "findings", "na"}
    assert reviewer(s, findings=["F1"])["extra"] == 1
    assert reviewer(s, helpers=["h-1"])["extra"] == 0


def test_01i_initial_budget_has_no_helpers_baseline():
    assert budget.initial(None)["seen_before"] == {"pairs": [], "findings": [], "na": []}
