"""Integration tests for the Reviewer coverage item `helpers` (CR-TASK-077: AC-002C-01h, AC-002C-01i).

FEATURE-002-F owns the run-state `helpers` list and the `helper` Reviewer subject type; neither exists
yet, so these tests seed the list in state.json and inject a helper subject at the review boundary.
"""

# ruff: noqa: F811 - pytest fixtures imported by name from the 002-A/002-C integration modules

from __future__ import annotations

import json

from test_guard import (  # noqa: F401 - fixture reuse
    GUARD,
    R2,
    env,
    na_confirmed,
    review,
)
from test_guard_budget import (  # noqa: F401 - fixture reuse
    aid,
    attempt,
    clock,
    planned,
    state_of,
)

from x_ipe_secure_code.guard import cancel, control, records
from x_ipe_secure_code.guard import service as guard

REPORTS = "x-ipe-docs/secure-code/reports/guard"
NA = f"policy:{R2}"


def seed_helpers(env, vid, *ids):
    """Write the FEATURE-002-F-owned `helpers` key directly (002-F commands do not exist yet)."""
    path = env["project"] / GUARD / vid / "state.json"
    state = json.loads(path.read_text())
    state["helpers"] = [{"id": h, "check": "C1", "digest": "sha256:" + "0" * 64} for h in ids]
    path.write_text(json.dumps(state))


def helper_run(env, *ids, **over):
    vid = planned(env, **over)
    seed_helpers(env, vid, *ids)
    return vid


# ---------- AC-002C-01h
def test_01h_guard_attempt_records_helpers_alone_or_mixed(env):
    vid = helper_run(env, "h-1", "h-2")
    alone = attempt(env, vid, "reviewer", {"helpers": ["h-1"]})
    assert alone.ok, alone.to_text()
    assert alone.data["attempt"] == aid(vid) and alone.data["kind"] == "reviewer" and alone.data["extra"] == 0
    mixed = attempt(env, vid, "reviewer", {"na": [NA], "helpers": ["h-2", "h-2"]})
    assert mixed.ok and mixed.data["extra"] == 0
    covers = [a["covers"] for a in state_of(env, vid)["attempts"]]
    assert covers == [
        {"pairs": [], "findings": [], "na": [], "helpers": ["h-1"]},
        {"pairs": [], "findings": [], "na": [NA], "helpers": ["h-2"]},
    ]


def test_01h_refusals_record_nothing(env):
    vid = helper_run(env, "h-1")
    before = state_of(env, vid)
    pair = [{"check": "C1", "method": "semantic-review"}]
    cases = [
        ("reviewer", {"helpers": ["h-9"]}, "unknown helper 'h-9'"),
        ("reviewer", {"na": [NA], "helpers": ["h-1", "h-9"]}, "covers.helpers[1]"),
        ("reviewer", {"helpers": []}, "finding, N/A decision or helper"),
        ("reviewer", {}, "finding, N/A decision or helper"),
        ("semantic_review", {"pairs": pair, "helpers": ["h-1"]}, "unknown fields"),
        ("helper", {"pairs": pair, "helpers": ["h-1"]}, "unknown fields"),
        ("generation", {"pairs": pair, "helpers": ["h-1"]}, "unknown fields"),
    ]
    for kind, covers, text in cases:
        out = attempt(env, vid, kind, covers)
        assert out.problems[0].code == "ATTEMPT_INVALID", (kind, covers)
        assert text in out.problems[0].message
    assert state_of(env, vid) == before


def test_01h_run_without_helpers_refuses_any_helper(env):
    vid = planned(env)
    out = attempt(env, vid, "reviewer", {"helpers": ["h-1"]})
    assert out.problems[0].code == "ATTEMPT_INVALID" and "unknown helper 'h-1'" in out.problems[0].message
    assert state_of(env, vid)["attempts"] == []


def test_01h_requests_without_helpers_recorded_as_before(env):
    vid = helper_run(env, "h-1")
    assert attempt(env, vid, "reviewer", {"findings": [], "na": [NA]}).ok
    assert attempt(env, vid).ok
    covers = [a["covers"] for a in state_of(env, vid)["attempts"]]
    assert covers == [
        {"pairs": [], "findings": [], "na": [NA]},
        {"pairs": [["C1", "semantic-review"]], "findings": [], "na": []},
    ]
    assert "helpers" not in state_of(env, vid)["budget"]["seen_before"]


def _with_helper_subject(monkeypatch, helper_id):
    """Inject a `helper` subject (FEATURE-002-F extension) into an otherwise valid Reviewer record."""
    real = records.validate_review

    def validate(state, doc):
        entry, warnings = real(state, doc)
        entry["subjects"].append({"type": "helper", "id": helper_id, "result": "confirmed", "basis": "read"})
        return entry, warnings

    monkeypatch.setattr(records, "validate_review", validate)


def test_01h_dec3_review_refuses_helper_subject_outside_attempt_coverage(env, monkeypatch):
    vid = helper_run(env, "h-1")
    a = attempt(env, vid, "reviewer", {"na": [NA]})
    _with_helper_subject(monkeypatch, "h-1")
    out = review(env, vid, [na_confirmed()], attempt=a.data["attempt"])
    assert out.problems[0].code == "ATTEMPT_INVALID"
    assert f"attempt {aid(vid)} does not cover h-1" in out.problems[0].message
    state = state_of(env, vid)
    assert state["reviews"] == [] and state["attempts"][0]["status"] == "unfinished"


def test_01h_dec3_review_accepts_helper_subject_inside_attempt_coverage(env, monkeypatch):
    vid = helper_run(env, "h-1")
    a = attempt(env, vid, "reviewer", {"na": [NA], "helpers": ["h-1"]})
    _with_helper_subject(monkeypatch, "h-1")
    out = review(env, vid, [na_confirmed()], attempt=a.data["attempt"])
    assert out.ok, out.to_text()
    state = state_of(env, vid)
    assert [s["type"] for s in state["reviews"][0]["subjects"]] == ["na_decision", "helper"]
    assert state["attempts"][0]["status"] == "finished"


# ---------- AC-002C-01i
def test_01i_first_coverage_planned_recoverage_extra_and_exhaustion(env):
    vid = helper_run(env, "h-1", "h-2", budget={"extra_attempts": 1})
    assert attempt(env, vid, "reviewer", {"helpers": ["h-1"]}).data["extra"] == 0
    assert attempt(env, vid, "reviewer", {"na": [NA], "helpers": ["h-1"]}).data["extra"] == 1
    refused = attempt(env, vid, "reviewer", {"helpers": ["h-1"]})
    assert refused.problems[0].code == "ATTEMPTS_EXHAUSTED" and "h-1" in refused.problems[0].message
    assert refused.data["budget"]["extra_left"] == 0
    first = attempt(env, vid, "reviewer", {"helpers": ["h-2"]})
    assert first.ok and first.data["extra"] == 0
    assert state_of(env, vid)["budget"]["extra_used"] == 1


def test_01i_pause_and_time_exhaustion_refuse_helper_attempts(env, clock):
    vid = helper_run(env, "h-1")
    clock.at(env, vid, 100)
    assert control.pause(str(env["project"]), vid, "asking the user").ok
    assert attempt(env, vid, "reviewer", {"helpers": ["h-1"]}).problems[0].code == "RUN_PAUSED"
    assert control.resume(str(env["project"]), vid).ok
    clock.at(env, vid, 3700)
    out = attempt(env, vid, "reviewer", {"helpers": ["h-1"]})
    assert out.problems[0].code == "BUDGET_TIME_EXHAUSTED"
    assert state_of(env, vid)["attempts"] == []


def test_01i_overrun_and_model_usage_for_helper_attempts(env, clock):
    vid = helper_run(env, "h-1")
    clock.at(env, vid, 10)
    a = attempt(env, vid, "reviewer", {"na": [NA], "helpers": ["h-1"]})
    clock.at(env, vid, 3700)
    out = review(env, vid, [na_confirmed()], attempt=a.data["attempt"], usage={"requests": 4})
    assert out.ok, out.to_text()
    recorded = state_of(env, vid)["attempts"][0]
    assert recorded["overrun_seconds"] == 100 and recorded["usage"]["requests"] == 4
    result = guard.conclude(str(env["project"]), vid)
    assert result.data["budget"]["model_usage"]["requests"] == 4


def test_01i_cancel_marks_unfinished_helper_attempt_cancelled(env):
    vid = helper_run(env, "h-1")
    assert attempt(env, vid, "reviewer", {"helpers": ["h-1"]}).ok
    out = cancel.cancel(str(env["project"]), vid, "user stopped")
    assert out.ok, out.to_text()
    data = json.loads((env["project"] / REPORTS / f"{vid}.json").read_text())
    last = data["attempts"][-1]
    assert last["status"] == "cancelled" and last["covers"]["helpers"] == ["h-1"]
    assert data["verdict"] != "pass"


def test_01i_report_attempts_table_lists_helpers(env):
    vid = helper_run(env, "h-1", "h-2")
    attempt(env, vid, "reviewer", {"na": [NA], "helpers": ["h-1", "h-2"]})
    result = guard.conclude(str(env["project"]), vid)
    assert result.ok, result.to_text()
    md = (env["project"] / REPORTS / f"{vid}.md").read_text()
    section = md.split("## Budget", 1)[1].split("\n## ", 1)[0]
    row = next(line for line in section.splitlines() if aid(vid) in line)
    assert NA in row and "h-1" in row and "h-2" in row


def test_01i_verification_opened_by_delivered_002c_counts_as_before(env):
    vid = planned(env)
    state = state_of(env, vid)
    assert "helpers" not in state and set(state["budget"]["seen_before"]) == {"pairs", "findings", "na"}
    assert attempt(env, vid, "reviewer", {"na": [NA]}).data["extra"] == 0
    assert attempt(env, vid, "reviewer", {"na": [NA]}).data["extra"] == 1
    assert attempt(env, vid).data["extra"] == 0


def test_01i_pre_budget_verification_loads_and_helper_first_coverage_planned(env):
    vid = planned(env)
    path = env["project"] / GUARD / vid / "state.json"
    legacy = json.loads(path.read_text())
    for key in ("budget", "attempts", "egress", "revision"):
        legacy.pop(key, None)
    path.write_text(json.dumps(legacy))
    seed_helpers(env, vid, "h-1")
    a = attempt(env, vid, "reviewer", {"helpers": ["h-1"]})
    assert a.ok and a.data["extra"] == 0
    state = state_of(env, vid)
    assert state["budget"]["legacy"] is True and "helpers" not in state["budget"]["seen_before"]
