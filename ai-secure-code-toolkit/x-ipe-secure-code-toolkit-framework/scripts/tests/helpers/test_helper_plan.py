"""FEATURE-002-F plan rules and reserved names (AC-002F-01b, 07a; design §2.1, §1.1)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import copy

import pytest
from helperhelp import (  # noqa: F401 - fixture reuse
    GAP,
    METHOD,
    env,
    helper_check,
    helper_run,
    henv,
    open_src,
    plan,
    raw_record,
    state_of,
)


def refused(out, code, *texts):
    assert not out.ok and out.problems[0].code == code, out.to_text()
    for text in texts:
        assert text in out.problems[0].message, out.problems[0].message


# ---------- AC-002F-01b
def test_01b_planned_helper_method_stored_as_auxiliary_with_gap(henv):
    vid = helper_run(henv)
    stored = state_of(henv, vid)["plan"]["checks"][0]
    assert stored["methods"] == [{"name": METHOD, "kind": "runtime", "required": False}]
    assert stored["method_choice"]["gap"] == GAP


@pytest.mark.parametrize(
    ("change", "text"),
    [
        ({"methods": [{"name": METHOD, "kind": "runtime", "required": True}]}, "auxiliary"),
        ({"methods": [{"name": METHOD, "kind": "runtime"}]}, "auxiliary"),
        ({"methods": [{"name": METHOD, "kind": "reading", "required": False}]}, "kind runtime"),
        (
            {"methods": [{"name": "helper.Bad_Name", "kind": "runtime", "required": False}]},
            "helper method name",
        ),
        ({"method_choice": None}, "gap"),
    ],
)
def test_01b_helper_method_rules_refused(henv, change, text):
    vid = open_src(henv)
    check = helper_check(**change)
    if change.get("methods") and check["methods"][0]["name"] != METHOD:
        check["method_choice"]["selected"] = [check["methods"][0]["name"]]
    if check["method_choice"] is None:
        del check["method_choice"]
    refused(plan(henv, vid, check), "PLAN_INVALID", text)
    assert state_of(henv, vid)["plan"] is None


@pytest.mark.parametrize(
    ("gap", "text"),
    [
        (None, "gap is required"),
        ({k: v for k, v in GAP.items() if k != "why_insufficient"}, "why_insufficient"),
        ({**GAP, "considered": []}, "considered"),
        ({**GAP, "extra": 1}, "unknown fields"),
        ("free text", "must be an object"),
    ],
)
def test_01b_gap_reason_required_and_validated(henv, gap, text):
    vid = open_src(henv)
    check = helper_check()
    if gap is None:
        del check["method_choice"]["gap"]
    else:
        check["method_choice"]["gap"] = gap
    refused(plan(henv, vid, check), "PLAN_INVALID", text)


def test_01b_gap_refused_for_checks_without_helper_method(henv):
    vid = open_src(henv)
    check = helper_check(
        methods=[{"name": "semantic-review", "kind": "reading", "required": True}],
        minimum_evidence=["reading"],
    )
    check["method_choice"]["selected"] = ["semantic-review"]
    refused(plan(henv, vid, check), "PLAN_INVALID", "gap", "helper method")


def _reading_plan(env):
    check = helper_check(
        methods=[{"name": "semantic-review", "kind": "reading", "required": True}],
        minimum_evidence=["reading"],
    )
    del check["method_choice"]
    return helper_run(env, check)


def test_01b_method_change_adds_auxiliary_helper_with_gap(henv):
    vid = _reading_plan(henv)
    change = {
        "check": "C1",
        "change": "supplement",
        "method": {"name": METHOD, "kind": "runtime"},
        "reason": "reading is not enough",
    }
    refused(raw_record(henv, vid, method_changes=[change]), "RECORD_INVALID", "gap is required")
    refused(
        raw_record(
            henv, vid, method_changes=[{**change, "method": {"name": METHOD, "kind": "reading"}, "gap": GAP}]
        ),
        "RECORD_INVALID",
        "kind runtime",
    )
    refused(
        raw_record(
            henv,
            vid,
            method_changes=[{**change, "method": {"name": "x-read", "kind": "reading"}, "gap": GAP}],
        ),
        "RECORD_INVALID",
        "helper method",
    )
    out = raw_record(henv, vid, method_changes=[{**change, "gap": copy.deepcopy(GAP)}])
    assert out.ok, out.to_text()
    plan_state = state_of(henv, vid)["plan"]
    assert {"name": METHOD, "kind": "runtime", "required": False} in plan_state["checks"][0]["methods"]
    assert plan_state["method_changes"][0]["gap"] == GAP


# ---------- AC-002F-07a (agent side): helper names and ids are reserved
@pytest.mark.parametrize(
    "parts",
    [
        {
            "evidence": [
                {
                    "id": "E1",
                    "kind": "runtime",
                    "method": METHOD,
                    "method_status": "ok",
                    "checks": ["C1"],
                    "paths": ["src/config"],
                    "summary": "x",
                }
            ]
        },
        {
            "evidence": [
                {
                    "id": "helper-h1-x-1",
                    "kind": "reading",
                    "method": "semantic-review",
                    "method_status": "ok",
                    "checks": [],
                    "paths": ["src/config"],
                    "summary": "x",
                }
            ]
        },
        {
            "findings": [
                {
                    "id": "helper-h1-f1",
                    "rule": "CWE/4.14/CWE-79",
                    "location": {"path": "src/config/app.yaml"},
                    "title": "t",
                    "source": "semantic",
                    "severity": "high",
                }
            ]
        },
        {
            "findings": [
                {
                    "id": "F1",
                    "rule": "CWE/4.14/CWE-79",
                    "location": {"path": "src/config/app.yaml"},
                    "title": "t",
                    "source": METHOD,
                    "severity": "high",
                }
            ]
        },
    ],
)
def test_07a_agent_reserved_refused(henv, parts):
    vid = helper_run(henv)
    before = state_of(henv, vid)
    refused(raw_record(henv, vid, **parts), "RECORD_INVALID", "recorded only by secure-code guard helper run")
    assert state_of(henv, vid) == before
