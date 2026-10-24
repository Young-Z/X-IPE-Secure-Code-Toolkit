"""FEATURE-002-F budget and attempts under the unchanged 002-C rules (AC-002F-01d, 06a, 06b, 06c)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import copy

from helperhelp import (  # noqa: F401 - fixture reuse
    GAP,
    METHOD,
    attempt,
    env,
    fake,
    flow,
    helper_check,
    helper_run,
    henv,
    pair,
    raw_record,
    state_of,
)

from x_ipe_secure_code.guard import service as guard


def _reading_run(env):
    check = helper_check(
        methods=[{"name": "semantic-review", "kind": "reading", "required": True}],
        minimum_evidence=["reading"],
    )
    del check["method_choice"]
    return helper_run(env, check)


# ---------- AC-002F-01d
def test_01d_later_method_costs_extra(flow):
    planned = helper_run(flow.env)
    assert attempt(flow.env, planned, "generation", pair()).data["extra"] == 0
    later = _reading_run(flow.env)
    change = {
        "check": "C1",
        "change": "supplement",
        "method": {"name": METHOD, "kind": "runtime"},
        "reason": "reading is not enough",
        "gap": copy.deepcopy(GAP),
    }
    assert raw_record(flow.env, later, method_changes=[change]).ok
    assert attempt(flow.env, later, "generation", pair()).data["extra"] == 1
    assert state_of(flow.env, later)["budget"]["extra_used"] == 1


# ---------- AC-002F-06c
def test_06c_generation_attempt_and_extra(flow):
    vid = helper_run(flow.env)
    missing = flow.submit(vid, flow.request(vid, None))
    assert missing.problems[0].code == "ATTEMPT_REQUIRED"
    wrong = attempt(flow.env, vid, "semantic_review", pair()).data["attempt"]
    assert flow.submit(vid, flow.request(vid, wrong)).problems[0].code == "ATTEMPT_INVALID"
    gen = flow.generation(vid)
    out = flow.submit(vid, flow.request(vid, gen, usage={"requests": 2, "input_tokens": 10}))
    assert out.ok and out.data["expected_extra_attempts"] == 2
    a = next(x for x in state_of(flow.env, vid)["attempts"] if x["id"] == gen)
    assert a["status"] == "finished" and a["usage"]["requests"] == 2
    assert flow.submit(vid, flow.request(vid, gen)).problems[0].code == "ATTEMPT_INVALID"
    regen = attempt(flow.env, vid, "generation", pair())
    assert regen.data["extra"] == 1
    helper_attempt = attempt(flow.env, vid, "helper", pair())
    assert helper_attempt.data["extra"] == 1


# ---------- AC-002F-06a
def test_06a_helper_attempt_lease(flow):
    vid, hid = flow.ready()
    assert flow.run(vid, hid, None).problems[0].code == "ATTEMPT_REQUIRED"
    gen = flow.generation(vid)
    assert flow.run(vid, hid, gen).problems[0].code == "ATTEMPT_INVALID"
    other = helper_run(flow.env)
    foreign = attempt(flow.env, other, "helper", pair()).data["attempt"]
    out = flow.run(vid, hid, foreign)
    assert out.problems[0].code == "ATTEMPT_INVALID" and "another verification" in out.problems[0].message
    reading = _reading_run(flow.env)
    wrong_pair = attempt(flow.env, reading, "helper", pair("C1", "semantic-review"))
    assert wrong_pair.ok
    a = flow.helper_attempt(vid)
    done = flow.run(vid, hid, a)
    assert done.ok and done.data["attempt"] == a
    assert flow.run(vid, hid, a).problems[0].code == "ATTEMPT_INVALID"
    unfinished = flow.helper_attempt(vid)
    assert guard.conclude(str(flow.root), vid).ok
    import json

    result = json.loads((flow.root / "x-ipe-docs/secure-code/reports/guard" / f"{vid}.json").read_text())
    statuses = {x["id"]: x["status"] for x in result["attempts"]}
    assert statuses[a] == "finished" and statuses[unfinished] == "unfinished"


# ---------- AC-002F-06b
def test_06b_time_counts_usage_na(flow):
    vid, hid = flow.ready()
    flow.fake.set(runs={"target": {"mode": "auto", "sleep": 1.5}})
    before = guard.show(str(flow.root), vid).data["budget"]["consumed_seconds"]
    a = flow.helper_attempt(vid)
    out = flow.run(vid, hid, a)
    assert out.ok
    assert out.data["budget"]["consumed_seconds"] >= before + 1.5
    record = next(x for x in state_of(flow.env, vid)["attempts"] if x["id"] == a)
    assert record["usage"] is None and record["kind"] == "helper"
    concluded = guard.conclude(str(flow.root), vid)
    assert concluded.data["budget"]["model_usage"]["not_applicable_attempts"] >= 1
