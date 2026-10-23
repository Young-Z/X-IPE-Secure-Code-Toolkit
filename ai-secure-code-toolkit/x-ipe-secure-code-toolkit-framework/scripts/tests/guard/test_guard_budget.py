"""Integration tests for FEATURE-002-C budget, attempts, pause and extension (service + control)."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from conftest import FakeInteraction, posix_only
from test_guard import (  # noqa: F401 - fixture reuse
    GUARD,
    R1,
    R2,
    env,
    ev,
    high_finding,
    na_confirmed,
    opened,
    plan,
    req,
    review,
)

from x_ipe_secure_code.guard import control, model
from x_ipe_secure_code.guard import service as guard

RECORD = "ai-secure-code-toolkit/guard-record/v1"
ATTEMPT = "ai-secure-code-toolkit/guard-attempt/v1"


def aid(vid, n=1):
    """Attempt ids are bound to their verification (a-<n>-<last 8 hex of the verification id>)."""
    return f"a-{n}-{vid[-8:]}"


def raw_record(env, vid, **parts):
    return guard.record(str(env["project"]), vid, req(env, {"schema": RECORD, **parts}))


def attempt(env, vid, kind="semantic_review", covers=None):
    covers = covers if covers is not None else {"pairs": [{"check": "C1", "method": "semantic-review"}]}
    return control.attempt(
        str(env["project"]), vid, req(env, {"schema": ATTEMPT, "kind": kind, "covers": covers})
    )


def state_of(env, vid):
    return json.loads((env["project"] / GUARD / vid / "state.json").read_text())


@pytest.fixture
def clock(monkeypatch):
    """Patch the Guard clock: `clock.at(vid_state, seconds)` sets now = opened_at + seconds."""

    class Clock:
        now = None

        def at(self, env, vid, seconds):
            opened_at = model.parse_time(state_of(env, vid)["opened_at"])
            self.now = (opened_at + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    c = Clock()
    real = model.utc_now
    monkeypatch.setattr(model, "utc_now", lambda: c.now or real())
    return c


def planned(env, **over):
    vid = opened(env, **over)
    assert plan(env, vid).ok
    return vid


# ---------- AC-002C-01a
def test_01a_open_budget_defaults_lower_and_refused_above(env):
    vid = opened(env)
    b = state_of(env, vid)["budget"]
    assert (b["total_seconds"], b["extra_attempts"], b["defaulted"]) == (3600, 3, True)
    vid2 = opened(env, budget={"minutes": 20, "extra_attempts": 1})
    assert state_of(env, vid2)["budget"]["total_seconds"] == 1200
    before = sorted(p.name for p in (env["project"] / GUARD).iterdir())
    from test_guard import open_run

    refused = open_run(env, budget={"minutes": 61})
    assert refused.problems[0].code == "BUDGET_INVALID" and "extend" in refused.next_steps[0]
    assert sorted(p.name for p in (env["project"] / GUARD).iterdir()) == before


# ---------- AC-002C-01b
def test_01b_show_open_run_states_budget_and_never_decreases(env, clock):
    vid = planned(env)
    clock.at(env, vid, 600)
    shown = guard.show(str(env["project"]), vid)
    assert shown.problems[0].code == "NOT_CONCLUDED"
    assert (
        shown.data["budget"]["consumed_seconds"] == 600 and shown.data["budget"]["remaining_seconds"] == 3000
    )
    clock.at(env, vid, 300)
    assert guard.show(str(env["project"]), vid).data["budget"]["consumed_seconds"] == 600
    result = attempt(env, vid)
    assert result.ok and result.data["budget"]["consumed_seconds"] == 600


# ---------- AC-002C-01c
def test_01c_records_need_a_registered_attempt_with_matching_coverage(env):
    vid = planned(env)
    refused = raw_record(env, vid, evidence=[ev()])
    assert refused.problems[0].code == "ATTEMPT_REQUIRED"
    a = attempt(env, vid)
    assert a.ok and a.data["attempt"] == aid(vid) and a.data["deadline_consumed"] == 3600
    other = raw_record(env, vid, attempt="a-9", evidence=[ev()])
    assert other.problems[0].code == "ATTEMPT_INVALID"
    outside = raw_record(env, vid, attempt=aid(vid), evidence=[ev(method="other-method")])
    assert outside.problems[0].code in ("ATTEMPT_INVALID", "RECORD_INVALID")
    assert state_of(env, vid)["evidence"] == []
    review_attempt = attempt(env, vid, "reviewer", {"na": [f"policy:{R2}"]})
    assert raw_record(env, vid, attempt=review_attempt.data["attempt"], evidence=[ev()]).problems[0].code == (
        "ATTEMPT_INVALID"
    )
    unregistered = review(env, vid, [na_confirmed()], attempt=None)
    assert unregistered.problems[0].code == "ATTEMPT_REQUIRED"
    assert review(env, vid, [na_confirmed()], attempt=review_attempt.data["attempt"]).ok


def test_01c_attempt_of_another_verification_refused(env):
    vid1, vid2 = planned(env), planned(env)
    assert attempt(env, vid1).ok
    assert attempt(env, vid2).ok
    state = state_of(env, vid2)
    assert [a["id"] for a in state["attempts"]] == [aid(vid2)]
    assert raw_record(env, vid2, attempt="a-2", evidence=[ev()]).problems[0].code == "ATTEMPT_INVALID"


# ---------- AC-002C-01d / 01e / 01f
def test_01d_01e_retries_cost_per_pair_and_attempts_are_single_use(env):
    vid = planned(env)
    assert attempt(env, vid).data["extra"] == 0
    ok = raw_record(env, vid, attempt=aid(vid), evidence=[ev()], usage={"requests": 2, "input_tokens": 10})
    assert ok.ok, ok.to_text()
    again = raw_record(env, vid, attempt=aid(vid), evidence=[ev("E2")])
    assert again.problems[0].code == "ATTEMPT_INVALID" and "finished" in again.problems[0].message
    retry = attempt(env, vid)
    assert retry.data["extra"] == 1 and retry.data["budget"]["extra_used"] == 1
    state = state_of(env, vid)
    assert state["attempts"][0]["status"] == "finished" and state["attempts"][0]["usage"]["requests"] == 2


def test_01d_method_added_later_costs_an_extra_attempt(env):
    vid = planned(env)
    change = {
        "check": "C1",
        "change": "supplement",
        "method": {"name": "manual-trace", "kind": "reading"},
        "reason": "second opinion",
    }
    assert raw_record(env, vid, method_changes=[change]).ok
    a = attempt(env, vid, covers={"pairs": [{"check": "C1", "method": "manual-trace"}]})
    assert a.data["extra"] == 1


def test_01e_cited_record_cannot_carry_method_changes_or_conflicts(env):
    vid = planned(env)
    attempt(env, vid)
    change = {
        "check": "C1",
        "change": "supplement",
        "method": {"name": "x", "kind": "reading"},
        "reason": "r",
    }
    refused = raw_record(env, vid, attempt=aid(vid), evidence=[ev()], method_changes=[change])
    assert refused.problems[0].code == "ATTEMPT_INVALID"


# ---------- AC-002C-02
def test_02a_02b_pause_blocks_work_and_freezes_time(env, clock):
    vid = planned(env)
    clock.at(env, vid, 100)
    paused = control.pause(str(env["project"]), vid, "asking the user which config is deployed")
    assert paused.ok and paused.data["budget"]["paused"] is True
    clock.at(env, vid, 900)
    assert attempt(env, vid).problems[0].code == "RUN_PAUSED"
    assert (
        raw_record(env, vid, ledger=[{"check": "C1", "state": "unconfirmed"}]).problems[0].code
        == "RUN_PAUSED"
    )
    assert guard.show(str(env["project"]), vid).data["budget"]["consumed_seconds"] == 100
    assert control.pause(str(env["project"]), vid, "again").problems[0].code == "ALREADY_PAUSED"
    clock.at(env, vid, 1000)
    resumed = control.resume(str(env["project"]), vid)
    assert resumed.ok and resumed.data["budget"]["consumed_seconds"] == 100
    pauses = state_of(env, vid)["budget"]["pauses"]
    assert len(pauses) == 1 and pauses[0]["reason"].startswith("asking") and pauses[0]["end"]
    assert control.resume(str(env["project"]), vid).problems[0].code == "NOT_PAUSED"


# ---------- AC-002C-03
def test_03a_time_exhaustion_refuses_new_attempts_but_keeps_started_work(env, clock):
    vid = planned(env)
    clock.at(env, vid, 10)
    assert attempt(env, vid).ok
    clock.at(env, vid, 3600)
    refused = attempt(env, vid)
    assert refused.problems[0].code == "BUDGET_TIME_EXHAUSTED" and "time" in refused.problems[0].message
    late = raw_record(env, vid, attempt=aid(vid), evidence=[ev()])
    assert late.ok, late.to_text()
    assert state_of(env, vid)["attempts"][0]["overrun_seconds"] == 0
    ledger_only = raw_record(env, vid, ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}])
    assert ledger_only.ok, ledger_only.to_text()
    change = {
        "check": "C1",
        "change": "supplement",
        "method": {"name": "x", "kind": "reading"},
        "reason": "r",
    }
    assert raw_record(env, vid, method_changes=[change]).problems[0].code == "BUDGET_TIME_EXHAUSTED"


def test_03a_overrun_recorded_for_late_result(env, clock):
    vid = planned(env)
    clock.at(env, vid, 10)
    attempt(env, vid)
    clock.at(env, vid, 3700)
    assert raw_record(env, vid, attempt=aid(vid), evidence=[ev()]).ok
    assert state_of(env, vid)["attempts"][0]["overrun_seconds"] == 100


def test_03b_attempts_exhausted_refuses_retries_only(env):
    vid = planned(env, budget={"extra_attempts": 0})
    assert attempt(env, vid).ok
    refused = attempt(env, vid)
    assert refused.problems[0].code == "ATTEMPTS_EXHAUSTED"


def test_03d_extend_needs_user_at_terminal(env):
    vid = planned(env)
    ok = control.extend(
        str(env["project"]),
        vid,
        30,
        2,
        "WebGoat needs a second pass",
        interaction=FakeInteraction(answers=[vid]),
    )
    assert ok.ok, ok.to_text()
    b = state_of(env, vid)["budget"]
    assert (b["total_seconds"], b["extra_attempts"]) == (5400, 5) and b["extensions"][0]["role"] == "user"


@pytest.mark.parametrize(
    "interaction, code",
    [
        (FakeInteraction(interactive=False), "INTERACTIVE_REQUIRED"),
        (FakeInteraction(answers=["wrong"]), "CONFIRMATION_MISMATCH"),
    ],
)
def test_03e_extend_refused_for_agents_or_mismatch(env, interaction, code):
    vid = planned(env)
    refused = control.extend(str(env["project"]), vid, 30, 0, "more", interaction=interaction)
    assert refused.problems[0].code == code
    assert state_of(env, vid)["budget"]["total_seconds"] == 3600


def test_03e_request_files_cannot_change_the_budget(env):
    vid = planned(env)
    refused = raw_record(env, vid, budget={"minutes": 999})
    assert refused.problems[0].code in ("RECORD_INVALID", "ATTEMPT_INVALID")
    assert state_of(env, vid)["budget"]["total_seconds"] == 3600


# ---------- AC-002C-06c legacy
def test_06c_legacy_run_gets_defaults_and_baseline(env):
    vid = planned(env)
    path = env["project"] / GUARD / vid / "state.json"
    legacy = json.loads(path.read_text())
    for key in ("budget", "attempts", "egress", "revision"):
        legacy.pop(key, None)
    legacy["evidence"] = [dict(ev(), stored=None, masked=False, masked_types=[], stored_bytes=0, lines=None)]
    path.write_text(json.dumps(legacy))
    a = attempt(env, vid)
    assert a.ok and a.data["extra"] == 1
    state = state_of(env, vid)
    assert state["budget"]["legacy"] is True and state["budget"]["defaulted"] is True
    assert state["egress"] == {"grants": [], "declarations": []}


def test_full_run_with_attempts_concludes(env):
    vid = planned(env)
    attempt(env, vid)
    parts = {
        "evidence": [ev()],
        "findings": [high_finding()],
        "ledger": [{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}],
    }
    assert raw_record(env, vid, attempt=aid(vid), **parts).ok
    a = attempt(env, vid, "reviewer", {"findings": ["F1"], "na": [f"policy:{R2}"]})
    subjects = [na_confirmed(), {"type": "finding", "id": "F1", "result": "confirmed", "basis": "x"}]
    assert review(env, vid, subjects, attempt=a.data["attempt"], usage={"requests": 1}).ok
    result = guard.conclude(str(env["project"]), vid)
    assert result.ok and result.data["verdict"] == "fail"
    assert result.data["budget"]["extra_used"] == 0
    assert R1


# ---------- AC-002C-03c / 06b report
def two_check_plan(env, vid):
    from test_guard import plan_doc

    doc = plan_doc()
    doc["checks"].append({**doc["checks"][0], "id": "C2"})
    return guard.record_plan(str(env["project"]), vid, req(env, doc))


def test_03c_exhausted_report_lists_only_unconfirmed_as_unverified(env, clock):
    vid = opened(env)
    assert two_check_plan(env, vid).ok
    clock.at(env, vid, 10)
    attempt(env, vid, covers={"pairs": [{"check": "C1", "method": "semantic-review"}]})
    parts = {
        "evidence": [ev()],
        "findings": [high_finding()],
        "ledger": [
            {"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]},
            {"check": "C2", "state": "unconfirmed", "reason": "not reached before the budget ran out"},
        ],
    }
    assert raw_record(env, vid, attempt=aid(vid), **parts).ok
    clock.at(env, vid, 4000)
    assert attempt(env, vid).problems[0].code == "BUDGET_TIME_EXHAUSTED"
    result = guard.conclude(str(env["project"]), vid)
    assert result.ok and result.data["verdict"] != "pass"
    data = json.loads((env["project"] / "x-ipe-docs/secure-code/reports/guard" / f"{vid}.json").read_text())
    assert data["budget"]["exhausted"] == "time"
    md = (env["project"] / "x-ipe-docs/secure-code/reports/guard" / f"{vid}.md").read_text()
    line = next(x for x in md.splitlines() if x.startswith("**Budget exhausted"))
    assert "(time)" in line and "C2" in line and "C1" not in line
    assert {r["check"]: r["state"] for r in data["ledger"]}["C1"] == "not_met"


def test_06b_report_budget_section_shows_extensions_pauses_attempts_usage(env, clock):
    vid = planned(env)
    clock.at(env, vid, 30)
    control.pause(str(env["project"]), vid, "asking about deployment")
    clock.at(env, vid, 90)
    control.resume(str(env["project"]), vid)
    control.extend(str(env["project"]), vid, 15, 1, "more time", interaction=FakeInteraction(answers=[vid]))
    attempt(env, vid)
    raw_record(env, vid, attempt=aid(vid), evidence=[ev()], usage={"requests": 3, "input_tokens": 900})
    attempt(env, vid, "reviewer", {"na": [f"policy:{R2}"]})
    guard.conclude(str(env["project"]), vid)
    md = (env["project"] / "x-ipe-docs/secure-code/reports/guard" / f"{vid}.md").read_text()
    section = md.split("## Budget", 1)[1].split("\n## ", 1)[0]
    assert "75.0 min" in section and "asking about deployment" in section and "more time" in section
    assert aid(vid) in section and aid(vid, 2) in section and "unfinished" in section
    assert "3 requests, 900 input" in section and "unknown for 1 attempt" in section


# ---------- closing review fixes (TASK-041)
def test_01c_attempt_id_of_another_verification_is_refused(env):
    vid_a, vid_b = planned(env), planned(env)
    foreign = attempt(env, vid_a).data["attempt"]
    attempt(env, vid_b)
    refused = raw_record(env, vid_b, attempt=foreign, evidence=[ev()])
    assert (
        refused.problems[0].code == "ATTEMPT_INVALID"
        and "another verification" in refused.problems[0].message
    )


def test_01b_every_run_bound_result_and_refusal_carries_the_budget(env):
    vid = planned(env, budget={"extra_attempts": 0})
    first = attempt(env, vid)
    refused = attempt(env, vid)
    assert first.data["budget"] and refused.problems[0].code == "ATTEMPTS_EXHAUSTED"
    assert refused.data["budget"]["extra_left"] == 0
    control.pause(str(env["project"]), vid, "waiting")
    paused = raw_record(env, vid, ledger=[{"check": "C1", "state": "unconfirmed", "reason": "x"}])
    assert paused.problems[0].code == "RUN_PAUSED" and paused.data["budget"]["paused"] is True


def test_04a_record_losing_to_cancel_leaves_no_evidence_file(env, monkeypatch):
    from x_ipe_secure_code.guard import runs

    vid = planned(env)
    a = attempt(env, vid).data["attempt"]
    real = runs.commit_state

    def cancel_first(root, state, *, expected_revision):
        runs.create_marker(
            root, vid, {"requested_at": "2026-10-20T10:00:00Z", "reason": None, "consumed_at_request": 1.0}
        )
        return real(root, state, expected_revision=expected_revision)

    monkeypatch.setattr(runs, "commit_state", cancel_first)
    out = raw_record(env, vid, attempt=a, evidence=[ev(content="raw excerpt")])
    assert out.problems[0].code == "RUN_CANCELLED"
    folder = env["project"] / GUARD / vid / "evidence"
    assert not folder.exists() or list(folder.iterdir()) == []


@posix_only
def test_04a_record_cleanup_never_follows_a_swapped_evidence_link(env, monkeypatch, tmp_path):
    """TASK-042: a lost record commit spares files behind a linked evidence folder; cancel still reported."""
    from x_ipe_secure_code.guard import runs

    vid = planned(env)
    a = attempt(env, vid).data["attempt"]
    real = runs.commit_state
    outside = tmp_path / "outside"
    names: list[str] = []

    def swap_then_cancel(root, state, *, expected_revision):
        folder = root / GUARD / vid / "evidence"
        names.extend(sorted(p.name for p in folder.iterdir()))
        folder.rename(outside)
        folder.symlink_to(outside, target_is_directory=True)
        runs.create_marker(
            root, vid, {"requested_at": "2026-10-20T10:00:00Z", "reason": None, "consumed_at_request": 1.0}
        )
        return real(root, state, expected_revision=expected_revision)

    monkeypatch.setattr(runs, "commit_state", swap_then_cancel)
    out = raw_record(env, vid, attempt=a, evidence=[ev(content="raw excerpt")])
    assert out.problems[0].code == "RUN_CANCELLED"
    assert names and sorted(p.name for p in outside.iterdir()) == names


def test_04f_conclude_already_publishing_wins_over_cancel(env, monkeypatch):
    from x_ipe_secure_code.guard import cancel, runs

    vid = planned(env)
    real = runs.create_result_exclusive

    def marker_then_publish(root, result):
        runs.create_marker(
            root, vid, {"requested_at": "2026-10-20T10:00:00Z", "reason": None, "consumed_at_request": 1.0}
        )
        return real(root, result)

    monkeypatch.setattr(runs, "create_result_exclusive", marker_then_publish)
    concluded = guard.conclude(str(env["project"]), vid)
    monkeypatch.setattr(runs, "create_result_exclusive", real)
    late = cancel.cancel(str(env["project"]), vid, "too late")
    assert concluded.ok and concluded.data.get("cancellation") is None
    assert late.problems[0].code == "RUN_FINISHED" and "before the cancellation" in late.problems[0].message
