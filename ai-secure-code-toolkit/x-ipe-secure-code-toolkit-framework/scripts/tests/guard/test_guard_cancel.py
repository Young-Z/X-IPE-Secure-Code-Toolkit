"""Integration tests for FEATURE-002-C cancellation (AC-002C-04a…04f)."""

from __future__ import annotations

import json
import os
import threading
import time

from conftest import posix_only
from test_guard import (  # noqa: F401 - fixture reuse
    GUARD,
    REPORTS,
    env,
    ev,
    full_run,
    high_finding,
    na_confirmed,
    opened,
    plan,
    record,
    review,
)
from test_guard_tool import check, fake, invocations, set_mode, tc, tool  # noqa: F401
from test_guard_tool import planned as tool_planned

from x_ipe_secure_code.atomic import ProcessLock
from x_ipe_secure_code.guard import cancel, control, runs
from x_ipe_secure_code.guard import service as guard


def cancel_run(env, vid, reason="user stopped"):
    return cancel.cancel(str(env["project"]), vid, reason)


def result_json(env, vid):
    return json.loads((env["project"] / REPORTS / f"{vid}.json").read_text())


def state_json(env, vid):
    return json.loads((env["project"] / GUARD / vid / "state.json").read_text())


def wait_for(path, timeout=15):
    end = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > end:
            raise AssertionError(f"{path} did not appear")
        time.sleep(0.05)


# ---------- AC-002C-04a / 04e / 04f
def test_04a_cancel_ends_run_and_refuses_later_changes(env):
    vid = opened(env)
    assert plan(env, vid).ok
    out = cancel_run(env, vid)
    assert out.ok, out.to_text()
    assert out.data["cancellation"]["tool_termination"] == {"tool": "none"}
    assert out.data["verdict"] == "cannot_confirm_pass"
    result = result_json(env, vid)
    assert result["cancellation"]["reason"] == "user stopped" and result["verdict"] != "pass"
    assert any(r["code"] == "CANCELLED" for r in result["reasons"] + result["other_blockers"])
    assert state_json(env, vid)["status"] == "cancelled"
    refused = record(env, vid, ledger=[{"check": "C1", "state": "unconfirmed"}])
    assert refused.problems[0].code == "RUN_CANCELLED"
    assert control.pause(str(env["project"]), vid, "x").problems[0].code == "RUN_CANCELLED"
    md = (env["project"] / REPORTS / f"{vid}.md").read_text()
    assert "## Cancellation" in md


def test_04e_cancel_keeps_confirmed_fail_and_lists_unfinished_agent_attempts(env):
    vid = opened(env)
    assert plan(env, vid).ok
    parts = {
        "evidence": [ev()],
        "findings": [high_finding()],
        "ledger": [{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}],
    }
    assert record(env, vid, **parts).ok
    subjects = [na_confirmed(), {"type": "finding", "id": "F1", "result": "confirmed", "basis": "x"}]
    assert review(env, vid, subjects).ok
    pending = control.attempt(
        str(env["project"]),
        vid,
        _attempt_req(env, {"pairs": [{"check": "C1", "method": "semantic-review"}]}),
    )
    assert pending.ok
    out = cancel_run(env, vid)
    assert out.data["verdict"] == "fail"
    c = result_json(env, vid)["cancellation"]
    assert c["agent_attempts"] == [pending.data["attempt"]] and "not confirmed" in c["agent_note"]
    assert "billed" in c["remote_note"]
    assert [a["status"] for a in result_json(env, vid)["attempts"]][-1] == "cancelled"
    assert (
        guard.accept_risk(str(env["project"]), vid, "F1", "accept", interaction=_terminal(["F1"]))
        .problems[0]
        .code
        == "NOT_ACCEPTABLE"
    )


def test_04f_cancel_idempotent_finished_refused_and_report_repaired(env):
    vid = opened(env)
    assert plan(env, vid).ok
    first = cancel_run(env, vid)
    again = cancel_run(env, vid, "second")
    assert again.ok and again.data["cancellation"] == first.data["cancellation"]
    md = env["project"] / REPORTS / f"{vid}.md"
    before = result_json(env, vid)
    md.unlink()
    assert guard.conclude(str(env["project"]), vid).ok and md.exists()
    assert result_json(env, vid) == before
    done, _ = full_run(env, finding=False)
    assert cancel_run(env, done).problems[0].code == "RUN_FINISHED"


def test_04d_two_concurrent_cancels_one_result(env):
    vid = opened(env)
    assert plan(env, vid).ok
    outs = []
    threads = [threading.Thread(target=lambda: outs.append(cancel_run(env, vid))) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert all(o.ok for o in outs) and outs[0].data["cancellation"] == outs[1].data["cancellation"]


def test_04a_cancel_while_paused_closes_pause_at_request(env):
    vid = opened(env)
    assert plan(env, vid).ok
    assert control.pause(str(env["project"]), vid, "waiting").ok
    assert cancel_run(env, vid).ok
    pauses = result_json(env, vid)["budget"]["pauses"]
    assert pauses[0]["end"] == result_json(env, vid)["cancellation"]["requested_at"]


def test_04a_finalization_pending_while_a_commit_is_in_progress(env, monkeypatch):
    vid = opened(env)
    assert plan(env, vid).ok
    monkeypatch.setattr(runs, "BARRIER_TIMEOUT", 0.3)
    with ProcessLock(runs.commit_lock(env["project"], vid), timeout=1):
        out = cancel_run(env, vid)
    assert out.ok and out.data["finalization"] == "pending"
    assert runs.read_result(env["project"], vid) is None
    refused = record(env, vid, ledger=[{"check": "C1", "state": "unconfirmed"}])
    assert refused.problems[0].code == "RUN_CANCELLED"
    concluded = guard.conclude(str(env["project"]), vid)
    assert concluded.ok and result_json(env, vid)["cancellation"]


# ---------- AC-002C-04b / 04c / 04d with a running tool
@posix_only
def test_04b_cancel_stops_running_tool_and_confirms(env, fake):
    set_mode(fake, "sleep")
    vid = tool_planned(env, [check()])
    outcome = {}
    runner = threading.Thread(target=lambda: outcome.setdefault("r", tool(env, vid, [tc()])))
    runner.start()
    wait_for(env["project"] / GUARD / vid / "tool-active.json")
    while not invocations(fake):
        time.sleep(0.05)
    out = cancel_run(env, vid)
    runner.join(30)
    assert out.ok and out.data["cancellation"]["tool_termination"]["tool"] == "confirmed"
    assert outcome["r"].problems[0].code == "RUN_CANCELLED"
    result = result_json(env, vid)
    assert result["adapter_runs"] == [] and [a["status"] for a in result["attempts"]] == ["cancelled"]
    assert not list((env["project"] / GUARD / vid / "adapter").glob("stage-*"))
    assert not (env["project"] / GUARD / vid / "tool-active.json").exists()


@posix_only
def test_04c_unacknowledged_tool_owner_reported_not_confirmed(env, monkeypatch):
    vid = opened(env)
    assert plan(env, vid).ok
    monkeypatch.setattr(cancel, "CANCEL_WAIT", 0.5)
    runs.write_run_json(env["project"], vid, "tool-active.json", {"pid": 424242, "attempt": "a-9", "at": "t"})
    out = cancel_run(env, vid)
    term = out.data["cancellation"]["tool_termination"]
    assert term["tool"] == "not_confirmed" and term["pid"] == 424242
    assert "## Cancellation" in (env["project"] / REPORTS / f"{vid}.md").read_text()


@posix_only
def test_04d_tool_finishing_after_cancel_records_nothing(env, fake, monkeypatch):
    from x_ipe_secure_code.guard import toolrun

    vid = tool_planned(env, [check()])
    real = toolrun._record

    def record_then_cancel(root, rvid, state, req, out):
        runs.create_marker(
            root, rvid, {"requested_at": "2026-10-20T10:00:00Z", "reason": None, "consumed_at_request": 1.0}
        )
        return real(root, rvid, state, req, out)

    monkeypatch.setattr(toolrun, "_record", record_then_cancel)
    result = tool(env, vid, [tc()])
    assert result.problems[0].code == "RUN_CANCELLED"
    assert state_json(env, vid).get("adapter_runs", []) == []
    ack = runs.read_run_json(env["project"], vid, "cancel-ack.json")
    assert ack["confirmed"] is True and "finished" in ack["detail"]
    evidence_dir = env["project"] / GUARD / vid / "evidence"
    assert not evidence_dir.exists() or list(evidence_dir.iterdir()) == []  # TASK-041: no orphan output


@posix_only
def test_04d_lost_commit_cleanup_never_follows_a_swapped_evidence_link(env, fake, monkeypatch, tmp_path):
    """TASK-042: cleanup after a lost commit must not delete files through a symlinked evidence folder."""
    from x_ipe_secure_code.guard import toolrun

    vid = tool_planned(env, [check()])
    real = toolrun._record
    outside = tmp_path / "outside"
    names: list[str] = []

    def record_swap_then_cancel(root, rvid, state, req, out):
        recorded = real(root, rvid, state, req, out)
        evidence = root / GUARD / rvid / "evidence"
        names.extend(sorted(p.name for p in evidence.iterdir()))
        evidence.rename(outside)  # a surviving process swaps the folder for a link
        evidence.symlink_to(outside, target_is_directory=True)
        runs.create_marker(
            root, rvid, {"requested_at": "2026-10-20T10:00:00Z", "reason": None, "consumed_at_request": 1.0}
        )
        return recorded

    monkeypatch.setattr(toolrun, "_record", record_swap_then_cancel)
    result = tool(env, vid, [tc()])
    assert result.problems[0].code == "RUN_CANCELLED"
    assert names and sorted(p.name for p in outside.iterdir()) == names


@posix_only
def test_remove_evidence_files_refuses_a_linked_folder(env, tmp_path):
    vid = opened(env)
    root = env["project"]
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x-1-output.json").write_text("keep")
    (root / GUARD / vid / "evidence").symlink_to(outside, target_is_directory=True)
    assert runs.remove_evidence_files(root, vid, ["x-1-output.json"]) is False
    assert (outside / "x-1-output.json").read_text() == "keep"


def test_remove_evidence_files_removes_named_files_only(env):
    vid = opened(env)
    root = env["project"]
    folder = root / GUARD / vid / "evidence"
    folder.mkdir(exist_ok=True)
    for name in ("a-1-output.json", "a-1-manifest.json", "a-10-output.json"):
        (folder / name).write_text("x")
    assert runs.remove_evidence_files(root, vid, ["a-1-output.json", "a-1-manifest.json", "gone.json"])
    assert sorted(p.name for p in folder.iterdir()) == ["a-10-output.json"]


@posix_only
def test_04a_other_verification_with_running_tool_unaffected(env, fake):
    fake["config"].write_text(json.dumps({"mode": "nap", "nap": 3}))
    busy = tool_planned(env, [check()])
    idle = opened(env)
    assert plan(env, idle).ok
    outcome = {}
    runner = threading.Thread(target=lambda: outcome.setdefault("r", tool(env, busy, [tc()])))
    runner.start()
    wait_for(env["project"] / GUARD / busy / "tool-active.json")
    start = time.monotonic()
    out = cancel_run(env, idle)
    assert out.ok and time.monotonic() - start < 2.5
    runner.join(30)
    assert outcome["r"].ok and outcome["r"].data["status"] == "completed"
    assert runs.read_result(env["project"], busy) is None and not runs.cancel_marker(env["project"], busy)


def test_cli_cancel(env):
    from conftest import run_cli

    vid = opened(env)
    argv = ["guard", "cancel", "--project", str(env["project"]), "--run", vid, "--json"]
    out = run_cli(argv, env["trust_dir"])
    assert out.returncode == 0 and json.loads(out.stdout)["data"]["cancellation"]


# ---------- helpers
def _attempt_req(env, covers, kind="semantic_review"):
    from test_guard import req

    return req(env, {"schema": "ai-secure-code-toolkit/guard-attempt/v1", "kind": kind, "covers": covers})


def _terminal(answers):
    from conftest import FakeInteraction

    return FakeInteraction(answers=list(answers))


assert os


# ---------- code review fixes (TASK-037)
@posix_only
def test_04b_confirmed_only_if_every_started_group_was_seen_exiting(env, fake, monkeypatch):
    import dataclasses

    from x_ipe_secure_code.adapters import process
    from x_ipe_secure_code.guard import toolrun

    check_two = check()
    vid = tool_planned(env, [check_two])
    real = process.run
    calls = []

    def run(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            out = real(*args, **kwargs)
            runs.create_marker(
                env["project"],
                vid,
                {"requested_at": "2026-10-20T10:00:00Z", "reason": None, "consumed_at_request": 1.0},
            )
            return dataclasses.replace(out, group_gone=False)
        return real(*args, **kwargs)

    monkeypatch.setattr(toolrun.process, "run", run)
    result = tool(env, vid, [tc(rules=("x-ipe-docs/rules/py.yaml", "x-ipe-docs/rules/py2.yaml"))])
    assert result.problems[0].code == "RUN_CANCELLED"
    ack = runs.read_run_json(env["project"], vid, "cancel-ack.json")
    assert ack["confirmed"] is False


@posix_only
def test_04c_dead_owner_reported_at_once(env, monkeypatch):
    import subprocess

    vid = opened(env)
    assert plan(env, vid).ok
    dead = subprocess.Popen(["true"])
    dead.wait()
    runs.write_run_json(
        env["project"], vid, "tool-active.json", {"pid": dead.pid, "attempt": "a-9", "at": "t"}
    )
    start = time.monotonic()
    out = cancel_run(env, vid)
    term = out.data["cancellation"]["tool_termination"]
    assert time.monotonic() - start < 10
    assert term["tool"] == "not_confirmed" and term["pid"] == dead.pid and "exited" in term["detail"]


@posix_only
def test_04d_late_cancel_reports_unconfirmed_when_a_group_survived(env, fake, monkeypatch):
    import dataclasses

    from x_ipe_secure_code.adapters import process
    from x_ipe_secure_code.guard import toolrun

    vid = tool_planned(env, [check()])
    real_run, real_record = process.run, toolrun._record
    monkeypatch.setattr(
        toolrun.process, "run", lambda *a, **k: dataclasses.replace(real_run(*a, **k), group_gone=False)
    )

    def record_then_cancel(root, rvid, state, req, out):
        runs.create_marker(
            root, rvid, {"requested_at": "2026-10-20T10:00:00Z", "reason": None, "consumed_at_request": 1.0}
        )
        return real_record(root, rvid, state, req, out)

    monkeypatch.setattr(toolrun, "_record", record_then_cancel)
    result = tool(env, vid, [tc()])
    assert result.problems[0].code == "RUN_CANCELLED"
    assert runs.read_run_json(env["project"], vid, "cancel-ack.json")["confirmed"] is False


def test_04b_report_wording_names_the_process_group_and_its_limit(env):
    vid = opened(env)
    assert plan(env, vid).ok
    runs.write_run_json(env["project"], vid, "cancel-ack.json", {"pid": 1, "confirmed": True, "detail": "x"})
    runs.write_run_json(
        env["project"], vid, "tool-active.json", {"pid": os.getpid(), "attempt": "a", "at": "t"}
    )
    assert cancel_run(env, vid).ok
    md = (env["project"] / REPORTS / f"{vid}.md").read_text()
    assert "process group was seen exiting" in md and "left the group are not tracked" in md
