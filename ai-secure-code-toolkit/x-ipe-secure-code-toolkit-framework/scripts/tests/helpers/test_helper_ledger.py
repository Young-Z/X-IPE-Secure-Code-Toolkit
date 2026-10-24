"""FEATURE-002-F ledger integration under the unchanged 002-A engine (AC-002F-03e, 03h, 05b, 07c, 07d;
DEC-3 variant B, spec v1.3.1 07c)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import copy
import json
import os

import pytest
from helperhelp import (  # noqa: F401 - fixture reuse
    METHOD,
    RULE,
    attempt,
    env,
    fake,
    flow,
    helper_check,
    helper_run,
    henv,
    mod,
    pair,
    raw_record,
    state_of,
)

from x_ipe_secure_code.guard import engine, report, targets
from x_ipe_secure_code.guard import service as guard

REPORTS = "x-ipe-docs/secure-code/reports/guard"


def result_of(env, vid):
    return json.loads((env["project"] / REPORTS / f"{vid}.json").read_text())


def helper_evidence(env, vid, hid):
    return [e for e in state_of(env, vid)["evidence"] if (e.get("helper") or {}).get("id") == hid]


def record_ledger(env, vid, state, evidence_ids, reason=None):
    entry = {"check": "C1", "state": state, "evidence": evidence_ids}
    if reason:
        entry["reason"] = reason
    out = raw_record(env, vid, ledger=[entry])
    assert out.ok, out.to_text()


def conclude(env, vid):
    out = guard.conclude(str(env["project"]), vid)
    assert out.ok, out.to_text()
    return result_of(env, vid)


def assert_engine_unchanged(env, vid, result):
    """The stored ledger equals what the unchanged 002-A engine computes from the recorded state."""
    state = state_of(env, vid)
    observed = {t["path"]: targets.observe(env["project"], t["path"]) for t in state["artifact"]["targets"]}
    policy_now = {a["rule"]: a["at_conclusion"] for a in result["scope"]["adopted"]}
    again = engine.conclude(state, observed, policy_now, result["ended_at"], None)
    assert again["ledger"] == result["ledger"]
    assert again["verdict"] == result["verdict"]


def row(result, check="C1"):
    return next(r for r in result["ledger"] if r["check"] == check)


# ---------- AC-002F-03e
def test_03e_rejected_failed_aux_equals_002a(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    assert flow.review(vid, hid, result="rejected").ok
    ev = helper_evidence(flow.env, vid, hid)
    assert ev and all(e["method_status"] == "failed" for e in ev)
    record_ledger(flow.env, vid, "met", [e["id"] for e in ev])
    result = conclude(flow.env, vid)
    assert row(result)["state"] == "unconfirmed"
    assert {"method": METHOD, "status": "failed"} in row(result)["substitution"]
    assert result["helpers"]["helpers"][0]["gap"] == "rejected by the Reviewer"
    assert_engine_unchanged(flow.env, vid, result)
    assert not flow.fake.creates("target")


# ---------- AC-002F-05b
@pytest.mark.parametrize(
    "reason", ["not_reviewed", "not_granted", "samples_mismatch", "failed", "check_failed"]
)
def test_05b_every_reason_failed_aux_equals_002a(flow, reason):
    vid = helper_run(flow.env)
    if reason == "check_failed":
        hid = flow.submit(
            vid, flow.request(vid, flow.generation(vid), script_file=flow.file("bad.py", "import os\n"))
        ).data["helper"]
    else:
        hid = flow.submit(vid).data["helper"]
    if reason not in ("not_reviewed", "check_failed"):
        assert flow.review(vid, hid).ok
    if reason in ("samples_mismatch", "failed"):
        assert flow.grant(vid).ok
        flow.fake.set(
            runs={"sample-1": {"mode": "none"}}
            if reason == "samples_mismatch"
            else {"target": {"mode": "none"}}
        )
        flow.run(vid, hid, flow.helper_attempt(vid))
    if reason == "not_granted":
        flow.run(vid, hid, flow.helper_attempt(vid))
    ev = helper_evidence(flow.env, vid, hid)
    assert ev and all(e["method_status"] == "failed" for e in ev)
    record_ledger(flow.env, vid, "met", [e["id"] for e in ev])
    result = conclude(flow.env, vid)
    assert row(result)["state"] == "unconfirmed"
    assert {"method": METHOD, "status": "failed"} in row(result)["substitution"]
    assert result["helpers"]["helpers"][0]["gap"]
    assert_engine_unchanged(flow.env, vid, result)


# ---------- AC-002F-03h
def test_03h_clean_needs_post_run_acceptance_extra(flow):
    vid, hid, out = flow.executed()
    assert out.data["outcome"] == "clean" and out.data["evidence"] is None
    assert [e["method_status"] for e in helper_evidence(flow.env, vid, hid)] == ["failed"]
    used = state_of(flow.env, vid)["budget"]["extra_used"]
    a = attempt(flow.env, vid, "reviewer", {"helpers": [hid]})
    assert a.data["extra"] == 1 and state_of(flow.env, vid)["budget"]["extra_used"] == used + 1
    record_ledger(flow.env, vid, "met", [helper_evidence(flow.env, vid, hid)[0]["id"]])
    result = conclude(flow.env, vid)
    assert row(result)["state"] == "unconfirmed"
    assert result["helpers"]["helpers"][0]["gap"] == "clean result not accepted"


def _partial(flow, *checks, other=None):
    vid = helper_run(flow.env, *checks)
    flow.fake.set(auto={**flow.fake.control["auto"], "skip_scanned": ["src/config/db.yaml"]})
    vid, hid = flow.ready(vid)
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    assert out.data["outcome"] == "clean" and out.data["uncovered_count"] == 1
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    return vid, hid


# ---------- AC-002F-07c
def test_07c_partial_alone_failed_and_unconfirmed(flow):
    vid, hid = _partial(flow)
    run = next(h for h in state_of(flow.env, vid)["helpers"] if h["id"] == hid)["runs"][0]
    assert run["acceptance"]["state"] == "accepted_partial"
    ev = helper_evidence(flow.env, vid, hid)
    assert [e["method_status"] for e in ev] == ["failed", "failed"]
    assert "src/config/db.yaml" in ev[-1]["summary"] and "never counts" in ev[-1]["summary"]
    record_ledger(flow.env, vid, "met", [e["id"] for e in ev])
    result = conclude(flow.env, vid)
    assert row(result)["state"] == "unconfirmed"
    assert {"method": METHOD, "status": "failed"} in row(result)["substitution"]
    assert_engine_unchanged(flow.env, vid, result)


def _two_methods():
    check = helper_check(
        methods=[
            {"name": "semantic-review", "kind": "reading", "required": False},
            {"name": METHOD, "kind": "runtime", "required": False},
        ],
        minimum_evidence=["reading"],
    )
    check["method_choice"]["considered"] = ["semantic-review", METHOD]
    check["method_choice"]["selected"] = ["semantic-review", METHOD]
    return check


def _reading_evidence(flow, vid, eid, paths):
    a = attempt(flow.env, vid, "semantic_review", pair("C1", "semantic-review")).data["attempt"]
    out = raw_record(
        flow.env,
        vid,
        attempt=a,
        evidence=[
            {
                "id": eid,
                "kind": "reading",
                "method": "semantic-review",
                "method_status": "ok",
                "checks": ["C1"],
                "paths": paths,
                "summary": "read the file",
            }
        ],
    )
    assert out.ok, out.to_text()


def test_07c_partial_plus_other_evidence_on_scanned_file_only(flow):
    vid, hid = _partial(flow, _two_methods())
    _reading_evidence(flow, vid, "E1", ["src/config/app.yaml"])
    record_ledger(flow.env, vid, "met", ["E1", *[e["id"] for e in helper_evidence(flow.env, vid, hid)]])
    result = conclude(flow.env, vid)
    assert row(result)["state"] == "met"
    assert_engine_unchanged(flow.env, vid, result)
    md = (flow.root / REPORTS / f"{vid}.md").read_text()
    assert "did not cover 1 file(s) of check C1: src/config/db.yaml" in md
    assert "Guard does not check per-file coverage" in md


def test_07c_partial_plus_evidence_covering_every_uncovered_file(flow):
    vid, hid = _partial(flow, _two_methods())
    _reading_evidence(flow, vid, "E1", ["src/config/db.yaml"])
    record_ledger(flow.env, vid, "met", ["E1", *[e["id"] for e in helper_evidence(flow.env, vid, hid)]])
    result = conclude(flow.env, vid)
    assert row(result)["state"] == "met"
    assert_engine_unchanged(flow.env, vid, result)


def test_07c_full_coverage_accepted_usable_runtime_evidence(flow):
    vid, hid, out = flow.executed()
    assert out.data["uncovered_count"] == 0
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    ok = [e for e in helper_evidence(flow.env, vid, hid) if e["method_status"] == "ok"]
    assert (
        len(ok) == 1
        and ok[0]["kind"] == "runtime"
        and set(ok[0]["paths"]) == {"src/config/app.yaml", "src/config/db.yaml"}
    )
    assert ok[0]["helper"]["acceptance"] == "accepted_full"
    record_ledger(flow.env, vid, "met", [ok[0]["id"]])
    result = conclude(flow.env, vid)
    assert row(result)["state"] == "met"
    assert result["helpers"]["helpers"][0]["gap"] is None
    assert_engine_unchanged(flow.env, vid, result)


def test_07c_object_too_large_never_counts(flow, monkeypatch):
    monkeypatch.setattr(mod("snapshot"), "OBJECT_FILES_MAX", 1)
    vid, hid, out = flow.executed()
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    run = next(h for h in state_of(flow.env, vid)["helpers"] if h["id"] == hid)["runs"][0]
    assert run["object_files"]["too_large"] is True and run["acceptance"]["state"] == "accepted_partial"
    assert all(e["method_status"] == "failed" for e in helper_evidence(flow.env, vid, hid))


def test_07c_unreadable_fifo_link_object_entries_only_partial(flow):
    """DAO-005 (2) repro: object entries the snapshot cannot copy are uncovered, never accepted_full."""
    cfg = flow.root / "src" / "config"
    (cfg / "locked.yaml").write_text("debug: true\n")
    os.chmod(cfg / "locked.yaml", 0)
    os.mkfifo(cfg / "c.fifo")
    os.symlink("app.yaml", cfg / "link.yaml")
    try:
        vid = helper_run(flow.env)
        out = flow.submit(vid, read_scope=["src/config/app.yaml", "src/config/db.yaml"])
        assert out.ok, out.to_text()
        hid = out.data["helper"]
        assert flow.review(vid, hid).ok and flow.grant(vid).ok
        run_out = flow.run(vid, hid, flow.helper_attempt(vid))
        assert run_out.data["outcome"] == "clean", run_out.to_text()
        uncovered = ["src/config/c.fifo", "src/config/link.yaml", "src/config/locked.yaml"]
        assert run_out.data["uncovered_count"] == 3
        assert flow.review(vid, hid, phase="post_run", run=1).ok
        run = next(h for h in state_of(flow.env, vid)["helpers"] if h["id"] == hid)["runs"][0]
        assert run["uncovered"] == uncovered and run["acceptance"]["state"] == "accepted_partial"
        ev = helper_evidence(flow.env, vid, hid)
        assert all(e["method_status"] == "failed" for e in ev)
        record_ledger(flow.env, vid, "met", [e["id"] for e in ev])
        result = conclude(flow.env, vid)
        assert row(result)["state"] == "unconfirmed"
        md = (flow.root / REPORTS / f"{vid}.md").read_text()
        assert f"did not cover 3 file(s) of check C1: {', '.join(uncovered)}" in md
        assert result["helpers"]["helpers"][0]["uncovered"] == uncovered
    finally:
        os.chmod(cfg / "locked.yaml", 0o600)


def test_07c_required_adapter_still_unconfirmed(flow):
    check = helper_check(
        methods=[
            {"name": "opengrep", "kind": "runtime", "required": True},
            {"name": METHOD, "kind": "runtime", "required": False},
        ]
    )
    check["method_choice"]["selected"] = ["opengrep", METHOD]
    vid = helper_run(flow.env, check)
    vid, hid = flow.ready(vid)
    assert flow.run(vid, hid, flow.helper_attempt(vid)).data["outcome"] == "clean"
    assert flow.review(vid, hid, phase="post_run", run=1).ok
    ok = [e["id"] for e in helper_evidence(flow.env, vid, hid) if e["method_status"] == "ok"]
    record_ledger(flow.env, vid, "met", ok)
    result = conclude(flow.env, vid)
    assert row(result)["state"] == "unconfirmed" and "required method opengrep" in row(result)["reason"]


# ---------- AC-002F-07d
def test_07d_helper_finding_needs_reviewer(flow):
    vid, hid = flow.ready()
    flow.fake.set(
        runs={
            "target": {
                "mode": "result",
                "result": {
                    "schema": "x-ipe-helper-result/1",
                    "helper": hid,
                    "status": "complete",
                    "scanned": ["src/config/app.yaml", "src/config/db.yaml"],
                    "findings": [
                        {
                            "path": "src/config/app.yaml",
                            "line": 2,
                            "rule": RULE,
                            "title": "debug on",
                            "excerpt": "debug: false",
                            "basis": "test",
                        }
                    ],
                    "notes": "",
                },
            }
        }
    )
    out = flow.run(vid, hid, flow.helper_attempt(vid))
    fid = out.data["findings"][0]
    record_ledger(flow.env, vid, "not_met", [out.data["evidence"]])
    unreviewed = copy.deepcopy(conclude(flow.env, vid))
    found = next(f for f in unreviewed["findings"] if f["id"] == fid)
    assert found["requires_review"] and found["review"] == "unconfirmed"
    assert unreviewed["verdict"] == "cannot_confirm_pass"
    assert any(r["code"] == "FINDING_UNCONFIRMED" and r["subject"] == fid for r in unreviewed["reasons"])
    vid2, hid2 = flow.ready()
    flow.fake.set(
        runs={
            "target": {
                "mode": "result",
                "result": {
                    "schema": "x-ipe-helper-result/1",
                    "helper": hid2,
                    "status": "complete",
                    "scanned": ["src/config/app.yaml"],
                    "findings": [
                        {
                            "path": "src/config/app.yaml",
                            "line": 2,
                            "rule": RULE,
                            "title": "debug on",
                            "excerpt": "debug: false",
                            "basis": "test",
                        }
                    ],
                    "notes": "",
                },
            }
        }
    )
    out2 = flow.run(vid2, hid2, flow.helper_attempt(vid2))
    fid2 = out2.data["findings"][0]
    a = attempt(flow.env, vid2, "reviewer", {"findings": [fid2]}).data["attempt"]
    from helperhelp import req, target_digest

    doc = {
        "schema": "ai-secure-code-toolkit/reviewer-record/v1",
        "attempt": a,
        "invocation": {"host": "h", "agent": "reviewer", "read_only": True},
        "requirement": "re-check",
        "reviewed_targets": [{"path": "src", "digest": target_digest(flow.env, vid2, "src")}],
        "subjects": [
            {
                "type": "finding",
                "id": fid2,
                "result": "confirmed",
                "basis": "debug is enabled",
                "severity_opinion": {"severity": "high"},
            }
        ],
    }
    assert guard.record_review(str(flow.root), vid2, req(flow.env, doc)).ok
    record_ledger(flow.env, vid2, "not_met", [out2.data["evidence"]])
    reviewed = conclude(flow.env, vid2)
    assert reviewed["verdict"] == "fail" and report.VERDICT_TEXT[reviewed["verdict"]] == "Fail"
