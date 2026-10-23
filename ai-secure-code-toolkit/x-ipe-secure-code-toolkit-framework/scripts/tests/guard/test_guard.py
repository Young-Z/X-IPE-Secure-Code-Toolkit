"""Integration tests for FEATURE-002-A Guard verification (service functions and CLI)."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from conftest import LAUNCHER, PASSPHRASE, SRC, FakeInteraction, posix_only, run_cli, tree_hashes

from x_ipe_secure_code.atomic import ProcessLock
from x_ipe_secure_code.auth.service import initialize_authorization
from x_ipe_secure_code.auth.trust_store import resolve as resolve_trust
from x_ipe_secure_code.guard import records
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.knowledge import service as knowledge
from x_ipe_secure_code.policy import service as policy
from x_ipe_secure_code.project_init import initialize_project

R1 = "CWE/4.14/CWE-79"
R2 = "CWE/4.14/CWE-89"
TOKEN = "ghp_" + "b" * 36
GUARD = ".x-ipe/private/secure-code/guard"
REPORTS = "x-ipe-docs/secure-code/reports/guard"


def _item(rule, body="Rule body.\n"):
    ns, ver, rid = rule.split("/")
    return {
        "namespace": ns,
        "version": ver,
        "rule_id": rid,
        "content": body,
        "source_location": "https://example.org/" + rid,
    }


@pytest.fixture
def env(project, tmp_path):
    assert initialize_project(str(project), "github-copilot").ok
    trust_dir = tmp_path / "trust-app"
    paths = resolve_trust(trust_dir)
    assert initialize_authorization(paths=paths, interaction=FakeInteraction(answers=[PASSPHRASE] * 2)).ok
    batch = tmp_path / "batch.json"
    batch.write_text(
        json.dumps({"schema": "ai-secure-code-toolkit/knowledge-batch/v1", "items": [_item(R1), _item(R2)]})
    )
    assert knowledge.import_batch(str(project), str(batch), [], [], trust_paths=paths).ok
    (project / "src").mkdir()
    (project / "src" / "login.py").write_text("def login(u):\n    return '<p>' + u\n")
    (project / "src" / "util.py").write_text("def helper():\n    return 1\n")
    (project / "README.md").write_text("# readme\n")
    (project / "cp.md").write_text("copilot said fine\n")
    return {
        "project": project,
        "paths": paths,
        "trust_dir": trust_dir,
        "tmp": tmp_path,
        "scope": save_scope(project, tmp_path, [R1, R2]),
    }


def change_rule(env, rule, body):
    upd = env["tmp"] / "upd.json"
    upd.write_text(json.dumps({"schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": body}))
    current = policy.resolve_policies(str(env["project"]), [rule], False, []).data["entries"][0]
    result = knowledge.update_rule(
        str(env["project"]),
        rule,
        current["source_evidence"]["state_digest"],
        str(upd),
        [],
        trust_paths=env["paths"],
    )
    assert result.ok, result.to_text()


def save_scope(project, tmp_path, adopt, mode="clues", name="decisions.json"):
    proposal = policy.resolve_policies(
        str(project), [] if mode == "apply_all" else list(adopt), mode == "apply_all", []
    )
    decisions = [
        {"ref": e["requested"], "decision": "adopted", "state_digest": e["source_evidence"]["state_digest"]}
        for e in proposal.data["entries"]
    ]
    doc = {
        "schema": "ai-secure-code-toolkit/scope-decisions/v1",
        "mode": mode,
        "proposal_digest": proposal.data["proposal_digest"],
        "clues": "login change",
        "language_context": ["python"],
        "decisions": decisions,
        "confirmation_note": "user confirmed",
    }
    if mode == "clues":
        doc["considered"] = list(adopt)
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    saved = policy.save_scope(str(project), str(path), True)
    assert saved.ok, saved.to_text()
    return saved.data["scope_id"]


_files = {"n": 0}


def req(env, doc):
    _files["n"] += 1
    path = env["tmp"] / f"req-{_files['n']}.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def open_run(env, **over):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-open/v1",
        "scope_id": env["scope"],
        "targets": [{"path": "src/login.py", "change": "modified"}],
        "context": [{"path": "README.md"}],
    }
    doc.update(over)
    return guard.open_verification(str(env["project"]), req(env, doc))


def opened(env, **over):
    result = open_run(env, **over)
    assert result.ok, result.to_text()
    return result.data["verification_id"]


def plan_doc(**over):
    doc = {
        "schema": "ai-secure-code-toolkit/guard-plan/v1",
        "checks": [
            {
                "id": "C1",
                "rule": R1,
                "object": ["src/login.py"],
                "methods": [{"name": "semantic-review", "kind": "reading", "required": True}],
                "minimum_evidence": ["reading"],
            }
        ],
        "not_applicable": [{"rule": R2, "reason": "no database access in the target"}],
    }
    doc.update(over)
    return doc


def plan(env, vid, **over):
    return guard.record_plan(str(env["project"]), vid, req(env, plan_doc(**over)))


ATTEMPT_SCHEMA = "ai-secure-code-toolkit/guard-attempt/v1"


def _covers(env, vid, doc):
    """Coverage of the attempt a well-formed record or Reviewer record needs (None when not needed)."""
    if "attempt" in doc:
        return None
    try:
        if "subjects" in doc:
            subjects = [s for s in doc.get("subjects") or [] if isinstance(s, dict)]
            findings = sorted({s["id"] for s in subjects if s.get("type") == "finding"})
            na = sorted({s["id"] for s in subjects if s.get("type") == "na_decision"})
            return ("reviewer", {"findings": findings, "na": na}) if findings or na else None
        if not (doc.get("evidence") or doc.get("findings")):
            return None
        state = json.loads((env["project"] / GUARD / vid / "state.json").read_text())
        checks = (state.get("plan") or {}).get("checks", [])
        methods = {c["id"]: [m["name"] for m in c["methods"]] for c in checks}
        pairs = {(c, e["method"]) for e in doc.get("evidence") or [] for c in e.get("checks") or []}
        for f in doc.get("findings") or []:
            c = f.get("check")
            if c in methods and not any(p[0] == c for p in pairs):
                pairs.add((c, methods[c][0]))
        if not pairs and methods:
            first = sorted(methods)[0]
            pairs.add((first, methods[first][0]))
        return ("semantic_review", {"pairs": [{"check": c, "method": m} for c, m in sorted(pairs)]})
    except (TypeError, KeyError, AttributeError, ValueError, OSError):
        return None


def with_attempt(env, vid, doc):
    """Register the attempt FEATURE-002-C requires before evidence, findings or a review is recorded.

    Retries beyond the default budget are extended as the user would (interactive terminal).
    """
    from x_ipe_secure_code.guard import control

    needed = _covers(env, vid, doc)
    if needed is None:
        return doc
    kind, covers = needed
    project = str(env["project"])
    doc_attempt = {"schema": ATTEMPT_SCHEMA, "kind": kind, "covers": covers}
    result = control.attempt(project, vid, req(env, doc_attempt))
    if not result.ok and result.problems[0].code == "ATTEMPTS_EXHAUSTED":
        control.extend(project, vid, 0, 10, "test retries", interaction=FakeInteraction(answers=[vid]))
        result = control.attempt(project, vid, req(env, doc_attempt))
    return {**doc, "attempt": result.data["attempt"]} if result.ok else doc


def record(env, vid, **parts):
    doc = with_attempt(env, vid, {"schema": "ai-secure-code-toolkit/guard-record/v1", **parts})
    return guard.record(str(env["project"]), vid, req(env, doc))


def ev(eid="E1", **over):
    e = {
        "id": eid,
        "kind": "reading",
        "method": "semantic-review",
        "method_status": "ok",
        "checks": ["C1"],
        "paths": ["src/login.py"],
        "summary": "read login()",
    }
    e.update(over)
    return e


def high_finding(fid="F1", **over):
    f = {
        "id": fid,
        "rule": R1,
        "check": "C1",
        "location": {"path": "src/login.py", "line": 2},
        "cwe": "CWE-79",
        "title": "Unescaped user input in HTML",
        "source": "semantic",
        "severity": "high",
        "evidence": ["E1"],
    }
    f.update(over)
    return f


def digest_of(env, rel):
    return "sha256:" + hashlib.sha256((env["project"] / rel).read_bytes()).hexdigest()


def review(env, vid, subjects, paths=("src/login.py",), **over):
    doc = {
        "schema": "ai-secure-code-toolkit/reviewer-record/v1",
        "invocation": {"host": "github-copilot", "agent": "guard-reviewer", "read_only": True},
        "requirement": "Re-check findings and N/A decisions",
        "reviewed_targets": [{"path": p, "digest": digest_of(env, p)} for p in paths],
        "subjects": subjects,
    }
    doc.update(over)
    return guard.record_review(str(env["project"]), vid, req(env, with_attempt(env, vid, doc)))


def na_confirmed():
    return {"type": "na_decision", "id": f"policy:{R2}", "result": "confirmed", "basis": "no SQL"}


def full_run(env, *, finding=True, confirm=True, **open_over):
    """Open → plan → record → review → conclude."""
    vid = opened(env, **open_over)
    assert plan(env, vid).ok
    parts = {
        "evidence": [ev()],
        "ledger": [
            {
                "check": "C1",
                "state": "not_met" if finding else "met",
                "evidence": ["E1"],
                "findings": ["F1"] if finding else [],
            }
        ],
    }
    if finding:
        parts["findings"] = [high_finding()]
    assert record(env, vid, **parts).ok
    subjects = [na_confirmed()]
    if finding and confirm:
        subjects.append({"type": "finding", "id": "F1", "result": "confirmed", "basis": "input reaches HTML"})
    assert review(env, vid, subjects).ok
    result = guard.conclude(str(env["project"]), vid)
    assert result.ok, result.to_text()
    return vid, result


def result_json(env, vid):
    return json.loads((env["project"] / REPORTS / f"{vid}.json").read_text())


def report_md(env, vid):
    return (env["project"] / REPORTS / f"{vid}.md").read_text()


def state_json(env, vid):
    return json.loads((env["project"] / GUARD / vid / "state.json").read_text())


# ---------- AC-002A-01


def test_01a_01b_report_and_result_share_one_conclusion(env):
    vid, result = full_run(env)
    data, md = result_json(env, vid), report_md(env, vid)
    assert result.data["verdict"] == data["verdict"] == "fail"
    assert "**Verdict: Fail**" in md and vid in md and env["scope"] in md
    for f in data["findings"]:
        assert f["id"] in md and f["final_severity"] in md
    for t in data["artifact"]["targets"]:
        assert t["path"] in md and t["digest_at_open"] in md
    for row in data["ledger"]:
        assert row["check"] in md
    assert data["evidence_retention"]["location"] in md and "30 days" in md
    assert "README.md" in md and "not verified" in md


def test_01c_01d_evidence_stored_masked_in_run_folder(env):
    vid = opened(env, request=f"verify {TOKEN}")
    assert plan(env, vid, checks=[{**plan_doc()["checks"][0], "object_part": f"part {TOKEN}"}]).ok
    assert record(
        env,
        vid,
        evidence=[ev(content=f"raw output {TOKEN}\n" + "x" * 5000)],
        ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}],
    ).ok
    assert guard.conclude(str(env["project"]), vid).ok
    stored = (env["project"] / GUARD / vid / "evidence" / "E1.txt").read_text()
    assert TOKEN not in stored and "[masked:credential.token]" in stored
    for text in (json.dumps(state_json(env, vid)), json.dumps(result_json(env, vid)), report_md(env, vid)):
        assert TOKEN not in text
    md = report_md(env, vid)
    assert "evidence/E1.txt" in md and "masked (credential.token)" in md and "x" * 200 not in md


def _age(env, vid, days):
    path = env["project"] / GUARD / vid / "state.json"
    state = json.loads(path.read_text())
    state["ended_at"] = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(json.dumps(state))
    result_path = env["project"] / REPORTS / f"{vid}.json"
    result = json.loads(result_path.read_text())
    result["ended_at"] = state["ended_at"]
    result_path.write_text(json.dumps(result))


def test_01e_01g_cleanup_removes_only_expired_finished_evidence(env):
    old, _ = full_run(env)
    recent, _ = full_run(env)
    running = opened(env)
    _age(env, old, 31)
    _age(env, recent, 29)
    assert guard.show(str(env["project"]), old).ok  # reading never extends retention
    result = guard.cleanup(str(env["project"]))
    assert result.ok
    assert [r["verification_id"] for r in result.data["removed"]] == [old]
    kept = {k["verification_id"]: k["reason"] for k in result.data["kept"]}
    assert "running" in kept[running] and "retained until" in kept[recent]
    assert not (env["project"] / GUARD / old).exists() and (env["project"] / GUARD / running).is_dir()
    for vid in (old, recent):
        assert (env["project"] / REPORTS / f"{vid}.json").is_file()
        assert (env["project"] / REPORTS / f"{vid}.md").is_file()
    shown = guard.show(str(env["project"]), old)
    assert shown.ok and shown.data["evidence_available"] is False and shown.data["verdict"] == "fail"
    assert "no longer available" in shown.data["evidence"]
    assert "**Verdict: Fail**" in report_md(env, old)


def test_01f_keep_marker_and_release(env):
    vid, _ = full_run(env)
    _age(env, vid, 40)
    kept = guard.keep(str(env["project"]), vid, "pending release review")
    assert kept.ok
    first = guard.cleanup(str(env["project"]))
    assert first.data["removed"] == []
    assert first.data["kept"] == [{"verification_id": vid, "reason": "keep marker: pending release review"}]
    assert guard.release(str(env["project"]), vid).data["released"] is True
    assert [r["verification_id"] for r in guard.cleanup(str(env["project"])).data["removed"]] == [vid]


def test_01h_older_report_flagged_when_targets_change(env):
    first, _ = full_run(env)
    (env["project"] / "src" / "login.py").write_text("def login(u):\n    return escape(u)\n")
    second, _ = full_run(env)
    assert first != second
    older = guard.show(str(env["project"]), first)
    assert older.data["targets_now"] == "changed" and older.data["changed_targets"] == ["src/login.py"]
    assert any("does not describe the current version" in s for s in older.next_steps)
    assert guard.show(str(env["project"]), second).data["targets_now"] == "unchanged"


# ---------- AC-002A-02


def test_02a_02b_independent_and_copilot_report_is_context_only(env):
    vid = opened(env, copilot_reports=[{"path": "cp.md"}])
    assert plan(env, vid).ok
    assert record(
        env, vid, evidence=[ev(paths=["cp.md"])], ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}]
    ).ok
    assert review(env, vid, [na_confirmed()]).ok
    result = guard.conclude(str(env["project"]), vid)
    assert result.data["verdict"] == "cannot_confirm_pass"
    data = result_json(env, vid)
    assert data["ledger"][0]["state"] == "unconfirmed"
    assert data["artifact"]["copilot_reports"][0]["path"] == "cp.md"
    assert "never evidence of a pass" in report_md(env, vid)


def test_02c_apply_all_never_widens_targets(env):
    scope = save_scope(env["project"], env["tmp"], [], mode="apply_all", name="all.json")
    result = open_run(env, scope_id=scope, targets=[{"path": "src/login.py"}, {"path": "src/util.py"}])
    assert [t["path"] for t in result.data["targets"]] == ["src/login.py", "src/util.py"]
    refused = open_run(env, targets=[{"path": "."}])
    assert refused.problems[0].code == "WHOLE_PROJECT_NOT_EXPLICIT" and refused.next_steps
    whole = open_run(env, targets=[], whole_project=True, context=[])
    assert whole.ok and [t["path"] for t in whole.data["targets"]] == ["."]


def test_02d_roles_kept_separate(env):
    refused = open_run(env, context=[{"path": "src/login.py"}])
    assert refused.problems[0].code == "ROLE_CONFLICT"
    vid = opened(env, suggested=[{"path": "src/util.py", "reason": "called by login"}])
    state = state_json(env, vid)
    assert state["artifact"]["suggested"] == [{"path": "src/util.py", "reason": "called by login"}]
    assert [c["path"] for c in state["artifact"]["context"]] == ["README.md"]


def test_02e_added_deleted_renamed(env):
    (env["project"] / "src" / "new.py").write_text("x = 1\n")
    vid = opened(
        env,
        targets=[
            {"path": "src/new.py", "change": "added"},
            {"path": "src/old.py", "change": "deleted"},
            {"path": "src/util.py", "change": "renamed", "old_path": "src/helpers.py"},
        ],
    )
    t = {x["path"]: x for x in state_json(env, vid)["artifact"]["targets"]}
    assert t["src/new.py"]["change"] == "added" and t["src/new.py"]["digest"]
    assert t["src/old.py"]["digest"] is None and t["src/old.py"]["change"] == "deleted"
    assert t["src/util.py"]["old_path"] == "src/helpers.py"


def test_02f_invalid_target_refused_with_next_step(env):
    for path in ("missing.py", "../outside.py"):
        result = open_run(env, targets=[{"path": path}])
        assert not result.ok and result.problems[0].code == "TARGET_INVALID" and result.next_steps
    assert not (env["project"] / GUARD).exists() or not any((env["project"] / GUARD).iterdir())


# ---------- AC-002A-03


def test_03a_no_scope_or_unusable_scope_is_maintenance_needed(env):
    result = open_run(env, scope_id="")
    assert result.problems[0].code == "MAINTENANCE_NEEDED" and "Framework" in result.next_steps[0]
    scope = save_scope(env["project"], env["tmp"], [R1], name="one.json")
    change_rule(env, R1, "Changed body.\n")
    result = open_run(env, scope_id=scope)
    assert result.problems[0].code == "MAINTENANCE_NEEDED"
    assert "verdict" not in result.data and "100%" not in result.to_text()
    assert not (env["project"] / REPORTS).exists() or not any((env["project"] / REPORTS).iterdir())
    assert not (env["project"] / GUARD).exists() or not any((env["project"] / GUARD).iterdir())


def test_03b_partial_scope_refused_with_lists(env):
    change_rule(env, R2, "Changed.\n")
    result = open_run(env)
    assert result.problems[0].code == "SCOPE_PARTIAL"
    assert result.data["adopted"] == [R1] and result.data["needs_reconfirmation"] == [R2]
    assert result.data["missing"] == [] and "scope save" in result.next_steps[0]


def test_03c_03d_scope_recorded_and_plan_limited_to_adopted(env):
    vid = opened(env)
    scope = state_json(env, vid)["scope"]
    assert scope["scope_id"] == env["scope"] and [a["rule"] for a in scope["adopted"]] == [R1, R2]
    assert all(a["state_digest"].startswith("sha256:") for a in scope["adopted"])
    bad = plan(env, vid, checks=[{**plan_doc()["checks"][0], "rule": "CWE/4.14/CWE-22"}])
    assert bad.problems[0].code == "PLAN_INVALID" and "adopted scope" in bad.problems[0].message
    vid2, _ = full_run(env)
    assert [a["rule"] for a in result_json(env, vid2)["scope"]["adopted"]] == [R1, R2]


# ---------- AC-002A-04, 05


def test_04e_na_for_missing_method_refused(env):
    vid = opened(env)
    assert plan(env, vid).ok
    result = record(
        env, vid, ledger=[{"check": "C1", "state": "n/a", "reason_type": "not_executed", "reason": "no time"}]
    )
    assert result.problems[0].code == "NA_NOT_OBJECTIVE" and "unconfirmed" in result.next_steps[0]
    assert state_json(env, vid)["ledger"] == {}


def test_05e_05f_incomplete_and_stale_reviews(env):
    vid = opened(env)
    assert plan(env, vid).ok
    assert record(
        env,
        vid,
        evidence=[ev()],
        findings=[high_finding()],
        ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}],
    ).ok
    incomplete = review(env, vid, [{"type": "finding", "id": "F1", "result": "confirmed"}], requirement="")
    assert incomplete.ok and incomplete.data["completeness"] == ["requirement is missing"]
    assert review(env, vid, [{"type": "finding", "id": "F1", "result": "confirmed"}, na_confirmed()]).ok
    (env["project"] / "src" / "login.py").write_text("changed after review\n")
    result = guard.conclude(str(env["project"]), vid)
    data = result_json(env, vid)
    assert [r["valid"] for r in data["reviews"]] == [False, False]
    assert "requirement is missing" in data["reviews"][0]["invalid_reasons"]
    assert any("stale" in r for r in data["reviews"][1]["invalid_reasons"])
    assert data["findings"][0]["review"] == "unconfirmed" and result.data["verdict"] == "cannot_confirm_pass"
    assert "TARGET_CHANGED" in [r["code"] for r in result.data["reasons"]]


def test_05g_reviewer_without_extra_authority(env):
    vid = opened(env)
    assert plan(env, vid).ok
    result = review(env, vid, [], risk_acceptances=[{"finding": "F1"}], targets=["src/util.py"])
    assert result.problems[0].code == "REVIEW_AUTHORITY"
    assert state_json(env, vid)["reviews"] == []


def test_review_disagreement_and_bound_false_positive(env):
    vid = opened(env)
    assert plan(env, vid).ok
    assert record(
        env,
        vid,
        evidence=[ev(), ev("E2", paths=["README.md"])],
        findings=[high_finding()],
        ledger=[{"check": "C1", "state": "not_met", "evidence": ["E1"], "findings": ["F1"]}],
    ).ok
    unbound = review(
        env, vid, [{"type": "finding", "id": "F1", "result": "false_positive", "evidence": ["E2"]}]
    )
    assert unbound.problems[0].code == "REVIEW_INVALID"
    assert review(env, vid, [{"type": "finding", "id": "F1", "result": "confirmed"}, na_confirmed()]).ok
    assert review(
        env, vid, [{"type": "finding", "id": "F1", "result": "false_positive", "evidence": ["E1"]}]
    ).ok
    result = guard.conclude(str(env["project"]), vid)
    assert result.data["verdict"] == "cannot_confirm_pass"
    assert "REVIEW_DISAGREEMENT" in [r["code"] for r in result.data["reasons"]]


# ---------- AC-002A-06


def test_06_pass_and_cannot_confirm_paths(env):
    _, passed = full_run(env, finding=False)
    assert passed.data["verdict"] == "pass"
    _, unreviewed = full_run(env, confirm=False)
    assert unreviewed.data["verdict"] == "cannot_confirm_pass"
    assert "FINDING_UNCONFIRMED" in [r["code"] for r in unreviewed.data["reasons"]]


def test_06h_conclude_twice_identical_and_repairs_report(env):
    vid, first = full_run(env)
    json_bytes = (env["project"] / REPORTS / f"{vid}.json").read_bytes()
    md = report_md(env, vid)
    again = guard.conclude(str(env["project"]), vid)
    assert again.to_dict() == first.to_dict()
    assert (env["project"] / REPORTS / f"{vid}.json").read_bytes() == json_bytes
    (env["project"] / REPORTS / f"{vid}.md").unlink()
    assert not guard.show(str(env["project"]), vid).data["report_consistent"]
    assert guard.conclude(str(env["project"]), vid).ok and report_md(env, vid) == md


def test_06j_policy_changed_after_open(env):
    vid = opened(env)
    assert plan(env, vid).ok
    assert record(env, vid, evidence=[ev()], ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}]).ok
    assert review(env, vid, [na_confirmed()]).ok
    change_rule(env, R1, "Changed after open.\n")
    result = guard.conclude(str(env["project"]), vid)
    assert result.data["verdict"] == "cannot_confirm_pass"
    assert [r for r in result.data["reasons"] if r["code"] == "POLICY_CHANGED"][0]["subject"] == R1


# ---------- AC-002A-07


def test_07a_07b_risk_acceptance_recorded_separately(env):
    vid, before = full_run(env)
    fake = FakeInteraction(answers=["F1"])
    result = guard.accept_risk(
        str(env["project"]), vid, "F1", "Accepted until the Q3 rewrite", interaction=fake
    )
    assert result.ok, result.to_text()
    data = result_json(env, vid)
    assert data["verdict"] == "fail" and data["findings"][0]["final_severity"] == "high"
    assert data["risk_acceptances"][0]["role"] == "user" and data["risk_acceptances"][0]["finding"] == "F1"
    assert "Accepted until the Q3 rewrite" in report_md(env, vid)
    assert guard.show(str(env["project"]), vid).data["report_consistent"] is True
    other, _ = full_run(env)
    assert result_json(env, other)["risk_acceptances"] == []


def test_07d_refusals_record_nothing(env):
    vid, _ = full_run(env)
    before = (env["project"] / REPORTS / f"{vid}.json").read_bytes()
    agent = guard.accept_risk(
        str(env["project"]), vid, "F1", "r", interaction=FakeInteraction(interactive=False)
    )
    assert agent.problems[0].code == "INTERACTIVE_REQUIRED"
    wrong = guard.accept_risk(
        str(env["project"]), vid, "F1", "r", interaction=FakeInteraction(answers=["F2"])
    )
    assert wrong.problems[0].code == "CONFIRMATION_MISMATCH"
    missing = guard.accept_risk(
        str(env["project"]), vid, "F9", "r", interaction=FakeInteraction(answers=["F9"])
    )
    assert missing.problems[0].code == "FINDING_NOT_FOUND"
    cli = run_cli(
        [
            "guard",
            "accept-risk",
            "--project",
            str(env["project"]),
            "--run",
            vid,
            "--finding",
            "F1",
            "--reason",
            "r",
            "--json",
        ],
        env["trust_dir"],
        input_text="F1\n",
    )
    assert cli.returncode == 1 and json.loads(cli.stdout)["problems"][0]["code"] == "INTERACTIVE_REQUIRED"
    assert (env["project"] / REPORTS / f"{vid}.json").read_bytes() == before
    passed, _ = full_run(env, finding=False)
    not_fail = guard.accept_risk(
        str(env["project"]), passed, "F1", "r", interaction=FakeInteraction(answers=["F1"])
    )
    assert not_fail.problems[0].code == "NOT_ACCEPTABLE"


# ---------- AC-002A-08 and command safety


def test_08a_only_run_folder_and_reports_written(env):
    project = env["project"]
    allowed = (
        str(project / GUARD),
        str(project / REPORTS),
        str(project / ".x-ipe/private/secure-code/locks"),
        str(project / ".x-ipe/private/secure-code/tmp"),
    )
    before = {k: v for k, v in tree_hashes(project).items() if not k.startswith(allowed)}
    full_run(env)
    after = {k: v for k, v in tree_hashes(project).items() if not k.startswith(allowed)}
    assert after == before


def test_lifecycle_refusals(env):
    project = str(env["project"])
    assert guard.conclude(project, "gv-bad").problems[0].code == "RUN_NOT_FOUND"
    assert guard.show(project, "../../etc").problems[0].code == "RUN_NOT_FOUND"
    vid = opened(env)
    assert record(env, vid, evidence=[ev()]).problems[0].code == "PLAN_REQUIRED"
    assert plan(env, vid).ok and plan(env, vid).problems[0].code == "PLAN_EXISTS"
    assert guard.show(project, vid).problems[0].code == "NOT_CONCLUDED"
    assert guard.conclude(project, vid).ok
    assert record(env, vid, evidence=[ev()]).problems[0].code == "RUN_FINISHED"


def test_result_is_commit_point_after_crash(env):
    vid, _ = full_run(env)
    path = env["project"] / GUARD / vid / "state.json"
    state = json.loads(path.read_text())
    state["status"], state["ended_at"] = "open", None
    path.write_text(json.dumps(state))
    assert record(env, vid, evidence=[ev("E9")]).problems[0].code == "RUN_FINISHED"
    assert guard.conclude(str(env["project"]), vid).ok
    assert state_json(env, vid)["status"] == "finished" and state_json(env, vid)["ended_at"]


def test_evidence_quota_across_records(env, monkeypatch):
    monkeypatch.setattr(records, "MAX_EVIDENCE_TOTAL", 100)
    vid = opened(env)
    assert plan(env, vid).ok
    assert record(env, vid, evidence=[ev(content="a" * 60)]).ok
    over = record(env, vid, evidence=[ev("E2", content="b" * 60)])
    assert over.problems[0].code == "EVIDENCE_QUOTA"


def test_locked_guard_lock(env):
    vid = opened(env)
    lock = env["project"] / ".x-ipe/private/secure-code/locks/guard.lock"
    code = (
        f"import sys; sys.path.insert(0, {str(SRC)!r})\n"
        "from x_ipe_secure_code.guard import service as g\n"
        "g.LOCK_TIMEOUT = 0.2\n"
        f"print(g.conclude({str(env['project'])!r}, {vid!r}).problems[0].code)\n"
    )
    with ProcessLock(lock, create=True):
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "LOCKED", out.stderr


def test_cli_round_trip(env):
    tdir = env["trust_dir"]
    project = str(env["project"])
    open_file = req(
        env,
        {
            "schema": "ai-secure-code-toolkit/guard-open/v1",
            "scope_id": env["scope"],
            "targets": [{"path": "src/login.py"}],
        },
    )
    out = run_cli(["guard", "open", "--project", project, "--request", open_file, "--json"], tdir)
    assert out.returncode == 0, out.stdout
    vid = json.loads(out.stdout)["data"]["verification_id"]
    for cmd, doc in (
        ("plan", plan_doc()),
        (
            "attempt",
            {
                "schema": ATTEMPT_SCHEMA,
                "kind": "semantic_review",
                "covers": {"pairs": [{"check": "C1", "method": "semantic-review"}]},
            },
        ),
        (
            "record",
            {
                "schema": "ai-secure-code-toolkit/guard-record/v1",
                "attempt": f"a-1-{vid[-8:]}",
                "evidence": [ev()],
                "ledger": [{"check": "C1", "state": "met", "evidence": ["E1"]}],
            },
        ),
    ):
        out = run_cli(
            ["guard", cmd, "--project", project, "--run", vid, "--request", req(env, doc), "--json"], tdir
        )
        assert out.returncode == 0, out.stdout
    out = run_cli(["guard", "conclude", "--project", project, "--run", vid], tdir)
    assert out.returncode == 0 and "Cannot confirm pass" in out.stdout
    out = run_cli(["guard", "show", "--project", project, "--run", "nope", "--json"], tdir)
    assert out.returncode == 1 and json.loads(out.stdout)["next_steps"]
    for cmd in (["keep", "--reason", "release"], ["release"]):
        assert run_cli(["guard", cmd[0], "--project", project, "--run", vid, *cmd[1:]], tdir).returncode == 0
    assert run_cli(["guard", "cleanup", "--project", project, "--json"], tdir).returncode == 0


@posix_only
def test_07a_accept_risk_through_a_real_terminal(env):
    import os
    import pty
    import select
    import time

    vid, _ = full_run(env)
    cmd = [
        sys.executable,
        str(LAUNCHER),
        "--test-trust-dir",
        str(env["trust_dir"]),
        "guard",
        "accept-risk",
        "--project",
        str(env["project"]),
        "--run",
        vid,
        "--finding",
        "F1",
        "--reason",
        "accepted for Q3",
    ]
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.execv(cmd[0], cmd)
    output, sent, deadline = b"", False, time.time() + 60
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
        if not sent and b"to confirm:" in output:
            os.write(fd, b"F1\n")
            sent = True
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors="replace")
    assert result_json(env, vid)["risk_acceptances"][0]["reason"] == "accepted for Q3"
    assert result_json(env, vid)["verdict"] == "fail"


# ---------- code review regressions (TASK-023)


@pytest.mark.parametrize(
    ("command", "doc"),
    [
        ("plan", {"exclusions": [{"check": ["C1"], "reason": "x"}]}),
        ("record", {"evidence": [ev(checks=[["C1"]])]}),
        ("record", {"findings": [high_finding(rule=["x"])]}),
        ("record", {"findings": [high_finding(check={"a": 1})]}),
        ("record", {"ledger": [{"check": ["C1"], "state": "met"}]}),
        ("review", {"subjects": [{"type": "finding", "id": ["F1"], "result": "confirmed"}]}),
        ("review", {"subjects": [{"type": "na_decision", "id": {"x": 1}, "result": "confirmed"}]}),
    ],
)
def test_malformed_shapes_are_refused_not_crashing(env, command, doc):
    vid = opened(env)
    if command != "plan":
        assert plan(env, vid).ok
    schema = {"plan": "guard-plan", "record": "guard-record", "review": "reviewer-record"}[command]
    full = {
        "schema": f"ai-secure-code-toolkit/{schema}/v1",
        **(plan_doc() if command == "plan" else {}),
        **doc,
    }
    out = run_cli(
        [
            "guard",
            command,
            "--project",
            str(env["project"]),
            "--run",
            vid,
            "--request",
            req(env, full),
            "--json",
        ],
        env["trust_dir"],
    )
    assert out.returncode == 1 and "Traceback" not in out.stderr, out.stderr
    assert json.loads(out.stdout)["problems"][0]["code"].endswith("_INVALID")


def test_non_utf8_paths_refused_and_no_run_folder_left(env):
    result = open_run(env, targets=[{"path": "src/gone\ud800.py", "change": "deleted"}])
    assert not result.ok and result.problems[0].code == "REQUEST_INVALID"
    renamed = open_run(env, targets=[{"path": "src/util.py", "change": "renamed", "old_path": "a\ud800"}])
    assert renamed.problems[0].code == "REQUEST_INVALID"
    assert not (env["project"] / GUARD).exists() or not any((env["project"] / GUARD).iterdir())
    vid = opened(env)
    assert plan(env, vid).ok
    bad = guard.record_review(
        str(env["project"]),
        vid,
        req(
            env,
            {
                "schema": "ai-secure-code-toolkit/reviewer-record/v1",
                "reviewed_targets": [{"path": "x\ud800", "digest": "sha256:" + "0" * 64}],
            },
        ),
    )
    assert bad.problems[0].code == "REVIEW_INVALID"


def test_evidence_ids_unique_ignoring_case(env):
    vid = opened(env)
    assert plan(env, vid).ok
    assert record(env, vid, evidence=[ev("E9", content="AAAA original")]).ok
    second = record(env, vid, evidence=[ev("e9", content="BBBB other")])
    assert second.problems[0].code == "RECORD_INVALID" and "duplicate" in second.problems[0].message
    assert (env["project"] / GUARD / vid / "evidence" / "E9.txt").read_text() == "AAAA original"


def test_credential_shaped_identifiers_refused(env):
    vid = opened(env)
    assert plan(env, vid).ok
    for finding in (
        high_finding(source="ghp_" + "Z" * 36),
        high_finding(cwe="AKIAZZZZZZZZZZZZZZZZ"),
        high_finding(fid="sk-" + "a" * 24),
    ):
        result = record(env, vid, evidence=[ev()], findings=[finding])
        assert result.problems[0].code == "RECORD_INVALID" and "credential" in result.problems[0].message
    assert "ghp_" not in (env["project"] / GUARD / vid / "state.json").read_text()


def test_skill_names_open_as_the_digest_source():
    from conftest import TOOLKIT_ROOT

    guard_dir = TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-guard"
    for path in (guard_dir / "SKILL.md", guard_dir / "references" / "guard-records.md"):
        text = path.read_text(encoding="utf-8")
        assert "`guard show`" not in text and "from `guard open`" in text


# ---------- closing review regressions (Bug Fix TASK-026)


def test_whole_project_never_counts_toolkit_data_as_target(env):
    copilot = env["project"] / "x-ipe-docs/secure-code/reports/copilot"
    copilot.mkdir(parents=True, exist_ok=True)
    (copilot / "c-1.md").write_text("Copilot: all fine\n")
    scratch = env["project"] / ".x-ipe/private/secure-code/tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "notes.txt").write_text("agent notes\n")
    vid = opened(env, targets=[], whole_project=True, context=[])
    assert plan(env, vid, checks=[{**plan_doc()["checks"][0], "object": ["."]}]).ok
    for path in ("x-ipe-docs/secure-code/reports/copilot/c-1.md", ".x-ipe/private/secure-code/tmp/notes.txt"):
        result = record(
            env,
            vid,
            evidence=[ev(paths=[path])],
            ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}],
        )
        assert result.problems and result.problems[0].code == "RECORD_INVALID", path
        located = record(env, vid, evidence=[ev()], findings=[high_finding(location={"path": path})])
        assert located.problems and located.problems[0].code == "RECORD_INVALID", path
    bad_plan_vid = opened(env, targets=[], whole_project=True, context=[])
    refused = plan(
        env,
        bad_plan_vid,
        checks=[{**plan_doc()["checks"][0], "object": ["x-ipe-docs/secure-code/reports/copilot/c-1.md"]}],
    )
    assert refused.problems and refused.problems[0].code == "PLAN_INVALID"


def test_listed_copilot_report_under_toolkit_folder_stays_context(env):
    copilot = env["project"] / "x-ipe-docs/secure-code/reports/copilot"
    copilot.mkdir(parents=True, exist_ok=True)
    (copilot / "c-1.md").write_text("Copilot: all fine\n")
    vid = opened(
        env,
        targets=[],
        whole_project=True,
        context=[],
        copilot_reports=[{"path": "x-ipe-docs/secure-code/reports/copilot/c-1.md"}],
    )
    assert plan(env, vid, checks=[{**plan_doc()["checks"][0], "object": ["."]}]).ok
    assert record(
        env,
        vid,
        evidence=[ev(paths=["x-ipe-docs/secure-code/reports/copilot/c-1.md"])],
        ledger=[{"check": "C1", "state": "met", "evidence": ["E1"]}],
    ).ok
    assert guard.conclude(str(env["project"]), vid).data["verdict"] == "cannot_confirm_pass"


def test_request_paths_in_docs_and_hints_stay_private():
    from conftest import TOOLKIT_ROOT

    readme = (TOOLKIT_ROOT / "README.md").read_text(encoding="utf-8")
    paths = re.findall(r"--request (\S+)", readme)
    assert paths and all(p.startswith(".x-ipe/private/secure-code/tmp/") for p in paths), paths
    service_text = (SRC / "x_ipe_secure_code" / "guard" / "service.py").read_text(encoding="utf-8")
    hints = re.findall(r"--request (\S+)", service_text)
    assert hints and all(h.startswith(".x-ipe/private/secure-code/tmp/") for h in hints), hints


def test_deeply_nested_request_refused(env):
    path = env["tmp"] / "deep.json"
    path.write_text(
        '{"schema": "ai-secure-code-toolkit/guard-open/v1", "targets": ' + "[" * 200000 + "]" * 200000 + "}"
    )
    out = run_cli(
        ["guard", "open", "--project", str(env["project"]), "--request", str(path), "--json"],
        env["trust_dir"],
    )
    assert out.returncode == 1 and "Traceback" not in out.stderr, out.stderr[-500:]
    assert json.loads(out.stdout)["problems"][0]["code"] == "REQUEST_INVALID"
