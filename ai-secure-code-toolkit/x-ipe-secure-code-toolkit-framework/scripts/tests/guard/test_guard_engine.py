"""Unit tests for the deterministic Guard conclusion engine (FEATURE-002-A AC-002A-04*, 05*, 06*)."""

from __future__ import annotations

import copy
import json

import pytest

from x_ipe_secure_code.guard import engine

R1 = "CWE/4.14/CWE-79"
R2 = "CWE/4.14/CWE-89"
D0 = "sha256:" + "0" * 64
D9 = "sha256:" + "9" * 64
ENDED = "2026-10-19T01:00:00Z"


def check(cid="C1", rule=R1, obj=("src/a.py",), methods=None, minimum=("reading",)):
    return {
        "id": cid,
        "rule": rule,
        "object": list(obj),
        "object_part": None,
        "description": None,
        "methods": methods or [{"name": "semantic-review", "kind": "reading", "required": True}],
        "minimum_evidence": list(minimum),
    }


def ev(eid="E1", kind="reading", method="semantic-review", status="ok", checks=("C1",), paths=("src/a.py",)):
    return {
        "id": eid,
        "kind": kind,
        "method": method,
        "method_status": status,
        "checks": list(checks),
        "paths": list(paths),
        "lines": None,
        "summary": "s",
        "stored": None,
        "stored_bytes": 0,
        "masked": False,
        "masked_types": [],
    }


def led(state="met", evidence=("E1",), findings=(), reason=None, reason_type=None):
    return {
        "state": state,
        "evidence": list(evidence),
        "findings": list(findings),
        "reason": reason,
        "reason_type": reason_type,
        "superseded": 0,
    }


def finding(fid="F1", severity="high", disputed=False, path="src/a.py", source="semantic", merged_into=None):
    return {
        "id": fid,
        "rule": R1,
        "check": "C1",
        "location": {"path": path, "line": 3},
        "cwe": "CWE-79",
        "title": "t",
        "description": None,
        "source": source,
        "severity": severity,
        "evidence": ["E1"],
        "disputed": disputed,
        "related": [],
        "merged_from": [],
        "merge_evidence": [],
        "merged_into": merged_into,
    }


def subject(sid="F1", result="confirmed", kind="finding", opinion=None, evidence=(), basis="checked"):
    return {
        "type": kind,
        "id": sid,
        "result": result,
        "basis": basis,
        "evidence": list(evidence),
        "severity_opinion": opinion,
    }


def review(*subjects, digest=D0, paths=("src/a.py",), completeness=()):
    return {
        "invocation": {"host": "h", "agent": "a", "read_only": True, "invoked_at": None, "declared": True},
        "requirement": "re-check",
        "reviewed_targets": [{"path": p, "digest": digest} for p in paths],
        "subjects": list(subjects),
        "reviewed_at": None,
        "completeness": list(completeness),
    }


def state(**over):
    s = {
        "schema": "ai-secure-code-toolkit/guard-run/v1",
        "verification_id": "gv-20261019T000000Z-00000000",
        "status": "open",
        "opened_at": "2026-10-19T00:00:00Z",
        "ended_at": None,
        "request": None,
        "baseline": None,
        "scope": {
            "scope_id": "sha256:" + "a" * 64,
            "mode": "clues",
            "adopted": [{"rule": R1, "state_digest": D9}],
        },
        "artifact": {
            "whole_project": False,
            "targets": [
                {
                    "path": "src/a.py",
                    "kind": "file",
                    "change": "modified",
                    "old_path": None,
                    "digest": D0,
                    "incomplete": False,
                    "not_followed": [],
                    "unreadable": [],
                }
            ],
            "context": [{"path": "README.md", "kind": "file", "digest": D9}],
            "suggested": [],
            "copilot_reports": [{"path": "cp.md", "kind": "file", "digest": D9}],
        },
        "plan": {"checks": [check()], "not_applicable": [], "exclusions": []},
        "evidence": [ev()],
        "findings": [],
        "ledger": {"C1": led()},
        "conflicts": [],
        "reviews": [],
    }
    s.update(over)
    return s


def run(s, observed=None, policy=None):
    if observed is None:
        observed = {
            t["path"]: {"digest": t["digest"], "incomplete": False, "not_followed": [], "unreadable": []}
            for t in s["artifact"]["targets"]
        }
    if policy is None:
        policy = {a["rule"]: "unchanged" for a in s["scope"]["adopted"]}
    return engine.conclude(s, observed, policy, ENDED)


def codes(result, key="reasons"):
    return [r["code"] for r in result[key]]


def row(result, cid="C1"):
    return next(r for r in result["ledger"] if r["check"] == cid)


def fnd(result, fid="F1"):
    return next(f for f in result["findings"] if f["id"] == fid)


# AC-002A-06b
def test_pass_when_every_check_met_and_only_low_findings():
    result = run(state(findings=[finding(severity="low"), finding("F2", severity="info")]))
    assert result["verdict"] == "pass" and codes(result) == ["ALL_CHECKS_SATISFIED"]
    assert fnd(result)["review"] == "not_required" and fnd(result)["final_severity"] == "low"


# AC-002A-06a, 06g
def test_confirmed_medium_or_higher_fails_whatever_the_ledger():
    for sev in ("medium", "high", "critical"):
        s = state(findings=[finding(severity=sev)], ledger={}, reviews=[review(subject())])
        result = run(s)
        assert result["verdict"] == "fail" and codes(result) == ["CONFIRMED_FINDING"]
        assert "CHECK_UNCONFIRMED" in codes(result, "other_blockers")


# AC-002A-06c
def test_confirmed_unknown_severity_is_not_low():
    result = run(state(findings=[finding(severity="unknown")], reviews=[review(subject())]))
    assert result["verdict"] == "cannot_confirm_pass" and codes(result) == ["SEVERITY_UNKNOWN"]
    s = state(
        findings=[finding(severity="unknown"), finding("F2", severity="high")],
        reviews=[review(subject(), subject("F2"))],
    )
    assert run(s)["verdict"] == "fail"


# AC-002A-06d, 04g
def test_zero_findings_with_unconfirmed_check_cannot_pass():
    result = run(state(ledger={}))
    assert result["verdict"] == "cannot_confirm_pass" and codes(result) == ["CHECK_UNCONFIRMED"]
    assert row(result)["state"] == "unconfirmed" and row(result)["recorded_state"] is None
    assert "not executed" in row(result)["reason"]


# AC-002A-06e
@pytest.mark.parametrize(
    ("original", "opinion", "evidenced", "final", "conflict"),
    [
        ("high", "low", False, "high", True),
        ("high", "low", True, "low", True),
        ("low", "high", False, "high", True),
        ("medium", "medium", False, "medium", False),
        ("unknown", "high", False, "high", True),
        ("unknown", "low", False, "unknown", True),
        ("unknown", "low", True, "low", True),
    ],
)
def test_severity_resolution(original, opinion, evidenced, final, conflict):
    op = {"severity": opinion, "evidence": ["E1"] if evidenced else []}
    result = run(state(findings=[finding(severity=original)], reviews=[review(subject(opinion=op))]))
    f = fnd(result)
    assert (f["final_severity"], f["severity_conflict"]) == (final, conflict)
    assert f["original_severity"] == original and f["severity_opinion"]["severity"] == opinion


# AC-002A-06f
def test_unresolved_verdict_affecting_conflict_blocks_pass():
    conflict = {
        "id": "K1",
        "kind": "requirement",
        "description": "d",
        "verdict_affecting": True,
        "resolved": False,
        "resolution": None,
        "evidence": [],
    }
    result = run(state(conflicts=[conflict]))
    assert result["verdict"] == "cannot_confirm_pass" and codes(result) == ["CONFLICT_UNRESOLVED"]
    resolved = dict(conflict, resolved=True, resolution="r", evidence=["E1"])
    assert run(state(conflicts=[resolved]))["verdict"] == "pass"
    assert run(state(conflicts=[dict(conflict, verdict_affecting=False)]))["verdict"] == "pass"


# AC-002A-06h
def test_conclusion_is_deterministic():
    s = state(findings=[finding()], reviews=[review(subject())])
    first, second = run(copy.deepcopy(s)), run(copy.deepcopy(s))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# AC-002A-06i, 04f
def test_scope_exclusion_prevents_pass_and_fail_still_wins():
    plan = {
        "checks": [check(), check("C2")],
        "not_applicable": [],
        "exclusions": [{"rule": None, "check": "C2", "reason": "user: later"}],
    }
    result = run(state(plan=plan))
    assert result["verdict"] == "cannot_confirm_pass" and codes(result) == ["SCOPE_EXCLUSION"]
    assert row(result, "C2")["state"] == "excluded"
    failing = run(state(plan=plan, findings=[finding()], reviews=[review(subject())]))
    assert failing["verdict"] == "fail" and "SCOPE_EXCLUSION" in codes(failing, "other_blockers")


def test_rule_level_exclusion_row():
    s = state(
        scope={
            "scope_id": "sha256:" + "a" * 64,
            "mode": "clues",
            "adopted": [{"rule": R1, "state_digest": D9}, {"rule": R2, "state_digest": D9}],
        },
        plan={
            "checks": [check()],
            "not_applicable": [],
            "exclusions": [{"rule": R2, "check": None, "reason": "user"}],
        },
    )
    result = run(s)
    assert result["verdict"] == "cannot_confirm_pass" and row(result, f"rule:{R2}")["state"] == "excluded"


# AC-002A-06j
def test_changed_targets_and_policies_block_pass():
    changed = run(
        state(),
        observed={"src/a.py": {"digest": D9, "incomplete": False, "not_followed": [], "unreadable": []}},
    )
    assert changed["verdict"] == "cannot_confirm_pass" and codes(changed) == ["TARGET_CHANGED"]
    assert changed["artifact"]["targets"][0]["changed"] is True
    policy = run(state(), policy={R1: "changed"})
    assert codes(policy) == ["POLICY_CHANGED"] and policy["scope"]["adopted"][0]["at_conclusion"] == "changed"
    assert codes(run(state(), policy={}))[0] == "POLICY_CHANGED"


# AC-002A-06k
def test_false_positive_and_info_never_fail_and_stay_reported():
    s = state(
        findings=[finding(), finding("F2", severity="info")],
        reviews=[review(subject(result="false_positive", evidence=["E1"]), subject("F2"))],
    )
    result = run(s)
    assert result["verdict"] == "pass"
    assert fnd(result)["review"] == "false_positive" and fnd(result)["evidence"] == ["E1"]
    assert fnd(result, "F2")["review"] == "confirmed"


# AC-002A-04c
def test_no_percentage_or_score_anywhere():
    text = json.dumps(run(state())).lower()
    assert "percent" not in text and "score" not in text and "%" not in text


# AC-002A-04d
def test_runtime_minimum_not_met_by_reading():
    s = state(plan={"checks": [check(minimum=("runtime",))], "not_applicable": [], "exclusions": []})
    result = run(s)
    assert row(result)["state"] == "unconfirmed" and row(result)["recorded_state"] == "met"
    assert "runtime" in row(result)["reason"]


# AC-002A-04j
def test_auxiliary_failure_substituted_but_required_failure_not():
    methods = [
        {"name": "semantic-review", "kind": "reading", "required": True},
        {"name": "opengrep", "kind": "runtime", "required": False},
    ]
    s = state(
        plan={
            "checks": [check(methods=methods, minimum=("reading", "runtime"))],
            "not_applicable": [],
            "exclusions": [],
        },
        evidence=[ev(), ev("E2", kind="runtime", method="opengrep", status="failed")],
        ledger={"C1": led(evidence=("E1", "E2"))},
    )
    result = run(s)
    assert row(result)["state"] == "met" and row(result)["substitution"] == [
        {"method": "opengrep", "status": "failed"}
    ]
    required = [dict(m, required=True) for m in methods]
    s["plan"]["checks"][0]["methods"] = required
    result = run(s)
    assert row(result)["state"] == "unconfirmed" and "opengrep" in row(result)["reason"]


# AC-002A-04h
def test_na_needs_a_valid_confirming_review():
    s = state(ledger={"C1": led("n/a", (), reason="no output", reason_type="objective")})
    assert row(run(s))["state"] == "unconfirmed" and run(s)["verdict"] == "cannot_confirm_pass"
    s["reviews"] = [review(subject("C1", kind="na_decision"))]
    assert row(run(s))["state"] == "n/a" and run(s)["verdict"] == "pass"
    s["reviews"] = [review(subject("C1", kind="na_decision", result="rejected"))]
    assert "rejected" in row(run(s))["reason"]


def test_policy_level_na_and_all_na_plan_can_pass():
    plan = {"checks": [], "not_applicable": [{"rule": R1, "reason": "no web output"}], "exclusions": []}
    s = state(plan=plan, ledger={}, evidence=[])
    result = run(s)
    assert (
        row(result, f"policy:{R1}")["state"] == "unconfirmed" and result["verdict"] == "cannot_confirm_pass"
    )
    s["reviews"] = [review(subject(f"policy:{R1}", kind="na_decision"))]
    assert run(s)["verdict"] == "pass"


# AC-002A-04i
def test_evidence_kinds_kept_separate():
    methods = [
        {"name": "semantic-review", "kind": "reading", "required": True},
        {"name": "design-doc", "kind": "document", "required": False},
    ]
    s = state(
        plan={"checks": [check(methods=methods)], "not_applicable": [], "exclusions": []},
        evidence=[ev(), ev("E2", kind="document", method="design-doc")],
        ledger={"C1": led(evidence=("E1", "E2"))},
    )
    assert row(run(s))["evidence_by_kind"] == {"document": ["E2"], "reading": ["E1"]}


# AC-002A-02b, 02d
def test_context_and_copilot_evidence_never_meet_a_check():
    for path in ("README.md", "cp.md"):
        s = state(evidence=[ev(paths=(path,))])
        assert row(run(s))["state"] == "unconfirmed"


# AC-002A-05b
def test_verdict_affecting_or_disputed_findings_need_review():
    result = run(state(findings=[finding()]))
    assert result["verdict"] == "cannot_confirm_pass" and codes(result) == ["FINDING_UNCONFIRMED"]
    assert fnd(result)["review"] == "unconfirmed" and fnd(result)["requires_review"]
    disputed = run(state(findings=[finding(severity="low", disputed=True)]))
    assert codes(disputed) == ["FINDING_UNCONFIRMED"]


# AC-002A-05c, 05d
def test_review_keeps_original_conclusion_and_unconfirmed_is_not_removed():
    result = run(
        state(
            findings=[finding(source="opengrep")],
            reviews=[review(subject(result="unconfirmed", basis="cannot reproduce"))],
        )
    )
    f = fnd(result)
    assert (
        f["review"] == "unconfirmed"
        and f["source"] == "opengrep"
        and f["review_basis"] == ["cannot reproduce"]
    )
    assert result["verdict"] == "cannot_confirm_pass"


# AC-002A-05e
def test_incomplete_review_is_invalid_with_reasons():
    result = run(
        state(findings=[finding()], reviews=[review(subject(), completeness=["requirement is missing"])])
    )
    assert result["reviews"][0]["valid"] is False
    assert result["reviews"][0]["invalid_reasons"] == ["requirement is missing"]
    assert fnd(result)["review"] == "unconfirmed"


# AC-002A-05f
def test_stale_and_unbound_reviews_are_invalid():
    stale = run(state(findings=[finding()], reviews=[review(subject(), digest=D9)]))
    assert stale["reviews"][0]["valid"] is False and "stale" in stale["reviews"][0]["invalid_reasons"][0]
    assert fnd(stale)["review"] == "unconfirmed"
    two = state(findings=[finding()], reviews=[review(subject(), paths=())])
    two["reviews"][0]["reviewed_targets"] = []
    unbound = run(two)
    assert any("not bound" in r for r in unbound["reviews"][0]["invalid_reasons"])
    other = run(state(findings=[finding()], reviews=[review(subject(), paths=("src/other.py",))]))
    assert any("not a target" in r for r in other["reviews"][0]["invalid_reasons"])


def test_disagreeing_valid_reviews_leave_subject_unconfirmed():
    s = state(
        findings=[finding()],
        reviews=[review(subject()), review(subject(result="false_positive", evidence=["E1"]))],
    )
    result = run(s)
    assert fnd(result)["review"] == "unconfirmed" and fnd(result)["review_disagreement"] is True
    assert "REVIEW_DISAGREEMENT" in codes(result) and result["verdict"] == "cannot_confirm_pass"
    s["reviews"].reverse()
    assert run(s)["verdict"] == result["verdict"]


def test_merge_is_a_label_and_never_hides_a_severe_finding():
    s = state(findings=[finding(merged_into="F2"), finding("F2", severity="low")])
    result = run(s)
    assert result["verdict"] == "cannot_confirm_pass" and fnd(result)["merged_into"] == "F2"
    s["reviews"] = [review(subject())]
    assert run(s)["verdict"] == "fail"


def test_no_plan_cannot_pass():
    result = run(state(plan=None, ledger={}))
    assert result["verdict"] == "cannot_confirm_pass" and codes(result) == ["NO_PLAN"]


def test_not_met_without_failing_finding_cannot_pass():
    result = run(state(ledger={"C1": led("not_met")}))
    assert codes(result) == ["CHECK_NOT_MET"]


def test_incomplete_tree_target_blocks_pass_from_either_snapshot():
    s = state()
    s["artifact"]["targets"][0].update(path="src", kind="dir", incomplete=True)
    s["plan"]["checks"][0]["object"] = ["src/a.py"]
    observed = {"src": {"digest": D0, "incomplete": False, "not_followed": [], "unreadable": []}}
    result = run(s, observed=observed)
    assert codes(result) == ["TARGET_INCOMPLETE"]
    s["artifact"]["targets"][0]["incomplete"] = False
    observed["src"]["incomplete"] = True
    assert codes(run(s, observed=observed)) == ["TARGET_INCOMPLETE"]
    observed["src"]["incomplete"] = False
    assert run(s, observed=observed)["verdict"] == "pass"


def test_deleted_target_stays_unchanged_when_still_absent():
    s = state()
    s["artifact"]["targets"].append(
        {
            "path": "src/gone.py",
            "kind": None,
            "change": "deleted",
            "old_path": None,
            "digest": None,
            "incomplete": False,
            "not_followed": [],
            "unreadable": [],
        }
    )
    observed = {
        "src/a.py": {"digest": D0, "incomplete": False, "not_followed": [], "unreadable": []},
        "src/gone.py": {"digest": None, "incomplete": False, "not_followed": [], "unreadable": []},
    }
    assert run(s, observed=observed)["verdict"] == "pass"
    observed["src/gone.py"]["digest"] = D9
    assert codes(run(s, observed=observed)) == ["TARGET_CHANGED"]


def test_result_records_scope_artifact_and_retention():
    result = run(state())
    assert result["schema"] == "ai-secure-code-toolkit/guard-result/v1" and result["ended_at"] == ENDED
    assert result["scope"]["adopted"] == [{"rule": R1, "state_digest": D9, "at_conclusion": "unchanged"}]
    assert result["artifact"]["targets"][0]["digest_at_open"] == D0
    assert result["evidence_retention"]["days_after_end"] == 30
    assert result["evidence"][0]["id"] == "E1" and "stored_bytes" not in result["evidence"][0]
