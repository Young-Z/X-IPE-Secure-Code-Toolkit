"""FEATURE-001-F Integration: query intent is never run implicitly; recompute on request.

AC-001F-03a, 03c, 03d, 03e, 03f (+ QUERY_INTENT_MISSING edge). Arrange stored Presets with an
intent naming other rules; Act list/show/resolve/preview and the two-step recompute; Assert the
stored list is the only membership and confirmation is digest-bound.
"""

from __future__ import annotations

import json

import pytest
from knowledge.exithelp import R1, R2, R3, files
from presethelp import PEnv, unchanged_but_lock


@pytest.fixture
def env(project, tmp_path):
    result = PEnv(project, tmp_path)
    result.rules()
    assert result.psave(query_intent=f"every rule, including {R3}", applicability_summary="web").ok
    return result


def code(result):
    assert not result.ok, result.to_dict()
    return result.problems[0].code


# AC-001F-03a
def test_query_not_evaluated_on_read_resolve_preview(env):
    original = env.preset_file().read_bytes()
    listed = env.presets.list_presets(str(env.project))
    assert listed.data["presets"][0]["rule_count"] == 2
    shown = env.pshow()
    assert [r["rule"] for r in shown.data["rules"]] == [R1, R2]
    resolved = env.presolve()
    assert [e["requested"] for e in resolved.data["entries"]] == [R1, R2]
    assert resolved.data["counts"]["requested"] == 2
    preview = env.preview("deactivate", R3)
    assert preview.ok, preview.to_dict()
    assert preview.data["impact"]["presets"]["items"] == []
    referencing = env.preview("deactivate", R1)
    assert [i["name"] for i in referencing.data["impact"]["presets"]["items"]] == ["web-input"]
    assert env.preset_file().read_bytes() == original


# AC-001F-03c
def test_recompute_diff_availability_digest_no_write(env):
    before = files(env.project)
    diff = env.recompute([R2, R3])
    assert diff.ok, diff.to_dict()
    data = diff.data
    assert [a["rule"] for a in data["add"]] == [R3]
    assert data["add"][0]["availability"] == "available"
    assert data["add"][0]["state_digest"] == env.show(R3).data["state_digest"]
    assert [r["rule"] for r in data["remove"]] == [R1]
    assert data["remove"][0]["availability"] == "available"
    assert data["unchanged_count"] == 1 and data["stored_count"] == 2
    assert data["unchanged"] is False
    assert data["recompute_digest"].startswith("sha256:")
    assert data["file_digest"] == env.pdigest()
    assert "not run" in data["query_intent_note"]
    text = diff.to_text()
    assert f"+ {R3}" in text and f"- {R1}" in text and "+1 -1 =1" in text
    again = env.recompute([R3, R2])
    assert again.data["recompute_digest"] == data["recompute_digest"]
    unchanged_but_lock(before, files(env.project))


# AC-001F-03d
def test_confirm_subset_applies_and_stale_refused(env, monkeypatch):
    monkeypatch.setattr(env.presets, "_now", lambda: "2026-10-30T10:00:00+08:00")
    diff = env.recompute([R2, R3])
    partial = env.recompute_confirm([R2, R3], diff.data["recompute_digest"], accept_add="all",
                                    accept_remove=[], keep_summary=True)
    assert partial.ok, partial.to_dict()
    stored = json.loads(env.preset_file().read_text())
    assert [r["rule"] for r in stored["rules"]] == sorted([R1, R2, R3])
    assert stored["snapshot_at"] == "2026-10-30T10:00:00+08:00"
    assert partial.data["applied"] == {"added": [R3], "removed": []}
    assert partial.data["summary"] == "kept"


@pytest.mark.parametrize("change", ["preset_edited", "candidate_updated", "stored_rule_exited"])
def test_confirm_refused_stale_with_new_diff(env, change):
    diff = env.recompute([R2, R3])
    if change == "preset_edited":
        assert env.pupdate(applicability_summary="edited meanwhile").ok
    elif change == "candidate_updated":
        assert env.update(R3, env.show(R3).data["state_digest"], content="Changed meanwhile.\n").ok
    else:
        env.exit("deactivate", R1)
    original = env.preset_file().read_bytes()
    before = files(env.project)
    stale = env.recompute_confirm([R2, R3], diff.data["recompute_digest"], keep_summary=True)
    assert code(stale) == "STALE_RECOMPUTE"
    assert stale.data["recompute_digest"] != diff.data["recompute_digest"]
    assert "add" in stale.data and "remove" in stale.data
    assert "confirm" in stale.next_steps[0].lower()
    assert env.preset_file().read_bytes() == original
    unchanged_but_lock(before, files(env.project))


def test_confirm_refuses_unknown_acceptance_and_missing_summary(env):
    diff = env.recompute([R2, R3])
    digest = diff.data["recompute_digest"]
    before = files(env.project)
    outside = env.recompute_confirm([R2, R3], digest, accept_add=[R1], keep_summary=True)
    assert code(outside) == "REQUEST_INVALID"
    no_summary = env.recompute_confirm([R2, R3], digest)
    assert code(no_summary) == "SUMMARY_DECISION_REQUIRED"
    unconfirmed = env.recompute_confirm([R2, R3], digest, keep_summary=True, confirmed=False)
    assert code(unconfirmed) == "CONFIRMATION_REQUIRED"
    unchanged_but_lock(before, files(env.project))


# AC-001F-03e
def test_no_difference_keeps_snapshot_unless_reconfirmed(env, monkeypatch):
    snapshot_at = json.loads(env.preset_file().read_text())["snapshot_at"]
    diff = env.recompute([R1, R2])
    assert diff.data["unchanged"] is True and diff.data["add"] == [] and diff.data["remove"] == []
    assert "unchanged" in diff.to_text().lower()
    before = files(env.project)
    plain = env.recompute_confirm([R1, R2], diff.data["recompute_digest"])
    assert plain.ok and plain.data["changed"] is False
    unchanged_but_lock(before, files(env.project))
    monkeypatch.setattr(env.presets, "_now", lambda: "2026-11-01T09:00:00+08:00")
    again = env.recompute_confirm([R1, R2], diff.data["recompute_digest"], reconfirm=True)
    assert again.ok and again.data["changed"] is True, again.to_dict()
    stored = json.loads(env.preset_file().read_text())
    assert stored["snapshot_at"] == "2026-11-01T09:00:00+08:00" != snapshot_at
    assert [r["rule"] for r in stored["rules"]] == [R1, R2]


# AC-001F-03f
def test_candidates_validated_invalid_listed_and_excluded(env):
    before = files(env.project)
    diff = env.recompute([R2, R3, "CWE/4.14/NOPE", "tag:injection", "reference:CWE/4.14/CWE-1"])
    assert diff.ok, diff.to_dict()
    invalid = {i["requested"]: i["reason"] for i in diff.data["invalid"]}
    assert invalid == {"CWE/4.14/NOPE": "not_found", "tag:injection": "dynamic_selector",
                       "reference:CWE/4.14/CWE-1": "invalid_reference"}
    assert [a["rule"] for a in diff.data["add"]] == [R3]
    assert [r["rule"] for r in diff.data["remove"]] == [R1]
    clean = env.recompute([R2, R3])
    assert clean.data["recompute_digest"] != diff.data["recompute_digest"]
    refused = env.recompute_confirm(
        [R2, R3, "CWE/4.14/NOPE", "tag:injection", "reference:CWE/4.14/CWE-1"],
        diff.data["recompute_digest"], accept_add=["CWE/4.14/NOPE"], keep_summary=True)
    assert code(refused) == "REQUEST_INVALID"
    unchanged_but_lock(before, files(env.project))


def test_recompute_without_intent_refused(project, tmp_path):
    env = PEnv(project, tmp_path)
    env.rules()
    assert env.psave().ok
    result = env.recompute([R1])
    assert code(result) == "QUERY_INTENT_MISSING"
    assert "intent" in result.next_steps[0].lower()
