"""FEATURE-001-F Integration: tags — concrete members, independence from Presets and Policies.

AC-001F-05a…05f. Tag writes are made by the Maintainer of the real initialized project; the
Reference-source part of 05a is conditional on FEATURE-001-E (review R-4, spec v1.5 DAO-008).
"""

from __future__ import annotations

import json
import os

import pytest
from knowledge.exithelp import R1, R2, R3, files, item
from presethelp import CUSTOM, TAGS, PEnv, unchanged_but_lock

from x_ipe_secure_code.policy import service as policy

REFERENCE_KNOWLEDGE = False  # FEATURE-001-E (Reference knowledge) is not delivered yet


@pytest.fixture
def env(project, tmp_path):
    result = PEnv(project, tmp_path)
    result.rules(custom=True)
    return result


def code(result):
    assert not result.ok, result.to_dict()
    return result.problems[0].code


# AC-001F-05a
def test_tag_save_one_file_concrete_members_across_local_namespaces(env):
    result = env.tsave(members=[R1, CUSTOM, "CWE/CWE-89"])
    assert result.ok, result.to_dict()
    assert sorted(os.listdir(env.project / TAGS)) == ["injection.json"]
    stored = json.loads(env.tag_file().read_text())
    assert stored == {
        "schema": "ai-secure-code-toolkit/tag/v1", "name": "injection",
        "members": [{"rule": CUSTOM, "source": "local"}, {"rule": R1, "source": "local"},
                    {"rule": R2, "source": "local"}],
    }
    raw = env.tag_file().read_text()
    assert "body" not in raw and "content" not in raw and "state_digest" not in raw


def test_reference_member_refused_before_001e(env):
    before = files(env.project)
    result = env.tsave(members=[R1, "reference:OWASP/2021/A03"])
    assert code(result) == "REFERENCES_INVALID"
    ref = next(r for r in result.data["references"] if r["requested"] == "reference:OWASP/2021/A03")
    assert ref["reason"] == "invalid_reference"
    assert "reference sources are not available" in ref["detail"].lower()
    assert result.next_steps
    unchanged_but_lock(before, files(env.project))


@pytest.mark.skipif(
    not REFERENCE_KNOWLEDGE,
    reason="conditional on FEATURE-001-E: Reference knowledge does not exist yet (AC-001F-05a)",
)
def test_tag_members_across_local_and_reference_sources(env):  # pragma: no cover - 001-E
    result = env.tsave(members=[R1, "reference:OWASP/2021/A03"])
    assert result.ok


# AC-001F-05b
@pytest.mark.parametrize("member,reason", [
    ("CWE/4.14/NOPE", "not_found"), ("injection", "dynamic_selector"), ("CWE/*", "dynamic_selector"),
])
def test_tag_member_unavailable_refused(env, member, reason):
    before = files(env.project)
    result = env.tsave(members=[R1, member])
    assert code(result) == "REFERENCES_INVALID"
    found = {r["requested"]: r["reason"] for r in result.data["references"]}
    assert found == {member: reason}
    unchanged_but_lock(before, files(env.project))


def test_tag_member_multiple_versions_refused(env):
    assert env.load(item("CWE/4.15/CWE-79")).ok
    result = env.tsave(members=["CWE/CWE-79"])
    assert code(result) == "REFERENCES_INVALID"
    assert result.data["references"][0]["reason"] == "multiple_versions"


# AC-001F-05c
def test_tag_changes_leave_preset_bytes_identical(env):
    assert env.psave(rules=[R1, R2]).ok
    original = env.preset_file().read_bytes()
    assert env.tsave(members=[R1, R2]).ok
    assert env.tupdate(members=[R1, R3]).ok
    assert env.tsave("more", members=[R2]).ok
    assert env.tdelete("more").ok
    shown = env.pshow()
    assert [r["rule"] for r in shown.data["rules"]] == [R1, R2]
    assert [e["requested"] for e in env.presolve().data["entries"]] == [R1, R2]
    assert env.preset_file().read_bytes() == original


# AC-001F-05d
def test_policy_resolution_identical_with_and_without_tags(env):
    before = policy.resolve_policies(str(env.project), [R1, CUSTOM], False, ["python"])
    assert env.tsave(members=[R1, CUSTOM]).ok
    assert env.tsave("critical", members=[R1]).ok
    after = policy.resolve_policies(str(env.project), [R1, CUSTOM], False, ["python"])
    assert after.to_dict() == before.to_dict()
    kinds = {e["rule"]: e["kind"] for e in after.data["entries"]}
    assert kinds == {R1: "institutional", CUSTOM: "custom"}
    assert all("tag" not in key for e in after.data["entries"] for key in e)
    assert after.data["proposal_digest"] == before.data["proposal_digest"]


# AC-001F-05e
def test_tag_clue_expanded_at_proposal_scope_record_stable(env):
    assert env.tsave(members=[R1, R2]).ok
    members = [m["rule"] for m in env.tshow().data["members"]]
    proposal = policy.resolve_policies(str(env.project), members, False, ["python"])
    decisions = env.req({
        "schema": "ai-secure-code-toolkit/scope-decisions/v1", "mode": "clues", "considered": members,
        "proposal_digest": proposal.data["proposal_digest"], "clues": "tag injection",
        "language_context": ["python"],
        "decisions": [{"ref": e["requested"], "decision": "adopted",
                       "state_digest": e["source_evidence"]["state_digest"]}
                      for e in proposal.data["entries"]],
        "confirmation_note": "User confirmed the tag expansion",
    })
    saved = policy.save_scope(str(env.project), decisions, True)
    assert saved.ok, saved.to_dict()
    path = env.scope_path(saved.data["scope_id"])
    record = json.loads(path.read_text())
    assert [a["rule"] for a in record["adopted"]] == [R1, R2]
    original = path.read_bytes()
    assert env.tupdate(members=[R3]).ok
    assert env.tdelete().ok
    assert path.read_bytes() == original
    assert policy.show_scope(str(env.project), saved.data["scope_id"]).data["adopted_rules"] == [R1, R2]


# AC-001F-05f
def test_tag_list_show_availability_read_only(env):
    assert env.tsave(members=[R1, R2]).ok
    assert env.tsave("alpha", members=[R3]).ok
    env.exit("deactivate", R2)
    before = files(env.project)
    listed = env.tags.list_tags(str(env.project))
    assert listed.ok
    assert [t["name"] for t in listed.data["tags"]] == ["alpha", "injection"]
    assert listed.data["tags"][1]["member_count"] == 2
    shown = env.tshow()
    members = {m["rule"]: m for m in shown.data["members"]}
    assert members[R1]["availability"] == "available"
    assert (members[R2]["availability"], members[R2]["reason"]) == ("missing", "deactivated")
    assert "never change severity" in shown.data["note"]
    assert files(env.project) == before
