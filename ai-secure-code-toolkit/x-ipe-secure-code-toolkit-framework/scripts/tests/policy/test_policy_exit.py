"""AC-001D-02f,04a-d Integration: no substitution, immutable scopes, transition exception.

Arrange actual confirmed decisions; Act exit and resolve/save/load; Assert exact
missing reasons, active membership and only the user's original confirmed choices.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from knowledge.exithelp import EXITS, R1, R2, R3, TARGET, Env, canonical, files, refusal, sha

from x_ipe_secure_code.policy import service as policy


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate()
    return result


@pytest.mark.parametrize("action,reason", [
    ("deactivate", "deactivated"), ("delete", "deleted"), ("rename", "renamed"),
])
@pytest.mark.parametrize("versionless", [False, True])
def test_explicit_missing_never_substituted(env, action, reason, versionless):
    # Explicit references: a real other-source-version candidate of the same rule ID exists, so
    # BR-04 non-substitution is meaningful. Version-less references cover the design branch
    # "no stored versions but exited identities"; a version-less ref with a remaining other
    # version keeps existing version-less semantics (design ambiguity reported, not encoded).
    alternate = "CWE/4.13/CWE-79-OTHER" if versionless else "CWE/4.13/CWE-79"
    ns, ver, rid = alternate.split("/")
    assert env.load({
        "namespace": ns, "version": ver, "rule_id": rid, "content": "Not a substitute.\n",
    }).ok
    env.exit(action)
    before = files(env.project)
    requested = "CWE/CWE-79" if versionless else R1
    result = policy.resolve_policies(str(env.project), [requested, R3], False, [])
    entry = next(e for e in result.data["entries"] if e["requested"] == requested)
    assert entry["availability"] == "missing"
    assert entry["reason"] == reason
    assert "requirement" not in entry
    assert "content" not in entry
    assert "source_evidence" not in entry
    assert entry.get("rule") not in (TARGET, alternate)
    if action == "rename":
        assert entry["renamed_to"] == TARGET
    if versionless and action != "deactivate":
        assert entry["exited"] == [
            {"rule": R1, "reason": reason, "renamed_to": TARGET if action == "rename" else None},
        ]
    assert result.data["status"] == "partial"
    assert files(env.project) == before


@pytest.mark.parametrize("action,reason", [("delete", "deleted"), ("rename", "renamed")])
def test_versionless_remaining_version_lists_exited(env, action, reason):
    """AC-001D-04a / BR-04, design v1.2 (human decision A).

    Arrange: CWE/4.13/CWE-79 stored beside R1 (CWE/4.14/CWE-79). Act: exit R1, then resolve
    the version-less CWE/CWE-79 and the explicit R1. Assert: version-less resolution is the
    pre-existing single-version result for 4.13, plus only the informational `exited` note;
    the explicit R1 stays missing and is never substituted; nothing is written.
    """
    remaining = "CWE/4.13/CWE-79"
    assert env.load({
        "namespace": "CWE", "version": "4.13", "rule_id": "CWE-79", "content": "Older version.\n",
    }).ok
    env.exit(action)
    before = files(env.project)
    result = policy.resolve_policies(str(env.project), ["CWE/CWE-79", R1], False, [])
    entries = {e["requested"]: e for e in result.data["entries"]}
    versionless = entries["CWE/CWE-79"]
    assert versionless["availability"] == "available"
    assert versionless["rule"] == remaining
    assert versionless["exited"] == [
        {"rule": R1, "reason": reason, "renamed_to": TARGET if action == "rename" else None},
    ]
    explicit = entries[R1]
    assert explicit["availability"] == "missing"
    assert explicit["reason"] == reason
    assert explicit.get("rule") != remaining
    assert "requirement" not in explicit
    assert result.data["counts"] == {"requested": 2, "available": 1, "missing": 1, "unclear": 0}

    alone = policy.resolve_policies(str(env.project), ["CWE/CWE-79"], False, [])
    assert alone.data["status"] == "complete"
    assert files(env.project) == before


def test_all_active_only_informational_counts(env):
    assert env.load({
        "namespace": "CWE", "version": "4.14", "rule_id": "KEEP", "content": "Keep.\n",
    }).ok
    env.exit("deactivate", R1)
    env.exit("delete", R2)
    env.exit("rename", R3, target="CWE/4.14/RENAMED")
    result = env.proposal(all_=True)
    assert result.ok
    assert result.data["status"] == "complete"
    assert {e["rule"] for e in result.data["entries"]} == {"CWE/4.14/KEEP", "CWE/4.14/RENAMED"}
    assert result.data["inactive"] == {"deactivated": 1, "deleted": 1, "renamed": 1}
    assert result.data["counts"] == {"requested": 2, "available": 2, "missing": 0, "unclear": 0}


def test_all_deactivated_has_honest_maintenance_step(env):
    for rule in (R1, R2, R3):
        env.exit("deactivate", rule)
    result = env.proposal(all_=True)
    assert not result.ok
    assert result.data["entries"] == []
    assert result.data["inactive"]["deactivated"] == 3
    assert result.data["status"] == "maintenance_needed"
    assert any("reactivat" in step.lower() and "Maintainer" in step for step in result.next_steps)


@pytest.mark.parametrize("action,reason", [
    ("deactivate", "deactivated"), ("delete", "deleted"), ("rename", "renamed"),
])
@pytest.mark.parametrize("only_exited", [False, True])
def test_scope_missing_and_immutable(env, action, reason, only_exited):
    refs = (R1,) if only_exited else (R1, R3)
    saved = env.save(env.decisions(refs))
    assert saved.ok
    path = env.scope_path(saved.data["scope_id"])
    original = path.read_bytes()
    env.exit(action)
    result = policy.show_scope(str(env.project), saved.data["scope_id"])
    found = next(e for e in result.data["entries"] if e["rule"] == R1)
    assert found["adoption"] == "missing"
    assert found["reason"] == reason
    assert "policy" not in found
    if action == "rename":
        assert found["renamed_to"] == TARGET
    assert result.data["status"] == ("maintenance_needed" if only_exited else "partial")
    assert R1 not in result.data["adopted_rules"]
    assert TARGET not in result.data["adopted_rules"]
    assert path.read_bytes() == original


def test_cycle_requires_reconfirmation(env):
    saved = env.save()
    path = env.scope_path(saved.data["scope_id"])
    original = path.read_bytes()
    content = (env.folder() / "content.md").read_bytes()
    env.exit("deactivate")
    env.exit("reactivate")
    result = policy.show_scope(str(env.project), saved.data["scope_id"])
    found = next(e for e in result.data["entries"] if e["rule"] == R1)
    assert found["adoption"] == "needs_reconfirmation"
    assert found["current_state_digest"] != found["confirmed_state_digest"]
    assert result.data["status"] == "partial"
    assert result.data["adopted_rules"] == [R3]
    assert any("confirm" in step.lower() for step in result.next_steps)
    assert (env.folder() / "content.md").read_bytes() == content
    assert path.read_bytes() == original


@pytest.mark.parametrize("action", ["deactivate", "delete", "rename"])
@pytest.mark.parametrize("all_", [False, True])
def test_single_exit_explicit_not_adopted_exception(env, action, all_):
    decisions = env.decisions(skipped=(R1,), all_=all_)
    original = json.loads(Path(decisions).read_text(encoding="utf-8"))
    env.exit(action)
    saved = env.save(decisions)
    assert saved.ok, saved.to_dict()
    record = json.loads(env.scope_path(saved.data["scope_id"]).read_text())
    expected = sorted(d["ref"] for d in original["decisions"] if d["decision"] == "adopted")
    assert sorted(a["rule"] for a in record["adopted"]) == expected
    assert record["not_adopted"] == [{
        "requested": R1, "availability": "missing", "reason": "User explicitly excluded this rule",
    }]
    assert TARGET not in {a["rule"] for a in record["adopted"]}
    if action == "rename" and all_:
        assert TARGET in json.dumps(saved.to_dict()), "new target must be reported outside confirmed scope"
    transitions = json.loads((env.project / EXITS / "transitions.json").read_text())
    latest = transitions["entries"][-1]
    assert latest["rule"] == R1
    assert latest["digest"] == sha(canonical({k: v for k, v in latest.items() if k != "digest"}))
    if action == "rename":
        assert set(latest["identities"]) == {R1, TARGET}
        assert latest["identities"][R1]["before"]["present"] is True
        assert latest["identities"][TARGET]["before"]["present"] is False
    for folder in (env.folder(), env.folder(TARGET)):
        if (folder / "record.json").exists():
            assert set(json.loads((folder / "record.json").read_text())["lifecycle"]) == {"state", "revision"}


@pytest.mark.parametrize("action", ["deactivate", "delete", "rename"])
@pytest.mark.parametrize("all_", [False, True])
def test_adopted_exit_is_stale_no_scope_published(env, action, all_):
    decisions = env.decisions(all_=all_)
    env.exit(action)
    before = files(env.project)
    refusal(env.save(decisions), "STALE_CONFIRMATION")
    assert files(env.project) == before


@pytest.mark.parametrize("all_", [False, True])
def test_reactivation_exception_only_for_explicit_clue_skip(env, all_):
    env.exit("deactivate")
    decisions = env.decisions(skipped=(R1,), all_=all_)
    env.exit("reactivate")
    before = files(env.project)
    saved = env.save(decisions)
    if all_:
        refusal(saved, "STALE_CONFIRMATION")
        assert files(env.project) == before
    else:
        assert saved.ok, saved.to_dict()
        assert saved.data["adopted_rules"] == [R3]
        assert saved.data["not_adopted"][0]["requested"] == R1
        assert saved.data["not_adopted"][0]["availability"] == "available"


@pytest.mark.parametrize("delta", ["unrelated_content", "second_exit", "same_rule_cycle", "later_content"])
def test_transition_does_not_explain_other_changes(env, delta):
    decisions = env.decisions(all_=True, skipped=(R1, R2))
    env.exit("deactivate")
    if delta == "unrelated_content":
        assert env.update(R2, env.show(R2).data["item_digest"], content="Unrelated delta.\n").ok
    elif delta == "second_exit":
        env.exit("delete", R2)
    elif delta == "same_rule_cycle":
        env.exit("reactivate")
    else:
        assert env.update(R1, env.show().data["state_digest"], content="Changed after transition.\n").ok
    before = files(env.project)
    refusal(env.save(decisions), "STALE_CONFIRMATION")
    assert files(env.project) == before


@pytest.mark.parametrize("tamper", ["payload", "rehash_without_binding", "binding"])
@pytest.mark.parametrize("action", ["deactivate", "delete", "rename"])
def test_transition_integrity_is_required_for_exception(env, tamper, action):
    decisions = env.decisions(skipped=(R1,), all_=True)
    env.exit(action)
    path = env.project / EXITS / "transitions.json"
    data = json.loads(path.read_text())
    entry = data["entries"][-1]
    if tamper == "binding":
        if action == "deactivate":
            log = env.folder() / "changelog.md"
            log.write_text(log.read_text().replace(entry["digest"], "sha256:" + "0" * 64))
        else:
            memory = env.project / EXITS / "memory.json"
            memory.write_text(memory.read_text().replace(entry["digest"], "sha256:" + "0" * 64))
    else:
        entry["identities"][R1]["before"]["state_digest"] = "sha256:" + "f" * 64
        if tamper == "rehash_without_binding":
            entry["digest"] = sha(canonical({k: v for k, v in entry.items() if k != "digest"}))
        path.write_text(json.dumps(data))
    before = files(env.project)
    refusal(env.save(decisions), "EXIT_TRANSITION_INVALID")
    assert files(env.project) == before


def test_existing_resolver_must_honor_lifecycle_marker(env):
    """AC-04a: behavioral RED on existing APIs, no future module import."""
    p = env.folder() / "record.json"
    record = json.loads(p.read_text())
    record["lifecycle"] = {"state": "deactivated", "revision": 1}
    p.write_text(json.dumps(record))
    before = files(env.project)
    result = env.proposal()
    found = next(e for e in result.data["entries"] if e["requested"] == R1)
    assert found["availability"] == "missing"
    assert found["reason"] == "deactivated"
    assert "requirement" not in found
    assert files(env.project) == before


def test_existing_all_must_exclude_deactivated_marker(env):
    """AC-04b: behavioral RED on existing apply-all resolution."""
    p = env.folder() / "record.json"
    record = json.loads(p.read_text())
    record["lifecycle"] = {"state": "deactivated", "revision": 1}
    p.write_text(json.dumps(record))
    result = env.proposal(all_=True)
    assert {e["rule"] for e in result.data["entries"]} == {R2, R3}
    assert result.data["inactive"] == {"deactivated": 1, "deleted": 0, "renamed": 0}
