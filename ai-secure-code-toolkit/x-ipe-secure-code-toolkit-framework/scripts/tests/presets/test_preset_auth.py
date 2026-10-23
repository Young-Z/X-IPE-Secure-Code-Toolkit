"""FEATURE-001-F Integration: authorization separation (G-05).

AC-001F-07a…07d. A "User" is a trust store without Maintainer qualification; Preset services
take no trust paths at all (they never call `require_maintainer`); tag writes do, before the
knowledge lock and again under it (review R-5).
"""

from __future__ import annotations

import inspect

import pytest
from conftest import tree_hashes
from knowledge.exithelp import R1, R2, R3, cleanup, finish, item, wait_ready
from presethelp import TAGS, PEnv, mod

from x_ipe_secure_code.auth.trust_store import resolve
from x_ipe_secure_code.knowledge import service as knowledge
from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import service as policy


@pytest.fixture
def env(project, tmp_path):
    result = PEnv(project, tmp_path)
    result.rules()
    return result


def protected(env):
    return tree_hashes(env.project / store.LOCAL_REL, env.project / store.PENDING_REL)


def user(env):
    return resolve(env.work / "no-qualification")


# AC-001F-07a
def test_user_preset_ops_succeed_without_knowledge_writes(env):
    before = protected(env)
    assert env.psave(query_intent="intent").ok
    assert env.pupdate(rules=[R1], keep_summary=True).ok
    diff = env.recompute([R1, R3])
    assert diff.ok
    assert env.recompute_confirm([R1, R3], diff.data["recompute_digest"], keep_summary=True).ok
    assert env.presolve().ok
    assert env.pdelete().ok
    assert protected(env) == before
    for function in (env.presets.save_preset, env.presets.update_preset, env.presets.delete_preset,
                     env.presets.recompute, env.presets.recompute_confirm):
        assert "trust_paths" not in inspect.signature(function).parameters
    source = inspect.getsource(env.presets)
    assert "require_maintainer" not in source


# AC-001F-07b
def test_user_after_preset_save_knowledge_import_refused(env):
    assert env.psave().ok
    batch = env.req({"schema": "ai-secure-code-toolkit/knowledge-batch/v1",
                     "items": [item("CWE/4.14/CWE-1")]})
    before = protected(env)
    result = knowledge.import_batch(str(env.project), batch, [], [], trust_paths=user(env))
    assert not result.ok and result.problems[0].code == "NOT_AUTHORIZED", result.to_dict()
    update = knowledge.update_rule(str(env.project), R1, env.show(R1).data["state_digest"],
                                   env.req({"schema": "ai-secure-code-toolkit/knowledge-update/v1",
                                            "content": "x\n"}), [], trust_paths=user(env))
    assert update.problems[0].code == "NOT_AUTHORIZED"
    assert protected(env) == before


# AC-001F-07c
@pytest.mark.parametrize("op", ["save", "update", "delete"])
def test_tag_writes_maintainer_only(env, op):
    if op != "save":
        assert env.tsave().ok
    lock = env.project / store.LOCK_REL
    lock.unlink()
    before = tree_hashes(env.project)
    if op == "save":
        refused = env.tsave("other", paths=user(env))
    elif op == "update":
        refused = env.tupdate(paths=user(env))
    else:
        refused = env.tdelete(paths=user(env))
    assert not refused.ok and refused.problems[0].code == "NOT_AUTHORIZED", refused.to_dict()
    assert refused.next_steps and refused.data["action"] == f"tag.{op}"
    assert refused.next_steps[0] == mod("knowledge.tags").ASK_STEP, refused.next_steps
    assert tree_hashes(env.project) == before
    assert not lock.exists()
    knowledge_before = protected(env)
    if op == "save":
        allowed = env.tsave("other")
    elif op == "update":
        allowed = env.tupdate()
    else:
        allowed = env.tdelete()
    assert allowed.ok, allowed.to_dict()
    assert protected(env) == knowledge_before


def test_maintainer_revoked_while_waiting_refused_under_lock(env):
    barrier = env.work / "tag-authorized"
    args = ["tag", "save", "--project", str(env.project), "--request", env.treq(), "--confirmed", "--json"]
    process = env.spawn(args, SECURE_CODE_TEST_PAUSE_AT=f"tag_write_authorized={barrier}")
    try:
        wait_ready(process, barrier)
        env.revoke()
        barrier.with_suffix(".go").touch()
        result = finish(process)
    finally:
        cleanup(process)
    assert result["ok"] is False and result["problems"][0]["code"] == "NOT_AUTHORIZED", result
    assert not env.tag_file().exists()


# AC-001F-07d
def test_user_reads_tags_and_uses_tag_as_clue(env):
    assert env.tsave(members=[R1, R2]).ok
    before = tree_hashes(env.project)
    listed = env.tags.list_tags(str(env.project))
    shown = env.tshow()
    assert listed.ok and shown.ok
    members = [m["rule"] for m in shown.data["members"]]
    proposal = policy.resolve_policies(str(env.project), members, False, [])
    assert proposal.ok and [e["requested"] for e in proposal.data["entries"]] == [R1, R2]
    assert tree_hashes(env.project) == before
    assert (env.project / TAGS).is_dir()
