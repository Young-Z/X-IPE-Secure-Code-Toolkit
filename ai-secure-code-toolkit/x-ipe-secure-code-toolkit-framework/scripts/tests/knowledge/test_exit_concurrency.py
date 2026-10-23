"""AC-001D-02f/06b Integration: bounded process races, with guaranteed cleanup.

Arrange confirmed scopes/impact/base states; Act competing CLI processes at the
documented pause hooks; a test-side lock probe (bounded handshake, no fixed sleeps)
proves each contender reached knowledge-lock acquisition and is blocked while the
holder is paused; Assert serialized publication and stale second decisions.
No orphaned workers.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from knowledge.exithelp import (
    R1,
    R2,
    STEPS,
    TARGET,
    Env,
    cleanup,
    files,
    finish,
    module,
    wait_blocked,
    wait_ready,
)

from x_ipe_secure_code.knowledge import store
from x_ipe_secure_code.policy import scope


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate()
    return result


def save_args(env, decisions):
    return [
        "scope", "save", "--project", str(env.project), "--decisions", decisions,
        "--confirmed", "--json",
    ]


def knowledge_lock(env):
    return env.project / store.LOCK_REL


def update_args(env, base):
    path = env.req({
        "schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": "Concurrent update.\n",
    })
    return [
        "knowledge", "update", "--project", str(env.project), "--rule", R1,
        "--base-state", base, "--input", path, "--json",
    ]


def test_scope_publication_first_makes_exit_stale(env):
    decisions = env.decisions()
    preview = env.preview()
    assert preview.ok
    barrier = env.work / "scope-before-publish"
    saving = env.spawn(
        save_args(env, decisions),
        SECURE_CODE_TEST_PAUSE_AT="scope_save_before_publish=" + str(barrier),
    )
    exiting = None
    try:
        wait_ready(saving, barrier)
        probe = env.work / "exit-probe"
        exiting = env.spawn(env.cli_args("deactivate", preview.data["impact_digest"]), probe=probe)
        wait_blocked(exiting, probe, knowledge_lock(env))
        assert exiting.poll() is None, "exit passed knowledge lock before scope publication"
        assert not list((env.project / scope.SCOPES_REL).glob("*.json"))
        barrier.with_suffix(".go").touch()
        assert finish(saving)["ok"] is True
        result = finish(exiting)
        assert result["ok"] is False
        assert result["problems"][0]["code"] == "STALE_IMPACT"
        assert len(list((env.project / scope.SCOPES_REL).glob("*.json"))) == 1
        assert env.show().data["state"] == "active"
    finally:
        cleanup(*[p for p in (saving, exiting) if p is not None])


@pytest.mark.parametrize("action", ["deactivate", "delete", "rename"])
@pytest.mark.parametrize("all_", [False, True])
@pytest.mark.parametrize("not_adopted", [False, True])
def test_exit_first_scope_rechecks_under_both_locks(env, action, all_, not_adopted):
    decisions = env.decisions(skipped=(R1,) if not_adopted else (), all_=all_)
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    assert preview.ok
    barrier = env.work / "exit-before-save"
    exiting = env.spawn(
        env.cli_args(action, preview.data["impact_digest"]),
        SECURE_CODE_TEST_PAUSE_AT="exit_locked=" + str(barrier),
    )
    saving = None
    try:
        wait_ready(exiting, barrier)
        probe = env.work / "save-probe"
        saving = env.spawn(save_args(env, decisions), probe=probe)
        wait_blocked(saving, probe, knowledge_lock(env))
        assert saving.poll() is None
        assert not list((env.project / scope.SCOPES_REL).glob("*.json"))
        barrier.with_suffix(".go").touch()
        assert finish(exiting)["ok"] is True
        result = finish(saving)
        if not_adopted:
            assert result["ok"] is True, result
            record = json.loads((env.project / result["data"]["path"]).read_text())
            assert R1 not in {a["rule"] for a in record["adopted"]}
            assert TARGET not in {a["rule"] for a in record["adopted"]}
            assert record["not_adopted"][0]["requested"] == R1
        else:
            assert result["ok"] is False
            assert result["problems"][0]["code"] == "STALE_CONFIRMATION"
            assert not list((env.project / scope.SCOPES_REL).glob("*.json"))
    finally:
        cleanup(*[p for p in (exiting, saving) if p is not None])


@pytest.mark.parametrize("action", ["deactivate", "reactivate"])
def test_exit_then_update_process_base_includes_revision(env, action):
    if action == "reactivate":
        env.exit("deactivate")
    shown = env.show().data
    base = shown.get("state_digest", shown["item_digest"])
    preview = env.preview(action)
    barrier = env.work / "exit-before-update"
    args = update_args(env, base)
    exiting = env.spawn(
        env.cli_args(action, preview.data["impact_digest"]),
        SECURE_CODE_TEST_PAUSE_AT="exit_locked=" + str(barrier),
    )
    updating = None
    try:
        wait_ready(exiting, barrier)
        probe = env.work / "update-probe"
        updating = env.spawn(args, probe=probe)
        wait_blocked(updating, probe, knowledge_lock(env))
        assert updating.poll() is None
        barrier.with_suffix(".go").touch()
        assert finish(exiting)["ok"] is True
        result = finish(updating)
        assert result["ok"] is False
        assert result["problems"][0]["code"] == "STATE_CONFLICT"
        assert env.show().data["content"] == "Rule CWE-79 body.\n"
        assert env.show().data["consistent"] is True
        assert not list(env.folder().glob("*.new"))
    finally:
        cleanup(*[p for p in (exiting, updating) if p is not None])


def test_two_exits_process_second_uses_first_result(env):
    first, second = env.preview(), env.preview("delete")
    barrier = env.work / "exit-before-exit"
    exiting = env.spawn(
        env.cli_args("deactivate", first.data["impact_digest"]),
        SECURE_CODE_TEST_PAUSE_AT="exit_locked=" + str(barrier),
    )
    competing = None
    try:
        wait_ready(exiting, barrier)
        probe = env.work / "competing-probe"
        competing = env.spawn(env.cli_args("delete", second.data["impact_digest"]), probe=probe)
        wait_blocked(competing, probe, knowledge_lock(env))
        assert competing.poll() is None
        barrier.with_suffix(".go").touch()
        assert finish(exiting)["ok"] is True
        result = finish(competing)
        assert result["ok"] is False
        assert result["problems"][0]["code"] == "STALE_IMPACT"
        assert env.show().data["record"]["lifecycle"] == {"state": "deactivated", "revision": 1}
        assert env.show().data["consistent"] is True
    finally:
        cleanup(*[p for p in (exiting, competing) if p is not None])


def test_exit_update_unordered_process_race_exactly_one_commits(env):
    preview = env.preview()
    base = env.show().data["item_digest"]
    update = update_args(env, base)
    processes = []
    try:
        with store.lock(env.project, write=True):
            probes = [env.work / "exit-probe", env.work / "update-probe"]
            processes = [
                env.spawn(env.cli_args("deactivate", preview.data["impact_digest"]), probe=probes[0]),
                env.spawn(update, probe=probes[1]),
            ]
            for process, probe in zip(processes, probes, strict=True):
                wait_blocked(process, probe, knowledge_lock(env))
            assert all(p.poll() is None for p in processes)
        results = [finish(p) for p in processes]
        assert sum(r["ok"] for r in results) == 1
        failed = next(r for r in results if not r["ok"])
        assert failed["problems"][0]["code"] in ("STALE_IMPACT", "STATE_CONFLICT")
        assert env.show().data["consistent"] is True
        assert not list(env.folder().glob("*.new"))
        assert not (env.folder() / store.JOURNAL).exists()
    finally:
        cleanup(*processes)


def test_handle_lock_excludes_another_process_and_is_bounded(env):
    durable = module("durable")
    tree = durable.Tree(env.project)
    code = (
        "import sys; from pathlib import Path; "
        "from x_ipe_secure_code.knowledge.durable import Tree, DirLock; "
        "from x_ipe_secure_code.atomic import LockHeld; "
        "tree=Tree(Path(sys.argv[1])); "
        "lock=DirLock(tree,sys.argv[2],create=True,timeout=0.2)\n"
        "try:\n lock.__enter__()\nexcept LockHeld:\n print('LOCKED')\n"
        "else:\n lock.__exit__(None,None,None); raise SystemExit(4)\n"
        "finally:\n tree.close()\n"
    )
    try:
        with durable.DirLock(tree, store.LOCK_REL, create=True):
            child = subprocess.run(
                [sys.executable, "-c", code, str(env.project), store.LOCK_REL],
                capture_output=True, text=True, timeout=5,
            )
            assert child.returncode == 0, child.stdout + child.stderr
            assert child.stdout.strip() == "LOCKED"
    finally:
        tree.close()


@pytest.mark.parametrize("action", list(STEPS))
def test_scope_locked_pause_is_also_inside_knowledge_lock(env, action):
    if action == "reactivate":
        env.exit("deactivate")
        decisions = env.decisions((R2,), skipped=())
    else:
        decisions = env.decisions()
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    barrier = env.work / "scope-locked"
    saving = env.spawn(
        save_args(env, decisions),
        SECURE_CODE_TEST_PAUSE_AT="scope_save_locked=" + str(barrier),
    )
    exiting = None
    try:
        wait_ready(saving, barrier)
        before = files(env.folder())
        probe = env.work / "exit-probe"
        exiting = env.spawn(env.cli_args(action, preview.data["impact_digest"]), probe=probe)
        wait_blocked(exiting, probe, knowledge_lock(env))
        assert exiting.poll() is None
        assert files(env.folder()) == before
        barrier.with_suffix(".go").touch()
        assert finish(saving)["ok"] is True
        result = finish(exiting)
        if action == "reactivate":
            assert result["ok"] is True
        else:
            assert result["problems"][0]["code"] == "STALE_IMPACT"
    finally:
        cleanup(*[p for p in (saving, exiting) if p is not None])
