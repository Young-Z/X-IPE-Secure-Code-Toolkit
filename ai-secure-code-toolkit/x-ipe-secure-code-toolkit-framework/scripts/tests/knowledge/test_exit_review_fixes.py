"""Stage C review fixes (TASK-051): regression tests written RED first.

1. A journal published by an exit that failed after its commit point while another command
   waited on the knowledge lock must be recovered by that waiter (re-checked under the lock) and
   never overwritten by a second exit (AC-001D-06a, FR-001D-8 / AC-001D-05c).
2. Names inside a per-rule 001-B `.commit-journal.json` must be single plain components; no
   recovery (handle-relative or path-based) may read, replace or delete outside the rule folder.
3. A parseable exit journal with missing keys is `EXIT_JOURNAL_INVALID`, never a traceback.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading

import pytest
from conftest import run_cli
from knowledge.exithelp import (
    EXITS,
    JOURNAL,
    R1,
    R3,
    TARGET,
    Env,
    cleanup,
    files,
    finish,
    item,
    need_symlinks,
    refusal,
    wait_blocked,
    wait_ready,
)
from knowledge.exitjournalhelp import JournalFixture

from x_ipe_secure_code import atomic
from x_ipe_secure_code.atomic import dumps_json
from x_ipe_secure_code.knowledge import durable, exit_journal, service, store
from x_ipe_secure_code.knowledge.identity import RuleRef
from x_ipe_secure_code.policy import service as policy

POSIX = pytest.mark.skipif(os.name != "posix", reason="dir_fd / process lock races are POSIX-specific here")


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate()
    return result


# --------------------------------------------------------------------------- 1. waiter recovery
def _failing_rename_paused(env):
    """Arrange confirm A (rename R1) paused at exit_locked, failing at replace:memory after commit."""
    preview = env.preview("rename", target=TARGET)
    assert preview.ok, preview.to_dict()
    barrier = env.work / "a-locked"
    first = env.spawn(
        env.cli_args("rename", preview.data["impact_digest"]),
        SECURE_CODE_TEST_PAUSE_AT="exit_locked=" + str(barrier),
        SECURE_CODE_TEST_FAIL_AT="replace:memory",
    )
    wait_ready(first, barrier)
    return first, barrier


def _assert_rename_fully_recorded(env):
    assert not (env.project / JOURNAL).exists()
    assert not env.folder().exists()
    assert env.folder(TARGET).is_dir()
    memory = json.loads((env.project / EXITS / "memory.json").read_text())["exited"]
    assert [(m["rule"], m["action"], m["renamed_to"]) for m in memory] == [(R1, "renamed", TARGET)]
    transitions = json.loads((env.project / EXITS / "transitions.json").read_text())["entries"]
    assert transitions[0]["action"] == "rename" and transitions[0]["rule"] == R1
    listed = service.list_rules(str(env.project))
    assert [e["rule"] for e in listed.data["exited"]] == [R1]
    reimport = env.load(item(R1))
    assert {e["rule"]: e for e in reimport.data["items"]}[R1]["code"] == "IDENTITY_RESERVED"


@POSIX
def test_waiting_confirm_recovers_failed_exit_before_its_own(env):
    """Process level: B (deactivate R3) waits on the lock while A fails after its commit point."""
    other = env.preview("deactivate", R3)
    assert other.ok, other.to_dict()
    first, barrier = _failing_rename_paused(env)
    second = None
    try:
        probe = env.work / "b-probe"
        args = env.cli_args("deactivate", other.data["impact_digest"])
        args[args.index("--rule") + 1] = R3
        second = env.spawn(args, probe=probe)
        wait_blocked(second, probe, env.project / store.LOCK_REL)
        barrier.with_suffix(".go").touch()
        a = finish(first)
        assert a["ok"] is False and a["problems"][0]["code"] == "IO_ERROR", a
        b = finish(second)
    finally:
        cleanup(*[p for p in (first, second) if p is not None])
    assert b["ok"] is True, b
    assert b["data"]["recovered_exit"]["action"] == "rename"
    assert b["data"]["recovered_exit"]["rule"] == R1
    assert b["data"]["recovered_exit"]["outcome"] == "completed"
    _assert_rename_fully_recorded(env)
    transitions = json.loads((env.project / EXITS / "transitions.json").read_text())["entries"]
    assert [(t["action"], t["rule"]) for t in transitions] == [("rename", R1), ("deactivate", R3)]


@POSIX
def test_waiting_read_command_recovers_failed_exit(env):
    """Process level: a `knowledge list` waiting on the lock recovers A instead of reading a half state."""
    first, barrier = _failing_rename_paused(env)
    reader = None
    try:
        probe = env.work / "list-probe"
        reader = env.spawn(["knowledge", "list", "--project", str(env.project), "--json"], probe=probe)
        wait_blocked(reader, probe, env.project / store.LOCK_REL)
        barrier.with_suffix(".go").touch()
        a = finish(first)
        assert a["ok"] is False and a["problems"][0]["code"] == "IO_ERROR", a
        listed = finish(reader)
    finally:
        cleanup(*[p for p in (first, reader) if p is not None])
    assert listed["ok"] is True, listed
    assert listed["data"]["recovered_exit"]["outcome"] == "completed"
    assert [e["rule"] for e in listed["data"]["exited"]] == [R1]
    _assert_rename_fully_recorded(env)


def test_session_rechecks_pending_journal_under_the_lock(env, monkeypatch):
    """Unit: a journal published while a session waits for the lock is recovered by that session."""
    fixture = JournalFixture(env, "deactivate")
    holding, released, blocked = threading.Event(), threading.Event(), threading.Event()
    outcome: dict = {}
    real_lock = atomic._lock

    def probing(fd):
        try:
            return real_lock(fd)
        except OSError:
            if threading.current_thread().name == "waiter":
                blocked.set()
            raise

    monkeypatch.setattr(atomic, "_lock", probing)

    def holder():
        with store.lock(env.project, write=True):
            holding.set()
            released.wait(10)
            fixture.publish(1)

    def waiter():
        with exit_journal.session(env.project, write=False) as session:
            outcome["recovered"] = session.recovered

    t1 = threading.Thread(target=holder)
    t1.start()
    assert holding.wait(10)
    t2 = threading.Thread(target=waiter, name="waiter")
    t2.start()
    assert blocked.wait(10), "waiter never reached a blocked knowledge-lock acquisition"
    released.set()
    t1.join(10)
    t2.join(15)
    assert outcome["recovered"]["outcome"] == "completed"
    fixture.assert_completed()


def test_run_refuses_to_overwrite_a_pending_journal(env):
    """Unit: run() never replaces an existing exits/journal.json (checked under the lock)."""
    fixture = JournalFixture(env, "deactivate")
    fixture.publish(0)
    before = files(env.project)
    with store.lock(env.project, write=True), durable.Tree(env.project) as tree:
        with pytest.raises((store.StoreError, OSError, exit_journal.JournalInvalid)):
            exit_journal.run(tree, fixture.journal)
    assert files(env.project) == before


# --------------------------------------------------------------------------- 2. 001-B journal names
def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hostile_journal(env, kind: str, listed: str):
    """Arrange a per-rule commit journal naming a file outside the rule folder; return canary dir."""
    outside = env.work / "outside-canary"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_bytes(b"must never change")
    (outside / "victim.txt.new").write_bytes(b"attacker bytes")
    folder = env.folder()
    if kind == "absolute":
        name = str(victim)
    elif kind == "dotdot":
        name = os.path.relpath(victim, folder)
    else:
        need_symlinks(env.work)
        (folder / "sub").symlink_to(outside, target_is_directory=True)
        name = "sub/victim.txt"
    journal = {"rule": R1, "base_digest": None, "new_digest": None, "replace": [], "delete": []}
    if listed == "delete":
        journal["delete"] = [name]
    else:
        journal["replace"] = [{"file": name, "sha256": _sha(b"attacker bytes")}]
    (folder / store.JOURNAL).write_bytes(dumps_json(journal))
    return outside


KINDS = [(k, listed) for k in ("absolute", "dotdot", "nested_link") for listed in ("delete", "replace")]


@POSIX
@pytest.mark.parametrize("kind,listed", KINDS)
def test_exit_never_follows_hostile_commit_journal_names(env, kind, listed):
    outside = _hostile_journal(env, kind, listed)
    canary, before = files(outside), files(env.project)
    preview = env.preview()
    digest = preview.data["impact_digest"] if preview.ok else "sha256:" + "0" * 64
    result = env.confirm(digest)
    refusal(result, "RULE_INCONSISTENT")
    assert files(outside) == canary
    assert files(env.project) == before


@POSIX
@pytest.mark.parametrize("kind,listed", KINDS)
def test_recover_at_rejects_names_before_any_io(env, kind, listed):
    outside = _hostile_journal(env, kind, listed)
    canary, before = files(outside), files(env.project)
    with durable.Tree(env.project) as tree, pytest.raises(store.StoreError) as caught:
        store.recover_at(tree, RuleRef.parse(R1))
    assert caught.value.code == "RULE_INCONSISTENT"
    assert files(outside) == canary
    assert files(env.project) == before


@POSIX
@pytest.mark.parametrize("kind,listed", KINDS)
def test_path_based_recovery_rejects_hostile_names(env, kind, listed):
    """The pre-existing path-based `store.recover` (update/import) shares the validation."""
    outside = _hostile_journal(env, kind, listed)
    canary, before = files(outside), files(env.project)
    with pytest.raises(store.StoreError) as caught:
        store.recover(env.project, RuleRef.parse(R1))
    assert caught.value.code == "RULE_INCONSISTENT"
    updated = env.update(R1, env.show().data["item_digest"] or "sha256:" + "0" * 64, content="x\n")
    refusal(updated, "RULE_INCONSISTENT")
    assert files(outside) == canary
    assert files(env.project) == before


# --------------------------------------------------------------------------- 3. missing journal keys
@pytest.mark.parametrize("missing", [
    "pre_state_pending", "pre_state_index_edges", "write_before", "remove_before", "append_before", "text",
])
@pytest.mark.parametrize("action", ["delete", "rename"])
def test_missing_journal_keys_are_invalid_not_traceback(env, missing, action):
    fixture = JournalFixture(env, action)
    journal = fixture.journal
    by_op = {s["op"]: s for s in journal["steps"]}
    if missing.startswith("pre_state"):
        del journal["pre_state"][missing.removeprefix("pre_state_")]
    elif missing == "text":
        del by_op["write"]["text"]
    else:
        op = missing.removesuffix("_before")
        if op not in by_op:
            pytest.skip(f"{action} has no {op} step")
        del by_op[op]["before"]
    (env.project / JOURNAL).parent.mkdir(parents=True, exist_ok=True)
    (env.project / JOURNAL).write_bytes(dumps_json(journal))
    before = files(env.project)
    listed = service.list_rules(str(env.project))
    refusal(listed, "EXIT_JOURNAL_INVALID", step="Maintainer")
    resolved = policy.resolve_policies(str(env.project), [R1], False, [])
    refusal(resolved, "EXIT_JOURNAL_INVALID", step="Maintainer")
    assert files(env.project) == before


def test_cli_list_with_missing_key_is_an_envelope(env):
    fixture = JournalFixture(env, "delete")
    del fixture.journal["pre_state"]["pending"]
    (env.project / JOURNAL).parent.mkdir(parents=True, exist_ok=True)
    (env.project / JOURNAL).write_bytes(dumps_json(fixture.journal))
    cli = run_cli(["knowledge", "list", "--project", str(env.project), "--json"], env.trust)
    assert cli.returncode == 1, cli.stdout + cli.stderr
    assert json.loads(cli.stdout)["problems"][0]["code"] == "EXIT_JOURNAL_INVALID"
    assert "Traceback" not in cli.stderr


# --------------------------------------------------------------------------- 2b. writer names stay valid
def _crashed_update(env, changes):
    """Arrange a real 001-B update interrupted after its commit journal (commit point)."""
    base = env.show().data["state_digest"]
    path = env.req({"schema": "ai-secure-code-toolkit/knowledge-update/v1", **changes})
    crashed = run_cli(
        ["knowledge", "update", "--project", str(env.project), "--rule", R1, "--base-state", base,
         "--input", path, "--json"],
        env.trust, env_extra={"SECURE_CODE_TEST_CRASH_AT": "after_journal"},
    )
    assert crashed.returncode == 86, crashed.stdout + crashed.stderr
    assert (env.folder() / store.JOURNAL).exists()


@pytest.mark.parametrize("lang", ["c#", "f#"])
def test_interrupted_commit_with_hash_example_rolls_forward_path_based(env, lang):
    """Regression of fix 2: `example-<LANG>.md` names produced by the writer (batch.LANG allows `#`)."""
    _crashed_update(env, {"examples": {lang: f"{lang} example.\n"}})
    shown = env.show()
    assert shown.ok and shown.data["consistent"] is True and shown.data["pending_commit"] is True
    assert shown.data["examples"][f"example-{lang}.md"] == f"{lang} example.\n"
    listed = {r["rule"]: r for r in service.list_rules(str(env.project)).data["rules"]}
    assert listed[R1]["consistent"] is True
    updated = env.update(R1, shown.data["state_digest"], content="After recovery.\n")
    assert updated.ok, updated.to_dict()
    assert not (env.folder() / store.JOURNAL).exists()
    assert not list(env.folder().glob("*.new"))
    assert (env.folder() / f"example-{lang}.md").read_text() == f"{lang} example.\n"


@pytest.mark.parametrize("lang", ["c#", "f#"])
def test_interrupted_commit_with_hash_example_rolls_forward_in_exit(env, lang):
    _crashed_update(env, {"examples": {lang: f"{lang} example.\n"}})
    preview = env.preview()
    assert preview.ok, preview.to_dict()
    result = env.confirm(preview.data["impact_digest"])
    assert result.ok, result.to_dict()
    assert not (env.folder() / store.JOURNAL).exists()
    assert not list(env.folder().glob("*.new"))
    assert (env.folder() / f"example-{lang}.md").read_text() == f"{lang} example.\n"
    assert json.loads((env.folder() / "record.json").read_text())["lifecycle"]["state"] == "deactivated"


def test_interrupted_commit_deleting_a_visible_extra_file_rolls_forward(env):
    """`_write_rule` deletes every visible stored file that the new item no longer has."""
    (env.folder() / "my notes.txt").write_text("hand-added\n")
    _crashed_update(env, {"content": "Without the extra file.\n"})
    journal = json.loads((env.folder() / store.JOURNAL).read_text())
    assert "my notes.txt" in journal["delete"]
    assert env.show().data["consistent"] is True
    updated = env.update(R1, env.show().data["state_digest"], content="After recovery.\n")
    assert updated.ok, updated.to_dict()
    assert not (env.folder() / "my notes.txt").exists()
    assert not (env.folder() / store.JOURNAL).exists()
