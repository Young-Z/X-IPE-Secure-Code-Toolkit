"""NFR-001D-1 and AC-03h/06a: no-follow handles and durable transaction integration.

Arrange project-local outside canaries / real exits; Act path swaps, OS failures
and primitives; Assert no outside read/write, correct fsync order and recoverable
IO_ERROR, never false success. Primitive tests are explicitly supplemental units.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
from pathlib import Path

import pytest
from conftest import run_cli
from knowledge.exithelp import (
    EXITS,
    JOURNAL,
    R1,
    STEPS,
    TARGET,
    Env,
    cleanup,
    files,
    finish,
    module,
    need_symlinks,
    refusal,
    wait_ready,
)
from knowledge.exitjournalhelp import JournalFixture

from x_ipe_secure_code.knowledge import service, store
from x_ipe_secure_code.policy import scope

POSIX = pytest.mark.skipif(os.name != "posix", reason="dir_fd / O_NOFOLLOW contract is POSIX-specific")


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate(rich=True)
    return result


CANARIES = [
    "namespace", "version", "source", "target_parent", "exits", "journal", "memory", "transitions",
    "tombstones", "pending_root", "pending_file", "index", "lock_parent", "knowledge_lock",
    "scope_lock", "scopes", "guard_root", "copilot_root", "guard_entry", "copilot_entry",
]


@pytest.mark.parametrize("component", CANARIES)
def test_named_path_symlink_canary(env, component):
    need_symlinks(env.work)
    env.pending()
    saved = env.save()
    vid, cid = env.open_runs(saved.data["scope_id"])
    action = "delete" if component == "tombstones" else "rename"
    rename_target = TARGET if action == "rename" else None
    preview = env.preview(action, target=rename_target)
    assert preview.ok
    paths = {
        "namespace": store.LOCAL_REL + "/CWE", "version": store.LOCAL_REL + "/CWE/4.14",
        "source": store.LOCAL_REL + "/" + R1, "target_parent": store.LOCAL_REL + "/CWE/4.14",
        "exits": EXITS, "journal": JOURNAL, "memory": EXITS + "/memory.json",
        "transitions": EXITS + "/transitions.json", "tombstones": EXITS + "/tombstones",
        "pending_root": store.PENDING_REL, "pending_file": store.PENDING_REL + "/" + R1 + ".json",
        "index": store.INDEX_REL, "lock_parent": str(Path(store.LOCK_REL).parent),
        "knowledge_lock": store.LOCK_REL, "scope_lock": scope.SCOPE_LOCK_REL,
        "scopes": scope.SCOPES_REL, "guard_root": ".x-ipe/private/secure-code/guard",
        "copilot_root": ".x-ipe/private/secure-code/copilot",
        "guard_entry": ".x-ipe/private/secure-code/guard/" + vid,
        "copilot_entry": ".x-ipe/private/secure-code/copilot/" + cid,
    }
    path = env.project / paths[component]
    directory = component not in {
        "journal", "memory", "transitions", "pending_file", "index", "knowledge_lock", "scope_lock",
    }
    outside = env.work / "outside-canary"
    outside.mkdir()
    (outside / "keep").write_bytes(b"must never change")
    target = outside if directory else outside / "keep"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.move(str(path), str(env.work / "original-component"))
    path.symlink_to(target, target_is_directory=directory)
    canary = files(outside)
    before = files(env.project)
    if component.endswith("_entry"):
        result = env.preview("rename", target=TARGET)
        assert result.ok, result.to_dict()
        kind = "guard_runs" if component == "guard_entry" else "copilot_collaborations"
        assert result.data["impact"][kind]["unreadable"]
    else:
        result = env.confirm(preview.data["impact_digest"], action, target=rename_target)
        refusal(result, "PATH_UNSAFE")
    assert files(outside) == canary
    assert files(env.project) == before


def test_tombstone_folder_link_during_recovery_never_followed(env):
    need_symlinks(env.work)
    fixture = JournalFixture(env, "delete")
    fixture.publish(1)
    outside = env.work / "tombstone-canary"
    outside.mkdir()
    (outside / "rule").mkdir()
    (outside / "keep").write_bytes(b"canary")
    fixture.tomb.rmdir()
    fixture.tomb.symlink_to(outside, target_is_directory=True)
    before, canary = files(env.project), files(outside)
    refusal(service.list_rules(str(env.project)), "PATH_UNSAFE")
    assert files(env.project) == before
    assert files(outside) == canary


@POSIX
@pytest.mark.parametrize("when", ["before_open", "after_open"])
def test_tree_component_swap_uses_no_follow_handles(env, when):
    """Unit: held descriptor never redirects to a replacement symlink."""
    need_symlinks(env.work)
    durable = module("durable")
    parent = env.project / "handle-parent"
    parent.mkdir()
    (parent / "value").write_bytes(b"original")
    outside = env.work / "swap-canary"
    outside.mkdir()
    (outside / "value").write_bytes(b"outside")
    original = files(outside)
    tree = durable.Tree(env.project)
    fd = None
    try:
        if when == "after_open":
            fd = tree.dir("handle-parent")
        parent.rename(env.project / "held-original")
        parent.symlink_to(outside, target_is_directory=True)
        if when == "before_open":
            with pytest.raises((store.StoreError, OSError)) as caught:
                tree.dir("handle-parent")
            if isinstance(caught.value, store.StoreError):
                assert caught.value.code == "PATH_UNSAFE"
        else:
            assert durable.read(fd, "value") == b"original"
            durable.write(fd, "value", b"held handle only", ".exit-handle.write.tmp")
            assert (env.project / "held-original/value").read_bytes() == b"held handle only"
        assert files(outside) == original
    finally:
        if fd is not None:
            os.close(fd)
        tree.close()


@POSIX
def test_tree_lock_parent_swap_after_open_cannot_lock_outside(env):
    """Unit: DirLock walks under the Tree root, not an already-swapped path."""
    need_symlinks(env.work)
    durable = module("durable")
    parent = env.project / "lock-parent"
    parent.mkdir()
    outside = env.work / "lock-canary"
    outside.mkdir()
    tree = durable.Tree(env.project)
    try:
        parent.rename(env.project / "original-lock-parent")
        parent.symlink_to(outside, target_is_directory=True)
        with pytest.raises((store.StoreError, OSError)):
            with durable.DirLock(tree, "lock-parent/lock", create=True, timeout=0.1):
                pytest.fail("lock followed swapped parent")
        assert files(outside) == {}
    finally:
        tree.close()


@POSIX
def test_write_primitive_fsyncs_file_then_replace_then_parent(env, monkeypatch):
    """Unit: durable write order and descriptor-relative replace."""
    durable = module("durable")
    tree = durable.Tree(env.project)
    fd = tree.dir("primitive", create=True)
    events = []
    real_fsync, real_replace = os.fsync, os.replace

    def sync(handle):
        events.append("dir" if stat.S_ISDIR(os.fstat(handle).st_mode) else "file")
        return real_fsync(handle)

    def replace_file(src, dst, **kwargs):
        events.append("replace")
        assert kwargs["src_dir_fd"] == fd
        assert kwargs["dst_dir_fd"] == fd
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "replace", replace_file)
    try:
        durable.write(fd, "value", b"durable", ".exit-test.value.tmp")
        assert events == ["file", "replace", "dir"]
        assert stat.S_IMODE((env.project / "primitive/value").stat().st_mode) == 0o600
    finally:
        os.close(fd)
        tree.close()


@POSIX
def test_mkdir_move_unlink_fsync_containing_directories(env, monkeypatch):
    """Unit: mkdir parents, move destination then source, unlink parent durability."""
    durable = module("durable")
    tree = durable.Tree(env.project)
    events = []
    real_fsync, real_mkdir, real_rename, real_unlink = os.fsync, os.mkdir, os.rename, os.unlink

    def sync(fd):
        events.append(("fsync", fd))
        return real_fsync(fd)

    def mkdir(path, mode=0o777, **kwargs):
        events.append(("mkdir", kwargs.get("dir_fd")))
        return real_mkdir(path, mode, **kwargs)

    def rename(src, dst, **kwargs):
        events.append(("rename", kwargs["dst_dir_fd"], kwargs["src_dir_fd"]))
        return real_rename(src, dst, **kwargs)

    def unlink(path, **kwargs):
        events.append(("unlink", kwargs["dir_fd"]))
        return real_unlink(path, **kwargs)

    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "mkdir", mkdir)
    monkeypatch.setattr(os, "rename", rename)
    monkeypatch.setattr(os, "unlink", unlink)
    src = dst = None
    try:
        src = tree.dir("durable-source/nested", create=True)
        dst = tree.dir("durable-destination", create=True)
        for i, event in enumerate(events):
            if event[0] == "mkdir":
                assert events[i + 1] == ("fsync", event[1])
        os.mkdir("moving", dir_fd=src)
        events.clear()
        durable.move(src, "moving", dst, "moved")
        assert events == [("rename", dst, src), ("fsync", dst), ("fsync", src)]
        durable.write(dst, "remove", b"x", ".exit-test.remove.tmp")
        events.clear()
        durable.unlink(dst, "remove")
        assert events == [("unlink", dst), ("fsync", dst)]
    finally:
        for fd in (src, dst):
            if fd is not None:
                os.close(fd)
        tree.close()


@POSIX
@pytest.mark.parametrize("action", list(STEPS))
def test_journal_steps_and_removal_durable_before_success(env, monkeypatch, action):
    env.pending()
    if action == "reactivate":
        env.exit("deactivate")
    events = []
    fsync, replace, rename, unlink = os.fsync, os.replace, os.rename, os.unlink

    def sync(fd):
        events.append(("sync", "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"))
        return fsync(fd)

    def replaced(src, dst, **kwargs):
        events.append(("replace", Path(dst).name))
        return replace(src, dst, **kwargs)

    def moved(src, dst, **kwargs):
        events.append(("move", Path(src).name))
        return rename(src, dst, **kwargs)

    def removed(path, **kwargs):
        events.append(("unlink", Path(path).name))
        return unlink(path, **kwargs)

    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "replace", replaced)
    monkeypatch.setattr(os, "rename", moved)
    monkeypatch.setattr(os, "unlink", removed)
    result = env.exit(action)
    events.append(("result", result.ok))
    start = events.index(("replace", "journal.json"))
    assert events[start + 1] == ("sync", "dir")
    first_step = next(i for i, e in enumerate(events[start + 2:], start + 2)
                      if e[0] in ("replace", "move", "unlink"))
    assert first_step > start + 1
    for i, event in enumerate(events):
        if event[0] in ("replace", "unlink", "move"):
            assert events[i + 1] == ("sync", "dir"), event
    end = events.index(("unlink", "journal.json"))
    assert events[end + 1:] == [("sync", "dir"), ("result", True)]


WRITE_STEPS = {
    "deactivate": ["journal", "record", "changelog", "index", "transitions"],
    "reactivate": ["journal", "record", "changelog", "transitions"],
    "delete": ["journal", "tombstone_record", "index", "memory", "transitions"],
    "rename": ["journal", "record", "changelog", "index", "memory", "transitions"],
}
FAILURES = [(a, s, p) for a, steps in WRITE_STEPS.items() for s in steps
            for p in ("temp_fsync", "replace", "dir_fsync")]


@POSIX
@pytest.mark.parametrize("action,step,primitive", FAILURES)
def test_write_failure_at_each_action_step_never_success(env, monkeypatch, action, step, primitive):
    """Integration: inject inside real durable primitives; next command must recover."""
    env.pending()
    if action == "reactivate":
        env.exit("deactivate")
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    durable = module("durable")
    names = {
        "journal": "journal.json", "record": "record.json", "changelog": "changelog.md",
        "index": "knowledge-documents.json", "memory": "memory.json",
        "transitions": "transitions.json", "tombstone_record": "exit-record.json",
    }
    active = {"target": False, "failed": False}
    real_write, real_fsync, real_replace = durable.write, os.fsync, os.replace

    def fail_once():
        if active["target"] and not active["failed"]:
            active["failed"] = True
            raise OSError(errno.EIO, f"injected {primitive}:{step}")

    def write(fd, name, data, tmp):
        active["target"] = name == names[step]
        try:
            return real_write(fd, name, data, tmp)
        finally:
            active["target"] = False

    def sync(fd):
        is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
        if (primitive == "dir_fsync" and is_dir) or (primitive == "temp_fsync" and not is_dir):
            fail_once()
        return real_fsync(fd)

    def replace_file(src, dst, **kwargs):
        if primitive == "replace":
            fail_once()
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(durable, "write", write)
    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "replace", replace_file)
    result = env.confirm(preview.data["impact_digest"], action, target=target)
    assert active["failed"], f"requested fault site {primitive}:{step} was not exercised"
    refusal(result, "IO_ERROR")
    assert result.data.get("outcome") not in ("deactivated", "reactivated", "deleted", "renamed")
    recovered = service.list_rules(str(env.project))
    assert recovered.ok, recovered.to_dict()
    assert not (env.project / JOURNAL).exists()
    if step != "journal" or primitive == "dir_fsync":
        transitions = json.loads((env.project / EXITS / "transitions.json").read_text())
        assert transitions["entries"][-1]["action"] == action


@pytest.mark.parametrize("action,site", [
    ("delete", "pending"), ("rename", "pending"),
    *[(a, "journal") for a in STEPS], ("delete", "move"), ("rename", "move"),
])
def test_unlink_move_and_final_journal_failure_retries(env, monkeypatch, action, site):
    env.pending()
    if action == "reactivate":
        env.exit("deactivate")
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    durable = module("durable")
    method = "move" if site == "move" else "unlink"
    real = getattr(durable, method)
    failed = []

    def injected(*args, **kwargs):
        matches = method == "move" or args[1] == ("journal.json" if site == "journal" else "CWE-79.json")
        if matches and not failed:
            failed.append(True)
            raise OSError(errno.EIO, "injected mutation failure")
        return real(*args, **kwargs)

    monkeypatch.setattr(durable, method, injected)
    result = env.confirm(preview.data["impact_digest"], action, target=target)
    assert failed
    refusal(result, "IO_ERROR")
    assert (env.project / JOURNAL).exists()
    assert service.list_rules(str(env.project)).ok
    assert not (env.project / JOURNAL).exists()
    transitions = json.loads((env.project / EXITS / "transitions.json").read_text())
    assert transitions["entries"][-1]["action"] == action


def test_exdev_after_journal_delete_move_rolls_back_narrowly(env, monkeypatch):
    fixture = JournalFixture(env, "delete")
    fixture.publish(1)
    original = files(env.folder())
    durable = module("durable")

    def exdev(*args, **kwargs):
        raise OSError(errno.EXDEV, "injected cross-device tombstone")

    monkeypatch.setattr(durable, "move", exdev)
    result = service.list_rules(str(env.project))
    assert result.ok, result.to_dict()
    assert result.data["recovered_exit"]["outcome"] == "rolled_back"
    assert files(env.folder()) == original
    assert not fixture.tomb.exists()
    assert not (env.project / JOURNAL).exists()
    assert not (env.project / EXITS / "memory.json").exists()


@POSIX
def test_exdev_detected_before_journal_does_not_change_knowledge(env, monkeypatch):
    env.save()
    (env.project / EXITS / "tombstones").mkdir(parents=True, exist_ok=True)
    preview = env.preview("delete")
    assert preview.ok
    before = files(env.project)
    public_inodes = {
        p.stat().st_ino for p in [env.project, *env.project.rglob("*")]
        if p.is_dir() and not p.is_relative_to(env.project / ".x-ipe")
    }
    real = os.fstat

    def other_device(fd):
        found = real(fd)
        if stat.S_ISDIR(found.st_mode) and found.st_ino not in public_inodes:
            fields = list(found)
            fields[2] = found.st_dev + 1
            return os.stat_result(fields)
        return found

    monkeypatch.setattr(os, "fstat", other_device)
    refusal(env.confirm(preview.data["impact_digest"], "delete"), "IO_ERROR")
    assert not (env.project / JOURNAL).exists()
    assert files(env.project) == before


def test_unlistable_corrupt_subfolder_is_not_metadata_only(env, monkeypatch):
    (env.folder() / "content.md").write_bytes(b"\xff")
    sub = env.folder() / ".private-residue"
    sub.mkdir()
    (sub / "hidden").write_bytes(b"bytes must bind")
    inode = sub.stat().st_ino
    before = files(env.project)
    real = os.scandir

    def denied(path):
        if (isinstance(path, int) and os.fstat(path).st_ino == inode) or path == sub:
            raise PermissionError("unlistable folder")
        return real(path)

    with monkeypatch.context() as patch:
        patch.setattr(os, "scandir", denied)
        refusal(env.preview("delete"), "RULE_FOLDER_UNREADABLE")
    assert files(env.project) == before


SWAPS = {
    "rule_parent": store.LOCAL_REL + "/CWE/4.14",
    "pending_root": store.PENDING_REL,
    "pending_parent": store.PENDING_REL + "/CWE/4.14",
}


def swap_for_link(env, rel):
    """Move a real component aside (inside the project, outside toolkit paths) and link an outside copy."""
    path = env.project / rel
    held = env.project / ".held-original"
    outside = env.work / "outside-canary"
    os.rename(path, held)
    shutil.copytree(held, outside, symlinks=True)
    path.symlink_to(outside, target_is_directory=True)
    return held, outside


@POSIX
@pytest.mark.parametrize("component,action", [
    ("rule_parent", "deactivate"), ("rule_parent", "delete"), ("rule_parent", "rename"),
    ("pending_root", "delete"), ("pending_parent", "delete"), ("pending_parent", "rename"),
])
def test_parent_swapped_after_tree_opened_never_followed(env, component, action):
    """NFR-001D-1 Integration: a parent becomes a link at exit_locked, after the confirm opened
    its Tree and locks. Either PATH_UNSAFE (in-root pending link: unreadable -> STALE_IMPACT)
    with nothing written, or the original handle was used; never any outside read/write."""
    need_symlinks(env.work)
    env.pending()
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    assert preview.ok, preview.to_dict()
    barrier = env.work / "swap-barrier"
    exiting = env.spawn(
        env.cli_args(action, preview.data["impact_digest"]),
        SECURE_CODE_TEST_PAUSE_AT="exit_locked=" + str(barrier),
    )
    try:
        wait_ready(exiting, barrier)
        held, outside = swap_for_link(env, SWAPS[component])
        held_before, canary, before = files(held), files(outside), files(env.project)
        barrier.with_suffix(".go").touch()
        result = finish(exiting)
    finally:
        cleanup(exiting)
    assert files(outside) == canary, "an outside canary was written, moved or removed"
    if result["ok"]:
        if component == "rule_parent":
            if action == "deactivate":
                record = json.loads((held / "CWE-79/record.json").read_text())
                assert record["lifecycle"]["state"] == "deactivated"
            else:
                assert not (held / "CWE-79").exists()
            if action == "rename":
                assert (held / TARGET.split("/")[-1]).is_dir()
        else:
            pending = held / ("CWE-79.json" if component == "pending_parent" else R1 + ".json")
            assert not pending.exists(), "pending removal did not use the original handle"
    else:
        allowed = {"PATH_UNSAFE", "STALE_IMPACT"} if component == "pending_parent" else {"PATH_UNSAFE"}
        assert result["problems"][0]["code"] in allowed, result
        assert len(result["next_steps"]) == 1, result
        assert files(held) == held_before
        assert files(env.project) == before
        assert not (env.project / JOURNAL).exists()


@POSIX
def test_rule_swap_before_handle_relative_commit_recovery_never_writes_outside(env):
    """AC-03h/NFR-001D-1 (design v1.1 D1): a pending 001-B per-rule commit journal makes
    exit-confirm run store.recover_at; the rule folder becomes a link at exit_locked (Tree open,
    before recovery). Recovery must never replace/unlink outside; PATH_UNSAFE or original handle."""
    need_symlinks(env.work)
    base = env.show().data["item_digest"]
    update = env.req({
        "schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": "Interrupted update.\n",
    })
    crashed = run_cli(
        ["knowledge", "update", "--project", str(env.project), "--rule", R1, "--base-state", base,
         "--input", update, "--json"],
        env.trust, env_extra={"SECURE_CODE_TEST_CRASH_AT": "after_journal"},
    )
    assert crashed.returncode == 86, crashed.stdout + crashed.stderr
    assert (env.folder() / store.JOURNAL).exists()
    assert list(env.folder().glob("*.new"))
    preview = env.preview()
    assert preview.ok, preview.to_dict()
    barrier = env.work / "recover-barrier"
    exiting = env.spawn(
        env.cli_args("deactivate", preview.data["impact_digest"]),
        SECURE_CODE_TEST_PAUSE_AT="exit_locked=" + str(barrier),
    )
    try:
        wait_ready(exiting, barrier)
        held, outside = swap_for_link(env, store.LOCAL_REL + "/" + R1)
        held_before, canary, before = files(held), files(outside), files(env.project)
        assert store.JOURNAL in canary and any(k.endswith(".new") for k in canary)
        barrier.with_suffix(".go").touch()
        result = finish(exiting)
    finally:
        cleanup(exiting)
    assert files(outside) == canary, "commit recovery followed the swapped rule folder"
    if result["ok"]:
        assert not (held / store.JOURNAL).exists()
        assert (held / "content.md").read_bytes() == b"Interrupted update.\n"
        assert json.loads((held / "record.json").read_text())["lifecycle"]["state"] == "deactivated"
    else:
        assert result["problems"][0]["code"] == "PATH_UNSAFE", result
        assert files(held) == held_before
        assert files(env.project) == before
        assert not (env.project / JOURNAL).exists()


@pytest.mark.parametrize("action", ["deactivate", "rename", "delete"])
def test_confirm_rolls_forward_pending_commit_through_handle_then_exits(env, action):
    """AC-06a / design v1.1 D1, owner-authored: a crashed 001-B update leaves a per-rule commit
    journal. Arrange the crash after its journal (commit point); Act preview + confirm; Assert the
    confirm succeeds, the interrupted update is rolled forward by store.recover_at before the exit,
    no 001-B journal or staged file remains and the exit result reflects the recovered content."""
    base = env.show().data["item_digest"]
    update = env.req({
        "schema": "ai-secure-code-toolkit/knowledge-update/v1", "content": "Interrupted update.\n",
    })
    crashed = run_cli(
        ["knowledge", "update", "--project", str(env.project), "--rule", R1, "--base-state", base,
         "--input", update, "--json"],
        env.trust, env_extra={"SECURE_CODE_TEST_CRASH_AT": "after_journal"},
    )
    assert crashed.returncode == 86, crashed.stdout + crashed.stderr
    assert (env.folder() / store.JOURNAL).exists()
    target = TARGET if action == "rename" else None
    preview = env.preview(action, target=target)
    assert preview.ok, preview.to_dict()

    result = env.confirm(preview.data["impact_digest"], action, target=target)

    assert result.ok, result.to_dict()
    assert not (env.project / JOURNAL).exists()
    if action == "delete":
        assert not env.folder().exists()
        landed = env.project / result.data["tombstone"] / "rule"
    else:
        landed = env.folder(TARGET if action == "rename" else R1)
        assert action != "rename" or not env.folder().exists()
        record = json.loads((landed / "record.json").read_text())
        assert record["lifecycle"]["state"] == ("deactivated" if action == "deactivate" else "active")
        assert record["lifecycle"]["revision"] >= 1
    assert (landed / "content.md").read_bytes() == b"Interrupted update.\n"
    assert not (landed / store.JOURNAL).exists()
    assert not list(landed.glob("*.new"))
