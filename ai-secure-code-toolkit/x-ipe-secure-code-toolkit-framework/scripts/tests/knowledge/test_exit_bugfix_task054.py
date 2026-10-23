"""Bug Fix TASK-054: rename-target collision lookup must not follow swapped folders.

Source: AC-001D-03e/03h, NFR-001D-1/NFR-001D-4, design v1.3 "Locks and reads" / "Handle-based
reads" (prepare uses only the command's Tree) / Security / Edge Cases (component replaced by a
link → PATH_UNSAFE, nothing outside). Regression tests written RED before the fix.
"""

from __future__ import annotations

import os
import shutil

import pytest
from knowledge.exithelp import TARGET, Env, files, need_symlinks, refusal

from x_ipe_secure_code.knowledge import lifecycle, store

POSIX = pytest.mark.skipif(os.name != "posix", reason="dir_fd / O_NOFOLLOW contract is POSIX-specific")
# The local root and its ancestors were followed by the path-based lookup (RED before the fix);
# a swapped version entry was already skipped (link entries are not folders) and guards the boundary.
SWAPPED = {
    "local_root": store.LOCAL_REL,
    "knowledge_parent": store.LOCAL_REL.rpartition("/")[0],
    "version": store.LOCAL_REL + "/CWE/4.14",
}


@pytest.fixture
def env(project, tmp_path):
    result = Env(project, tmp_path)
    result.populate()
    return result


@POSIX
@pytest.mark.parametrize("component", list(SWAPPED))
@pytest.mark.parametrize("command", ["preview", "confirm"])
def test_fix_rename_target_collision_never_reads_a_swapped_folder(env, monkeypatch, command, component):
    """Arrange: outside copy of the swapped folder with a case variant of the rename target; the
    swap happens at the first exit-memory read, immediately before target validation (after the
    rule was read through the command's Tree). Act: rename preview/confirm. Assert: the outside
    folder is never listed, the refusal is PATH_UNSAFE, nothing outside or in the original changes."""
    need_symlinks(env.work)
    digest = None
    if command == "confirm":
        preview = env.preview("rename", target=TARGET)
        assert preview.ok, preview.to_dict()
        digest = preview.data["impact_digest"]
    rel = SWAPPED[component]
    outside = env.work / "outside-knowledge"
    shutil.copytree(env.project / rel, outside, symlinks=True)
    variant_parent = outside / os.path.relpath(store.LOCAL_REL + "/CWE/4.14", rel)
    (variant_parent / TARGET.split("/")[-1].lower()).mkdir()
    canary = files(outside)
    original = files(env.project / rel)
    held = env.work / "held-original"
    swapped: list[bool] = []
    real_read = lifecycle.read_memory

    def swap_then_read(tree):
        if not swapped:
            os.rename(env.project / rel, held)
            (env.project / rel).symlink_to(outside, target_is_directory=True)
            swapped.append(True)
        return real_read(tree)

    scanned: list[str] = []
    real_scandir = os.scandir

    def watched(path="."):
        if not isinstance(path, int):
            scanned.append(os.path.realpath(path))
        return real_scandir(path)

    monkeypatch.setattr(lifecycle, "read_memory", swap_then_read)
    monkeypatch.setattr(os, "scandir", watched)
    if command == "preview":
        result = env.preview("rename", target=TARGET)
    else:
        result = env.confirm(digest, "rename", target=TARGET)
    monkeypatch.setattr(os, "scandir", real_scandir)

    assert swapped, "the swap point was not reached"
    root = os.path.realpath(outside)
    assert [p for p in scanned if p == root or p.startswith(root + os.sep)] == []
    refusal(result, "PATH_UNSAFE")
    assert files(outside) == canary
    assert files(held) == original
