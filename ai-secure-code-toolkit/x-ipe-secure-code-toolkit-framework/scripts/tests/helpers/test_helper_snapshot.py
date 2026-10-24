"""FEATURE-002-F snapshot and target-version binding (AC-002F-04i, 04j, 04n; DEC-2 B own walker; M6)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import json
import os
import sys

import pytest
from helperhelp import (  # noqa: F401 - fixture reuse
    GUARD,
    env,
    fake,
    flow,
    helper_run,
    henv,
    mod,
    state_of,
)

from x_ipe_secure_code.guard import targets


def artifact(root, *paths):
    return {
        "targets": [
            {"path": p, "kind": targets.kind_of(root, p, "t"), "digest": targets.observe(root, p)["digest"]}
            for p in paths
        ],
        "context": [],
        "copilot_reports": [],
    }


def build(root, art, scope, objects=None, dest=None, should_stop=lambda: False):
    dest = dest or root.parent / f"stage-{len(list(root.parent.iterdir()))}"
    return mod("snapshot").build(root, art, scope, objects or scope, dest, should_stop, 1e18), dest


def refused(fn, code):
    with pytest.raises(mod("snapshot").SnapshotRefused) as exc:
        fn()
    assert exc.value.code == code, exc.value.reason
    return exc.value


# ---------- AC-002F-04i
def test_04i_target_changed_since_open(flow):
    vid = helper_run(flow.env)
    hid = flow.submit(vid).data["helper"]
    (flow.root / "src" / "config" / "db.yaml").write_text("host: other\n")
    current = targets.observe(flow.root, "src")["digest"]
    out = flow.review(vid, hid, reviewed_targets=[{"path": "src", "digest": current}])
    assert out.ok, out.to_text()
    assert flow.grant(vid).ok
    run = flow.run(vid, hid, flow.helper_attempt(vid))
    assert (
        run.data["reason_code"] == "target_changed" and "target changed since open" in run.problems[0].message
    )
    assert not flow.fake.creates("sample")


def test_04i_manifest_bound(flow):
    vid, hid, out = flow.executed()
    h = next(h for h in state_of(flow.env, vid)["helpers"] if h["id"] == hid)
    run = h["runs"][0]
    manifest = json.loads((flow.root / GUARD / vid / run["manifest"]["file"]).read_text())
    assert manifest["digest"] == run["manifest"]["digest"] and manifest["purpose"] == "target"
    for f in manifest["files"]:
        data = (flow.root / f["path"]).read_bytes()
        assert f["size"] == len(data) and f["sha256"] == mod("model").sha(data)
    assert [f["path"] for f in manifest["files"]] == ["src/config/app.yaml", "src/config/db.yaml"]
    assert manifest["targets"][0]["digest_at_open"] == manifest["targets"][0]["digest_staged"]
    events = {e["step"]: e for e in h["events"]}
    assert events["snapshot_built"]["manifest"] == run["manifest"]["digest"]
    attempt = next(a for a in state_of(flow.env, vid)["attempts"] if a["id"] == run["attempt"])
    assert attempt["status"] == "finished" and run["attempt"] == attempt["id"]


def test_dec2_walker_digest_parity_with_open(tmp_path):
    root = tmp_path / "proj"
    t = root / "t"
    (t / "sub").mkdir(parents=True)
    (t / "sub" / "a.txt").write_text("a")
    (t / "b.txt").write_text("b")
    (t / ".git").mkdir()
    (t / ".git" / "x").write_text("x")
    os.symlink("b.txt", t / "inside-link")
    os.symlink("/etc/hosts", t / "outside-link")
    os.symlink("missing", t / "dangling")
    os.mkfifo(t / "fifo")
    (t / "locked.txt").write_text("secret")
    os.chmod(t / "locked.txt", 0)
    if sys.platform != "darwin":
        (t / os.fsdecode(b"bad\xff.txt")).write_text("x")
    try:
        art = artifact(root, "t")
        parts, dest = build(root, art, ["t/sub"], ["t"])
        assert parts["targets"][0]["digest_staged"] == targets.snapshot(root, "t", "dir")["digest"]
        assert [f["path"] for f in parts["files"]] == ["t/sub/a.txt"]
        assert (dest / "t" / "sub" / "a.txt").read_text() == "a"
        assert not (dest / "t" / "b.txt").exists()
        file_art = artifact(root, "t/b.txt")
        parts, _ = build(root, file_art, ["t/b.txt"])
        assert parts["targets"][0]["digest_staged"] == targets.snapshot(root, "t/b.txt", "file")["digest"]
        refused(lambda: build(root, art, ["t"]), "snapshot_unsafe")
    finally:
        os.chmod(t / "locked.txt", 0o600)


def test_07c_object_entries_seen_but_not_coverable(tmp_path):
    """DAO-005 (2): every non-excluded check-object entry outside the read scope that cannot be copied
    (unreadable, FIFO, link, non-UTF-8 name) is still an object entry, so it can only be uncovered."""
    root = tmp_path / "proj"
    src = root / "src"
    src.mkdir(parents=True)
    (src / "a.py").write_text("a = 1\n")
    (src / "b.py").write_text("b = 2\n")
    os.chmod(src / "b.py", 0)
    os.mkfifo(src / "c.fifo")
    os.symlink("a.py", src / "d.py")
    (src / ".git").mkdir()
    (src / ".git" / "x").write_text("x")
    expected = ["src/a.py", "src/b.py", "src/c.fifo", "src/d.py"]
    if sys.platform != "darwin":
        (src / os.fsdecode(b"e\xff.py")).write_text("e")
        expected.append(targets.display_name("src/" + os.fsdecode(b"e\xff.py")))
    try:
        parts, _ = build(root, artifact(root, "src"), ["src/a.py"], ["src"])
        assert [f["path"] for f in parts["files"]] == ["src/a.py"]
        assert parts["object_files"]["files"] == sorted(expected)
        assert parts["object_files"]["count"] == len(expected)
        assert parts["targets"][0]["digest_staged"] == parts["targets"][0]["digest_at_open"]
        os.symlink(".", src / "ld")
        parts, _ = build(root, artifact(root, "src"), ["src/a.py"], ["src/ld/a.py"])
        assert parts["object_files"]["files"] == ["src/ld"]
    finally:
        os.chmod(src / "b.py", 0o600)


def test_07c_unreadable_object_folder_refused_not_omitted(tmp_path):
    """An unreadable folder under the check object is never silently skipped: the snapshot refuses
    (fail closed, like the delivered `targets.stage`), so no clean result can claim coverage."""
    root = tmp_path / "proj"
    (root / "src" / "locked").mkdir(parents=True)
    (root / "src" / "a.py").write_text("a = 1\n")
    (root / "src" / "locked" / "x.py").write_text("x = 1\n")
    os.chmod(root / "src" / "locked", 0)
    try:
        refused(lambda: build(root, artifact(root, "src"), ["src/a.py"], ["src"]), "snapshot_unsafe")
    finally:
        os.chmod(root / "src" / "locked", 0o700)


# ---------- AC-002F-04j
def test_04j_swap_to_symlink_during_copy(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    (root / "t").mkdir(parents=True)
    (root / "t" / "a.txt").write_text("a")
    (root / "t" / "b.txt").write_text("b")
    art = artifact(root, "t")
    snapshot = mod("snapshot")
    real = snapshot.safe_io.copy_hash

    def racing(fd, dest, limit, mode=0o600):
        victim = root / "t" / "b.txt"
        if victim.is_file() and not victim.is_symlink():
            victim.unlink()
            os.symlink("/etc/passwd", victim)
        return real(fd, dest, limit, mode)

    monkeypatch.setattr(snapshot.safe_io, "copy_hash", racing)
    error = refused(lambda: build(root, art, ["t"]), "snapshot_unsafe")
    assert "b.txt" in error.reason


def test_m6_cancel_during_walk(tmp_path):
    root = tmp_path / "proj"
    (root / "t").mkdir(parents=True)
    for i in range(5):
        (root / "t" / f"{i}.txt").write_text(str(i))
    calls = []

    def stop():
        calls.append(1)
        return len(calls) > 2

    refused(lambda: build(root, artifact(root, "t"), ["t"], should_stop=stop), "cancelled")
    assert len(calls) == 3


def test_m6_small_scope_large_target(tmp_path):
    root = tmp_path / "proj"
    (root / "t" / "small").mkdir(parents=True)
    (root / "t" / "small" / "x.txt").write_text("x")
    big = root / "t" / "big"
    big.mkdir()
    for i in range(2500):
        (big / f"{i}.txt").write_text(str(i))
    parts, _ = build(root, artifact(root, "t"), ["t/small"])
    assert (
        len(parts["files"]) == 1
        and parts["targets"][0]["digest_staged"] == parts["targets"][0]["digest_at_open"]
    )


def test_m6_owning_target_beyond_002b_bounds(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    (root / "t" / "small").mkdir(parents=True)
    (root / "t" / "small" / "x.txt").write_text("x")
    for i in range(10):
        (root / "t" / f"{i}.txt").write_text(str(i))
    monkeypatch.setattr(mod("snapshot"), "MAX_STAGE_FILES", 5)
    refused(lambda: build(root, artifact(root, "t"), ["t/small"]), "target_too_large")
