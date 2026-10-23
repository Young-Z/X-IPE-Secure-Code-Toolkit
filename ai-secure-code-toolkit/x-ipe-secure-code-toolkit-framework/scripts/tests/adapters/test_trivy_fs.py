"""Unit tests for the descriptor-based staging-root safety helpers (`adapters/trivy_fs.py`, AC-002D-04a).

They compose `knowledge/durable.py` (no-follow walks, `open_child`, `entry`, `listdir`, `readlink`,
`rmdir_empty`); swaps are injected through the `durable` module functions the helpers call.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

import pytest

from x_ipe_secure_code.knowledge import durable

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX descriptors")
STAGE_REL = ".x-ipe/private/secure-code/adapter-stage/trivy"
STAGE_PATTERN = r"^stage-[0-9a-f]{16}$"


def fs():
    from x_ipe_secure_code.adapters import trivy_fs

    return trivy_fs


@pytest.fixture
def root(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    tree = durable.Tree(project)
    yield {"project": project, "tree": tree, "outside": tmp_path / "outside"}
    tree.close()


def ident(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def fill(path: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_bytes(data)


@pytest.mark.parametrize("component", [".x-ipe", "private", "secure-code", "adapter-stage", "trivy"])
def test_symlinked_ancestor_refused(root, component):
    parts = STAGE_REL.split("/")
    upto = parts[: parts.index(component)]
    base = root["project"].joinpath(*upto) if upto else root["project"]
    base.mkdir(parents=True, exist_ok=True)
    root["outside"].mkdir()
    os.symlink(root["outside"], base / component)
    with pytest.raises(durable.StoreError) as exc:
        fs().open_root(root["tree"], STAGE_REL)
    assert exc.value.code == "PATH_UNSAFE"
    assert list(root["outside"].iterdir()) == []  # nothing created outside


def test_open_root_is_private(root):
    fd = fs().open_root(root["tree"], STAGE_REL)
    try:
        st = os.fstat(fd)
        assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == os.getuid()
    finally:
        os.close(fd)


def test_leaf_created_exclusively(root, monkeypatch):
    import secrets

    root_fd = fs().open_root(root["tree"], STAGE_REL)
    stage_root = root["project"] / STAGE_REL
    (stage_root / ("stage-" + "a" * 16)).mkdir()
    os.symlink(root["project"], stage_root / ("stage-" + "b" * 16))
    names = iter(["a" * 16, "b" * 16, "c" * 16])
    monkeypatch.setattr(secrets, "token_hex", lambda n=8: next(names))
    name, fd, identity = fs().make_leaf(root_fd, "stage-")
    try:
        assert name == "stage-" + "c" * 16 and re.fullmatch(STAGE_PATTERN, name)
        assert ident(os.fstat(fd)) == identity == ident(os.lstat(stage_root / name))
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o700
        assert (stage_root / ("stage-" + "b" * 16)).is_symlink()  # never followed or replaced
    finally:
        os.close(fd)
        os.close(root_fd)


def test_copy_into_hashes_and_never_follows(root, tmp_path):
    from x_ipe_secure_code.adapters import safe_io

    root_fd = fs().open_root(root["tree"], STAGE_REL)
    name, leaf_fd, _ = fs().make_leaf(root_fd, "stage-")
    src = tmp_path / "src.txt"
    src.write_bytes(b"hello trivy\n" * 100)
    digest, size = fs().copy_into(leaf_fd, "src/a/b.txt", safe_io.open_absolute_nofollow(src), 1 << 20)
    assert digest == "sha256:" + hashlib.sha256(src.read_bytes()).hexdigest() and size == 1200
    leaf = root["project"] / STAGE_REL / name
    assert (leaf / "src/a/b.txt").read_bytes() == src.read_bytes()
    victim = tmp_path / "victim"
    victim.write_text("keep")
    os.symlink(victim, leaf / "src/a/link.txt")
    with pytest.raises(OSError):
        fs().copy_into(leaf_fd, "src/a/link.txt", safe_io.open_absolute_nofollow(src), 1 << 20)
    assert victim.read_text() == "keep"
    with pytest.raises(safe_io.TooLarge):
        fs().copy_into(leaf_fd, "src/big.txt", safe_io.open_absolute_nofollow(src), 10)
    os.close(leaf_fd)
    os.close(root_fd)


def test_sweep_unlinks_symlink_stage_entries_without_traversal(root):
    root_fd = fs().open_root(root["tree"], STAGE_REL)
    stage_root = root["project"] / STAGE_REL
    fill(root["outside"], {"keep/file.txt": b"precious"})
    os.symlink(root["outside"], stage_root / ("stage-" + "1" * 16))
    fs().sweep(root_fd, STAGE_PATTERN)
    assert not os.path.lexists(stage_root / ("stage-" + "1" * 16))
    assert (root["outside"] / "keep/file.txt").read_bytes() == b"precious"
    os.close(root_fd)


def test_sweep_removes_real_stage_folders_and_leaves_unexpected_names(root):
    root_fd = fs().open_root(root["tree"], STAGE_REL)
    stage_root = root["project"] / STAGE_REL
    leftover = stage_root / ("stage-" + "2" * 16)
    fill(leftover, {"src/pom.xml": b"<p/>", "c1/root/pom.xml": b"<p/>", "home/.cache/x": b"x"})
    os.chmod(leftover / "src", 0o555)
    (stage_root / "unexpected").mkdir()
    (stage_root / "notes.txt").write_text("n")
    report = fs().sweep(root_fd, STAGE_PATTERN)
    assert not leftover.exists()
    assert (stage_root / "unexpected").is_dir() and (stage_root / "notes.txt").read_text() == "n"
    text = str(report)
    assert "STAGING_UNEXPECTED" in text and "unexpected" in text and "notes.txt" in text
    os.close(root_fd)


def test_component_links_unlinked_without_touching_generations(root, tmp_path):
    gen = root["project"] / ".x-ipe/private/secure-code/tools/trivy-cache/gen/vulnerability_db/g1"
    fill(gen, {"db/trivy.db": b"d" * 4096, "db/metadata.json": b"{}"})
    for p in (gen / "db/trivy.db", gen / "db/metadata.json"):
        p.chmod(0o444)
    (gen / "db").chmod(0o555)
    try:
        _links_case(root, gen)
    finally:
        (gen / "db").chmod(0o755)


def _links_case(root, gen):
    before = {p.name: p.read_bytes() for p in (gen / "db").iterdir()}
    root_fd = fs().open_root(root["tree"], STAGE_REL)
    name, leaf_fd, _ = fs().make_leaf(root_fd, "stage-")
    cache = root["project"] / STAGE_REL / name / "c1" / "cache"
    cache.mkdir(parents=True)
    os.symlink(str(gen / "db"), cache / "db")
    cache_fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    with pytest.raises(Exception):  # noqa: B017 - a wrong expected target is never unlinked
        fs().unlink_link(cache_fd, "db", str(gen / "java-db"))
    assert (cache / "db").is_symlink()
    (cache / "real").mkdir()
    with pytest.raises(Exception):  # noqa: B017 - a real folder is not a link
        fs().unlink_link(cache_fd, "real", str(gen / "db"))
    fs().unlink_link(cache_fd, "db", str(gen / "db"))
    assert (
        not os.path.lexists(cache / "db")
        and {p.name: p.read_bytes() for p in (gen / "db").iterdir()} == before
    )
    os.close(cache_fd)
    os.close(leaf_fd)
    os.close(root_fd)


def _leaf_with_marker(root):
    root_fd = fs().open_root(root["tree"], STAGE_REL)
    name, leaf_fd, identity = fs().make_leaf(root_fd, "stage-")
    leaf = root["project"] / STAGE_REL / name
    fill(leaf, {"src/secret.env": b"KEY=1", "sub/deep/file": b"x"})
    return root_fd, name, leaf_fd, identity, leaf


def test_leaf_absent_after_successful_removal(root):
    root_fd, name, leaf_fd, identity, leaf = _leaf_with_marker(root)
    assert fs().leaf_matches(root_fd, name, leaf_fd, identity)
    fs().remove_tree_at(root_fd, name, identity)
    assert durable.entry(root_fd, name) is None and not leaf.exists()
    os.close(leaf_fd)
    os.close(root_fd)


def test_replacement_before_cleanup_not_deleted(root):
    root_fd, name, leaf_fd, identity, leaf = _leaf_with_marker(root)
    moved = leaf.with_name("moved-away")
    os.rename(leaf, moved)
    fill(leaf, {"marker.txt": b"decoy"})
    assert not fs().leaf_matches(root_fd, name, leaf_fd, identity)
    with pytest.raises(fs().IdentityChanged):
        fs().remove_tree_at(root_fd, name, identity)
    assert (leaf / "marker.txt").read_bytes() == b"decoy"
    fs().empty_by_fd(leaf_fd)
    assert list(moved.iterdir()) == []  # the original folder emptied through its descriptor
    os.close(leaf_fd)
    os.close(root_fd)


def test_replacement_between_entry_and_open_child_not_deleted(root, monkeypatch):
    root_fd, name, leaf_fd, identity, leaf = _leaf_with_marker(root)
    real = durable.open_child
    swapped = {"done": False}

    def open_child(dfd, child):
        if child == name and not swapped["done"]:
            swapped["done"] = True
            os.rename(leaf, leaf.with_name("moved-away"))
            fill(leaf, {"marker.txt": b"decoy"})
        return real(dfd, child)

    monkeypatch.setattr(durable, "open_child", open_child)
    with pytest.raises(fs().IdentityChanged):
        fs().remove_tree_at(root_fd, name, identity)
    assert swapped["done"] and (leaf / "marker.txt").read_bytes() == b"decoy"
    os.close(leaf_fd)
    os.close(root_fd)


def test_nested_folder_replaced_during_removal_not_deleted(root, monkeypatch):
    root_fd, name, leaf_fd, identity, leaf = _leaf_with_marker(root)
    real = durable.open_child
    decoy = {}

    def open_child(dfd, child):
        if child == "sub" and not decoy:
            os.rename(leaf / "sub", leaf / "sub-moved")
            fill(leaf / "sub", {"marker.txt": b"decoy"})
            decoy["path"] = leaf / "sub" / "marker.txt"
        return real(dfd, child)

    monkeypatch.setattr(durable, "open_child", open_child)
    with pytest.raises(fs().IdentityChanged):
        fs().remove_tree_at(root_fd, name, identity)
    assert decoy["path"].read_bytes() == b"decoy"
    os.close(leaf_fd)
    os.close(root_fd)


def test_sweep_skips_replaced_entry(root, monkeypatch):
    root_fd = fs().open_root(root["tree"], STAGE_REL)
    stage_root = root["project"] / STAGE_REL
    name = "stage-" + "3" * 16
    fill(stage_root / name, {"src/x": b"x"})
    real = durable.open_child

    def open_child(dfd, child):
        if child == name and not (stage_root / "moved").exists():
            os.rename(stage_root / name, stage_root / "moved")
            fill(stage_root / name, {"marker.txt": b"decoy"})
        return real(dfd, child)

    monkeypatch.setattr(durable, "open_child", open_child)
    report = fs().sweep(root_fd, STAGE_PATTERN)
    assert (stage_root / name / "marker.txt").read_bytes() == b"decoy" and name in str(report)
    os.close(root_fd)
