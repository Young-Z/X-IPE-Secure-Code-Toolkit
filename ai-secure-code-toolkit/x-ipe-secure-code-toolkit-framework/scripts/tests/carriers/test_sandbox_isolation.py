"""FEATURE-003-B: sandbox-only generation during development (AC-003B-07a…07e, NFR-003B-7).

These tests exercise the suite-wide write-audit and protected-tree harness
(tests/support/write_audit.py, tests/support/auditsite/sitecustomize.py, conftest hooks).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from carhelp import (
    AGENTS,
    BEGIN,
    CLAUDE,
    END,
    FRAMEWORK,
    INSTR,
    RECORD,
    allow,
    sandbox,
    watch_writes,
    write_audit,
    written_paths,
)
from conftest import LAUNCHER, TOOLKIT_ROOT, tree_hashes

DEV_REPO = TOOLKIT_ROOT.parent


def _ok(proc, out):
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    return out


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------- AC-003B-07a

def test_07a_dev_repo_carriers_unchanged():
    snapshot = write_audit().session_snapshot()
    copilot_instructions = DEV_REPO / ".github" / "copilot-instructions.md"
    assert copilot_instructions.is_file()  # the development repository has its own instructions
    assert snapshot[str(copilot_instructions)] == _sha(copilot_instructions)
    for rel in (AGENTS, CLAUDE):
        path = DEV_REPO / rel
        if str(path) in snapshot:
            assert path.is_file() and _sha(path) == snapshot[str(path)]
        else:
            assert not path.exists(), path
    for folder in (DEV_REPO / ".github" / "instructions", DEV_REPO / ".x-ipe" / "private" / "secure-code"):
        now = {str(p): _sha(p) for p in folder.rglob("*") if p.is_file()} if folder.exists() else {}
        before = {k: v for k, v in snapshot.items() if k.startswith(str(folder) + os.sep)}
        assert now == before, folder


# ---------------------------------------------------------------- AC-003B-07b

def test_07b_nested_sandbox_writes_only_under_root_ancestors_unchanged(tmp_path):
    outer = tmp_path / "ancestors"
    seeds = {
        outer / AGENTS: f"# ancestor rules\n{BEGIN}\nancestor fragment\n{END}\n",
        outer / ".github" / "copilot-instructions.md": "ancestor instructions\n",
        outer / "x" / AGENTS: "plain ancestor agents\n",
    }
    for path, text in seeds.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    before = tree_hashes(outer)
    box = sandbox(tmp_path, parent=outer / "x")
    with watch_writes() as writes:
        out = _ok(*box.select_all())
    root = box.root.resolve()
    assert Path(out["data"]["root"]) == root  # the explicit root, never a parent
    assert written_paths(writes) and all(p == root or root in p.parents for p in written_paths(writes))
    project_prefix = str(box.root)
    after = {k: v for k, v in tree_hashes(outer).items()
             if not (k == project_prefix + "/" or k.startswith(project_prefix + "/"))}
    assert after == before
    for path, text in seeds.items():
        assert path.read_text(encoding="utf-8") == text


# ---------------------------------------------------------------- AC-003B-07c

def test_07c_write_audit_active_in_process_and_subprocesses(tmp_path):
    from x_ipe_secure_code.atomic import atomic_write_bytes

    box = sandbox(tmp_path, init=False)
    with watch_writes() as writes:
        _ok(*box.init())
    root = str(box.root.resolve())
    assert writes and all(r["product"] and r["allowed"] for r in writes)
    assert any(r["pid"] != os.getpid() for r in writes)  # the CLI subprocess was audited
    assert all(root in r["allowed_roots"] for r in writes)  # per-invocation registered root
    assert any(Path(p) == box.root.resolve() / RECORD for r in writes for p in r["resolved"])
    target = box.root / "in-process.txt"
    with allow(box.root), watch_writes() as inproc:
        atomic_write_bytes(target, b"x")
    assert any(r["pid"] == os.getpid() and str(target.resolve()) in r["resolved"] for r in inproc)
    assert all(r["allowed"] for r in inproc)


def _canary_targets(tmp_path, base: Path, other: Path) -> dict[str, Path]:
    (tmp_path / "outside").mkdir(exist_ok=True)
    return {
        "under-base": base / f"canary-{uuid.uuid4().hex}",
        "tmp-path-outside-project": tmp_path / "outside" / f"canary-{uuid.uuid4().hex}",
        "other-registered-project": other / f"canary-{uuid.uuid4().hex}",
    }


def _related(record: dict, target: Path) -> bool:
    """The canary itself, its temp sibling, or (re-)creating its parent folder."""
    paths = [Path(p) for p in record["resolved"]]
    return all(p in (target, target.parent) or p.parent == target.parent for p in paths)


def test_07c_canaries_detected(tmp_path, tmp_path_factory):
    from x_ipe_secure_code.atomic import atomic_write_bytes

    wa = write_audit()
    base = Path(tmp_path_factory.getbasetemp()).resolve()
    project = sandbox(tmp_path, init=False).root.resolve()
    other = (tmp_path / "second registered" / "q").resolve()
    other.mkdir(parents=True)
    with wa.allow(other):
        atomic_write_bytes(other / "registered.txt", b"q")  # Q is a registered project of this test
    env = dict(os.environ)
    env.update(wa.child_env([project]))

    for name, target in _canary_targets(tmp_path, base, other).items():
        target = target.resolve()
        with wa.allow(project), wa.expect_violations() as found:
            atomic_write_bytes(target, b"canary in-process")
        assert found and all(_related(r, target) and r["pid"] == os.getpid() for r in found), name
        target.unlink()
        with wa.expect_violations() as found:
            proc = subprocess.run([sys.executable, str(LAUNCHER), "--test-canary-write", str(target)],
                                  env=env, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        assert found and all(_related(r, target) and r["pid"] != os.getpid() for r in found), name
        target.unlink()

    control = project / "control.txt"
    with wa.allow(project), watch_writes() as writes:
        atomic_write_bytes(control, b"ok")
    assert writes and all(r["allowed"] for r in writes)
    with watch_writes() as writes:
        proc = subprocess.run([sys.executable, str(LAUNCHER), "--test-canary-write", str(project / "c2.txt")],
                              env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0 and writes and all(r["allowed"] for r in writes)


EXCEPTIONS_SAMPLE = ["{rootdir}/.pytest_cache/**", "**/__pycache__/**"]


def _classify(event, args, root: Path, *, cwd: Path, fds=(), rootdir: Path | None = None):
    rootdir = rootdir or root.parent
    exceptions = [e.replace("{rootdir}", str(rootdir)) for e in EXCEPTIONS_SAMPLE]
    return write_audit().classify(event, args, allowed=[root], exceptions=exceptions, cwd=cwd,
                                  open_dir_fds=list(fds))


@pytest.fixture
def area(tmp_path):
    root = (tmp_path / "registered").resolve()
    outside = (tmp_path / "elsewhere").resolve()
    for folder in (root / "sub", outside):
        folder.mkdir(parents=True)
    return root, outside


@pytest.mark.parametrize("mode,write", [("r", False), ("rb", False), ("w", True), ("a", True), ("x", True),
                                        ("r+", True), ("wb", True)])
def test_07c_classifier_open_modes(area, mode, write):
    root, outside = area
    inside = _classify("open", (str(root / "f.txt"), mode, 0), root, cwd=root)
    assert inside.write is write and inside.allowed
    out = _classify("open", (str(outside / "f.txt"), mode, 0), root, cwd=root)
    assert out.write is write and out.allowed is (not write)


@pytest.mark.parametrize("flags,write", [(os.O_RDONLY, False), (os.O_WRONLY | os.O_CREAT, True),
                                         (os.O_RDWR, True), (os.O_WRONLY | os.O_TRUNC, True),
                                         (os.O_WRONLY | os.O_APPEND, True)])
def test_07c_classifier_os_open_flags(area, flags, write):
    root, outside = area
    verdict = _classify("open", (str(outside / "g.txt"), None, flags), root, cwd=root)
    assert verdict.write is write and verdict.allowed is (not write)


def test_07c_classifier_rename_replace_and_mkdir(area):
    root, outside = area
    ok = _classify("os.rename", (str(root / "a"), str(root / "b"), None, None), root, cwd=root)
    assert ok.write and ok.allowed and set(ok.paths) == {str(root / "a"), str(root / "b")}
    leak = _classify("os.rename", (str(root / "a"), str(outside / "b"), None, None), root, cwd=root)
    assert leak.write and not leak.allowed
    for event, args in (("os.mkdir", (str(outside / "d"), 0o777, None)),
                        ("os.remove", (str(outside / "f"), None)),
                        ("os.rmdir", (str(outside / "d"), None)),
                        ("os.truncate", (str(outside / "f"), 0)),
                        ("os.chmod", (str(outside / "f"), 0o600, None)),
                        ("shutil.rmtree", (str(outside / "d"), None)),
                        ("os.symlink", (str(root / "t"), str(outside / "l"), None))):
        verdict = _classify(event, args, root, cwd=root)
        assert verdict.write and not verdict.allowed, event
    inside = _classify("os.mkdir", (str(root / "new"), 0o777, None), root, cwd=root)
    assert inside.write and inside.allowed


def test_07c_classifier_dir_fd_and_relative_candidates(area):
    root, outside = area
    fd_in = os.open(root / "sub", os.O_RDONLY)
    fd_out = os.open(outside, os.O_RDONLY)
    try:
        resolved = _classify("os.mkdir", ("child", 0o777, fd_in), root, cwd=outside)
        assert resolved.allowed and resolved.paths == [str(root / "sub" / "child")]
        escaped = _classify("os.mkdir", ("child", 0o777, fd_out), root, cwd=root)
        assert not escaped.allowed
        # a relative open may carry a hidden dir_fd: every candidate must be allowed (sound)
        rel_ok = _classify("open", ("rel.txt", None, os.O_WRONLY | os.O_CREAT), root, cwd=root, fds=[fd_in])
        assert rel_ok.write and rel_ok.allowed
        rel_bad = _classify("open", ("rel.txt", None, os.O_WRONLY | os.O_CREAT), root, cwd=root,
                            fds=[fd_in, fd_out])
        assert rel_bad.write and not rel_bad.allowed
        unresolvable = _classify("os.mkdir", ("x", 0o777, 987654), root, cwd=root)
        assert not unresolvable.allowed
    finally:
        os.close(fd_in)
        os.close(fd_out)


def test_07c_classifier_cache_exceptions(area):
    root, outside = area
    cache = _classify("open", (str(outside / "pkg" / "__pycache__" / "m.pyc"), "wb", 0), root, cwd=root)
    assert cache.write and cache.allowed
    pytest_cache = _classify("open", (str(root.parent / ".pytest_cache" / "v" / "x"), "w", 0), root, cwd=root)
    assert pytest_cache.allowed
    other = _classify("open", (str(outside / "pycache.txt"), "w", 0), root, cwd=root)
    assert not other.allowed


def test_07c_exceptions_declared_in_test_configuration(pytestconfig):
    declared = pytestconfig.getini("write_audit_exceptions")
    assert "{rootdir}/.pytest_cache/**" in declared and "**/__pycache__/**" in declared
    assert any("{uv_cache}" in item for item in declared)
    assert len(declared) <= 5  # nothing else is excepted


# ---------------------------------------------------------------- AC-003B-07d

def _protected_tree(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("a = 1\n")
    (root / "README.md").write_text("readme\n")
    return root


@pytest.mark.parametrize("change", ["modified", "new-agents", "new-claude", "new-instructions", "new-private",
                                    "deleted"])
def test_07d_protected_snapshot_detects_change(tmp_path, change):
    wa = write_audit()
    tree = _protected_tree(tmp_path / "protected")
    before = wa.snapshot_tree(tree)
    assert wa.protected_violations(before, wa.snapshot_tree(tree)) == []
    target = {"modified": tree / "src" / "a.py", "new-agents": tree / "src" / AGENTS,
              "new-claude": tree / CLAUDE, "new-instructions": tree / ".github" / "instructions" / "x.md",
              "new-private": tree / ".x-ipe" / "private" / "secure-code" / "x",
              "deleted": tree / "README.md"}[change]
    if change == "deleted":
        target.unlink()
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("changed\n")
    violations = wa.protected_violations(before, wa.snapshot_tree(tree))
    assert violations and any(str(target) in item for item in violations)


def test_07d_registered_project_ancestor_snapshot(tmp_path):
    wa = write_audit()
    ancestors = tmp_path / "anc"
    project = ancestors / "p" / "project"
    project.mkdir(parents=True)
    (ancestors / AGENTS).write_text("ancestor\n")
    snapshot = wa.ancestor_snapshot(project)
    assert str(ancestors / AGENTS) in snapshot
    assert wa.ancestor_violations(project, snapshot) == []
    (ancestors / AGENTS).write_text("changed\n")
    (ancestors / "p" / CLAUDE).write_text("new\n")
    (ancestors / ".github" / "instructions").mkdir(parents=True)
    (ancestors / ".github" / "instructions" / "n.instructions.md").write_text("new\n")
    (project / AGENTS).write_text("inside the project: not an ancestor path\n")
    violations = " ".join(wa.ancestor_violations(project, snapshot))
    assert str(ancestors / AGENTS) in violations and str(ancestors / "p" / CLAUDE) in violations
    assert "n.instructions.md" in violations
    assert str(project / AGENTS) not in violations


# ---------------------------------------------------------------- AC-003B-07e

def _seed(level: Path) -> None:
    files = {
        AGENTS: f"# seeded\n{BEGIN}\nseed fragment\n{END}\n",
        CLAUDE: "# seeded claude without markers\n",
        ".github/copilot-instructions.md": "seed instructions\n",
        INSTR: f'---\napplyTo: "**"\n---\n\n{BEGIN}\nseed\n{END}\n',
        RECORD: json.dumps({"schema": "ai-secure-code-toolkit/install-record/v1", "toolkit_version": "0.1.0",
                            "environment": "github-copilot", "skills_dir": ".github/skills",
                            "host_entry": AGENTS, "fragment_sha256": None,
                            "initialized_at": "2026-01-01T00:00:00Z",
                            "updated_at": "2026-01-01T00:00:00Z", "files": {}}),
        f".github/skills/{FRAMEWORK}/SKILL.md": "---\nname: seeded\n---\n",
    }
    for rel, text in files.items():
        path = level / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def test_07e_seeded_ancestors_do_not_change_results_or_get_read(tmp_path):
    seed = tmp_path / "seed"
    for level in (seed, seed / "a"):
        _seed(level)
    seeded = sandbox(tmp_path, init=False, parent=seed / "a" / "b")
    twin = sandbox(tmp_path, init=False, name="twin")
    seed_before = {k: v for k, v in tree_hashes(seed).items() if not k.startswith(str(seeded.root))}

    def sequence(box):
        log = tmp_path / f"opened-{uuid.uuid4().hex}.log"
        outputs = []
        runs = (("init", "--project", str(box.root), "--env", "github-copilot"),
                ("carriers", "--project", str(box.root), "--env", "github-copilot", "--select",
                 "github-instructions", "--select", "system-prompt", "--system-prompt-host", "copilot-cli"),
                ("status", "--project", str(box.root)))
        for args in runs:
            proc, out = box.run(*args, extra=("--audit-open", str(log)))
            _ok(proc, out)
            text = proc.stdout.replace(str(box.root), "<ROOT>")
            outputs.append(text.replace(str(box.root.resolve()), "<ROOT>"))
        return outputs, log

    seeded_out, log = sequence(seeded)
    twin_out, _ = sequence(twin)
    assert seeded_out == twin_out  # results equal those without the seeds
    root = seeded.root.resolve()
    for line in log.read_text(encoding="utf-8").splitlines():
        path = Path(line) if os.path.isabs(line) else Path(os.getcwd()) / line
        path = Path(os.path.realpath(path))
        if seed.resolve() in path.parents and not (path == root or root in path.parents):
            raise AssertionError(f"ancestor opened for project discovery: {path}")
    after = {k: v for k, v in tree_hashes(seed).items() if not k.startswith(str(seeded.root))}
    assert after == seed_before  # no ancestor write
