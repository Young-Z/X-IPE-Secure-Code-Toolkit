"""FEATURE-002-B regression (TASK-100): the shared no-follow open must not block on a FIFO.

`safe_io.open_nofollow` / `open_absolute_nofollow` opened with a blocking `os.open` before the `fstat`
regular-file check, so a FIFO (no writer) at a registered binary path hung `status`, registration
inspection and the Guard pre-check snapshot, and a FIFO rule file or image archive hung Guard request
validation. Intended (AC-002B-01c/01d/02b/06a, FR-002B-2/5/8): the existing refusal a non-regular file
already gets ("… is not a regular file") under the existing code, without blocking.
Library calls run in a child process with a timeout so a regression fails instead of hanging.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest
import write_audit
from conftest import LAUNCHER, SRC, _cli_roots

posix = pytest.mark.skipif(os.name != "posix" or not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
TIMEOUT = 20
REGISTER = ("A Maintainer registers the official binary: "
            "secure-code tools register --tool opengrep --path PATH")
NOT_REGULAR = "The registered binary is missing or unreadable: opengrep-bin is not a regular file"
CHILD = """
import json, sys
from pathlib import Path
sys.path.insert(0, {src!r})
from x_ipe_secure_code.adapters import registry_store, safe_io, trivy_request
from x_ipe_secure_code.guard import toolreq
from x_ipe_secure_code.guard.model import Checker, GuardError
kind, a, b = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
try:
    if kind == "open_nofollow":
        result = safe_io.open_nofollow(a, b)
    elif kind == "open_absolute_nofollow":
        result = safe_io.open_absolute_nofollow(a)
    elif kind == "hash_path":
        result = safe_io.hash_path(a)
    elif kind == "inspect_binary":
        result = registry_store.inspect_binary(str(a)).__dict__
    elif kind == "check":
        result = registry_store.check(a, "opengrep", stage_bin=Path(b) if b != "-" else None)
        result = result.__dict__ if isinstance(result, registry_store.Gap) else "passed"
    elif kind == "rule_file":
        result = list(toolreq._rule_file(a, Checker("REQUEST_INVALID", "fix"), b, "where"))
        result[1] = result[1].decode()
    elif kind == "archive":
        state = {{"artifact": {{"targets": [{{"path": b, "kind": "file"}}]}}}}
        result = trivy_request._archive(a, state, Checker("REQUEST_INVALID", "fix"), b, "where")
    print(json.dumps({{"result": result}}))
except safe_io.UnsafePath as exc:
    print(json.dumps({{"UnsafePath": str(exc)}}))
except GuardError as exc:
    print(json.dumps({{"GuardError": [exc.code, exc.message]}}))
"""


def _child(kind, a, b="-"):
    """One library call in a child process; a blocking open fails the test instead of hanging it."""
    cmd = [sys.executable, "-c", CHILD.format(src=str(SRC)), kind, str(a), str(b)]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{kind} did not finish within {TIMEOUT}s (blocked on a non-regular file)")
    assert proc.returncode == 0 and "Traceback" not in proc.stderr, proc.stderr
    return json.loads(proc.stdout)


def _status(project, trust):
    args = ["status", "--project", str(project), "--json"]
    env = dict(os.environ)
    env.update(write_audit.child_env(_cli_roots(args, trust)))
    cmd = [sys.executable, str(LAUNCHER), "--test-trust-dir", str(trust), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"status did not finish within {TIMEOUT}s (blocked on a non-regular file)")
    assert proc.returncode == 0 and "Traceback" not in proc.stderr, proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def _host_digest():
    from x_ipe_secure_code.adapters import digests

    host = digests.host_platform()
    for digest, build in digests.TABLE.items():
        if digests.matches(build, host):
            return digest
    pytest.skip(f"no official Opengrep build for this machine ({host})")


def _register_record(project, binary):
    tools = project / ".x-ipe/private/secure-code/tools"
    tools.mkdir(parents=True)
    (tools / "opengrep.json").write_text(json.dumps({"path": str(binary), "digest": _host_digest(),
                                                     "version": "1.31.0"}))


@pytest.fixture
def fifo(tmp_path):
    path = tmp_path / "bins" / "opengrep-bin"
    path.parent.mkdir()
    os.mkfifo(path)
    yield path
    assert path.is_fifo()


@posix
def test_open_nofollow_refuses_fifo_without_blocking(tmp_path):
    (tmp_path / "rules").mkdir()
    os.mkfifo(tmp_path / "rules" / "fifo.yaml")
    assert _child("open_nofollow", tmp_path, "rules/fifo.yaml") == {
        "UnsafePath": "rules/fifo.yaml is not a regular file"}
    assert (tmp_path / "rules" / "fifo.yaml").is_fifo()


@posix
@pytest.mark.parametrize("kind", ["open_absolute_nofollow", "hash_path"])
def test_absolute_open_refuses_fifo_without_blocking(fifo, kind):
    assert _child(kind, fifo) == {"UnsafePath": "opengrep-bin is not a regular file"}


@posix
def test_registration_refuses_fifo_binary_without_blocking(fifo):
    """AC-002B-01c: a path that is not a regular file is refused with the reason."""
    assert _child("inspect_binary", fifo) == {"result": {
        "code": "TOOL_PATH_INVALID",
        "reason": f"{fifo} is not a readable regular file (no symbolic links): "
                  "opengrep-bin is not a regular file",
        "next_step": "Pass the real binary file, not a link"}}


@posix
def test_precheck_snapshot_refuses_fifo_binary_without_blocking(project, fifo, tmp_path):
    """AC-002B-01d: a failed pre-check snapshot means nothing is staged or executed."""
    _register_record(project, fifo)
    stage = tmp_path / "stage" / "opengrep"
    assert _child("check", project, stage) == {"result": {
        "code": "TOOL_NOT_REGISTERED",
        "reason": NOT_REGULAR,
        "next_step": REGISTER}}
    assert not stage.exists()


@posix
def test_status_reports_fifo_binary_without_blocking(project, fifo, tmp_path):
    """AC-002B-06a: status reports the failing reason and next step, without executing or writing."""
    trust = tmp_path / "trust-app"
    _register_record(project, fifo)
    position = write_audit.mark()
    out = _status(project, trust)
    assert write_audit.writes_since(position) == []
    tool = out["data"]["tools"]["opengrep"]
    assert tool["registered"] is True
    assert tool["check"] == NOT_REGULAR
    assert tool["next_step"] == REGISTER


@posix
def test_status_folder_binary_refusal_unchanged(project, tmp_path):
    """Characterization: the existing non-regular branch (a folder), same refusal before and after."""
    trust = tmp_path / "trust-app"
    folder = tmp_path / "bins" / "opengrep-bin"
    folder.mkdir(parents=True)
    _register_record(project, folder)
    tool = _status(project, trust)["data"]["tools"]["opengrep"]
    assert tool["check"] == NOT_REGULAR
    assert tool["next_step"] == REGISTER


@posix
def test_guard_rule_file_fifo_refused_without_blocking(tmp_path):
    """AC-002B-02b: a rule source that is not an existing regular local rule file is refused."""
    (tmp_path / "rules").mkdir()
    os.mkfifo(tmp_path / "rules" / "fifo.yaml")
    (tmp_path / "rules" / "ok.yaml").write_text("rules: []\n")
    assert _child("rule_file", tmp_path, "rules/fifo.yaml") == {"GuardError": [
        "REQUEST_INVALID", "where: rules/fifo.yaml is not an existing regular local rule file without links "
        "(rules/fifo.yaml is not a regular file)"]}
    assert _child("rule_file", tmp_path, "rules/ok.yaml") == {"result": ["rules/ok.yaml", "rules: []\n"]}


@posix
def test_guard_image_archive_fifo_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "image.tar")
    assert _child("archive", tmp_path, "image.tar") == {"GuardError": [
        "REQUEST_INVALID", "where: image.tar is not a readable regular file without links "
        "(image.tar is not a regular file)"]}


def test_regular_file_descriptor_unchanged(tmp_path):
    """Regular files: same bytes and digest, and the descriptor is returned in blocking mode."""
    from x_ipe_secure_code.adapters import safe_io

    data = os.urandom(3 * safe_io.CHUNK + 17)
    (tmp_path / "sub").mkdir()
    path = tmp_path / "sub" / "bin"
    path.write_bytes(data)
    fd = safe_io.open_nofollow(tmp_path, "sub/bin")
    try:
        if safe_io.NONBLOCK:  # Windows: no O_NONBLOCK, and get_blocking() refuses regular files
            assert os.get_blocking(fd) is True
        assert os.read(fd, len(data) + 1) == data
    finally:
        os.close(fd)
    assert safe_io.hash_path(path) == "sha256:" + hashlib.sha256(data).hexdigest()
    with pytest.raises(safe_io.UnsafePath, match="^sub is not a regular file$"):
        safe_io.open_nofollow(tmp_path, "sub")


STAGE_CHILD = """
import json, os, sys
from pathlib import Path
sys.path.insert(0, {src!r})
from x_ipe_secure_code.adapters import safe_io
from x_ipe_secure_code.guard import targets
root, dest, swapped = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
real_scandir = os.scandir


class Swapped:
    # A directory entry seen as a regular file by scandir that is a FIFO when opened (swap mid-walk).
    def __init__(self, entry):
        self._entry, self.name, self.path = entry, entry.name, entry.path

    def is_symlink(self):
        return False

    def is_dir(self, follow_symlinks=True):
        return False

    def is_file(self, follow_symlinks=True):
        return True


def scandir(target):
    return [Swapped(e) if e.name == swapped else e for e in real_scandir(target)]


targets.os.scandir = scandir
try:
    print(json.dumps({{"result": targets.stage(root, "s", "dir", dest, 10_000_000, 100)}}))
except safe_io.UnsafePath as exc:
    print(json.dumps({{"UnsafePath": str(exc)}}))
"""


def _stage_child(root, dest, swapped):
    cmd = [sys.executable, "-c", STAGE_CHILD.format(src=str(SRC)), str(root), str(dest), swapped]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"stage did not finish within {TIMEOUT}s (blocked on a non-regular file)")
    assert proc.returncode == 0 and "Traceback" not in proc.stderr, proc.stderr
    return json.loads(proc.stdout)


@posix
def test_stage_walk_fifo_swapped_in_refused_without_blocking(tmp_path):
    """A file swapped for a FIFO between the folder listing and the open: existing refusal, no block."""
    root = tmp_path / "p"
    (root / "s").mkdir(parents=True)
    (root / "s" / "a.py").write_text("a = 1\n")
    os.mkfifo(root / "s" / "fifo")
    assert _stage_child(root, tmp_path / "stage", "fifo") == {"UnsafePath": "s/fifo changed while staging"}
    assert (root / "s" / "fifo").is_fifo()


@posix
def test_stage_walk_regular_files_unchanged(tmp_path):
    """Characterization: regular files are staged and hashed exactly like the snapshot (before and after)."""
    from x_ipe_secure_code.guard import targets

    root = tmp_path / "p"
    (root / "s" / "d").mkdir(parents=True)
    (root / "s" / "a.py").write_text("a = 1\n")
    (root / "s" / "d" / "b.py").write_bytes(os.urandom(70_000))
    os.mkfifo(root / "s" / "fifo")
    out = _stage_child(root, tmp_path / "stage", "a.py")["result"]
    assert out["files"] == ["s/a.py", "s/d/b.py"] and out["irregular"] == ["s/fifo"]
    assert out["digest"] == targets.snapshot(root, "s", "dir")["digest"]
    for rel in out["files"]:
        assert (tmp_path / "stage" / rel).read_bytes() == (root / rel).read_bytes()
