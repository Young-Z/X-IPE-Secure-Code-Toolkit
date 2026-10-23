"""FEATURE-001-A-level init regression (TASK-079): an unopenable host entry file (AC-001A-04h, FR-001A-9).

Plain `init` crashed with a PermissionError traceback and no result when the environment's host entry
file exists but cannot be opened (e.g. mode 000). Intended (specification "Host entry file is not valid
UTF-8 or not writable: refuse the fragment step with reason"; technical design: `HOST_ENTRY_UNREADABLE`
is a blocking problem returned before any write): refused like a non-UTF-8 host entry file.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
import write_audit
from conftest import run_cli

posix_non_root = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                                    reason="needs POSIX permissions and a non-root user")
HOSTS = [("github-copilot", "AGENTS.md"), ("claude-code", "CLAUDE.md")]


def _init(project, trust, env):
    proc = run_cli(["init", "--project", str(project), "--env", env, "--json"], trust)
    return proc


def _hashes(root, skip):
    result = {}
    for path in sorted(root.rglob("*")):
        if path == skip:
            stat = path.stat()
            result[str(path)] = f"mode={stat.st_mode} size={stat.st_size} mtime={stat.st_mtime_ns}"
        elif path.is_file() and not path.is_symlink():
            result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            result[str(path)] = "dir" if path.is_dir() else "other"
    return result


def _assert_refused_unreadable(proc, host_name):
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 1, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["command"] == "init" and out["ok"] is False
    assert out["data"]["fragment"] == "unreadable"
    assert [p["code"] for p in out["problems"]] == ["HOST_ENTRY_UNREADABLE"]
    message = out["problems"][0]["message"]
    assert host_name in message and "cannot be read" in message
    assert out["next_steps"] == ["Resolve the listed problems; nothing was written"]


@posix_non_root
@pytest.mark.parametrize("env,host_name", HOSTS)
def test_init_unopenable_host_entry_refused_writes_nothing(project, tmp_path, env, host_name):
    trust = tmp_path / "trust-app"
    host = project / host_name
    host.write_text("# My agent notes\n", encoding="utf-8")
    host.chmod(0)
    try:
        before = _hashes(project, host)
        position = write_audit.mark()
        proc = _init(project, trust, env)
        writes = write_audit.writes_since(position)
        _assert_refused_unreadable(proc, host_name)
        assert writes == [] and _hashes(project, host) == before
        assert not (project / ".x-ipe").exists() and not (project / "x-ipe-docs").exists()
    finally:
        host.chmod(0o644)
    assert host.read_text(encoding="utf-8") == "# My agent notes\n"


@posix_non_root
def test_reinit_unopenable_host_entry_refused_record_unchanged(project, tmp_path):
    trust = tmp_path / "trust-app"
    first = _init(project, trust, "github-copilot")
    assert first.returncode == 0, first.stdout + first.stderr
    host = project / "AGENTS.md"
    host.chmod(0)
    try:
        before = _hashes(project, host)
        position = write_audit.mark()
        proc = _init(project, trust, "github-copilot")
        writes = write_audit.writes_since(position)
        _assert_refused_unreadable(proc, "AGENTS.md")
        assert writes == [] and _hashes(project, host) == before
    finally:
        host.chmod(0o644)
    again = _init(project, trust, "github-copilot")  # readable again: converges as before
    assert again.returncode == 0 and json.loads(again.stdout)["data"]["already_current"] is True


def test_init_non_utf8_host_entry_refusal_unchanged(project, tmp_path):
    trust = tmp_path / "trust-app"
    (project / "AGENTS.md").write_bytes(b"\xff\xfe not utf-8\n")
    before = _hashes(project, None)
    proc = _init(project, trust, "github-copilot")
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["data"]["fragment"] == "unreadable"
    assert out["problems"] == [{"code": "HOST_ENTRY_UNREADABLE", "message": "Host entry file is not UTF-8"}]
    assert out["next_steps"] == ["Resolve the listed problems; nothing was written"]
    assert _hashes(project, None) == before
