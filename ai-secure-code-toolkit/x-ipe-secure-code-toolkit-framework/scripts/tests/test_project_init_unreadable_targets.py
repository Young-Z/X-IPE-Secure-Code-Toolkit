"""FEATURE-001-A-level init regression (TASK-095): unreadable skill targets and non-regular host entries.

Plain `init` crashed with a PermissionError traceback when an existing skill file target could not be
opened, and blocked indefinitely (holding the project lock) when the host entry file was a FIFO.
Intended (specification edge cases "permission denied during install: fail with reason" and "same-named
non-toolkit skill: refuse, report the conflict"; technical design: blocking problems return before any
write): refused with an existing problem code, the reason and the blocked-init next step, nothing written.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest
import write_audit
from conftest import LAUNCHER, _cli_roots, run_cli

posix = pytest.mark.skipif(os.name != "posix", reason="needs POSIX FIFOs")
posix_non_root = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                                    reason="needs POSIX permissions and a non-root user")
HOSTS = [("github-copilot", "AGENTS.md", ".github/skills"), ("claude-code", "CLAUDE.md", ".claude/skills")]
SKILL = "x-ipe-secure-code-toolkit-framework/SKILL.md"
BLOCKED = ["Resolve the listed problems; nothing was written"]
TIMEOUT = 30


def _init(project, trust, env):
    """Run plain init like `run_cli`, but with a short timeout so a blocking read fails the test."""
    args = ["init", "--project", str(project), "--env", env, "--json"]
    child_env = dict(os.environ)
    child_env.update(write_audit.child_env(_cli_roots(args, trust)))
    cmd = [sys.executable, str(LAUNCHER), "--test-trust-dir", str(trust), *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, env=child_env, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"init did not finish within {TIMEOUT}s (blocked on a non-regular file)")


def _tree(root):
    result = {}
    for path in sorted(root.rglob("*")):
        stat = path.lstat()
        if path.is_fifo() or not os.access(path, os.R_OK):
            result[str(path)] = f"mode={stat.st_mode} size={stat.st_size} mtime={stat.st_mtime_ns}"
        elif path.is_file() and not path.is_symlink():
            result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            result[str(path)] = "dir" if path.is_dir() else "other"
    return result


def _refused(proc):
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 1, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["command"] == "init" and out["ok"] is False
    assert out["next_steps"] == BLOCKED
    return out


@posix_non_root
@pytest.mark.parametrize("env,host_name,skills", HOSTS)
def test_fresh_init_foreign_unreadable_skill_file_is_a_conflict(project, tmp_path, env, host_name, skills):
    trust = tmp_path / "trust-app"
    target = project / skills / SKILL
    target.parent.mkdir(parents=True)
    target.write_text("# my own skill\n", encoding="utf-8")
    target.chmod(0)
    try:
        before = _tree(project)
        position = write_audit.mark()
        proc = _init(project, trust, env)
        writes = write_audit.writes_since(position)
        out = _refused(proc)
        assert [p["code"] for p in out["problems"]] == ["SKILL_NAME_CONFLICT"]
        message = out["problems"][0]["message"]
        assert f"{skills}/{SKILL}" in message and "cannot be read" in message
        assert out["data"]["files"]["conflicts"] == [f"{skills}/{SKILL}"]
        assert writes == [] and _tree(project) == before
        assert not (project / host_name).exists()
        assert not (project / ".x-ipe").exists() and not (project / "x-ipe-docs").exists()
    finally:
        target.chmod(0o644)
    assert target.read_text(encoding="utf-8") == "# my own skill\n"


@posix_non_root
def test_reinit_unreadable_installed_skill_file_refused_record_unchanged(project, tmp_path):
    trust = tmp_path / "trust-app"
    first = run_cli(["init", "--project", str(project), "--env", "github-copilot", "--json"], trust)
    assert first.returncode == 0, first.stdout + first.stderr
    target = project / ".github/skills" / SKILL
    target.chmod(0)
    try:
        before = _tree(project)
        position = write_audit.mark()
        proc = _init(project, trust, "github-copilot")
        writes = write_audit.writes_since(position)
        out = _refused(proc)
        assert [p["code"] for p in out["problems"]] == ["IO_ERROR"]
        message = out["problems"][0]["message"]
        assert f".github/skills/{SKILL}" in message and "cannot be read" in message
        assert out["data"]["files"]["conflicts"] == [f".github/skills/{SKILL}"]
        assert writes == [] and _tree(project) == before
    finally:
        target.chmod(0o644)
    again = _init(project, trust, "github-copilot")  # readable again: converges as before
    assert again.returncode == 0 and json.loads(again.stdout)["data"]["already_current"] is True


@posix
@pytest.mark.parametrize("env,host_name,skills", HOSTS)
def test_fresh_init_fifo_host_entry_refused_without_blocking(project, tmp_path, env, host_name, skills):
    trust = tmp_path / "trust-app"
    host = project / host_name
    os.mkfifo(host)
    before = _tree(project)
    position = write_audit.mark()
    proc = _init(project, trust, env)
    writes = write_audit.writes_since(position)
    out = _refused(proc)
    assert out["data"]["fragment"] == "unreadable"
    assert [p["code"] for p in out["problems"]] == ["HOST_ENTRY_UNREADABLE"]
    message = out["problems"][0]["message"]
    assert host_name in message and "cannot be read" in message and "not a regular file" in message
    assert writes == [] and _tree(project) == before and host.is_fifo()
    assert not (project / ".x-ipe").exists() and not (project / "x-ipe-docs").exists()


@posix
def test_reinit_fifo_host_entry_refused_record_unchanged(project, tmp_path):
    trust = tmp_path / "trust-app"
    first = run_cli(["init", "--project", str(project), "--env", "github-copilot", "--json"], trust)
    assert first.returncode == 0, first.stdout + first.stderr
    host = project / "AGENTS.md"
    saved = host.read_bytes()
    host.unlink()
    os.mkfifo(host)
    before = _tree(project)
    position = write_audit.mark()
    proc = _init(project, trust, "github-copilot")
    writes = write_audit.writes_since(position)
    out = _refused(proc)
    assert out["data"]["fragment"] == "unreadable"
    assert [p["code"] for p in out["problems"]] == ["HOST_ENTRY_UNREADABLE"]
    assert writes == [] and _tree(project) == before
    host.unlink()
    host.write_bytes(saved)
    again = _init(project, trust, "github-copilot")  # a regular file again: converges as before
    assert again.returncode == 0 and json.loads(again.stdout)["data"]["already_current"] is True


@posix
def test_fresh_init_fifo_at_skill_path_is_a_conflict_without_blocking(project, tmp_path):
    trust = tmp_path / "trust-app"
    target = project / ".github/skills" / SKILL
    target.parent.mkdir(parents=True)
    os.mkfifo(target)
    before = _tree(project)
    position = write_audit.mark()
    proc = _init(project, trust, "github-copilot")
    writes = write_audit.writes_since(position)
    out = _refused(proc)
    assert [p["code"] for p in out["problems"]] == ["SKILL_NAME_CONFLICT"]
    assert "not a regular file" in out["problems"][0]["message"]
    assert writes == [] and _tree(project) == before and target.is_fifo()


def test_fresh_init_readable_foreign_skill_conflict_message_unchanged(project, tmp_path):
    trust = tmp_path / "trust-app"
    target = project / ".github/skills" / SKILL
    target.parent.mkdir(parents=True)
    target.write_text("# my own skill\n", encoding="utf-8")
    proc = _init(project, trust, "github-copilot")
    out = _refused(proc)
    message = f".github/skills/{SKILL} exists and was not placed by this toolkit"
    assert out["problems"] == [{"code": "SKILL_NAME_CONFLICT", "message": message}]
