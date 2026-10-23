"""FEATURE-001-A-level regression (TASK-097): toolkit-owned files that exist but cannot be read.

A FIFO at the install record blocked `init` (holding the project lock), `status` and `carriers`, because
the record was read after an existence check only. The sweep of the same paths found: `status` crashed
on an unreadable installed toolkit file or knowledge folder and blocked on a FIFO trust file; `init`
blocked on a FIFO and crashed on an unreadable file in the toolkit source (payload).
Intended (specification L192 / NFR-001A-5 "fail with reason", AC-001A-09a…09e separated status with
obvious configuration problems, technical design "blocking problems … return before any write"):
existing problem codes and next steps, nothing written, no traceback, no blocking.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest
import write_audit
from conftest import LAUNCHER, TOOLKIT_ROOT, _cli_roots, run_cli

posix = pytest.mark.skipif(os.name != "posix", reason="needs POSIX FIFOs")
posix_non_root = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                                    reason="needs POSIX permissions and a non-root user")
RECORD = ".x-ipe/private/secure-code/install-record.json"
INSPECT = [f"Inspect {RECORD}; it is not repaired automatically"]
SKILL = ".github/skills/x-ipe-secure-code-toolkit-framework/SKILL.md"
SECTIONS = ("install", "authorization", "policies", "default_preset", "tools", "host_integration")
TIMEOUT = 30


def _cli(args, trust):
    """Run the CLI like `run_cli`, but with a short timeout so a blocking read fails the test."""
    args = [str(a) for a in args] + ["--json"]
    child_env = dict(os.environ)
    child_env.update(write_audit.child_env(_cli_roots(args, trust)))
    cmd = [sys.executable, str(LAUNCHER), "--test-trust-dir", str(trust), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=child_env, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{args[0]} did not finish within {TIMEOUT}s (blocked on a non-regular file)")
    assert "Traceback" not in proc.stderr, proc.stderr
    return proc, json.loads(proc.stdout)


def _installed(project, trust):
    proc = run_cli(["init", "--project", str(project), "--env", "github-copilot", "--json"], trust)
    assert proc.returncode == 0, proc.stdout + proc.stderr


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


def _fifo_record(project):
    record = project / RECORD
    record.parent.mkdir(parents=True, exist_ok=True)
    record.unlink(missing_ok=True)
    os.mkfifo(record)
    return record


def _refused_record(proc, out, command):
    assert proc.returncode == 1, proc.stdout
    assert out["command"] == command and out["ok"] is False
    assert out["problems"] == [{"code": "RECORD_INVALID",
                                "message": "install record unreadable: not a regular file"}]
    assert out["next_steps"] == INSPECT


@posix
def test_fresh_init_fifo_install_record_refused_without_blocking(project, tmp_path):
    trust = tmp_path / "trust-app"
    record = _fifo_record(project)
    before = _tree(project)
    position = write_audit.mark()
    proc, out = _cli(["init", "--project", project, "--env", "github-copilot"], trust)
    writes = write_audit.writes_since(position)
    _refused_record(proc, out, "init")
    assert writes == [] and _tree(project) == before and record.is_fifo()
    assert not (project / "AGENTS.md").exists() and not (project / ".github").exists()


@posix
@pytest.mark.parametrize("command", ["init", "carriers"])
def test_installed_fifo_install_record_refused_without_blocking(project, tmp_path, command):
    trust = tmp_path / "trust-app"
    _installed(project, trust)
    record = _fifo_record(project)
    before = _tree(project)
    position = write_audit.mark()
    proc, out = _cli([command, "--project", project, "--env", "github-copilot"], trust)
    writes = write_audit.writes_since(position)
    _refused_record(proc, out, command)
    assert writes == [] and _tree(project) == before and record.is_fifo()


@posix
def test_status_fifo_install_record_reported_as_invalid_record(project, tmp_path):
    trust = tmp_path / "trust-app"
    _installed(project, trust)
    _fifo_record(project)
    before = _tree(project)
    position = write_audit.mark()
    proc, out = _cli(["status", "--project", project], trust)
    writes = write_audit.writes_since(position)
    assert proc.returncode == 0, proc.stdout
    data = out["data"]
    assert all(section in data for section in SECTIONS)
    inspect = "Inspect the install record; it is not repaired automatically"
    assert {k: v for k, v in data["install"].items() if k != "root"} == {
        "state": "invalid record", "next_step": inspect}
    assert {"code": "RECORD_INVALID", "message": "install record unreadable: not a regular file"} \
        in data["problems"]
    assert writes == [] and _tree(project) == before


@posix_non_root
def test_unreadable_install_record_refusal_unchanged(project, tmp_path):
    """Characterization: the existing OSError branch of the record load (passes before and after)."""
    trust = tmp_path / "trust-app"
    _installed(project, trust)
    record = project / RECORD
    record.chmod(0)
    try:
        proc, out = _cli(["init", "--project", project, "--env", "github-copilot"], trust)
    finally:
        record.chmod(0o600)
    assert proc.returncode == 1 and out["next_steps"] == INSPECT
    assert [p["code"] for p in out["problems"]] == ["RECORD_INVALID"]
    assert out["problems"][0]["message"].startswith("install record unreadable: [Errno 13] Permission denied")


@posix_non_root
def test_status_unreadable_installed_toolkit_file_counted_as_changed(project, tmp_path):
    trust = tmp_path / "trust-app"
    _installed(project, trust)
    target = project / SKILL
    target.chmod(0)
    try:
        before = _tree(project)
        position = write_audit.mark()
        proc, out = _cli(["status", "--project", project], trust)
        writes = write_audit.writes_since(position)
        assert writes == [] and _tree(project) == before
    finally:
        target.chmod(0o644)
    assert proc.returncode == 0, proc.stdout
    install = out["data"]["install"]
    assert install["state"] == "installed" and install["changed_toolkit_files"] == 1
    assert install["next_step"] == "Re-run project initialization to review"
    assert {"code": "TOOLKIT_FILES_CHANGED", "message": "1 toolkit file(s) differ from the install record"} \
        in out["data"]["problems"]


@posix_non_root
def test_status_unreadable_knowledge_folders_reported_not_traceback(project, tmp_path):
    trust = tmp_path / "trust-app"
    _installed(project, trust)
    knowledge = project / "x-ipe-docs/secure-code/knowledge"
    (knowledge / "reference/acme/1.0/R-1").mkdir(parents=True)
    (knowledge / "reference/beta/1.0/R-2").mkdir(parents=True)
    local, namespace = knowledge / "local", knowledge / "reference/acme"
    local.chmod(0)
    namespace.chmod(0)
    try:
        before = _tree(project)
        position = write_audit.mark()
        proc, out = _cli(["status", "--project", project], trust)
        writes = write_audit.writes_since(position)
        assert writes == [] and _tree(project) == before
    finally:
        local.chmod(0o755)
        namespace.chmod(0o755)
    assert proc.returncode == 0, proc.stdout
    data = out["data"]
    assert all(section in data for section in SECTIONS)
    assert (data["policies"]["local"], data["policies"]["reference"]) == (0, 1)
    io_errors = [p for p in data["problems"] if p["code"] == "IO_ERROR"]
    folder = "Folder x-ipe-docs/secure-code/knowledge"
    assert io_errors == [
        {"code": "IO_ERROR", "message": f"{folder}/local cannot be read (Permission denied)"},
        {"code": "IO_ERROR", "message": f"{folder}/reference/acme cannot be read (Permission denied)"},
    ]


@posix
def test_status_fifo_trust_file_reported_invalid_without_blocking(project, tmp_path):
    trust = tmp_path / "trust-app"
    _installed(project, trust)
    (trust / "trust").mkdir(parents=True, exist_ok=True)
    os.mkfifo(trust / "trust" / "trusted-public-key.pem")
    proc, out = _cli(["status", "--project", project], trust)
    assert proc.returncode == 0, proc.stdout
    auth = out["data"]["authorization"]
    assert auth["role"] == "user" and auth["state"] == "invalid"
    assert "trusted public key missing or unreadable" in auth["reason"]
    assert {"code": "TRUST_INVALID", "message": auth["reason"]} in out["data"]["problems"]
    assert (trust / "trust" / "trusted-public-key.pem").is_fifo()


def _payload_copy(tmp_path):
    dest = tmp_path / "toolkit-copy"
    for name in ("x-ipe-secure-code-toolkit-framework", "x-ipe-secure-code-toolkit-copilot",
                 "x-ipe-secure-code-toolkit-guard"):
        shutil.copytree(TOOLKIT_ROOT / name, dest / name, symlinks=True,
                        ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".ruff_cache",
                                                      "tests", ".coverage*"))
    return dest


@posix
def test_init_fifo_in_toolkit_source_refused_before_any_write(project, tmp_path):
    trust = tmp_path / "trust-app"
    source = _payload_copy(tmp_path)
    os.mkfifo(source / "x-ipe-secure-code-toolkit-guard" / "extra")
    position = write_audit.mark()
    args = ["init", "--project", project, "--env", "github-copilot", "--toolkit-source", source]
    proc, out = _cli(args, trust)
    writes = write_audit.writes_since(position)
    assert proc.returncode == 1 and out["ok"] is False
    assert out["problems"] == [{"code": "PAYLOAD_INCOMPLETE", "message": (
        "Toolkit source file x-ipe-secure-code-toolkit-guard/extra is not a readable regular file")}]
    assert out["next_steps"] == ["Use a complete toolkit folder (--toolkit-source DIR)"]
    assert writes == [] and list(project.iterdir()) == []


@posix_non_root
def test_init_unreadable_file_in_toolkit_source_refused_before_any_write(project, tmp_path):
    trust = tmp_path / "trust-app"
    source = _payload_copy(tmp_path)
    bad = source / "x-ipe-secure-code-toolkit-guard" / "SKILL.md"
    bad.chmod(0)
    try:
        position = write_audit.mark()
        args = ["init", "--project", project, "--env", "github-copilot", "--toolkit-source", source]
        proc, out = _cli(args, trust)
        writes = write_audit.writes_since(position)
    finally:
        bad.chmod(0o644)
    assert proc.returncode == 1 and out["ok"] is False
    assert out["problems"] == [{"code": "PAYLOAD_INCOMPLETE", "message": (
        "Toolkit source file x-ipe-secure-code-toolkit-guard/SKILL.md is not a readable regular file")}]
    assert writes == [] and list(project.iterdir()) == []


@posix_non_root
def test_init_unreadable_folder_in_toolkit_source_refused_before_any_write(project, tmp_path):
    """Review finding: os.walk skipped an unlistable folder, so init installed a partial toolkit (exit 0)."""
    trust = tmp_path / "trust-app"
    source = _payload_copy(tmp_path)
    folder = source / "x-ipe-secure-code-toolkit-framework" / "references"
    folder.chmod(0)
    try:
        position = write_audit.mark()
        args = ["init", "--project", project, "--env", "github-copilot", "--toolkit-source", source]
        proc, out = _cli(args, trust)
        writes = write_audit.writes_since(position)
    finally:
        folder.chmod(0o755)
    assert proc.returncode == 1 and out["ok"] is False
    assert out["problems"] == [{"code": "PAYLOAD_INCOMPLETE", "message": (
        "Toolkit source folder x-ipe-secure-code-toolkit-framework/references cannot be read "
        "(Permission denied)")}]
    assert out["next_steps"] == ["Use a complete toolkit folder (--toolkit-source DIR)"]
    assert writes == [] and list(project.iterdir()) == []
