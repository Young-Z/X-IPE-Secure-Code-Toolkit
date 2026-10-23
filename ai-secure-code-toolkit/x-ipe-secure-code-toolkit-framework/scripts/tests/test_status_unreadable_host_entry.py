"""FEATURE-001-A-level status regression: an unopenable host entry file (AC-001A-09a…09c).

Defect fix approved by the delegated representative (DAO-001 in
x-ipe-docs/dao/26-10-23/decisions_made_code_implementation.md) during FEATURE-003-B TASK-062: status
crashed with a PermissionError traceback and no result.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
import write_audit
from conftest import TOOLKIT_ROOT, run_cli

posix_non_root = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                                    reason="needs POSIX permissions and a non-root user")


def _init(project, trust):
    proc = run_cli(["init", "--project", str(project), "--env", "github-copilot", "--json"], trust)
    assert proc.returncode == 0, proc.stdout


def _hashes(root, skip):
    result = {}
    for path in sorted(root.rglob("*")):
        if path == skip:
            stat = path.stat()
            result[str(path)] = f"mode={stat.st_mode} size={stat.st_size} mtime={stat.st_mtime_ns}"
        elif path.is_file() and not path.is_symlink():
            result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


@posix_non_root
def test_status_unopenable_host_entry_reported_with_next_step_not_traceback(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    agents = project / "AGENTS.md"
    agents.chmod(0)
    try:
        before = _hashes(project, agents)
        position = write_audit.mark()
        proc = run_cli(["status", "--project", str(project), "--json"], trust)
        writes = write_audit.writes_since(position)
        assert "Traceback" not in proc.stderr, proc.stderr
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(proc.stdout)["data"]
        sections = ("install", "authorization", "policies", "default_preset", "tools", "host_integration")
        for section in sections:
            assert section in data, section
        host = data["host_integration"]
        assert host["fragment"] == "unreadable" and host["host_effect"] == "not verified"
        assert host["next_step"] == "Make AGENTS.md readable, then re-run status"
        assert {"code": "FRAGMENT_UNREADABLE", "message": "Toolkit fragment in AGENTS.md is unreadable"} \
            in data["problems"]
        assert writes == [] and _hashes(project, agents) == before  # AC-001A-09b: status changes nothing
    finally:
        agents.chmod(0o644)


def test_status_non_utf8_host_entry_output_unchanged(project, tmp_path):
    trust = tmp_path / "trust-app"
    _init(project, trust)
    (project / "AGENTS.md").write_bytes(b"\xff\xfe not utf-8\n")
    proc = run_cli(["status", "--project", str(project), "--json"], trust)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)["data"]
    host = data["host_integration"]
    assert host["fragment"] == "unreadable"
    assert host["next_step"] == "Run project initialization to add the toolkit fragment"
    assert {"code": "FRAGMENT_UNREADABLE", "message": "Toolkit fragment in AGENTS.md is unreadable"} \
        in data["problems"]


def test_cli_contract_lists_fragment_unreadable_as_status_output():
    contract = (TOOLKIT_ROOT / "x-ipe-secure-code-toolkit-framework" / "references" / "cli-contract.md")
    flat = " ".join(contract.read_text(encoding="utf-8").split())
    status_only = flat[flat.index("status-only:"):flat.index("knowledge:", flat.index("status-only:"))]
    assert "`FRAGMENT_UNREADABLE`" in status_only
