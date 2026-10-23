"""FEATURE-003-B code-review fixes (TASK-062): unreadable carrier files; audit-hook internal errors."""

from __future__ import annotations

import hashlib
import os

import pytest
from carhelp import AGENTS, INSTR, codes, sandbox, status_entry, watch_writes, write_audit

posix_non_root = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                                    reason="needs POSIX permissions and a non-root user")
CASES = [(INSTR, "github-instructions", "CARRIER_UNREADABLE"),
         (AGENTS, "host-entry", "HOST_ENTRY_UNREADABLE")]


def _readable_hashes(root, skip):
    """SHA-256 of every readable file plus the mode/size of the unreadable one."""
    result = {}
    for path in sorted(root.rglob("*")):
        if path == skip:
            stat = path.stat()
            result[str(path)] = f"mode={stat.st_mode} size={stat.st_size} mtime={stat.st_mtime_ns}"
        elif path.is_file() and not path.is_symlink():
            result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


@pytest.fixture
def unreadable(tmp_path, request):
    rel = request.param
    box = sandbox(tmp_path)
    proc, out = box.carriers("--select", "github-instructions")
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    path = box.path(rel)
    path.chmod(0)
    try:
        yield box, path
    finally:
        path.chmod(0o644)


@posix_non_root
@pytest.mark.parametrize("unreadable,kind,code", [(rel, kind, code) for rel, kind, code in CASES],
                         indirect=["unreadable"], ids=["instructions", "agents"])
def test_carriers_refuses_an_unopenable_carrier_and_writes_nothing(unreadable, kind, code):
    box, path = unreadable
    box.edit_definition()  # every carrier would otherwise be updated
    before = _readable_hashes(box.root, path)
    with watch_writes() as writes:
        proc, out = box.carriers()
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 1 and not out["ok"]
    assert codes(out) == [code]
    assert path.relative_to(box.root).as_posix() in out["problems"][0]["message"]
    assert writes == [] and _readable_hashes(box.root, path) == before


@posix_non_root
@pytest.mark.parametrize("unreadable,kind,code", [(rel, kind, code) for rel, kind, code in CASES],
                         indirect=["unreadable"], ids=["instructions", "agents"])
def test_status_reports_an_unopenable_carrier_unreadable_with_full_output(unreadable, kind, code):
    box, path = unreadable
    before = _readable_hashes(box.root, path)
    proc, out = box.status()
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 0 and out["ok"], proc.stdout + proc.stderr
    data = out["data"]
    assert set(data) >= {"install", "authorization", "policies", "default_preset", "tools",
                         "host_integration", "problems"}
    assert status_entry(out, kind)["fragment"] == "unreadable"
    assert status_entry(out, kind)["host_effect"] == "not verified"
    other = "host-entry" if kind == "github-instructions" else "github-instructions"
    assert status_entry(out, other)["fragment"] == "present"
    if kind == "host-entry":
        assert data["host_integration"]["fragment"] == "unreadable"
    assert _readable_hashes(box.root, path) == before


def test_audit_hook_internal_error_is_recorded_as_a_violation(tmp_path):
    from x_ipe_secure_code.atomic import atomic_write_bytes

    wa = write_audit()
    project = tmp_path / "p"
    project.mkdir()
    real = wa._handle

    def broken(event, args):
        raise RuntimeError("injected audit failure")

    with wa.allow(project):
        position = wa.mark()
        wa._handle = broken
        try:
            atomic_write_bytes(project / "f.txt", b"x")  # the hook fails internally during this write
        finally:
            wa._handle = real
    assert (project / "f.txt").read_bytes() == b"x"  # the audited operation itself is not disturbed
    found = wa.violations_since(position)
    errors = [r for r in found if r["event"] == "audit-error"]
    assert errors and all("injected audit failure" in r["error"] for r in errors)
    assert wa.internal_error_problems()  # the session-finish flag is set …
    wa.consume(found)  # … and consuming the expected records clears it (otherwise the suite fails)
    assert wa.violations_since(position) == [] and wa.internal_error_problems() == []
