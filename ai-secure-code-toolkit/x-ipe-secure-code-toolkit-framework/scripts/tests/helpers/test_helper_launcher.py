"""FEATURE-002-F trusted PID-1 launcher payload (DAO-018/019; AC-002F-04e host-side checks only — the
launcher's runtime behaviour is proven by conformance P-17 on a real runtime, not on this host)."""

# ruff: noqa: F811 - pytest fixtures imported by name from the shared helper modules

from __future__ import annotations

import hashlib
import subprocess
import sys

import pytest
from helperhelp import mod

LAUNCHER = mod("execute_io").LAUNCHER


def test_launcher_digest_constant():
    assert "sha256:" + hashlib.sha256(LAUNCHER.read_bytes()).hexdigest() == mod("model").LAUNCHER_SHA256
    assert mod("execute_io").launcher_bytes() == LAUNCHER.read_bytes()


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["target"],
        ["bogus", "5"],
        ["target", "0"],
        ["target", "121"],
        ["target", "x"],
        ["target", "5", "extra"],
        ["target", "-5"],
    ],
)
def test_launcher_args_validated(args):
    # not isolated (-I) here: the suite's write audit must see this child Python process start
    out = subprocess.run([sys.executable, "-B", str(LAUNCHER), *args], capture_output=True, timeout=30)
    assert out.returncode == 125


def test_launcher_staging_listing_exact(tmp_path, monkeypatch):
    execute_io = mod("execute_io")
    folder = execute_io.stage_helper(tmp_path / "h", b"print(1)\n")
    from pathlib import Path

    assert sorted(p.name for p in Path(folder).iterdir()) == ["launcher.py", "script.py"]
    assert all((Path(folder) / n).stat().st_mode & 0o777 == 0o444 for n in ("launcher.py", "script.py"))
    assert Path(folder).stat().st_mode & 0o777 == 0o555
    only = execute_io.stage_helper(tmp_path / "v", None)
    assert sorted(p.name for p in Path(only).iterdir()) == ["launcher.py"]
    monkeypatch.setattr(mod("execute_io"), "LAUNCHER_SHA256", "sha256:" + "0" * 64)
    with pytest.raises(mod("canonical").ConfigMismatch):
        execute_io.stage_helper(tmp_path / "w", None)
    for p in (Path(folder), Path(only)):
        p.chmod(0o700)
