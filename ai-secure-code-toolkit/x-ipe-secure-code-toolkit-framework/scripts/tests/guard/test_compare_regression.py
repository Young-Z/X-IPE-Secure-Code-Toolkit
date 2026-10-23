"""FEATURE-002-G: delivered commands are unaffected by comparisons (AC-002G-07h, 07i).

07h uses a frozen clock (test-side patching only, FR-002G-10, DAO-012): delivered `guard conclude` also
persists budget-clock consumption, so an unfrozen run is not a valid oracle. No field is normalized.
"""

from __future__ import annotations

import io
import json
import shutil
from contextlib import redirect_stdout

import test_guard
from comparehelp import (
    COMPARISONS,
    E_ID,
    L_ID,
    REPORTS,
    freeze_clock,
    manifest,
    put_pair,
    run_compare,
)

from x_ipe_secure_code import cli
from x_ipe_secure_code.auth import trust_store
from x_ipe_secure_code.project_init import initialize_project

env = test_guard.env  # fixture reuse without re-import


def _cli(args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main([*args, "--json"])
    return code, buf.getvalue()


def _at(monkeypatch, text):
    freeze_clock(monkeypatch, text)


def test_07h_delivered_commands_unaffected_by_comparisons(env, monkeypatch, tmp_path):
    monkeypatch.setattr(trust_store, "default_app_dir", lambda: env["trust_dir"])
    project = env["project"]
    _at(monkeypatch, "2026-09-01T08:00:00Z")
    old, _ = test_guard.full_run(env)
    _at(monkeypatch, "2026-10-20T10:00:00Z")
    earlier, _ = test_guard.full_run(env)
    _at(monkeypatch, "2026-10-21T11:00:00Z")
    later, _ = test_guard.full_run(env, finding=False)
    _at(monkeypatch, "2026-10-22T09:00:00Z")
    open_run = test_guard.opened(env)
    assert test_guard.plan(env, open_run).ok
    _at(monkeypatch, "2026-10-22T12:00:00Z")
    out, _ = run_compare(project, (earlier,), (later,))
    assert out["ok"], out
    subject_copy, control_copy = tmp_path / "b-subject", tmp_path / "b-control"
    shutil.copytree(project, subject_copy, symlinks=True)
    shutil.copytree(project, control_copy, symlinks=True)
    shutil.rmtree(control_copy / COMPARISONS)
    comparison_bytes = {p.name: p.read_bytes() for p in (subject_copy / COMPARISONS).iterdir()}
    assert len(comparison_bytes) == 2

    commands = [
        ["guard", "show", "--run", earlier],
        ["guard", "keep", "--run", earlier, "--reason", "r"],
        ["guard", "release", "--run", earlier],
        ["guard", "conclude", "--run", open_run],
        ["guard", "cleanup"],
        ["status"],
    ]

    def run_all(source):
        shutil.rmtree(project)
        shutil.copytree(source, project, symlinks=True)
        _at(monkeypatch, "2026-10-25T12:00:00Z")
        outputs = [_cli([*cmd, "--project", str(project)]) for cmd in commands]
        return outputs, manifest(project, exclude=COMPARISONS)

    subject_out, subject_manifest = run_all(subject_copy)
    after = {p.name: p.read_bytes() for p in (project / COMPARISONS).iterdir()}
    control_out, control_manifest = run_all(control_copy)
    assert subject_out == control_out
    assert subject_manifest == control_manifest
    assert after == comparison_bytes
    cleanup = json.loads(subject_out[4][1])
    assert {r["verification_id"] for r in cleanup["data"]["removed"]} == {old}
    assert "comparisons" not in subject_out[4][1]
    assert json.loads(subject_out[3][1])["ok"] is True  # the open run concluded under the frozen clock


def test_07i_init_layout_unchanged_comparisons_after_first_success(project):
    assert initialize_project(str(project), "github-copilot").ok
    reports = project / REPORTS
    assert reports.is_dir() and not (project / COMPARISONS).exists()
    refused, _ = run_compare(project, (E_ID,), (E_ID,))
    assert refused["ok"] is False and not (project / COMPARISONS).exists()
    put_pair(project)
    missing, _ = run_compare(project, ("gv-20261011T000000Z-00000000",), (L_ID,))
    assert missing["ok"] is False and not (project / COMPARISONS).exists()
    done, _ = run_compare(project)
    assert done["ok"] and (project / COMPARISONS).is_dir()
