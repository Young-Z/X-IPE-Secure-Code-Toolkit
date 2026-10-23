"""FEATURE-001-F Integration: consumers load a Preset-based `clues` record through the unchanged
paths (AC-001F-09f): 001-C `scope show`, Guard open (FEATURE-002-A), Copilot open (FEATURE-003-A),
also after the Preset was changed or deleted.
"""

from __future__ import annotations

import pytest
from knowledge.exithelp import R1, R2
from presethelp import PEnv

from x_ipe_secure_code.copilot import service as copilot
from x_ipe_secure_code.guard import service as guard
from x_ipe_secure_code.policy import service as policy


@pytest.fixture
def saved(project, tmp_path):
    env = PEnv(project, tmp_path)
    env.rules()
    assert env.psave().ok
    proposal = env.presolve()
    result = env.pscope_save("web-input", env.pdecisions(proposal))
    assert result.ok, result.to_dict()
    return env, result.data["scope_id"]


def test_scope_show_loads_preset_scope_after_delete(saved):
    env, scope_id = saved
    assert env.pupdate(rules=[R1], keep_summary=True).ok
    assert env.pdelete().ok
    shown = policy.show_scope(str(env.project), scope_id)
    assert shown.ok, shown.to_dict()
    assert shown.data["mode"] == "clues" and shown.data["adopted_rules"] == [R1, R2]
    assert shown.data["clues"].startswith("preset:web-input@sha256:")


def test_guard_opens_with_preset_scope(saved):
    env, scope_id = saved
    assert env.pdelete().ok
    opened = guard.open_verification(str(env.project), env.open_request(scope_id, "guard"))
    assert opened.ok, opened.to_dict()
    assert opened.data["verification_id"]


def test_copilot_opens_with_preset_scope(saved):
    env, scope_id = saved
    assert env.pupdate(rules=[R1], keep_summary=True).ok
    opened = copilot.open_collaboration(str(env.project), env.open_request(scope_id, "copilot"))
    assert opened.ok, opened.to_dict()
    assert opened.data["collaboration_id"]
