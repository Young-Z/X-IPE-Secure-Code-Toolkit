"""Commit barrier, clock and exclusive result primitives (FEATURE-002-C design: runs.py)."""

from __future__ import annotations

import json
import threading

import pytest

from x_ipe_secure_code.atomic import ProcessLock
from x_ipe_secure_code.guard import runs
from x_ipe_secure_code.guard.model import SCHEMA_RESULT, SCHEMA_RUN, GuardError

VID = "gv-20261020T100000Z-0000abcd"


@pytest.fixture()
def root(tmp_path):
    (tmp_path / runs.run_rel(VID)).mkdir(parents=True)
    runs.write_state(tmp_path, {"schema": SCHEMA_RUN, "verification_id": VID, "revision": 3, "x": 1})
    return tmp_path


def test_commit_state_increments_revision(root):
    state = runs.read_state(root, VID)
    state["x"] = 2
    runs.commit_state(root, state, expected_revision=3)
    stored = runs.read_state(root, VID)
    assert stored["x"] == 2 and stored["revision"] == 4


def test_commit_state_refuses_stale_revision(root):
    state = runs.read_state(root, VID)
    with pytest.raises(GuardError) as exc:
        runs.commit_state(root, state, expected_revision=2)
    assert exc.value.code == "STATE_CHANGED"
    assert runs.read_state(root, VID)["revision"] == 3


def test_commit_state_refuses_after_cancel_marker(root):
    assert runs.create_marker(root, VID, {"requested_at": "t", "reason": None, "consumed_at_request": 5.0})
    assert not runs.create_marker(
        root, VID, {"requested_at": "u", "reason": None, "consumed_at_request": 9.0}
    )
    assert runs.cancel_marker(root, VID)["requested_at"] == "t"
    state = runs.read_state(root, VID)
    with pytest.raises(GuardError) as exc:
        runs.commit_state(root, state, expected_revision=3)
    assert exc.value.code == "RUN_CANCELLED"


def test_commit_state_refuses_after_result(root):
    runs.write_result(root, {"schema": SCHEMA_RESULT, "verification_id": VID})
    with pytest.raises(GuardError) as exc:
        runs.commit_state(root, runs.read_state(root, VID), expected_revision=3)
    assert exc.value.code == "RUN_FINISHED"


def test_update_state_reads_latest(root):
    def fn(state):
        state["x"] += 10

    out = runs.update_state(root, VID, fn)
    assert out["x"] == 11 and runs.read_state(root, VID)["revision"] == 4


def test_commit_waits_for_barrier_holder(root):
    order = []
    barrier = runs.commit_lock(root, VID)

    def writer():
        runs.update_state(root, VID, lambda s: s.update(x=99))
        order.append("written")

    with ProcessLock(barrier, timeout=1):
        t = threading.Thread(target=writer)
        t.start()
        t.join(0.3)
        order.append("released")
    t.join(5)
    assert order == ["released", "written"]


def test_bump_clock_monotonic_and_frozen_by_marker(root):
    assert runs.bump_clock(root, VID, 100.0) == 100.0
    assert runs.bump_clock(root, VID, 90.0) == 100.0
    assert json.loads((root / runs.run_rel(VID) / "clock.json").read_text())["consumed_hw"] == 100.0
    runs.create_marker(root, VID, {"requested_at": "t", "reason": None, "consumed_at_request": 120.0})
    assert runs.bump_clock(root, VID, 500.0) == 120.0


def test_create_result_exclusive_once(root):
    r1 = {"schema": SCHEMA_RESULT, "verification_id": VID, "n": 1}
    r2 = {"schema": SCHEMA_RESULT, "verification_id": VID, "n": 2}
    runs.create_result_exclusive(root, r1)
    with pytest.raises(FileExistsError):
        runs.create_result_exclusive(root, r2)
    assert runs.read_result(root, VID)["n"] == 1
    leftovers = [p.name for p in (root / runs.REPORTS_REL).iterdir() if p.name.startswith(".")]
    assert leftovers == []
