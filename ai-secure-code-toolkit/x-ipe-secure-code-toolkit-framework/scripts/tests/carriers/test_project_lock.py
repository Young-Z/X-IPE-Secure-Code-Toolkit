"""FEATURE-003-B unit tests: the file-free project lock (AC-003B-04g, 04h, 04i; DAO-005 RED-first items).

- EWOULDBLOCK/EAGAIN from flock means "supported but held": bounded wait of the existing toolkit lock
  timeout (atomic.LOCK_TIMEOUT, 10.0 s, value unchanged), then LockHeld / LOCKED.
- ENOLCK/EOPNOTSUPP/ENOTSUP/EINVAL (or a root that cannot be opened read-only) means "unavailable":
  carriers refuses LOCK_UNAVAILABLE (interim, B11); plain init runs exactly the FEATURE-001-A path.
"""

from __future__ import annotations

import errno
import fcntl
import inspect
import os
import time

import pytest
from carhelp import (
    HELD_ERRNOS,
    UNAVAILABLE_ERRNOS,
    allow,
    baseline_001a,
    flock_failing_with,
    init_001a_sequence,
    listing,
    sandbox,
    toolkit_copy,
)

from x_ipe_secure_code.environments import PROFILES


def _atomic():
    from x_ipe_secure_code import atomic

    return atomic


def _root(tmp_path):
    root = tmp_path / "lock root ü"
    root.mkdir()
    return root


def test_lock_timeout_reuses_existing_value():
    atomic = _atomic()
    from x_ipe_secure_code.copilot import service as copilot_service
    from x_ipe_secure_code.guard import service as guard_service

    process_default = inspect.signature(atomic.ProcessLock.__init__).parameters["timeout"].default
    project_default = inspect.signature(atomic.ProjectLock.__init__).parameters["timeout"].default
    assert atomic.LOCK_TIMEOUT == 10.0
    assert process_default == project_default == atomic.LOCK_TIMEOUT
    assert copilot_service.LOCK_TIMEOUT == guard_service.LOCK_TIMEOUT == atomic.LOCK_TIMEOUT


def test_held_lock_waited_for_bounded_time_then_lockheld_and_acquired_after_release(tmp_path):
    atomic = _atomic()
    root = _root(tmp_path)
    holder = os.open(root, os.O_RDONLY)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        assert atomic.ProjectLock.available(root) is True  # held by another descriptor = supported
        start = time.monotonic()
        with pytest.raises(atomic.LockHeld), atomic.ProjectLock(root, timeout=0.4):
            pass
        assert 0.4 <= time.monotonic() - start < 3.0
    finally:
        os.close(holder)
    with atomic.ProjectLock(root, timeout=0.4):
        pass
    assert listing(root) == set()  # no lock file, ever


@pytest.mark.parametrize("name", sorted(HELD_ERRNOS))
def test_probe_ewouldblock_eagain_is_supported_but_held(tmp_path, monkeypatch, name):
    atomic = _atomic()
    root = _root(tmp_path)
    calls = flock_failing_with(monkeypatch, HELD_ERRNOS[name])
    assert atomic.ProjectLock.available(root) is True
    start = time.monotonic()
    with pytest.raises(atomic.LockHeld), atomic.ProjectLock(root, timeout=0.3):
        pass
    assert time.monotonic() - start >= 0.3  # waited (polled), did not give up as "unavailable"
    assert len(calls) >= 3
    assert listing(root) == set()


@pytest.mark.parametrize("name", sorted(UNAVAILABLE_ERRNOS))
def test_probe_enolck_eopnotsupp_enotsup_einval_is_unavailable(tmp_path, monkeypatch, name):
    atomic = _atomic()
    root = _root(tmp_path)
    flock_failing_with(monkeypatch, UNAVAILABLE_ERRNOS[name])
    assert atomic.ProjectLock.available(root) is False
    start = time.monotonic()
    with pytest.raises(atomic.LockUnavailable), atomic.ProjectLock(root, timeout=5.0):
        pass
    assert time.monotonic() - start < 1.0  # no bounded wait for an unavailable lock
    assert listing(root) == set()


def test_root_not_openable_read_only_is_unavailable(tmp_path, monkeypatch):
    atomic = _atomic()
    root = _root(tmp_path)
    real_open = os.open

    def deny(path, flags, *args, **kwargs):
        if os.fspath(path) == os.fspath(root):
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny)
    assert atomic.ProjectLock.available(root) is False


def test_windows_simulated_unavailable_without_io(tmp_path, monkeypatch):
    from carhelp import simulate_no_lock_platform

    atomic = _atomic()
    root = _root(tmp_path)
    flock_calls = simulate_no_lock_platform(monkeypatch)
    opened: list = []
    real_open = os.open
    monkeypatch.setattr(os, "open", lambda *a, **k: opened.append(a) or real_open(*a, **k))
    assert atomic.ProjectLock.available(root) is False
    assert opened == [] and flock_calls == []  # a constant decision, no I/O


def test_plain_init_ewouldblock_waits_bounded_then_locked(tmp_path, monkeypatch):
    from x_ipe_secure_code.project_init import initialize_project

    box = sandbox(tmp_path)
    before = box.hashes()
    flock_failing_with(monkeypatch, errno.EWOULDBLOCK)
    start = time.monotonic()
    with allow(box.root):
        result = initialize_project(str(box.root), "github-copilot")
    elapsed = time.monotonic() - start
    assert not result.ok and [p.code for p in result.problems] == ["LOCKED"]
    assert any("retry" in step.lower() for step in result.next_steps)
    assert 9.5 <= elapsed <= 13.0  # the existing 10.0 s toolkit lock timeout, never unbounded
    assert box.hashes() == before


@pytest.mark.parametrize("env", list(PROFILES))
@pytest.mark.parametrize("name", sorted(UNAVAILABLE_ERRNOS))
def test_plain_init_with_unavailable_lock_identical_to_001a_baseline(tmp_path, monkeypatch, name, env):
    from x_ipe_secure_code.project_init import initialize_project

    atomic = _atomic()
    era = toolkit_copy(tmp_path, era="001A")
    root = tmp_path / f"proj {env} ü"
    root.mkdir()
    calls = flock_failing_with(monkeypatch, UNAVAILABLE_ERRNOS[name])
    assert atomic.ProjectLock.available(root) is False

    def run_init(*args, json_out=True):
        replace = [args[1]] if args else None
        with allow(root):
            result = initialize_project(str(root), env, replace, str(era))
        return (0 if result.ok else 1), (result.to_json() if json_out else result.to_text())

    steps = init_001a_sequence(run_init, root, PROFILES[env].host_entry)
    assert steps == baseline_001a()["sequences"][env]  # byte-identical to the FEATURE-001-A baseline
    assert all(not op & fcntl.LOCK_EX for _fd, op in calls)  # nothing beyond the availability probe
    assert not any("lock" in rel for rel in listing(root / ".x-ipe"))
