"""FEATURE-001-E test guards (AC-001E-08f, B4 = B), autouse in every `tests/reference/` module.

Every test module imports `network_guards` (a nested conftest.py would shadow `tests/conftest.py`
under the prepend import mode), so every test runs with:
- a resolver guard: every Python-level name-resolution call fails and is recorded;
- a socket guard: `connect`/`connect_ex` only to `AF_INET` `("127.0.0.1", port)`, every attempt recorded;
- a subprocess guard: no process may be started from a FEATURE-001-E fetch call stack.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from typing import Any

import pytest

GUARD: dict[str, list[Any]] = {"resolver": [], "connects": [], "refused_connects": [], "subprocess": []}
FETCH_MODULES = ("x_ipe_secure_code.reference", "x_ipe_secure_code.guard.egress")
RESOLVERS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo", "getfqdn")


class GuardViolation(AssertionError):
    pass


def _in_fetch_stack() -> bool:
    frame = sys._getframe(1)
    while frame is not None:
        if str(frame.f_globals.get("__name__", "")).startswith(FETCH_MODULES):
            return True
        frame = frame.f_back
    return False


def _resolver(name: str):
    def refuse(*args: Any, **kwargs: Any) -> Any:
        GUARD["resolver"].append((name, args[:1]))
        raise GuardViolation(f"name resolution attempted: {name}{args[:1]}")

    return refuse


def _connect(real: Any):
    def guarded(self: socket.socket, address: Any, *args: Any) -> Any:
        if self.family != socket.AF_INET or not (
            isinstance(address, tuple) and len(address) == 2 and address[0] == "127.0.0.1"
        ):
            GUARD["refused_connects"].append(address)
            raise GuardViolation(f"non-loopback connection attempted: {address!r}")
        GUARD["connects"].append(address)
        return real(self, address, *args)

    return guarded


def _no_spawn(real: Any, name: str):
    def guarded(*args: Any, **kwargs: Any) -> Any:
        if _in_fetch_stack():
            GUARD["subprocess"].append(name)
            raise GuardViolation(f"process started from a fetch call stack: {name}")
        return real(*args, **kwargs)

    return guarded


@pytest.fixture(autouse=True)
def network_guards(monkeypatch):
    for key in GUARD:
        GUARD[key].clear()
    for name in RESOLVERS:
        monkeypatch.setattr(socket, name, _resolver(name))
    monkeypatch.setattr(socket.socket, "connect", _connect(socket.socket.connect))
    monkeypatch.setattr(socket.socket, "connect_ex", _connect(socket.socket.connect_ex))
    monkeypatch.setattr(subprocess, "Popen", _no_spawn(subprocess.Popen, "Popen"))
    monkeypatch.setattr(os, "system", _no_spawn(os.system, "system"))
    for name in ("posix_spawn", "posix_spawnp", "fork", "forkpty"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, _no_spawn(getattr(os, name), name))
    yield GUARD
    assert GUARD["resolver"] == [], GUARD["resolver"]
    assert GUARD["refused_connects"] == [], GUARD["refused_connects"]
    assert GUARD["subprocess"] == [], GUARD["subprocess"]
