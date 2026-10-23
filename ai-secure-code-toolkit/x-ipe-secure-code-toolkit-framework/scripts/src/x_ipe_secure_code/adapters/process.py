"""Run a tool without a shell (POSIX).

Minimal environment, stdout to a capped file (or a capped in-memory buffer), time limit and
process-group kill.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

STDERR_TAIL = 4096
POLL = 0.1


@dataclass(frozen=True)
class ProcessOutcome:
    exit: int | None
    timed_out: bool
    oversized: bool
    stderr_tail: str
    seconds: float
    cancelled: bool = False
    group_gone: bool = True
    stdout: bytes | None = None  # in-memory stdout (FEATURE-002-D) when no stdout file was requested


def _kill_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# os.waitid is missing on macOS before Python 3.13: there the leader is reaped before the final group
# kill (the FEATURE-002-B behaviour), which leaves a narrow process-group-id reuse window (stated limit).
HAS_WAITID = hasattr(os, "waitid") and hasattr(os, "WNOWAIT")


def _exited(proc: subprocess.Popen) -> bool:
    """True once the group leader has exited; with waitid it stays unreaped (pid/pgid reserved)."""
    if not HAS_WAITID:
        return proc.poll() is not None
    try:
        return os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    except ChildProcessError:
        return True


GROUP_WAIT = 5.0


def _live_members(pgid: int, proc: Path = Path("/proc")) -> bool | None:
    """Whether a not-yet-exited process is in the group; None when the member list cannot be read.

    Zombies (`Z`/`X`) have exited and only await reaping by their (re-)parent: killed Opengrep workers
    re-parented to a container PID 1 that never reaps them stay zombies forever.
    """
    if (proc / "self" / "stat").exists():
        want = str(pgid).encode()
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = (entry / "stat").read_bytes().rsplit(b")", 1)[1].split()
            except (OSError, IndexError):
                continue
            if len(fields) > 2 and fields[2] == want and fields[0] not in (b"Z", b"X"):
                return True
        return False
    try:
        out = subprocess.run(
            ["ps", "-A", "-o", "pgid=,stat="], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == str(pgid) and not parts[1].startswith(("Z", "X")):
            return True
    return False


def _group_gone(pgid: int, wait: float = GROUP_WAIT) -> bool:
    """After reaping: wait for the group to disappear; exited (zombie) members count as gone.

    A live, unknown or reused member reads as "not gone" (the safe side: never a false confirmation).
    """
    end = time.monotonic() + wait
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass  # macOS answers EPERM for a zombie-only group; the member list decides
        if _live_members(pgid) is False:
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(POLL / 2)


def minimal_env(stage: Path, home: Path) -> dict[str, str]:
    """The minimal environment of a launched tool: private home, caches and temporary folder only."""
    for sub in ("tmp", "work"):
        (stage / sub).mkdir(parents=True, exist_ok=True)
    for sub in (".config", ".cache"):
        (home / sub).mkdir(mode=0o700, exist_ok=True)
    return {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "TMPDIR": str(stage / "tmp"),
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
    }


def run(
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    deadline: float,
    stdout_path: Path | None,
    stdout_cap: int,
    should_stop: Callable[[], bool] | None = None,
    stderr_sink: Callable[[bytes], None] | None = None,
) -> ProcessOutcome:
    """Run `argv` until it exits, passes `deadline` (monotonic), writes more than `stdout_cap` bytes or
    `should_stop()` (cancellation) becomes true. The group is killed while the leader is unreaped.

    `stdout_path=None` keeps stdout in memory (never on disk); `stderr_sink` receives every stderr chunk.
    """
    if os.name != "posix":  # pragma: no cover - guarded by the pre-check
        raise RuntimeError("Adapter execution is supported on POSIX systems only in this version")
    start = time.monotonic()
    if should_stop is not None and should_stop():
        return ProcessOutcome(None, False, False, "", 0.0, cancelled=True)
    tail = bytearray()
    memory = bytearray() if stdout_path is None else None
    over = threading.Event()
    if stdout_path is not None:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with open(stdout_path, "wb") if stdout_path is not None else open(os.devnull, "wb") as out:
        proc = subprocess.Popen(
            argv,
            shell=False,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=out if memory is None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        pgid = proc.pid

        def drain() -> None:
            for chunk in iter(lambda: proc.stderr.read(4096), b""):
                if stderr_sink is not None:
                    stderr_sink(chunk)
                tail.extend(chunk)
                del tail[:-STDERR_TAIL]

        def collect() -> None:
            for chunk in iter(lambda: proc.stdout.read(65536), b""):
                if over.is_set():
                    continue
                memory.extend(chunk)
                if len(memory) > stdout_cap:
                    over.set()
                    del memory[stdout_cap:]

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        collector = threading.Thread(target=collect, daemon=True) if memory is not None else None
        if collector is not None:
            collector.start()
        timed_out = oversized = cancelled = False
        while not _exited(proc):
            if time.monotonic() > deadline:
                timed_out = True
            elif over.is_set() or (stdout_path is not None and stdout_path.stat().st_size > stdout_cap):
                oversized = True
            elif should_stop is not None and should_stop():
                cancelled = True
            if timed_out or oversized or cancelled:
                _kill_group(pgid)
                break
            time.sleep(POLL)
        give_up = time.monotonic() + 30
        while not _exited(proc) and time.monotonic() < give_up:
            time.sleep(POLL / 10)
        if HAS_WAITID:
            _kill_group(pgid)
            proc.wait()
        else:
            proc.wait()
            _kill_group(pgid)
        gone = _group_gone(pgid)
        reader.join(timeout=5)
        if collector is not None:
            collector.join(timeout=5)
    if not (timed_out or oversized or cancelled):
        if over.is_set() or (stdout_path is not None and stdout_path.stat().st_size > stdout_cap):
            oversized = True
    return ProcessOutcome(
        None if timed_out or oversized or cancelled else proc.returncode,
        timed_out,
        oversized,
        tail.decode("utf-8", errors="replace")[-STDERR_TAIL:],
        round(time.monotonic() - start, 2),
        cancelled,
        gone,
        None if memory is None or oversized else bytes(memory),
    )
