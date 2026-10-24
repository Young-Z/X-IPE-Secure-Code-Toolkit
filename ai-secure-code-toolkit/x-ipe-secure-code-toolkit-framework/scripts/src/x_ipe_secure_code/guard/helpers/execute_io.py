"""One toolkit-owned container run, results collection and the orphan sweep (design §9.0, §9.3, §10.1).

Every run: results volume (verified) → read-only holder (verified, started) → run container (verified,
normalized configuration kept) → `start --attach` under the L-10 deadline with stdout/stderr capped at
L-09 → confirmed stop → `cp <holder>:/results -` (never following links) → removal of every object,
verified by inspect. The exit status is never evidence.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..mask import mask_text
from . import canonical, results
from .canonical import LABEL, ConfigMismatch, Spec
from .model import L09_OUTPUT, LAUNCHER_SHA256, sha
from .model import canonical as canonical_json
from .runtime import CliRuntime, RuntimeGap

ERRNO_HINTS = (
    ("pids", ("Resource temporarily unavailable", "EAGAIN", "can't start new thread")),
    ("open_files", ("Too many open files", "EMFILE")),
    ("tmp", ("No space left on device", "ENOSPC")),
)


@dataclass
class Outcome:
    container: str
    purpose: str
    config: dict[str, Any] | None = None
    config_digest: str | None = None
    rendering: dict[str, Any] | None = None
    exit: int | None = None
    limit: str | None = None
    reason: str | None = None
    stdout: str = ""
    stderr: str = ""
    raw_stdout: bytes = b""
    truncated: bool = False
    seconds: float = 0.0
    result: bytes | None = None
    collect_error: str | None = None
    cancelled: bool = False
    stopped: bool = True
    cleanup: bool = True
    infrastructure: str | None = None
    mismatch: str | None = None
    oom: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunSpec:
    """A container run as the toolkit plans it (all values toolkit-owned)."""

    purpose: str
    name: str
    verification: str
    image: str
    interpreter: str
    image_env: list[str]
    limit: int
    stage_helper: str
    stage_input: str | None = None
    with_results: bool = True
    rendered: dict[str, Any] | None = None
    kill_client_after: float | None = None  # conformance P-17 only: the toolkit kills its own attach client
    self_stop_wait: float | None = None  # conformance P-17 only: wait for the container to stop by itself


def _spec(run: RunSpec, purpose: str, name: str, deadline: int, holder_seconds: int = 0) -> Spec:
    return Spec(
        purpose=purpose,
        name=name,
        image=run.image,
        interpreter=run.interpreter,
        image_env=run.image_env,
        labels=canonical.labels(run.verification, purpose, deadline),
        limit=run.limit,
        stage_input=run.stage_input,
        stage_helper=run.stage_helper,
        volume=f"{run.name}-results" if run.with_results else None,
        holder_seconds=holder_seconds,
    )


LAUNCHER = Path(__file__).resolve().parent / "payload" / "launcher.py"


def launcher_bytes() -> bytes:
    """The trusted launcher payload, re-hashed against the pinned digest before every use."""
    data = LAUNCHER.read_bytes()
    if sha(data) != LAUNCHER_SHA256:
        raise ConfigMismatch("launcher digest differs from the toolkit constant")
    return data


def stage_helper(folder: Path, script: bytes | None) -> str:
    """The read-only `/helper` folder: exactly launcher.py (+ script.py); dirs 0555, files 0444."""
    folder.mkdir(parents=True, mode=0o700)
    (folder / "launcher.py").write_bytes(launcher_bytes())
    if script is not None:
        (folder / "script.py").write_bytes(script)
    expected = {"launcher.py"} | ({"script.py"} if script is not None else set())
    for name in expected:
        (folder / name).chmod(0o444)
    folder.chmod(0o555)
    if {p.name for p in folder.iterdir()} != expected or any(p.is_symlink() for p in folder.iterdir()):
        raise ConfigMismatch("helper staging listing")
    return str(folder)


def _hint(stderr: str) -> str | None:
    for name, needles in ERRNO_HINTS:
        if any(n in stderr for n in needles):
            return name
    return None


def run_container(
    rt: CliRuntime,
    run: RunSpec,
    should_stop: Callable[[], bool],
    on_objects: Callable[[list[str], str | None], None],
) -> Outcome:
    """Run one container start under the canonical configuration; never raises for container outcomes."""
    deadline = int(time.time()) + run.limit + 60
    holder = f"{run.name}-holder"
    volume = f"{run.name}-results" if run.with_results else None
    names = [run.name, holder] if run.with_results else [run.name]
    out = Outcome(container=run.name, purpose=run.purpose)
    on_objects(names, volume)
    start = time.monotonic()
    try:
        if volume:
            vlabels = canonical.labels(run.verification, "results", deadline)
            rt.ok(canonical.volume_args(volume, vlabels))
            canonical.verify_volume(rt.volume(volume), vlabels)
            hspec = _spec(run, "holder", holder, deadline, run.limit + 30)
            rt.ok(canonical.create_args(hspec))
            canonical.verify(rt.inspect(holder), hspec, None)
            rt.ok(["start", holder])
        spec = _spec(run, run.purpose, run.name, deadline)
        rt.ok(canonical.create_args(spec))
        created = rt.inspect(run.name)
        out.config = canonical.verify(created, spec, run.rendered)
        out.rendering = canonical.rendering(created)
        out.config_digest = sha(canonical_json(out.config))
        attached = time.monotonic()
        _attach(rt, run, out, should_stop)
        if out.cancelled:
            return out
        if run.self_stop_wait is not None:
            out.extra["self_stopped"] = rt.wait_stopped(run.name, run.self_stop_wait)
            out.extra["stopped_after"] = round(time.monotonic() - attached, 1)
        state = (rt.inspect(run.name) or {}).get("State") or {}
        if state.get("Running"):
            rt.call(["kill", run.name])
            out.stopped = rt.wait_stopped(run.name)
            state = (rt.inspect(run.name) or {}).get("State") or {}
        if not out.stopped:
            out.limit, out.reason = None, "container did not stop"
            return out
        out.oom = bool(state.get("OOMKilled"))
        if out.exit is None and isinstance(state.get("ExitCode"), int) and not out.limit:
            out.exit = state["ExitCode"]
        _classify(out)
        if volume and (out.limit is None and out.reason is None or run.self_stop_wait is not None):
            got = rt.call(["cp", f"{holder}:/results", "-"], cap=results.TAR_CAP)
            try:
                out.result = results.from_tar(got.stdout if got.exit == 0 else None)
            except results.ResultInvalid as exc:
                out.collect_error = exc.reason
    except ConfigMismatch as exc:
        out.mismatch = exc.invariant
    except RuntimeGap as exc:
        out.infrastructure = exc.reason
    finally:
        out.seconds = round(time.monotonic() - start, 2)
        try:
            out.cleanup = rt.remove(names, volume)
        except RuntimeGap:
            out.cleanup = False
    return out


def _attach(rt: CliRuntime, run: RunSpec, out: Outcome, should_stop: Callable[[], bool]) -> None:
    kept, over = bytearray(), [False]

    def sink(chunk: bytes) -> None:
        room = L09_OUTPUT - len(kept)
        kept.extend(chunk[: max(0, room)])
        if len(chunk) > room:
            over[0] = True

    started = time.monotonic()

    def stop() -> bool:
        if run.kill_client_after is not None and time.monotonic() - started > run.kill_client_after:
            return True
        return over[0] or should_stop()

    attach = rt.call(
        ["start", "--attach", run.name], timeout=run.limit, cap=L09_OUTPUT, should_stop=stop, stderr_sink=sink
    )
    out.stderr = mask_text(bytes(kept).decode("utf-8", "replace"))[0]
    out.raw_stdout = attach.stdout or b""
    out.stdout = mask_text(out.raw_stdout.decode("utf-8", "replace"))[0]
    if attach.timed_out:
        out.limit, out.reason = "time", "time limit (L-10)"
    elif attach.oversized or over[0]:
        out.limit, out.reason, out.truncated = "output", "output limit exceeded (L-09)", True
    elif attach.cancelled and run.kill_client_after is None:
        out.cancelled = True
    else:
        out.exit = attach.exit
    out.extra["group_gone"] = attach.group_gone


def _classify(out: Outcome) -> None:
    if out.limit:
        return
    if out.oom:
        out.limit, out.reason = "memory", "memory limit (L-06)"
    elif out.exit == 124:
        out.limit, out.reason = "time", "time limit (L-10)"
    elif out.exit == 152:
        out.limit, out.reason = "time", "cpu time limit (L-10)"
    elif out.exit not in (0, None):
        hint = _hint(out.stderr)
        out.limit = hint
        out.reason = (
            f"{hint} limit reached" if hint else f"script error under enforced limits (exit {out.exit})"
        )


def sweep(rt: CliRuntime, now: float | None = None) -> list[str]:
    """Remove labelled runtime objects whose deadline passed or whose owner process is gone (M4)."""
    now = time.time() if now is None else now
    containers, volumes = rt.labelled(f"{LABEL}=helper")
    removed = []

    def expired(row: dict[str, str]) -> bool:
        try:
            deadline = int(row.get(f"label:{LABEL}.deadline", "0"))
        except ValueError:
            deadline = 0
        owner = row.get(f"label:{LABEL}.owner-pid", "")
        alive = owner.isdigit() and (int(owner) == os.getpid() or _alive(int(owner)))
        return deadline < now or not alive

    for row in containers:
        if expired(row):
            rt.call(["rm", "-f", row["name"]])
            removed.append(row["name"])
    for row in volumes:
        if expired(row):
            rt.call(["volume", "rm", "-f", row["name"]])
            removed.append(row["name"])
    return removed


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
