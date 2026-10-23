"""Run folders, run state, structured result and report files (all paths symlink-checked)."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from ..adapters import safe_io
from ..atomic import PRIVATE_DIR_MODE, PRIVATE_FILE_MODE, ProcessLock, atomic_write_bytes, dumps_json
from ..knowledge import store
from .model import GUARD_REL, REPORTS_REL, RUN_ID, SCHEMA_RESULT, SCHEMA_RUN, GuardError

NEW_RUN = "Pass the verification_id returned by secure-code guard open"


def check_id(text: Any) -> str:
    if not isinstance(text, str) or not RUN_ID.fullmatch(text):
        raise GuardError("RUN_NOT_FOUND", f"Not a verification id: {text!r}", NEW_RUN)
    return text


def run_rel(vid: str) -> str:
    return f"{GUARD_REL}/{vid}"


def run_dir(root: Path, vid: str) -> Path:
    store.ensure_safe(root, run_rel(vid), expect_dir=True)
    return root / run_rel(vid)


def allocate(root: Path, opened_at: str) -> str:
    store.ensure_safe(root, GUARD_REL, expect_dir=True)
    (root / GUARD_REL).mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    stamp = opened_at.replace("-", "").replace(":", "")
    while True:
        vid = f"gv-{stamp}-{secrets.token_hex(4)}"
        try:
            (root / run_rel(vid)).mkdir(mode=PRIVATE_DIR_MODE)
            return vid
        except FileExistsError:
            continue


def _state_path(root: Path, vid: str) -> Path:
    run_dir(root, vid)
    store.ensure_safe(root, f"{run_rel(vid)}/state.json", expect_dir=False)
    return root / run_rel(vid) / "state.json"


def has_state(root: Path, vid: str) -> bool:
    return _state_path(root, vid).is_file()


def read_state(root: Path, vid: str) -> dict[str, Any]:
    path = _state_path(root, vid)
    if not path.is_file():
        raise GuardError(
            "RUN_NOT_FOUND", f"No open verification {vid} (unknown, or its evidence was removed)", NEW_RUN
        )
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        state = None
    if (
        not isinstance(state, dict)
        or state.get("schema") != SCHEMA_RUN
        or state.get("verification_id") != vid
    ):
        raise GuardError(
            "RUN_INVALID",
            f"Run state of {vid} is not readable",
            "Start a new verification with secure-code guard open",
        )
    return state


def write_state(root: Path, state: dict[str, Any]) -> None:
    atomic_write_bytes(_state_path(root, state["verification_id"]), dumps_json(state), private=True)


def write_evidence(root: Path, vid: str, eid: str, text: str) -> None:
    rel = f"{run_rel(vid)}/evidence"
    store.ensure_safe(root, rel, expect_dir=True)
    store.ensure_safe(root, f"{rel}/{eid}.txt", expect_dir=False)
    folder = root / rel
    dest = folder / f"{eid}.txt"
    if dest.parent != folder or dest.name != f"{eid}.txt":
        raise GuardError("RECORD_INVALID", f"Evidence id {eid!r} is not a safe file name")
    folder.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    atomic_write_bytes(dest, text.encode("utf-8", errors="replace"), private=True)


def remove_evidence_files(root: Path, vid: str, names: list[str]) -> bool:
    """Unlink exactly the named files of the run's evidence folder without following any link.

    Returns False (removing nothing further) when the folder or an entry is not safe to remove.
    """
    if any(not n or "/" in n or "\\" in n or n in (".", "..") for n in names):
        raise ValueError(f"not plain evidence file names: {names!r}")
    rel = f"{run_rel(vid)}/evidence"
    if not os.path.lexists(root / rel):
        return True
    if not safe_io.POSIX_FD:
        try:
            store.ensure_safe(root, rel, expect_dir=True)
            for name in names:
                store.ensure_safe(root, f"{rel}/{name}", expect_dir=False)
                (root / rel / name).unlink(missing_ok=True)
        except (OSError, store.StoreError):
            return False
        return True
    try:
        fd = safe_io.open_dir_nofollow(root, rel)
    except (OSError, safe_io.UnsafePath):
        return False
    try:
        for name in names:
            try:
                os.unlink(name, dir_fd=fd)  # removes a link entry itself, never its target
            except FileNotFoundError:
                continue
            except OSError:
                return False
    finally:
        os.close(fd)
    return True


def result_rel(vid: str, suffix: str) -> str:
    return f"{REPORTS_REL}/{vid}.{suffix}"


def _report_path(root: Path, vid: str, suffix: str) -> Path:
    store.ensure_safe(root, REPORTS_REL, expect_dir=True)
    store.ensure_safe(root, result_rel(vid, suffix), expect_dir=False)
    return root / result_rel(vid, suffix)


def result_bytes(root: Path, vid: str) -> bytes | None:
    path = _report_path(root, vid, "json")
    return path.read_bytes() if path.is_file() else None


def read_result(root: Path, vid: str) -> dict[str, Any] | None:
    """The structured result (the commit point of a conclusion), or None when not concluded."""
    raw = result_bytes(root, vid)
    if raw is None:
        return None
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        result = None
    if (
        not isinstance(result, dict)
        or result.get("schema") != SCHEMA_RESULT
        or result.get("verification_id") != vid
    ):
        raise GuardError(
            "RUN_INVALID",
            f"Structured result of {vid} is not readable",
            "Restore the result file or start a new verification",
        )
    return result


def write_result(root: Path, result: dict[str, Any]) -> None:
    atomic_write_bytes(_report_path(root, result["verification_id"], "json"), dumps_json(result))


def report_text(root: Path, vid: str) -> str | None:
    path = _report_path(root, vid, "md")
    try:
        return path.read_text(encoding="utf-8") if path.is_file() else None
    except (OSError, UnicodeError):
        return None


def write_report(root: Path, vid: str, text: str) -> None:
    atomic_write_bytes(_report_path(root, vid, "md"), text.encode("utf-8"))


def remove_report(root: Path, vid: str) -> None:
    _report_path(root, vid, "md").unlink(missing_ok=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def keep_path(root: Path, vid: str) -> Path:
    store.ensure_safe(root, f"{run_rel(vid)}/keep.json", expect_dir=False)
    return root / run_rel(vid) / "keep.json"


# --------------------------------------------------------------------------- FEATURE-002-C commit barrier
BARRIER_TIMEOUT = 30.0
RETRY_STEP = "Retry the command"


def _run_file(root: Path, vid: str, name: str) -> Path:
    run_dir(root, vid)
    store.ensure_safe(root, f"{run_rel(vid)}/{name}", expect_dir=False)
    return root / run_rel(vid) / name


def commit_lock(root: Path, vid: str) -> Path:
    return _run_file(root, vid, "commit.lock")


def fsync_dir(path: Path) -> None:
    if os.name != "posix":  # pragma: no cover - directory fsync is POSIX only
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _write_all_close(fd: int, data: bytes) -> None:
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def cancel_marker(root: Path, vid: str) -> dict[str, Any] | None:
    path = _run_file(root, vid, "cancel.json")
    return (
        (_read_json(path) or {"requested_at": None, "consumed_at_request": None}) if path.exists() else None
    )


def create_marker(root: Path, vid: str, doc: dict[str, Any]) -> bool:
    """Create the durable cancellation marker; False when one already exists (the first one wins)."""
    path = _run_file(root, vid, "cancel.json")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE)
    except FileExistsError:
        return False
    _write_all_close(fd, dumps_json(doc))
    fsync_dir(path.parent)
    return True


def write_run_json(root: Path, vid: str, name: str, doc: dict[str, Any]) -> None:
    atomic_write_bytes(_run_file(root, vid, name), dumps_json(doc), private=True)


def read_run_json(root: Path, vid: str, name: str) -> dict[str, Any] | None:
    path = _run_file(root, vid, name)
    return _read_json(path) if path.exists() else None


def remove_run_file(root: Path, vid: str, name: str) -> None:
    _run_file(root, vid, name).unlink(missing_ok=True)


def refuse_closed(root: Path, vid: str) -> None:
    concluded = result_bytes(root, vid) is not None
    cancelled = (read_result(root, vid) or {}).get("cancellation") if concluded else None
    if cancelled or (not concluded and _run_file(root, vid, "cancel.json").exists()):
        raise GuardError(
            "RUN_CANCELLED",
            f"Verification {vid} was cancelled; nothing more can be recorded",
            f"Read its result: secure-code guard show --run {vid}",
        )
    if concluded:
        raise GuardError(
            "RUN_FINISHED",
            f"Verification {vid} is already concluded",
            "Start a new verification with secure-code guard open",
        )


def commit_state(
    root: Path, state: dict[str, Any], *, expected_revision: int, on_commit: Any = None
) -> None:
    """The only writer of an open run's state: barrier, cancel/finish re-check, revision check, write.

    `on_commit()` (FEATURE-002-D) runs inside the barrier after both checks, just before the state write.
    """
    vid = state["verification_id"]
    with ProcessLock(commit_lock(root, vid), timeout=BARRIER_TIMEOUT):
        refuse_closed(root, vid)
        if read_state(root, vid).get("revision", 0) != expected_revision:
            raise GuardError("STATE_CHANGED", f"Verification {vid} changed meanwhile", RETRY_STEP)
        if on_commit is not None:
            on_commit()
        state["revision"] = expected_revision + 1
        write_state(root, state)


def update_state(root: Path, vid: str, fn: Any) -> dict[str, Any]:
    """Read-modify-write of the latest state inside the barrier (`fn` validates and mutates)."""
    with ProcessLock(commit_lock(root, vid), timeout=BARRIER_TIMEOUT):
        refuse_closed(root, vid)
        state = read_state(root, vid)
        fn(state)
        state["revision"] = state.get("revision", 0) + 1
        write_state(root, state)
    return state


def bump_clock(root: Path, vid: str, raw: float) -> float:
    """Persist and return the never-decreasing consumed time; frozen at the cancellation request."""
    marker = cancel_marker(root, vid)
    if marker is not None and isinstance(marker.get("consumed_at_request"), (int, float)):
        return float(marker["consumed_at_request"])
    with ProcessLock(_run_file(root, vid, "clock.lock"), timeout=BARRIER_TIMEOUT):
        stored = (read_run_json(root, vid, "clock.json") or {}).get("consumed_hw", 0.0)
        stored = float(stored) if isinstance(stored, (int, float)) else 0.0
        value = max(stored, float(raw))
        if value > stored:
            write_run_json(root, vid, "clock.json", {"consumed_hw": round(value, 1)})
        return round(value, 1)


def stored_clock(root: Path, vid: str) -> float:
    value = (read_run_json(root, vid, "clock.json") or {}).get("consumed_hw", 0.0)
    return float(value) if isinstance(value, (int, float)) else 0.0


def create_result_exclusive(root: Path, result: dict[str, Any]) -> None:
    """Publish the structured result exactly once (FileExistsError when another writer won)."""
    final = _report_path(root, result["verification_id"], "json")
    final.parent.mkdir(parents=True, exist_ok=True)
    tmp = final.parent / f".{final.name}.{secrets.token_hex(6)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        _write_all_close(fd, dumps_json(result))
        os.link(tmp, final)
    finally:
        tmp.unlink(missing_ok=True)
    fsync_dir(final.parent)
