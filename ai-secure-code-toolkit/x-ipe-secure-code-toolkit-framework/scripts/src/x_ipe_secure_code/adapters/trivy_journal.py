"""Crash-atomic provisioning journal, deterministic recovery and a lock-free coherent read (FEATURE-002-D).

Commit point: the verification state contains the `tool_provisioning` entry of the journal (same `n` and
attempt). Writers order their changes as journal → pointer swap → state commit → journal removal → GC;
`recover` (Guard lock held) rolls forward or back; `evaluate` (status) never writes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..guard import runs
from ..guard.model import GuardError
from ..knowledge import durable
from . import trivy_cache
from .trivy import COMPONENTS

SCHEMA = "ai-secure-code-toolkit/trivy-journal/v1"
JOURNAL = "journal.json"
ATTEMPTS = 5
BUSY = (
    "busy: the cache changed during every read attempt (provisioning or recovery in progress); retry status"
)


def encode(data: bytes | None) -> dict[str, str] | None:
    if data is None:
        return None
    return {
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "bytes_b64": base64.b64encode(data).decode(),
    }


def decode(blob: Any) -> bytes | None:
    return base64.b64decode(blob["bytes_b64"]) if isinstance(blob, dict) else None


def read_bytes(root: Path) -> bytes | None:
    with durable.Tree(root) as tree:
        fd = tree.opt_dir(trivy_cache.CACHE_REL)
        if fd is None:
            return None
        try:
            return durable.read(fd, JOURNAL)
        finally:
            os.close(fd)


def read(root: Path) -> dict[str, Any] | None:
    data = read_bytes(root)
    if data is None:
        return None
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        return {"schema": SCHEMA, "unreadable": True}
    return doc if isinstance(doc, dict) else {"schema": SCHEMA, "unreadable": True}


def write(root: Path, doc: dict[str, Any]) -> None:
    with durable.Tree(root) as tree:
        fd = tree.dir(trivy_cache.CACHE_REL, create=True)
        try:
            durable.write(
                fd, JOURNAL, json.dumps(doc, indent=1).encode("utf-8"), ".journal.json.tmp", mode=0o600
            )
        finally:
            os.close(fd)


def remove(root: Path) -> None:
    with durable.Tree(root) as tree:
        fd = tree.opt_dir(trivy_cache.CACHE_REL)
        if fd is not None:
            try:
                durable.unlink(fd, JOURNAL)
            finally:
                os.close(fd)


def pending_new_pointer(root: Path) -> dict[str, Any] | None:
    doc = read(root)
    return trivy_cache.parse_pointer(decode((doc or {}).get("new_pointer")))


def _committed(state: dict[str, Any] | None, journal: dict[str, Any]) -> bool:
    return any(
        e.get("n") == journal.get("provisioning") and e.get("attempt") == journal.get("attempt")
        for e in (state or {}).get("tool_provisioning", [])
    )


def _state(root: Path, vid: Any) -> dict[str, Any] | None:
    try:
        return runs.read_state(root, runs.check_id(vid))
    except (GuardError, OSError, ValueError, KeyError):
        return None


def _set_pointer(root: Path, data: bytes | None) -> None:
    if trivy_cache.read_pointer_bytes(root) != data:
        trivy_cache.write_pointer_bytes(root, data)


def _delete(root: Path, generations: list[str]) -> None:
    for item in generations or []:
        component, _, gen = str(item).partition("/")
        if component in COMPONENTS and gen:
            trivy_cache.remove_generation(root, component, gen)


def recover(root: Path) -> str | None:
    """Resolve an interrupted final commit (Guard lock held): 'forward', 'back' or None. Idempotent."""
    journal = read(root)
    if journal is None:
        return None
    state = _state(root, journal.get("verification_id"))
    if not journal.get("unreadable") and _committed(state, journal):
        _set_pointer(root, decode(journal.get("new_pointer")))
        remove(root)
        trivy_cache.collect_garbage(root)
        return "forward"
    if not journal.get("unreadable"):
        _set_pointer(root, decode(journal.get("old_pointer")))
        _delete(root, journal.get("new_generations"))
    remove(root)
    if state is not None and state.get("status") == "open":
        _record_interrupted(root, state, journal)
    trivy_cache.collect_garbage(root)
    return "back"


def _record_interrupted(root: Path, state: dict[str, Any], journal: dict[str, Any]) -> None:
    entry = {
        "n": journal.get("provisioning"),
        "adapter": "trivy",
        "attempt": journal.get("attempt"),
        "outcome": "interrupted",
        "previous": "kept",
        "operations": [],
        "recovered_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    rev = state["revision"]
    state.setdefault("tool_provisioning", []).append(entry)
    try:
        runs.commit_state(root, state, expected_revision=rev)
    except GuardError:
        pass  # cancelled/finished meanwhile: the verification already reports it as not completed


# --------------------------------------------------------------------------- read-only coherent snapshot
def _state_key(root: Path, journal_bytes: bytes | None) -> tuple | None:
    if journal_bytes is None:
        return None
    try:
        journal = json.loads(journal_bytes.decode("utf-8"))
    except (UnicodeError, ValueError):
        return ("unreadable",)
    state = _state(root, journal.get("verification_id")) if isinstance(journal, dict) else None
    if state is None:
        return ("missing",)
    return (state.get("revision"), _committed(state, journal))


def _view(journal_bytes: bytes | None, pointer: bytes | None, key: tuple | None) -> bytes | None:
    if journal_bytes is None:
        return pointer
    try:
        journal = json.loads(journal_bytes.decode("utf-8"))
    except (UnicodeError, ValueError):
        return pointer
    committed = bool(key and len(key) == 2 and key[1])
    return decode(journal.get("new_pointer" if committed else "old_pointer"))


def _reads(root: Path) -> tuple[bytes | None, bytes | None]:
    with durable.Tree(root) as tree:
        fd = tree.opt_dir(trivy_cache.CACHE_REL)
        if fd is None:
            return None, None
        try:
            return durable.read(fd, JOURNAL), durable.read(fd, trivy_cache.POINTER)
        finally:
            os.close(fd)


def evaluate(root: Path, now: datetime | None = None) -> dict[str, Any]:
    """Seqlock-style double read of journal, pointer and verification state; never writes or recovers."""
    now = now or datetime.now(UTC)
    for attempt in range(1, ATTEMPTS + 1):
        j1, p1 = _reads(root)
        s1 = _state_key(root, j1)
        doc = trivy_cache.parse_pointer(_view(j1, p1, s1))
        components = {
            name: trivy_cache.component_state(root, name, now, pointer=doc or {}) for name in COMPONENTS
        }
        j2, p2 = _reads(root)
        s2 = _state_key(root, j2)
        if (j1, p1, s1) == (j2, p2, s2):
            return {
                "components": components,
                "recovery_pending": j1 is not None,
                "cache": "coherent",
                "attempts": attempt,
            }
        time.sleep(0.05 * 2 ** (attempt - 1))
    return {
        "components": {name: {"state": "unreadable", "reason": BUSY} for name in COMPONENTS},
        "recovery_pending": None,
        "cache": "busy",
        "attempts": ATTEMPTS,
    }
