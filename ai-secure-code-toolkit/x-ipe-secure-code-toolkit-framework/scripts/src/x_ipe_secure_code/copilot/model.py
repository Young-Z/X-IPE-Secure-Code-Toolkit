"""Copilot constants, identifiers, limits and private/report paths (FEATURE-003-A).

All paths are checked with `store.ensure_safe` before anything is created, linked or replaced.
"""

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from typing import Any

from ..atomic import PRIVATE_DIR_MODE, atomic_write_bytes, dumps_json
from ..guard import model as guard_model
from ..guard.model import SCHEMA_REVIEW, GuardError
from ..guard.records import AUTHORITY_KEYS as GUARD_AUTHORITY_KEYS
from ..knowledge import store

SCHEMA_OPEN = "ai-secure-code-toolkit/copilot-open/v1"
SCHEMA_ARTIFACTS = "ai-secure-code-toolkit/copilot-artifacts/v1"
SCHEMA_SUGGEST = "ai-secure-code-toolkit/copilot-suggest/v1"
SCHEMA_STATE = "ai-secure-code-toolkit/copilot-collab/v1"
SCHEMA_RESULT = "ai-secure-code-toolkit/copilot-result/v1"
__all__ = ["SCHEMA_REVIEW", "CopilotError"]

STAGES = ("design", "implementation", "bug_fix", "refactor")
ADOPTION_RESULTS = ("adopted", "partial", "not_adopted", "not_applicable", "cannot_verify")
STATES = (*ADOPTION_RESULTS, "not_reviewed", "stale", "policy_changed")
NEEDS_ATTENTION = frozenset(
    {"partial", "not_adopted", "cannot_verify", "not_reviewed", "stale", "policy_changed"}
)
HIGH_RISK = ("critical", "high", "unknown")
SEVERITY_ORDER = (*HIGH_RISK, "medium", "low", "info")
FOLDER_CHANGES = ("added", "modified", "unspecified")
# Guard's authority keys plus the parts only a Copilot collaboration has.
AUTHORITY_KEYS = (
    *GUARD_AUTHORITY_KEYS,
    *(k for k in ("suggestions", "artifacts", "manifest", "stage") if k not in GUARD_AUTHORITY_KEYS),
)

COLLAB_ID = re.compile(r"cp-\d{8}T\d{6}Z-[0-9a-f]{8}")
COPILOT_REL = f"{store.PRIVATE_REL}/copilot"
LOCK_REL = f"{store.PRIVATE_REL}/locks/copilot.lock"
REPORTS_REL = "x-ipe-docs/secure-code/reports/copilot"

CopilotError = GuardError
NEW_COLLAB = "Open a new collaboration with secure-code copilot open"


def utc_now() -> str:
    """Current UTC time text (shared clock with Guard, patchable in tests)."""
    return guard_model.utc_now()


def check_id(text: Any) -> str:
    """A well-formed collaboration id, else `COLLAB_NOT_FOUND`."""
    if not isinstance(text, str) or not COLLAB_ID.fullmatch(text):
        raise GuardError("COLLAB_NOT_FOUND", f"Not a collaboration id: {text!r}", NEW_COLLAB)
    return text


def collab_rel(cid: str) -> str:
    return f"{COPILOT_REL}/{cid}"


def state_path(root: Path, cid: str) -> Path:
    """Checked path of the collaboration state file."""
    store.ensure_safe(root, COPILOT_REL, expect_dir=True)
    store.ensure_safe(root, collab_rel(cid), expect_dir=True)
    store.ensure_safe(root, f"{collab_rel(cid)}/state.json", expect_dir=False)
    return root / collab_rel(cid) / "state.json"


def allocate(root: Path, opened_at: str) -> str:
    """Create a new private collaboration folder exclusively and return its id."""
    store.ensure_safe(root, COPILOT_REL, expect_dir=True)
    (root / COPILOT_REL).mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    stamp = opened_at.replace("-", "").replace(":", "")
    while True:
        cid = f"cp-{stamp}-{secrets.token_hex(4)}"
        store.ensure_safe(root, collab_rel(cid), expect_dir=True)
        try:
            (root / collab_rel(cid)).mkdir(mode=PRIVATE_DIR_MODE)
            return cid
        except FileExistsError:
            continue


def read_state(root: Path, cid: str) -> dict[str, Any] | None:
    """The collaboration state, None when its private data does not exist."""
    path = state_path(root, cid)
    if not path.is_file():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        state = None
    if (
        not isinstance(state, dict)
        or state.get("schema") != SCHEMA_STATE
        or state.get("collaboration_id") != cid
    ):
        raise GuardError("COLLAB_INVALID", f"State of collaboration {cid} is not readable", NEW_COLLAB)
    return state


def write_state(root: Path, state: dict[str, Any]) -> None:
    """Atomic owner-only replace of the state; the revision grows with every write."""
    state["revision"] = state.get("revision", 0) + 1
    atomic_write_bytes(state_path(root, state["collaboration_id"]), dumps_json(state), private=True)


def report_rel(cid: str, n: int, suffix: str) -> str:
    return f"{REPORTS_REL}/{cid}-r{n}.{suffix}"


def report_path(root: Path, cid: str, n: int, suffix: str) -> Path:
    """Checked path of one report file of round `n`."""
    store.ensure_safe(root, REPORTS_REL, expect_dir=True)
    store.ensure_safe(root, report_rel(cid, n, suffix), expect_dir=False)
    return root / report_rel(cid, n, suffix)


def report_rounds(root: Path, cid: str) -> list[int]:
    """Round numbers that have a structured result file (used when the private data is gone)."""
    store.ensure_safe(root, REPORTS_REL, expect_dir=True)
    folder = root / REPORTS_REL
    if not folder.is_dir():
        return []
    pattern = re.compile(re.escape(cid) + r"-r([1-9]\d{0,8})\.json")
    return sorted(int(m.group(1)) for p in folder.iterdir() if (m := pattern.fullmatch(p.name)))
