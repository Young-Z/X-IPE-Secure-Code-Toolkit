"""FEATURE-002-F constants (limits L-01…L-12), identifiers, digests, events and helper state accessors.

Helpers are temporary, run-only check scripts bound to one check of one verification. Their state lives
in the verification's run state (`helpers`, `helper_grants`) and its private run folder; nothing here
decides a verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ...knowledge import store
from ..model import GuardError

SCHEMA_HELPER = "ai-secure-code-toolkit/guard-helper/v1"
SCHEMA_RESULT = "x-ipe-helper-result/1"
SCHEMA_IMAGE = "ai-secure-code-toolkit/helper-image/v1"
SCHEMA_CONFORMANCE = "ai-secure-code-toolkit/helper-conformance/v1"
SCHEMA_MANIFEST = "ai-secure-code-toolkit/helper-snapshot/v1"

# L-01…L-12 (FEATURE-002-F specification, Functional Requirements).
L01_HELPERS = 5
L02_EACH, L02_SAMPLE_BYTES, L02_TOTAL = 5, 64 * 1024, 256 * 1024
L03_BYTES, L03_LINES = 64 * 1024, 2000
L04_DEPTH, L04_NODES = 50, 20000
L05_FILES, L05_FILE_BYTES, L05_TOTAL = 2000, 5 * 1024 * 1024, 50 * 1024 * 1024
L05_COMPONENTS, L05_PATH_BYTES = 32, 1024
L06_MEMORY, L06_NANO_CPUS, L06_PIDS, L06_NOFILE = 536870912, 1_000_000_000, 64, 256
L07_TMP = 16 * 1024 * 1024
L08_AREA, L08_INODES, L08_FILE, L08_DEPTH = 2 * 1024 * 1024, 16, 1024 * 1024, 16
L08_FINDINGS, L08_SCANNED, L08_TITLE, L08_EXCERPT, L08_BASIS, L08_NOTES = 500, 2000, 200, 2048, 500, 2048
L09_OUTPUT = 64 * 1024
L10 = {"version": 30, "compile": 30, "sample": 120, "target": 120}
L12_LOW, L12_HIGH = (3, 10, 0), (3, 13)
OBJECT_FILES_MAX = 2000
UNCOVERED_IN_EVIDENCE, UNCOVERED_IN_REPORT = 20, 50

HELPER_METHOD = re.compile(r"helper\.[a-z0-9][a-z0-9-]{0,40}")
HELPER_ID = re.compile(r"h-(\d+)-([0-9a-f]{8})")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
HELPERS_REL = f"{store.PRIVATE_REL}/helpers"
IMAGE_REL = f"{HELPERS_REL}/image.json"
KEY_REL = f"{HELPERS_REL}/integrity.key"
CONFORMANCE_REL = f"{HELPERS_REL}/conformance"

# Digest of the trusted PID-1 launcher payload (guard/helpers/payload/launcher.py), checked before use.
LAUNCHER_SHA256 = "sha256:5e04622572486931eeb6bbc062a70cb96c856415e31ea3bf788031eb580b70bd"

STATIC_STATEMENT = "Static rules are defence in depth only; they never make a script safe."
CONSENT = (
    "Recorded cooperative consent. The toolkit cannot prove a person gave it; it is not a security "
    "boundary. The enforced container limits are the security boundary."
)
TEMPORARY = "temporary, run-only — not a formal rule or Adapter"
RESERVED = "helper evidence is recorded only by secure-code guard helper run"
GAP_NEXT = (
    "Helper not executed; its method counts as a failed auxiliary method and the gap is reported. "
    "Continue with other methods or conclude"
)
REVIEW_STEP = "Register a reviewer attempt covering the helper and record the Reviewer's result"
SHOW_STEP = "Use a helper id from secure-code guard helper show of this verification"
MAINTAINER_STEP = "Ask the Maintainer; the toolkit never installs, configures, pulls or builds"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def is_helper_method(name: Any) -> bool:
    return isinstance(name, str) and name.casefold().startswith("helper.")


def helpers(state: dict[str, Any]) -> list[dict[str, Any]]:
    """The 002-F helper records of a run state (absent = none).

    Entries without the 002-F record shape (e.g. ids seeded by the CR-TASK-077 tests before 002-F existed)
    are not 002-F helpers and are ignored here; `budget` still counts their ids as delivered.
    """
    value = state.get("helpers")
    if not isinstance(value, list):
        return []
    return [
        h for h in value if isinstance(h, dict) and isinstance(h.get("helper_digest"), str) and "script" in h
    ]


def grants(state: dict[str, Any]) -> list[dict[str, Any]]:
    value = state.get("helper_grants")
    return value if isinstance(value, list) else []


def suffix(state: dict[str, Any]) -> str:
    return str(state.get("verification_id") or "")[-8:]


def find(state: dict[str, Any], hid: Any, code: str = "HELPER_UNKNOWN") -> dict[str, Any]:
    """The helper with this id, or a refusal (an id of another verification is named as such)."""
    for helper in helpers(state):
        if helper["id"] == hid:
            return helper
    match = HELPER_ID.fullmatch(hid) if isinstance(hid, str) else None
    if match and match.group(2) != suffix(state):
        raise GuardError(code, f"helper {hid} belongs to another verification", SHOW_STEP)
    raise GuardError(code, f"helper {hid!r} is not a helper of this verification", SHOW_STEP)


def declaration_digest(helper: dict[str, Any]) -> str:
    keys = ("check", "method", "rule", "goal", "read_scope", "judgement_basis", "language")
    return sha(canonical({k: helper[k] for k in keys}))


def samples_digest(samples: list[dict[str, Any]]) -> str:
    keys = ("id", "kind", "origin", "path", "sha256")
    return sha(canonical([{k: s[k] for k in keys} for s in samples]))


def helper_digest(script_sha: str, declaration_sha: str, samples_sha: str) -> str:
    return sha(canonical({"script": script_sha, "declaration": declaration_sha, "samples": samples_sha}))


def digests(helper: dict[str, Any]) -> dict[str, Any]:
    """The digests a review and a grant bind to (AC-002F-03d, 04o)."""
    return {
        "helper_digest": helper["helper_digest"],
        "script_sha256": helper["script"]["sha256"],
        "declaration_sha256": helper["declaration_sha256"],
        "samples_sha256": helper["samples_sha256"],
        "sample_digests": [s["sha256"] for s in helper["samples"]],
    }


def event(helper: dict[str, Any], step: str, outcome: str, at: str, **extra: Any) -> dict[str, Any]:
    """Append one ordered audit event (AC-002F-09a)."""
    entry = {
        "seq": len(helper["events"]) + 1,
        "at": at,
        "step": step,
        "outcome": outcome,
        "attempt": extra.pop("attempt", None),
        "script_sha256": helper["script"]["sha256"],
        "grant": extra.pop("grant", None),
        "conformance": extra.pop("conformance", None),
        "manifest": extra.pop("manifest", None),
        "detail": extra.pop("detail", None),
    }
    entry.update(extra)
    helper["events"].append(entry)
    return entry


def has_helper_methods(state: dict[str, Any]) -> bool:
    plan = state.get("plan") or {}
    return any(is_helper_method(m["name"]) for c in plan.get("checks", []) for m in c["methods"])


def run_record(helper: dict[str, Any], n: Any) -> dict[str, Any] | None:
    return next((r for r in helper["runs"] if r["n"] == n), None)


def granted(state: dict[str, Any], helper: dict[str, Any]) -> dict[str, Any] | None:
    """The grant listing exactly the helper's current digests (AC-002F-04o), or None."""
    want = {k: v for k, v in digests(helper).items() if k != "sample_digests"}
    for g in grants(state):
        for item in g["helpers"]:
            if item["id"] == helper["id"] and all(item.get(k) == v for k, v in want.items()):
                return g
    return None
