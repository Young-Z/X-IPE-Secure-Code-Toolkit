"""Toolkit-recorded helper evidence and findings (design §2.10, DEC-3 variant B). Single writer.

A submission records one failed auxiliary-method item; every terminal event records another failed item
with its reason; `ok` runtime evidence is written only for a findings result (at the run) or for an
accepted clean result covering the whole check object (at the post-run review). Shapes are the delivered
002-A shapes plus an additive `helper` key, so the unchanged 002-A engine computes the ledger.
"""

from __future__ import annotations

from typing import Any

from ..mask import mask_text
from ..model import MAX_TEXT
from .model import TEMPORARY, suffix


def _prefix(state: dict[str, Any], helper: dict[str, Any]) -> str:
    n = helper["id"].split("-")[1]
    return f"helper-h{n}-{suffix(state)}"


def append(
    state: dict[str, Any],
    helper: dict[str, Any],
    status: str,
    summary: str,
    paths: list[str],
    *,
    run: int | None = None,
    outcome: str | None = None,
    acceptance: str | None = None,
    review: int | None = None,
    manifest: str | None = None,
) -> dict[str, Any]:
    """Append one helper evidence item (method_status `ok` or `failed`) to the run state."""
    prefix = _prefix(state, helper)
    k = 1 + sum(
        1
        for e in state["evidence"]
        if e["id"].startswith(prefix + "-") and "-f" not in e["id"][len(prefix) :]
    )
    text, kinds = mask_text(f"temporary helper {helper['id']} ({TEMPORARY}): {summary}"[:MAX_TEXT])
    item = {
        "id": f"{prefix}-{k}",
        "kind": "runtime",
        "method": helper["method"],
        "method_status": status,
        "checks": [helper["check"]],
        "paths": sorted(dict.fromkeys(paths)) or list(helper["read_scope"]),
        "lines": None,
        "summary": text,
        "stored": None,
        "stored_bytes": 0,
        "masked": bool(kinds),
        "masked_types": kinds,
        "helper": {
            "id": helper["id"],
            "run": run,
            "script_sha256": helper["script"]["sha256"],
            "manifest": manifest,
            "outcome": outcome,
            "acceptance": acceptance,
            "review": review,
        },
    }
    state["evidence"].append(item)
    return item


def failed(state: dict[str, Any], helper: dict[str, Any], reason: str, **kw: Any) -> dict[str, Any]:
    return append(state, helper, "failed", reason, kw.pop("paths", None) or list(helper["read_scope"]), **kw)


def finding(
    state: dict[str, Any], helper: dict[str, Any], run: dict[str, Any], found: dict[str, Any], eid: str
) -> dict[str, Any]:
    """One helper finding (source = the helper method; severity unknown: the Reviewer decides)."""
    prefix = _prefix(state, helper)
    m = 1 + sum(1 for f in state["findings"] if f["id"].startswith(prefix + "-f"))
    item = {
        "id": f"{prefix}-f{m}",
        "rule": helper["rule"],
        "check": helper["check"],
        "location": {"path": found["path"], "line": found["line"]},
        "cwe": None,
        "title": found["title"],
        "description": f"{found['basis']} — excerpt: {found['excerpt']}"[:MAX_TEXT],
        "source": helper["method"],
        "severity": "unknown",
        "evidence": [eid],
        "disputed": False,
        "related": [],
        "merged_from": [],
        "merge_evidence": [],
        "merged_into": None,
        "helper": {
            "id": helper["id"],
            "run": run["n"],
            "script_sha256": helper["script"]["sha256"],
            "manifest": run["manifest"]["digest"] if run.get("manifest") else None,
        },
    }
    state["findings"].append(item)
    return item
