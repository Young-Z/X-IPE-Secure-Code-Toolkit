"""Opengrep v1.31.0 Adapter: argv, status, sanitizing, normalization and per-file accounting.

Facts from the tool-level validation (FEATURE-002-B): exit 0 with or without findings; errors in
JSON `errors`; skipped folders only with `--verbose`; other-language files are neither scanned nor
skipped; parse failures are not reported; `check_id` is prefixed by the rule location.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from ..guard.mask import mask_text
from .process import ProcessOutcome

SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
REMOVED = "[removed: matched source]"
CWE = re.compile(r"CWE-\d+")
HEX = re.compile(r"[0-9a-f]{16,128}")
PYTHON = (".py", ".pyi")


def build_argv(binary: Path, rule_file: Path, targets: list[Path], include_ignored: bool) -> list[str]:
    argv = [str(binary), "scan", "--json", "--verbose", "--disable-version-check", "--no-git-ignore"]
    argv += ["--config", str(rule_file)]
    if include_ignored:
        argv.append("--x-ignore-semgrepignore-files")
    return argv + [str(t) for t in targets]


def parse(stdout_path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(stdout_path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None
    return doc if _well_formed(doc) else None


def _well_formed(doc: Any) -> bool:
    """Only the output shape observed for the verified version is accepted; anything else is a failed run."""
    if (
        not isinstance(doc, dict)
        or not isinstance(doc.get("results"), list)
        or not isinstance(doc.get("paths"), dict)
    ):
        return False
    paths = doc["paths"]
    scanned, skipped = paths.get("scanned", []), paths.get("skipped", [])
    errors = doc.get("errors", [])
    return (
        all(isinstance(r, dict) for r in doc["results"])
        and isinstance(scanned, list)
        and all(isinstance(p, str) for p in scanned)
        and isinstance(skipped, list)
        and all(isinstance(s, dict) for s in skipped)
        and isinstance(errors, list)
        and all(isinstance(e, dict) for e in errors)
        and isinstance(doc.get("skipped_rules", []), list)
    )


def status_of(outcome: ProcessOutcome, doc: dict[str, Any] | None) -> str:
    if outcome.timed_out:
        return "timed_out"
    if outcome.oversized or doc is None or outcome.exit != 0:
        return "failed"
    return "completed_with_errors" if doc.get("errors") else "completed"


def sanitize(doc: Any, prefix: str) -> Any:
    """Mask every string, drop matched source and metavariable content, make staged paths relative."""

    def clean(value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if k == "lines":
                    out[k] = REMOVED
                elif k == "metavars":
                    out[k] = sorted(v) if isinstance(v, dict) else []
                else:
                    out[k] = clean(v, k)
            return out
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, str):
            return mask_text(value.replace(prefix, ""))[0]
        return value

    return clean(doc)


def cwe_of(metadata: Any) -> str | None:
    raw = metadata.get("cwe") if isinstance(metadata, dict) else None
    for item in raw if isinstance(raw, list) else [raw]:
        match = CWE.search(item) if isinstance(item, str) else None
        if match:
            return match.group(0)
    return None


def results(doc: dict[str, Any], rule_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Results of one single-rule process: (normalized, unattributed)."""
    found, unattributed = [], []
    for r in doc.get("results", []):
        cid = r.get("check_id") if isinstance(r, dict) else None
        if not isinstance(cid, str) or not (cid == rule_id or cid.endswith("." + rule_id)):
            unattributed.append(
                {
                    "check_id": str(cid)[:200],
                    "path": str(r.get("path"))[:300] if isinstance(r, dict) else None,
                }
            )
            continue
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        tool_sev = extra.get("severity") if isinstance(extra.get("severity"), str) else None
        fp = extra.get("fingerprint")
        found.append(
            {
                "rule_id": rule_id,
                "path": str(r.get("path")),
                "line": _line(r.get("start")),
                "end_line": _line(r.get("end")),
                "tool_severity": tool_sev,
                "severity": SEVERITY_MAP.get(tool_sev, "unknown"),
                "cwe": cwe_of(extra.get("metadata")),
                "message": str(extra.get("message") or rule_id)[:8000],
                "fingerprint": fp if isinstance(fp, str) and HEX.fullmatch(fp) else None,
            }
        )
    found.sort(key=lambda f: (f["path"], f["line"] or 0, f["rule_id"]))
    return found, unattributed


def _line(position: Any) -> int | None:
    line = position.get("line") if isinstance(position, dict) else None
    return line if isinstance(line, int) and not isinstance(line, bool) and 0 < line < 10**9 else None


def _skipped(doc: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    for entry in doc.get("paths", {}).get("skipped") or []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            out.append({"path": entry["path"].rstrip("/"), "reason": str(entry.get("reason"))[:200]})
    return out


def account(files: list[str], docs: list[dict[str, Any]]) -> dict[str, list]:
    """Classify object files by what the tool itself reported (no guessing)."""
    scanned = {p for d in docs for p in (d.get("paths", {}).get("scanned") or []) if isinstance(p, str)}
    skipped = [s for d in docs for s in _skipped(d)]
    result: dict[str, list] = {"scanned": [], "skipped": [], "unaccounted": []}
    for f in sorted(files):
        if f in scanned:
            result["scanned"].append(f)
            continue
        reason = next((s["reason"] for s in skipped if f == s["path"] or f.startswith(s["path"] + "/")), None)
        if reason is None:
            result["unaccounted"].append(f)
        else:
            result["skipped"].append({"path": f, "reason": reason})
    return result


def rule_gaps(doc: dict[str, Any]) -> list[str]:
    gaps = []
    if not doc.get("paths", {}).get("scanned"):
        gaps.append("rule applied to no file")
    if doc.get("skipped_rules"):
        gaps.append("rule skipped by the tool")
    return gaps


def unparseable_python(root: Path, files: list[str]) -> list[str]:
    """Python files the toolkit cannot parse (Opengrep does not report parse failures)."""
    bad = []
    for f in files:
        if f.endswith(PYTHON):
            try:
                ast.parse((root / f).read_bytes(), filename=f)
            except (SyntaxError, ValueError, OSError, RecursionError, MemoryError):
                bad.append(f)
    return sorted(bad)
