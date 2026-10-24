"""Helper result collection and validation (FR-002F-8, AC-002F-04k/07b/07g/12b; design §10).

The `cp` tar stream of the results area is parsed in memory and never extracted: only a `results`
directory and an optional regular `results/result.json` owned by the container user within L-08 are
accepted. The JSON must match the exact schema; only its fields are read and every text is masked.
"""

from __future__ import annotations

import io
import json
import tarfile
from typing import Any

from ..mask import mask_text
from .model import (
    L08_BASIS,
    L08_DEPTH,
    L08_EXCERPT,
    L08_FILE,
    L08_FINDINGS,
    L08_INODES,
    L08_NOTES,
    L08_SCANNED,
    L08_TITLE,
    SCHEMA_RESULT,
)

KEYS = {"schema", "helper", "status", "scanned", "findings", "notes"}
FINDING_KEYS = {"path", "line", "rule", "title", "excerpt", "basis"}
TAR_CAP = 3 * 1024 * 1024


class ResultInvalid(Exception):
    """The method failed; `reason` names the first violation."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def from_tar(data: bytes | None) -> bytes:
    """The bytes of `results/result.json` from a `cp <holder>:/results -` tar stream."""
    if not data:
        raise ResultInvalid("no result: results area could not be collected")
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        members = []
        for member in tar:
            members.append(member)
            if len(members) > L08_INODES:
                raise ResultInvalid(f"results area has more than {L08_INODES} entries")
    except tarfile.TarError as exc:
        raise ResultInvalid(f"results area is not a valid archive ({exc.__class__.__name__})") from None
    result = None
    for m in members:
        name = m.name.rstrip("/")
        if name == "results" and m.isdir():
            continue
        if name == "results/result.json":
            if not m.isreg():
                kind = "symbolic link" if m.issym() else "hard link" if m.islnk() else "non-regular entry"
                raise ResultInvalid(f"result.json is a {kind}")
            if m.linkname:
                raise ResultInvalid("result.json names a link target")
            if m.uid != 65534:
                raise ResultInvalid(f"result.json is owned by uid {m.uid}, not the container user")
            if m.size > L08_FILE:
                raise ResultInvalid(f"result.json larger than {L08_FILE} bytes (L-08)")
            result = m
            continue
        kind = (
            "directory"
            if m.isdir()
            else "link"
            if (m.issym() or m.islnk())
            else "file"
            if m.isreg()
            else "special file"
        )
        raise ResultInvalid(f"unexpected {kind} in the results area: {mask_text(name)[0][:200]}")
    if result is None:
        raise ResultInvalid("no result: helper wrote no result.json")
    handle = tar.extractfile(result)
    raw = handle.read(L08_FILE + 1) if handle else b""
    if len(raw) != result.size:
        raise ResultInvalid("result.json is truncated")
    return raw


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ResultInvalid("result.json has duplicate keys")
    return dict(pairs)


def _refuse_constant(name: str) -> Any:
    raise ResultInvalid(f"result.json contains {name}")


def _depth(value: Any) -> int:
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, depth = stack.pop()
        deepest = max(deepest, depth)
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    return deepest


def _text(value: Any, where: str, limit: int, *, utf8: bool = False) -> str:
    if not isinstance(value, str):
        raise ResultInvalid(f"{where} must be text")
    size = len(value.encode("utf-8")) if utf8 else len(value)
    if size > limit:
        raise ResultInvalid(f"{where} longer than {limit} {'bytes' if utf8 else 'characters'} (L-08)")
    return value


def parse(raw: bytes, helper_id: str, rule: str, manifest_paths: set[str]) -> dict[str, Any]:
    """Validate `result.json` exactly (AC-002F-07g) and return the masked normalized result."""
    if not raw.strip():
        raise ResultInvalid("result.json is empty")
    try:
        doc = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_refuse_constant
        )
    except ResultInvalid:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ResultInvalid(f"result.json is not valid UTF-8 JSON ({exc.__class__.__name__})") from None
    if not isinstance(doc, dict):
        raise ResultInvalid("result.json must be an object")
    if _depth(doc) > L08_DEPTH:
        raise ResultInvalid(f"result.json nested deeper than {L08_DEPTH} (L-08)")
    if set(doc) != KEYS:
        raise ResultInvalid(f"result.json keys must be exactly {', '.join(sorted(KEYS))}")
    if doc["schema"] != SCHEMA_RESULT:
        raise ResultInvalid(f"result.json schema must be {SCHEMA_RESULT}")
    if doc["helper"] != helper_id:
        raise ResultInvalid("result.json names another helper")
    if doc["status"] not in ("complete", "error"):
        raise ResultInvalid("result.json status must be complete or error")
    scanned = doc["scanned"]
    if not isinstance(scanned, list) or len(scanned) > L08_SCANNED:
        raise ResultInvalid(f"scanned must be a list of at most {L08_SCANNED} paths (L-08)")
    if len(set(map(str, scanned))) != len(scanned) or not all(isinstance(p, str) for p in scanned):
        raise ResultInvalid("scanned must list unique paths")
    for p in scanned:
        if p not in manifest_paths:
            raise ResultInvalid("scanned names a path outside the snapshot manifest")
    notes = _text(doc["notes"], "notes", L08_NOTES, utf8=True)
    findings = doc["findings"]
    if not isinstance(findings, list) or len(findings) > L08_FINDINGS:
        raise ResultInvalid(f"findings must be a list of at most {L08_FINDINGS} (L-08)")
    out_findings = []
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict) or set(f) != FINDING_KEYS:
            raise ResultInvalid(f"{where} keys must be exactly {', '.join(sorted(FINDING_KEYS))}")
        if f["path"] not in manifest_paths:
            raise ResultInvalid(f"{where}.path is outside the snapshot manifest")
        line = f["line"]
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            raise ResultInvalid(f"{where}.line must be a positive number or null")
        if f["rule"] != rule:
            raise ResultInvalid(f"{where}.rule must be the bound check's rule")
        out_findings.append(
            {
                "path": f["path"],
                "line": line,
                "rule": rule,
                "title": mask_text(_text(f["title"], f"{where}.title", L08_TITLE))[0],
                "excerpt": mask_text(_text(f["excerpt"], f"{where}.excerpt", L08_EXCERPT, utf8=True))[0],
                "basis": mask_text(_text(f["basis"], f"{where}.basis", L08_BASIS))[0],
            }
        )
    if doc["status"] == "error":
        raise ResultInvalid("helper reported status error")
    if not out_findings and not scanned:
        raise ResultInvalid("nothing scanned")
    masked_kinds = sorted(
        {k for f in findings for key in ("title", "excerpt", "basis") for k in mask_text(f[key])[1]}
        | set(mask_text(notes)[1])
    )
    return {
        "schema": SCHEMA_RESULT,
        "helper": helper_id,
        "status": "complete",
        "scanned": sorted(scanned),
        "findings": out_findings,
        "notes": mask_text(notes)[0],
        "masked_types": masked_kinds,
    }
