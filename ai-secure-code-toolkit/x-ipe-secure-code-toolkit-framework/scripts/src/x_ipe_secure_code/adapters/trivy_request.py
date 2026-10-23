"""Trivy request validation for `secure-code guard tool` (FEATURE-002-D, AC-002D-03a…03i).

Only named parameters are accepted; a refusal records nothing (no attempt, no evidence, nothing run).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from ..guard import targets
from ..guard.model import Checker, GuardError
from ..guard.toolreq import MAX_CHECKS, bind_targets, planned_method
from . import ADAPTERS, safe_io, trivy_archive
from .trivy import CONFIG_TYPES, MODES, SCANNERS

ARCHIVE_STEP = trivy_archive.STEP


def _scanners(ck: Checker, raw: Any, where: str) -> list[str]:
    items = ck.items(raw, f"{where}.scanners", required=True)
    out = []
    for s in items:
        if s == "license":
            raise ck.fail(f"{where}.scanners: license scanning is out of scope in this version")
        if s not in SCANNERS:
            raise ck.fail(f"{where}.scanners: {s!r} is not one of {', '.join(SCANNERS)}")
        if s in out:
            raise ck.fail(f"{where}.scanners: {s} appears twice")
        out.append(s)
    return out


def _archive(root: Path, state: dict[str, Any], ck: Checker, rel: str, where: str) -> dict[str, Any]:
    explicit = any(t["path"] == rel and t["kind"] == "file" for t in state["artifact"]["targets"])
    if not explicit:
        raise ck.fail(
            f"{where}: {rel} is not an explicitly declared file target of the verification; image archives "
            "are accepted only as explicit file targets (a .tar inside a folder target is an ordinary file)"
        )
    if not rel.endswith(".tar"):
        raise ck.fail(f"{where}: {rel} is not a docker save .tar archive")
    try:
        fd = safe_io.open_nofollow(root, rel)
    except (OSError, safe_io.UnsafePath) as exc:
        raise ck.fail(f"{where}: {rel} is not a readable regular file without links ({exc})") from None
    try:
        size = os.fstat(fd).st_size
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ck.fail(f"{where}: {rel} is not a regular file")
        info = trivy_archive.validate_archive(fd, size)
    finally:
        os.close(fd)
    if isinstance(info, trivy_archive.ArchiveError):
        raise GuardError(info.code, f"{where}: {rel}: {info.reason}", ARCHIVE_STEP)
    return info.to_dict()


def _config_types(
    root: Path, ck: Checker, raw: Any, scanners: list[str], scan: list[str], where: str
) -> list:
    if raw is None:
        return []
    items = ck.items(raw, f"{where}.config_types")
    if items and "misconfig" not in scanners:
        raise ck.fail(f"{where}.config_types need the misconfig scanner")
    out, seen = [], set()
    for k, item in enumerate(items):
        w = f"{where}.config_types[{k}]"
        ck.obj(item, w, {"path", "type"}, frozenset({"path", "type"}))
        try:
            rel = targets.normalize(item["path"], f"{w}.path")
        except GuardError as exc:
            raise ck.fail(exc.message) from None
        if not any(rel == t or t == "." or rel.startswith(t + "/") for t in scan):
            raise ck.fail(f"{w}: {rel} is not a file of this check's object")
        path = root / rel
        if path.is_symlink() or not path.is_file():
            raise ck.fail(f"{w}: {rel} is not a regular file of this check's object")
        if item["type"] not in CONFIG_TYPES:
            raise ck.fail(f"{w}: type must be one of {', '.join(CONFIG_TYPES)} (compose is not supported)")
        if rel in seen:
            raise ck.fail(f"{w}: one override per file")
        seen.add(rel)
        out.append({"path": rel, "type": item["type"]})
    return out


def validate(root: Path, state: dict[str, Any], doc: dict[str, Any], ck: Checker) -> dict[str, Any]:
    ck.obj(
        doc,
        "request",
        {"schema", "adapter", "time_limit_seconds", "checks"},
        frozenset({"adapter", "time_limit_seconds", "checks"}),
    )
    spec = ADAPTERS["trivy"]
    limit = doc["time_limit_seconds"]
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= spec.max_time_limit:
        raise ck.fail(f"time_limit_seconds must be a whole number from 1 to {spec.max_time_limit}")
    raw_checks = ck.items(doc["checks"], "checks", required=True)
    if len(raw_checks) > MAX_CHECKS:
        raise ck.fail(f"at most {MAX_CHECKS} checks per run")
    out: list[dict[str, Any]] = []
    for i, raw in enumerate(raw_checks):
        where = f"checks[{i}]"
        ck.obj(
            raw,
            where,
            {"check", "scanners", "mode", "targets", "config_types"},
            frozenset({"check", "scanners", "mode", "targets"}),
        )
        cid = ck.key(raw["check"], f"{where}.check")
        if any(c["check"] == cid for c in out):
            raise ck.fail(f"{where}: check {cid} appears twice")
        scanners = _scanners(ck, raw["scanners"], where)
        mode = ck.choice(raw["mode"], f"{where}.mode", MODES)
        if mode == "image_archive" and scanners != ["vuln"]:
            raise ck.fail(f"{where}: image_archive mode allows only the vuln scanner")
        check = planned_method(state, cid, "trivy", where)
        scan = bind_targets(state, check, raw["targets"], ck, where)
        archives = (
            {rel: _archive(root, state, ck, rel, where) for rel in scan} if mode == "image_archive" else {}
        )
        config_types = _config_types(root, ck, raw.get("config_types"), scanners, scan, where)
        out.append(
            {
                "check": cid,
                "check_def": check,
                "scanners": scanners,
                "mode": mode,
                "targets": scan,
                "config_types": config_types,
                "archives": archives,
                "rule_files": [],
            }
        )
    return {"adapter": "trivy", "include_ignored": False, "time_limit": limit, "checks": out}
