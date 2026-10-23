"""Copilot artifacts and the per-file manifest (AC-003A-03a, 03c, 03i).

Every artifact file, and every regular file inside a folder artifact, is a manifest member with the
digest recorded at open or at the last artifact update. Only manifest members can be bound to
suggestions. Links and special entries inside folders are never members (`not_bindable`).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..guard.model import CHANGES, Checker, GuardError
from ..guard.targets import file_digest, kind_of, normalize, not_in_tree, tree_files
from .model import FOLDER_CHANGES

MAX_MANIFEST_FILES = 5000
REQUEST_STEP = "Fix the request file (see the Copilot skill references/copilot-records.md)"
NAME_STEP = (
    "Name the changed artifact files or folders explicitly; Copilot focuses on the change and its "
    "related impact (no automatic whole-project review)"
)
FOLDER_STEP = "Deleted or renamed folders are recorded as their individual files; list each file"
NARROW_STEP = f"Name narrower artifacts (at most {MAX_MANIFEST_FILES} files per collaboration)"


def _invalid(message: str, step: str) -> GuardError:
    return GuardError("TARGET_INVALID", message, step)


def _whole() -> GuardError:
    return GuardError("WHOLE_PROJECT_REFUSED", "Copilot never reviews the whole project", NAME_STEP)


def _kind(root: Path, rel: str, where: str) -> str | None:
    if not_in_tree(rel):
        raise _invalid(f"{where}: {rel} is toolkit data or Git internals, not an artifact", NAME_STEP)
    try:
        return kind_of(root, rel, where)
    except GuardError as exc:
        raise _invalid(exc.message, exc.next_step or NAME_STEP) from None


def _was_folder(state: dict[str, Any] | None, rel: str) -> bool:
    if state is None:
        return False
    if any(a["path"] == rel and a["kind"] == "dir" for a in state["artifacts"]):
        return True
    return rel not in state["manifest"] and any(p.startswith(rel + "/") for p in state["manifest"])


def parse_entries(
    root: Path, raw_list: Any, where: str, *, state: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Validate artifact entries `{path, change?, old_path?}`; returns `{path, kind, change, old_path}`.

    Refusals: `ARTIFACTS_REQUIRED` (none given), `WHOLE_PROJECT_REFUSED` ('.'), `TARGET_INVALID`
    (missing, outside, link, private or toolkit data, deleted/renamed folders), `REQUEST_INVALID`.
    """
    ck = Checker("REQUEST_INVALID", REQUEST_STEP)
    items = ck.items(raw_list, where)
    if not items:
        raise GuardError("ARTIFACTS_REQUIRED", "No artifact was given", NAME_STEP)
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(items):
        at = f"{where}[{index}]"
        ck.obj(raw, at, {"path", "change", "old_path"}, frozenset({"path"}))
        rel = normalize(raw["path"], at)
        if rel == ".":
            raise _whole()
        change = ck.choice(raw.get("change", "unspecified"), f"{at}.change", CHANGES)
        old = raw.get("old_path")
        if change == "renamed":
            if old in (None, ""):
                raise ck.fail(f"{at} is renamed but has no old_path")
            old = normalize(old, f"{at}.old_path")
            if old in (".", rel):
                raise ck.fail(f"{at}.old_path must name the earlier file path")
        elif old is not None:
            raise ck.fail(f"{at}.old_path is only allowed for renamed artifacts")
        for path in (rel, old):
            if path is None:
                continue
            if path in seen:
                raise ck.fail(f"{at}: {path} is given twice")
            seen.add(path)
        kind = _kind(root, rel, at)
        if change == "deleted":
            if kind is not None:
                raise _invalid(
                    f"{at}: {rel} is declared deleted but exists", "Declare it modified, or remove it"
                )
            if _was_folder(state, rel):
                raise _invalid(f"{at}: {rel} is a folder and cannot be declared deleted", FOLDER_STEP)
            kind = "file"
        elif kind is None:
            raise _invalid(f"{at}: {rel} does not exist", "Check the path, or declare the artifact deleted")
        if kind == "dir" and change not in FOLDER_CHANGES:
            raise _invalid(f"{at}: {rel} is a folder and cannot be declared {change}", FOLDER_STEP)
        if old is not None:
            old_kind = _kind(root, old, f"{at}.old_path")
            if old_kind is not None:
                raise _invalid(f"{at}.old_path: {old} still exists", "Declare the files added or modified")
            if _was_folder(state, old):
                raise _invalid(f"{at}.old_path: {old} was a folder", FOLDER_STEP)
        found.append({"path": rel, "kind": kind, "change": change, "old_path": old})
    return found


def check_size(paths: set[str] | dict[str, Any]) -> None:
    """Refuse a manifest of more than `MAX_MANIFEST_FILES` members."""
    if len(paths) > MAX_MANIFEST_FILES:
        raise GuardError(
            "MANIFEST_TOO_LARGE",
            f"The collaboration would have more than {MAX_MANIFEST_FILES} files",
            NARROW_STEP,
        )


def expand(
    root: Path, entries: list[dict[str, Any]], now: str
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    """Manifest records for the entries (path -> record) and the folder members that are not bindable.

    The number of records is limited to `MAX_MANIFEST_FILES` (folders stop walking beyond it).
    """
    records: dict[str, dict[str, Any]] = {}
    not_bindable: list[dict[str, str]] = []

    def add(path: str, digest: str | None, change: str, source: str, old: str | None = None) -> None:
        records[path] = {
            "digest": digest,
            "change": change,
            "old_path": old,
            "source": source,
            "recorded_at": now,
        }
        check_size(records)

    for entry in entries:
        rel, change = entry["path"], entry["change"]
        if change == "deleted":
            add(rel, None, "deleted", rel)
        elif entry["kind"] == "dir":
            tree = tree_files(root, rel, limit=MAX_MANIFEST_FILES)
            if tree["truncated"]:
                raise GuardError(
                    "MANIFEST_TOO_LARGE", f"{rel} has more than {MAX_MANIFEST_FILES} files", NARROW_STEP
                )
            for path, digest in tree["files"].items():
                add(path, digest, change, rel)
            not_bindable += tree["not_bindable"]
        else:
            try:
                digest = file_digest(root / rel)
            except OSError as exc:
                raise _invalid(
                    f"{rel} could not be read: {exc.strerror}", "Check the file permissions"
                ) from None
            add(rel, digest, change, rel, entry["old_path"])
            if entry["old_path"] is not None:
                add(entry["old_path"], None, "renamed_away", rel)
                records[entry["old_path"]]["renamed_to"] = rel
    return records, not_bindable


def current(root: Path, paths: Iterable[str]) -> dict[str, str | None]:
    """Current state of manifest members: digest, None (absent), `unreadable`, `not_a_file` or `unsafe`."""
    out: dict[str, str | None] = {}
    for rel in paths:
        try:
            kind = kind_of(root, rel, "artifact")
        except GuardError:
            out[rel] = "unsafe"
            continue
        if kind is None:
            out[rel] = None
        elif kind != "file":
            out[rel] = "not_a_file"
        else:
            try:
                out[rel] = file_digest(root / rel)
            except OSError:
                out[rel] = "unreadable"
    return out
