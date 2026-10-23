"""Local rule storage: redo-log commit inside the rule folder, recovery, pending, index, lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..atomic import atomic_write_bytes, dumps_json
from ..paths import unsafe_component
from . import durable
from .batch import LANG, Item
from .durable import StoreError
from .identity import IdentityError, RuleRef

LOCAL_REL = "x-ipe-docs/secure-code/knowledge/local"
PRIVATE_REL = ".x-ipe/private/secure-code"
LOCK_REL = f"{PRIVATE_REL}/locks/knowledge.lock"
PENDING_REL = f"{PRIVATE_REL}/pending"
INDEX_REL = f"{PRIVATE_REL}/knowledge-documents.json"
JOURNAL = ".commit-journal.json"
RECORD_SCHEMA = "ai-secure-code-toolkit/local-rule/v1"
CRASH_ENV = "SECURE_CODE_TEST_CRASH_AT"
PAUSE_ENV = "SECURE_CODE_TEST_PAUSE_AT"
LIFECYCLE_STATES = ("active", "deactivated")
_crash_counts: dict[str, int] = {}


def _crash_point(name: str) -> None:
    """Test-only: exit the process at a named commit boundary (never changes data)."""
    target = os.environ.get(CRASH_ENV)
    if not target:
        return
    point, _, nth = target.partition("@")
    if point != name:
        return
    _crash_counts[name] = _crash_counts.get(name, 0) + 1
    if _crash_counts[name] == int(nth or 1):
        os._exit(86)


def _pause_point(name: str) -> None:
    """Test-only: `SECURE_CODE_TEST_PAUSE_AT=<point>=<path>`: write `<path>.ready`, wait <= 30 s for `.go`."""
    target = os.environ.get(PAUSE_ENV)
    if not target:
        return
    point, _, path = target.partition("=")
    if point != name or not path:
        return
    marker = Path(path)
    marker.with_suffix(".ready").write_text("ready\n", encoding="utf-8")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not marker.with_suffix(".go").exists():
        time.sleep(0.02)


def ensure_safe(root: Path, rel: str, *, expect_dir: bool) -> None:
    """Refuse symbolic links or wrong kinds on any existing component of `rel`."""
    reason = unsafe_component(root, rel, expect_dir=expect_dir)
    if reason:
        raise StoreError("PATH_UNSAFE", reason)


def lock(root: Path, *, write: bool) -> durable.DirLock:
    """Knowledge lock reached by a no-follow walk from an own root handle (closed on release)."""
    tree = durable.Tree(root)
    try:
        held = durable.DirLock(tree, LOCK_REL, create=write)
    except BaseException:
        tree.close()
        raise
    held.owns_tree = True
    return held


def local_root(root: Path) -> Path:
    return root / LOCAL_REL


def rule_dir(root: Path, ref: RuleRef) -> Path:
    return local_root(root) / ref.namespace / ref.version / ref.rule_id


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def example_file(key: str) -> str:
    return "example.md" if key == "general" else f"example-{key}.md"


def item_files(item: Item) -> dict[str, str]:
    files = {"content.md": item.content}
    files.update({example_file(k): v for k, v in item.examples.items()})
    return files


@dataclass
class StoredRule:
    ref: RuleRef
    record: dict[str, Any]
    files: dict[str, str]
    item: Item | None
    digest: str | None
    consistent: bool
    pending_journal: bool
    record_raw: str | None = None


# Names `_write_rule` stages (`replace`): record, changelog, content and `example_file(key)` for
# `general` or a batch.LANG key. Its `delete` list holds stored visible files the new item no
# longer has (examples, or hand-added extra files), so deletes only need to be such a plain name.
WRITTEN_FILE = re.compile(
    rf"record\.json|changelog\.md|content\.md|example\.md|example-(?:{LANG.pattern})\.md"
)
RESTORE_STEP = "Restore the rule's files (for example from version control) or delete the rule"


def plain_rule_file(name: Any) -> bool:
    """One visible file name inside the rule folder: no separator, NUL, drive, `.`/`..`, dot
    prefix (journal, temporaries) or `.new` staging suffix."""
    return (
        isinstance(name, str)
        and bool(name)
        and not any(c in name for c in "/\\\0")
        and not os.path.isabs(name)
        and not os.path.splitdrive(name)[0]
        and not name.startswith(".")
        and not name.endswith(".new")
    )


def commit_entries(journal: Any) -> tuple[list[tuple[str, str]], list[str]]:
    """(replace [(file, sha256)], delete [file]) of a per-rule commit journal.

    Replaced names must be names the rule writer stages; deleted names a plain visible file of
    the rule folder other than record/changelog; ValueError otherwise, before any file is touched.
    """
    if not isinstance(journal, dict):
        raise ValueError("commit journal is not an object")
    replace, delete = journal.get("replace", []), journal.get("delete", [])
    if not isinstance(replace, list) or not isinstance(delete, list):
        raise ValueError("commit journal lists are malformed")
    pairs = []
    for entry in replace:
        if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
            raise ValueError("commit journal entry is malformed")
        pairs.append((entry.get("file"), entry["sha256"]))
    for name, _ in pairs:
        if not (plain_rule_file(name) and WRITTEN_FILE.fullmatch(name)):
            raise ValueError(f"commit journal replaces an unexpected file: {name!r}")
    for name in delete:
        if not plain_rule_file(name) or name in ("record.json", "changelog.md"):
            raise ValueError(f"commit journal deletes an unexpected file: {name!r}")
    return pairs, list(delete)


def logical_view(raw: dict[str, str]) -> tuple[dict[str, str], bool, bool]:
    """Logical file texts of a rule folder map (regular files incl. `.new` and the 001-B journal),
    applying a committed journal in memory. Returns (files, ok, journal)."""
    files = {n: t for n, t in raw.items() if not n.startswith(".") and not n.endswith(".new")}
    if JOURNAL not in raw:
        return files, True, False
    try:
        replace, delete = commit_entries(json.loads(raw[JOURNAL]))
        for name, digest in replace:
            staged = raw.get(f"{name}.new")
            if staged is not None and _sha(staged) == digest:
                files[name] = staged
            elif name in files and _sha(files[name]) == digest:
                pass
            else:
                return files, False, True
        for name in delete:
            files.pop(name, None)
    except (ValueError, KeyError, TypeError, AttributeError):
        return files, False, True
    return files, True, True


def _folder_map(folder: Path) -> dict[str, str]:
    return {
        p.name: p.read_text(encoding="utf-8")
        for p in folder.iterdir()
        if p.is_file() and (not p.name.startswith(".") or p.name == JOURNAL)
    }


def lifecycle_valid(record: dict[str, Any]) -> bool:
    """Absent = active revision 0; otherwise exactly {state, revision} with known values."""
    if "lifecycle" not in record:
        return True
    value = record["lifecycle"]
    return (
        isinstance(value, dict)
        and set(value) == {"state", "revision"}
        and value["state"] in LIFECYCLE_STATES
        and type(value["revision"]) is int
        and value["revision"] >= 1
    )


def lifecycle_of(record: dict[str, Any]) -> dict[str, Any] | None:
    """The validated lifecycle object, or None when absent (active, revision 0)."""
    if "lifecycle" not in record:
        return None
    if not lifecycle_valid(record):
        raise ValueError("malformed lifecycle")
    return dict(record["lifecycle"])


def lifecycle_state(record: dict[str, Any]) -> tuple[str, int]:
    found = lifecycle_of(record)
    return (found["state"], found["revision"]) if found else ("active", 0)


def revision_digest(item_digest: str, revision: int) -> str:
    if revision == 0:
        return item_digest
    body = json.dumps(
        {"item_digest": item_digest, "lifecycle_revision": revision}, sort_keys=True, separators=(",", ":")
    )
    return "sha256:" + _sha(body)


def state_digest(stored: StoredRule) -> str | None:
    """Rule state digest: the item digest for never-exited rules, else item digest + revision."""
    if stored.digest is None or not lifecycle_valid(stored.record):
        return stored.digest
    return revision_digest(stored.digest, lifecycle_state(stored.record)[1])


def item_from(ref: RuleRef, record: dict[str, Any], files: dict[str, str]) -> Item:
    examples = {}
    for name, text in files.items():
        if name == "example.md":
            examples["general"] = text
        elif name.startswith("example-") and name.endswith(".md"):
            examples[name[len("example-") : -3]] = text
    applicability = record.get("applicability")
    return Item(
        ref=ref,
        name=record.get("name"),
        source_location=record.get("source_location"),
        content=files.get("content.md", ""),
        examples=examples,
        applicability=None if applicability == "unknown" else applicability,
        relations=[RuleRef.parse(r) for r in record.get("relations", [])],
    )


def read_rule(root: Path, ref: RuleRef) -> StoredRule | None:
    ensure_safe(root, f"{LOCAL_REL}/{ref.rel}", expect_dir=True)
    folder = rule_dir(root, ref)
    if not folder.is_dir():
        return None
    return rule_from_files(ref, _folder_map(folder))


def rule_from_files(ref: RuleRef, raw: dict[str, str]) -> StoredRule | None:
    """Shared by path and handle reads: `raw` holds the folder's regular files (incl. journal view)."""
    files, ok, journal = logical_view(raw)
    if "record.json" not in files:
        return None if not files else StoredRule(ref, {}, files, None, None, False, journal)
    raw = files.pop("record.json")
    try:
        record = json.loads(raw)
        item = item_from(ref, record, files)
        digest = item.digest()
        consistent = (
            ok
            and record.get("item_digest") == digest
            and record.get("schema") == RECORD_SCHEMA
            and lifecycle_valid(record)
        )
    except (ValueError, KeyError, TypeError, AttributeError, IdentityError):
        return StoredRule(ref, {}, files, None, None, False, journal, raw)
    return StoredRule(ref, record, files, item, digest, consistent, journal, raw)


def iter_refs(root: Path) -> list[RuleRef]:
    refs: list[RuleRef] = []
    base = local_root(root)
    if not base.is_dir():
        return refs
    for ns in sorted(os.scandir(base), key=lambda e: e.name):
        if not ns.is_dir(follow_symlinks=False):
            continue
        for ver in sorted(os.scandir(ns.path), key=lambda e: e.name):
            if not ver.is_dir(follow_symlinks=False):
                continue
            for rid in sorted(os.scandir(ver.path), key=lambda e: e.name):
                if rid.is_dir(follow_symlinks=False):
                    try:
                        refs.append(RuleRef.parse(f"{ns.name}/{ver.name}/{rid.name}"))
                    except IdentityError:
                        continue
    return refs


def texts_at(dfd: int) -> dict[str, str]:
    raw = {}
    for name, info in durable.listdir(dfd):
        if stat.S_ISREG(info.st_mode) and (not name.startswith(".") or name == JOURNAL):
            data = durable.read(dfd, name)
            if data is not None:
                raw[name] = data.decode("utf-8")
    return raw


def read_rule_at(tree: durable.Tree, ref: RuleRef) -> StoredRule | None:
    """Handle-relative `read_rule` through the command's Tree (no links followed)."""
    fd = tree.opt_dir(f"{LOCAL_REL}/{ref.rel}")
    if fd is None:
        return None
    try:
        return rule_from_files(ref, texts_at(fd))
    finally:
        durable.close(fd)


def _subfolders(tree: durable.Tree, dfd: int) -> list[str]:
    return [n for n, info in tree.list(dfd) if stat.S_ISDIR(info.st_mode)]


def iter_refs_at(tree: durable.Tree) -> list[RuleRef]:
    """Handle-relative `iter_refs`: link entries are skipped, never followed."""
    refs: list[RuleRef] = []
    base = tree.opt_dir(LOCAL_REL)
    if base is None:
        return refs
    try:
        for ns in _subfolders(tree, base):
            nfd = tree.dir(f"{LOCAL_REL}/{ns}")
            try:
                for ver in _subfolders(tree, nfd):
                    vfd = tree.dir(f"{LOCAL_REL}/{ns}/{ver}")
                    try:
                        for rid in _subfolders(tree, vfd):
                            try:
                                refs.append(RuleRef.parse(f"{ns}/{ver}/{rid}"))
                            except IdentityError:
                                continue
                    finally:
                        durable.close(vfd)
            finally:
                durable.close(nfd)
    finally:
        durable.close(base)
    return refs


def find_collision_at(tree: durable.Tree, ref: RuleRef) -> str | None:
    """Handle-relative `identity.find_collision` through the command's Tree: same case-insensitive
    rule and message, link entries are not folders and a link component is PATH_UNSAFE."""
    rel = LOCAL_REL
    for part in (ref.namespace, ref.version, ref.rule_id):
        fd = tree.opt_dir(rel)
        if fd is None:
            return None
        try:
            names = _subfolders(tree, fd)
        finally:
            durable.close(fd)
        if part in names:
            rel = f"{rel}/{part}"
            continue
        clash = [name for name in names if name.lower() == part.lower()]
        if clash:
            return f"'{part}' collides with existing '{clash[0]}' (differs only by letter case)"
        return None
    return None


def list_pending_at(tree: durable.Tree) -> list[dict[str, Any]]:
    """Handle-relative `list_pending` (pending/NS/VER/ID.json); unreadable files are skipped."""
    result = []
    for rel, name in pending_files_at(tree):
        fd = tree.dir(rel)
        try:
            data = json.loads((durable.read(fd, name) or b"").decode("utf-8"))
        except (OSError, ValueError, StoreError):
            continue
        finally:
            durable.close(fd)
        result.append(data)
    return result


def pending_files_at(tree: durable.Tree) -> list[tuple[str, str]]:
    """(folder rel, file name) of every regular `*.json` under pending/NS/VER, sorted."""
    found: list[tuple[str, str]] = []

    def walk(rel: str, depth: int) -> None:
        fd = tree.opt_dir(rel)
        if fd is None:
            return
        try:
            entries = tree.list(fd)
        finally:
            durable.close(fd)
        for name, info in entries:
            if depth < 2 and stat.S_ISDIR(info.st_mode):
                walk(f"{rel}/{name}", depth + 1)
            elif depth == 2 and stat.S_ISREG(info.st_mode) and name.endswith(".json"):
                found.append((rel, name))

    walk(PENDING_REL, 0)
    return sorted(found)


def recover_at(tree: durable.Tree, ref: RuleRef) -> None:
    """Handle-relative `recover`: same 001-B roll-forward/discard decisions, all I/O via the rule
    folder descriptor of the command's Tree (no links followed, nothing written outside)."""
    rel = f"{LOCAL_REL}/{ref.rel}"
    fd = tree.opt_dir(rel)
    if fd is None:
        return
    try:
        raw = durable.read(fd, JOURNAL)
        if raw is not None:
            try:
                replace, delete = commit_entries(json.loads(raw.decode("utf-8")))
                for name, digest in replace:
                    staged = durable.read(fd, f"{name}.new")
                    final = durable.read(fd, name)
                    if staged is not None:
                        if _sha(staged.decode("utf-8")) != digest:
                            raise StoreError(
                                "RULE_INCONSISTENT", f"{ref}: staged {name} does not match", RESTORE_STEP
                            )
                        durable.write(fd, name, staged, f".{name}.recover.tmp", mode=0o644)
                        durable.unlink(fd, f"{name}.new")
                    elif final is None or _sha(final.decode("utf-8")) != digest:
                        raise StoreError(
                            "RULE_INCONSISTENT", f"{ref}: {name} cannot be completed", RESTORE_STEP
                        )
                for name in delete:
                    durable.unlink(fd, name)
            except (ValueError, KeyError, TypeError) as exc:
                raise StoreError(
                    "RULE_INCONSISTENT", f"{ref}: unreadable commit journal", RESTORE_STEP
                ) from exc
            durable.unlink(fd, JOURNAL)
        for name, info in tree.list(fd):
            if name.endswith(".new") and stat.S_ISREG(info.st_mode):
                durable.unlink(fd, name)
        empty = not tree.list(fd)
    finally:
        durable.close(fd)
    if empty:
        parent = tree.dir(rel.rpartition("/")[0])
        try:
            durable.rmdir_empty(parent, ref.rule_id)
        finally:
            durable.close(parent)


def recover(root: Path, ref: RuleRef) -> None:
    """Physical roll-forward or discard; caller holds the write lock."""
    ensure_safe(root, f"{LOCAL_REL}/{ref.rel}", expect_dir=True)
    folder = rule_dir(root, ref)
    if not folder.is_dir():
        return
    journal_path = folder / JOURNAL
    if journal_path.exists():
        try:
            replace, delete = commit_entries(json.loads(journal_path.read_text(encoding="utf-8")))
            for name, digest in replace:
                staged, final = folder / f"{name}.new", folder / name
                if staged.exists():
                    if _sha(staged.read_text(encoding="utf-8")) != digest:
                        raise StoreError(
                            "RULE_INCONSISTENT", f"{ref}: staged {name} does not match journal", RESTORE_STEP
                        )
                    os.replace(staged, final)
                elif not (final.exists() and _sha(final.read_text(encoding="utf-8")) == digest):
                    raise StoreError(
                        "RULE_INCONSISTENT", f"{ref}: {name} cannot be completed from journal", RESTORE_STEP
                    )
            for name in delete:
                (folder / name).unlink(missing_ok=True)
        except (ValueError, KeyError, TypeError) as exc:
            raise StoreError(
                "RULE_INCONSISTENT", f"{ref}: unreadable commit journal", RESTORE_STEP
            ) from exc
        journal_path.unlink()
    for stray in folder.glob("*.new"):
        stray.unlink()
    if not any(folder.iterdir()):
        folder.rmdir()


def commit(
    root: Path,
    ref: RuleRef,
    writes: dict[str, str],
    deletes: list[str],
    *,
    base_digest: str | None,
    new_digest: str,
) -> None:
    """Redo-log commit of one rule; caller holds the write lock and checked authority."""
    rel = f"{LOCAL_REL}/{ref.rel}"
    reason = unsafe_component(root, rel, expect_dir=True)
    if reason:
        raise StoreError("PATH_UNSAFE", reason)
    folder = rule_dir(root, ref)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in writes.items():
        atomic_write_bytes(folder / f"{name}.new", text.encode("utf-8"))
    _crash_point("after_new_files")
    journal = {
        "rule": ref.rel,
        "base_digest": base_digest,
        "new_digest": new_digest,
        "replace": [{"file": n, "sha256": _sha(t)} for n, t in sorted(writes.items())],
        "delete": sorted(deletes),
    }
    atomic_write_bytes(folder / JOURNAL, dumps_json(journal))
    _crash_point("after_journal")
    for index, name in enumerate(sorted(writes)):
        os.replace(folder / f"{name}.new", folder / name)
        if index == 0:
            _crash_point("after_first_replace")
    for name in deletes:
        (folder / name).unlink(missing_ok=True)
    _crash_point("before_journal_delete")
    (folder / JOURNAL).unlink()


def record_text(
    item: Item,
    *,
    created_at: str,
    updated_at: str,
    source_documents: list[str],
    lifecycle: dict[str, Any] | None = None,
) -> str:
    record = {
        "schema": RECORD_SCHEMA,
        "namespace": item.ref.namespace,
        "version": item.ref.version,
        "rule_id": item.ref.rule_id,
        "kind": item.ref.kind,
        "name": item.name,
        "source_location": item.source_location,
        "source_location_status": "provided" if item.source_location else "missing",
        "applicability": item.applicability or "unknown",
        "relations": [str(r) for r in item.relations],
        "item_digest": item.digest(),
        "source_documents": sorted(set(source_documents)),
        "created_at": created_at,
        "updated_at": updated_at,
    }
    if lifecycle is not None:
        record["lifecycle"] = {"state": lifecycle["state"], "revision": lifecycle["revision"]}
    return dumps_json(record).decode("utf-8")


# --------------------------------------------------------------------------- pending + index
def pending_path(root: Path, ref: RuleRef) -> Path:
    return root / PENDING_REL / ref.namespace / ref.version / f"{ref.rule_id}.json"


def write_pending(root: Path, ref: RuleRef, item_digest: str, findings: list[dict], time: str) -> None:
    ensure_safe(root, f"{PENDING_REL}/{ref.rel}.json", expect_dir=False)
    atomic_write_bytes(
        pending_path(root, ref),
        dumps_json({"rule": ref.rel, "item_digest": item_digest, "findings": findings, "held_at": time}),
    )


def remove_pending(root: Path, ref: RuleRef) -> None:
    ensure_safe(root, f"{PENDING_REL}/{ref.rel}.json", expect_dir=False)
    pending_path(root, ref).unlink(missing_ok=True)


def list_pending(root: Path) -> list[dict[str, Any]]:
    base = root / PENDING_REL
    result = []
    if base.is_dir():
        for path in sorted(base.rglob("*.json")):
            try:
                result.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
    return result


def load_index(root: Path) -> dict[str, Any]:
    path = root / INDEX_REL
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_index(root: Path, index: dict[str, Any]) -> None:
    ensure_safe(root, INDEX_REL, expect_dir=False)
    atomic_write_bytes(root / INDEX_REL, dumps_json(index))
