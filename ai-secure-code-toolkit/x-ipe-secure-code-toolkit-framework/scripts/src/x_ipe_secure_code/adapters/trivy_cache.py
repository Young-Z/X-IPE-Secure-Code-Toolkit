"""Per-project Trivy component cache (FEATURE-002-D): immutable generations, `components.json` pointer,
component state and sizes, scan folders reading components in place, post-scan re-hash and invalid mark,
strict installation of downloaded subtrees, removal and garbage collection.

Writers run under the project Guard lock; `status` only reads (`component_state`).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..knowledge import durable, store
from . import trivy_fs
from .trivy import COMPONENTS, SUBTREE, VERSION

CACHE_REL = f"{store.PRIVATE_REL}/tools/trivy-cache"
SCHEMA = "ai-secure-code-toolkit/trivy-cache/v1"
POINTER = "components.json"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
DB_KEYS = ("Version", "UpdatedAt", "NextUpdate", "DownloadedAt")
BUNDLE_KEYS = ("MajorVersion", "Digest", "DownloadedAt")
CHUNK = 1024 * 1024
OP_PATTERN = r"^op-[0-9a-f]{16}$"


class Rejected(Exception):
    """A downloaded subtree does not have the exact validated shape."""


# --------------------------------------------------------------------------- pointer
def pointer_bytes(doc: dict[str, Any]) -> bytes:
    return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8")


def read_pointer_bytes(root: Path) -> bytes | None:
    with durable.Tree(root) as tree:
        fd = tree.opt_dir(CACHE_REL)
        if fd is None:
            return None
        try:
            return durable.read(fd, POINTER)
        finally:
            os.close(fd)


def parse_pointer(data: bytes | None) -> dict[str, Any] | None:
    if data is None:
        return None
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        return {"schema": SCHEMA, "components": {}, "unreadable": True}
    if not isinstance(doc, dict) or not isinstance(doc.get("components"), dict):
        return {"schema": SCHEMA, "components": {}, "unreadable": True}
    return doc


def load_pointer(root: Path) -> dict[str, Any] | None:
    return parse_pointer(read_pointer_bytes(root))


def write_pointer_bytes(root: Path, data: bytes | None) -> None:
    """Atomic durable replace of `components.json` (removal when `data` is None)."""
    with durable.Tree(root) as tree:
        fd = tree.dir(CACHE_REL, create=True)
        try:
            if data is None:
                durable.unlink(fd, POINTER)
            else:
                durable.write(fd, POINTER, data, ".components.json.tmp", mode=0o600)
        finally:
            os.close(fd)


def empty_pointer() -> dict[str, Any]:
    return {"schema": SCHEMA, "tool_version": VERSION, "revision": 0, "components": {}}


# --------------------------------------------------------------------------- metadata and state
def parse_time(text: Any) -> datetime | None:
    if not isinstance(text, str):
        return None
    # Trivy writes some times in the process's local zone (e.g. checks-bundle `DownloadedAt`): accept a
    # `±hh:mm` offset and convert to UTC.
    m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(?:Z|([+-])(\d\d):(\d\d))", text)
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    zone = UTC
    if m.group(3):
        hours, minutes = int(m.group(4)), int(m.group(5))
        if hours > 23 or minutes > 59:
            return None
        sign = -1 if m.group(3) == "-" else 1
        zone = timezone(sign * timedelta(hours=hours, minutes=minutes))
    try:
        local = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(microsecond=int(frac), tzinfo=zone)
    except ValueError:
        return None
    return local.astimezone(UTC)


def metadata_problem(component: str, meta: Any, tag: str) -> str | None:
    if not isinstance(meta, dict):
        return "metadata.json is not an object"
    if component == "checks_bundle":
        if meta.get("MajorVersion") != _int(tag):
            return f"MajorVersion {meta.get('MajorVersion')!r} does not match tag {tag}"
        if not isinstance(meta.get("Digest"), str) or not DIGEST.fullmatch(meta["Digest"]):
            return "Digest is not sha256:<64 hex>"
        times = ("DownloadedAt",)
    else:
        if meta.get("Version") != _int(tag):
            return f"Version {meta.get('Version')!r} does not match tag {tag}"
        times = ("UpdatedAt", "NextUpdate", "DownloadedAt")
    for key in times:
        if parse_time(meta.get(key)) is None:
            return f"{key} is not an RFC 3339 time"
    return None


def _int(tag: str) -> int | None:
    return int(tag) if str(tag).isdigit() else None


def _sha(path: Path) -> str:
    sha = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | durable.NOFOLLOW)
    try:
        while chunk := os.read(fd, CHUNK):
            sha.update(chunk)
    finally:
        os.close(fd)
    return "sha256:" + sha.hexdigest()


def _walk(base: Path) -> tuple[dict[str, os.stat_result], list[str]]:
    """Regular files below `base` (lstat, never following links) and problems found."""
    files: dict[str, os.stat_result] = {}
    problems: list[str] = []

    def walk(folder: Path, rel: str) -> None:
        for entry in sorted(os.scandir(folder), key=lambda e: e.name):
            sub = f"{rel}/{entry.name}" if rel else entry.name
            st = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                walk(Path(entry.path), sub)
            elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                files[sub] = st
            else:
                problems.append(f"{sub} is a link or special file")

    walk(base, "")
    return files, problems


def generation_path(root: Path, name: str, generation: str) -> Path:
    return root / CACHE_REL / "gen" / name / generation


def _structure(gen: Path, entry: dict[str, Any], full: bool) -> str | None:
    try:
        st = os.lstat(gen)
    except FileNotFoundError:
        return "generation folder missing"
    if not stat.S_ISDIR(st.st_mode):
        return "generation is not a real folder"
    try:
        files, problems = _walk(gen)
    except OSError as exc:
        return f"generation not readable: {exc}"
    if problems:
        return problems[0]
    recorded = entry.get("files") or {}
    if set(files) != set(recorded):
        extra = sorted(set(files) - set(recorded))
        missing = sorted(set(recorded) - set(files))
        return f"unexpected file {extra[0]}" if extra else f"file {missing[0]} missing"
    for rel, rec in sorted(recorded.items()):
        if files[rel].st_size != rec.get("size"):
            return f"{rel} size changed"
        if (full or rel.endswith("metadata.json")) and _sha(gen / rel) != rec.get("sha256"):
            return f"{rel} changed since provisioning"
    return None


def disk_bytes(path: Path) -> int | None:
    try:
        total = os.lstat(path).st_blocks * 512
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            for n in dirnames + filenames:
                total += os.lstat(os.path.join(dirpath, n)).st_blocks * 512
        return total
    except OSError:
        return None


def _age(seconds: int) -> str:
    return f"{seconds // 86400} d {seconds % 86400 // 3600} h"


def component_state(root: Path, name: str, now: Any, pointer: dict[str, Any] | None = None) -> dict[str, Any]:
    """present / missing / unreadable (incl. invalid), metadata, age (databases only) and on-disk size."""
    if pointer is None:
        pointer = load_pointer(root)
    entry = ((pointer or {}).get("components") or {}).get(name)
    if not entry:
        return {"state": "missing", "reason": "not provisioned"}
    out: dict[str, Any] = {
        k: entry.get(k)
        for k in ("registry", "repository", "tag", "generation", "metadata", "content_digest", "size_bytes")
    }
    if name == "checks_bundle":
        out["source"] = f"{entry.get('repository')}:{entry.get('tag')}"
    gen = generation_path(root, name, str(entry.get("generation")))
    size = disk_bytes(gen)
    if size is not None:
        out["disk_bytes"] = size
    if entry.get("invalid"):
        return {
            **out,
            "state": "unreadable",
            "reason": f"invalid: {entry['invalid'].get('reason')}; re-provision",
        }
    problem = _structure(gen, entry, full=False)
    meta = None
    if problem is None:
        try:
            meta = json.loads((gen / SUBTREE[name] / "metadata.json").read_bytes())
        except (OSError, ValueError):
            problem = "metadata.json not readable"
        else:
            problem = metadata_problem(name, meta, str(entry.get("tag")))
    if problem:
        return {**out, "state": "unreadable", "reason": problem}
    out["metadata"] = {k: meta.get(k) for k in (BUNDLE_KEYS if name == "checks_bundle" else DB_KEYS)}
    if name != "checks_bundle":
        when = now if isinstance(now, datetime) else parse_time(now) or datetime.now(UTC)
        seconds = int((when - parse_time(meta["UpdatedAt"])).total_seconds())
        out.update(age_seconds=seconds, age=_age(seconds))
    return {**out, "state": "present", "reason": None}


# --------------------------------------------------------------------------- scans
def scan_folder(root: Path, needed: list[str], dest_fd: int, pointer: dict[str, Any]) -> dict[str, str]:
    """Directory links (in the disposable scan folder) to the current generations: read in place."""
    links = {}
    for name in needed:
        entry = pointer["components"][name]
        target = str((generation_path(root, name, entry["generation"]) / SUBTREE[name]).resolve())
        os.symlink(target, SUBTREE[name], dir_fd=dest_fd)
        links[SUBTREE[name]] = target
    return links


def rehash(root: Path, used: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Full re-hash of every used component against its provisioning digests."""
    out = {}
    for name, entry in sorted(used.items()):
        problem = _structure(generation_path(root, name, entry["generation"]), entry, full=True)
        out[name] = "unchanged" if problem is None else problem
    return out


def mark_invalid(root: Path, name: str, generation: str, reason: str, vid: str, run: int | None) -> None:
    pointer = load_pointer(root)
    entry = ((pointer or {}).get("components") or {}).get(name)
    if not entry or entry.get("generation") != generation or entry.get("invalid"):
        return
    entry["invalid"] = {"reason": reason, "detected_at": _now(), "verification_id": vid, "run": run}
    pointer["revision"] = int(pointer.get("revision", 0)) + 1
    write_pointer_bytes(root, pointer_bytes(pointer))


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- provisioning
def verify_subtree(cache: Path, component: str, tag: str, fallback: bool) -> tuple[dict[str, Any], dict]:
    """Exact validated subtree of one component in the operation's cache folder; returns file records."""
    sub = SUBTREE[component]
    names = sorted(os.listdir(cache)) if cache.is_dir() else []
    if names != [sub] or not stat.S_ISDIR(os.lstat(cache / sub).st_mode):
        raise Rejected(
            f"the download did not produce exactly the {sub}/ subtree (found: {names or 'nothing'})"
        )
    files, problems = _walk(cache / sub)
    if problems:
        raise Rejected(problems[0])
    rels = {f"{sub}/{r}" for r in files}
    if any(not re.fullmatch(r"[A-Za-z0-9._/+@-]+", r) or ".." in r.split("/") for r in rels):
        raise Rejected("unexpected file name in the download")
    if component == "checks_bundle":
        if fallback:
            raise Rejected("the tool fell back to embedded checks: the checks bundle was not downloaded")
        others = rels - {"policy/metadata.json"}
        if (
            "policy/metadata.json" not in rels
            or not others
            or any(not r.startswith("policy/content/") for r in others)
        ):
            raise Rejected("policy/metadata.json and a non-empty policy/content/ are required")
    else:
        db = "trivy.db" if component == "vulnerability_db" else "trivy-java.db"
        if rels != {f"{sub}/{db}", f"{sub}/metadata.json"}:
            raise Rejected(f"expected exactly {sub}/{db} and {sub}/metadata.json")
    try:
        meta = json.loads((cache / sub / "metadata.json").read_bytes())
    except (OSError, ValueError):
        raise Rejected("metadata.json is not readable JSON") from None
    problem = metadata_problem(component, meta, tag)
    if problem:
        raise Rejected(problem)
    records = {f"{sub}/{r}": {"sha256": _sha(cache / sub / r), "size": st.st_size} for r, st in files.items()}
    return records, meta


def content_digest(records: dict[str, Any]) -> str:
    lines = "".join(f"{rel}\0{rec['sha256']}\n" for rel, rec in sorted(records.items()))
    return "sha256:" + hashlib.sha256(lines.encode("utf-8")).hexdigest()


def install_generation(root: Path, component: str, cache: Path) -> str:
    """Move a verified subtree into a new read-only generation; returns its id."""
    gen_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    with durable.Tree(root) as tree:
        fd = tree.dir(f"{CACHE_REL}/gen/{component}", create=True)
        try:
            os.mkdir(gen_id, 0o700, dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)
    gen = generation_path(root, component, gen_id)
    os.rename(cache / SUBTREE[component], gen / SUBTREE[component])
    for dirpath, _dirnames, filenames in os.walk(gen, topdown=False):
        for n in filenames:
            p = os.path.join(dirpath, n)
            os.chmod(p, 0o444, follow_symlinks=False)
            fd = os.open(p, os.O_RDONLY | durable.NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        os.chmod(dirpath, 0o555)
    return gen_id


def remove_generation(root: Path, component: str, generation: str) -> None:
    with durable.Tree(root) as tree:
        fd = tree.opt_dir(f"{CACHE_REL}/gen/{component}")
        if fd is None:
            return
        try:
            found = durable.entry(fd, generation)
            if found is not None and stat.S_ISDIR(found.st_mode):
                trivy_fs.remove_tree_at(fd, generation, (found.st_dev, found.st_ino))
        finally:
            os.close(fd)


def referenced(root: Path, pointer: dict[str, Any] | None, extra: dict[str, Any] | None = None) -> set[str]:
    out = set()
    for doc in (pointer, extra):
        for name, entry in ((doc or {}).get("components") or {}).items():
            out.add(f"{name}/{entry.get('generation')}")
    return out


def collect_garbage(root: Path) -> list[dict[str, Any]]:
    """Delete generations no pointer (nor a pending journal) references, and leftover operation folders."""
    from . import trivy_journal

    keep = referenced(root, load_pointer(root), trivy_journal.pending_new_pointer(root))
    report: list[dict[str, Any]] = []
    with durable.Tree(root) as tree:
        gen_fd = tree.opt_dir(f"{CACHE_REL}/gen")
        if gen_fd is not None:
            try:
                for component, st in durable.listdir(gen_fd):
                    if component not in COMPONENTS or not stat.S_ISDIR(st.st_mode):
                        continue
                    cfd = durable.open_child(gen_fd, component)
                    try:
                        for gen, gst in durable.listdir(cfd):
                            if f"{component}/{gen}" not in keep and stat.S_ISDIR(gst.st_mode):
                                trivy_fs.remove_tree_at(cfd, gen, (gst.st_dev, gst.st_ino))
                    finally:
                        os.close(cfd)
            finally:
                os.close(gen_fd)
        staging = tree.opt_dir(f"{CACHE_REL}/staging")
        if staging is not None:
            try:
                report += trivy_fs.sweep(staging, OP_PATTERN)
            finally:
                os.close(staging)
    return report


def remove(root: Path, names: list[str]) -> dict[str, dict[str, Any]]:
    """Drop the named components from the pointer (atomic), then collect their generations."""
    pointer = load_pointer(root) or empty_pointer()
    removed = {}
    for name in names:
        entry = pointer["components"].pop(name, None)
        if entry:
            freed = disk_bytes(generation_path(root, name, entry["generation"])) or 0
            removed[name] = {"generation": entry["generation"], "freed_disk_bytes": freed}
    if removed:
        pointer["revision"] = int(pointer.get("revision", 0)) + 1
        write_pointer_bytes(root, pointer_bytes(pointer))
        collect_garbage(root)
    return removed
