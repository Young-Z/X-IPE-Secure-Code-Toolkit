"""Link-free, bounded snapshot of a helper's read scope bound to the target version at open
(FR-002F-6, AC-002F-04i/04j/04n; design §9.2, DEC-2 B: own walker on the delivered no-follow primitives).

One pass per owning target: files under the read scope are opened relative to their parent directory
descriptor without following links, confirmed regular on the handle, read once, copied and hashed (job A,
L-05); every other file of the owning targets of the scope and of the check object is hashed only (job B,
002-B staging bounds) so the target digest at open is reproduced exactly like `targets.snapshot`; the
check-object file list is collected for coverage (job C). `targets.py` is not changed.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ...adapters import safe_io
from ..targets import EXCLUDED_PREFIXES, display_name, owning_target
from ..toolrun import MAX_STAGE_BYTES, MAX_STAGE_FILES
from .model import (
    L05_COMPONENTS,
    L05_FILE_BYTES,
    L05_FILES,
    L05_PATH_BYTES,
    L05_TOTAL,
    OBJECT_FILES_MAX,
    SCHEMA_MANIFEST,
    canonical,
    sha,
)


class SnapshotRefused(Exception):
    """`code` ∈ limit, snapshot_unsafe, target_changed, target_too_large, cancelled, time."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code, self.reason = code, reason


def under(path: str, roots: list[str]) -> bool:
    return any(path == r or r == "." or path.startswith(r + "/") for r in roots)


def _excluded(rel: str, name: str) -> bool:
    return name == ".git" or any(f"{rel}/".startswith(p) for p in EXCLUDED_PREFIXES)


class _Walk:
    def __init__(
        self,
        scope: list[str],
        objects: list[str],
        dest: Path | None,
        should_stop: Callable[[], bool],
        deadline: float,
    ) -> None:
        self.scope, self.objects, self.dest = scope, objects, dest
        self.should_stop, self.deadline = should_stop, deadline
        self.files: list[dict[str, Any]] = []
        self.object_files: list[str] = []
        self.too_large = False
        self.copied = 0
        self.hashed_files = 0
        self.hashed_bytes = 0

    def tick(self) -> None:
        if self.should_stop():
            raise SnapshotRefused("cancelled", "verification cancelled during the snapshot")
        if time.monotonic() > self.deadline:
            raise SnapshotRefused("time", "verification time ran out during the snapshot")

    def file(self, fd: int, rel: str) -> str:
        """Hash (and for scope files copy) one opened regular file; returns its digest; closes `fd`."""
        in_scope = under(rel, self.scope)
        self.seen(rel)
        if not in_scope:
            self.hashed_files += 1
            if self.hashed_files > MAX_STAGE_FILES:
                os.close(fd)
                raise SnapshotRefused("target_too_large", "target too large to bind to the version at open")
            digest, size = _hash_fd(fd)
            self.hashed_bytes += size
            if self.hashed_bytes > MAX_STAGE_BYTES:
                raise SnapshotRefused("target_too_large", "target too large to bind to the version at open")
            return digest
        if len(rel.split("/")) > L05_COMPONENTS or len(rel.encode("utf-8")) > L05_PATH_BYTES:
            os.close(fd)
            raise SnapshotRefused("limit", f"limit L-05: path {rel} too long")
        if len(self.files) >= L05_FILES:
            os.close(fd)
            raise SnapshotRefused("limit", f"limit L-05: more than {L05_FILES} files in the read scope")
        assert self.dest is not None
        try:
            digest, size = safe_io.copy_hash(fd, self.dest / rel, L05_FILE_BYTES, 0o444)
        except safe_io.TooLarge:
            raise SnapshotRefused("limit", f"limit L-05: {rel} larger than {L05_FILE_BYTES} bytes") from None
        self.copied += size
        if self.copied > L05_TOTAL:
            raise SnapshotRefused("limit", f"limit L-05: read scope larger than {L05_TOTAL} bytes")
        self.files.append({"path": rel, "size": size, "sha256": digest})
        return digest

    def seen(self, rel: str) -> None:
        """Every non-excluded check-object entry counts; one the snapshot cannot copy stays uncovered."""
        if under(rel, self.objects) or any(under(o, [rel]) for o in self.objects):
            if len(self.object_files) < OBJECT_FILES_MAX:
                self.object_files.append(display_name(rel))
            else:
                self.too_large = True

    def irregular(self, rel: str, kind: str) -> None:
        if under(rel, self.scope) or any(under(s, [rel]) for s in self.scope):
            raise SnapshotRefused("snapshot_unsafe", f"snapshot unsafe: {display_name(rel)} is a {kind}")
        self.seen(rel)


def _hash_fd(fd: int) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    try:
        while chunk := os.read(fd, safe_io.CHUNK):
            size += len(chunk)
            digest.update(chunk)
    finally:
        os.close(fd)
    return "sha256:" + digest.hexdigest(), size


def _walk_target(root: Path, rel: str, kind: str, w: _Walk) -> str:
    if kind == "file":
        w.tick()
        try:
            fd = safe_io.open_nofollow(root, rel)
        except (OSError, safe_io.UnsafePath):
            w.irregular(rel, "link or unreadable file")
            return "unreadable"
        return w.file(fd, rel)
    lines: list[str] = []

    def walk(dfd: int, folder_rel: str) -> None:
        try:
            entries = sorted(os.scandir(dfd), key=lambda e: e.name)
        except OSError:
            w.irregular(folder_rel or ".", "unreadable folder")
            lines.append(f"{folder_rel or '.'}\0unreadable\n")
            return
        for entry in entries:
            w.tick()
            entry_rel = f"{folder_rel}/{entry.name}" if folder_rel else entry.name
            if _excluded(entry_rel, entry.name):
                continue
            if entry.is_symlink():
                w.irregular(entry_rel, "symbolic link")
                lines.append(f"{entry_rel}\0link\0{os.readlink(entry.name, dir_fd=dfd)}\n")
            elif entry.is_dir(follow_symlinks=False):
                try:
                    sub = os.open(entry.name, os.O_RDONLY | safe_io.DIRECTORY | safe_io.NOFOLLOW, dir_fd=dfd)
                except OSError:
                    raise SnapshotRefused(
                        "snapshot_unsafe", f"snapshot unsafe: {display_name(entry_rel)} changed"
                    ) from None
                try:
                    walk(sub, entry_rel)
                finally:
                    os.close(sub)
            elif entry.is_file(follow_symlinks=False):
                try:
                    fd = os.open(entry.name, os.O_RDONLY | safe_io.NOFOLLOW | safe_io.NONBLOCK, dir_fd=dfd)
                except OSError:
                    w.irregular(entry_rel, "unreadable file")
                    lines.append(f"{entry_rel}\0unreadable\n")
                    continue
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    os.close(fd)
                    raise SnapshotRefused(
                        "snapshot_unsafe", f"snapshot unsafe: {display_name(entry_rel)} changed"
                    )
                if safe_io.NONBLOCK:
                    os.set_blocking(fd, True)
                if display_name(entry_rel) != entry_rel:
                    w.irregular(entry_rel, "file with a non-UTF-8 name")
                    lines.append(f"{entry_rel}\0file\0{_hash_fd(fd)[0]}\n")
                    continue
                lines.append(f"{entry_rel}\0file\0{w.file(fd, entry_rel)}\n")
            else:
                w.irregular(entry_rel, "special file")
                lines.append(f"{entry_rel}\0special\n")

    try:
        base = safe_io.open_dir_nofollow(root, rel)
    except (OSError, safe_io.UnsafePath):
        raise SnapshotRefused("target_changed", f"target changed since open: {rel}") from None
    try:
        walk(base, "" if rel == "." else rel)
    finally:
        os.close(base)
    return "sha256:" + hashlib.sha256("".join(sorted(lines)).encode("utf-8", "surrogateescape")).hexdigest()


def build(
    root: Path,
    artifact: dict[str, Any],
    scope: list[str],
    objects: list[str],
    dest: Path,
    should_stop: Callable[[], bool],
    deadline: float,
) -> dict[str, Any]:
    """Copy the read scope into `dest` bound to the target version at open; return the manifest parts."""
    w = _Walk(scope, objects, dest, should_stop, deadline)
    owners = sorted({owning_target(artifact, p) for p in [*scope, *objects]} - {None})
    bound = []
    for owner in owners:
        entry = next(t for t in artifact["targets"] if t["path"] == owner)
        if entry["digest"] is None:
            raise SnapshotRefused("target_changed", f"target changed since open: {owner} was absent")
        try:
            staged = _walk_target(root, owner, entry["kind"], w)
        except safe_io.UnsafePath as exc:
            raise SnapshotRefused("snapshot_unsafe", f"snapshot unsafe: {exc}") from None
        if staged != entry["digest"]:
            raise SnapshotRefused("target_changed", f"target changed since open: {owner}")
        bound.append({"path": owner, "digest_at_open": entry["digest"], "digest_staged": staged})
    files = sorted(w.files, key=lambda f: f["path"])
    return {
        "targets": bound,
        "files": files,
        "digest": sha(canonical(files)),
        "object_files": {
            "count": len(w.object_files),
            "files": sorted(w.object_files),
            "too_large": w.too_large,
        },
    }


def manifest(helper_id: str, purpose: str, parts: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA_MANIFEST,
        "helper": helper_id,
        "purpose": purpose,
        "targets": parts["targets"],
        "files": parts["files"],
        "digest": parts["digest"],
    }


def place_sample(dest: Path, path: str, data: bytes) -> dict[str, Any]:
    target = dest / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(0o444)
    files = [{"path": path, "size": len(data), "sha256": sha(data)}]
    return {"targets": [], "files": files, "digest": sha(canonical(files))}


def seal(folder: Path) -> None:
    """Staging permissions: directories 0555, files 0444 (readable by the container user)."""
    for dirpath, _dirnames, filenames in os.walk(folder, topdown=False):
        for name in filenames:
            os.chmod(os.path.join(dirpath, name), 0o444, follow_symlinks=False)
        os.chmod(dirpath, 0o555)


def unseal_remove(folder: Path) -> bool:
    import shutil

    if not folder.exists():
        return True
    for dirpath, _dirnames, _filenames in os.walk(folder):
        os.chmod(dirpath, 0o700)
    shutil.rmtree(folder, ignore_errors=True)
    return not folder.exists()
