"""Descriptor-based safety for the Trivy private folders (FEATURE-002-D, staging-root safety).

Every create, copy, sweep and removal below `adapter-stage/trivy/` and `tools/trivy-cache/` is relative to
an already opened folder descriptor and never follows a link; it composes the no-follow primitives of
`knowledge/durable.py` (always called through the module, so the test fault hooks apply).
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from typing import Any

from ..knowledge import durable
from . import safe_io

CHUNK = 1024 * 1024


class IdentityChanged(Exception):
    """The folder at a name is no longer the one the caller created or listed; nothing was deleted there."""


def _ident(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def open_root(tree: durable.Tree, rel: str) -> int:
    """Private (0700, owned) real folder `rel` below the project, created when missing; returns its fd."""
    fd = tree.dir(rel, create=True)
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        os.close(fd)
        raise durable.unsafe(f"{rel} is not a private folder of this user")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.fchmod(fd, 0o700)
    return fd


def make_dir(dfd: int, name: str) -> int:
    """Exclusive private sub-folder of `dfd`; returns its descriptor."""
    os.mkdir(name, 0o700, dir_fd=dfd)
    return durable.open_child(dfd, name)


def make_leaf(root_fd: int, prefix: str) -> tuple[str, int, tuple[int, int]]:
    """A new uniquely named folder (exclusive creation; an existing name or link is never reused)."""
    for _ in range(5):
        name = f"{prefix}{secrets.token_hex(8)}"
        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
        except FileExistsError:
            continue
        fd = durable.open_child(root_fd, name)
        identity = _ident(os.fstat(fd))
        found = durable.entry(root_fd, name)
        if found is None or _ident(found) != identity:
            os.close(fd)
            raise IdentityChanged(f"{name} changed while it was created")
        return name, fd, identity
    raise OSError("could not create a unique private folder")


def _parent(leaf_fd: int, parts: list[str]) -> int:
    fd = os.dup(leaf_fd)
    try:
        for part in parts:
            try:
                nxt = durable.open_child(fd, part)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=fd)
                nxt = durable.open_child(fd, part)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def copy_into(leaf_fd: int, rel: str, src_fd: int, limit: int) -> tuple[str, int]:
    """Copy `src_fd` to `rel` below `leaf_fd` (new file, no link followed) while hashing; closes `src_fd`."""
    parts = rel.split("/")
    try:
        dfd = _parent(leaf_fd, parts[:-1])
    except BaseException:
        os.close(src_fd)
        raise
    sha, size = hashlib.sha256(), 0
    try:
        out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | durable.NOFOLLOW, 0o600, dir_fd=dfd)
    except BaseException:
        os.close(src_fd)
        os.close(dfd)
        raise
    try:
        while chunk := os.read(src_fd, CHUNK):
            size += len(chunk)
            if size > limit:
                raise safe_io.TooLarge(f"{rel} exceeds {limit} bytes")
            sha.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(out, view) :]
    finally:
        os.close(out)
        os.close(src_fd)
        os.close(dfd)
    return "sha256:" + sha.hexdigest(), size


def unlink_link(dfd: int, name: str, expected: str) -> None:
    """Remove the symbolic link itself (never its target) when it still points to `expected`."""
    found = durable.entry(dfd, name)
    if found is None or not stat.S_ISLNK(found.st_mode):
        raise durable.unsafe(f"{name} is not the expected link")
    if durable.readlink(dfd, name) != expected:
        raise durable.unsafe(f"{name} does not point to the expected component")
    os.unlink(name, dir_fd=dfd)


def _empty(fd: int) -> None:
    os.fchmod(fd, 0o700)
    for child, st in durable.listdir(fd):
        if stat.S_ISDIR(st.st_mode):
            remove_tree_at(fd, child, _ident(st))
        else:
            os.unlink(child, dir_fd=fd)


def remove_tree_at(dfd: int, name: str, expected: tuple[int, int]) -> None:
    """Remove the folder `name` of `dfd` only while it is still the folder identified by `expected`."""
    found = durable.entry(dfd, name)
    if found is None or not stat.S_ISDIR(found.st_mode) or _ident(found) != expected:
        raise IdentityChanged(f"{name} is not the expected folder")
    fd = durable.open_child(dfd, name)
    try:
        if _ident(os.fstat(fd)) != expected:
            raise IdentityChanged(f"{name} was replaced before removal")
        _empty(fd)
    finally:
        os.close(fd)
    again = durable.entry(dfd, name)
    if again is None or _ident(again) != expected:
        raise IdentityChanged(f"{name} was replaced during removal")
    durable.rmdir_empty(dfd, name)


def empty_by_fd(fd: int) -> None:
    """Remove the contents of an opened folder through its descriptor only."""
    _empty(fd)


def leaf_matches(root_fd: int, name: str, leaf_fd: int, identity: tuple[int, int]) -> bool:
    found = durable.entry(root_fd, name)
    return (
        found is not None
        and stat.S_ISDIR(found.st_mode)
        and _ident(found) == identity
        and _ident(os.fstat(leaf_fd)) == identity
    )


def sweep(root_fd: int, pattern: str) -> list[dict[str, Any]]:
    """Remove leftover private folders matching `pattern`; links are unlinked, other names reported."""
    report: list[dict[str, Any]] = []
    for name, st in durable.listdir(root_fd):
        if not re.fullmatch(pattern, name):
            report.append(
                {
                    "code": "STAGING_UNEXPECTED",
                    "name": name,
                    "message": f"unexpected entry {name} left untouched",
                }
            )
            continue
        if stat.S_ISDIR(st.st_mode):
            try:
                remove_tree_at(root_fd, name, _ident(st))
            except (IdentityChanged, OSError, durable.StoreError) as exc:
                report.append({"code": "STAGING_LEFTOVER", "name": name, "message": f"not removed: {exc}"})
        else:
            os.unlink(name, dir_fd=root_fd)
            report.append(
                {"code": "STAGING_LEFTOVER", "name": name, "message": "link or file entry unlinked"}
            )
    return report


def link_into(dst_fd: int, rel: str, src_fd: int) -> None:
    """Hard link `rel` of folder `src_fd` to the same `rel` below `dst_fd` (same file system, no links)."""
    parts = rel.split("/")
    dfd = _parent(dst_fd, parts[:-1])
    try:
        os.link(rel, parts[-1], src_dir_fd=src_fd, dst_dir_fd=dfd, follow_symlinks=False)
    finally:
        os.close(dfd)
