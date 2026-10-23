"""No-follow file access: open by descriptor, check the type on the descriptor, hash while copying.

POSIX uses `dir_fd` walking with O_NOFOLLOW for every component. Elsewhere a narrower
lstat/fstat identity check is used (Adapter execution is refused on Windows in this version).
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

CHUNK = 1024 * 1024
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
BINARY = getattr(os, "O_BINARY", 0)
NONBLOCK = getattr(os, "O_NONBLOCK", 0)
POSIX_FD = os.name == "posix" and os.open in os.supports_dir_fd


class UnsafePath(Exception):
    pass


class TooLarge(Exception):
    pass


def _check_regular(fd: int, rel: str) -> int:
    """Refuse a non-regular file; a regular file's descriptor is returned in blocking mode."""
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise UnsafePath(f"{rel} is not a regular file")
    if NONBLOCK:
        os.set_blocking(fd, True)
    return fd


def open_dir_nofollow(root: Path, rel: str) -> int:
    """Descriptor of the folder `root/rel` ('.' = root) without following links (POSIX)."""
    fd = os.open(root, os.O_RDONLY | DIRECTORY)
    if rel in ("", "."):
        return fd
    try:
        for part in rel.split("/"):
            try:
                nxt = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=fd)
            except OSError as exc:
                raise UnsafePath(f"{rel}: {part} is not a real folder ({exc.strerror})") from None
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_nofollow(root: Path, rel: str) -> int:
    """Read-only descriptor of the regular file `root/rel`; refuses any symbolic link on the way."""
    if not POSIX_FD:
        path = Path(root) / rel
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
            raise UnsafePath(f"{rel} is a link")
        fd = os.open(path, os.O_RDONLY | BINARY | NONBLOCK)
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            os.close(fd)
            raise UnsafePath(f"{rel} changed while opening")
        return _check_regular(fd, rel)
    parent, _, name = rel.rpartition("/")
    dfd = open_dir_nofollow(Path(root), parent or ".")
    try:
        try:
            fd = os.open(name, os.O_RDONLY | NOFOLLOW | NONBLOCK, dir_fd=dfd)
        except OSError as exc:
            raise UnsafePath(f"{rel} cannot be opened safely ({exc.strerror})") from None
    finally:
        os.close(dfd)
    return _check_regular(fd, rel)


def open_absolute_nofollow(path: Path) -> int:
    """Descriptor of an absolute regular file; the final component must not be a link."""
    path = Path(path)
    return open_nofollow(path.parent, path.name)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("write made no progress")
        view = view[written:]


def copy_hash(fd: int, dest: Path, limit: int, mode: int = 0o600) -> tuple[str, int]:
    """Copy from the descriptor to a new file while hashing; closes `fd`."""
    sha = hashlib.sha256()
    size = 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | BINARY, mode)
    try:
        while chunk := os.read(fd, CHUNK):
            size += len(chunk)
            if size > limit:
                raise TooLarge(f"{dest.name} exceeds {limit} bytes")
            sha.update(chunk)
            _write_all(out, chunk)
    finally:
        os.close(out)
        os.close(fd)
    return "sha256:" + sha.hexdigest(), size


def hash_fd(fd: int) -> str:
    sha = hashlib.sha256()
    try:
        while chunk := os.read(fd, CHUNK):
            sha.update(chunk)
    finally:
        os.close(fd)
    return "sha256:" + sha.hexdigest()


def hash_path(path: Path) -> str:
    return hash_fd(open_absolute_nofollow(Path(path)))
