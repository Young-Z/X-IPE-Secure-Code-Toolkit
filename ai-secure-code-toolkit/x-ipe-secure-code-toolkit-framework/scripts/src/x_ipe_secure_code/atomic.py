"""Atomic file writes, an exclusive lock file and the file-free project lock (cooperating writers only)."""

from __future__ import annotations

import errno
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700
LOCK_TIMEOUT = 10.0  # the existing ProcessLock default, named (value unchanged)
LOCK_POLL = 0.05
# flock errors meaning "this file system cannot lock" rather than "another holder has the lock"
UNSUPPORTED_ERRNOS = frozenset(getattr(errno, name) for name in ("ENOLCK", "EOPNOTSUPP", "ENOTSUP", "EINVAL")
                               if hasattr(errno, name))
HELD_ERRNOS = frozenset({errno.EWOULDBLOCK, errno.EAGAIN})


def write_private_new(path: Path, data: bytes) -> None:
    """Create a new file with owner-only permissions; fail if it exists."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                 PRIVATE_FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def atomic_write_bytes(path: Path, data: bytes, *, private: bool = False) -> None:
    """Write via a temp file in the same directory, fsync, then os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{secrets.token_hex(6)}")
    mode = PRIVATE_FILE_MODE if private else 0o644
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def dumps_json(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


class LockHeld(Exception):
    def __init__(self, path: Path, info: str) -> None:
        super().__init__(f"Lock held: {path} ({info})")
        self.path = path
        self.info = info


class ExclusiveLock:
    """Exclusive-create lock file. A stale lock is reported, never broken automatically."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._held = False

    def __enter__(self) -> ExclusiveLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE)
        except FileExistsError:
            try:
                info = self.path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                info = "unreadable"
            raise LockHeld(self.path, info) from None
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"pid={os.getpid()} time={int(time.time())}\n")
        self._held = True
        return self

    def __exit__(self, *exc: object) -> None:
        if self._held:
            self.path.unlink(missing_ok=True)
            self._held = False


class ProcessLock:
    """OS-managed advisory lock, released automatically when the process exits.

    `create=False` never creates the lock file: if it does not exist, nobody ever
    wrote, so the context simply proceeds without locking (read-only callers).
    """

    def __init__(self, path: Path, *, timeout: float = LOCK_TIMEOUT, create: bool = True) -> None:
        self.path = path
        self.timeout = timeout
        self.create = create
        self._fd: int | None = None

    def __enter__(self) -> ProcessLock:
        if self.create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE)
        else:
            try:
                fd = os.open(self.path, os.O_RDWR)
            except FileNotFoundError:
                return self
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                _lock(fd)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockHeld(self.path, "held by another process") from None
                time.sleep(0.05)
        self._fd = fd
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            try:
                _unlock(self._fd)
            finally:
                os.close(self._fd)
                self._fd = None


class LockUnavailable(Exception):
    """Exclusivity cannot be established on this platform or file system (no lock file is used)."""


class ProjectLock:
    """Exclusive lock on the project root folder itself; never creates or touches any file.

    POSIX: polls flock(LOCK_EX | LOCK_NB) every LOCK_POLL seconds on a read-only descriptor of the root
    until `timeout`, then raises LockHeld. EWOULDBLOCK/EAGAIN mean "held"; ENOLCK, EOPNOTSUPP, ENOTSUP
    or EINVAL, a root that cannot be opened read-only, or Windows mean LockUnavailable. The OS releases
    the lock when the process ends, so there is never a stale lock.
    """

    def __init__(self, root: Path, *, timeout: float = LOCK_TIMEOUT) -> None:
        self.root = root
        self.timeout = timeout
        self._fd: int | None = None

    @staticmethod
    def _open(root: Path) -> int | None:
        if os.name == "nt" or fcntl is None:
            return None
        try:
            return os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            return None

    @staticmethod
    def available(root: Path) -> bool:
        """Read-only probe; a constant False without any I/O on Windows."""
        if os.name == "nt" or fcntl is None:
            return False
        fd = ProjectLock._open(root)
        if fd is None:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return True
        except OSError as exc:
            return exc.errno not in UNSUPPORTED_ERRNOS and exc.errno in HELD_ERRNOS
        finally:
            os.close(fd)

    def __enter__(self) -> ProjectLock:
        fd = self._open(self.root)
        if fd is None:
            raise LockUnavailable(f"no file-free lock for {self.root}")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if exc.errno not in HELD_ERRNOS:
                    os.close(fd)
                    raise LockUnavailable(f"flock unsupported for {self.root}: {exc.strerror}") from None
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockHeld(self.root, "held by another run") from None
                time.sleep(LOCK_POLL)
        self._fd = fd
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


if os.name == "nt":  # pragma: no cover - Windows only
    import msvcrt

    fcntl = None

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
