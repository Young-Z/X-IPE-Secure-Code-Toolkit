"""Durable, no-follow file primitives relative to directory handles (FEATURE-001-D).

POSIX: every component is opened with O_NOFOLLOW relative to the command's root handle
(`Tree`); every replace/unlink/move/mkdir is followed by an fsync of the containing folder.
Windows (honest limit): path fallback with lstat/identity checks and no directory fsync;
handles are opaque integers that must be closed with `close`.
Standard library only: `store` imports this module, never the reverse.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from pathlib import Path

from .. import atomic
from ..atomic import LockHeld

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
NONBLOCK = getattr(os, "O_NONBLOCK", 0)
BINARY = getattr(os, "O_BINARY", 0)
POSIX_FD = os.name == "posix" and os.open in os.supports_dir_fd and os.scandir in os.supports_fd
FAIL_ENV = "SECURE_CODE_TEST_FAIL_AT"
_fail_counts: dict[str, int] = {}
_step: str = ""
_WIN: dict[int, Path] = {}


class StoreError(Exception):
    """Refusal of a knowledge storage operation (re-exported as `store.StoreError`)."""

    def __init__(self, code: str, message: str, next_step: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.next_step = next_step


def unsafe(message: str) -> StoreError:
    return StoreError(
        "PATH_UNSAFE", message, "Replace the symbolic link or wrong entry with a real folder/file"
    )


def set_step(name: str) -> None:
    """Name of the exit step being applied (only used by the test failure-injection hook)."""
    global _step
    _step = name


def _inject(primitive: str) -> None:
    """Test-only: `SECURE_CODE_TEST_FAIL_AT=<primitive>:<step>[@n]` raises OSError (never changes data)."""
    target = os.environ.get(FAIL_ENV)
    if not target:
        return
    point, _, nth = target.partition("@")
    if point != f"{primitive}:{_step}":
        return
    _fail_counts[point] = _fail_counts.get(point, 0) + 1
    if _fail_counts[point] == int(nth or 1):
        code = errno.EXDEV if primitive == "exdev" else errno.EIO
        raise OSError(code, f"injected failure at {point}")


def _parts(rel: str) -> list[str]:
    return [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]


def _win_handle(path: Path) -> int:
    handle = -(len(_WIN) + 1)
    while handle in _WIN:
        handle -= 1
    _WIN[handle] = path
    return handle


def close(fd: int | None) -> None:
    if fd is None:
        return
    if fd < 0:
        _WIN.pop(fd, None)
    else:
        os.close(fd)


def _fsync_dir(dfd: int) -> None:
    if POSIX_FD:
        os.fsync(dfd)


class Tree:
    """One per command: the project-root handle all later reads and writes are relative to."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        if POSIX_FD:
            self.fd = os.open(self.root, os.O_RDONLY | DIRECTORY)
        else:  # pragma: no cover - Windows only
            self.fd = _win_handle(self.root)

    def __enter__(self) -> Tree:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self.fd is not None:
            close(self.fd)
            self.fd = None  # type: ignore[assignment]

    def dir(self, rel: str, *, create: bool = False, mode: int = 0o700) -> int:
        """New handle of the real folder `rel` (no links followed); caller closes it."""
        if not POSIX_FD:  # pragma: no cover - Windows only
            return self._win_dir(rel, create, mode)
        fd = os.dup(self.fd)
        try:
            for part in _parts(rel):
                try:
                    nxt = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(part, mode, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                    nxt = self._open_part(part, fd, rel)
                except OSError as exc:
                    raise unsafe(f"{rel}: '{part}' is not a real folder ({exc.strerror})") from None
                os.close(fd)
                fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _open_part(part: str, fd: int, rel: str) -> int:
        try:
            return os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=fd)
        except OSError as exc:
            raise unsafe(f"{rel}: '{part}' is not a real folder ({exc.strerror})") from None

    def opt_dir(self, rel: str, *, mode: int = 0o700) -> int | None:
        """Like `dir`, but None when a component is absent."""
        try:
            return self.dir(rel, mode=mode)
        except FileNotFoundError:
            return None

    def _win_dir(self, rel: str, create: bool, mode: int) -> int:  # pragma: no cover - Windows only
        current = self.root
        for part in _parts(rel):
            current = current / part
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(current, mode)
                info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise unsafe(f"{rel}: '{part}' is a link")
            if not stat.S_ISDIR(info.st_mode):
                raise unsafe(f"{rel}: '{part}' is not a folder")
        return _win_handle(current)

    def list(self, dfd: int) -> list[tuple[str, os.stat_result]]:
        return listdir(dfd)


def listdir(dfd: int) -> list[tuple[str, os.stat_result]]:
    """Entries of a folder handle, sorted by name, never following links."""
    target = _WIN[dfd] if not POSIX_FD else dfd
    with os.scandir(target) as it:
        return sorted(((e.name, e.stat(follow_symlinks=False)) for e in it), key=lambda x: x[0])


def entry(dfd: int, name: str) -> os.stat_result | None:
    try:
        if not POSIX_FD:  # pragma: no cover - Windows only
            return os.lstat(_WIN[dfd] / name)
        return os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _open_file(dfd: int, name: str, flags: int, mode: int = 0o600) -> int:
    if not POSIX_FD:  # pragma: no cover - Windows only
        return os.open(_WIN[dfd] / name, flags | BINARY, mode)
    return os.open(name, flags | NOFOLLOW, mode, dir_fd=dfd)


def read(dfd: int, name: str) -> bytes | None:
    """Bytes of a regular file (None if absent); links and special files are never opened."""
    before = entry(dfd, name)
    if before is None:
        return None
    if not stat.S_ISREG(before.st_mode):
        raise unsafe(f"{name} is not a regular file")
    fd = _open_file(dfd, name, os.O_RDONLY | NONBLOCK)
    try:
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(after.st_mode):
            raise unsafe(f"{name} changed while opening")
        chunks = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "write made no progress")
        view = view[written:]


def _remove_quietly(dfd: int, name: str) -> None:
    try:
        if not POSIX_FD:  # pragma: no cover - Windows only
            os.unlink(_WIN[dfd] / name)
        else:
            os.unlink(name, dir_fd=dfd)
    except OSError:
        pass


def write(dfd: int, name: str, data: bytes, tmp: str, *, mode: int | None = None) -> None:
    """Durable replace: exclusive no-follow temp, fsync file, replace, fsync folder.

    The file keeps the mode of the file it replaces; a new file is owner-only unless `mode` is given.
    """
    current = entry(dfd, name)
    if current is not None and not stat.S_ISREG(current.st_mode):
        raise unsafe(f"{name} is not a regular file")
    if mode is None:
        mode = stat.S_IMODE(current.st_mode) if current is not None else 0o600
    if entry(dfd, tmp) is not None:
        _remove_quietly(dfd, tmp)
    fd = _open_file(dfd, tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    if current is not None and POSIX_FD:
        os.fchmod(fd, mode)  # keep the replaced file's mode regardless of the umask
    replaced = False
    try:
        try:
            _write_all(fd, data)
            _inject("temp_fsync")
            os.fsync(fd)
        finally:
            os.close(fd)
        _inject("replace")
        if not POSIX_FD:  # pragma: no cover - Windows only
            os.replace(_WIN[dfd] / tmp, _WIN[dfd] / name)
        else:
            os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        replaced = True
    finally:
        if not replaced:
            _remove_quietly(dfd, tmp)
    _inject("dir_fsync")
    _fsync_dir(dfd)


def unlink(dfd: int, name: str) -> None:
    """Remove a regular file and make the removal durable."""
    found = entry(dfd, name)
    if found is None:
        return
    if not stat.S_ISREG(found.st_mode):
        raise unsafe(f"{name} is not a regular file")
    _inject("unlink")
    if not POSIX_FD:  # pragma: no cover - Windows only
        os.unlink(_WIN[dfd] / name)
    else:
        os.unlink(name, dir_fd=dfd)
    _fsync_dir(dfd)


def same_device(a: int, b: int) -> bool:
    if not POSIX_FD:  # pragma: no cover - Windows only
        return os.stat(_WIN[a]).st_dev == os.stat(_WIN[b]).st_dev
    return os.fstat(a).st_dev == os.fstat(b).st_dev


def move(src_dfd: int, name: str, dst_dfd: int, new: str) -> None:
    """Atomic folder move between two handles; destination must be absent."""
    found = entry(src_dfd, name)
    if found is None or not stat.S_ISDIR(found.st_mode):
        raise unsafe(f"{name} is not a real folder")
    if entry(dst_dfd, new) is not None:
        raise OSError(errno.EEXIST, f"{new} already exists")
    if not same_device(src_dfd, dst_dfd):
        raise OSError(errno.EXDEV, "source and destination are on different devices")
    _inject("exdev")
    _inject("move")
    if not POSIX_FD:  # pragma: no cover - Windows only
        os.rename(_WIN[src_dfd] / name, _WIN[dst_dfd] / new)
    else:
        os.rename(name, new, src_dir_fd=src_dfd, dst_dir_fd=dst_dfd)
    _fsync_dir(dst_dfd)
    _fsync_dir(src_dfd)


def open_child(dfd: int, name: str) -> int:
    """Handle of a real subfolder of `dfd` (link or other kind → PATH_UNSAFE)."""
    if not POSIX_FD:  # pragma: no cover - Windows only
        info = os.lstat(_WIN[dfd] / name)
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise unsafe(f"{name} is not a real folder")
        return _win_handle(_WIN[dfd] / name)
    try:
        return os.open(name, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=dfd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise unsafe(f"{name} is not a real folder") from None
        raise


def readlink(dfd: int, name: str) -> str:
    if not POSIX_FD:  # pragma: no cover - Windows only
        return os.readlink(_WIN[dfd] / name)
    return os.readlink(name, dir_fd=dfd)


def rmdir_empty(dfd: int, name: str) -> None:
    if not POSIX_FD:  # pragma: no cover - Windows only
        os.rmdir(_WIN[dfd] / name)
    else:
        os.rmdir(name, dir_fd=dfd)
    _fsync_dir(dfd)


class DirLock:
    """Exclusive advisory lock on `rel`, reached by a no-follow walk from the Tree root.

    `create=False` and absent → proceed unlocked (same semantics as `atomic.ProcessLock`).
    """

    def __init__(self, tree: Tree, rel: str, *, create: bool, timeout: float = 10.0) -> None:
        self.tree, self.rel, self.create, self.timeout = tree, rel, create, timeout
        self.owns_tree = False
        self._fd: int | None = None
        parent, _, self.name = rel.rpartition("/")
        try:
            self._parent = tree.dir(parent, create=True) if create else tree.opt_dir(parent)
            found = entry(self._parent, self.name) if self._parent is not None else None
            if found is not None and not stat.S_ISREG(found.st_mode):
                raise unsafe(f"{rel} is not a regular lock file")
        except BaseException:
            close(getattr(self, "_parent", None))
            self._release_tree()
            raise

    def _release_tree(self) -> None:
        if self.owns_tree:
            self.tree.close()

    def __enter__(self) -> DirLock:
        try:
            self._acquire()
        except BaseException:
            close(self._parent)
            self._parent = None
            self._release_tree()
            raise
        return self

    def _open_lock(self) -> int | None:
        """Open-existing, else exclusive-create (concurrent plain O_CREAT via a dir handle can fail
        with ENOENT on macOS); None when absent and not creating."""
        assert self._parent is not None
        for _ in range(100):
            try:
                return _open_file(self._parent, self.name, os.O_RDWR)
            except FileNotFoundError:
                if not self.create:
                    return None
            try:
                return _open_file(self._parent, self.name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
        raise OSError(errno.EAGAIN, f"{self.rel} could not be opened")

    def _acquire(self) -> None:
        if self._parent is None:
            return
        try:
            fd = self._open_lock()
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EISDIR, errno.EMLINK):
                raise unsafe(f"{self.rel} is not a regular lock file") from None
            raise
        if fd is None:
            return
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise unsafe(f"{self.rel} is not a regular lock file")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                atomic._lock(fd)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockHeld(Path(self.rel), "held by another process") from None
                time.sleep(0.05)
        self._fd = fd

    def __exit__(self, *exc: object) -> None:
        try:
            if self._fd is not None:
                try:
                    atomic._unlock(self._fd)
                finally:
                    os.close(self._fd)
                    self._fd = None
        finally:
            close(self._parent)
            self._parent = None
            self._release_tree()
