"""No-follow reads and the exclusive comparison writer of `secure-code guard compare` (FEATURE-002-G).

Reads: every access is relative to one `durable.Tree` root handle, components are opened without
following links, and each file is read with a byte cap. Writes (FR-002G-8, DEC-03 A): each final name
is published by `link()` from an exclusive no-follow temp, so a final name never holds partial bytes
and is never overwritten or followed. Commit order: structured comparison, folder fsync, Markdown
(commit marker), folder fsync, then the folder identity and the pair are re-verified before success.
"""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
from collections.abc import Callable
from typing import Any

from ..knowledge import durable
from .compare_render import footer_digest
from .model import GUARD_REL, REPORTS_REL, GuardError

OVERSIZE = object()  # a file larger than the read cap (never read beyond cap + 1 bytes)
COMPARISONS = "comparisons"
COMPARISONS_REL = f"{REPORTS_REL}/{COMPARISONS}"
MAX_ATTEMPTS = 8
UNSUPPORTED_LINK = frozenset(
    getattr(errno, name) for name in ("EPERM", "ENOTSUP", "EOPNOTSUPP", "ENOSYS") if hasattr(errno, name)
)
NO_FOLLOW_LINK = {"follow_symlinks": False} if os.link in os.supports_follow_symlinks else {}
UNSAFE_STEP = "Replace the symbolic link or special entry with a real folder or file"
WRITE_STEP = "Check permissions and free space of reports/guard/comparisons/, then retry"


def _fail_point(step: str) -> None:
    """Test seam (no-op in delivered use): tests replace it to inject failures at named write steps."""


def unsafe(rel: str, what: str) -> GuardError:
    return GuardError("PATH_UNSAFE", f"{rel}: {what}", UNSAFE_STEP, {"path": rel})


class WriteFailed(Exception):
    def __init__(self, code: str, step: str, message: str) -> None:
        super().__init__(message)
        self.code, self.step, self.message = code, step, message


def _open_rel(tree: durable.Tree, dfd: int, rel: str, name: str, flags: int, mode: int = 0o644) -> int:
    if durable.POSIX_FD:
        return os.open(name, flags | durable.NOFOLLOW, mode, dir_fd=dfd)
    return os.open(tree.root / rel / name, flags | durable.BINARY, mode)  # pragma: no cover - Windows only


def read_bounded(tree: durable.Tree, dfd: int, rel: str, name: str, cap: int) -> Any:
    """Bytes of a regular file (None if absent, OVERSIZE above `cap`); links and special files refused."""
    before = durable.entry(dfd, name)
    if before is None:
        return None
    if not stat.S_ISREG(before.st_mode):
        raise unsafe(f"{rel}/{name}", "not a regular file")
    if before.st_size > cap:
        return OVERSIZE
    fd = _open_rel(tree, dfd, rel, name, os.O_RDONLY | durable.NONBLOCK)
    try:
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(after.st_mode):
            raise unsafe(f"{rel}/{name}", "changed while opening")
        chunks, total = [], 0
        while total <= cap:
            chunk = os.read(fd, min(1024 * 1024, cap + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    return OVERSIZE if total > cap else b"".join(chunks)


class Inputs:
    """Metadata checks and bounded content reads below `reports/guard/`, all through one root handle."""

    def __init__(self, tree: durable.Tree) -> None:
        self.tree = tree
        try:
            self.reports_fd = tree.dir(REPORTS_REL)
        except FileNotFoundError:
            raise GuardError(
                "RUN_NOT_FOUND",
                "There are no Guard reports in this project",
                "Name a concluded verification of this project",
            ) from None
        except durable.StoreError:
            raise unsafe(REPORTS_REL, "a component is a symbolic link or not a folder") from None

    def close(self) -> None:
        durable.close(self.reports_fd)

    def twin(self, name: str) -> os.stat_result | None:
        """lstat of a report twin; links and special files are refused before any read."""
        info = durable.entry(self.reports_fd, name)
        if info is not None and not stat.S_ISREG(info.st_mode):
            raise unsafe(f"{REPORTS_REL}/{name}", "not a regular file")
        return info

    def run_folder(self, vid: str) -> str:
        """Existence of a run folder (metadata only): available, not available or unknown."""
        try:
            gfd = self.tree.opt_dir(GUARD_REL)
        except (durable.StoreError, OSError):
            return "unknown"
        if gfd is None:
            return "not available"
        try:
            info = durable.entry(gfd, vid)
        except OSError:
            return "unknown"
        finally:
            durable.close(gfd)
        if info is None:
            return "not available"
        return "available" if stat.S_ISDIR(info.st_mode) else "unknown"

    def comparisons_precheck(self) -> None:
        info = durable.entry(self.reports_fd, COMPARISONS)
        if info is not None and not stat.S_ISDIR(info.st_mode):
            raise unsafe(COMPARISONS_REL, "is a symbolic link or not a folder")

    def read(self, name: str, cap: int) -> Any:
        return read_bounded(self.tree, self.reports_fd, REPORTS_REL, name, cap)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Writer:
    """One exclusive write of a comparison pair (steps W0…W10 of the technical design)."""

    def __init__(self, tree: durable.Tree, reports_fd: int) -> None:
        self.tree, self.reports_fd = tree, reports_fd
        self.cfd: int | None = None
        self.created = False
        self.created_id: tuple[int, int] | None = None  # identity of the folder this command created
        self.made: list[str] = []  # temps and final names this command created (removed on failure)
        self.step = "folder_create"

    def at(self, step: str) -> None:
        self.step = step
        _fail_point(step)

    def verify(self) -> None:
        """The held `comparisons/` handle is still the folder reached from the root without links."""
        try:
            fd = self.tree.dir(COMPARISONS_REL)
        except durable.StoreError:
            raise unsafe(COMPARISONS_REL, "is a symbolic link or not a folder") from None
        except FileNotFoundError:
            raise WriteFailed("COMPARISON_WRITE_FAILED", self.step, "comparisons/ was moved away") from None
        try:
            a, b = os.fstat(fd), os.fstat(self.cfd)
        finally:
            durable.close(fd)
        if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
            raise WriteFailed("COMPARISON_WRITE_FAILED", self.step, "comparisons/ was replaced")

    def folder(self) -> None:
        info = durable.entry(self.reports_fd, COMPARISONS)
        if info is None:
            self.at("folder_create")
            if durable.POSIX_FD:
                os.mkdir(COMPARISONS, 0o777, dir_fd=self.reports_fd)
            else:  # pragma: no cover - Windows only
                os.mkdir(self.tree.root / COMPARISONS_REL)
            self.created = True
            made = durable.entry(self.reports_fd, COMPARISONS)
            if made is not None and stat.S_ISDIR(made.st_mode):
                self.created_id = (made.st_dev, made.st_ino)
            if durable.POSIX_FD:
                os.fsync(self.reports_fd)
        elif not stat.S_ISDIR(info.st_mode):
            raise unsafe(COMPARISONS_REL, "is a symbolic link or not a folder")
        try:
            self.cfd = self.tree.dir(COMPARISONS_REL)
        except durable.StoreError:
            raise unsafe(COMPARISONS_REL, "is a symbolic link or not a folder") from None
        self.at("after_checks")
        self.verify()

    def exists(self, name: str) -> bool:
        return durable.entry(self.cfd, name) is not None

    def temp(self, final: str, data: bytes, kind: str) -> str:
        name = f".{final}.{secrets.token_hex(6)}.tmp"
        fd = _open_rel(self.tree, self.cfd, COMPARISONS_REL, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        self.made.append(name)
        try:
            self.at(f"{kind}_write")
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError(errno.EIO, "write made no progress")
                view = view[written:]
            self.at(f"{kind}_fsync")
            os.fsync(fd)
        finally:
            os.close(fd)
        return name

    def link(self, tmp: str, final: str, step: str) -> bool:
        """Publish `tmp` as `final` (False when the name exists: collision); the temp is removed."""
        self.at(step)
        self.verify()
        self.step = step.replace("before_", "")  # json_link / markdown_link
        try:
            if durable.POSIX_FD:
                os.link(tmp, final, src_dir_fd=self.cfd, dst_dir_fd=self.cfd, **NO_FOLLOW_LINK)
            else:  # pragma: no cover - Windows only
                base = self.tree.root / COMPARISONS_REL
                os.link(base / tmp, base / final)
        except FileExistsError:
            self.unlink(tmp)
            return False
        except NotImplementedError:  # pragma: no cover - platform without hard links
            raise WriteFailed("HARDLINK_UNSUPPORTED", self.step, "hard links are not supported") from None
        except OSError as exc:
            if exc.errno in UNSUPPORTED_LINK or getattr(exc, "winerror", None) == 1:
                raise WriteFailed("HARDLINK_UNSUPPORTED", self.step, "hard links are not supported") from None
            raise
        self.made.append(final)
        self.unlink(tmp)
        return True

    def unlink(self, name: str) -> None:
        try:
            if durable.POSIX_FD:
                os.unlink(name, dir_fd=self.cfd)
            else:  # pragma: no cover - Windows only
                os.unlink(self.tree.root / COMPARISONS_REL / name)
        except FileNotFoundError:
            pass
        if name in self.made:
            self.made.remove(name)

    def fsync_folder(self, step: str) -> None:
        self.step = step
        if durable.POSIX_FD:
            os.fsync(self.cfd)

    def read_back(self, name: str, cap: int) -> Any:
        return read_bounded(self.tree, self.cfd, COMPARISONS_REL, name, cap)

    def cleanup(self) -> None:
        """Remove, through the held handle only, everything this command created."""
        if self.cfd is not None:
            for name in list(self.made):
                try:
                    self.unlink(name)
                except OSError:
                    pass
            try:
                if durable.POSIX_FD:
                    os.fsync(self.cfd)
            except OSError:
                pass
        if not self.created:
            return
        try:  # only while it is still the same, empty entry under reports/guard/ (never by path elsewhere)
            if self.cfd is not None:
                held = os.fstat(self.cfd)
                identity: tuple[int, int] | None = (held.st_dev, held.st_ino)
            else:
                identity = self.created_id
            info = durable.entry(self.reports_fd, COMPARISONS)
            same = identity is not None and info is not None and (info.st_dev, info.st_ino) == identity
            if same and stat.S_ISDIR(info.st_mode):
                durable.rmdir_empty(self.reports_fd, COMPARISONS)
        except OSError:
            pass

    def commit(
        self, factory: Callable[[], tuple[str, bytes, Callable[[str], bytes]]]
    ) -> tuple[str, list[str]]:
        self.folder()
        collisions: list[str] = []
        for _ in range(MAX_ATTEMPTS):
            cid, json_bytes, markdown_factory = factory()
            names = (f"{cid}.json", f"{cid}.md")
            taken = [n for n in names if self.exists(n)]
            if taken:
                collisions += taken
                continue
            tmp = self.temp(names[0], json_bytes, "json")
            if not self.link(tmp, names[0], "before_json_link"):
                collisions.append(names[0])
                continue
            self.fsync_folder("after_json_link")
            self.at("after_json_dir_fsync")
            if self.read_back(names[0], len(json_bytes)) != json_bytes:
                raise WriteFailed(
                    "COMPARISON_WRITE_FAILED", "json_read_back", "structured comparison differs"
                )
            md_bytes = markdown_factory(sha256_hex(json_bytes))
            tmp = self.temp(names[1], md_bytes, "markdown")
            if not self.link(tmp, names[1], "before_markdown_link"):
                collisions.append(names[1])
                self.unlink(names[0])
                self.fsync_folder("collision")
                continue
            self.at("after_markdown_link")
            self.at("before_final_dir_fsync")
            self.at("folder_fsync")
            self.fsync_folder("folder_fsync")
            self.at("before_final_verification")
            self.verify()
            self.final_check(names, json_bytes, md_bytes)
            return cid, collisions
        raise GuardError(
            "COMPARISON_COLLISION",
            f"{MAX_ATTEMPTS} allocated comparison names already existed",
            "Retry; existing entries in comparisons/ were not touched",
            {"collisions": collisions},
        )

    def final_check(self, names: tuple[str, str], json_bytes: bytes, md_bytes: bytes) -> None:
        got_json = self.read_back(names[0], len(json_bytes))
        got_md = self.read_back(names[1], len(md_bytes))
        cid = names[0][: -len(".json")]
        if (
            got_json != json_bytes
            or got_md != md_bytes
            or footer_digest(md_bytes.decode("utf-8")) != sha256_hex(json_bytes)
            or not md_bytes.startswith(f"# Guard Report Comparison {cid}\n".encode())
        ):
            raise WriteFailed(
                "COMPARISON_WRITE_FAILED", "final_verification", "the written pair does not verify"
            )


def write_pair(
    tree: durable.Tree, reports_fd: int, factory: Callable[[], tuple[str, bytes, Callable[[str], bytes]]]
) -> tuple[str, list[str]]:
    """Write one comparison pair exclusively; on any failure remove what this command created."""
    writer = _Writer(tree, reports_fd)
    try:
        return writer.commit(factory)
    except GuardError:
        writer.cleanup()
        raise
    except WriteFailed:
        writer.cleanup()
        raise
    except (OSError, durable.StoreError) as exc:
        writer.cleanup()
        raise WriteFailed("COMPARISON_WRITE_FAILED", writer.step, str(exc)) from None
    finally:
        durable.close(writer.cfd)
