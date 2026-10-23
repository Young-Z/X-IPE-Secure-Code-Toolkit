"""Artifact scope: path roles, change meaning and file/tree digests (symbolic links are never followed)."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..paths import RootError, safe_relative
from .mask import mask_text
from .model import CHANGES, Checker, GuardError

EXCLUDED_PREFIXES = (".x-ipe/private/", "x-ipe-docs/secure-code/")
PRIVATE_PREFIX = ".x-ipe/private/"
PATH_STEP = "Pass existing project-relative paths without symbolic links"
REQUEST_STEP = "Fix the open request (see the Guard skill references/guard-records.md)"


def _invalid(message: str, step: str = PATH_STEP) -> GuardError:
    return GuardError("TARGET_INVALID", message, step)


def normalize(raw: Any, where: str) -> str:
    """Project-relative POSIX path; the project itself is '.'."""
    if not isinstance(raw, str):
        raise GuardError("REQUEST_INVALID", f"{where}.path must be text", REQUEST_STEP)
    try:
        raw.encode("utf-8")
    except UnicodeError:
        raise GuardError("REQUEST_INVALID", f"{where}.path must be valid UTF-8 text", REQUEST_STEP) from None
    text = raw.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    if text.rstrip("/") in ("", "."):
        return "."
    if mask_text(text)[1]:
        raise GuardError(
            "REQUEST_INVALID",
            f"{where}.path looks like a credential; paths are stored unmasked",
            REQUEST_STEP,
        )
    try:
        return safe_relative(text)
    except RootError:
        raise _invalid(f"{where}: {raw!r} is not a project-relative path inside the project") from None


def kind_of(root: Path, rel: str, where: str) -> str | None:
    """'file', 'dir' or None (absent); refuses symbolic links, special files and private toolkit data."""
    if rel == ".":
        return "dir"
    if f"{rel}/".startswith(PRIVATE_PREFIX):
        raise _invalid(f"{where}: {rel} is private toolkit data, not an artifact")
    current = root
    parts = rel.split("/")
    for index, part in enumerate(parts):
        current = current / part
        if current.is_symlink():
            raise _invalid(f"{where}: {'/'.join(parts[: index + 1])} is a symbolic link")
        if not current.exists():
            return None
        if index < len(parts) - 1 and not current.is_dir():
            raise _invalid(f"{where}: {'/'.join(parts[: index + 1])} is not a folder")
    if current.is_file():
        return "file"
    if current.is_dir():
        return "dir"
    raise _invalid(f"{where}: {rel} is not a regular file or folder")


def display_name(rel: str) -> str:
    """File-system names that are not UTF-8 shown with escapes, so they stay storable."""
    return rel.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def file_digest(path: str | Path) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return "sha256:" + sha.hexdigest()


def _excluded(rel: str, name: str) -> bool:
    return name == ".git" or any(f"{rel}/".startswith(p) for p in EXCLUDED_PREFIXES)


def _walk(root: Path, rel: str) -> Iterator[tuple[str, str, Any]]:
    """Yield `(event, entry_rel, value)` for every entry of a folder in name order; links never followed.

    Events: `dir_unreadable`, `link` (value: link text, real path), `file` (value: digest),
    `file_unreadable` and `special`. Excluded toolkit data and `.git` are skipped.
    """
    base = root if rel == "." else root / rel

    def walk(folder: str, folder_rel: str) -> Iterator[tuple[str, str, Any]]:
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError:
            yield "dir_unreadable", folder_rel or ".", None
            return
        for entry in entries:
            entry_rel = f"{folder_rel}/{entry.name}" if folder_rel else entry.name
            if _excluded(entry_rel, entry.name):
                continue
            if entry.is_symlink():
                yield "link", entry_rel, (os.readlink(entry.path), os.path.realpath(entry.path))
            elif entry.is_dir(follow_symlinks=False):
                yield from walk(entry.path, entry_rel)
            elif entry.is_file(follow_symlinks=False):
                try:
                    digest = file_digest(entry.path)
                except OSError:
                    yield "file_unreadable", entry_rel, None
                    continue
                yield "file", entry_rel, digest
            else:
                yield "special", entry_rel, None

    yield from walk(str(base), "" if rel == "." else rel)


def _tree(root: Path, rel: str) -> dict[str, Any]:
    base_real = os.path.realpath(root if rel == "." else root / rel)
    lines: list[str] = []
    not_followed: list[dict[str, Any]] = []
    unreadable: list[str] = []
    for event, entry_rel, value in _walk(root, rel):
        if event == "dir_unreadable":
            unreadable.append(display_name(entry_rel))
            lines.append(f"{entry_rel}\0unreadable\n")
        elif event == "link":
            text, real = value
            lines.append(f"{entry_rel}\0link\0{text}\n")
            if not os.path.exists(real):
                unreadable.append(display_name(entry_rel))
            else:
                inside = real == base_real or real.startswith(base_real + os.sep)
                not_followed.append({"path": display_name(entry_rel), "inside_tree": inside})
        elif event == "file":
            lines.append(f"{entry_rel}\0file\0{value}\n")
        elif event == "file_unreadable":
            unreadable.append(display_name(entry_rel))
            lines.append(f"{entry_rel}\0unreadable\n")
        else:
            unreadable.append(display_name(entry_rel))
            lines.append(f"{entry_rel}\0special\n")
    digest = "sha256:" + hashlib.sha256("".join(sorted(lines)).encode("utf-8", "surrogateescape")).hexdigest()
    incomplete = bool(unreadable) or any(not n["inside_tree"] for n in not_followed)
    return {
        "digest": digest,
        "incomplete": incomplete,
        "not_followed": not_followed,
        "unreadable": unreadable,
    }


NOT_BINDABLE = {
    "dir_unreadable": "folder could not be read",
    "link": "symbolic link (not followed)",
    "file_unreadable": "file could not be read",
    "special": "not a regular file",
}


def tree_files(root: Path, rel: str, limit: int | None = None) -> dict[str, Any]:
    """Per-file digests of a folder (same walk and exclusions as the folder digest).

    Returns `files` ({path: digest} of storable regular files), `not_bindable` (links, special,
    unreadable or unstorable names, each with a reason) and `truncated` (more than `limit` files).
    """
    files: dict[str, str] = {}
    not_bindable: list[dict[str, str]] = []
    for event, entry_rel, value in _walk(root, rel):
        shown = display_name(entry_rel)
        if event != "file":
            not_bindable.append({"path": mask_text(shown)[0], "reason": NOT_BINDABLE[event]})
        elif shown != entry_rel:
            not_bindable.append({"path": shown, "reason": "name is not valid UTF-8"})
        elif mask_text(entry_rel)[1]:
            not_bindable.append({"path": mask_text(entry_rel)[0], "reason": "name looks like a credential"})
        else:
            files[entry_rel] = value
            if limit is not None and len(files) > limit:
                return {"files": files, "not_bindable": not_bindable, "truncated": True}
    return {"files": files, "not_bindable": not_bindable, "truncated": False}


def snapshot(root: Path, rel: str, kind: str | None) -> dict[str, Any]:
    """Digest and completeness of one path of known kind (None = absent)."""
    if kind is None:
        return {"digest": None, "incomplete": False, "not_followed": [], "unreadable": []}
    if kind == "dir":
        return _tree(root, rel)
    try:
        digest = file_digest(root / rel)
    except OSError:
        return {"digest": "unreadable", "incomplete": True, "not_followed": [], "unreadable": [rel]}
    return {"digest": digest, "incomplete": False, "not_followed": [], "unreadable": []}


def stage(
    root: Path,
    rel: str,
    kind: str,
    dest_root: Path,
    max_bytes: int,
    max_files: int,
    dest_fd: int | None = None,
    skip: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Copy one target into `dest_root` without following links, hashing the copied bytes.

    The digest is computed exactly like `snapshot` (same lines), so it can be compared with the
    digest recorded when the verification was opened. Links and special entries are hashed by the
    same markers but never copied; they are returned as `irregular`. With `dest_fd` (FEATURE-002-D)
    every copy is created descriptor-relative below that folder instead of below `dest_root`. Files in
    `skip` (FEATURE-002-D: explicit image-archive targets staged on their own) are hashed into the digest
    but neither copied nor counted against the limits.
    """
    from ..adapters import safe_io

    def copy(fd: int, entry_rel: str, limit: int) -> tuple[str, int]:
        if dest_fd is None:
            return safe_io.copy_hash(fd, dest_root / entry_rel, limit)
        from ..adapters import trivy_fs

        return trivy_fs.copy_into(dest_fd, entry_rel, fd, limit)

    if kind == "file":
        fd = safe_io.open_nofollow(root, rel)
        digest, size = copy(fd, rel, max_bytes)
        return {"digest": digest, "files": [rel], "irregular": [], "bytes": size}
    lines: list[str] = []
    files: list[str] = []
    irregular: list[str] = []
    total = 0

    def walk(dfd: int, folder_rel: str) -> None:
        nonlocal total
        try:
            entries = sorted(os.scandir(dfd), key=lambda e: e.name)
        except OSError:
            irregular.append(display_name(folder_rel or "."))
            lines.append(f"{folder_rel or '.'}\0unreadable\n")
            return
        for entry in entries:
            entry_rel = f"{folder_rel}/{entry.name}" if folder_rel else entry.name
            if _excluded(entry_rel, entry.name):
                continue
            if entry.is_symlink():
                lines.append(f"{entry_rel}\0link\0{os.readlink(entry.name, dir_fd=dfd)}\n")
                irregular.append(display_name(entry_rel))
            elif entry.is_dir(follow_symlinks=False):
                try:
                    sub = os.open(entry.name, os.O_RDONLY | safe_io.DIRECTORY | safe_io.NOFOLLOW, dir_fd=dfd)
                except OSError as exc:
                    raise safe_io.UnsafePath(
                        f"{display_name(entry_rel)} changed while staging ({exc.strerror})"
                    ) from None
                try:
                    walk(sub, entry_rel)
                finally:
                    os.close(sub)
            elif entry.is_file(follow_symlinks=False):
                try:
                    fd = os.open(entry.name, os.O_RDONLY | safe_io.NOFOLLOW | safe_io.NONBLOCK, dir_fd=dfd)
                except OSError:
                    irregular.append(display_name(entry_rel))
                    lines.append(f"{entry_rel}\0unreadable\n")
                    continue
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    os.close(fd)
                    raise safe_io.UnsafePath(f"{display_name(entry_rel)} changed while staging")
                if safe_io.NONBLOCK:
                    os.set_blocking(fd, True)
                if entry_rel in skip:
                    lines.append(f"{entry_rel}\0file\0{safe_io.hash_fd(fd)}\n")
                    continue
                if display_name(entry_rel) != entry_rel:  # not representable as UTF-8: hashed, never scanned
                    lines.append(f"{entry_rel}\0file\0{safe_io.hash_fd(fd)}\n")
                    irregular.append(display_name(entry_rel))
                    continue
                digest, size = copy(fd, entry_rel, max_bytes - total)
                total += size
                files.append(entry_rel)
                if len(files) > max_files:
                    raise safe_io.TooLarge(f"more than {max_files} files to stage")
                lines.append(f"{entry_rel}\0file\0{digest}\n")
            else:
                irregular.append(display_name(entry_rel))
                lines.append(f"{entry_rel}\0special\n")

    base = safe_io.open_dir_nofollow(root, rel)
    try:
        walk(base, "" if rel == "." else rel)
    finally:
        os.close(base)
    digest = "sha256:" + hashlib.sha256("".join(sorted(lines)).encode("utf-8", "surrogateescape")).hexdigest()
    return {"digest": digest, "files": files, "irregular": irregular, "bytes": total}


def observe(root: Path, rel: str) -> dict[str, Any]:
    """Current snapshot at conclusion; unsafe or special paths get a digest that never matches."""
    try:
        kind = kind_of(root, rel, "target")
    except GuardError:
        return {"digest": "unsafe", "incomplete": True, "not_followed": [], "unreadable": [rel]}
    return snapshot(root, rel, kind)


def parse_open(root: Path, doc: dict[str, Any]) -> dict[str, Any]:
    """Validate the open request; return scope id, request texts and the recorded artifact scope."""
    ck = Checker("REQUEST_INVALID", REQUEST_STEP)
    allowed = {
        "schema",
        "scope_id",
        "request",
        "baseline",
        "whole_project",
        "targets",
        "context",
        "suggested",
        "copilot_reports",
        "budget",
    }
    ck.obj(doc, "request", allowed)
    scope_id = doc.get("scope_id")
    if scope_id in (None, ""):
        raise GuardError(
            "MAINTENANCE_NEEDED",
            "No adopted scope was given; Guard verifies only against adopted Policies",
            "Select and confirm Policies with the Framework skill (secure-code scope save), "
            "then pass its scope_id",
        )
    if not isinstance(scope_id, str):
        raise ck.fail("scope_id must be text")
    whole = ck.flag(doc.get("whole_project"), "whole_project")
    raw_targets = ck.items(doc.get("targets"), "targets")
    if whole and raw_targets:
        raise ck.fail("whole_project cannot be combined with other targets")
    if not whole and not raw_targets:
        raise GuardError(
            "TARGETS_REQUIRED",
            "No target was given",
            "Name the files or folders to verify, "
            "or choose the whole project explicitly (whole_project: true)",
        )
    roles: dict[str, str] = {}

    def claim(rel: str, role: str) -> None:
        if rel in roles:
            raise GuardError(
                "ROLE_CONFLICT",
                f"{rel} is given as {roles[rel]} and as {role}",
                "Give each path exactly one role: target, context or suggested",
            )
        roles[rel] = role

    found: list[dict[str, Any]] = []
    if whole:
        claim(".", "target")
        found.append(
            {
                "path": ".",
                "kind": "dir",
                "change": "unspecified",
                "old_path": None,
                **snapshot(root, ".", "dir"),
            }
        )
    for index, raw in enumerate(raw_targets):
        where = f"targets[{index}]"
        ck.obj(raw, where, {"path", "change", "old_path"}, frozenset({"path"}))
        rel = normalize(raw["path"], where)
        if rel == ".":
            raise GuardError(
                "WHOLE_PROJECT_NOT_EXPLICIT",
                "The whole project was given as a target without an explicit whole_project choice",
                "Ask the user; set whole_project: true only when the user explicitly chose the whole project",
            )
        change = ck.choice(raw.get("change", "unspecified"), f"{where}.change", CHANGES)
        old = raw.get("old_path")
        if change == "renamed":
            if old in (None, ""):
                raise ck.fail(f"{where} is renamed but has no old_path")
            old = normalize(old, f"{where}.old_path")
        elif old is not None:
            raise ck.fail(f"{where}.old_path is only allowed for renamed targets")
        claim(rel, "target")
        kind = kind_of(root, rel, where)
        if change == "deleted":
            if kind is not None:
                raise _invalid(
                    f"{where}: {rel} is declared deleted but exists", "Declare it modified, or remove it"
                )
        elif kind is None:
            raise _invalid(f"{where}: {rel} does not exist", "Check the path, or declare the target deleted")
        found.append(
            {"path": rel, "kind": kind, "change": change, "old_path": old, **snapshot(root, rel, kind)}
        )
    artifact = {
        "whole_project": whole,
        "targets": found,
        "context": [],
        "suggested": [],
        "copilot_reports": [],
    }
    for role, key in (
        ("context", "context"),
        ("Copilot report", "copilot_reports"),
        ("suggested", "suggested"),
    ):
        for index, raw in enumerate(ck.items(doc.get(key), key)):
            where = f"{key}[{index}]"
            ck.obj(raw, where, {"path", "reason"} if key == "suggested" else {"path"}, frozenset({"path"}))
            rel = normalize(raw["path"], where)
            claim(rel, role)
            kind = kind_of(root, rel, where)
            if kind is None:
                raise _invalid(f"{where}: {rel} does not exist")
            if key == "suggested":
                artifact[key].append(
                    {"path": rel, "reason": ck.text(raw.get("reason"), f"{where}.reason", required=False)}
                )
            elif key == "copilot_reports" and kind != "file":
                raise _invalid(f"{where}: {rel} is not a file")
            else:
                artifact[key].append(
                    {"path": rel, "kind": kind, "digest": snapshot(root, rel, kind)["digest"]}
                )
    return {
        "scope_id": scope_id,
        "request": ck.text(doc.get("request"), "request", required=False),
        "baseline": ck.text(doc.get("baseline"), "baseline", required=False),
        "artifact": artifact,
    }


def not_in_tree(path: str) -> bool:
    """Paths a folder digest never covers: toolkit data and Git internals (see `_tree`)."""
    return ".git" in path.split("/") or any(f"{path}/".startswith(p) for p in EXCLUDED_PREFIXES)


def owning_target(artifact: dict[str, Any], path: str) -> str | None:
    """The recorded target equal to `path`, else the deepest folder target whose digest covers it."""
    best: str | None = None
    for target in artifact["targets"]:
        rel = target["path"]
        if rel == path:
            return rel
        if not_in_tree(path):
            continue
        if target["kind"] == "dir" and (rel == "." or path.startswith(rel + "/")):
            if best is None or best == "." or len(rel) > len(best):
                best = rel
    return best


def path_role(artifact: dict[str, Any], path: str) -> str | None:
    """'target', 'context' or 'copilot_report' for a recorded path (or a path inside a recorded folder).

    A path listed explicitly as context or Copilot report keeps that role even inside a target folder.
    """
    read_only = (("context", "context"), ("copilot_reports", "copilot_report"))
    for key, role in read_only:
        if any(entry["path"] == path for entry in artifact[key]):
            return role
    for key, role in read_only:
        for entry in artifact[key]:
            if entry["kind"] == "dir" and path.startswith(entry["path"] + "/"):
                if owning_target(artifact, path) is None or len(entry["path"]) > len(
                    owning_target(artifact, path)
                ):
                    return role
    if owning_target(artifact, path) is not None:
        return "target"
    return None
