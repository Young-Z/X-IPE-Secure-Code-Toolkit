"""Explicit project-root validation: no parent-directory search, ever."""

from __future__ import annotations

import os
from pathlib import Path


class RootError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def validate_root(raw: str | None) -> Path:
    if raw is None or not str(raw).strip():
        raise RootError("ROOT_REQUIRED", "An explicit project root is required (--project PATH)")
    path = Path(os.path.realpath(os.path.expanduser(str(raw))))
    if not path.exists():
        raise RootError("ROOT_INVALID", f"Project root does not exist: {path}")
    if not path.is_dir():
        raise RootError("ROOT_INVALID", f"Project root is not a directory: {path}")
    return path


def safe_relative(raw: str) -> str:
    """Normalize a project-relative path given by the user (e.g. --replace)."""
    text = raw.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts or ".." in parts or text.startswith("/") or (len(text) > 1 and text[1] == ":"):
        raise RootError("PATH_INVALID", f"Not a project-relative path: {raw}")
    return "/".join(parts)


def unsafe_component(root: Path, rel: str, *, expect_dir: bool) -> str | None:
    """Return why writing `rel` under `root` would be unsafe, or None.

    Every existing component must be a real directory (no symbolic links), and an existing
    final component must have the expected kind. Missing components are created later.
    """
    current = root
    parts = rel.split("/")
    for index, part in enumerate(parts):
        current = current / part
        last = index == len(parts) - 1
        if current.is_symlink():
            return f"{current.relative_to(root).as_posix()} is a symbolic link"
        if not current.exists():
            return None
        if not last and not current.is_dir():
            return f"{current.relative_to(root).as_posix()} is not a folder"
        if last and expect_dir != current.is_dir():
            kind = "folder" if expect_dir else "file"
            return f"{current.relative_to(root).as_posix()} is not a {kind}"
    return None
