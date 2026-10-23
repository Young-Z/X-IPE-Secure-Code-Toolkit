"""Locate the three pre-generated skills and enumerate the files to place in a project."""

from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlparse

SKILL_NAMES = (
    "x-ipe-secure-code-toolkit-framework",
    "x-ipe-secure-code-toolkit-copilot",
    "x-ipe-secure-code-toolkit-guard",
)
EXCLUDED_DIRS = frozenset({".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "dist",
                           "build", ".git"})
EXCLUDED_FILES = frozenset({".coverage", ".DS_Store"})
EXCLUDED_REL_DIRS = frozenset({"scripts/tests"})


class PayloadError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


DISTRIBUTION = "ai-secure-code-toolkit"


def _installed_origin() -> Path | None:
    """Source folder recorded by the installer (PEP 610 direct_url.json), e.g. under uvx."""
    try:
        raw = importlib.metadata.distribution(DISTRIBUTION).read_text("direct_url.json")
    except importlib.metadata.PackageNotFoundError:
        return None
    if not raw:
        return None
    try:
        url = json.loads(raw).get("url", "")
    except (ValueError, AttributeError):
        return None
    parsed = urlparse(url)
    if parsed.scheme != "file":
        return None
    path = unquote(parsed.path)
    if os.name == "nt":  # pragma: no cover - Windows only
        if len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        if parsed.netloc:
            path = f"//{parsed.netloc}{path}"
    return Path(path)


def framework_dir() -> Path:
    """The Framework skill folder this code was launched from.

    Running from source: <skill>/scripts/src/x_ipe_secure_code/payload.py → <skill>.
    Running via uvx/uv tool (code copied into uv's cache): the recorded source
    <skill>/scripts → <skill>.
    """
    here = Path(__file__).resolve().parents[3]
    if (here / "SKILL.md").is_file():
        return here
    origin = _installed_origin()
    if origin is not None and (origin.parent / "SKILL.md").is_file():
        return origin.parent
    return here


def locate(source: str | Path | None = None) -> Path:
    root = Path(os.path.realpath(source)) if source else framework_dir().parent
    missing = [name for name in SKILL_NAMES if not (root / name / "SKILL.md").is_file()]
    if missing:
        raise PayloadError("PAYLOAD_INCOMPLETE",
                           f"Toolkit source {root} lacks skills: {', '.join(missing)}")
    return root


def files(root: Path) -> dict[str, Path]:
    """Return {'<skill>/<relative posix path>': absolute source path}."""
    result: dict[str, Path] = {}
    for name in SKILL_NAMES:
        base = root / name
        for current, dirs, names in os.walk(base, followlinks=False):
            current_path = Path(current)
            rel_dir = current_path.relative_to(base).as_posix()
            kept = []
            for directory in sorted(dirs):
                rel = directory if rel_dir == "." else f"{rel_dir}/{directory}"
                if (directory in EXCLUDED_DIRS or directory.endswith(".egg-info")
                        or rel in EXCLUDED_REL_DIRS):
                    continue
                if (current_path / directory).is_symlink():
                    raise PayloadError("PAYLOAD_SYMLINK", f"Symlink in toolkit source: {name}/{rel}")
                kept.append(directory)
            dirs[:] = kept
            for filename in sorted(names):
                if (filename in EXCLUDED_FILES or filename.endswith(".pyc")
                        or filename.startswith(".coverage.")):
                    continue
                path = current_path / filename
                rel = filename if rel_dir == "." else f"{rel_dir}/{filename}"
                if path.is_symlink():
                    raise PayloadError("PAYLOAD_SYMLINK", f"Symlink in toolkit source: {name}/{rel}")
                result[f"{name}/{rel}"] = path
    return dict(sorted(result.items()))
