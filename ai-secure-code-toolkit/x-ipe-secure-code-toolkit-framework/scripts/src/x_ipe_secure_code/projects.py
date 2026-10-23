"""Shared project-root checks for commands that read or write secure-code data."""

from __future__ import annotations

from pathlib import Path

from .knowledge import store
from .paths import RootError, validate_root
from .results import Result


def knowledge_root(project: str | None, command: str) -> Path | Result:
    """Validate the project root and its initialized knowledge layout.

    Returns the root path, or a refused Result with one next step.
    """
    try:
        root = validate_root(project)
    except RootError as exc:
        return Result.refused(command, exc.code, exc.message, "Pass an existing project with --project")
    if not store.local_root(root).is_dir():
        return Result.refused(
            command,
            "PROJECT_NOT_INITIALIZED",
            f"{store.LOCAL_REL} does not exist in {root}",
            f"secure-code init --project {root} --env <environment>",
        )
    try:
        store.ensure_safe(root, store.LOCAL_REL, expect_dir=True)
        store.ensure_safe(root, store.PRIVATE_REL, expect_dir=True)
    except store.StoreError as exc:
        return Result.refused(command, exc.code, exc.message, "Replace the symbolic link with a real folder")
    return root
