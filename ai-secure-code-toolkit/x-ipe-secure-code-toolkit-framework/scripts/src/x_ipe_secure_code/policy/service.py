"""`policy resolve`, `scope save` and `scope show` commands (FEATURE-001-C).

None of these commands needs or checks Maintainer authorization, and none writes knowledge.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..atomic import LockHeld, atomic_write_bytes, dumps_json
from ..knowledge import exit_journal, store
from ..projects import knowledge_root
from ..results import Problem, Result
from . import resolve, scope
from .refs import is_utf8

OUTPUT_SCHEMA = "ai-secure-code-toolkit/policy-output/v1"
RETRY = "Retry when the other operation finished"


def _session_refusal(command: str, exc: BaseException) -> Result:
    if isinstance(exc, LockHeld):
        return Result.refused(command, "LOCKED", str(exc), RETRY)
    if isinstance(exc, store.StoreError):
        return Result.refused(
            command, exc.code, exc.message, exc.next_step or "Replace the symbolic link with a real file"
        )
    if isinstance(exc, OSError):
        return Result.refused(
            command,
            "IO_ERROR",
            f"Knowledge could not be locked or read: {exc}",
            "Check that the project's .x-ipe/private folder is writable and readable",
        )
    raise exc


def _snapshot(root: Path, command: str) -> tuple[resolve.Library, dict[str, Any] | None] | Result:
    """Recover a pending exit, then take the library snapshot under the knowledge lock
    (creating only the lock file); returns (library, recovered exit or None)."""
    try:
        with exit_journal.session(root, write=True) as session:
            return resolve.snapshot(session.tree), session.recovered
    except (LockHeld, store.StoreError, OSError) as exc:
        return _session_refusal(command, exc)


def _strip_requirements(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_requirements(v) for k, v in value.items() if k != "requirement"}
    if isinstance(value, list):
        return [_strip_requirements(v) for v in value]
    return value


def _finish(command: str, data: dict[str, Any], steps: list[str], output: str | None) -> Result:
    if output:
        path = Path(output)
        if path.is_symlink() or path.is_dir():
            return Result.refused(
                command,
                "PATH_UNSAFE",
                f"{output} is a symbolic link or folder",
                "Choose a new file path for --output",
            )
        if not path.parent.is_dir():
            return Result.refused(
                command,
                "REQUEST_INVALID",
                f"Folder of {output} does not exist",
                "Choose an output file in an existing folder",
            )
        try:
            atomic_write_bytes(path, dumps_json({"schema": OUTPUT_SCHEMA, "command": command, **data}))
        except OSError as exc:
            return Result.refused(command, "IO_ERROR", f"Could not write {output}: {exc}")
        data = {**_strip_requirements(copy.deepcopy(data)), "output_file": output}
    if data["status"] == resolve.MAINTENANCE_NEEDED:
        return Result(command, False, data, [Problem("MAINTENANCE_NEEDED", "No usable formal Policy")], steps)
    return Result(command, True, data, [], steps)


def resolve_policies(
    project: str | None, rules: list[str], apply_all: bool, languages: list[str], output: str | None = None
) -> Result:
    """Resolve rule references (or all formal rules) into structured Policies; read-only.

    Args:
        project: Explicit project root.
        rules: Requested references (`NS/VER/ID` or `NS/ID`); empty with `apply_all`.
        apply_all: Propose every formal Local rule (no clues, no default Preset).
        languages: Artifact languages for advisory notes (never filters).
        output: Optional file receiving the full result.

    Returns:
        Result with status complete / partial / maintenance_needed and a proposal digest.
    """
    command = "policy resolve"
    if bool(rules) == bool(apply_all):
        return Result.refused(
            command,
            "REQUEST_INVALID",
            "Pass either --rule (one or more) or --all",
            "Use --rule for clues, or --all when the user gave no clues",
        )
    if not is_utf8(languages):
        return Result.refused(
            command,
            "REQUEST_INVALID",
            "--language must be valid UTF-8 text",
            "Pass language names such as java or python",
        )
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    taken = _snapshot(root, command)
    if isinstance(taken, Result):
        return taken
    lib, recovered = taken
    data = resolve.build(
        lib, rules, apply_all, languages, default_preset_exists=(root / resolve.DEFAULT_PRESET_REL).is_file()
    )
    if recovered:
        data["recovered_exit"] = recovered
    return _finish(command, data, resolve.next_steps(data), output)


def save_scope(project: str | None, decisions_path: str, confirmed: bool) -> Result:
    """Save the user-confirmed adopted scope as a digest-identified record.

    Args:
        project: Explicit project root.
        decisions_path: Decisions file written after the user confirmed.
        confirmed: Explicit flag that the user confirmed this scope.

    Returns:
        Result with scope_id and record path, or a refusal (nothing written).
    """
    command = "scope save"
    if not confirmed:
        return Result.refused(
            command,
            "CONFIRMATION_REQUIRED",
            "The scope was not marked as confirmed",
            "Save only after the user confirmed the scope, then pass --confirmed",
        )
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    try:
        decisions = scope.load_decisions(decisions_path)
    except scope.ScopeError as exc:
        return Result.refused(command, exc.code, exc.message, exc.next_step)
    recovered: dict[str, Any] | None = None
    try:
        # Knowledge lock held across the final re-check and publication (scope lock inside).
        with exit_journal.session(root, write=True) as session:
            recovered = session.recovered
            lib = resolve.snapshot(session.tree)
            data = resolve.build(
                lib, decisions.considered or [], decisions.mode == "apply_all", decisions.language_context
            )
            store._pause_point("scope_save_locked")
            adopted, not_adopted, outside = scope.check_decisions(decisions, data, lib, session.tree)
            record = scope.build_record(
                decisions, adopted, not_adopted, datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            store._pause_point("scope_save_before_publish")
            rel, created, stored = scope.publish(root, record, session.tree)
    except scope.ScopeError as exc:
        return exit_journal.with_recovered(
            Result.refused(command, exc.code, exc.message, exc.next_step), recovered
        )
    except LockHeld as exc:
        return exit_journal.with_recovered(Result.refused(command, "LOCKED", str(exc), RETRY), recovered)
    except store.StoreError as exc:
        step = exc.next_step or "Replace the symbolic link with a real folder"
        return exit_journal.with_recovered(Result.refused(command, exc.code, exc.message, step), recovered)
    except OSError as exc:
        return exit_journal.with_recovered(
            Result.refused(command, "IO_ERROR", f"Scope record could not be written: {exc}"), recovered
        )
    data = {
        "scope_id": stored["scope_id"],
        "path": rel,
        "created": created,
        "mode": stored["mode"],
        "adopted_rules": [a["rule"] for a in stored["adopted"]],
        "not_adopted": stored["not_adopted"],
        "created_at": stored["created_at"],
    }
    if outside:
        data["outside_confirmed_scope"] = outside
    return exit_journal.with_recovered(
        Result(
            command,
            True,
            data,
            [],
            ["Give this scope_id to Guard or Copilot; they load it with: secure-code scope show --scope ID"],
        ),
        recovered,
    )


def show_scope(project: str | None, scope_id: str, output: str | None = None) -> Result:
    """Load a scope record and compare each adopted Policy with its confirmed state.

    Args:
        project: Explicit project root.
        scope_id: `sha256:<hex>` or `<hex>` from scope save.
        output: Optional file receiving the full result.

    Returns:
        Result with adopted_rules (the only list consumers count) and per-rule adoption state.
    """
    command = "scope show"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    data = load_adopted(root, scope_id, command)
    if isinstance(data, Result):
        return data
    steps = []
    if data["status"] != resolve.COMPLETE:
        steps.append("Changed or missing Policies are not adopted: resolve again and confirm a new scope")
    return _finish(command, data, steps, output)


def load_adopted(root: Path, scope_id: str, command: str) -> dict[str, Any] | Result:
    """Load a scope record and compare it with current knowledge (shared by scope show and Guard).

    Returns the load data (status, adopted_rules, entries) or a refused Result.
    """
    try:
        record = scope.read_record(root, scope_id)
    except scope.ScopeError as exc:
        return Result.refused(command, exc.code, exc.message, exc.next_step)
    except store.StoreError as exc:
        return Result.refused(command, exc.code, exc.message, "Replace the symbolic link with a real file")
    taken = _snapshot(root, command)
    if isinstance(taken, Result):
        return taken
    lib, recovered = taken
    loaded = scope.load_scope(lib, record)
    if recovered:
        loaded["recovered_exit"] = recovered
    return loaded


def adoption_now(
    root: Path, scope_id: str, adopted: list[dict[str, Any]], command: str
) -> dict[str, str] | Result:
    """Current state of each rule adopted when a Guard verification or Copilot collaboration opened.

    Args:
        root: Project root.
        scope_id: Adopted scope identifier recorded at open.
        adopted: `[{"rule", "state_digest"}]` recorded at open.
        command: Command name for refusals.

    Returns:
        `{rule: "unchanged" | "changed" | "missing"}`; `{}` when the scope record can no longer be
        loaded; a refused Result only for `LOCKED`, `IO_ERROR` (retryable) or `EXIT_JOURNAL_INVALID`.
    """
    loaded = load_adopted(root, scope_id, command)
    if isinstance(loaded, Result):
        if loaded.problems[0].code in ("LOCKED", "IO_ERROR", "EXIT_JOURNAL_INVALID"):
            return loaded
        return {}
    entries = {e["rule"]: e for e in loaded["entries"]}
    now: dict[str, str] = {}
    for a in adopted:
        e = entries.get(a["rule"])
        if e is None or e["adoption"] == "missing":
            now[a["rule"]] = "missing"
        elif e["adoption"] == "adopted" and e["confirmed_state_digest"] == a["state_digest"]:
            now[a["rule"]] = "unchanged"
        else:
            now[a["rule"]] = "changed"
    return now
