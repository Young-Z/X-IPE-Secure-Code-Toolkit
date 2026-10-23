"""Internal drafting authorization of a host environment (FEATURE-001-G, FR-001G-9, DEC-2, DEC-6).

`knowledge drafting-authorize --host LABEL [--revoke]` records (or revokes) that the Maintainer
authorized the self-reported host label to process internal (`@`) rule content for AI drafting.
Recording needs the Maintainer qualification and an interactive terminal with the typed label; the
record is a per-project private file outside formal knowledge, created on first use only (never by
`init`). `--list` is read-only. Honest limits: labels are self-reported, a terminal is not proof of
a human, and the record has no integrity protection.
"""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..atomic import LockHeld, dumps_json
from ..auth.interaction import TerminalInteraction
from ..auth.service import require_maintainer
from ..auth.trust_store import TrustPaths
from ..projects import knowledge_root
from ..results import Result
from . import durable, exit_journal, store
from .drafting_model import HOST_LABEL, UTC_TIME, read_nofollow

COMMAND = "knowledge drafting-authorize"
SCHEMA = "ai-secure-code-toolkit/drafting-authorizations/v1"
PRIVATE_REL = store.PRIVATE_REL
NAME = "drafting-authorizations.json"
AUTH_REL = f"{PRIVATE_REL}/{NAME}"
ENTRY_KEYS = frozenset({"host", "classification", "state", "authorized_at", "maintainer_check", "revoked_at"})
INVALID_STEP = "The Maintainer inspects or restores .x-ipe/private/secure-code/drafting-authorizations.json"
RECOVERY_STEP = (
    "Run `secure-code knowledge list --project <path>`, which completes the interrupted "
    "operation, then repeat the command"
)
TTY_STEP = "Only the Maintainer at an interactive terminal can authorize a host environment; agents cannot"


class RecordInvalid(Exception):
    """The authorization record exists but does not have the v1 shape (fails closed)."""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or set(data) != {"schema", "authorizations"} or data["schema"] != SCHEMA:
        raise RecordInvalid("record must be {schema, authorizations} with schema " + SCHEMA)
    entries = data["authorizations"]
    if not isinstance(entries, list):
        raise RecordInvalid("authorizations must be a list")
    active: set[str] = set()
    for entry in entries:
        ok = (
            isinstance(entry, dict)
            and set(entry) == ENTRY_KEYS
            and isinstance(entry["host"], str)
            and HOST_LABEL.fullmatch(entry["host"])
            and entry["classification"] == "internal"
            and entry["maintainer_check"] == "maintainer"
            and isinstance(entry["authorized_at"], str)
            and UTC_TIME.fullmatch(entry["authorized_at"])
            and (
                (entry["state"] == "active" and entry["revoked_at"] is None)
                or (
                    entry["state"] == "revoked"
                    and isinstance(entry["revoked_at"], str)
                    and UTC_TIME.fullmatch(entry["revoked_at"])
                )
            )
        )
        if not ok:
            raise RecordInvalid("an authorization entry is malformed")
        if entry["state"] == "active":
            if entry["host"] in active:
                raise RecordInvalid(f"more than one active entry for {entry['host']}")
            active.add(entry["host"])
    return entries


def _read(tree: durable.Tree) -> list[dict[str, Any]]:
    fd = tree.opt_dir(PRIVATE_REL)
    if fd is None:
        return []
    try:
        found = durable.entry(fd, NAME)
        if found is None:
            return []
        if not stat.S_ISREG(found.st_mode):
            raise RecordInvalid(f"{AUTH_REL} is not a regular file")
        data = read_nofollow(fd, NAME, 1024 * 1024)
    finally:
        durable.close(fd)
    if data is None:
        raise RecordInvalid(f"{AUTH_REL} is too large")
    try:
        return _validate(json.loads(data.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecordInvalid(f"{AUTH_REL} is not readable JSON ({type(exc).__name__})") from None


def read_record(root: Path) -> list[dict[str, Any]]:
    with durable.Tree(root) as tree:
        return _read(tree)


def is_authorized(root: Path, host: str) -> tuple[bool, str | None]:
    """Gate lookup: an active internal authorization for `host`; malformed records fail closed."""
    try:
        entries = read_record(root)
    except (RecordInvalid, durable.StoreError, OSError):
        return False, "AUTHORIZATION_RECORD_INVALID"
    return any(e["host"] == host and e["state"] == "active" for e in entries), None


def run(
    project: str | None, list_: bool, host: str | None, revoke: bool, *, trust_paths: TrustPaths | None = None
) -> Result:
    """CLI dispatch: exactly one of `--list [--host]` or `--host [--revoke]`."""
    if list_ and not revoke:
        return list_authorizations(project, host)
    if list_ or host is None:
        return Result.refused(
            COMMAND,
            "ARGUMENT_INVALID",
            "Use --list [--host LABEL] or --host LABEL [--revoke]",
            "Agents only ever run the read-only --list form",
        )
    return authorize(project, host, revoke, trust_paths=trust_paths)


def list_authorizations(project: str | None, host: str | None) -> Result:
    root = knowledge_root(project, COMMAND)
    if isinstance(root, Result):
        return root
    try:
        with durable.Tree(root) as tree:
            if exit_journal.has_pending(tree):
                return Result.refused(
                    COMMAND,
                    "RECOVERY_PENDING",
                    "An interrupted knowledge exit is pending; read-only drafting commands "
                    "do not complete it",
                    RECOVERY_STEP,
                )
            entries = _read(tree)
    except RecordInvalid as exc:
        return Result.refused(COMMAND, "AUTHORIZATION_RECORD_INVALID", str(exc), INVALID_STEP)
    except durable.StoreError as exc:
        return Result.refused(COMMAND, exc.code, exc.message, exc.next_step)
    except OSError as exc:
        return Result.refused(COMMAND, "IO_ERROR", str(exc.strerror or exc))
    if host is not None:
        entries = [e for e in entries if e["host"] == host]
    data: dict[str, Any] = {"authorizations": entries}
    if host is not None:
        data["host"] = host
        data["status"] = "authorized" if any(e["state"] == "active" for e in entries) else "not_authorized"
    return Result(COMMAND, True, data)


def authorize(
    project: str | None,
    host: str,
    revoke: bool,
    *,
    interaction: Any = None,
    trust_paths: TrustPaths | None = None,
) -> Result:
    root = knowledge_root(project, COMMAND)
    if isinstance(root, Result):
        return root
    try:
        recovered = exit_journal.ensure_recovered(root)
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.refusal(COMMAND, exc)
    result = _authorize(root, host, revoke, interaction or TerminalInteraction(), trust_paths)
    return exit_journal.with_recovered(result, recovered)


def _authorize(
    root: Path, host: str, revoke: bool, interaction: Any, trust_paths: TrustPaths | None
) -> Result:
    if not interaction.is_interactive():
        return Result.refused(
            COMMAND,
            "INTERACTIVE_REQUIRED",
            "Recording or revoking a drafting authorization needs an interactive terminal",
            TTY_STEP,
        )
    decision = require_maintainer("knowledge.drafting-authorize", paths=trust_paths)
    if not decision.allowed:
        denied = decision.to_result()
        denied.command = COMMAND
        return denied
    if not (isinstance(host, str) and HOST_LABEL.fullmatch(host)):
        return Result.refused(
            COMMAND, "HOST_LABEL_INVALID", "Host labels match [a-z0-9][a-z0-9._-]{0,63}", TTY_STEP
        )
    verb = "Revoke the authorization of" if revoke else "Authorize"
    typed = interaction.prompt_text(
        f"{verb} host environment '{host}' to process internal (@) rule content for AI drafting? "
        "Type the host label to confirm: "
    )
    if typed is None or typed.strip() != host:
        return Result.refused(
            COMMAND, "CONFIRMATION_MISMATCH", "The typed label does not match; nothing recorded", TTY_STEP
        )
    try:
        with store.lock(root, write=True), durable.Tree(root) as tree:
            entries = _read(tree)
            outcome = _change(entries, host, revoke)
            if outcome != "unchanged":
                fd = tree.dir(PRIVATE_REL)
                try:
                    durable.write(
                        fd,
                        NAME,
                        dumps_json({"schema": SCHEMA, "authorizations": entries}),
                        f".{NAME}.tmp",
                        mode=0o600,
                    )
                finally:
                    durable.close(fd)
    except RecordInvalid as exc:
        return Result.refused(COMMAND, "AUTHORIZATION_RECORD_INVALID", str(exc), INVALID_STEP)
    except LockHeld as exc:
        return Result.refused(COMMAND, "LOCKED", str(exc), exit_journal.RETRY_STEP)
    except durable.StoreError as exc:
        return Result.refused(COMMAND, exc.code, exc.message, exc.next_step)
    except OSError as exc:
        return Result.refused(COMMAND, "IO_ERROR", str(exc.strerror or exc))
    return Result(
        COMMAND,
        True,
        {
            "host": host,
            "classification": "internal",
            "outcome": outcome,
            "authorizations": [e for e in entries if e["host"] == host],
        },
    )


def _change(entries: list[dict[str, Any]], host: str, revoke: bool) -> str:
    active = next((e for e in entries if e["host"] == host and e["state"] == "active"), None)
    if revoke:
        if active is None:
            return "unchanged"
        active.update(state="revoked", revoked_at=_now())
        return "revoked"
    if active is not None:
        return "unchanged"
    entries.append(
        {
            "host": host,
            "classification": "internal",
            "state": "active",
            "authorized_at": _now(),
            "maintainer_check": "maintainer",
            "revoked_at": None,
        }
    )
    return "recorded"
