"""Owner authorization: initialize, re-authorize after revocation, revoke, require.

Every change after first initialization commits by atomically replacing the signed
trust state; grants are written first under their own id, so an interruption leaves
the previous state fully valid. First initialization commits by renaming a complete
staging folder onto the absent trust folder.
"""

from __future__ import annotations

import getpass
import os
import platform
import secrets
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..atomic import ExclusiveLock, LockHeld, atomic_write_bytes, dumps_json, write_private_new
from ..results import Result
from . import keys
from .crypto import key_id, public_pem
from .interaction import Interaction, TerminalInteraction
from .records import GRANT_SCHEMA, STATE_SCHEMA, b64, canonical
from .trust_store import TrustPaths, resolve
from .verify import NEXT_RECOVERY, AuthStatus, TrustSnapshot, inspect_trust, verify

MIN_PASSPHRASE = 12
HONEST_LIMIT = ("Local workflow-level protection: it does not resist someone with write access "
                "to this account replacing the trust configuration.")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _person() -> dict[str, str]:
    if os.name == "nt":  # pragma: no cover - Windows only
        user = getpass.getuser()
    else:
        import pwd

        user = pwd.getpwuid(os.getuid()).pw_name
    return {"os_user": user, "host": platform.node()}


def _signed(private_key: Any, kind: str, record: dict[str, Any]) -> dict[str, Any]:
    body = {k: v for k, v in record.items() if k != "signature"}
    return {**body, "signature": b64(keys.sign(private_key, canonical(kind, body)))}


def _grant(private_key: Any, kid: str, generation: int, now: str) -> dict[str, Any]:
    return _signed(private_key, "maintainer-grant", {
        "schema": GRANT_SCHEMA, "grant_id": uuid.uuid4().hex, "key_id": kid,
        "generation": generation, "qualification": "maintainer", "issued_at": now,
        "issued_to": _person(),
    })


def _commit_state(paths: TrustPaths, state: dict[str, Any]) -> None:
    atomic_write_bytes(paths.state, dumps_json(state), private=True)


def _cleanup(paths: TrustPaths, keep_grant: str | None) -> None:
    for leftover in paths.app_dir.glob("trust.staging-*"):
        shutil.rmtree(leftover, ignore_errors=True)
    if keep_grant and paths.grants_dir.is_dir():
        for grant_file in paths.grants_dir.glob("*.json"):
            if grant_file.stem != keep_grant:
                grant_file.unlink(missing_ok=True)


def _locked(command: str, paths: TrustPaths, interaction: Interaction, body) -> Result:
    if not interaction.is_interactive():
        return Result.refused(command, "NOT_INTERACTIVE",
                              "This command needs an interactive terminal operated by the owner",
                              "Run it yourself in a terminal; agents and pipes are refused")
    try:
        paths.app_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with ExclusiveLock(paths.lock):
            return body()
    except LockHeld as held:
        return Result.refused(command, "LOCKED", f"Another authorization command holds "
                              f"{held.path} ({held.info})",
                              "Wait for it to finish; remove a stale lock file manually")
    except OSError as exc:
        return Result.refused(command, "IO_ERROR", f"File operation failed: {exc.strerror or exc}")


def _ask(interaction: Interaction, prompt: str, command: str) -> str | Result:
    answer = interaction.prompt_secret(prompt)
    if answer is None:
        return Result.refused(command, "ABORTED", "Cancelled by the owner")
    return answer


def initialize_authorization(paths: TrustPaths | None = None,
                             interaction: Interaction | None = None) -> Result:
    command = "auth init"
    paths = paths or resolve()
    interaction = interaction or TerminalInteraction()

    def body() -> Result:
        snap = inspect_trust(paths)
        _cleanup(paths, snap.state["current_grant_id"] if snap.state else None)
        if snap.kind == "active":
            return Result.refused(command, "ALREADY_INITIALIZED",
                                  "A valid Maintainer authorization already exists",
                                  "Check with 'secure-code auth status'; run 'secure-code auth "
                                  "revoke' first if you want to re-authorize")
        if snap.kind == "partial":
            return Result.refused(command, "TRUST_PARTIAL", snap.reason, NEXT_RECOVERY)
        if snap.kind == "revoked":
            return _reauthorize(command, paths, interaction, snap)
        return _first_init(command, paths, interaction)

    return _locked(command, paths, interaction, body)


def _first_init(command: str, paths: TrustPaths, interaction: Interaction) -> Result:
    first = _ask(interaction, f"Enter new passphrase (min {MIN_PASSPHRASE} characters): ",
                 command)
    if isinstance(first, Result):
        return first
    if len(first) < MIN_PASSPHRASE:
        return Result.refused(command, "PASSPHRASE_TOO_SHORT",
                              f"Use at least {MIN_PASSPHRASE} characters")
    second = _ask(interaction, "Confirm passphrase: ", command)
    if isinstance(second, Result):
        return second
    if first != second:
        return Result.refused(command, "PASSPHRASE_MISMATCH", "The two entries differ")

    private_key = keys.generate()
    public_key = private_key.public_key()
    kid = key_id(public_key)
    now = _now()
    grant = _grant(private_key, kid, 1, now)
    state = _signed(private_key, "trust-state", {
        "schema": STATE_SCHEMA, "key_id": kid, "generation": 1, "status": "active",
        "current_grant_id": grant["grant_id"], "created_at": now, "created_by": _person(),
        "updated_at": now,
    })
    staging = paths.app_dir / f"trust.staging-{secrets.token_hex(8)}"
    try:
        staging.mkdir(mode=0o700)
        (staging / "grants").mkdir(mode=0o700)
        write_private_new(staging / paths.public_key.name, public_pem(public_key))
        write_private_new(staging / paths.signing_key.name, keys.encrypt(private_key, first))
        write_private_new(staging / "grants" / f"{grant['grant_id']}.json", dumps_json(grant))
        write_private_new(staging / paths.state.name, dumps_json(state))
        os.rename(staging, paths.trust_dir)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return Result(command, True, {
        "outcome": "initialized", "role": "maintainer", "trust_dir": str(paths.trust_dir),
        "created_at": now, "created_by": state["created_by"], "limit": HONEST_LIMIT,
    })


def _unlock(command: str, paths: TrustPaths, interaction: Interaction,
            snap: TrustSnapshot) -> Any:
    answer = _ask(interaction, "Enter existing passphrase: ", command)
    if isinstance(answer, Result):
        return answer
    try:
        private_key = keys.decrypt(paths.signing_key.read_bytes(), answer)
    except keys.WrongPassphrase:
        return Result.refused(command, "PASSPHRASE_WRONG",
                              "The passphrase does not unlock the signing key; nothing changed")
    if key_id(private_key.public_key()) != snap.state["key_id"]:
        return Result.refused(command, "TRUST_PARTIAL",
                              "Signing key does not match the trusted public key", NEXT_RECOVERY)
    return private_key


def _reauthorize(command: str, paths: TrustPaths, interaction: Interaction,
                 snap: TrustSnapshot) -> Result:
    private_key = _unlock(command, paths, interaction, snap)
    if isinstance(private_key, Result):
        return private_key
    now = _now()
    generation = snap.state["generation"] + 1
    grant = _grant(private_key, snap.state["key_id"], generation, now)
    atomic_write_bytes(paths.grant(grant["grant_id"]), dumps_json(grant), private=True)
    state = _signed(private_key, "trust-state", {
        **snap.state, "generation": generation, "status": "active",
        "current_grant_id": grant["grant_id"], "updated_at": now,
    })
    _commit_state(paths, state)
    _cleanup(paths, grant["grant_id"])
    return Result(command, True, {"outcome": "reauthorized", "role": "maintainer",
                                  "generation": generation, "limit": HONEST_LIMIT})


def revoke_authorization(paths: TrustPaths | None = None,
                         interaction: Interaction | None = None) -> Result:
    command = "auth revoke"
    paths = paths or resolve()
    interaction = interaction or TerminalInteraction()

    def body() -> Result:
        snap = inspect_trust(paths)
        if snap.kind == "pristine":
            return Result(command, True, {"outcome": "nothing_authorized"})
        if snap.kind == "revoked":
            return Result(command, True, {"outcome": "already_revoked"})
        if snap.kind == "partial":
            return Result.refused(command, "TRUST_PARTIAL", snap.reason, NEXT_RECOVERY)
        private_key = _unlock(command, paths, interaction, snap)
        if isinstance(private_key, Result):
            return private_key
        state = _signed(private_key, "trust-state", {
            **snap.state, "generation": snap.state["generation"] + 1, "status": "revoked",
            "updated_at": _now(),
        })
        _commit_state(paths, state)
        return Result(command, True, {"outcome": "revoked", "role": "user"})

    return _locked(command, paths, interaction, body)


def auth_status(paths: TrustPaths | None = None) -> Result:
    status = verify(paths or resolve())
    return Result("auth status", True, {**status.to_dict(), "limit": HONEST_LIMIT},
                  next_steps=[status.next_step] if status.role != "maintainer" else [])


@dataclass(frozen=True)
class Decision:
    action: str
    allowed: bool
    status: AuthStatus

    def to_result(self) -> Result:
        data = {"action": self.action, "role": self.status.role, "state": self.status.state,
                "qualification": "maintainer" if self.allowed else None}
        if self.allowed:
            return Result("require maintainer", True, data)
        return Result.refused("require maintainer", "NOT_AUTHORIZED",
                              f"Maintainer qualification required: {self.status.reason}",
                              self.status.next_step, data)


def require_maintainer(action: str, paths: TrustPaths | None = None) -> Decision:
    """Qualification check only; scope, network, budget and autonomy are separate."""
    status = verify(paths or resolve())
    return Decision(action=action, allowed=status.role == "maintainer", status=status)
