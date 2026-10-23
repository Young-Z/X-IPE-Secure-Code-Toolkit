"""Authorization verification. Reads only the trusted public key, trust state and grant.

This module must never import the signing-key helpers (enforced by tests).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyFormatError, key_id, load_public, verify_signature
from .records import RecordInvalid, canonical, check_grant, check_state, parse, unb64
from .trust_store import TrustPaths, resolve

NEXT_INIT = "Owner runs 'secure-code auth init' in an interactive terminal"
NEXT_REAUTH = "Owner runs 'secure-code auth init' interactively with the existing passphrase"
NEXT_RECOVERY = ("Trust state is incomplete or invalid; recovery is not automated in this "
                 "version - inspect the trust folder manually")


@dataclass(frozen=True)
class AuthStatus:
    role: str
    state: str
    reason: str
    next_step: str
    created_at: str | None = None
    created_by: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "state": self.state,
            "reason": self.reason,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "next_step": self.next_step,
        }


@dataclass(frozen=True)
class TrustSnapshot:
    kind: str  # pristine | active | revoked | partial
    reason: str
    public_key: Ed25519PublicKey | None = None
    state: dict[str, Any] | None = None
    grant: dict[str, Any] | None = None


class _Bad(Exception):
    pass


def _signed(pub: Ed25519PublicKey, kind: str, record: dict[str, Any]) -> bool:
    try:
        signature = unb64(record["signature"])
    except RecordInvalid:
        return False
    return verify_signature(pub, signature, canonical(kind, record))


def _load_key_and_state(paths: TrustPaths) -> tuple[Ed25519PublicKey, dict[str, Any]]:
    try:
        pub = load_public(paths.public_key.read_bytes())
    except (OSError, KeyFormatError) as exc:
        raise _Bad(f"trusted public key missing or unreadable ({exc.__class__.__name__})") from exc
    try:
        state = parse(paths.state.read_bytes())
        check_state(state)
    except (OSError, RecordInvalid) as exc:
        raise _Bad(f"trust state missing or malformed: {exc}") from exc
    if state["key_id"] != key_id(pub) or not _signed(pub, "trust-state", state):
        raise _Bad("trust state signature does not match the trusted public key")
    return pub, state


def _load_grant(paths: TrustPaths, pub: Ed25519PublicKey, grant_id: str) -> dict[str, Any]:
    try:
        grant = parse(paths.grant(grant_id).read_bytes())
        check_grant(grant)
    except (OSError, RecordInvalid) as exc:
        raise _Bad(f"authorization missing or malformed: {exc}") from exc
    if grant["key_id"] != key_id(pub) or not _signed(pub, "maintainer-grant", grant):
        raise _Bad("authorization signature does not match the trusted public key")
    return grant


def verify(paths: TrustPaths | None = None) -> AuthStatus:
    """Return the current role. Re-reads everything on every call; nothing is cached."""
    paths = paths or resolve()
    if not os.path.lexists(paths.trust_dir):
        return AuthStatus("user", "not_initialized", "no authorization on this machine",
                          NEXT_INIT)
    try:
        pub, state = _load_key_and_state(paths)
    except _Bad as exc:
        return AuthStatus("user", "invalid", str(exc), NEXT_RECOVERY)
    meta = {"created_at": state["created_at"], "created_by": state["created_by"]}
    if state["status"] == "revoked":
        return AuthStatus("user", "revoked", "authorization was revoked", NEXT_REAUTH, **meta)
    try:
        grant = _load_grant(paths, pub, state["current_grant_id"])
    except _Bad as exc:
        return AuthStatus("user", "invalid", str(exc), NEXT_RECOVERY, **meta)
    if grant["grant_id"] != state["current_grant_id"] or grant["generation"] != state["generation"]:
        return AuthStatus("user", "revoked", "authorization was superseded or revoked",
                          NEXT_REAUTH, **meta)
    return AuthStatus("maintainer", "valid", "signed Maintainer authorization is valid",
                      "None - maintenance actions still re-verify each time", **meta)


def inspect_trust(paths: TrustPaths) -> TrustSnapshot:
    """Full classification for initialization/revocation (no early exit on revoked)."""
    if not os.path.lexists(paths.trust_dir):
        return TrustSnapshot("pristine", "no trust folder")
    if not paths.signing_key.is_file():
        return TrustSnapshot("partial", "signing key missing")
    try:
        pub, state = _load_key_and_state(paths)
        grant = _load_grant(paths, pub, state["current_grant_id"])
    except _Bad as exc:
        return TrustSnapshot("partial", str(exc))
    if grant["grant_id"] != state["current_grant_id"]:
        return TrustSnapshot("partial", "current authorization does not match trust state")
    if state["status"] == "active" and grant["generation"] == state["generation"]:
        return TrustSnapshot("active", "valid", pub, state, grant)
    if state["status"] == "revoked" and grant["generation"] == state["generation"] - 1:
        return TrustSnapshot("revoked", "revoked", pub, state, grant)
    return TrustSnapshot("partial", "generation mismatch between trust state and authorization")
