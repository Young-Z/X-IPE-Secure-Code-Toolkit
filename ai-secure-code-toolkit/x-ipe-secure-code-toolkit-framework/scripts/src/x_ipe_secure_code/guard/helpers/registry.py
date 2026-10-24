"""002-F-owned toolkit state: the Maintainer image registration, conformance records and their integrity
key (design §2.5–§2.7, §12.3). Records carry an HMAC-SHA256 over their canonical JSON; a missing key, an
edited record or one not written with the key counts as absent. Honest limit: a local actor who can read
the key file can forge records. 002-B/002-D tool registration files are never touched (AC-002F-08f).
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

from ... import __version__
from ...adapters import safe_io
from ...atomic import atomic_write_bytes, dumps_json, write_private_new
from ...knowledge import store
from .model import (
    CONFORMANCE_REL,
    HELPERS_REL,
    IMAGE_REL,
    KEY_REL,
    SCHEMA_CONFORMANCE,
    SCHEMA_IMAGE,
    canonical,
)

MAX_RECORD = 1024 * 1024
# DAO-005 (DEC-I4): public OpenPGP key fingerprints the official images publish are not credentials.
FINGERPRINT_KEYS = frozenset({"GPG_KEY", "GPG_KEYS"})
FINGERPRINT_VALUE = re.compile(r"[0-9A-Fa-f]{40}( [0-9A-Fa-f]{40})*")
FINGERPRINT_LABEL = "public key fingerprint (not a secret)"


def public_fingerprint(entry: str) -> bool:
    key, sep, value = entry.partition("=")
    return bool(sep) and key in FINGERPRINT_KEYS and FINGERPRINT_VALUE.fullmatch(value) is not None


def _read_bytes(root: Path, rel: str, limit: int) -> bytes | None:
    try:
        store.ensure_safe(root, rel, expect_dir=False)
        fd = safe_io.open_nofollow(root, rel)
    except (OSError, safe_io.UnsafePath, store.StoreError):
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    return data if len(data) <= limit else None


def key(root: Path, create: bool = False) -> bytes | None:
    data = _read_bytes(root, KEY_REL, 64)
    if data is not None and len(data) == 32:
        return data
    if not create or data is not None:
        return None
    store.ensure_safe(root, HELPERS_REL, expect_dir=True)
    (root / HELPERS_REL).mkdir(parents=True, exist_ok=True, mode=0o700)
    fresh = secrets.token_bytes(32)
    write_private_new(root / KEY_REL, fresh)
    return fresh


def mac(secret: bytes, doc: dict[str, Any]) -> str:
    body = {k: v for k, v in doc.items() if k != "mac"}
    return "hmac-sha256:" + hmac.new(secret, canonical(body), "sha256").hexdigest()


def _verified(root: Path, rel: str, schema: str) -> dict[str, Any] | None:
    secret = key(root)
    raw = _read_bytes(root, rel, MAX_RECORD)
    if secret is None or raw is None:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("schema") != schema or not isinstance(doc.get("mac"), str):
        return None
    return doc if hmac.compare_digest(doc["mac"], mac(secret, doc)) else None


def _write(root: Path, rel: str, doc: dict[str, Any]) -> dict[str, Any]:
    secret = key(root, create=True)
    if secret is None:
        raise OSError("the helper integrity key is not usable")
    doc = {**doc, "mac": None}
    doc["mac"] = mac(secret, doc)
    store.ensure_safe(root, rel, expect_dir=False)
    atomic_write_bytes(root / rel, dumps_json(doc), private=True)
    return doc


def image(root: Path) -> dict[str, Any] | None:
    """The verified image registration, or None (absent, edited or without key)."""
    return _verified(root, IMAGE_REL, SCHEMA_IMAGE)


def write_image(root: Path, doc: dict[str, Any]) -> dict[str, Any]:
    return _write(root, IMAGE_REL, {"schema": SCHEMA_IMAGE, **doc})


def conformance_id(identity: dict[str, Any], image_id: str) -> str:
    from .model import sha

    digest = sha(canonical({"identity": identity, "image": image_id, "toolkit_version": __version__}))
    return "cf-" + digest.split(":", 1)[1][:16]


def write_conformance(root: Path, doc: dict[str, Any]) -> dict[str, Any]:
    rel = f"{CONFORMANCE_REL}/{doc['id']}.json"
    store.ensure_safe(root, CONFORMANCE_REL, expect_dir=True)
    (root / CONFORMANCE_REL).mkdir(parents=True, exist_ok=True, mode=0o700)
    return _write(root, rel, {"schema": SCHEMA_CONFORMANCE, **doc})


def conformance(root: Path, identity: dict[str, Any], image_id: str) -> dict[str, Any] | None:
    """A valid passing conformance record for exactly this runtime identity, image and toolkit version."""
    cid = conformance_id(identity, image_id)
    doc = _verified(root, f"{CONFORMANCE_REL}/{cid}.json", SCHEMA_CONFORMANCE)
    if doc is None or doc.get("id") != cid or doc.get("passed") is not True:
        return None
    if (
        doc.get("identity") != identity
        or doc.get("image") != image_id
        or doc.get("toolkit_version") != __version__
    ):
        return None
    if not doc.get("probes") or not all(p.get("pass") is True for p in doc["probes"]):
        return None
    return doc


# --------------------------------------------------------------------------- tools register-helper-image
INTERPRETERS = ("/usr/local/bin/python3", "/usr/bin/python3")


def _version_probe(rt: Any, root: Path, image_id: str, env: list[str]) -> tuple[dict[str, Any], str]:
    from . import execute_io
    from .canonical import ConfigMismatch
    from .runtime import RuntimeGap

    stage = root / HELPERS_REL / f"stage-{secrets.token_hex(6)}"
    try:
        folder = execute_io.stage_helper(stage / "helper", None)
        for k, interpreter in enumerate(INTERPRETERS, 1):
            run = execute_io.RunSpec(
                purpose="version",
                name=f"xsc-reg-{secrets.token_hex(4)}-version-{k}",
                verification="registration",
                image=image_id,
                interpreter=interpreter,
                image_env=env,
                limit=30,
                stage_helper=folder,
                with_results=False,
            )
            out = execute_io.run_container(rt, run, lambda: False, lambda names, volume: None)
            if out.mismatch:
                raise ConfigMismatch(out.mismatch)
            if out.infrastructure:
                raise RuntimeGap("HELPER_RUNTIME_UNAVAILABLE", out.infrastructure)
            if out.exit != 0:
                continue
            try:
                answer = json.loads(out.raw_stdout.decode("utf-8").strip().splitlines()[0])
            except (UnicodeError, ValueError, IndexError):
                answer = None
            return (answer if isinstance(answer, dict) else {}), interpreter
        return {}, ""
    finally:
        from .snapshot import unseal_remove

        unseal_remove(stage)


def register_image(project: str | None, ref: str, trust_paths: Any = None) -> Any:
    """Maintainer registration of a locally present helper image (AC-002F-11a; never pulls or builds)."""
    from ...auth.service import require_maintainer
    from ...guard.mask import mask_text
    from ...guard.model import utc_now
    from ...projects import knowledge_root
    from ...results import Result
    from . import execute_io
    from .canonical import ConfigMismatch
    from .model import L12_HIGH, L12_LOW, MAINTAINER_STEP
    from .runtime import CliRuntime, RuntimeGap

    command = "tools register-helper-image"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    decision = require_maintainer("tools.register_helper_image", paths=trust_paths)
    if not decision.allowed:
        refused = decision.to_result()
        refused.command = command
        return refused
    try:
        rt = CliRuntime.discover()
        execute_io.sweep(rt)
        identity = rt.identity()
        doc = rt.image(ref)
        if doc is None:
            return Result.refused(
                command,
                "HELPER_IMAGE_UNAVAILABLE",
                f"image {ref} is not present locally; the toolkit never pulls or builds — obtaining an image "
                "needs a separate human decision",
                MAINTAINER_STEP,
            )
        image_id = str(doc.get("Id") or "")
        image_id = image_id if image_id.startswith("sha256:") else f"sha256:{image_id}"
        config = doc.get("Config") or {}
        if config.get("Volumes"):
            return Result.refused(
                command, "HELPER_IMAGE_UNSUPPORTED", "image declares VOLUME", MAINTAINER_STEP
            )
        env = [str(e) for e in config.get("Env") or []]
        flagged = sorted({e.split("=", 1)[0] for e in env if mask_text(e)[1] and not public_fingerprint(e)})
        if flagged:
            return Result.refused(
                command,
                "HELPER_IMAGE_UNSUPPORTED",
                f"image environment contains credential-like values: {', '.join(flagged)}",
                MAINTAINER_STEP,
            )
        answer, interpreter = _version_probe(rt, root, image_id, env)
    except ConfigMismatch as exc:
        return Result.refused(
            command, "HELPER_CONFIG_MISMATCH", f"configuration mismatch: {exc.invariant}", MAINTAINER_STEP
        )
    except RuntimeGap as exc:
        return Result.refused(command, exc.code, exc.reason, MAINTAINER_STEP)
    version = answer.get("version")
    if (
        not isinstance(version, list)
        or len(version) != 3
        or not all(isinstance(v, int) and not isinstance(v, bool) for v in version)
        or answer.get("implementation") != "cpython"
        or answer.get("executable") != interpreter
        or not (L12_LOW <= tuple(version) and tuple(version[:2]) <= L12_HIGH)
    ):
        return Result.refused(
            command,
            "HELPER_IMAGE_UNSUPPORTED",
            "image interpreter is not CPython 3.10.0–3.13.x "
            f"(reported {mask_text(json.dumps(answer))[0][:200]})",
            MAINTAINER_STEP,
        )
    record = write_image(
        root,
        {
            "image": image_id,
            "repo_digests": [str(d) for d in doc.get("RepoDigests") or []],
            "cpython": ".".join(map(str, version)),
            "interpreter": interpreter,
            "env": env,
            "config": {
                "user": config.get("User") or "",
                "entrypoint": config.get("Entrypoint"),
                "volumes": config.get("Volumes"),
                "labels": config.get("Labels") or {},
            },
            "registered_at": utc_now(),
            "registered_by": {"role": "maintainer"},
            "toolkit_version": __version__,
            "runtime": {"kind": identity["kind"], "server_version": identity["server_version"]},
        },
    )
    data = {
        "image": image_id,
        "repo_digests": record["repo_digests"],
        "cpython": record["cpython"],
        "interpreter": interpreter,
        "env_keys": [e.split("=", 1)[0] for e in env],
        "env": env,
        "env_labels": {e.split("=", 1)[0]: FINGERPRINT_LABEL for e in env if public_fingerprint(e)},
        "runtime": record["runtime"],
    }
    return Result(command, True, data, [], ["Run secure-code tools helper-conformance"])
