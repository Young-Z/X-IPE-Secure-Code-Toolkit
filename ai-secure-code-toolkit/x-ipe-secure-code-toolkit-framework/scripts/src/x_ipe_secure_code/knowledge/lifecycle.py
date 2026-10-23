"""Exit lifecycle data: private exit paths, ids, reasons, exit memory, transition log,
fingerprints and the strict document-index reader (FEATURE-001-D)."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import stat
from typing import Any

from ..atomic import dumps_json
from . import durable, store
from .durable import StoreError
from .identity import RuleRef

EXITS_REL = f"{store.PRIVATE_REL}/exits"
TOMBSTONES_REL = f"{EXITS_REL}/tombstones"
JOURNAL_NAME = "journal.json"
MEMORY_NAME = "memory.json"
TRANSITIONS_NAME = "transitions.json"
EXIT_RECORD_NAME = "exit-record.json"
INDEX_DIR, _, INDEX_NAME = store.INDEX_REL.rpartition("/")
SCHEMA_PREFIX = "ai-secure-code-toolkit/"
JOURNAL_SCHEMA = SCHEMA_PREFIX + "exit-journal/v1"
MEMORY_SCHEMA = SCHEMA_PREFIX + "exit-memory/v1"
TRANSITIONS_SCHEMA = SCHEMA_PREFIX + "exit-transitions/v1"
EXIT_RECORD_SCHEMA = SCHEMA_PREFIX + "exit-record/v1"
EXIT_ID = re.compile(r"ex-\d{8}T\d{6}Z-[0-9a-f]{8}")
TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAX_REASON = 1000
ACTIONS = ("deactivate", "reactivate", "delete", "rename")
EXITED = {"delete": "deleted", "rename": "renamed"}
MEMORY_STEP = (
    "Restore .x-ipe/private/secure-code/exits/memory.json from a backup or ask a Maintainer to inspect it"
)


def canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def text(data: Any) -> str:
    """Serialized private JSON payload (same form as every other toolkit file)."""
    return dumps_json(data).decode("utf-8")


def new_exit_id(at: str) -> str:
    return "ex-" + at.replace("-", "").replace(":", "") + "-" + secrets.token_hex(4)


def reason_problem(reason: Any) -> str | None:
    """`REASON_REQUIRED`, `REASON_INVALID` or None for a usable one-line reason."""
    if not isinstance(reason, str) or not reason.strip():
        return "REASON_REQUIRED"
    if len(reason) > MAX_REASON or any(ord(c) < 32 or ord(c) == 127 or c in "\u2028\u2029" for c in reason):
        return "REASON_INVALID"
    return None


def transition_digest(entry: dict[str, Any]) -> str:
    return sha(canonical({k: v for k, v in entry.items() if k != "digest"}))


def tombstone_rel(exit_id: str) -> str:
    return f"{TOMBSTONES_REL}/{exit_id}"


# --------------------------------------------------------------------------- private JSON files
def read_at(tree: durable.Tree, rel: str, name: str) -> bytes | None:
    fd = tree.opt_dir(rel)
    if fd is None:
        return None
    try:
        return durable.read(fd, name)
    finally:
        durable.close(fd)


def _json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def memory_entries(raw: bytes | None) -> list[dict[str, Any]]:
    """Parse exit memory; ValueError when it is not a valid exit-memory/v1 document."""
    if raw is None:
        return []
    data = _json(raw)
    valid = isinstance(data, dict) and data.get("schema") == MEMORY_SCHEMA
    if not (valid and isinstance(data.get("exited"), list)):
        raise ValueError("not an exit-memory/v1 document")
    for entry in data["exited"]:
        if not (
            isinstance(entry, dict)
            and isinstance(entry.get("rule"), str)
            and entry.get("action") in EXITED.values()
            and isinstance(entry.get("exit_id"), str)
        ):
            raise ValueError("malformed exit-memory entry")
    return data["exited"]


def read_memory(tree: durable.Tree) -> list[dict[str, Any]]:
    """Strict read for write paths: EXIT_MEMORY_INVALID when unreadable or malformed."""
    try:
        return memory_entries(read_at(tree, EXITS_REL, MEMORY_NAME))
    except (ValueError, OSError) as exc:
        raise StoreError("EXIT_MEMORY_INVALID", f"exit memory is unreadable: {exc}", MEMORY_STEP) from None


def memory_or_empty(tree: durable.Tree) -> tuple[list[dict[str, Any]], str | None]:
    """Lenient read for read paths: (entries, notice code or None)."""
    try:
        return read_memory(tree), None
    except StoreError as exc:
        if exc.code != "EXIT_MEMORY_INVALID":
            raise
        return [], "EXIT_MEMORY_UNREADABLE"


def memory_text(entries: list[dict[str, Any]]) -> str:
    return text({"schema": MEMORY_SCHEMA, "exited": sorted(entries, key=lambda e: (e["rule"], e["exit_id"]))})


def reserved(entries: list[dict[str, Any]], ref: RuleRef | str) -> dict[str, Any] | None:
    """Exit-memory entry for this identity, ignoring letter case (latest exit wins)."""
    rel = (ref.rel if isinstance(ref, RuleRef) else ref).lower()
    found = [e for e in entries if e["rule"].lower() == rel]
    return max(found, key=lambda e: (e.get("at") or "", e["exit_id"])) if found else None


def transition_entries(raw: bytes | None) -> list[dict[str, Any]]:
    if raw is None:
        return []
    data = _json(raw)
    if (
        not isinstance(data, dict)
        or data.get("schema") != TRANSITIONS_SCHEMA
        or not isinstance(data.get("entries"), list)
        or not all(isinstance(e, dict) for e in data["entries"])
    ):
        raise ValueError("not an exit-transitions/v1 document")
    return data["entries"]


def transitions_text(entries: list[dict[str, Any]]) -> str:
    return text({"schema": TRANSITIONS_SCHEMA, "entries": entries})


# --------------------------------------------------------------------------- fingerprints
def files_fingerprint(files: dict[str, bytes | str]) -> str:
    """Logical view fingerprint: canonical [[relpath, "file", sha256]] sorted by relpath."""
    rows = []
    for name, body in sorted(files.items()):
        data = body.encode("utf-8") if isinstance(body, str) else body
        rows.append([name, "file", sha(data)])
    return sha(canonical(rows))


SPECIAL_KINDS = (
    (stat.S_ISFIFO, "fifo"),
    (stat.S_ISSOCK, "socket"),
    (stat.S_ISCHR, "chardev"),
    (stat.S_ISBLK, "blockdev"),
)


def _unreadable(rel: str, exc: BaseException) -> StoreError:
    return StoreError(
        "RULE_FOLDER_UNREADABLE",
        f"{rel or 'rule folder'} cannot be read completely ({exc})",
        "Fix the permissions of the rule folder, then preview again",
    )


def folder_rows(dfd: int, prefix: str = "") -> tuple[list[list[str]], list[dict[str, str]]]:
    """Physical rows of every entry a move would carry (links never followed, special files never
    opened, every regular file hashed by its bytes)."""
    rows: list[list[str]] = []
    special: list[dict[str, str]] = []
    try:
        entries = durable.listdir(dfd)
    except OSError as exc:
        raise _unreadable(prefix.rstrip("/"), exc) from None
    for name, info in entries:
        rel = prefix + name
        mode = info.st_mode
        if stat.S_ISREG(mode):
            try:
                data = durable.read(dfd, name)
            except OSError as exc:
                raise _unreadable(rel, exc) from None
            rows.append([rel, "file", sha(data or b"")])
        elif stat.S_ISLNK(mode):
            rows.append([rel, "link", sha(durable.readlink(dfd, name).encode("utf-8", "surrogateescape"))])
        elif stat.S_ISDIR(mode):
            rows.append([rel, "dir", ""])
            try:
                sub = durable.open_child(dfd, name)
            except OSError as exc:
                raise _unreadable(rel, exc) from None
            try:
                more, extra = folder_rows(sub, rel + "/")
            finally:
                durable.close(sub)
            rows += more
            special += extra
        else:
            kind = next((k for test, k in SPECIAL_KINDS if test(mode)), "other")
            rows.append([rel, kind, f"meta:size={info.st_size};mode={oct(stat.S_IMODE(mode))}"])
            special.append({"path": rel, "kind": kind})
    return rows, special


def folder_fingerprint(dfd: int) -> tuple[str, list[dict[str, str]]]:
    rows, special = folder_rows(dfd)
    return sha(canonical(sorted(rows))), sorted(special, key=lambda e: e["path"])


# --------------------------------------------------------------------------- strict index
def index_entries(raw: bytes | None) -> dict[str, Any]:
    """Strict document index: ValueError when malformed (never treated as empty)."""
    if raw is None:
        return {}
    data = _json(raw)
    if not isinstance(data, dict):
        raise ValueError("index is not an object")
    for document, entry in data.items():
        if not (
            DIGEST.fullmatch(document)
            and isinstance(entry, dict)
            and isinstance(entry.get("items", []), list)
            and isinstance(entry.get("failed", []), list)
            and all(isinstance(e, dict) and isinstance(e.get("rule"), str) for e in entry.get("items", []))
        ):
            raise ValueError(f"malformed index entry {document[:20]}")
    return data


def read_index_strict(tree: durable.Tree) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """(index, None) or (None, {"detail", "sha256"}) when the index cannot be used."""
    try:
        raw = read_at(tree, INDEX_DIR, INDEX_NAME)
    except OSError as exc:
        return None, {"detail": f"unreadable: {exc.strerror or exc}", "sha256": f"error:{exc.errno}"}
    try:
        return index_entries(raw), None
    except (ValueError, UnicodeDecodeError) as exc:
        return None, {"detail": f"malformed: {exc}", "sha256": sha(raw or b"")}


def index_edges(index: dict[str, Any], label: str) -> list[str]:
    """Documents whose stored edges include the rule label (sorted)."""
    return sorted(d for d, e in index.items() if any(i.get("rule") == label for i in e.get("items", [])))


def invalidate_index(index: dict[str, Any], label: str, edges: list[str], at: str) -> dict[str, Any]:
    """Move the rule's edge to `failed` and mark each named document entry incomplete."""
    result = json.loads(json.dumps(index))
    for document in edges:
        entry = result[document]
        entry["items"] = [e for e in entry.get("items", []) if e.get("rule") != label]
        entry["failed"] = sorted(set(entry.get("failed", [])) | {label})
        entry["complete"] = False
        entry["updated_at"] = at
    return result
