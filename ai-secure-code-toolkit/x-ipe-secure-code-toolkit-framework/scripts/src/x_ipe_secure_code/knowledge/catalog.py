"""Preset and tag files (FEATURE-001-F): identity slugs, request files, schema validation,
deterministic serialization, no-follow reads, digest-guarded writes under the existing knowledge
lock, reference validation through the 001-C availability check, the `presets`/`tags` exit-impact
providers and broken-reference reporting.

JSON files are the only authoritative format. Nothing is followed, created or written on a link.
Query intent and summaries are stored and copied as text only; they are never evaluated.
"""

from __future__ import annotations

import json
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..policy import resolve, scope
from ..policy.refs import is_utf8, parse_requested
from ..results import Result
from . import durable, exit_journal, lifecycle, store
from .identity import RESERVED, IdentityError, RuleRef

PRESETS_REL = "x-ipe-docs/secure-code/presets"
TAGS_REL = "x-ipe-docs/secure-code/tags"
MAX_BYTES = 1024 * 1024
MAX_TEXT = scope.MAX_TEXT
SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
SELECTOR_CHARS = frozenset("*?[]{}()!|&,;=~#")
SNAPSHOT_NOTE = "last confirmed list change; does not freeze rule content"
QUERY_NOTE = "intent text only — not run"
HISTORY_NOTE = (
    "The toolkit keeps no Preset/tag change history; version control is the history; "
    "snapshot_at is not a history"
)
TAG_NOTE = "tags never change severity, mandatory marking or Presets"
RESTORE_STEP = "Restore it from version control or re-save it"
LINK_STEP = "Replace the symbolic link with a real file: restore it from version control or re-save it"
NAME_STEP = "Choose a lowercase name of a-z, 0-9 and hyphens"
REQUEST_STEP = "Fix the request (see references/presets-and-tags.md)"
REFS_STEP = "Choose concrete, available references (version-qualified where several versions exist)"
STALE_STEP = "Show the current content to the user and retry with the current digest"
CONFIRM_STEP = "Save only after the user confirmed, then pass --confirmed"
IO_STEP = "Check folder permissions and retry"
_BAD = (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, IdentityError)


@dataclass(frozen=True)
class Kind:
    name: str
    rel: str
    schema: str
    members: str
    keys: frozenset[str]
    label: str
    code: str


PRESET = Kind(
    "preset",
    PRESETS_REL,
    "ai-secure-code-toolkit/preset/v1",
    "rules",
    frozenset({"schema", "name", "rules", "query_intent", "applicability_summary", "snapshot_at"}),
    "Preset",
    "PRESET",
)
TAG = Kind(
    "tag",
    TAGS_REL,
    "ai-secure-code-toolkit/tag/v1",
    "members",
    frozenset({"schema", "name", "members"}),
    "tag",
    "TAG",
)


class CatalogError(Exception):
    """A refused Preset/tag operation (nothing written)."""

    def __init__(
        self, code: str, message: str, next_step: str | None = None, data: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.code, self.message, self.next_step, self.data = code, message, next_step, data

    def result(self, command: str) -> Result:
        return Result.refused(command, self.code, self.message, self.next_step, self.data)


class Denied(Exception):
    """An authorization refusal raised under the lock (carries the delivered refusal Result)."""

    def __init__(self, result: Result) -> None:
        super().__init__(result.problems[0].message)
        self.result = result


# --------------------------------------------------------------------------- identity, requests
def _identity(message: str) -> CatalogError:
    return CatalogError("IDENTITY_INVALID", message, NAME_STEP)


def check_slug(name: Any, kind: str) -> bool:
    """Validate a Preset/tag identity (A1); True when it names the default Preset."""
    if not isinstance(name, str):
        raise _identity("The name must be 1-64 lowercase letters a-z, digits 0-9 and hyphens")
    if "/" in name or "\\" in name:
        raise _identity(f"The name {name!r} must not contain a path separator")
    if name.upper() in RESERVED:
        raise _identity(f"The name {name!r} is a reserved device name on Windows")
    if not SLUG.fullmatch(name):
        raise _identity(
            f"The name {name!r} must be 1-64 lowercase letters a-z, digits 0-9 and hyphens "
            "(no hyphen at the start or end)"
        )
    if name == "default":
        if kind == "tag":
            raise _identity("The name 'default' is reserved for the default Preset and cannot name a tag")
        return True
    return False


def request_error(message: str) -> CatalogError:
    return CatalogError("REQUEST_INVALID", message, REQUEST_STEP)


def load_request(path: str, schema: str, keys: set[str] | frozenset[str]) -> dict[str, Any]:
    """Load a request file: regular non-link file, <= 1 MiB, UTF-8 JSON object, exact schema."""
    file = Path(path)
    try:
        if file.is_symlink() or not file.is_file():
            raise request_error(f"{path} is not a regular file")
        if file.stat().st_size > MAX_BYTES:
            raise request_error(f"{path} is larger than {MAX_BYTES} bytes")
        data = json.loads(file.read_bytes().decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise request_error(f"{path} is not readable UTF-8 JSON: {exc}") from None
    if not isinstance(data, dict) or data.get("schema") != schema:
        raise request_error(f"The request must be a JSON object with schema '{schema}'")
    if not is_utf8(data):
        raise request_error("The request contains text that is not valid UTF-8")
    unknown = sorted(set(data) - set(keys))
    if unknown:
        raise request_error(f"Unknown request fields: {unknown}")
    for key, value in data.items():
        if isinstance(value, str) and len(value) > MAX_TEXT:
            raise request_error(f"{key} is longer than {MAX_TEXT} characters")
    return data


def text_field(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is not None and not isinstance(value, str):
        raise request_error(f"{key} must be text or null")
    return value


def ref_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list):
        raise request_error(f"{key} must be a list of rule references")
    return value


def confirmed_or_refuse(confirmed: bool) -> None:
    if not confirmed:
        raise CatalogError("CONFIRMATION_REQUIRED", "The change was not marked as confirmed", CONFIRM_STEP)


# --------------------------------------------------------------------------- documents
class Member(str):
    """A stored identity that remembers its member source (FEATURE-001-E, P4): `local` or `reference`.
    It compares, hashes and sorts exactly like the plain identity text."""

    source: str

    def __new__(cls, rel: str, source: str = "local") -> Member:
        member = super().__new__(cls, rel)
        member.source = source
        return member


def source_of(rel: str) -> str:
    return getattr(rel, "source", "local")


def _members(rels: list[str]) -> list[dict[str, str]]:
    first: dict[str, str] = {}
    for rel in rels:
        first.setdefault(str(rel), source_of(rel))
    return [{"rule": rel, "source": first[rel]} for rel in sorted(first)]


def preset_doc(
    name: str, rules: list[str], query_intent: str | None, summary: str | None, snapshot_at: str
) -> dict[str, Any]:
    return {
        "schema": PRESET.schema,
        "name": name,
        "rules": _members(rules),
        "query_intent": query_intent,
        "applicability_summary": summary,
        "snapshot_at": snapshot_at,
    }


def tag_doc(name: str, members: list[str]) -> dict[str, Any]:
    return {"schema": TAG.schema, "name": name, "members": _members(members)}


def serialize(doc: dict[str, Any]) -> bytes:
    """Deterministic bytes: sorted keys, sorted unique references, UTF-8, trailing newline."""
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def file_digest(raw: bytes) -> str:
    return lifecycle.sha(raw)


def parse(kind: Kind, stem: str, raw: bytes) -> dict[str, Any]:
    """Validate a stored file (never treated as empty when invalid)."""
    if len(raw) > MAX_BYTES:
        raise ValueError("larger than 1 MiB")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or set(data) != kind.keys:
        raise ValueError("unexpected or missing keys")
    if data["schema"] != kind.schema:
        raise ValueError("unknown schema")
    if data["name"] != stem:
        raise ValueError("name does not match the file name")
    try:
        check_slug(stem, kind.name)
    except CatalogError as exc:
        raise ValueError(exc.message) from None
    members = data[kind.members]
    if not isinstance(members, list) or not members:
        raise ValueError(f"{kind.members} must be a non-empty list")
    rels = []
    for member in members:
        if not isinstance(member, dict) or set(member) != {"rule", "source"} or member["source"] not in (
            "local", "reference"
        ):
            raise ValueError("each reference must be {rule, source: local or reference}")
        rels.append(RuleRef.parse(member["rule"]).rel)
    if rels != sorted(set(rels)):
        raise ValueError("references are not sorted and unique")
    if kind is PRESET:
        for key in ("query_intent", "applicability_summary"):
            value = data[key]
            if value is not None and (not isinstance(value, str) or len(value) > MAX_TEXT):
                raise ValueError(f"{key} must be text of at most {MAX_TEXT} characters or null")
        if datetime.fromisoformat(data["snapshot_at"]).utcoffset() is None:
            raise ValueError("snapshot_at has no timezone offset")
    if not is_utf8(data):
        raise ValueError("text is not valid UTF-8")
    return data


@dataclass
class Entry:
    name: str
    data: dict[str, Any]
    digest: str

    @property
    def rels(self) -> list[str]:
        key = "rules" if "rules" in self.data else "members"
        return [Member(m["rule"], m["source"]) for m in self.data[key]]


@dataclass
class Scan:
    entries: list[Entry] = field(default_factory=list)
    invalid: list[dict[str, Any]] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)


def _detail(exc: BaseException) -> str:
    return getattr(exc, "message", None) or str(exc) or type(exc).__name__


def _undecodable(name: str) -> str | None:
    """Printable stand-in for a listed name that is not valid UTF-8, else None.

    POSIX raw bytes arrive as U+DC80-U+DCFF and are shown as \\xNN; any other unpaired surrogate (possible
    for NTFS names on Windows) is shown as \\uNNNN."""
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        try:
            return name.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
        except UnicodeEncodeError:
            return name.encode("utf-8", "backslashreplace").decode("utf-8")
    return None


def scan(tree: durable.Tree, kind: Kind, *, unsafe_store: str = "refuse") -> Scan:
    """No-follow list of one store (A3). Store link: refuse (PATH_UNSAFE) or one finding."""
    try:
        fd = tree.opt_dir(kind.rel)
    except durable.StoreError:
        if unsafe_store == "refuse":
            raise
        folder = kind.rel.rsplit("/", 1)[1] + "/"
        return Scan(invalid=[{"file": folder, "code": "PATH_UNSAFE", "detail": "not a real folder"}])
    found = Scan()
    if fd is None:
        return found
    try:
        for name, info in durable.listdir(fd):
            shown = _undecodable(name)
            if name.startswith(".") or not name.endswith(".json"):
                found.ignored.append(shown or name)
                continue
            if shown is not None:
                found.invalid.append(
                    {"file": shown, "code": f"{kind.code}_INVALID", "detail": "file name is not valid UTF-8"}
                )
                continue
            if not stat.S_ISREG(info.st_mode):
                found.invalid.append({"file": name, "code": "PATH_UNSAFE", "detail": "not a regular file"})
                continue
            try:
                raw = durable.read(fd, name) or b""
            except (durable.StoreError, OSError) as exc:
                found.invalid.append({"file": name, "code": "PATH_UNSAFE", "detail": _detail(exc)})
                continue
            try:
                data = parse(kind, name[:-5], raw)
            except _BAD as exc:
                found.invalid.append(
                    {
                        "file": name,
                        "code": f"{kind.code}_INVALID",
                        "detail": _detail(exc),
                        "content_digest": file_digest(raw),
                    }
                )
                continue
            found.entries.append(Entry(name[:-5], data, file_digest(raw)))
    finally:
        durable.close(fd)
    found.entries.sort(key=lambda e: e.name)
    return found


def listed_invalid(found: Scan) -> list[dict[str, Any]]:
    return [
        {"file": i["file"], "code": i["code"], "detail": i["detail"], "next_step": RESTORE_STEP}
        for i in found.invalid
    ]


def not_found(kind: Kind, name: str) -> CatalogError:
    return CatalogError(
        f"{kind.code}_NOT_FOUND",
        f"No {kind.label} named {name!r}",
        f"List the existing names with: secure-code {kind.name} list",
    )


def read_one(tree: durable.Tree, kind: Kind, name: str) -> Entry:
    """Read and validate one file; links → PATH_UNSAFE, invalid → *_INVALID (A3)."""
    check_slug(name, kind.name)
    fd = tree.opt_dir(kind.rel)
    if fd is None:
        raise not_found(kind, name)
    try:
        raw = durable.read(fd, f"{name}.json")
    except durable.StoreError as exc:
        raise CatalogError(exc.code, exc.message, LINK_STEP, {"file": f"{name}.json"}) from None
    finally:
        durable.close(fd)
    if raw is None:
        raise not_found(kind, name)
    try:
        data = parse(kind, name, raw)
    except _BAD as exc:
        raise CatalogError(
            f"{kind.code}_INVALID",
            f"{kind.label} file {name}.json is invalid: {_detail(exc)}",
            RESTORE_STEP,
            {"file": f"{name}.json"},
        ) from None
    return Entry(name, data, file_digest(raw))


# --------------------------------------------------------------------------- references
def is_dynamic(text: str) -> bool:
    """A tag name, expression, wildcard or other selector instead of a concrete reference."""
    return (
        "/" not in text
        or text.lower().startswith(("tag:", "preset:"))
        or any(c in SELECTOR_CHARS or c.isspace() for c in text)
    )


def check_references(lib: resolve.Library, texts: list[Any]) -> tuple[list[str], list[dict[str, Any]], int]:
    """A2: (valid fully qualified identities sorted, invalid with reasons, duplicates dropped)."""
    valid: dict[str, Member] = {}
    invalid: list[dict[str, Any]] = []
    duplicates = 0
    for text in texts:
        if not isinstance(text, str):
            invalid.append(
                {"requested": str(text), "reason": "invalid_reference", "detail": "a reference must be text"}
            )
            continue
        if text.lower().startswith("reference:"):
            # FEATURE-001-E (P4): a registered Reference rule is stored as {rule, source: reference}
            req = parse_requested(text[len("reference:"):])
            full = None if req.invalid else req.full()
            if full is None or not lib.refs.has(full):
                invalid.append(
                    {
                        "requested": text,
                        "reason": "invalid_reference",
                        "detail": "not a registered Reference rule; ask a Maintainer to register it "
                        "(secure-code knowledge reference register)",
                    }
                )
                continue
            duplicates += full.rel in valid
            valid.setdefault(full.rel, Member(full.rel, "reference"))
            continue
        if is_dynamic(text):
            invalid.append(
                {
                    "requested": text,
                    "reason": "dynamic_selector",
                    "detail": "only concrete NAMESPACE/VERSION/RULE_ID references are stored",
                }
            )
            continue
        found = resolve.entry_for(lib, parse_requested(text), [])
        if found["availability"] != "available":
            item = {"requested": text, "reason": found["reason"]}
            item.update({k: found[k] for k in ("detail", "candidates", "renamed_to") if k in found})
            invalid.append(item)
            continue
        if found["rule"] in valid:
            duplicates += 1
        source = "reference" if found.get("knowledge_kind") == "reference" else "local"
        valid.setdefault(found["rule"], Member(found["rule"], source))
    return [valid[rel] for rel in sorted(valid)], invalid, duplicates


def validated_members(lib: resolve.Library, texts: list[Any]) -> tuple[list[str], int]:
    """References for a save/update: every one must be concrete and available (A2)."""
    if not texts:
        raise CatalogError(
            "MEMBERSHIP_EMPTY",
            "The list of rules is empty",
            "Add at least one rule, or delete the Preset/tag",
        )
    valid, invalid, duplicates = check_references(lib, texts)
    if invalid:
        names = ", ".join(f"{i['requested']} ({i['reason']})" for i in invalid)
        raise CatalogError(
            "REFERENCES_INVALID", f"Unusable references: {names}", REFS_STEP, {"references": invalid}
        )
    return valid, duplicates


def availability(lib: resolve.Library, rels: list[str]) -> list[dict[str, Any]]:
    """Current availability of stored references (001-C reasons, incl. 001-D exit reasons)."""
    rows = []
    for rel in rels:
        found = resolve.evaluate(lib, RuleRef.parse(rel), [])
        row: dict[str, Any] = {"source": source_of(rel), "rule": rel, "availability": found["availability"]}
        if found["availability"] == "available":
            row["state_digest"] = found["source_evidence"]["state_digest"]
        else:
            row["reason"] = found["reason"]
            if found.get("renamed_to"):
                row["renamed_to"] = found["renamed_to"]
        rows.append(row)
    return rows


def counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        state: sum(1 for r in rows if r["availability"] == state)
        for state in ("available", "missing", "unclear")
    }


def broken_refs(lib: resolve.Library, owner: str, name: str, rels: list[str]) -> list[dict[str, Any]]:
    """Broken references with owner, target and reason; `renamed_to` is information only."""
    broken = []
    for row in availability(lib, rels):
        if row["availability"] != "available":
            item = {"owner": owner, "name": name, "target": row["rule"], "reason": row["reason"]}
            if row.get("renamed_to"):
                item["renamed_to"] = row["renamed_to"]
            broken.append(item)
    return broken


# --------------------------------------------------------------------------- sessions and writes
def in_session(
    command: str, root: Path, fn: Callable[[exit_journal.Session], Any], *, write: bool = False
) -> tuple[Any, dict[str, Any] | None] | Result:
    """Run `fn` inside the knowledge session; refusals carry any recovered exit."""
    recovered: dict[str, Any] | None = None
    try:
        with exit_journal.session(root, write=write) as session:
            recovered = session.recovered
            return fn(session), recovered
    except CatalogError as exc:
        return exit_journal.with_recovered(exc.result(command), recovered)
    except Denied as exc:
        return exit_journal.with_recovered(exc.result, recovered)
    except (LockHeld, durable.StoreError, exit_journal.JournalInvalid) as exc:
        return exit_journal.with_recovered(exit_journal.refusal(command, exc), recovered)
    except OSError as exc:
        return exit_journal.with_recovered(
            Result.refused(command, "IO_ERROR", f"{exc.strerror or exc}", IO_STEP), recovered
        )


def _case_variant(dfd: int, name: str) -> bool:
    wanted = f"{name}.json"
    return any(entry.lower() == wanted and entry != wanted for entry, _ in durable.listdir(dfd))


@dataclass
class Write:
    """One digest-guarded write (A4). `build(current, lib)` returns the new bytes, or None to
    write nothing; `delete` removes the file; `authorize()` re-checks under the lock."""

    kind: Kind
    name: str
    create: bool = False
    delete: bool = False
    expected: str | None = None
    check_digest: bool = True
    build: Callable[[Entry | None, resolve.Library], bytes | None] | None = None
    authorize: Callable[[], Result | None] | None = None


@dataclass
class Written:
    previous: Entry | None
    previous_digest: str | None
    data: bytes | None
    path: str


def guarded_write(session: exit_journal.Session, op: Write) -> Written:
    """Under the knowledge lock: authorize, stale-digest check, re-check references, then write."""
    kind, file = op.kind, f"{op.name}.json"
    store._pause_point(f"{kind.name}_write_locked")
    if op.authorize is not None:
        denied = op.authorize()
        if denied is not None:
            raise Denied(denied)
    dfd = session.tree.opt_dir(kind.rel)
    try:
        raw = durable.read(dfd, file) if dfd is not None else None
        if op.create:
            if raw is not None or (dfd is not None and _case_variant(dfd, op.name)):
                raise CatalogError(
                    f"{kind.code}_EXISTS",
                    f"There is already a {kind.label} {op.name!r} (names are unique ignoring letter case)",
                    f"Update the existing {kind.label} or choose another name",
                )
        else:
            if raw is None:
                raise not_found(kind, op.name)
            if op.check_digest and op.expected != file_digest(raw):
                raise CatalogError(
                    "STALE_DIGEST",
                    f"The {kind.label} changed since it was shown (or no current digest was given)",
                    STALE_STEP,
                    {"current_digest": file_digest(raw)},
                )
        previous = None
        if raw is not None and not op.delete:
            try:
                previous = Entry(op.name, parse(kind, op.name, raw), file_digest(raw))
            except _BAD as exc:
                raise CatalogError(
                    f"{kind.code}_INVALID",
                    f"{kind.label} file {file} is invalid: {_detail(exc)}",
                    RESTORE_STEP,
                    {"file": file},
                ) from None
        new = None
        if op.delete:
            assert dfd is not None
            durable.set_step(f"{kind.name}_write")
            try:
                durable.unlink(dfd, file)
            finally:
                durable.set_step("")
        else:
            assert op.build is not None
            new = op.build(previous, resolve.snapshot(session.tree))
            if new is not None:
                if dfd is None:
                    dfd = session.tree.dir(kind.rel, create=True, mode=0o755)
                durable.set_step(f"{kind.name}_write")
                try:
                    durable.write(dfd, file, new, f".{file}.tmp", mode=0o644 if raw is None else None)
                finally:
                    durable.set_step("")
    finally:
        durable.close(dfd)
    return Written(previous, file_digest(raw) if raw is not None else None, new, f"{kind.rel}/{file}")


# --------------------------------------------------------------------------- 001-D plug-in (A9, A10)
def _provider(kind: Kind) -> Callable[[Any], Any]:
    def collect(ctx: Any) -> Any:
        from .impact import Found

        found = scan(ctx.tree, kind, unsafe_store="finding")
        items = [{"name": e.name, "file_digest": e.digest} for e in found.entries if ctx.ref.rel in e.rels]
        unreadable = [
            {k: i[k] for k in ("file", "detail", "content_digest") if k in i} for i in found.invalid
        ]
        return Found(items, {"unreadable": unreadable})

    collect.__name__ = f"{kind.name}s_provider"
    return collect


presets_provider = _provider(PRESET)
tags_provider = _provider(TAG)


def links_extension(tree: durable.Tree, lib: resolve.Library) -> dict[str, Any] | None:
    """Broken Preset/tag references for `knowledge links`; None when no Preset/tag files exist."""
    scans = {kind.name: scan(tree, kind, unsafe_store="finding") for kind in (PRESET, TAG)}
    if not any(s.entries or s.invalid for s in scans.values()):
        return None
    broken: dict[str, list[dict[str, Any]]] = {}
    for kind_name, found in scans.items():
        rows = [b for e in found.entries for b in broken_refs(lib, kind_name, e.name, e.rels)]
        broken[kind_name] = sorted(rows, key=lambda b: (b["name"], b["target"]))
    unreadable = [
        {"kind": kind_name, "file": i["file"], "detail": i["detail"]}
        for kind_name, found in scans.items()
        for i in found.invalid
    ]
    return {
        "presets": broken["preset"],
        "tags": broken["tag"],
        "unreadable": unreadable,
        "counts": {
            "presets": len(broken["preset"]),
            "tags": len(broken["tag"]),
            "unreadable": len(unreadable),
        },
    }
