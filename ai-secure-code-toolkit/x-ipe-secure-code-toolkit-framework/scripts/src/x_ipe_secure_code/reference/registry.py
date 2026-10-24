"""Formal Reference knowledge records (FEATURE-001-E, FR-001E-1/2): schemas, validation, digests and the
read-only registry view taken through the command's no-follow `durable.Tree`.

Layout under `x-ipe-docs/secure-code/knowledge/reference/`: `<NS>/<VER>/.source.json`,
`<NS>/<VER>/.changelog.md`, `<NS>/<VER>/<RULE_ID>/reference.json` (one folder per rule, so the delivered
status count works unchanged) and `.removed.json` (tombstones). No record holds a body.
"""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass, field
from typing import Any

from ..knowledge import durable, lifecycle
from ..knowledge.identity import IdentityError, RuleRef, make_ref
from . import REGISTRY_REL, clock

SOURCE_SCHEMA = "ai-secure-code-toolkit/reference-source/v1"
RULE_SCHEMA = "ai-secure-code-toolkit/reference-rule/v1"
REMOVED_SCHEMA = "ai-secure-code-toolkit/reference-removed/v1"
SOURCE_FILE, RULE_FILE, CHANGELOG, REMOVED_FILE = (
    ".source.json",
    "reference.json",
    ".changelog.md",
    ".removed.json",
)
SOURCE_KEYS = frozenset(
    {
        "schema",
        "namespace",
        "version",
        "display_name",
        "scheme",
        "domains",
        "port",
        "path_prefix",
        "revision",
        "registered_at",
        "updated_at",
    }
)
RULE_KEYS = frozenset(
    {
        "schema",
        "rule",
        "title",
        "entry_url",
        "applicability",
        "revision",
        "registered_at",
        "updated_at",
    }
)
MAX_TITLE, MAX_RECORD = 300, 64 * 1024


@dataclass(frozen=True)
class Bad:
    """A registry record that cannot be used (unreadable, invalid or without its source)."""

    detail: str


def canonical_digest(data: Any) -> str:
    return lifecycle.sha(lifecycle.canonical(data))


def source_digest(source: dict[str, Any]) -> str:
    keys = ("schema", "namespace", "version", "scheme", "domains", "port", "path_prefix")
    return canonical_digest({k: source[k] for k in keys})


def registration_digest(rule: dict[str, Any], source: dict[str, Any]) -> str:
    return canonical_digest(
        {
            "source": source_digest(source),
            "rule": rule["rule"],
            "title": rule["title"],
            "entry_url": rule["entry_url"],
            "applicability": rule["applicability"],
        }
    )


def _time(value: Any) -> bool:
    try:
        clock.parse(value)
        return True
    except (TypeError, ValueError):
        return False


def check_source_record(data: Any, ns_ver: str) -> dict[str, Any]:
    """Structural validation of a stored source record (ValueError when unusable)."""
    if not isinstance(data, dict) or set(data) != SOURCE_KEYS or data["schema"] != SOURCE_SCHEMA:
        raise ValueError("not a reference-source/v1 record")
    if f"{data['namespace']}/{data['version']}" != ns_ver:
        raise ValueError("record does not match its folder")
    domains = data["domains"]
    if not isinstance(domains, list) or not domains or not all(isinstance(d, str) and d for d in domains):
        raise ValueError("domains must be a non-empty list")
    if data["scheme"] not in ("http", "https") or not (data["port"] is None or type(data["port"]) is int):
        raise ValueError("scheme or port malformed")
    if not (data["path_prefix"] is None or isinstance(data["path_prefix"], str)):
        raise ValueError("path_prefix malformed")
    if not (data["display_name"] is None or isinstance(data["display_name"], str)):
        raise ValueError("display_name malformed")
    if type(data["revision"]) is not int or not _time(data["registered_at"]) or not _time(data["updated_at"]):
        raise ValueError("revision or times malformed")
    return data


def check_applicability(value: Any) -> str | list[str]:
    if value is None or value == "unknown":
        return "unknown"
    if (
        isinstance(value, list)
        and value
        and len(value) <= 20
        and all(isinstance(v, str) and 0 < len(v) <= 50 and v.isprintable() for v in value)
    ):
        return sorted(set(value))
    raise ValueError("applicability must be 'unknown' or a list of language names")


def check_rule_record(data: Any, rel: str) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) != RULE_KEYS or data["schema"] != RULE_SCHEMA:
        raise ValueError("not a reference-rule/v1 record")
    if data["rule"] != rel:
        raise ValueError("record does not match its folder")
    title = data["title"]
    if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE:
        raise ValueError("title malformed")
    if (
        not isinstance(data["entry_url"], str)
        or check_applicability(data["applicability"]) != data["applicability"]
    ):
        raise ValueError("entry_url or applicability malformed")
    if type(data["revision"]) is not int or not _time(data["registered_at"]) or not _time(data["updated_at"]):
        raise ValueError("revision or times malformed")
    return data


def removed_entries(raw: bytes | None) -> list[dict[str, Any]]:
    if raw is None:
        return []
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or set(data) != {"schema", "removed"} or data["schema"] != REMOVED_SCHEMA:
        raise ValueError("not a reference-removed/v1 document")
    entries = data["removed"]
    if not isinstance(entries, list) or not all(
        isinstance(e, dict) and set(e) == {"rule", "removal_id", "removed_at", "reason"} for e in entries
    ):
        raise ValueError("malformed tombstone")
    return entries


@dataclass
class RegistryView:
    """Read-only snapshot of the registry (plus cache states attached by `cache.attach`)."""

    sources: dict[str, dict[str, Any] | Bad] = field(default_factory=dict)
    rules: dict[str, dict[str, Any] | Bad] = field(default_factory=dict)
    removed: dict[str, dict[str, Any]] = field(default_factory=dict)
    states: dict[str, Any] = field(default_factory=dict)
    notice: str | None = None

    @classmethod
    def empty(cls) -> RegistryView:
        return cls()

    @property
    def present(self) -> bool:
        """Any registered Reference rule or tombstone: every Reference behaviour is gated on this."""
        return bool(self.rules or self.removed)

    @property
    def count(self) -> int:
        return len(self.rules)

    def has(self, ref: RuleRef) -> bool:
        return ref.rel in self.rules

    def is_removed(self, ref: RuleRef) -> bool:
        return ref.rel in self.removed and ref.rel not in self.rules

    def identities(self) -> list[RuleRef]:
        return sorted(RuleRef.parse(rel) for rel in self.rules)

    def versions(self, namespace: str, rule_id: str) -> list[RuleRef]:
        return [r for r in self.identities() if r.namespace == namespace and r.rule_id == rule_id]

    def usable(self, ref: RuleRef) -> tuple[dict[str, Any], dict[str, Any]] | Bad:
        """(rule record, source record) or why the registration cannot be used."""
        rule = self.rules.get(ref.rel)
        if rule is None:
            return Bad("not registered")
        if isinstance(rule, Bad):
            return rule
        source = self.sources.get(f"{ref.namespace}/{ref.version}")
        if source is None:
            return Bad("its source is not registered")
        if isinstance(source, Bad):
            return Bad(f"its source record is unusable ({source.detail})")
        return rule, source


def _entries(tree: durable.Tree, rel: str) -> list[tuple[str, Any]]:
    fd = tree.dir(rel)
    try:
        return tree.list(fd)
    finally:
        durable.close(fd)


def read_json(tree: durable.Tree, rel: str, name: str) -> Any:
    raw = lifecycle.read_at(tree, rel, name)
    if raw is None:
        return None
    if len(raw) > MAX_RECORD:
        raise ValueError("record larger than 64 KiB")
    return json.loads(raw.decode("utf-8"))


def _read(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except durable.StoreError as exc:
        return Bad(exc.code)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return Bad(f"{type(exc).__name__}: {exc}")


def view_at(tree: durable.Tree) -> RegistryView:
    """Read every source, rule and tombstone (links never followed; unreadable records become `Bad`)."""
    view = RegistryView()
    base = tree.opt_dir(REGISTRY_REL)
    if base is None:
        return view
    durable.close(base)
    try:
        for entry in removed_entries(lifecycle.read_at(tree, REGISTRY_REL, REMOVED_FILE)):
            view.removed[entry["rule"]] = entry
    except (ValueError, UnicodeError, durable.StoreError, OSError):
        view.notice = "REFERENCE_TOMBSTONES_UNREADABLE"
    for ns, info in _entries(tree, REGISTRY_REL):
        if not stat.S_ISDIR(info.st_mode) or ns.startswith("."):
            continue
        for ver, vinfo in _entries(tree, f"{REGISTRY_REL}/{ns}"):
            if not stat.S_ISDIR(vinfo.st_mode) or ver.startswith("."):
                continue
            try:
                make_ref(ns, ver, "probe")
            except IdentityError:
                continue
            folder = f"{REGISTRY_REL}/{ns}/{ver}"
            ns_ver = f"{ns}/{ver}"
            source = _read(read_json, tree, folder, SOURCE_FILE)
            if source is not None:
                view.sources[ns_ver] = (
                    source if isinstance(source, Bad) else _read(check_source_record, source, ns_ver)
                )
            for rid, rinfo in _entries(tree, folder):
                if not stat.S_ISDIR(rinfo.st_mode) or rid.startswith("."):
                    continue
                try:
                    ref = make_ref(ns, ver, rid)
                except IdentityError:
                    continue
                record = _read(read_json, tree, f"{folder}/{rid}", RULE_FILE)
                if record is None:
                    record = Bad(f"{RULE_FILE} is missing")
                view.rules[ref.rel] = (
                    record if isinstance(record, Bad) else _read(check_rule_record, record, ref.rel)
                )
    return view


def rule_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record[k] for k in ("rule", "title", "entry_url", "applicability")}
