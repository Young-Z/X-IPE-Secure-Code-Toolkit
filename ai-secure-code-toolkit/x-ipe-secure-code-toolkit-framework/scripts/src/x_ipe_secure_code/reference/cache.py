"""Private Reference cache (FEATURE-001-E, FR-001E-6) under `.x-ipe/private/secure-code/reference-cache/`.

Entries are self-validating (key, entry digest, 7-day window, Policy state digest). Readers never lock and
never write; publication is generation- and registration-checked under the knowledge lock and the cache
lock, with capacity accounting and eviction of expired/invalid entries under the same cache lock. No lock
is held across the network. The cache never becomes formal knowledge.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..knowledge import durable, exit_journal, lifecycle, store
from ..knowledge.identity import RuleRef
from . import CACHE_LOCK_REL, CACHE_REL, MAX_TEXT, PARSER_VERSION, TTL_DAYS, clock, registry, urls

ENTRY_SCHEMA = "ai-secure-code-toolkit/reference-cache-entry/v1"
STATE_SCHEMA = "ai-secure-code-toolkit/reference-cache-state/v1"
ENTRIES_REL = f"{CACHE_REL}/entries"
STATE_NAME = "state.json"
ENTRY_NAME = re.compile(r"[0-9a-f]{64}\.json")
TMP_NAME = re.compile(r"\..+\.tmp")
MAX_ENTRY = 1024 * 1024
TTL = timedelta(days=TTL_DAYS)
ENTRY_KEYS = frozenset(
    {
        "schema",
        "key",
        "kind",
        "rule",
        "explore_url",
        "canonical_url",
        "registration_digest",
        "parser_version",
        "generation",
        "fetched_at",
        "expires_at",
        "http_status",
        "content_type",
        "response_digest",
        "text",
        "masking",
        "links",
        "links_truncated",
        "policy_state_digest",
        "title",
        "applicability",
        "entry_digest",
    }
)


# --------------------------------------------------------------------------- keys and digests
def cache_key(
    kind: str, target: str, canonical_url: str, reg_digest: str, parser_version: str = PARSER_VERSION
) -> str:
    data = {
        "kind": kind,
        "target": target,
        "canonical_url": canonical_url,
        "registration_digest": reg_digest,
        "parser_version": parser_version,
    }
    return registry.canonical_digest(data).split(":", 1)[1]


def rule_key(rule: dict[str, Any], source: dict[str, Any]) -> str:
    return cache_key("rule", rule["rule"], rule["entry_url"], registry.registration_digest(rule, source))


def explore_key(url: str, source: dict[str, Any]) -> str:
    return cache_key("explore", url, url, registry.source_digest(source))


def policy_state_digest(
    rule: str, title: str, applicability: Any, entry_url: str, text: str, parser_version: str = PARSER_VERSION
) -> str:
    """BR-12: stable inputs only (no fetch times, response digest, status, headers or cache metadata)."""
    return registry.canonical_digest(
        {
            "kind": "reference",
            "rule": rule,
            "title": title,
            "applicability": applicability,
            "entry_url": entry_url,
            "parser_version": parser_version,
            "requirement": text,
        }
    )


def entry_digest(entry: dict[str, Any]) -> str:
    return registry.canonical_digest({k: v for k, v in entry.items() if k != "entry_digest"})


def build_entry(
    *,
    kind: str,
    rule: dict[str, Any] | None,
    explore_url: str | None,
    canonical_url: str,
    reg_digest: str,
    fetched_at: datetime,
    http_status: int,
    content_type: str,
    response_digest: str,
    text: str,
    masking: dict[str, Any],
    links: list[dict[str, Any]],
    links_truncated: bool,
) -> dict[str, Any]:
    """Unpublished entry (generation and entry digest are set at publication)."""
    target = rule["rule"] if rule is not None else explore_url
    assert target is not None
    return {
        "schema": ENTRY_SCHEMA,
        "key": cache_key(kind, target, canonical_url, reg_digest),
        "kind": kind,
        "rule": rule["rule"] if rule is not None else None,
        "explore_url": explore_url,
        "canonical_url": canonical_url,
        "registration_digest": reg_digest,
        "parser_version": PARSER_VERSION,
        "generation": 0,
        "fetched_at": clock.iso(fetched_at),
        "expires_at": clock.iso(fetched_at + TTL),
        "http_status": http_status,
        "content_type": content_type,
        "response_digest": response_digest,
        "text": text,
        "masking": masking,
        "links": links,
        "links_truncated": links_truncated,
        "policy_state_digest": policy_state_digest(
            rule["rule"], rule["title"], rule["applicability"], canonical_url, text
        )
        if rule is not None
        else None,
        "title": rule["title"] if rule is not None else None,
        "applicability": rule["applicability"] if rule is not None else None,
        "entry_digest": None,
    }


# --------------------------------------------------------------------------- validation on read
@dataclass
class CacheState:
    state: str  # valid | expired | invalid | not_cached
    key: str
    entry: dict[str, Any] | None = None
    detail: str | None = None


def _invalid(key: str, detail: str) -> CacheState:
    return CacheState("invalid", key, None, detail)


def validate(entry: Any, key: str, now: datetime) -> CacheState:
    if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS or entry["schema"] != ENTRY_SCHEMA:
        return _invalid(key, "not a reference-cache-entry/v1 record")
    try:
        kind = entry["kind"]
        target = entry["rule"] if kind == "rule" else entry["explore_url"] if kind == "explore" else None
        if not isinstance(target, str) or (entry["rule"] is not None and entry["explore_url"] is not None):
            return _invalid(key, "kind and target do not match")
        if (
            entry["key"] != key
            or cache_key(
                kind, target, entry["canonical_url"], entry["registration_digest"], entry["parser_version"]
            )
            != key
        ):
            return _invalid(key, "key does not match the entry")
        if entry_digest(entry) != entry["entry_digest"]:
            return _invalid(key, "entry digest does not match")
        fetched, expires = clock.parse(entry["fetched_at"]), clock.parse(entry["expires_at"])
        if expires - fetched != TTL:
            return _invalid(key, "expiry is not fetch time + 7 days")
        if fetched > now:
            return _invalid(key, "fetch time lies in the future")
        if type(entry["generation"]) is not int or entry["generation"] < 1:
            return _invalid(key, "generation malformed")
        if not isinstance(entry["text"], str) or len(entry["text"].encode("utf-8")) > MAX_TEXT:
            return _invalid(key, "text malformed or over the limit")
        if (
            kind == "rule"
            and policy_state_digest(
                entry["rule"],
                entry["title"],
                entry["applicability"],
                entry["canonical_url"],
                entry["text"],
                entry["parser_version"],
            )
            != entry["policy_state_digest"]
        ):
            return _invalid(key, "policy state digest does not match")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return _invalid(key, f"malformed ({type(exc).__name__})")
    return CacheState("valid" if now < expires else "expired", key, entry)


def _parse_entry(raw: bytes) -> Any:
    if len(raw) > MAX_ENTRY:
        raise ValueError("entry larger than 1 MiB")
    return json.loads(raw.decode("utf-8"))


def read_state(tree: durable.Tree, key: str, now: datetime) -> CacheState:
    """State of the entry for `key` (no lock, no write; links and special files are never followed)."""
    try:
        fd = tree.opt_dir(ENTRIES_REL)
        if fd is None:
            return CacheState("not_cached", key)
        try:
            raw = durable.read(fd, f"{key}.json")
        finally:
            durable.close(fd)
    except durable.StoreError as exc:
        return _invalid(key, exc.message)
    except OSError as exc:
        return _invalid(key, f"unreadable ({exc.strerror or exc})")
    if raw is None:
        return CacheState("not_cached", key)
    try:
        return validate(_parse_entry(raw), key, now)
    except (ValueError, UnicodeError):
        return _invalid(key, "not readable JSON")


def attach(tree: durable.Tree, view: registry.RegistryView, now: datetime) -> registry.RegistryView:
    """Attach the current-key cache state of every usable registered rule to the view."""
    for rel in view.rules:
        usable = view.usable(RuleRef.parse(rel))
        if not isinstance(usable, registry.Bad):
            view.states[rel] = read_state(tree, rule_key(*usable), now)
    return view


# --------------------------------------------------------------------------- generations and listing
def _state_doc(tree: durable.Tree) -> dict[str, int]:
    try:
        raw = lifecycle.read_at(tree, CACHE_REL, STATE_NAME)
        data = json.loads(raw.decode("utf-8")) if raw is not None else None
    except (ValueError, UnicodeError, OSError, durable.StoreError):
        data = None
    if (
        isinstance(data, dict)
        and data.get("schema") == STATE_SCHEMA
        and isinstance(data.get("generations"), dict)
    ):
        return {k: v for k, v in data["generations"].items() if isinstance(k, str) and type(v) is int}
    return {}


def current_generation(tree: durable.Tree, key: str) -> int:
    entry_gen = 0
    try:
        raw = lifecycle.read_at(tree, ENTRIES_REL, f"{key}.json")
        if raw is not None:
            found = _parse_entry(raw).get("generation")
            entry_gen = found if type(found) is int else 0
    except (ValueError, UnicodeError, OSError, AttributeError, durable.StoreError):
        entry_gen = 0
    return max(_state_doc(tree).get(key, 0), entry_gen)


def _listing(fd: int) -> list[tuple[str, os.stat_result]]:
    return durable.listdir(fd)


def _cache_lock(tree: durable.Tree) -> durable.DirLock:
    return durable.DirLock(tree, CACHE_LOCK_REL, create=True)


def _entries_dir(tree: durable.Tree) -> int:
    durable.close(tree.dir(CACHE_REL, create=True, mode=0o700))
    return tree.dir(ENTRIES_REL, create=True, mode=0o700)


def _write_state(tree: durable.Tree, generations: dict[str, int]) -> None:
    fd = tree.dir(CACHE_REL, create=True, mode=0o700)
    try:
        data = lifecycle.canonical({"schema": STATE_SCHEMA, "generations": dict(sorted(generations.items()))})
        durable.write(
            fd,
            STATE_NAME,
            data + b"\n",
            f".{STATE_NAME}.{os.getpid()}.{secrets.token_hex(4)}.tmp",
            mode=0o600,
        )
    finally:
        durable.close(fd)


def _stored(fd: int, name: str) -> Any:
    try:
        return _parse_entry(durable.read(fd, name) or b"")
    except (ValueError, UnicodeError, OSError, durable.StoreError):
        return None


# --------------------------------------------------------------------------- publish
@dataclass
class Published:
    written: bool
    note: str | None = None
    generation: int | None = None
    local: bool = False


def _registration_current(tree: durable.Tree, entry: dict[str, Any], fetch_digest: str) -> tuple[bool, bool]:
    """(registration unchanged, formal Local record now present) under the knowledge lock (kind-aware)."""
    view = registry.view_at(tree)
    if entry["kind"] == "rule":
        ref = RuleRef.parse(entry["rule"])
        usable = view.usable(ref)
        if isinstance(usable, registry.Bad) or registry.registration_digest(*usable) != fetch_digest:
            return False, False
        local = store.read_rule_at(tree, ref) is not None
        memory, _ = lifecycle.memory_or_empty(tree)
        return True, local or any(m["rule"] == ref.rel for m in memory)
    for source in view.sources.values():
        if isinstance(source, registry.Bad) or registry.source_digest(source) != fetch_digest:
            continue
        try:
            urls.check_target(source, entry["explore_url"])
            return True, False
        except urls.UrlRefusal:
            return False, False
    return False, False


def _evict(fd: int, now: datetime, keep: str) -> None:
    for name, info in _listing(fd):
        if not (stat.S_ISREG(info.st_mode) and ENTRY_NAME.fullmatch(name)) or name == keep:
            continue
        found = validate(_stored(fd, name), name[:-5], now)
        if found.state in ("expired", "invalid"):
            durable.unlink(fd, name)


def _total(fd: int) -> dict[str, int]:
    return {n: i.st_size for n, i in _listing(fd) if stat.S_ISREG(i.st_mode) and ENTRY_NAME.fullmatch(n)}


def publish(
    root: Path, entry: dict[str, Any], *, start_generation: int, fetch_digest: str, capacity: int
) -> Published:
    """Generation- and registration-checked commit (knowledge lock → cache lock; nothing across network)."""
    with exit_journal.session(root, write=True) as session:
        tree = session.tree
        current, local = _registration_current(tree, entry, fetch_digest)
        if not current:
            return Published(False, "registration_changed")
        if local:
            return Published(False, "local_present", local=True)
        with _cache_lock(tree):
            key = entry["key"]
            if current_generation(tree, key) != start_generation:
                return Published(False, "superseded_by_newer_fetch")
            entry = {**entry, "generation": start_generation + 1}
            entry["entry_digest"] = entry_digest(entry)
            data = lifecycle.canonical(entry) + b"\n"
            if len(data) > MAX_ENTRY:  # readers refuse entries above 1 MiB: never write one
                return Published(False, "cache_not_written: entry_size")
            name = f"{key}.json"
            fd = _entries_dir(tree)
            try:
                sizes = _total(fd)
                if sum(sizes.values()) - sizes.get(name, 0) + len(data) > capacity:
                    _evict(fd, clock.utc_now(), name)
                    sizes = _total(fd)
                    if sum(sizes.values()) - sizes.get(name, 0) + len(data) > capacity:
                        return Published(False, "cache_not_written: capacity")
                durable.write(fd, name, data, f".{key}.{os.getpid()}.{secrets.token_hex(4)}.tmp", mode=0o600)
            finally:
                durable.close(fd)
            generations = _state_doc(tree)
            generations[key] = start_generation + 1
            _write_state(tree, generations)
    return Published(True, None, start_generation + 1)


# --------------------------------------------------------------------------- invalidate / clean
def invalidate_at(
    tree: durable.Tree,
    *,
    rule: str | None = None,
    source: str | None = None,
    source_digest: str | None = None,
) -> list[str]:
    """Delete entries of a rule identity, or of a source (its rules and its explore pages); the caller
    holds the knowledge lock. Generations are kept so in-flight fetches still fail their re-check."""
    fd = tree.opt_dir(ENTRIES_REL)
    if fd is None:
        return []
    removed = []
    try:
        with _cache_lock(tree):
            for name, info in _listing(fd):
                if not (stat.S_ISREG(info.st_mode) and ENTRY_NAME.fullmatch(name)):
                    continue
                found = _stored(fd, name)
                if not isinstance(found, dict):
                    continue
                owner = found.get("rule")
                hit = (rule is not None and owner == rule) or (
                    source is not None
                    and (
                        (isinstance(owner, str) and owner.startswith(source + "/"))
                        or (
                            found.get("kind") == "explore"
                            and found.get("registration_digest") == source_digest
                        )
                    )
                )
                if hit:
                    durable.unlink(fd, name)
                    removed.append(name[:-5])
    finally:
        durable.close(fd)
    return sorted(removed)


def _current_keys(view: registry.RegistryView) -> set[str]:
    keys = set()
    for rel in view.rules:
        usable = view.usable(RuleRef.parse(rel))
        if not isinstance(usable, registry.Bad):
            keys.add(rule_key(*usable))
    return keys


def _orphaned(entry: dict[str, Any], view: registry.RegistryView, keys: set[str]) -> bool:
    if entry["kind"] == "rule":
        return entry["key"] not in keys
    for source in view.sources.values():
        if isinstance(source, registry.Bad) or registry.source_digest(source) != entry["registration_digest"]:
            continue
        try:
            urls.check_target(source, entry["explore_url"])
            return entry["parser_version"] != PARSER_VERSION
        except urls.UrlRefusal:
            return True
    return True


def clean(root: Path, capacity: int) -> dict[str, Any]:
    """Remove expired, invalid and orphaned entries and stale temporaries (never knowledge files)."""
    removed: list[dict[str, str]] = []
    with exit_journal.session(root, write=True) as session:
        tree = session.tree
        view = registry.view_at(tree)
        keys = _current_keys(view)
        with _cache_lock(tree):
            fd = tree.opt_dir(ENTRIES_REL)
            if fd is None:
                return {"removed": [], "total_bytes": 0, "capacity": capacity}
            try:
                now = clock.utc_now()
                orphans = []
                for name, info in _listing(fd):
                    if TMP_NAME.fullmatch(name) and stat.S_ISREG(info.st_mode):
                        durable.unlink(fd, name)
                        removed.append({"key": name, "reason": "stale_temporary"})
                        continue
                    if not ENTRY_NAME.fullmatch(name):
                        continue
                    key = name[:-5]
                    if not stat.S_ISREG(info.st_mode):
                        raise durable.unsafe(f"{ENTRIES_REL}/{name} is not a regular file")
                    found = validate(_stored(fd, name), key, now)
                    reason = found.state if found.state in ("expired", "invalid") else None
                    if reason is None and found.entry is not None and _orphaned(found.entry, view, keys):
                        reason = "orphaned"
                        orphans.append(key)
                    if reason:
                        durable.unlink(fd, name)
                        removed.append({"key": key, "reason": reason})
                if orphans:
                    generations = _state_doc(tree)
                    _write_state(tree, {k: v for k, v in generations.items() if k not in orphans})
                total = sum(_total(fd).values())
            finally:
                durable.close(fd)
    return {"removed": removed, "total_bytes": total, "capacity": capacity}


# --------------------------------------------------------------------------- readers for other features
def impact_items(
    tree: durable.Tree, ref: RuleRef, target: RuleRef | None
) -> tuple[list[dict[str, Any]], list[str]]:
    """Cache entries of an identity (and a rename target) with their state, for the exit impact (P2/P3)."""
    fd = tree.opt_dir(ENTRIES_REL)
    if fd is None:
        return [], []
    wanted = {ref.rel} | ({target.rel} if target is not None else set())
    items, unreadable = [], []
    now = clock.utc_now()
    try:
        for name, info in _listing(fd):
            if not ENTRY_NAME.fullmatch(name):
                continue
            if not stat.S_ISREG(info.st_mode):
                unreadable.append(name)
                continue
            raw = _stored(fd, name)
            if not isinstance(raw, dict):
                unreadable.append(name)
                continue
            if raw.get("rule") not in wanted:
                continue
            found = validate(raw, name[:-5], now)
            items.append(
                {
                    "key": name[:-5],
                    "kind": raw.get("kind"),
                    "rule": raw.get("rule"),
                    "fetched_at": raw.get("fetched_at"),
                    "expires_at": raw.get("expires_at"),
                    "state": found.state,
                }
            )
    finally:
        durable.close(fd)
    return items, unreadable


def impact_provider(ctx: Any) -> Any:
    """`reference_cache` exit-impact provider (P2/P3/P5): entries of the identity (and rename target)."""
    from ..knowledge.impact import Found

    items, unreadable = impact_items(ctx.tree, ctx.ref, ctx.target)
    return Found(items, {"unreadable": unreadable})


def available_count(root: Path) -> int:
    """Registered rules with a valid, unexpired current-key entry (read-only; any error → not available)."""
    try:
        with durable.Tree(root) as tree:
            view = attach(tree, registry.view_at(tree), clock.utc_now())
    except (OSError, durable.StoreError, ValueError):
        return 0
    return sum(1 for s in view.states.values() if s.state == "valid")
