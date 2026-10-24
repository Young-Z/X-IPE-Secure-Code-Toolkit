"""Exit impact providers (FEATURE-001-D): the extensible provider list, unsupported kinds and
the impact digest. Every read goes through the command's no-follow `durable.Tree`; providers
only read toolkit files (knowledge, scopes, private run states, pending decisions, index)."""

from __future__ import annotations

import json
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..policy import resolve, scope
from ..reference import cache as reference_cache
from . import catalog, durable, lifecycle, store
from .identity import RuleRef

SCHEMA = "ai-secure-code-toolkit/exit-impact/v1"
NOT_CHECKED = "not checked in this version"
UNSUPPORTED: tuple[str, ...] = ()  # FEATURE-001-E (P2): `reference_cache` is a provider now
SCOPE_FILE = re.compile(r"[0-9a-f]{64}\.json")


@dataclass(frozen=True)
class Context:
    tree: durable.Tree
    ref: RuleRef
    target: RuleRef | None
    lib: resolve.Library


@dataclass
class Found:
    items: list[dict[str, Any]]
    extra: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        return lifecycle.sha(lifecycle.canonical({"items": self.items, **self.extra}))

    def view(self) -> dict[str, Any]:
        return {"count": len(self.items), "items": self.items, **self.extra}


@dataclass(frozen=True)
class Provider:
    kind: str
    collect: Callable[[Context], Found]


def relations(ctx: Context) -> Found:
    items, pointing, unreadable = [], [], []
    for source, stored in sorted(ctx.lib.rules.items()):
        record = stored.record if isinstance(stored, store.StoredRule) else None
        targets = record.get("relations") if isinstance(record, dict) else None
        if not isinstance(targets, list):
            unreadable.append(source.rel)
            continue
        if ctx.ref.rel in targets:
            items.append({"source": source.rel, "self": source == ctx.ref})
        if ctx.target is not None and ctx.target.rel in targets:
            pointing.append({"source": source.rel})
    return Found(items, {"pointing_to_target": pointing, "unreadable_sources": unreadable})


def scope_records(tree: durable.Tree) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Verified scope records and unreadable entries (links and invalid files are never used)."""
    fd = tree.opt_dir(scope.SCOPES_REL)
    if fd is None:
        return [], []
    records, unreadable = [], []
    try:
        for name, info in durable.listdir(fd):
            if not stat.S_ISREG(info.st_mode):
                if SCOPE_FILE.fullmatch(name) or stat.S_ISLNK(info.st_mode):
                    unreadable.append({"file": name, "detail": "not a regular file"})
                continue
            if not SCOPE_FILE.fullmatch(name):
                continue
            try:
                record = json.loads((durable.read(fd, name) or b"").decode("utf-8"))
                records.append(scope.verify_record(record, name[:-5]))
            except (ValueError, scope.ScopeError, store.StoreError, OSError) as exc:
                unreadable.append({"file": name, "detail": type(exc).__name__})
    finally:
        durable.close(fd)
    return records, unreadable


def scopes(ctx: Context) -> Found:
    records, unreadable = scope_records(ctx.tree)
    items = [
        {"scope_id": r["scope_id"], "created_at": r["created_at"]}
        for r in records
        if any(a.get("rule") == ctx.ref.rel for a in r["adopted"])
    ]
    return Found(sorted(items, key=lambda i: i["scope_id"]), {"unreadable": unreadable})


def _open_runs(ctx: Context, root_rel: str, pattern: re.Pattern[str], schema: str, id_key: str) -> Found:
    fd = ctx.tree.opt_dir(root_rel)
    if fd is None:
        return Found([], {"unreadable": []})
    items, unreadable = [], []
    try:
        for name, info in durable.listdir(fd):
            if stat.S_ISLNK(info.st_mode):
                unreadable.append({id_key: name, "detail": "symbolic link (not followed)"})
                continue
            if not (stat.S_ISDIR(info.st_mode) and pattern.fullmatch(name)):
                continue
            try:
                child = durable.open_child(fd, name)
                try:
                    state = json.loads((durable.read(child, "state.json") or b"null").decode("utf-8"))
                finally:
                    durable.close(child)
                if not (
                    isinstance(state, dict) and state.get("schema") == schema and state.get(id_key) == name
                ):
                    raise ValueError("not a run state")
                if state.get("status") != "open":
                    continue
                for adopted in state["scope"]["adopted"]:
                    if adopted["rule"] == ctx.ref.rel:
                        items.append({id_key: name, "state_digest": adopted["state_digest"]})
            except (ValueError, KeyError, TypeError, store.StoreError, OSError) as exc:
                unreadable.append({id_key: name, "detail": type(exc).__name__})
    finally:
        durable.close(fd)
    return Found(items, {"unreadable": unreadable})


def guard_runs(ctx: Context) -> Found:
    from ..guard.model import GUARD_REL, RUN_ID, SCHEMA_RUN

    return _open_runs(ctx, GUARD_REL, RUN_ID, SCHEMA_RUN, "verification_id")


def copilot_collaborations(ctx: Context) -> Found:
    from ..copilot.model import COLLAB_ID, COPILOT_REL, SCHEMA_STATE

    return _open_runs(ctx, COPILOT_REL, COLLAB_ID, SCHEMA_STATE, "collaboration_id")


def pending_location(ref: RuleRef) -> tuple[str, str]:
    return f"{store.PENDING_REL}/{ref.namespace}/{ref.version}", f"{ref.rule_id}.json"


def pending_bytes(tree: durable.Tree, ref: RuleRef) -> bytes | None:
    """The rule's pending decision file (a used path: a link or other kind is PATH_UNSAFE)."""
    return lifecycle.read_at(tree, *pending_location(ref))


def pending_decisions(ctx: Context) -> Found:
    raw = pending_bytes(ctx.tree, ctx.ref)
    if raw is None:
        return Found([])
    try:
        held = json.loads(raw.decode("utf-8")).get("held_at")
    except (ValueError, AttributeError):
        held = None
    return Found([{"rule": ctx.ref.rel, "held_at": held, "sha256": lifecycle.sha(raw)}])


def document_index(ctx: Context) -> Found:
    index, unreadable = lifecycle.read_index_strict(ctx.tree)
    if index is None:
        return Found([], {"unreadable": unreadable})
    items = []
    for document, entry in sorted(index.items()):
        edge = any(i.get("rule") == ctx.ref.rel for i in entry.get("items", []))
        if edge or ctx.ref.rel in entry.get("failed", []):
            items.append(
                {"document": document, "edge": edge, "sha256": lifecycle.sha(lifecycle.canonical(entry))}
            )
    return Found(items, {"unreadable": None})


PROVIDERS: tuple[Provider, ...] = (
    Provider("relations", relations),
    Provider("scopes", scopes),
    Provider("guard_runs", guard_runs),
    Provider("copilot_collaborations", copilot_collaborations),
    Provider("pending_decisions", pending_decisions),
    Provider("document_index", document_index),
    Provider("presets", catalog.presets_provider),
    Provider("tags", catalog.tags_provider),
    Provider("reference_cache", reference_cache.impact_provider),  # FEATURE-001-E (P2/P3/P5)
)


def collect(ctx: Context) -> dict[str, Found]:
    return {p.kind: p.collect(ctx) for p in PROVIDERS}


def view(found: dict[str, Found]) -> dict[str, Any]:
    """Impact as shown first in the preview; unsupported kinds are stated, never empty."""
    shown: dict[str, Any] = {kind: f.view() for kind, f in found.items()}
    shown.update({kind: NOT_CHECKED for kind in UNSUPPORTED})
    return shown


RULE_STATE_KEYS = ("consistent", "state", "revision", "state_digest", "fingerprint")


def digest(request: dict[str, Any], rule_state: dict[str, Any], found: dict[str, Found]) -> str:
    canonical = {
        "schema": SCHEMA,
        **{k: request[k] for k in ("action", "rule", "target", "reason")},
        "rule_state": {k: rule_state[k] for k in RULE_STATE_KEYS},
        "providers": {kind: f.fingerprint() for kind, f in found.items()},
        "unsupported": list(UNSUPPORTED),
    }
    return lifecycle.sha(lifecycle.canonical(canonical))
