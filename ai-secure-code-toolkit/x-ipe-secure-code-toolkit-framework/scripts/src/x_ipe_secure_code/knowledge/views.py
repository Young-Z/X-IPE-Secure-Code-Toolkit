"""Read-only knowledge views: `knowledge list` and `knowledge show` with lifecycle markers,
exited identities and broken relations (FEATURE-001-B, extended by FEATURE-001-D)."""

from __future__ import annotations

from typing import Any

from ..atomic import LockHeld
from ..projects import knowledge_root
from ..results import Result
from . import durable, exit_journal, lifecycle, store
from .identity import IdentityError, RuleRef

SHOW_EXITED_STEP = (
    "This identity has exited; restore is not available (secure-code knowledge links lists references)"
)


def _lifecycle_fields(stored: store.StoredRule) -> dict[str, Any]:
    valid = store.lifecycle_valid(stored.record)
    state, revision = store.lifecycle_state(stored.record) if valid else ("active", 0)
    return {"state": state, "state_digest": store.state_digest(stored), "lifecycle_revision": revision}


def _exited(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: entry.get(k) for k in ("rule", "action", "renamed_to", "at", "reason")}


def list_rules(project: str | None, namespace: str | None = None, version: str | None = None) -> Result:
    command = "knowledge list"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root

    def wanted(rel: str) -> bool:
        parts = rel.split("/")
        return (not namespace or parts[0] == namespace) and (not version or parts[1] == version)

    try:
        with exit_journal.session(root, write=False) as session:
            rules = []
            for ref in store.iter_refs(root):
                if not wanted(ref.rel):
                    continue
                stored = store.read_rule(root, ref)
                if stored is None:
                    continue
                rules.append(
                    {
                        "rule": ref.rel,
                        "kind": ref.kind,
                        "name": stored.record.get("name"),
                        "applicability": stored.record.get("applicability", "unknown"),
                        "item_digest": stored.digest,
                        "consistent": stored.consistent,
                        **_lifecycle_fields(stored),
                    }
                )
            pending = [p for p in store.list_pending(root) if wanted(p["rule"])]
            memory, notice = lifecycle.memory_or_empty(session.tree)
            recovered = session.recovered
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.refusal(command, exc)
    from ..policy.resolve import latest_exits

    exited = [_exited(e) for rel, e in sorted(latest_exits(memory).items()) if wanted(rel)]
    data = {"rules": rules, "pending": pending, "count": len(rules), "exited": exited}
    if notice:
        data["notices"] = [notice]
    return exit_journal.with_recovered(Result(command, True, data), recovered)


def _relations_status(tree: durable.Tree, relations: list[Any]) -> list[dict[str, Any]]:
    from ..policy import resolve
    from ..policy.refs import parse_requested

    texts = [r for r in relations if isinstance(r, str)]
    lib = resolve.partial(tree, texts)
    status = []
    for text in texts:
        found = resolve.entry_for(lib, parse_requested(text), [])
        item = {"target": text, "availability": found["availability"]}
        for key in ("reason", "renamed_to"):
            if found.get(key) is not None:
                item[key] = found[key]
        status.append(item)
    return status


def show_rule(project: str | None, rule: str) -> Result:
    command = "knowledge show"
    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    try:
        ref = RuleRef.parse(rule)
    except IdentityError as exc:
        return Result.refused(command, exc.code, exc.message)
    try:
        with exit_journal.session(root, write=False) as session:
            recovered = session.recovered
            stored = store.read_rule(root, ref)
            exited = None
            relations: list[dict[str, Any]] = []
            if stored is None:
                memory, _ = lifecycle.memory_or_empty(session.tree)
                exited = lifecycle.reserved(memory, ref)
            else:
                relations = _relations_status(session.tree, list(stored.record.get("relations") or []))
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.refusal(command, exc)
    if stored is None:
        if exited:
            return exit_journal.with_recovered(
                Result.refused(
                    command, "RULE_NOT_FOUND", f"{ref} has exited ({exited['action']})", SHOW_EXITED_STEP,
                    {"exited": _exited(exited)},
                ),
                recovered,
            )
        return exit_journal.with_recovered(
            Result.refused(command, "RULE_NOT_FOUND", f"{ref} is not stored"), recovered
        )
    files = dict(stored.files)
    log = files.pop("changelog.md", "")
    content = files.pop("content.md", "")
    data = {
        "rule": ref.rel,
        "record": stored.record,
        "content": content,
        "examples": files,
        "changelog": log,
        "item_digest": stored.digest,
        "consistent": stored.consistent,
        "pending_commit": stored.pending_journal,
        **_lifecycle_fields(stored),
        "relations_status": relations,
        "broken_relations": [r for r in relations if r["availability"] != "available"],
    }
    return exit_journal.with_recovered(Result(command, True, data), recovered)
