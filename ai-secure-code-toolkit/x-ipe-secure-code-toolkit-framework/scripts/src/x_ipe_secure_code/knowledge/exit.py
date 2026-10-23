"""`knowledge exit-preview`, `knowledge exit-confirm` and `knowledge links` (FEATURE-001-D).

Impact first, digest-bound confirmation, journaled exit; references never block and nothing
outside the exited rule, its private records and the document index is changed.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..atomic import LockHeld
from ..auth.trust_store import TrustPaths
from ..policy import resolve, scope
from ..policy.refs import parse_requested
from ..projects import knowledge_root
from ..results import Result
from . import catalog, changelog, durable, exit_journal, impact, lifecycle, store
from .identity import IdentityError, RuleRef
from .lifecycle import DIGEST, EXITS_REL, sha

PREVIEW = "knowledge exit-preview"
CONFIRM = "knowledge exit-confirm"
LINKS = "knowledge links"
PREVIEW_STEP = "Run secure-code knowledge exit-preview and show the impact to the Maintainer"
STALE_STEP = "Preview again (secure-code knowledge exit-preview) and show the new impact to the Maintainer"
RESTORE_STEP = store.RESTORE_STEP
TARGET_STEP = "Rename within the same NAMESPACE/VERSION to a new, unused rule ID"
REASON_STEP = "Give the Maintainer's reason as one line of at most 1000 characters"
REPAIR_STEP = "Repairing references is a separate, explicit decision by an authorized person"
INDEX_STEP = (
    "Restore .x-ipe/private/secure-code/knowledge-documents.json or remove it "
    "(later imports rebuild it), then preview again"
)


class Refused(Exception):
    def __init__(self, code: str, message: str, step: str | None, data: dict[str, Any] | None = None):
        super().__init__(message)
        self.code, self.message, self.step, self.data = code, message, step, data


@dataclass
class Request:
    action: str
    ref: RuleRef
    target: str | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "rule": self.ref.rel, "target": self.target, "reason": self.reason}


@dataclass
class Prepared:
    req: Request
    target: RuleRef | None
    stored: store.StoredRule | None
    readable: bool
    state: str
    revision: int
    rule_state: dict[str, Any]
    lib: resolve.Library
    found: dict[str, impact.Found]
    impact: dict[str, Any]
    digest: str


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _request(rule: Any, action: Any, target: Any, reason: Any) -> Request:
    if action not in lifecycle.ACTIONS:
        raise Refused(
            "ACTION_INVALID", f"Unknown action {action!r}", "Use deactivate, reactivate, delete or rename"
        )
    if (action == "rename") != (target is not None):
        raise Refused(
            "ARGUMENT_INVALID",
            "--to is required for rename and only allowed for rename",
            "Pass --to NAMESPACE/VERSION/NEW_ID only with --action rename",
        )
    try:
        ref = RuleRef.parse(rule)
    except IdentityError as exc:
        raise Refused(exc.code, exc.message, "Pass the rule as NAMESPACE/VERSION/RULE_ID") from None
    problem = lifecycle.reason_problem(reason)
    if problem:
        raise Refused(problem, "A one-line reason from the Maintainer is required", REASON_STEP)
    return Request(action, ref, target, reason)


# --------------------------------------------------------------------------- prepare (never writes)
def _target_checks(tree: durable.Tree, req: Request, memory: list[dict[str, Any]]) -> RuleRef:
    try:
        target = RuleRef.parse(req.target)
    except IdentityError as exc:
        raise Refused(exc.code, exc.message, TARGET_STEP) from None
    ref = req.ref
    if (target.namespace, target.version) != (ref.namespace, ref.version) or target.rule_id == ref.rule_id:
        raise Refused(
            "RENAME_TARGET_INVALID", f"{target} is not a new ID in {ref.namespace}/{ref.version}", TARGET_STEP
        )
    exited = lifecycle.reserved(memory, target)
    if exited:
        raise Refused(
            "IDENTITY_RESERVED", f"{target} is a reserved exited identity ({exited['rule']})", TARGET_STEP
        )
    collision = store.find_collision_at(tree, target)
    if collision:
        raise Refused("IDENTITY_COLLISION", collision, TARGET_STEP)
    parent = tree.opt_dir(f"{store.LOCAL_REL}/{target.namespace}/{target.version}")
    try:
        exists = parent is not None and durable.entry(parent, target.rule_id) is not None
    finally:
        durable.close(parent)
    if exists or impact.pending_bytes(tree, target) is not None:
        raise Refused(
            "RENAME_TARGET_EXISTS", f"{target} exists or is held as a pending decision", TARGET_STEP
        )
    return target


def prepare(tree: durable.Tree, req: Request, *, strict_memory: bool) -> Prepared:
    ref = req.ref
    try:
        stored = store.read_rule_at(tree, ref)
        unreadable = False
    except store.StoreError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        stored, unreadable = None, True
    if stored is None and not unreadable:
        exists = tree.opt_dir(f"{store.LOCAL_REL}/{ref.rel}")
        durable.close(exists)
        if exists is None:
            memory, _ = lifecycle.memory_or_empty(tree)
            exited = lifecycle.reserved(memory, ref)
            data = (
                {"exited": {k: exited.get(k) for k in ("rule", "action", "renamed_to", "at", "reason")}}
                if exited
                else None
            )
            raise Refused(
                "RULE_NOT_FOUND",
                f"{ref} is not stored",
                "Preview an existing rule (see secure-code knowledge list)",
                data,
            )
        unreadable = True
    readable = bool(stored and stored.item is not None and stored.consistent)
    if not readable and req.action != "delete":
        raise Refused("RULE_INCONSISTENT", f"{ref} is inconsistent or unreadable", RESTORE_STEP)
    record = stored.record if stored else {}
    state, revision = (
        store.lifecycle_state(record) if record and store.lifecycle_valid(record) else ("unknown", 0)
    )
    needed = {"deactivate": "active", "reactivate": "deactivated"}.get(req.action)
    if needed and state != needed:
        raise Refused(
            "ACTION_NOT_APPLICABLE",
            f"{ref} is {state}; {req.action} needs an {needed} rule",
            "Preview the action that matches the rule's current state (see secure-code knowledge show)",
        )
    memory = lifecycle.read_memory(tree) if strict_memory else lifecycle.memory_or_empty(tree)[0]
    target = _target_checks(tree, req, memory) if req.action == "rename" else None
    if readable:
        assert stored is not None
        fingerprint = lifecycle.files_fingerprint({**stored.files, "record.json": stored.record_raw or ""})
        special: list[dict[str, str]] = []
    else:
        fd = tree.dir(f"{store.LOCAL_REL}/{ref.rel}")
        try:
            fingerprint, special = lifecycle.folder_fingerprint(fd)
        finally:
            durable.close(fd)
    rule_state = {
        "consistent": readable,
        "state": state,
        "revision": revision,
        "state_digest": store.state_digest(stored) if readable and stored else None,
        "fingerprint": fingerprint,
        "special_entries": special,
        "pending_commit": bool(stored and stored.pending_journal),
    }
    lib = resolve.snapshot(tree)
    found = impact.collect(impact.Context(tree, ref, target, lib))
    digest = impact.digest(req.as_dict(), rule_state, found)
    return Prepared(
        req, target, stored, readable, state, revision, rule_state, lib, found, impact.view(found), digest
    )


def _will(p: Prepared) -> list[str]:
    ref, action = p.req.ref.rel, p.req.action
    pending = p.found["pending_decisions"].items
    edges = [i for i in p.found["document_index"].items if i["edge"]]
    revision = f"increase the lifecycle revision {p.revision} → {p.revision + 1}"
    will = {
        "deactivate": [
            f"mark {ref} deactivated (content and changelog are kept)",
            f"keep {len(pending)} pending decision(s)",
        ],
        "reactivate": [f"mark {ref} active again"],
        "delete": [
            f"move the rule folder as found to a private tombstone under {lifecycle.TOMBSTONES_REL}",
            f"remove {len(pending)} pending decision(s)",
            f"reserve {ref} as deleted",
        ],
        "rename": [
            f"move the rule folder to {p.target}",
            f"remove {len(pending)} pending decision(s)",
            f"reserve {ref} as renamed to {p.target}",
        ],
    }[action]
    if action != "reactivate":
        will.append(f"invalidate {len(edges)} index entr{'y' if len(edges) == 1 else 'ies'}")
    if action != "delete":
        will.append(f"record the action in the changelog and {revision}")
    return [*will, "no other rule, scope record, run or report is changed; references are reported broken"]


def _preview_data(p: Prepared) -> dict[str, Any]:
    return {
        "impact": p.impact,
        "action": p.req.action,
        "rule": p.req.ref.rel,
        "target": p.req.target,
        "reason": p.req.reason,
        "rule_state": p.rule_state,
        "will": _will(p),
        "impact_digest": p.digest,
        "references_block": False,
    }


# --------------------------------------------------------------------------- commands
def _start(command: str, project: str | None, trust_paths: TrustPaths | None) -> tuple[Path, Any] | Result:
    from .service import _authorize

    root = knowledge_root(project, command)
    if isinstance(root, Result):
        return root
    try:
        recovered = exit_journal.ensure_recovered(root)
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.refusal(command, exc)
    denied = _authorize(command, trust_paths)
    if denied:
        return exit_journal.with_recovered(denied, recovered)
    return root, recovered


def _scope_lock(tree: durable.Tree) -> durable.DirLock:
    """Scope lock, never created here (v1.3): every scope-lock holder takes the knowledge lock first."""
    return durable.DirLock(tree, scope.SCOPE_LOCK_REL, create=False)


def preview(
    project: str | None,
    rule: Any,
    action: Any,
    target: Any,
    reason: Any,
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    started = _start(PREVIEW, project, trust_paths)
    if isinstance(started, Result):
        return started
    root, recovered = started
    try:
        req = _request(rule, action, target, reason)
        with exit_journal.session(root, write=False) as session, _scope_lock(session.tree):
            recovered = recovered or session.recovered
            prepared = prepare(session.tree, req, strict_memory=False)
    except Refused as exc:
        return exit_journal.with_recovered(
            Result.refused(PREVIEW, exc.code, exc.message, exc.step, exc.data), recovered
        )
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.with_recovered(exit_journal.refusal(PREVIEW, exc), recovered)
    steps = [
        "Show the whole impact to the Maintainer; references do not block the decision",
        "Only after the Maintainer explicitly confirms: run secure-code knowledge exit-confirm "
        "with this impact_digest",
    ]
    return exit_journal.with_recovered(Result(PREVIEW, True, _preview_data(prepared), [], steps), recovered)


def confirm(
    project: str | None,
    rule: Any,
    action: Any,
    target: Any,
    reason: Any,
    impact_digest: Any,
    *,
    trust_paths: TrustPaths | None = None,
) -> Result:
    from .service import _authorize

    started = _start(CONFIRM, project, trust_paths)
    if isinstance(started, Result):
        return started
    root, recovered = started
    try:
        req = _request(rule, action, target, reason)
        if not (isinstance(impact_digest, str) and DIGEST.fullmatch(impact_digest)):
            raise Refused(
                "IMPACT_DIGEST_REQUIRED", "A confirmation needs the impact digest of a preview", PREVIEW_STEP
            )
        with exit_journal.session(root, write=True) as session, _scope_lock(session.tree):
            recovered = recovered or session.recovered
            tree = session.tree
            store._pause_point("exit_locked")
            prepared = prepare(tree, req, strict_memory=req.action in ("delete", "rename"))
            if prepared.digest != impact_digest:
                raise Refused(
                    "STALE_IMPACT",
                    "The impact changed since the preview (or another request was previewed)",
                    STALE_STEP,
                    {"impact": prepared.impact},
                )
            if req.action != "reactivate" and prepared.found["document_index"].extra.get("unreadable"):
                raise Refused(
                    "INDEX_INVALID", "The knowledge-documents index is unreadable or malformed", INDEX_STEP
                )
            if prepared.readable:
                store.recover_at(tree, req.ref)
                prepared.stored = store.read_rule_at(tree, req.ref)
            journal, data = _plan(tree, prepared)
            if _authorize(CONFIRM, trust_paths):
                raise Refused(
                    "NOT_AUTHORIZED",
                    "Maintainer qualification no longer valid",
                    "Re-run the authorization step",
                )
            exit_journal.run(tree, journal)
    except Refused as exc:
        return exit_journal.with_recovered(
            Result.refused(CONFIRM, exc.code, exc.message, exc.step, exc.data), recovered
        )
    except (LockHeld, store.StoreError, OSError, exit_journal.JournalInvalid) as exc:
        return exit_journal.with_recovered(exit_journal.refusal(CONFIRM, exc), recovered)
    steps = [REPAIR_STEP + " (secure-code knowledge links lists broken references)"]
    return exit_journal.with_recovered(Result(CONFIRM, True, data, [], steps), recovered)


# --------------------------------------------------------------------------- plan
def _post_library(
    p: Prepared, new_record: dict[str, Any] | None, text: str | None, memory_entry: dict[str, Any] | None
) -> resolve.Library:
    lib, ref, stored = p.lib, p.req.ref, p.stored
    rules, exited = dict(lib.rules), dict(lib.exited)
    if p.req.action in ("deactivate", "reactivate"):
        rules[ref] = dataclasses.replace(stored, record=new_record, record_raw=text)
    else:
        rules.pop(ref, None)
        exited[ref.rel] = memory_entry
    if p.req.action == "rename":
        assert (
            p.target is not None and stored is not None and stored.item is not None and new_record is not None
        )
        rules[p.target] = dataclasses.replace(
            stored,
            ref=p.target,
            record=new_record,
            record_raw=text,
            item=dataclasses.replace(stored.item, ref=p.target),
            digest=new_record["item_digest"],
        )
    return resolve.Library(rules, set(lib.pending), exited, lib.notices)


def _write(name: str, old: bytes | None, text: str) -> dict[str, Any]:
    return {
        "name": name,
        "op": "write",
        "before": sha(old) if old is not None else None,
        "after": sha(text.encode("utf-8")),
        "text": text,
    }


def _plan(tree: durable.Tree, p: Prepared) -> tuple[dict[str, Any], dict[str, Any]]:
    req, ref, target = p.req, p.req.ref, p.target
    action = req.action
    at = _now()
    exit_id = lifecycle.new_exit_id(at)
    rule_rel = f"{store.LOCAL_REL}/{ref.rel}"
    tomb = lifecycle.tombstone_rel(exit_id)
    to = p.revision + 1
    old_state = store.state_digest(p.stored) if p.readable and p.stored else None
    pending_raw = impact.pending_bytes(tree, ref) if action in ("delete", "rename") else None
    index_raw = lifecycle.read_at(tree, lifecycle.INDEX_DIR, lifecycle.INDEX_NAME)
    edges: list[str] = []
    index: dict[str, Any] = {}
    if action != "reactivate":
        index = lifecycle.index_entries(index_raw)
        edges = lifecycle.index_edges(index, ref.rel)
    memory_raw = lifecycle.read_at(tree, EXITS_REL, lifecycle.MEMORY_NAME)
    transitions_raw = lifecycle.read_at(tree, EXITS_REL, lifecycle.TRANSITIONS_NAME)
    try:
        previous = lifecycle.transition_entries(transitions_raw)
    except ValueError:
        raise store.StoreError(
            "EXIT_TRANSITION_INVALID", "the exit transition log is unreadable", scope.TRANSITION_STEP
        ) from None
    new_record = text = None
    new_state = None
    if action != "delete":
        assert p.stored is not None and p.stored.item is not None
        new_record = json.loads(p.stored.record_raw or "{}")
        state = {"deactivate": "deactivated", "reactivate": "active"}.get(action, p.state)
        if action == "rename":
            assert target is not None
            new_record["rule_id"] = target.rule_id
            new_record["item_digest"] = dataclasses.replace(p.stored.item, ref=target).digest()
            new_record["updated_at"] = at
        new_record["lifecycle"] = {"state": state, "revision": to}
        text = lifecycle.text(new_record)
        new_state = store.revision_digest(new_record["item_digest"], to)
    memory_entry = None
    if action in ("delete", "rename"):
        memory_entry = {
            "rule": ref.rel,
            "action": lifecycle.EXITED[action],
            "renamed_to": target.rel if target else None,
            "exit_id": exit_id,
            "at": at,
            "reason": req.reason,
            "tombstone": tomb if action == "delete" else None,
            "transition": None,
        }
    post = _post_library(p, new_record, text, memory_entry)
    identities = {ref.rel: {"before": resolve.view_of(p.lib, ref), "after": resolve.view_of(post, ref)}}
    if target is not None:
        identities[target.rel] = {
            "before": resolve.view_of(p.lib, target),
            "after": resolve.view_of(post, target),
        }
    transition = {
        "exit_id": exit_id,
        "action": action,
        "rule": ref.rel,
        "target": target.rel if target else None,
        "at": at,
        "identities": identities,
    }
    transition["digest"] = lifecycle.transition_digest(transition)
    td = transition["digest"]
    if memory_entry is not None:
        memory_entry["transition"] = td
    steps: dict[str, dict[str, Any]] = {}
    final: dict[str, bytes] = {}
    if action != "delete":
        assert text is not None
        record_raw = lifecycle.read_at(tree, rule_rel, "record.json")
        log = lifecycle.read_at(tree, rule_rel, "changelog.md")
        if record_raw is None or log is None:
            raise Refused("RULE_INCONSISTENT", f"{ref} has no record or changelog", RESTORE_STEP)
        suffix = changelog.lifecycle_entry(
            time=at,
            action=action,
            exit_id=exit_id,
            reason=req.reason,
            rule=ref.rel,
            target=target.rel if target else None,
            revision_from=p.revision,
            revision_to=to,
            state_before=old_state,
            state_after=new_state,
            impact_digest=p.digest,
            transition=td,
            old_record=record_raw.decode("utf-8"),
            new_record=text,
        )
        steps["record"] = _write("record", record_raw, text)
        steps["changelog"] = {
            "name": "changelog",
            "op": "append",
            "before": sha(log),
            "after": sha(log + suffix.encode("utf-8")),
            "suffix": suffix,
            "suffix_digest": sha(suffix.encode("utf-8")),
        }
        final = {"record.json": text.encode("utf-8"), "changelog.md": log + suffix.encode("utf-8")}
    removed = [ref.rel] if pending_raw is not None else []
    if action == "delete":
        folder_fp, special = _physical(tree, rule_rel)
        steps["tombstone_dir"] = {"name": "tombstone_dir", "op": "mkdir"}
        steps["move"] = {"name": "move", "op": "move", "fingerprint": folder_fp}
        steps["tombstone_record"] = _write(
            "tombstone_record",
            None,
            lifecycle.text(
                {
                    "schema": lifecycle.EXIT_RECORD_SCHEMA,
                    "exit_id": exit_id,
                    "action": "delete",
                    "rule": ref.rel,
                    "reason": req.reason,
                    "at": at,
                    "role": "maintainer",
                    "consistent": p.readable,
                    "pending_commit": p.rule_state["pending_commit"],
                    "state_digest": old_state,
                    "lifecycle_revision": {"from": p.revision, "to": to},
                    "folder_fingerprint": folder_fp,
                    "impact_digest": p.digest,
                    "transition": td,
                    "impact_counts": {kind: len(f.items) for kind, f in p.found.items()},
                    "removed_pending": removed,
                    "invalidated_index": edges,
                    "special_entries": special,
                }
            ),
        )
        _same_device(tree, ref)
    elif action == "rename":
        assert target is not None
        source = (f"{store.LOCAL_REL}/{ref.namespace}/{ref.version}", ref.rule_id)
        steps["move"] = {
            "name": "move",
            "op": "move",
            "fingerprint": exit_journal.planned_fingerprint(tree, *source, final),
        }
    if pending_raw is not None:
        steps["pending"] = {"name": "pending", "op": "remove", "before": sha(pending_raw)}
    if edges:
        steps["index"] = _write(
            "index", index_raw, lifecycle.text(lifecycle.invalidate_index(index, ref.rel, edges, at))
        )
    if memory_entry is not None:
        entries = lifecycle.memory_entries(memory_raw)
        steps["memory"] = _write("memory", memory_raw, lifecycle.memory_text([*entries, memory_entry]))
    steps["transitions"] = _write(
        "transitions", transitions_raw, lifecycle.transitions_text([*previous, transition])
    )
    journal = {
        "schema": lifecycle.JOURNAL_SCHEMA,
        "exit_id": exit_id,
        "action": action,
        "rule": ref.rel,
        "target": target.rel if target else None,
        "reason": req.reason,
        "at": at,
        "impact_digest": p.digest,
        "transition_digest": td,
        "pre_state": {"pending": sha(pending_raw) if pending_raw is not None else None, "index_edges": edges},
        "steps": [steps[name] for name in exit_journal.ORDER[action] if name in steps],
    }
    data = {
        "outcome": {
            "deactivate": "deactivated",
            "reactivate": "reactivated",
            "delete": "deleted",
            "rename": "renamed",
        }[action],
        "rule": ref.rel,
        "target": target.rel if target else None,
        "exit_id": exit_id,
        "lifecycle_revision": to,
        "state_digest": new_state,
        "removed_pending": removed,
        "invalidated_index": edges,
        "tombstone": tomb if action == "delete" else None,
        "impact": p.impact,
    }
    return journal, data


def _physical(tree: durable.Tree, rel: str) -> tuple[str, list[dict[str, str]]]:
    fd = tree.dir(rel)
    try:
        return lifecycle.folder_fingerprint(fd)
    finally:
        durable.close(fd)


def _same_device(tree: durable.Tree, ref: RuleRef) -> None:
    """EXDEV detected before the journal: nothing is written."""
    src = tree.dir(f"{store.LOCAL_REL}/{ref.namespace}/{ref.version}")
    try:
        for rel in (lifecycle.TOMBSTONES_REL, EXITS_REL, store.PRIVATE_REL):
            dst = tree.opt_dir(rel)
            if dst is not None:
                break
        try:
            if dst is not None and not durable.same_device(src, dst):
                raise Refused(
                    "IO_ERROR",
                    "The knowledge folder and the private tombstone folder are on different devices",
                    "Keep x-ipe-docs and .x-ipe/private on the same file system, then preview again",
                )
        finally:
            durable.close(dst)
    finally:
        durable.close(src)


# --------------------------------------------------------------------------- links
def links(project: str | None) -> Result:
    """Read-only broken-reference report; nothing is substituted, repaired or written."""
    root = knowledge_root(project, LINKS)
    if isinstance(root, Result):
        return root
    recovered = None
    try:
        with exit_journal.session(root, write=False) as session, _scope_lock(session.tree):
            recovered = session.recovered
            lib = resolve.snapshot(session.tree)
            records, unreadable_scopes = impact.scope_records(session.tree)
            extension = catalog.links_extension(session.tree, lib)
    except (LockHeld, store.StoreError, OSError) as exc:
        return exit_journal.with_recovered(exit_journal.refusal(LINKS, exc), recovered)
    broken, unreadable_sources = [], []
    for source, stored in sorted(lib.rules.items()):
        record = stored.record if isinstance(stored, store.StoredRule) else None
        relations = record.get("relations") if isinstance(record, dict) else None
        if not isinstance(relations, list):
            unreadable_sources.append(source.rel)
            continue
        state = store.lifecycle_state(record)[0] if store.lifecycle_valid(record) else "inconsistent"
        for text in relations:
            if not isinstance(text, str):
                continue
            found = resolve.entry_for(lib, parse_requested(text), [])
            if found["availability"] != "available":
                broken.append(_broken({"source": source.rel, "source_state": state, "target": text}, found))
    scopes = []
    for record in records:
        for adopted in record["adopted"]:
            found = resolve.evaluate(lib, RuleRef.parse(adopted["rule"]), [])
            if found["availability"] != "available":
                scopes.append(_broken({"scope_id": record["scope_id"], "rule": adopted["rule"]}, found))
    data = {
        "broken_relations": broken,
        "scopes": sorted(scopes, key=lambda s: (s["scope_id"], s["rule"])),
        "unreadable_sources": unreadable_sources,
        "unreadable_scopes": unreadable_scopes,
        "counts": {"broken_relations": len(broken), "scopes": len(scopes)},
    }
    if extension is not None:
        data["preset_tag_links"] = extension
    return exit_journal.with_recovered(Result(LINKS, True, data, [], [REPAIR_STEP]), recovered)


def _broken(base: dict[str, Any], found: dict[str, Any]) -> dict[str, Any]:
    item = {**base, "reason": found.get("reason")}
    if found.get("renamed_to"):
        item["renamed_to"] = found["renamed_to"]
    return item
